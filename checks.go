package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	slsaPredicateV1        = "https://slsa.dev/provenance/v1"
	githubOIDCIssuer       = "https://token.actions.githubusercontent.com"
	githubTenantOIDCIssuer = "https://token.actions.%s.ghe.com"
	githubHostedRunner     = "github-hosted"
)

var errNoProvenance = errors.New("no build provenance attestation found")

// workflowRefSuffix matches the "@<ref>" that terminates a workflow URI in a
// Fulcio certificate, e.g. ".../release.yml@refs/heads/main".
var workflowRefSuffix = regexp.MustCompile(`@(refs/.*|[0-9a-fA-F]+)$`)

type checker struct {
	api         githubAPI
	verifier    bundleVerifier
	owner, repo string
	tenant      string
	trustDomain func() (string, error)
}

func (c *checker) fullName() string { return c.owner + "/" + c.repo }

func (c *checker) hostURL() string {
	if c.tenant == "" {
		return "https://github.com"
	}
	return fmt.Sprintf("https://%s.ghe.com", c.tenant)
}

type provenanceResult struct {
	asset  asset
	digest string // hex-encoded sha256
	cert   *certificate.Summary
	err    error
}

// checkProvenance verifies the SLSA build provenance for an asset using the
// digest reported by the API, so it can run before the asset is downloaded.
func (c *checker) checkProvenance(a asset) provenanceResult {
	res := provenanceResult{asset: a}
	if a.Digest == nil || !strings.HasPrefix(*a.Digest, "sha256:") {
		res.err = errors.New("GitHub did not report a sha256 digest for this asset")
		return res
	}
	res.digest = strings.TrimPrefix(*a.Digest, "sha256:")

	attestations, err := c.api.Attestations("sha256:"+res.digest, slsaPredicateV1)
	if errors.Is(err, errNotFound) {
		res.err = errNoProvenance
		return res
	} else if err != nil {
		res.err = fmt.Errorf("failed to fetch attestations: %w", err)
		return res
	}

	hostURL := c.hostURL()
	issuer := githubOIDCIssuer
	if c.tenant != "" {
		issuer = fmt.Sprintf(githubTenantOIDCIssuer, c.tenant)
	}
	expected := certificate.Summary{
		Issuer:                   issuer,
		SourceRepositoryOwnerURI: fmt.Sprintf("%s/%s", hostURL, c.owner),
		SourceRepositoryURI:      fmt.Sprintf("%s/%s", hostURL, c.fullName()),
	}
	// Any GitHub Actions workflow on this host may sign, which allows reusable
	// workflows in other repositories. The source repository is pinned through
	// the certificate extensions, which come from the OIDC token.
	policy, err := buildPolicy("^"+regexp.QuoteMeta(hostURL+"/"), "sha256", res.digest)
	if err != nil {
		res.err = err
		return res
	}

	var sigErr, extErr error
	for _, att := range attestations {
		result, err := c.verifier.Verify(att.Bundle, policy, true)
		if err != nil {
			sigErr = err
			continue
		}
		if err := checkCertExtensions(*result.Signature.Certificate, expected); err != nil {
			extErr = err
			continue
		}
		if result.Statement.GetPredicateType() != slsaPredicateV1 {
			continue
		}
		res.cert = result.Signature.Certificate
		return res
	}
	switch {
	case extErr != nil:
		res.err = fmt.Errorf("attestation was not built from %s: %w", c.fullName(), extErr)
	case sigErr != nil:
		res.err = fmt.Errorf("attestation signature verification failed: %w", sigErr)
	default:
		res.err = errNoProvenance
	}
	return res
}

func checkCertExtensions(given, expected certificate.Summary) error {
	if !strings.EqualFold(expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI) {
		return fmt.Errorf("expected SourceRepositoryOwnerURI to be %s, got %s", expected.SourceRepositoryOwnerURI, given.SourceRepositoryOwnerURI)
	}
	if !strings.EqualFold(expected.SourceRepositoryURI, given.SourceRepositoryURI) {
		return fmt.Errorf("expected SourceRepositoryURI to be %s, got %s", expected.SourceRepositoryURI, given.SourceRepositoryURI)
	}
	if !strings.EqualFold(expected.Issuer, given.Issuer) {
		return fmt.Errorf("expected Issuer to be %s, got %s", expected.Issuer, given.Issuer)
	}
	return nil
}

func buildPolicy(sanRegex, digestAlg, digestHex string) (verify.PolicyBuilder, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	sanMatcher, err := verify.NewSANMatcher("", sanRegex)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	// The OIDC issuer is enforced separately via the certificate extensions.
	issuerMatcher, err := verify.NewIssuerMatcher("", ".*")
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	return verify.NewPolicy(verify.WithArtifactDigest(digestAlg, digest), verify.WithCertificateIdentity(certID)), nil
}

type releaseCheck struct {
	// subjects maps asset name to the hex-encoded sha256 GitHub signed for it.
	subjects map[string]string
	err      error
}

// checkRelease verifies the attestation GitHub signs when an immutable release
// is published, and returns the asset digests it records.
func (c *checker) checkRelease(r *release) releaseCheck {
	tag := r.TagName
	ref, err := c.api.RefSHA(tag)
	if err != nil {
		return releaseCheck{err: fmt.Errorf("failed to resolve tag %s: %w", tag, err)}
	}
	refAlg := "sha1"
	if len(ref) == 64 {
		refAlg = "sha256"
	}

	attestations, err := c.api.Attestations(refAlg+":"+ref, "release")
	if err != nil && !errors.Is(err, errNotFound) {
		return releaseCheck{err: fmt.Errorf("failed to fetch release attestation: %w", err)}
	}
	var candidate *attestation
	for _, a := range attestations {
		if a.Initiator != "github" {
			continue
		}
		st, err := unverifiedStatement(a)
		if err != nil {
			return releaseCheck{err: fmt.Errorf("failed to parse release attestation: %w", err)}
		}
		if st.GetPredicate().GetFields()["tag"].GetStringValue() == tag {
			candidate = a
			break
		}
	}
	if candidate == nil {
		return releaseCheck{err: errors.New("no signed release attestation found")}
	}

	td, err := c.trustDomain()
	if err != nil {
		return releaseCheck{err: fmt.Errorf("error getting trust domain: %w", err)}
	}
	if td == "" {
		td = "dotcom"
	}
	// Release attestations are signed by GitHub itself, never by a workflow.
	policy, err := buildPolicy(fmt.Sprintf(`^https://%s\.releases\.github\.com$`, regexp.QuoteMeta(td)), refAlg, ref)
	if err != nil {
		return releaseCheck{err: err}
	}
	result, err := c.verifier.Verify(candidate.Bundle, policy, false)
	if err != nil {
		return releaseCheck{err: fmt.Errorf("release attestation verification failed: %w", err)}
	}

	statement := result.Statement
	fields := statement.GetPredicate().GetFields()
	if got := fields["tag"].GetStringValue(); got != tag {
		return releaseCheck{err: fmt.Errorf("release attestation is for tag %q, not %q", got, tag)}
	}
	// Release predicate v0.1 records the release ID as "releaseId"; v0.2 as "databaseId".
	releaseID := fields["databaseId"].GetStringValue()
	if releaseID == "" {
		releaseID = fields["releaseId"].GetStringValue()
	}
	if releaseID != strconv.FormatInt(r.ID, 10) {
		return releaseCheck{err: fmt.Errorf("release attestation is for release ID %q, not %d", releaseID, r.ID)}
	}

	subjects := make(map[string]string)
	for _, s := range statement.GetSubject() {
		if d := s.GetDigest()["sha256"]; s.GetName() != "" && d != "" {
			subjects[s.GetName()] = d
		}
	}
	return releaseCheck{subjects: subjects}
}

func unverifiedStatement(a *attestation) (*in_toto.Statement, error) {
	env := a.Bundle.GetDsseEnvelope()
	if env == nil {
		return nil, errors.New("attestation is not a DSSE envelope")
	}
	var st in_toto.Statement
	if err := protojson.Unmarshal(env.Payload, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// confirmProvenance prints the immutability and provenance details for the
// release and each asset, and decides whether the download should proceed.
// It returns the expected sha256 digest for each asset, keyed by name.
func confirmProvenance(e *env, c *checker, r *release, assets []asset) (map[string]string, error) {
	var rel releaseCheck
	if r.Immutable {
		rel = c.checkRelease(r)
	}
	results := make([]provenanceResult, len(assets))
	for i, a := range assets {
		results[i] = c.checkProvenance(a)
	}

	out := e.stderr
	cs := e.colors

	var problems []string
	fmt.Fprintf(out, "%s %s\n", cs.bold(c.fullName()), cs.bold(r.TagName))
	switch {
	case !r.Immutable:
		fmt.Fprintf(out, "%s Not an immutable release; assets can be replaced after publishing\n", cs.warningIcon())
	case rel.err != nil:
		problems = append(problems, "the release attestation could not be verified")
		fmt.Fprintf(out, "%s Release is marked immutable, but %s\n", cs.failureIcon(), rel.err)
	default:
		fmt.Fprintf(out, "%s Immutable release, verified by GitHub's signed release attestation\n", cs.successIcon())
	}

	digests := make(map[string]string, len(results))
	var unverified int
	for _, res := range results {
		fmt.Fprintf(out, "\n%s\n", cs.bold(res.asset.Name))
		ok := true
		if r.Immutable && rel.err == nil {
			if signed, listed := rel.subjects[res.asset.Name]; !listed {
				ok = false
				fmt.Fprintf(out, "%s Not listed in the signed release attestation\n", cs.failureIcon())
			} else if res.asset.Digest == nil || *res.asset.Digest != "sha256:"+signed {
				ok = false
				fmt.Fprintf(out, "%s Digest differs from the signed release attestation (sha256:%s)\n", cs.failureIcon(), signed)
			} else {
				fmt.Fprintf(out, "%s Listed in the signed release attestation\n", cs.successIcon())
			}
		}
		if res.err != nil {
			ok = false
			fmt.Fprintf(out, "%s %s\n", cs.failureIcon(), capitalize(res.err.Error()))
		} else {
			fmt.Fprintf(out, "%s Verified SLSA build provenance\n", cs.successIcon())
			printProvenanceDetails(e, res.cert)
		}
		if res.digest != "" {
			digests[res.asset.Name] = res.digest
		}
		if !ok {
			unverified++
		}
	}
	fmt.Fprintln(out)
	if unverified > 0 {
		problems = append(problems, fmt.Sprintf("%s failed verification", pluralize(unverified, "asset")))
	}

	if !e.canPrompt {
		if len(problems) > 0 {
			return nil, fmt.Errorf("refusing to download: %s; run `gh release download` to download without verifying",
				strings.Join(problems, " and "))
		}
		return digests, nil
	}

	question := fmt.Sprintf("Download %s?", pluralize(len(assets), "asset"))
	if len(assets) == 1 {
		question = fmt.Sprintf("Download %s?", assets[0].Name)
	}
	ok, err := e.confirm(question, len(problems) == 0)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errCancel
	}
	return digests, nil
}

func printProvenanceDetails(e *env, cert *certificate.Summary) {
	sourceRepo := cert.SourceRepositoryURI
	rows := [][2]string{
		{"Build instructions", workflowURL(sourceRepo, cert.BuildConfigURI, cert.BuildConfigDigest)},
	}
	if cert.BuildSignerURI != "" && cert.BuildSignerURI != cert.BuildConfigURI {
		rows = append(rows, [2]string{"Signer workflow", cert.BuildSignerURI})
	}
	source := sourceRepo
	if cert.SourceRepositoryDigest != "" {
		source = fmt.Sprintf("%s/tree/%s", sourceRepo, cert.SourceRepositoryDigest)
	}
	rows = append(rows,
		[2]string{"Source", source},
		[2]string{"Source ref", cert.SourceRepositoryRef},
	)
	if cert.RunInvocationURI != "" {
		rows = append(rows, [2]string{"Build run", cert.RunInvocationURI})
	}
	if cert.RunnerEnvironment != "" {
		runner := cert.RunnerEnvironment
		if runner != githubHostedRunner {
			runner = e.colors.yellow(runner)
		}
		rows = append(rows, [2]string{"Runner", runner})
	}

	width := 0
	for _, row := range rows {
		width = max(width, len(row[0]))
	}
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(e.stderr, "  - %-*s %s\n", width+1, row[0]+":", row[1])
	}
}

// workflowURL turns a certificate workflow URI such as
// https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/heads/main
// into a browsable link pinned to the commit that ran it.
func workflowURL(sourceRepo, configURI, configDigest string) string {
	path, ok := strings.CutPrefix(configURI, sourceRepo+"/")
	if !ok || configDigest == "" {
		return configURI
	}
	path = workflowRefSuffix.ReplaceAllString(path, "")
	return fmt.Sprintf("%s/blob/%s/%s", sourceRepo, configDigest, path)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func pluralize(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
