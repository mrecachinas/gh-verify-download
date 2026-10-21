package main

import (
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/cli/go-gh/v2/pkg/config"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// The TUF root for GitHub's Sigstore instance, as embedded in gh.
//
//go:embed embed/tuf-repo.github.com/root.json
var githubTUFRoot []byte

const (
	githubTUFMirror     = "https://tuf-repo.github.com"
	publicGoodIssuerOrg = "sigstore.dev"
	githubIssuerOrg     = "GitHub, Inc."
)

// bundleVerifier checks a Sigstore bundle's signature against a policy.
type bundleVerifier interface {
	// Verify verifies b. Bundles signed by the Sigstore public good instance
	// are only accepted when allowPublicGood is true.
	Verify(b *bundle.Bundle, policy verify.PolicyBuilder, allowPublicGood bool) (*verify.VerificationResult, error)
}

// sigstoreVerifier picks GitHub's or the public good trusted root from the
// bundle's certificate issuer, the same way gh attestation verify does. Each
// root is fetched over TUF the first time it is needed.
type sigstoreVerifier struct {
	trustDomain func() (string, error)
	httpClient  *http.Client

	githubOnce, publicGoodOnce sync.Once
	github, publicGood         *verify.Verifier
	githubErr, publicGoodErr   error
}

func (v *sigstoreVerifier) Verify(b *bundle.Bundle, policy verify.PolicyBuilder, allowPublicGood bool) (*verify.VerificationResult, error) {
	issuer, err := bundleIssuer(b)
	if err != nil {
		return nil, err
	}

	var verifier *verify.Verifier
	switch issuer {
	case githubIssuerOrg:
		v.githubOnce.Do(func() { v.github, v.githubErr = v.newGitHubVerifier() })
		verifier, err = v.github, v.githubErr
	case publicGoodIssuerOrg:
		if !allowPublicGood {
			return nil, errors.New("detected public good instance but requested verification without public good instance")
		}
		v.publicGoodOnce.Do(func() { v.publicGood, v.publicGoodErr = v.newPublicGoodVerifier() })
		verifier, err = v.publicGood, v.publicGoodErr
	default:
		return nil, errors.New("leaf certificate issuer is not recognized")
	}
	if err != nil {
		return nil, err
	}

	result, err := verifier.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("verifying with issuer %q", issuer)
	}
	return result, nil
}

func bundleIssuer(b *bundle.Bundle) (string, error) {
	if !b.MinVersion("0.2") {
		return "", fmt.Errorf("unsupported bundle version: %s", b.MediaType)
	}
	content, err := b.VerificationContent()
	if err != nil {
		return "", fmt.Errorf("failed to get bundle verification content: %w", err)
	}
	cert := content.Certificate()
	if cert == nil {
		return "", errors.New("leaf cert not found")
	}
	if len(cert.Issuer.Organization) != 1 {
		return "", errors.New("expected the leaf certificate issuer to only have one organization")
	}
	return cert.Issuer.Organization[0], nil
}

func (v *sigstoreVerifier) tufOptions() *tuf.Options {
	opts := tuf.DefaultOptions()
	// Share gh's TUF cache.
	opts.CachePath = filepath.Join(config.CacheDir(), ".sigstore", "root")
	opts.CacheValidity = 1
	if os.Getenv("CODESPACES") == "true" {
		opts.DisableLocalCache = true
	}
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(v.httpClient)
	opts.WithFetcher(f)
	return opts
}

func (v *sigstoreVerifier) newGitHubVerifier() (*verify.Verifier, error) {
	td, err := v.trustDomain()
	if err != nil {
		return nil, fmt.Errorf("error getting trust domain: %w", err)
	}
	opts := v.tufOptions()
	opts.Root = githubTUFRoot
	opts.RepositoryBaseURL = githubTUFMirror
	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	target := "trusted_root.json"
	if td != "" {
		target = td + ".trusted_root.json"
	}
	data, err := client.GetTarget(target)
	if err != nil {
		return nil, err
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, err
	}
	return verify.NewVerifier(trustedRoot, verify.WithSignedTimestamps(1))
}

func (v *sigstoreVerifier) newPublicGoodVerifier() (*verify.Verifier, error) {
	client, err := tuf.New(v.tufOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}
	return verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1))
}
