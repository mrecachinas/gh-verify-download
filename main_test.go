package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func Test_parseReleaseAssetURL(t *testing.T) {
	tests := []struct {
		url, wantRepo, wantHost, wantTag, wantAsset string
		wantErr                                     bool
	}{
		{url: "https://github.com/vektra/mockery/releases/download/v2.53.8/mockery_2.53.8_Darwin_arm64.tar.gz",
			wantRepo: "vektra/mockery", wantHost: "github.com", wantTag: "v2.53.8", wantAsset: "mockery_2.53.8_Darwin_arm64.tar.gz"},
		{url: "https://github.com/OWNER/REPO/releases/download/pkg/v1.0.0/app.zip",
			wantRepo: "OWNER/REPO", wantHost: "github.com", wantTag: "pkg/v1.0.0", wantAsset: "app.zip"},
		{url: "https://github.com/OWNER/REPO/releases/download/v1%2B1/my%20app.zip",
			wantRepo: "OWNER/REPO", wantHost: "github.com", wantTag: "v1+1", wantAsset: "my app.zip"},
		{url: "https://acme.ghe.com/OWNER/REPO/releases/download/v1/app.zip",
			wantRepo: "OWNER/REPO", wantHost: "acme.ghe.com", wantTag: "v1", wantAsset: "app.zip"},
		{url: "https://github.com/OWNER/REPO/releases/tag/v1", wantErr: true},
		{url: "https://github.com/OWNER/REPO/releases/download/v1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			repo, tag, name, err := parseReleaseAssetURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepo, repo.Owner+"/"+repo.Name)
			assert.Equal(t, tt.wantHost, repo.Host)
			assert.Equal(t, tt.wantTag, tag)
			assert.Equal(t, tt.wantAsset, name)
		})
	}
}

func Test_workflowURL(t *testing.T) {
	assert.Equal(t,
		"https://github.com/o/r/blob/abc/.github/workflows/release.yml",
		workflowURL("https://github.com/o/r", "https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1", "abc"))
	assert.Equal(t,
		"https://github.com/other/wf/.github/workflows/build.yml@refs/heads/main",
		workflowURL("https://github.com/o/r", "https://github.com/other/wf/.github/workflows/build.yml@refs/heads/main", "abc"))
}

type fakeAPI struct {
	release *release
	refSHA  string
	attest  func(digest, predicateType string) ([]*attestation, error)
	bodies  map[string]string

	mu         sync.Mutex
	downloaded []string
}

func (f *fakeAPI) Release(string) (*release, error) { return f.release, nil }
func (f *fakeAPI) RefSHA(string) (string, error)    { return f.refSHA, nil }
func (f *fakeAPI) TrustDomain() (string, error)     { return "", nil }
func (f *fakeAPI) Attestations(digest, predicateType string) ([]*attestation, error) {
	return f.attest(digest, predicateType)
}
func (f *fakeAPI) Download(assetURL string, w io.Writer) error {
	f.mu.Lock()
	f.downloaded = append(f.downloaded, assetURL)
	f.mu.Unlock()
	body, ok := f.bodies[assetURL]
	if !ok {
		return fmt.Errorf("unexpected download of %s", assetURL)
	}
	_, err := io.WriteString(w, body)
	return err
}

// fakeVerifier returns canned results; release attestations are the only
// ones verified without the public good instance.
type fakeVerifier struct {
	provenance *verify.VerificationResult
	provErr    error
	release    *verify.VerificationResult
	releaseErr error
}

func (v fakeVerifier) Verify(_ *bundle.Bundle, _ verify.PolicyBuilder, allowPublicGood bool) (*verify.VerificationResult, error) {
	if !allowPublicGood {
		if v.release == nil && v.releaseErr == nil {
			return nil, errors.New("release verifier should not be called")
		}
		return v.release, v.releaseErr
	}
	return v.provenance, v.provErr
}

func provenanceFor(sourceRepoURI string) *verify.VerificationResult {
	return &verify.VerificationResult{
		Statement: &in_toto.Statement{PredicateType: slsaPredicateV1},
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{
				Issuer:                   githubOIDCIssuer,
				SourceRepositoryURI:      sourceRepoURI,
				SourceRepositoryOwnerURI: sourceRepoURI[:strings.LastIndex(sourceRepoURI, "/")],
				SourceRepositoryDigest:   "abc123",
				SourceRepositoryRef:      "refs/tags/v6",
				BuildConfigURI:           sourceRepoURI + "/.github/workflows/release.yml@refs/tags/v6",
				BuildConfigDigest:        "abc123",
				BuildSignerURI:           sourceRepoURI + "/.github/workflows/release.yml@refs/tags/v6",
				RunInvocationURI:         sourceRepoURI + "/actions/runs/1/attempts/1",
				RunnerEnvironment:        githubHostedRunner,
			},
		},
	}
}

func releaseResult(t *testing.T, tag, releaseID string, subjects map[string]string) *verify.VerificationResult {
	t.Helper()
	pred, err := structpb.NewStruct(map[string]any{"tag": tag, "databaseId": releaseID})
	require.NoError(t, err)
	st := &in_toto.Statement{PredicateType: "https://in-toto.io/attestation/release/v0.2", Predicate: pred}
	for name, digest := range subjects {
		st.Subject = append(st.Subject, &in_toto.ResourceDescriptor{Name: name, Digest: map[string]string{"sha256": digest}})
	}
	return &verify.VerificationResult{Statement: st}
}

// The release attestation test bundle is for tag v6.
const testTag = "v6"

func newTestAPI(t *testing.T, immutable, hasReleaseAtt, hasProvenance bool, assets []asset, bodies map[string]string) *fakeAPI {
	releaseBundle, err := bundle.LoadJSONFromPath("testdata/github_release_bundle.json")
	require.NoError(t, err)
	return &fakeAPI{
		release: &release{ID: 42, TagName: testTag, Immutable: immutable, Assets: assets},
		refSHA:  "c5e17a62e06a1d201570249c61fae531e9244e1b",
		bodies:  bodies,
		attest: func(digest, predicateType string) ([]*attestation, error) {
			if predicateType == "release" {
				assert.Equal(t, "sha1:c5e17a62e06a1d201570249c61fae531e9244e1b", digest)
				if !hasReleaseAtt {
					return nil, errNotFound
				}
				return []*attestation{{Bundle: releaseBundle, Initiator: "github"}}, nil
			}
			assert.Equal(t, slsaPredicateV1, predicateType)
			if !hasProvenance {
				return nil, errNotFound
			}
			return []*attestation{{}}, nil
		},
	}
}

func digestPtr(s string) *string { return &s }

func Test_run(t *testing.T) {
	appAsset := []asset{
		{Name: "app.zip", URL: "https://api.github.com/assets/1", Digest: digestPtr("sha256:" + sum("hello"))},
		{Name: "other.zip", URL: "https://api.github.com/assets/2", Digest: digestPtr("sha256:0000")},
	}
	good := provenanceFor("https://github.com/OWNER/REPO")
	goodRelease := func(t *testing.T) *verify.VerificationResult {
		return releaseResult(t, testTag, "42", map[string]string{"app.zip": sum("hello")})
	}

	tests := []struct {
		name          string
		interactive   bool
		output        string
		immutable     bool
		hasReleaseAtt bool
		release       func(t *testing.T) *verify.VerificationResult
		releaseErr    error
		hasProvenance bool
		provenance    *verify.VerificationResult
		provErr       error
		confirm       func(string, bool) (bool, error)
		body          string
		wantErr       string
		wantStderr    []string
		wantStdout    string
		wantFile      bool
	}{
		{
			name: "immutable release with verified attestations downloads", immutable: true, hasReleaseAtt: true,
			release: goodRelease, hasProvenance: true, provenance: good, body: "hello",
			wantStderr: []string{
				"OWNER/REPO v6",
				"✓ Immutable release, verified by GitHub's signed release attestation",
				"✓ Listed in the signed release attestation",
				"✓ Verified SLSA build provenance",
				"Build instructions: https://github.com/OWNER/REPO/blob/abc123/.github/workflows/release.yml",
				"Source:             https://github.com/OWNER/REPO/tree/abc123",
				"Source ref:         refs/tags/v6",
				"Build run:          https://github.com/OWNER/REPO/actions/runs/1/attempts/1",
			},
			wantFile: true,
		},
		{
			name: "mutable release with verified provenance downloads", hasProvenance: true, provenance: good, body: "hello",
			wantStderr: []string{"! Not an immutable release"}, wantFile: true,
		},
		{
			name:       "missing provenance refuses",
			wantErr:    "refusing to download: 1 asset failed verification",
			wantStderr: []string{"X No build provenance attestation found"},
		},
		{
			name: "provenance from another repository is rejected", hasProvenance: true,
			provenance: provenanceFor("https://github.com/EVIL/REPO"),
			wantErr:    "refusing to download", wantStderr: []string{"X Attestation was not built from OWNER/REPO"},
		},
		{
			name: "provenance signature failure is rejected", hasProvenance: true, provErr: errors.New("bad signature"),
			wantErr: "refusing to download", wantStderr: []string{"X Attestation signature verification failed: bad signature"},
		},
		{
			name: "immutable release without a release attestation is rejected", immutable: true,
			hasProvenance: true, provenance: good,
			wantErr:    "refusing to download: the release attestation could not be verified",
			wantStderr: []string{"X Release is marked immutable, but no signed release attestation found"},
		},
		{
			name: "release attestation signature failure is rejected", immutable: true, hasReleaseAtt: true,
			releaseErr: errors.New("bad signature"), hasProvenance: true, provenance: good,
			wantErr:    "the release attestation could not be verified",
			wantStderr: []string{"release attestation verification failed: bad signature"},
		},
		{
			name: "release attestation for a different release is rejected", immutable: true, hasReleaseAtt: true,
			release: func(t *testing.T) *verify.VerificationResult {
				return releaseResult(t, testTag, "99", map[string]string{"app.zip": sum("hello")})
			},
			hasProvenance: true, provenance: good,
			wantErr:    "the release attestation could not be verified",
			wantStderr: []string{`release attestation is for release ID "99", not 42`},
		},
		{
			name: "asset missing from the release attestation is rejected", immutable: true, hasReleaseAtt: true,
			release: func(t *testing.T) *verify.VerificationResult {
				return releaseResult(t, testTag, "42", map[string]string{"other.zip": sum("hello")})
			},
			hasProvenance: true, provenance: good,
			wantErr:    "refusing to download: 1 asset failed verification",
			wantStderr: []string{"X Not listed in the signed release attestation"},
		},
		{
			name: "asset digest differing from the release attestation is rejected", immutable: true, hasReleaseAtt: true,
			release: func(t *testing.T) *verify.VerificationResult {
				return releaseResult(t, testTag, "42", map[string]string{"app.zip": "ffff"})
			},
			hasProvenance: true, provenance: good,
			wantErr:    "refusing to download: 1 asset failed verification",
			wantStderr: []string{"X Digest differs from the signed release attestation (sha256:ffff)"},
		},
		{
			name: "downloaded content not matching the attested digest is not saved", hasProvenance: true, provenance: good,
			body: "tampered", wantErr: "does not match its attested digest",
		},
		{
			name: "interactive decline cancels", interactive: true,
			confirm: func(prompt string, def bool) (bool, error) {
				assert.Equal(t, "Download app.zip?", prompt)
				assert.False(t, def)
				return false, nil
			},
			wantErr: errCancel.Error(),
		},
		{
			name: "interactive accept downloads despite missing provenance", interactive: true,
			confirm: func(string, bool) (bool, error) { return true, nil }, body: "hello", wantFile: true,
		},
		{
			name: "interactive accept still checks the downloaded digest", interactive: true,
			confirm: func(string, bool) (bool, error) { return true, nil }, body: "tampered",
			wantErr: "does not match its attested digest",
		},
		{
			name: "verified asset is written to standard output", output: "-", hasProvenance: true, provenance: good,
			body: "hello", wantStdout: "hello",
		},
		{
			name: "tampered asset is not written to standard output", output: "-", hasProvenance: true, provenance: good,
			body: "tampered", wantErr: "does not match its attested digest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bodies := map[string]string{}
			if tt.body != "" {
				bodies["https://api.github.com/assets/1"] = tt.body
			}
			api := newTestAPI(t, tt.immutable, tt.hasReleaseAtt, tt.hasProvenance, appAsset, bodies)
			v := fakeVerifier{provenance: tt.provenance, provErr: tt.provErr, releaseErr: tt.releaseErr}
			if tt.release != nil {
				v.release = tt.release(t)
			}
			var stdout, stderr bytes.Buffer
			e := &env{
				api: api, verifier: v, stdout: &stdout, stderr: &stderr,
				canPrompt: tt.interactive, confirm: tt.confirm,
			}
			opts := &options{
				Repo:    repository.Repository{Host: "github.com", Owner: "OWNER", Name: "REPO"},
				TagName: testTag, AssetName: "app.zip", Destination: dir, OutputFile: tt.output, Concurrency: 1,
			}

			err := run(opts, e)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			for _, s := range tt.wantStderr {
				assert.Contains(t, stderr.String(), s)
			}
			assert.Equal(t, tt.wantStdout, stdout.String())
			if tt.body == "" {
				assert.Empty(t, api.downloaded, "nothing should be downloaded")
			}
			_, statErr := os.Stat(filepath.Join(dir, "app.zip"))
			if tt.wantFile {
				assert.NoError(t, statErr)
			} else {
				assert.True(t, os.IsNotExist(statErr), "expected app.zip not to exist")
			}
		})
	}
}

func Test_run_multipleAssets(t *testing.T) {
	tests := []struct {
		name      string
		assets    []string
		served    map[string]string
		existing  map[string]string
		link      [2]string
		clobber   bool
		wantErr   string
		wantFiles map[string]string // "" means the file must not exist
	}{
		{
			name:      "all verified assets are written",
			assets:    []string{"a.zip", "b.zip"},
			served:    map[string]string{"a.zip": "a.zip-content", "b.zip": "b.zip-content"},
			wantFiles: map[string]string{"a.zip": "a.zip-content", "b.zip": "b.zip-content"},
		},
		{
			name:      "one tampered asset leaves the destination untouched",
			assets:    []string{"a.zip", "b.zip"},
			served:    map[string]string{"a.zip": "a.zip-content", "b.zip": "tampered"},
			existing:  map[string]string{"a.zip": "old"},
			clobber:   true,
			wantErr:   "downloaded b.zip does not match its attested digest",
			wantFiles: map[string]string{"a.zip": "old", "b.zip": ""},
		},
		{
			name:    "assets differing only in case are rejected",
			assets:  []string{"App.zip", "app.zip"},
			wantErr: `assets "App.zip" and "app.zip" differ only in case`,
		},
		{
			name:      "hard-linked destinations are rejected",
			assets:    []string{"a.zip", "b.zip"},
			existing:  map[string]string{"a.zip": "old"},
			link:      [2]string{"a.zip", "b.zip"},
			clobber:   true,
			wantErr:   "are the same file on disk (hard links)",
			wantFiles: map[string]string{"a.zip": "old", "b.zip": "old"},
		},
		{
			name:      "existing file without --clobber is reported",
			assets:    []string{"a.zip"},
			existing:  map[string]string{"a.zip": "old"},
			wantErr:   "already exists (use `--clobber` to overwrite file or `--skip-existing` to skip file)",
			wantFiles: map[string]string{"a.zip": "old"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.existing {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
			}
			if tt.link[0] != "" {
				require.NoError(t, os.Link(filepath.Join(dir, tt.link[0]), filepath.Join(dir, tt.link[1])))
			}
			var assets []asset
			bodies := map[string]string{}
			for i, name := range tt.assets {
				u := fmt.Sprintf("https://api.github.com/assets/%d", i)
				assets = append(assets, asset{Name: name, URL: u, Digest: digestPtr("sha256:" + sum(name+"-content"))})
				if body, ok := tt.served[name]; ok {
					bodies[u] = body
				}
			}
			var stderr bytes.Buffer
			e := &env{
				api:      newTestAPI(t, false, false, true, assets, bodies),
				verifier: fakeVerifier{provenance: provenanceFor("https://github.com/OWNER/REPO")},
				stdout:   io.Discard, stderr: &stderr,
			}
			err := run(&options{
				Repo:    repository.Repository{Host: "github.com", Owner: "OWNER", Name: "REPO"},
				TagName: testTag, Patterns: []string{"*"}, Destination: dir, Clobber: tt.clobber, Concurrency: 2,
			}, e)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			for name, want := range tt.wantFiles {
				got, readErr := os.ReadFile(filepath.Join(dir, name))
				if want == "" {
					assert.True(t, os.IsNotExist(readErr), "expected %s not to exist", name)
				} else {
					require.NoError(t, readErr)
					assert.Equal(t, want, string(got))
				}
			}
		})
	}
}

func Test_run_assetNamedDashIsAFile(t *testing.T) {
	var stdout bytes.Buffer
	assets := []asset{{Name: "-", URL: "https://api.github.com/assets/1", Digest: digestPtr("sha256:" + sum("content"))}}
	api := newTestAPI(t, false, false, true, assets, map[string]string{"https://api.github.com/assets/1": "content"})
	dir := t.TempDir()
	t.Chdir(dir)
	e := &env{
		api:      api,
		verifier: fakeVerifier{provenance: provenanceFor("https://github.com/OWNER/REPO")},
		stdout:   &stdout, stderr: io.Discard,
	}
	err := run(&options{
		Repo:    repository.Repository{Host: "github.com", Owner: "OWNER", Name: "REPO"},
		TagName: testTag, Patterns: []string{"*"}, Destination: ".", Concurrency: 1,
	}, e)
	require.NoError(t, err)
	assert.Empty(t, stdout.String())
	got, err := os.ReadFile(filepath.Join(dir, "-"))
	require.NoError(t, err)
	assert.Equal(t, "content", string(got))
}

func Test_run_refusalMessage(t *testing.T) {
	assets := []asset{{Name: "app.zip", URL: "https://api.github.com/assets/1", Digest: digestPtr("sha256:" + sum("hello"))}}
	var stderr bytes.Buffer
	err := run(&options{
		Repo:    repository.Repository{Host: "github.com", Owner: "OWNER", Name: "REPO"},
		TagName: testTag, AssetName: "app.zip", Destination: t.TempDir(), Concurrency: 1,
	}, &env{api: newTestAPI(t, false, false, false, assets, nil), verifier: fakeVerifier{}, stdout: io.Discard, stderr: &stderr})
	assert.EqualError(t, err, "refusing to download: 1 asset failed verification")
}

func Test_run_unsupportedHost(t *testing.T) {
	err := run(&options{Repo: repository.Repository{Host: "ghes.example.com", Owner: "o", Name: "r"}}, &env{})
	assert.EqualError(t, err, "`verify-download` is not supported for ghes.example.com: artifact attestations are not available on GitHub Enterprise Server")
}

func Test_writeStdout(t *testing.T) {
	png := string(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 16)...))
	tests := []struct {
		name, content string
		tty, allow    bool
		wantErr       string
	}{
		{name: "text", content: "hello"},
		{name: "escape sequences refused", content: "\x1b[31mred", wantErr: "terminal escape sequences"},
		{name: "escape sequences allowed", content: "\x1b[31mred", allow: true},
		{name: "binary piped", content: png},
		{name: "binary to terminal refused", content: png, tty: true, wantErr: "refusing to output binary content (image/png) to the terminal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			d := &destination{file: "-", stdout: &out, stdoutTTY: tt.tty, allowEscapes: tt.allow}
			err := d.write("x", strings.NewReader(tt.content))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, out.String())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.content, out.String())
		})
	}
}
