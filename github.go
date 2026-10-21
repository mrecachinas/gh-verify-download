package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/klauspost/compress/snappy"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

var errNotFound = errors.New("not found")

type release struct {
	ID        int64   `json:"id"`
	TagName   string  `json:"tag_name"`
	Immutable bool    `json:"immutable"`
	Assets    []asset `json:"assets"`
}

type asset struct {
	Name   string  `json:"name"`
	URL    string  `json:"url"`
	Digest *string `json:"digest"`
}

type attestation struct {
	Bundle    *bundle.Bundle
	Initiator string
}

// githubAPI is the subset of the GitHub API this extension uses.
type githubAPI interface {
	Release(tag string) (*release, error)
	RefSHA(tag string) (string, error)
	Attestations(digest, predicateType string) ([]*attestation, error)
	TrustDomain() (string, error)
	Download(assetURL string, w io.Writer) error
}

type liveAPI struct {
	repo     repository.Repository
	rest     *api.RESTClient
	http     *http.Client
	external *http.Client
}

func newLiveAPI(repo repository.Repository) (*liveAPI, error) {
	opts := api.ClientOptions{Host: repo.Host}
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		return nil, err
	}
	httpClient, err := api.NewHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	return &liveAPI{
		repo:     repo,
		rest:     rest,
		http:     httpClient,
		external: &http.Client{Timeout: 2 * time.Minute},
	}, nil
}

func (c *liveAPI) repoPath(elem ...string) string {
	parts := []string{"repos", url.PathEscape(c.repo.Owner), url.PathEscape(c.repo.Name)}
	return strings.Join(append(parts, elem...), "/")
}

func (c *liveAPI) Release(tag string) (*release, error) {
	path := c.repoPath("releases", "latest")
	if tag != "" {
		path = c.repoPath("releases", "tags", url.PathEscape(tag))
	}
	var r release
	if err := c.rest.Get(path, &r); err != nil {
		if isNotFound(err) {
			return nil, errors.New("release not found")
		}
		return nil, err
	}
	return &r, nil
}

func (c *liveAPI) RefSHA(tag string) (string, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := c.rest.Get(c.repoPath("git", "ref", url.PathEscape("tags/"+tag)), &ref); err != nil {
		return "", err
	}
	return ref.Object.SHA, nil
}

func (c *liveAPI) TrustDomain() (string, error) {
	var meta struct {
		Domains struct {
			ArtifactAttestations struct {
				TrustDomain string `json:"trust_domain"`
			} `json:"artifact_attestations"`
		} `json:"domains"`
	}
	if err := c.rest.Get("meta", &meta); err != nil {
		return "", err
	}
	return meta.Domains.ArtifactAttestations.TrustDomain, nil
}

// Attestations returns the attestations GitHub has for a subject digest in
// this repository, or errNotFound if there are none.
func (c *liveAPI) Attestations(digest, predicateType string) ([]*attestation, error) {
	q := url.Values{"per_page": {"100"}}
	if predicateType != "" {
		q.Set("predicate_type", predicateType)
	}
	var resp struct {
		Attestations []struct {
			Bundle    json.RawMessage `json:"bundle"`
			BundleURL string          `json:"bundle_url"`
			Initiator string          `json:"initiator"`
		} `json:"attestations"`
	}
	if err := c.rest.Get(c.repoPath("attestations", url.PathEscape(digest))+"?"+q.Encode(), &resp); err != nil {
		if isNotFound(err) {
			return nil, errNotFound
		}
		return nil, err
	}
	if len(resp.Attestations) == 0 {
		return nil, errNotFound
	}

	out := make([]*attestation, 0, len(resp.Attestations))
	for _, a := range resp.Attestations {
		var b *bundle.Bundle
		var err error
		if a.BundleURL != "" {
			b, err = c.fetchBundle(a.BundleURL)
		} else if len(a.Bundle) > 0 && string(a.Bundle) != "null" {
			b = &bundle.Bundle{}
			err = b.UnmarshalJSON(a.Bundle)
		} else {
			err = errors.New("attestation has no bundle")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to load attestation bundle: %w", err)
		}
		out = append(out, &attestation{Bundle: b, Initiator: a.Initiator})
	}
	return out, nil
}

// fetchBundle downloads a snappy-compressed bundle from blob storage. The URL
// is pre-signed, so no GitHub credentials are sent.
func (c *liveAPI) fetchBundle(bundleURL string) (*bundle.Bundle, error) {
	resp, err := c.external.Get(bundleURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching bundle returned HTTP %d", resp.StatusCode)
	}
	compressed, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	raw, err := snappy.Decode(nil, compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress bundle: %w", err)
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}
	return bundle.NewBundle(&pb)
}

func (c *liveAPI) Download(assetURL string, w io.Writer) error {
	req, err := http.NewRequest(http.MethodGet, assetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading asset returned HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func isNotFound(err error) bool {
	var httpErr *api.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
}

// parseReleaseAssetURL parses a URL of the form
// https://HOST/OWNER/REPO/releases/download/TAG/ASSET
func parseReleaseAssetURL(s string) (repository.Repository, string, string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return repository.Repository{}, "", "", fmt.Errorf("invalid release asset URL %q", s)
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) < 6 || segments[2] != "releases" || segments[3] != "download" {
		return repository.Repository{}, "", "", fmt.Errorf("expected a release asset URL like https://github.com/OWNER/REPO/releases/download/TAG/ASSET, got %q", s)
	}
	tag := strings.Join(segments[4:len(segments)-1], "/")
	name := segments[len(segments)-1]
	if segments[0] == "" || segments[1] == "" || tag == "" || name == "" {
		return repository.Repository{}, "", "", fmt.Errorf("invalid release asset URL %q", s)
	}
	return repository.Repository{Host: u.Hostname(), Owner: segments[0], Name: segments[1]}, tag, name, nil
}

func isURLArg(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}
