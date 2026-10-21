package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/cli/go-gh/v2/pkg/config"
	"github.com/cli/go-gh/v2/pkg/prompter"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/cli/go-gh/v2/pkg/term"
)

// env holds everything run needs from the outside world, so tests can
// replace it.
type env struct {
	api       githubAPI
	verifier  bundleVerifier
	stdout    io.Writer
	stderr    io.Writer
	stdoutTTY bool
	canPrompt bool
	colors    colorScheme
	confirm   func(prompt string, defaultValue bool) (bool, error)
	// trustDomain returns the host's attestation trust domain ("" for github.com).
	trustDomain func() (string, error)
	err         error
}

func newLiveEnv(repo repository.Repository) *env {
	stdoutTTY := term.IsTerminal(os.Stdout)
	e := &env{
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		stdoutTTY: stdoutTTY,
		canPrompt: stdoutTTY && term.IsTerminal(os.Stdin) && !promptDisabled(),
		colors:    colorScheme{enabled: stdoutTTY && os.Getenv("NO_COLOR") == ""},
	}
	p := prompter.New(os.Stdin, os.Stdout, os.Stderr)
	e.confirm = p.Confirm

	client, err := newLiveAPI(repo)
	if err != nil {
		e.err = err
		return e
	}
	e.api = client
	var once sync.Once
	var td string
	var tdErr error
	e.trustDomain = func() (string, error) {
		once.Do(func() { td, tdErr = client.TrustDomain() })
		return td, tdErr
	}
	e.verifier = &sigstoreVerifier{httpClient: &http.Client{}, trustDomain: e.trustDomain}
	return e
}

func checkHostSupported(host string) error {
	if auth.IsEnterprise(host) {
		return fmt.Errorf("`verify-download` is not supported for %s: artifact attestations are not available on GitHub Enterprise Server", host)
	}
	return nil
}

func promptDisabled() bool {
	if os.Getenv("GH_PROMPT_DISABLED") != "" {
		return true
	}
	cfg, err := config.Read(nil)
	if err != nil {
		return false
	}
	v, _ := cfg.Get([]string{"prompt"})
	return v == "disabled"
}

func run(opts *options, e *env) error {
	if e.err != nil {
		return e.err
	}
	host := opts.Repo.Host
	if err := checkHostSupported(host); err != nil {
		return err
	}

	r, err := e.api.Release(opts.TagName)
	if err != nil {
		return err
	}

	var toDownload []asset
	for _, a := range r.Assets {
		if opts.AssetName != "" && a.Name != opts.AssetName {
			continue
		}
		if len(opts.Patterns) > 0 && !matchAny(opts.Patterns, a.Name) {
			continue
		}
		if runtime.GOOS == "windows" && isWindowsReservedFilename(a.Name) {
			return fmt.Errorf("unable to download release due to asset with reserved filename %q", a.Name)
		}
		toDownload = append(toDownload, a)
	}
	if len(toDownload) == 0 {
		if opts.AssetName != "" {
			return fmt.Errorf("release %s has no asset named %q", r.TagName, opts.AssetName)
		}
		if len(r.Assets) > 0 {
			return errors.New("no assets match the file pattern")
		}
		return errors.New("no assets to download")
	}
	if len(toDownload) > 1 && opts.OutputFile != "" {
		return fmt.Errorf("unable to write more than one asset with `--output`, got %d assets", len(toDownload))
	}

	tenant, _ := strings.CutSuffix(host, ".ghe.com")
	if tenant == host {
		tenant = ""
	}
	td := e.trustDomain
	if td == nil {
		td = func() (string, error) { return "", nil }
	}
	c := &checker{
		api:         e.api,
		verifier:    e.verifier,
		owner:       opts.Repo.Owner,
		repo:        opts.Repo.Name,
		tenant:      tenant,
		trustDomain: td,
	}
	digests, err := confirmProvenance(e, c, r, toDownload)
	if err != nil {
		return err
	}

	dest := &destination{
		file:         opts.OutputFile,
		dir:          opts.Destination,
		clobber:      opts.Clobber,
		skipExisting: opts.SkipExisting,
		stdout:       e.stdout,
		stdoutTTY:    e.stdoutTTY,
		allowEscapes: opts.AllowEscapes,
	}
	return downloadVerified(e.api, dest, toDownload, digests, opts.Concurrency)
}

// downloadVerified downloads assets into a private staging directory and
// checks each one against its expected digest there. Only once every asset
// has passed are they written to the destination, one at a time. A failed
// check therefore leaves the destination untouched, nothing unchecked reaches
// standard output, and concurrent downloads never share a destination file.
func downloadVerified(client githubAPI, dest *destination, assets []asset, digests map[string]string, concurrency int) error {
	seen := make(map[string]string, len(assets))
	var pending []asset
	for _, a := range assets {
		if err := validateName(a.Name); err != nil {
			return err
		}
		folded := strings.ToLower(a.Name)
		if other, ok := seen[folded]; ok {
			return fmt.Errorf("assets %q and %q differ only in case and cannot both be downloaded", other, a.Name)
		}
		seen[folded] = a.Name

		if err := dest.check(a.Name); errors.Is(err, errSkipped) {
			continue
		} else if err != nil {
			return err
		}
		pending = append(pending, a)
	}
	if len(pending) == 0 {
		return nil
	}
	if err := dest.checkHardLinks(pending); err != nil {
		return err
	}

	stagingDir, err := os.MkdirTemp("", "gh-verify-download-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)

	sem := make(chan struct{}, max(concurrency, 1))
	errs := make([]error, len(pending))
	var wg sync.WaitGroup
	for i, a := range pending {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			errs[i] = stageAsset(client, stagingDir, a, digests[a.Name])
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}

	for _, a := range pending {
		if err := publish(dest, filepath.Join(stagingDir, a.Name), a.Name); err != nil {
			return err
		}
	}
	return nil
}

func stageAsset(client githubAPI, dir string, a asset, expectedDigest string) error {
	f, err := os.OpenFile(filepath.Join(dir, a.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	err = client.Download(a.URL, io.MultiWriter(f, hasher))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("downloading %s: %w", a.Name, err)
	}
	if expectedDigest == "" {
		return nil
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != expectedDigest {
		return fmt.Errorf("downloaded %s does not match its attested digest (expected sha256:%s, got sha256:%s); nothing was saved", a.Name, expectedDigest, actual)
	}
	return nil
}

func publish(dest *destination, stagedPath, name string) error {
	f, err := os.Open(stagedPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return dest.write(name, f)
}

var errSkipped = errors.New("skipped")

// destination writes verified assets to a directory, a single file, or
// standard output.
type destination struct {
	file         string
	dir          string
	clobber      bool
	skipExisting bool
	stdout       io.Writer
	stdoutTTY    bool
	allowEscapes bool
}

// isStdout reports whether output goes to standard output. Only an explicit
// "--output -" means that; an asset that happens to be named "-" is a file.
func (d *destination) isStdout() bool { return d.file == "-" }

func (d *destination) path(name string) string {
	if d.file != "" {
		return d.file
	}
	return filepath.Join(d.dir, name)
}

func (d *destination) check(name string) error {
	if d.isStdout() {
		return nil
	}
	fp := d.path(name)
	if _, err := os.Lstat(fp); err == nil {
		if d.skipExisting {
			return errSkipped
		}
		if !d.clobber {
			return fmt.Errorf("%s already exists (use `--clobber` to overwrite file or `--skip-existing` to skip file)", fp)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// checkHardLinks rejects existing destination files that are the same file on
// disk, since overwriting one would also overwrite the other with a different
// asset's content.
func (d *destination) checkHardLinks(assets []asset) error {
	if d.isStdout() {
		return nil
	}
	type existing struct {
		path string
		info os.FileInfo
	}
	var seen []existing
	for _, a := range assets {
		fp := d.path(a.Name)
		info, err := os.Lstat(fp)
		if err != nil {
			continue
		}
		for _, e := range seen {
			if os.SameFile(e.info, info) {
				return fmt.Errorf("%s and %s are the same file on disk (hard links), so one asset would overwrite the other", e.path, fp)
			}
		}
		seen = append(seen, existing{fp, info})
	}
	return nil
}

func (d *destination) write(name string, r io.Reader) error {
	if d.isStdout() {
		return d.writeStdout(r)
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !d.clobber {
		flags |= os.O_EXCL
	}
	var f *os.File
	var err error
	if d.file != "" {
		if err := os.MkdirAll(filepath.Dir(d.file), 0o755); err != nil {
			return err
		}
		f, err = os.OpenFile(d.file, flags, 0o644)
	} else {
		if err := os.MkdirAll(d.dir, 0o755); err != nil {
			return err
		}
		// os.Root refuses paths, including symlinks, that leave the directory.
		var root *os.Root
		root, err = os.OpenRoot(d.dir)
		if err != nil {
			return err
		}
		defer root.Close()
		f, err = root.OpenFile(name, flags, 0o644)
	}
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists (use `--clobber` to overwrite file or `--skip-existing` to skip file)", d.path(name))
		}
		return err
	}
	_, err = io.Copy(f, r)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// writeStdout refuses binary content bound for a terminal, and text containing
// terminal escape sequences, unless --allow-escape-sequences is set. This
// matches gh release download.
func (d *destination) writeStdout(r io.Reader) error {
	if d.allowEscapes {
		_, err := io.Copy(d.stdout, r)
		return err
	}
	head := make([]byte, 512)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	head = head[:n]

	if mime, ok := binaryContentType(head); ok {
		if d.stdoutTTY {
			return fmt.Errorf("refusing to output binary content (%s) to the terminal; use `--output` to save it to a file, or pass --allow-escape-sequences to output it anyway", mime)
		}
		if _, err := d.stdout.Write(head); err != nil {
			return err
		}
		_, err := io.Copy(d.stdout, r)
		return err
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	content := append(head, rest...)
	if slices.Contains(content, 0x1B) {
		return errors.New("the asset contains terminal escape sequences; use `--output` to save it to a file, or pass --allow-escape-sequences to output it anyway")
	}
	_, err = d.stdout.Write(content)
	return err
}

func binaryContentType(content []byte) (string, bool) {
	if len(content) == 0 {
		return "", false
	}
	ct := http.DetectContentType(content)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.HasPrefix(ct, "text/") {
		return "", false
	}
	return ct, true
}

func validateName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("refusing to download asset with unsafe name %q", name)
	}
	return nil
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, err := filepath.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}

func isWindowsReservedFilename(filename string) bool {
	reserved := []string{"CON", "PRN", "AUX", "NUL", "COM0",
		"COM1", "COM2", "COM3", "COM4", "COM5",
		"COM6", "COM7", "COM8", "COM9", "COM¹",
		"COM²", "COM³", "LPT0", "LPT1", "LPT2",
		"LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
		"LPT8", "LPT9", "LPT¹", "LPT²", "LPT³"}
	return slices.Contains(reserved, strings.ToUpper(strings.Split(filename, ".")[0]))
}

type colorScheme struct{ enabled bool }

func (c colorScheme) wrap(code, s string) string {
	if !c.enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c colorScheme) bold(s string) string   { return c.wrap("1", s) }
func (c colorScheme) yellow(s string) string { return c.wrap("33", s) }
func (c colorScheme) successIcon() string    { return c.wrap("32", "✓") }
func (c colorScheme) warningIcon() string    { return c.wrap("33", "!") }
func (c colorScheme) failureIcon() string    { return c.wrap("31", "X") }
