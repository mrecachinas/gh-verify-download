// gh-verify-download checks a GitHub release's immutability and each asset's
// build provenance before downloading it.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/spf13/cobra"
)

type options struct {
	Repo         repository.Repository
	TagName      string
	AssetName    string
	Patterns     []string
	Destination  string
	OutputFile   string
	Clobber      bool
	SkipExisting bool
	AllowEscapes bool
	Concurrency  int
}

// errCancel signals that the user declined the download.
var errCancel = errors.New("cancelled")

type flagError struct{ error }

func main() {
	cmd := newCmd()
	if err := cmd.Execute(); err != nil {
		if errors.Is(err, errCancel) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, err)
		var fe flagError
		if errors.As(err, &fe) {
			fmt.Fprintln(os.Stderr)
			fmt.Fprint(os.Stderr, cmd.UsageString())
		}
		os.Exit(1)
	}
}

func newCmd() *cobra.Command {
	opts := &options{}
	var repoFlag string

	cmd := &cobra.Command{
		Use:   "verify-download [<tag> | <asset-url>]",
		Short: "Verify release immutability and build provenance, then download assets",
		Long: strings.TrimSpace(`
Download assets from a GitHub release after checking where they came from.

Before anything is downloaded, the release and each asset are checked:

- An immutable release must have a release attestation signed by GitHub
  that lists each asset's name and digest.
- Each asset's SLSA build provenance attestation must be signed by GitHub
  Actions and built from the release's repository. The workflow, source
  commit, and ref that built it are shown.

You are then asked to confirm the download; when not running interactively,
the command fails if any check fails. After downloading, each file is checked
against its digest. When writing to standard output, the asset is checked
before any of it is written.

Without a tag, assets are downloaded from the latest release and --pattern is
required. A release asset URL, such as one copied from a release page, can be
given instead of a tag to download that single asset.

Source archives and GitHub Enterprise Server are not supported.
`),
		Example: strings.TrimSpace(`
  # Check provenance before downloading an asset by its URL
  $ gh verify-download https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_macOS_arm64.zip

  # Download matching assets from a specific release
  $ gh verify-download v1.2.3 -R OWNER/REPO -p '*.tar.gz'
`),
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if len(opts.Patterns) == 0 {
					return flagError{errors.New("`--pattern` is required when downloading the latest release")}
				}
			} else if isURLArg(args[0]) {
				repo, tag, asset, err := parseReleaseAssetURL(args[0])
				if err != nil {
					return flagError{err}
				}
				if repoFlag != "" {
					return flagError{errors.New("`--repo` cannot be used with a release asset URL")}
				}
				if len(opts.Patterns) > 0 {
					return flagError{errors.New("`--pattern` cannot be used with a release asset URL")}
				}
				opts.Repo = repo
				opts.TagName = tag
				opts.AssetName = asset
			} else {
				opts.TagName = args[0]
			}

			if opts.Clobber && opts.SkipExisting {
				return flagError{errors.New("specify only one of `--clobber` or `--skip-existing`")}
			}
			if opts.Destination != "." && opts.OutputFile != "" {
				return flagError{errors.New("specify only one of `--dir` or `--output`")}
			}

			if opts.Repo.Name == "" {
				var err error
				if repoFlag != "" {
					opts.Repo, err = repository.Parse(repoFlag)
				} else {
					opts.Repo, err = repository.Current()
				}
				if err != nil {
					return fmt.Errorf("could not determine repository: %w", err)
				}
			}

			if err := checkHostSupported(opts.Repo.Host); err != nil {
				return err
			}
			opts.Concurrency = 5
			return run(opts, newLiveEnv(opts.Repo))
		},
	}

	cmd.Flags().StringVarP(&repoFlag, "repo", "R", "", "Select another repository using the `[HOST/]OWNER/REPO` format")
	cmd.Flags().StringVarP(&opts.OutputFile, "output", "O", "", "The `file` to write a single asset to (use \"-\" to write to standard output)")
	cmd.Flags().StringVarP(&opts.Destination, "dir", "D", ".", "The `directory` to download files into")
	cmd.Flags().StringArrayVarP(&opts.Patterns, "pattern", "p", nil, "Download only assets that match a glob pattern")
	cmd.Flags().BoolVar(&opts.Clobber, "clobber", false, "Overwrite existing files of the same name")
	cmd.Flags().BoolVar(&opts.SkipExisting, "skip-existing", false, "Skip downloading when files of the same name exist")
	cmd.Flags().BoolVar(&opts.AllowEscapes, "allow-escape-sequences", false, "Allow printing terminal escape sequences when writing an asset to standard output")

	return cmd
}
