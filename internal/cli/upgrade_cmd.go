package cli

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/JuribaDev/yalla/internal/release"
	"github.com/JuribaDev/yalla/internal/upgrade"
)

// upgradeStatusDoc is the JSON envelope payload for `yalla upgrade
// --check`. It is the public-API contract; field renames are breaking
// changes.
type upgradeStatusDoc struct {
	CurrentVersion  string                `json:"current_version"`
	LatestVersion   string                `json:"latest_version"`
	UpdateAvailable bool                  `json:"update_available"`
	IsPreRelease    bool                  `json:"is_prerelease,omitempty"`
	ReleaseURL      string                `json:"release_url,omitempty"`
	PublishedAt     string                `json:"published_at,omitempty"`
	Plan            upgrade.Plan          `json:"plan"`
	Applied         bool                  `json:"applied"`
	Action          string                `json:"action"`
	Message         string                `json:"message,omitempty"`
	Target          *upgradeTargetDoc     `json:"target,omitempty"`
	ChecksumsURL    string                `json:"checksums_url,omitempty"`
	ArchiveURL      string                `json:"archive_url,omitempty"`
	Asset           *upgrade.ReleaseAsset `json:"asset,omitempty"`
}

// upgradeTargetDoc reports the (GOOS, GOARCH) pair the running binary
// resolves to. Embedded only when known so an unknown target does not
// produce a misleading "linux/amd64" stamp.
type upgradeTargetDoc struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// upgradeAction values are the public action identifiers an agent can
// switch on. The strings are part of the JSON contract.
const (
	upgradeActionUpToDate         = "up_to_date"
	upgradeActionReportPackageMgr = "report_package_manager"
	upgradeActionReportManual     = "report_manual_upgrade"
	upgradeActionApplied          = "applied"
	upgradeActionUnsupported      = "unsupported"
	upgradeActionUnknown          = "unknown_install"
)

// upgradeCheckClientFactory and upgradeApplyClientFactory are the test
// seams swapped by the upgrade tests. Both default to short-timeout
// http.Client values; tests override them to point at httptest.Server
// instances.
var (
	upgradeCheckClientFactory = func() *http.Client {
		return &http.Client{Timeout: 15 * time.Second}
	}
	upgradeApplyClientFactory = func() *http.Client {
		return &http.Client{Timeout: 60 * time.Second}
	}
)

// upgradeProbeFactory builds the channel-detection probe. The default
// uses os.Executable + runtime.GOOS + os.LookupEnv; tests inject a
// hermetic probe to drive specific channels.
var upgradeProbeFactory = func() (upgrade.Probe, error) {
	exe, err := os.Executable()
	if err != nil {
		return upgrade.Probe{}, err
	}
	return upgrade.DefaultProbe(exe, runtime.GOOS, os.LookupEnv), nil
}

// upgradeCheckOptions and upgradeApplyOptions are the testable seams
// the cli command consults. Tests override these to point Check and
// ApplyManual at httptest.Server URLs.
var (
	upgradeCheckBaseURL    = ""
	upgradeApplyArchiveURL = ""
	upgradeApplyChecksums  = ""
	upgradeRuntimeGOARCH   = runtime.GOARCH
)

func newUpgradeCommand() *cobra.Command {
	var (
		check      bool
		yes        bool
		prerelease bool
	)
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Check for and apply yalla updates",
		Long: `Check for newer yalla releases and, when permitted by the install channel,
download and replace the binary atomically.

By default ` + "`yalla upgrade`" + ` only checks: it reports the latest
release and the upgrade command appropriate to the detected install
channel (Homebrew, npm, npx, Scoop, WinGet, manual, or unknown). yalla
never overwrites a binary it does not own — for package-managed
installs the JSON envelope and the human output point at the native
package-manager command instead.

Pass ` + "`--yes`" + ` to perform a self-replacement. This is only
permitted when the channel is detected as ` + "`manual`" + `; on every
other channel the call exits with ` + "`E_UNSUPPORTED`" + ` and the
appropriate package-manager command is reported.`,
		Example: `  yalla upgrade --check
  yalla upgrade --check --json
  yalla upgrade --yes`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			streams := IOStreamsFromContext(ctx)
			r := rendererFromContext(c, streams)
			build := BuildInfoFromContext(ctx)
			if check && yes {
				return yerr.New(yerr.CodeUsage, "--check and --yes are mutually exclusive").
					WithHint("pick one: --check to inspect, --yes to apply")
			}
			return runUpgrade(ctx, r, build, upgradeRunOptions{
				Apply:             yes,
				IncludePrerelease: prerelease,
			})
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report the upgrade plan without modifying anything (default behaviour)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the upgrade for manually-installed binaries (refused on package-managed channels)")
	cmd.Flags().BoolVar(&prerelease, "prerelease", false, "include pre-release versions when looking up the latest release")
	return cmd
}

type upgradeRunOptions struct {
	Apply             bool
	IncludePrerelease bool
}

// runUpgrade is the testable seam shared by RunE and the unit tests.
// It builds the Probe, fetches the latest release, computes the Plan,
// and either reports or applies the upgrade.
func runUpgrade(ctx context.Context, r *output.Renderer, build BuildInfo, opts upgradeRunOptions) error {
	probe, err := upgradeProbeFactory()
	if err != nil {
		return yerr.Newf(yerr.CodeInternal, "resolve binary path: %v", err).
			WithHint("yalla could not determine its own location; reinstall and try again")
	}
	channel := upgrade.Detect(probe)
	plan := upgrade.PlanFor(channel, probe.BinaryPath)

	current := build.Version
	if current == "" {
		current = "0.0.0-dev"
	}
	doc := upgradeStatusDoc{
		CurrentVersion: current,
		Plan:           plan,
	}

	latest, err := upgrade.Check(ctx, upgrade.CheckOptions{
		HTTPClient:        upgradeCheckClientFactory(),
		BaseURL:           upgradeCheckBaseURL,
		IncludePrerelease: opts.IncludePrerelease,
		UserAgent:         "yalla/" + current,
	})
	if err != nil {
		return yerr.Newf(yerr.CodeNetwork, "check for updates: %v", err).
			WithHint("verify network access to api.github.com or use a package manager")
	}

	doc.LatestVersion = latest.Version
	doc.IsPreRelease = latest.IsPreRelease
	doc.ReleaseURL = latest.HTMLURL
	if !latest.PublishedAt.IsZero() {
		doc.PublishedAt = latest.PublishedAt.UTC().Format(time.RFC3339)
	}

	curV, curErr := upgrade.ParseSemVer(current)
	latV, latErr := upgrade.ParseSemVer(latest.Version)
	switch {
	case curErr != nil || latErr != nil:
		// Fall back to a string compare so a dev build like 0.0.0-dev
		// still flags an upgrade when the upstream tag exists.
		doc.UpdateAvailable = current != latest.Version && latest.Version != ""
	default:
		doc.UpdateAvailable = curV.LessThan(latV)
	}

	if !doc.UpdateAvailable {
		doc.Action = upgradeActionUpToDate
		doc.Message = "yalla " + current + " is up to date."
		return emitUpgradeStatus(r, doc)
	}

	if !opts.Apply {
		switch channel {
		case upgrade.ChannelManual:
			doc.Action = upgradeActionReportManual
			doc.Message = "Update " + latest.Version + " is available. Run `yalla upgrade --yes` to download and replace the binary."
		case upgrade.ChannelUnknown:
			doc.Action = upgradeActionUnknown
			doc.Message = "Update " + latest.Version + " is available. yalla cannot identify the install layout; download from " + latest.HTMLURL
		default:
			doc.Action = upgradeActionReportPackageMgr
			doc.Message = "Update " + latest.Version + " is available. " + plan.Note
		}
		return emitUpgradeStatus(r, doc)
	}

	// --yes path. Refuse on every channel except Manual.
	if channel != upgrade.ChannelManual {
		doc.Action = upgradeActionUnsupported
		doc.Message = "yalla refuses to overwrite a " + string(channel) + "-managed binary. Use the package manager: " + plan.Command
		return yerr.New(yerr.CodeUnsupported, doc.Message).
			WithHintf("run `%s` instead, or reinstall yalla manually before using --yes", plan.Command)
	}

	target := release.Target{OS: probe.GOOS, Arch: upgradeRuntimeGOARCH}
	doc.Target = &upgradeTargetDoc{OS: target.OS, Arch: target.Arch}

	archiveName := target.ArchiveName(latest.Version)
	asset, hasAsset := latest.FindAsset(archiveName)
	if hasAsset {
		doc.Asset = &asset
		doc.ArchiveURL = asset.DownloadURL
	}
	doc.ChecksumsURL = upgradeApplyChecksums
	if doc.ArchiveURL == "" {
		doc.ArchiveURL = upgradeApplyArchiveURL
	}

	applyErr := upgrade.ApplyManual(ctx, upgrade.ApplyOptions{
		HTTPClient:   upgradeApplyClientFactory(),
		Version:      latest.Version,
		Target:       target,
		BinaryPath:   probe.BinaryPath,
		ArchiveURL:   doc.ArchiveURL,
		ChecksumsURL: doc.ChecksumsURL,
		Logf: func(format string, args ...any) {
			r.Logf(format, args...)
		},
	})
	if applyErr != nil {
		return yerr.Newf(yerr.CodeInternal, "apply upgrade: %v", applyErr).
			WithHint("the running binary was NOT replaced; download manually from " + latest.HTMLURL)
	}

	doc.Applied = true
	doc.Action = upgradeActionApplied
	doc.Message = "yalla upgraded from " + current + " to " + latest.Version + "."
	return emitUpgradeStatus(r, doc)
}

func emitUpgradeStatus(r *output.Renderer, doc upgradeStatusDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	r.Human(doc.Message)
	if doc.Plan.Command != "" && !doc.Applied {
		r.Human("  command: " + doc.Plan.Command)
	}
	if doc.ReleaseURL != "" {
		r.Human("  release: " + doc.ReleaseURL)
	}
	return nil
}
