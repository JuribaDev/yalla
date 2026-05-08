// Package cli builds the yalla Cobra command tree.
//
// The root command established here is intentionally thin: it wires global
// flags, exposes injectable IO streams, and propagates both through the
// command context so subcommands added in later stories can read them without
// reaching for package-level globals. Keeping the construction injectable is a
// hard requirement of US-0001 so tests can drive it with in-memory buffers.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// IOStreams bundles the three CLI streams. Data goes to Out (stdout). Logs,
// prompts, warnings, progress, and errors go to ErrOut (stderr). Tests pass
// in *bytes.Buffer values to assert the stdout/stderr contract.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// DefaultIOStreams binds to the process's standard streams.
func DefaultIOStreams() IOStreams {
	return IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
}

// GlobalFlags carries the values bound to the root command's persistent flags.
// A pointer is stored on the command's context so subcommands and tests can
// read them after parsing.
type GlobalFlags struct {
	JSON    bool
	NoInput bool
	Config  string
	BaseURL string
	Token   string
	Verbose bool
}

// BuildInfo describes the version metadata stamped into the binary at build
// time. The struct is exported so the entrypoint can populate it from
// -ldflags-injected variables in cmd/yalla/main.go.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// String renders BuildInfo for the bare `--version` flag. The format is the
// CLI's public contract for the human-facing version string; the structured
// JSON variant lives behind the future `yalla version --json` command.
func (b BuildInfo) String() string {
	if b.Version == "" {
		b.Version = "0.0.0-dev"
	}
	return fmt.Sprintf("yalla %s (commit %s, built %s)", b.Version, b.Commit, b.Date)
}

type contextKey int

const (
	ioStreamsKey contextKey = iota
	globalFlagsKey
	buildInfoKey
)

// WithIOStreams returns ctx annotated with the provided IO streams.
func WithIOStreams(ctx context.Context, s IOStreams) context.Context {
	return context.WithValue(ctx, ioStreamsKey, s)
}

// IOStreamsFromContext returns the streams stored on ctx, falling back to the
// process defaults when none are present. The fallback keeps subcommands
// resilient if they are constructed outside of NewRootCommand (for example in
// future docs-generation tooling).
func IOStreamsFromContext(ctx context.Context) IOStreams {
	if v, ok := ctx.Value(ioStreamsKey).(IOStreams); ok {
		return v
	}
	return DefaultIOStreams()
}

// WithGlobalFlags returns ctx annotated with the provided global flags pointer.
func WithGlobalFlags(ctx context.Context, f *GlobalFlags) context.Context {
	return context.WithValue(ctx, globalFlagsKey, f)
}

// GlobalFlagsFromContext returns the flags stored on ctx, or zero-valued
// defaults when none are present.
func GlobalFlagsFromContext(ctx context.Context) *GlobalFlags {
	if v, ok := ctx.Value(globalFlagsKey).(*GlobalFlags); ok {
		return v
	}
	return &GlobalFlags{}
}

// WithBuildInfo returns ctx annotated with the binary's build metadata.
func WithBuildInfo(ctx context.Context, b BuildInfo) context.Context {
	return context.WithValue(ctx, buildInfoKey, b)
}

// BuildInfoFromContext returns the build metadata stored on ctx.
func BuildInfoFromContext(ctx context.Context) BuildInfo {
	if v, ok := ctx.Value(buildInfoKey).(BuildInfo); ok {
		return v
	}
	return BuildInfo{Version: "0.0.0-dev", Commit: "unknown", Date: "unknown"}
}

// NewRootCommand constructs the top-level yalla command with all global flags
// wired and IO streams routed for the agent contract. Streams and build info
// are injected so tests and alternate entrypoints can drive the command tree.
func NewRootCommand(streams IOStreams, build BuildInfo) *cobra.Command {
	flags := &GlobalFlags{}

	cmd := &cobra.Command{
		Use:   "yalla",
		Short: "Agent-first CLI for Dokploy.",
		Long: `Yalla is a production-grade Dokploy CLI built for AI agents and humans.

It covers every Dokploy OpenAPI operation through stable JSON contracts,
ships as native cross-platform binaries, and keeps stdout reserved for data
while logs, prompts, warnings, and errors are written to stderr.`,
		Version:       build.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		// Args: cobra.NoArgs makes positional arguments on `yalla` itself a
		// stable error. Real work always lands on a subcommand, so any stray
		// token from a misconfigured agent should fail loudly rather than be
		// silently dropped.
		Args: cobra.NoArgs,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			ctx = WithIOStreams(ctx, streams)
			ctx = WithGlobalFlags(ctx, flags)
			ctx = WithBuildInfo(ctx, build)
			c.SetContext(ctx)
			return nil
		},
		// Cobra's default help template only renders UsageString when the
		// command is Runnable (has Run/RunE) or has subcommands. Until later
		// stories register subcommands, we need an explicit RunE so a bare
		// `yalla` invocation prints the full help with flags rather than a
		// bare description.
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}

	// Cobra writes help, usage, and version output through the command's Out
	// writer. The agent contract reserves stdout for data only, so we route
	// every Cobra-managed stream onto stderr; data emission for future
	// subcommands flows through IOStreamsFromContext(ctx).Out.
	cmd.SetIn(streams.In)
	cmd.SetOut(streams.ErrOut)
	cmd.SetErr(streams.ErrOut)

	// Stable, human-readable version line. JSON version output is the job of a
	// future `yalla version --json` subcommand.
	cmd.SetVersionTemplate(build.String() + "\n")

	pf := cmd.PersistentFlags()
	pf.BoolVar(&flags.JSON, "json", false, "emit machine-readable JSON output to stdout")
	pf.BoolVar(&flags.NoInput, "no-input", false, "never prompt; fail with a stable error code if input is required")
	pf.StringVar(&flags.Config, "config", "", "path to a yalla config file (overrides the default search path)")
	pf.StringVar(&flags.BaseURL, "base-url", "", "Dokploy API base URL (e.g. https://dokploy.example.com)")
	pf.StringVar(&flags.Token, "token", "", "Dokploy API token; redacted in all logs and output")
	pf.BoolVarP(&flags.Verbose, "verbose", "v", false, "enable verbose diagnostic logging on stderr")

	return cmd
}

// Execute runs the root command using the process's default IO streams and
// returns the exit code the binary should exit with. Centralising this
// indirection keeps cmd/yalla/main.go tiny and gives tests a reusable hook.
func Execute(build BuildInfo) int {
	streams := DefaultIOStreams()
	cmd := NewRootCommand(streams, build)
	if err := cmd.Execute(); err != nil {
		// Surface the failure on stderr in a stable shape. Typed error
		// envelopes and JSON-aware error rendering arrive in US-0002; for
		// now we keep the message terse and stripped of any colourisation.
		fmt.Fprintln(streams.ErrOut, "yalla:", strings.TrimSpace(err.Error()))
		return 1
	}
	return 0
}
