package testutil

import (
	"bytes"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/cli"
)

// DefaultBuildInfo is the BuildInfo every Run uses unless overridden via
// RunOptions. Pinning the version string keeps golden files stable across
// developer machines and CI.
var DefaultBuildInfo = cli.BuildInfo{
	Version: "0.0.0-test",
	Commit:  "testcommit",
	Date:    "2026-05-08",
}

// Streams returns an IOStreams backed by in-memory buffers along with
// pointers to those buffers so individual assertions can introspect them.
// The stdin reader is empty by default; callers that need to drive prompts
// or `--input -` plumbing should swap it via Run's StdinOptions.
func Streams() (cli.IOStreams, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	return cli.IOStreams{
		In:     strings.NewReader(""),
		Out:    &stdout,
		ErrOut: &stderr,
	}, &stdout, &stderr
}

// StreamsWithStdin behaves like Streams but seeds stdin with the supplied
// payload so commands that read `--input -` (the raw API executor) and any
// future prompt-aware command can be exercised end to end.
func StreamsWithStdin(stdin string) (cli.IOStreams, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	return cli.IOStreams{
		In:     strings.NewReader(stdin),
		Out:    &stdout,
		ErrOut: &stderr,
	}, &stdout, &stderr
}

// RunOptions tunes a single Run invocation. The zero value yields the
// production code path with empty stdin, the package-level DefaultBuildInfo,
// and no BuildInfo override.
type RunOptions struct {
	// Stdin is the bytes the command should read from os.Stdin. An empty
	// string yields a closed-but-readable stream — the same behaviour as
	// the binary when stdin is not piped.
	Stdin string
	// Build overrides DefaultBuildInfo for tests that exercise the
	// version/manifest surface. The zero value falls back to
	// DefaultBuildInfo.
	Build cli.BuildInfo
}

// RunResult is the outcome of a single command execution captured for
// assertions. Stdout and Stderr are returned as strings (the buffers behind
// them are private to Run) so tests can use string-equality and substring
// helpers without thinking about *bytes.Buffer.
type RunResult struct {
	// Stdout is the captured data stream. It MUST be empty whenever a
	// command fails or whenever the command emits a diagnostic that is
	// not data — assertions for that contract live in jsonassert.go.
	Stdout string
	// Stderr is the captured diagnostic stream. The typed-error renderer,
	// help text, and verbose logs all land here.
	Stderr string
	// Exit is the POSIX-style exit code the binary would return. It is
	// derived from the typed error's Code via errors.Code.ExitCode().
	Exit int
}

// Run executes the yalla root command under in-memory streams and returns
// the captured stdout, stderr, and exit code. It mirrors Execute exactly
// (buildRoot → cmd.Execute → renderTerminalError) so tests assert against
// the same bytes the production binary prints.
//
// The harness honours RunOptions.Stdin so tests can drive `api call --input -`
// and any future prompt-aware command without touching the real stdin.
func Run(t testing.TB, opts RunOptions, args ...string) RunResult {
	t.Helper()
	build := opts.Build
	if build == (cli.BuildInfo{}) {
		build = DefaultBuildInfo
	}
	streams, stdout, stderr := StreamsWithStdin(opts.Stdin)
	exit := cli.ExecuteForTest(streams, build, args)
	return RunResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Exit:   exit,
	}
}

// RunArgs is a convenience wrapper for the common case where no stdin or
// build override is needed. The variadic args land on the root command.
func RunArgs(t testing.TB, args ...string) RunResult {
	return Run(t, RunOptions{}, args...)
}
