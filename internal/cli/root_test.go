package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// testStreams returns an IOStreams backed by in-memory buffers along with
// pointers to those buffers so individual assertions can introspect them.
func testStreams() (IOStreams, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	return IOStreams{
		In:     strings.NewReader(""),
		Out:    &stdout,
		ErrOut: &stderr,
	}, &stdout, &stderr
}

func runRoot(t *testing.T, args ...string) (*cobra.Command, *bytes.Buffer, *bytes.Buffer, error) {
	t.Helper()
	streams, stdout, stderr := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test", Commit: "abc123", Date: "2026-05-08"})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return cmd, stdout, stderr, err
}

func TestRoot_NoArgs_PrintsHelpToStderrOnly(t *testing.T) {
	_, stdout, stderr, err := runRoot(t)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty when no subcommand runs, got %q", stdout.String())
	}
	got := stderr.String()
	for _, want := range []string{"yalla", "Usage:", "Flags:"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr missing %q; got:\n%s", want, got)
		}
	}
}

func TestRoot_RegistersAllRequiredGlobalFlags(t *testing.T) {
	streams, _, _ := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})

	required := []string{"json", "no-input", "config", "base-url", "token", "verbose"}
	for _, name := range required {
		if cmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing required persistent flag --%s", name)
		}
	}
	if cmd.Version == "" {
		t.Error("expected cobra.Command.Version to be set so --version is wired")
	}
	// Cobra registers --version implicitly when Version is non-empty.
	if cmd.Flags().Lookup("version") == nil && cmd.PersistentFlags().Lookup("version") == nil {
		// Cobra exposes --version only after first parse; trigger it.
		cmd.SetArgs([]string{"--version"})
		_ = cmd.Execute()
		if cmd.Flags().Lookup("version") == nil {
			t.Error("expected --version flag to be wired by cobra")
		}
	}
}

func TestRoot_VerboseHasShortAlias(t *testing.T) {
	streams, _, _ := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	f := cmd.PersistentFlags().Lookup("verbose")
	if f == nil {
		t.Fatal("--verbose flag missing")
	}
	if f.Shorthand != "v" {
		t.Errorf("--verbose short alias = %q, want %q", f.Shorthand, "v")
	}
}

func TestRoot_PersistentPreRun_PopulatesContextForSubcommands(t *testing.T) {
	streams, _, _ := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})

	var capturedFlags *GlobalFlags
	var capturedStreams IOStreams
	var capturedBuild BuildInfo

	probe := &cobra.Command{
		Use: "probe",
		RunE: func(c *cobra.Command, _ []string) error {
			capturedFlags = GlobalFlagsFromContext(c.Context())
			capturedStreams = IOStreamsFromContext(c.Context())
			capturedBuild = BuildInfoFromContext(c.Context())
			return nil
		},
	}
	cmd.AddCommand(probe)

	cmd.SetArgs([]string{
		"--json",
		"--no-input",
		"--config", "/tmp/yalla.yaml",
		"--base-url", "https://dokploy.example.com",
		"--token", "supersecret",
		"--verbose",
		"probe",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if capturedFlags == nil {
		t.Fatal("subcommand never ran; flags not captured")
	}
	if !capturedFlags.JSON {
		t.Error("--json not parsed into GlobalFlags")
	}
	if !capturedFlags.NoInput {
		t.Error("--no-input not parsed into GlobalFlags")
	}
	if capturedFlags.Config != "/tmp/yalla.yaml" {
		t.Errorf("Config = %q, want /tmp/yalla.yaml", capturedFlags.Config)
	}
	if capturedFlags.BaseURL != "https://dokploy.example.com" {
		t.Errorf("BaseURL = %q, want https://dokploy.example.com", capturedFlags.BaseURL)
	}
	if capturedFlags.Token != "supersecret" {
		t.Errorf("Token = %q, want supersecret", capturedFlags.Token)
	}
	if !capturedFlags.Verbose {
		t.Error("--verbose not parsed into GlobalFlags")
	}
	if capturedStreams.Out == nil || capturedStreams.ErrOut == nil {
		t.Error("IOStreams not propagated to subcommand context")
	}
	if capturedBuild.Version != "0.0.0-test" {
		t.Errorf("BuildInfo.Version = %q, want 0.0.0-test", capturedBuild.Version)
	}
}

func TestRoot_VersionFlag_PrintsBuildInfo(t *testing.T) {
	_, stdout, stderr, err := runRoot(t, "--version")
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	combined := stdout.String() + stderr.String()
	for _, want := range []string{"yalla", "0.0.0-test"} {
		if !strings.Contains(combined, want) {
			t.Errorf("--version output missing %q; stdout=%q stderr=%q", want, stdout.String(), stderr.String())
		}
	}
}

func TestRoot_HelpFlag_KeepsStdoutEmpty(t *testing.T) {
	_, stdout, stderr, err := runRoot(t, "--help")
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("--help leaked into stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("--help should print usage on stderr, got %q", stderr.String())
	}
}

func TestRoot_UnknownCommand_FailsWithoutLeakingToStdout(t *testing.T) {
	_, stdout, _, err := runRoot(t, "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must remain data-only on error, got %q", stdout.String())
	}
}

func TestExecute_ReturnsNonZeroForUnknownCommand(t *testing.T) {
	// Execute uses os.Stdin/Stdout/Stderr by default, which is fine for the
	// exit-code assertion. We swap os.Args via cobra's mechanism by building
	// the command manually here to avoid touching the real os.Args.
	streams, stdout, stderr := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"definitely-not-a-command"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from cobra for unknown command")
	}
	// The error itself comes from cobra; the binary entrypoint translates it
	// into exit code 1 via cli.Execute. This test asserts the underlying
	// invariant Execute relies on.
	if stdout.Len() != 0 {
		t.Errorf("stdout leak on error: %q", stdout.String())
	}
	_ = stderr
}

func TestContextAccessors_FallbackToDefaults(t *testing.T) {
	ctx := context.Background()
	if got := GlobalFlagsFromContext(ctx); got == nil || got.JSON {
		t.Errorf("GlobalFlagsFromContext fallback should return zero-value flags, got %+v", got)
	}
	if got := IOStreamsFromContext(ctx); got.Out == nil {
		t.Error("IOStreamsFromContext fallback should return DefaultIOStreams")
	}
	if got := BuildInfoFromContext(ctx); got.Version == "" {
		t.Error("BuildInfoFromContext fallback should populate Version")
	}
}
