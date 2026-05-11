package cli

import (
	"encoding/json"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// runExecuteWith is the test harness for the executeWith → renderTerminalError
// pipeline. It constructs the root command with in-memory streams, attaches
// the supplied subcommand (if any) so we can drive specific RunE failures,
// runs the command tree under the given args, and returns the captured
// stdout, stderr, and exit code.
func runExecuteWith(t *testing.T, sub *cobra.Command, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	streams, outBuf, errBuf := testStreams()
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	if sub != nil {
		cmd.AddCommand(sub)
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	exit = renderTerminalError(streams, flags, err)
	return outBuf.String(), errBuf.String(), exit
}

func TestRenderTerminalError_NilReturnsZero(t *testing.T) {
	t.Parallel()
	streams, _, _ := testStreams()
	if got := renderTerminalError(streams, &GlobalFlags{}, nil); got != 0 {
		t.Errorf("renderTerminalError(nil) = %d, want 0", got)
	}
}

func TestExecuteWith_UnknownCommand_HumanFormat(t *testing.T) {
	t.Parallel()
	stdout, stderr, exit := runExecuteWith(t, nil, "definitely-not-a-command")
	if exit != 2 {
		t.Errorf("exit = %d, want 2 (E_USAGE)", exit)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty on error; got %q", stdout)
	}
	if !strings.Contains(stderr, "Error [E_USAGE]") {
		t.Errorf("stderr missing E_USAGE banner; got %q", stderr)
	}
}

func TestExecuteWith_UnknownCommand_JSONEnvelope(t *testing.T) {
	t.Parallel()
	stdout, stderr, exit := runExecuteWith(t, nil, "--json", "definitely-not-a-command")
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty for JSON error; got %q", stdout)
	}
	type payload struct {
		SchemaVersion string `json:"schema_version"`
		Error         struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint,omitempty"`
		} `json:"error"`
	}
	var got payload
	if err := json.Unmarshal([]byte(stderr), &got); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stderr)
	}
	if got.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", got.SchemaVersion)
	}
	if got.Error.Code != "E_USAGE" {
		t.Errorf("code = %q, want E_USAGE", got.Error.Code)
	}
	if got.Error.Message == "" {
		t.Error("message must not be empty")
	}
}

func TestExecuteWith_TypedErrorPreservesCodeAndExit(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return yerr.New(yerr.CodeNotFound, "project foo not found").
				WithHint("run `yalla project list`")
		},
	}
	stdout, stderr, exit := runExecuteWith(t, probe, "probe")
	if exit != 5 {
		t.Errorf("exit = %d, want 5 (E_NOT_FOUND)", exit)
	}
	if stdout != "" {
		t.Errorf("stdout leak on typed error: %q", stdout)
	}
	for _, want := range []string{"E_NOT_FOUND", "project foo not found", "hint: run `yalla project list`"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q; got %q", want, stderr)
		}
	}
}

func TestExecuteWith_TypedAuthError_JSONIncludesHint(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return yerr.New(yerr.CodeAuth, "invalid token").WithHint("set DOKPLOY_TOKEN")
		},
	}
	stdout, stderr, exit := runExecuteWith(t, probe, "--json", "probe")
	if exit != 4 {
		t.Errorf("exit = %d, want 4 (E_AUTH)", exit)
	}
	if stdout != "" {
		t.Errorf("stdout leak: %q", stdout)
	}
	if !strings.Contains(stderr, `"code":"E_AUTH"`) {
		t.Errorf("missing code in JSON; got %q", stderr)
	}
	if !strings.Contains(stderr, `"hint":"set DOKPLOY_TOKEN"`) {
		t.Errorf("missing hint in JSON; got %q", stderr)
	}
}

func TestExecuteWith_PlainErrorMapsToInternal(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return stderrors.New("connection refused")
		},
	}
	stdout, stderr, exit := runExecuteWith(t, probe, "probe")
	if exit != 1 {
		t.Errorf("exit = %d, want 1 (E_INTERNAL fallback)", exit)
	}
	if stdout != "" {
		t.Errorf("stdout leak: %q", stdout)
	}
	if !strings.Contains(stderr, "E_INTERNAL") {
		t.Errorf("expected E_INTERNAL banner; got %q", stderr)
	}
}

func TestExecuteWith_RedactsTokenInErrorMessage(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return yerr.New(yerr.CodeNetwork, "POST /v1/x failed: token=supersecret-token-value rejected")
		},
	}
	stdout, stderr, exit := runExecuteWith(t, probe, "--token", "supersecret-token-value", "probe")
	if exit != 8 {
		t.Errorf("exit = %d, want 8 (E_NETWORK)", exit)
	}
	if stdout != "" {
		t.Errorf("stdout leak: %q", stdout)
	}
	if strings.Contains(stderr, "supersecret-token-value") {
		t.Errorf("token leaked into error: %q", stderr)
	}
	if !strings.Contains(stderr, "[REDACTED]") {
		t.Errorf("expected redaction sentinel; got %q", stderr)
	}
}

func TestExecuteWith_RedactsTokenInJSONErrorMessage(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return yerr.New(yerr.CodeAuth, "auth failed for supersecret-token-value")
		},
	}
	_, stderr, _ := runExecuteWith(t, probe, "--json", "--token", "supersecret-token-value", "probe")
	if strings.Contains(stderr, "supersecret-token-value") {
		t.Errorf("token leaked into JSON error: %q", stderr)
	}
}

func TestExecuteWith_NoErrorReturnsZeroAndSilentStreams(t *testing.T) {
	t.Parallel()
	probe := &cobra.Command{
		Use: "probe",
		RunE: func(*cobra.Command, []string) error {
			return nil
		},
	}
	stdout, stderr, exit := runExecuteWith(t, probe, "probe")
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("expected silent streams; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestExecuteWith_PreservesStderrOnlyForUnknownFlag(t *testing.T) {
	t.Parallel()
	stdout, stderr, exit := runExecuteWith(t, nil, "--definitely-not-a-flag")
	if exit != 2 {
		t.Errorf("exit = %d, want 2 for unknown flag", exit)
	}
	if stdout != "" {
		t.Errorf("stdout leak on unknown flag: %q", stdout)
	}
	if !strings.Contains(stderr, "E_USAGE") {
		t.Errorf("expected E_USAGE banner; got %q", stderr)
	}
}
