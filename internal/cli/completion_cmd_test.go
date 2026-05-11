package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/output"
)

// TestCompletion_AllSupportedShellsEmitNonEmptyScript exercises every
// shell in supportedShells to lock the completion surface. Each call
// must succeed and produce a non-empty script on stdout with no stderr
// noise. The contents differ wildly across shells; we only assert
// non-empty + a shell-specific anchor string.
func TestCompletion_AllSupportedShellsEmitNonEmptyScript(t *testing.T) {
	cases := []struct {
		shell  string
		anchor string
	}{
		{"bash", "bash completion"},
		{"zsh", "#compdef"},
		{"fish", "fish completion for yalla"},
		{"powershell", "Register-ArgumentCompleter"},
	}
	for _, tc := range cases {
		t.Run(tc.shell, func(t *testing.T) {
			stdout, stderr, err := runRootArgs(t, "completion", tc.shell)
			if err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty; got %q", stderr)
			}
			if len(stdout) == 0 {
				t.Fatalf("stdout empty for %s completion", tc.shell)
			}
			if !strings.Contains(stdout, tc.anchor) {
				t.Errorf("%s completion missing anchor %q; first 200 bytes:\n%s",
					tc.shell, tc.anchor, stdout[:min(200, len(stdout))])
			}
		})
	}
}

// TestCompletion_JSONWrapsScript verifies the --json path: the script
// lives under the standard envelope's data.script field and the shell
// name round-trips. Stderr stays empty.
func TestCompletion_JSONWrapsScript(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "completion", "bash")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	var env struct {
		SchemaVersion string        `json:"schema_version"`
		Data          completionDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("envelope schema_version = %q", env.SchemaVersion)
	}
	if env.Data.Shell != "bash" {
		t.Errorf("shell = %q, want %q", env.Data.Shell, "bash")
	}
	if !strings.Contains(env.Data.Script, "bash completion") {
		t.Errorf("envelope script missing bash completion anchor")
	}
}

// TestCompletion_NoShellPrintsHelp covers the bare `yalla completion`
// invocation: cobra returns help (data-on-stderr in our routing) and
// stdout stays empty. No shell is selected so no script is generated.
func TestCompletion_NoShellPrintsHelp(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "completion")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty; got %q", stdout)
	}
	for _, want := range []string{"bash", "zsh", "fish", "powershell"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("help output missing shell %q; stderr=%q", want, stderr)
		}
	}
}

// TestCompletion_UnknownShellIsUsageError covers cobra's own arg
// validation: an unknown subcommand under `completion` must surface
// E_USAGE and keep stdout empty.
func TestCompletion_UnknownShellIsUsageError(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "completion", "tcsh")
	if err == nil {
		t.Fatal("expected error for unsupported shell")
	}
	if stdout != "" {
		t.Errorf("stdout must be empty on usage error; got %q", stdout)
	}
	if !strings.Contains(stderr, "E_USAGE") {
		t.Errorf("expected E_USAGE on stderr; got %q", stderr)
	}
}
