package cli

// US-0011 secret-leak regression net.
//
// These tests are the canonical end-to-end regression net for the redaction
// contract documented in SECURITY.md. They drive a representative slice of
// commands through the production exit-code path (buildRoot → cmd.Execute →
// renderTerminalError) with a sentinel `--token` value and assert that the
// sentinel never appears in stdout, stderr, or any JSON envelope —
// regardless of mode (`--json` vs human), regardless of whether `--verbose`
// is set, and regardless of which Code the typed error renders as.
//
// The narrower unit tests in internal/output/redact_test.go exercise the
// redactor in isolation. These tests are the integration-level guarantee
// that every visible writer in the command tree actually goes through it.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

// secretSentinel is a long, recognisable token. It must be at least
// minRedactableLen characters so the redactor treats it as a secret.
const secretSentinel = "yalla-test-bearer-token-DO-NOT-LEAK-0123456789"

// assertNoLeak fails the test when the sentinel appears in either stream.
// Helper kept local so the failure message points at the leak path.
func assertNoLeak(t *testing.T, label, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stdout, secretSentinel) {
		t.Errorf("%s: sentinel leaked into stdout: %q", label, stdout)
	}
	if strings.Contains(stderr, secretSentinel) {
		t.Errorf("%s: sentinel leaked into stderr: %q", label, stderr)
	}
}

// TestRedaction_AuthErrorEnvelopeNeverEchoesToken covers the typed-error
// rendering path (yalla.error.v1 envelope plus the human "Error [CODE]"
// banner). A 401 from Dokploy sometimes echoes the bearer back in its
// response body — yalla must scrub it before the renderer touches stderr.
func TestRedaction_AuthErrorEnvelopeNeverEchoesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the Authorization header verbatim into the body so a
		// missing redactor would surface the secret in the envelope.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","received":"` + r.Header.Get(api.HeaderAuthorization) + `"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, secretSentinel)
	withTempConfig(t, "")

	for _, mode := range []struct {
		name string
		args []string
	}{
		{"json", []string{"--json", "api", "call", "project-all"}},
		{"human", []string{"api", "call", "project-all"}},
		{"verbose-json", []string{"--json", "--verbose", "api", "call", "project-all"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			stdout, stderr, _ := runRootArgs(t, mode.args...)
			assertNoLeak(t, mode.name, stdout, stderr)
			// The renderer must positively confirm redaction happened —
			// otherwise an empty response would silently pass.
			combined := stdout + stderr
			if !strings.Contains(combined, output.Sentinel) {
				t.Errorf("%s: expected redaction sentinel in output; combined=%q", mode.name, combined)
			}
		})
	}
}

// TestRedaction_DryRunEnvelopeScrubsAuthorization is a focused regression
// for the dry-run path: the resolved request envelope must replace the
// Bearer value with the sentinel rather than the original token.
func TestRedaction_DryRunEnvelopeScrubsAuthorization(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, secretSentinel)
	withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all", "--dry-run")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	assertNoLeak(t, "dry-run-json", stdout, stderr)
	if !strings.Contains(stdout, output.Sentinel) {
		t.Errorf("expected sentinel in dry-run envelope; stdout=%q", stdout)
	}
	// Belt and braces: confirm the human dry-run rendering also redacts.
	stdout, stderr, err = runRootArgs(t, "api", "call", "project-all", "--dry-run")
	if err != nil {
		t.Fatalf("Execute (human): %v (stderr=%q)", err, stderr)
	}
	assertNoLeak(t, "dry-run-human", stdout, stderr)
	if !strings.Contains(stdout, "Authorization: "+output.Sentinel) {
		t.Errorf("expected human dry-run to render Authorization: %s; stdout=%q", output.Sentinel, stdout)
	}
}

// TestRedaction_VerboseHumanModeDoesNotLeakToken covers the verbose
// diagnostic path. `--verbose` is wired into GlobalFlags and a renderer
// constructed with the same Redactor seed; any future Logf call that takes
// the token must be scrubbed. We exercise the path indirectly by driving
// `config get` (which echoes config-resolved fields) with `--verbose`.
func TestRedaction_VerboseHumanModeDoesNotLeakToken(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvToken, secretSentinel)

	stdout, stderr, err := runRootArgs(t, "--verbose", "config", "get")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	assertNoLeak(t, "verbose-config-get", stdout, stderr)
	if !strings.Contains(stdout, output.Sentinel) {
		t.Errorf("expected sentinel in verbose human output; stdout=%q", stdout)
	}
}

// TestRedaction_ConfigSetThenGetNeverPrintsSecret covers the round-trip
// of writing a secret via `config set` and reading it back via
// `config get`. Neither the set acknowledgement nor the get rendering may
// echo the underlying token.
func TestRedaction_ConfigSetThenGetNeverPrintsSecret(t *testing.T) {
	withTempConfig(t, "")

	// Write the token through the CLI itself.
	stdout, stderr, err := runRootArgs(t, "--json", "config", "set", "token", secretSentinel)
	if err != nil {
		t.Fatalf("config set: %v (stderr=%q)", err, stderr)
	}
	assertNoLeak(t, "config-set-json", stdout, stderr)

	stdout, stderr, err = runRootArgs(t, "config", "set", "token", secretSentinel)
	if err != nil {
		t.Fatalf("config set human: %v (stderr=%q)", err, stderr)
	}
	assertNoLeak(t, "config-set-human", stdout, stderr)

	// Read it back through every supported get shape.
	for _, mode := range []struct {
		name string
		args []string
	}{
		{"get-all-human", []string{"config", "get"}},
		{"get-all-json", []string{"--json", "config", "get"}},
		{"get-key-human", []string{"config", "get", "token"}},
		{"get-key-json", []string{"--json", "config", "get", "token"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			stdout, stderr, err := runRootArgs(t, mode.args...)
			if err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
			}
			assertNoLeak(t, mode.name, stdout, stderr)
		})
	}
}

// TestRedaction_TokenInQueryStringScrubbed exercises the well-known
// transport-pattern path: even if a Dokploy URL accidentally contains a
// `?token=…` query parameter, the dry-run output must scrub it. This
// belongs in the integration suite because the redactor pattern is part of
// the public contract — see SECURITY.md.
func TestRedaction_TokenInQueryStringScrubbed(t *testing.T) {
	r := output.NewRedactor()
	in := "GET https://dokploy.example.com/some/path?token=" + secretSentinel + "&page=1"
	got := r.Redact(in)
	if strings.Contains(got, secretSentinel) {
		t.Errorf("query-string token leaked: %q", got)
	}
	if !strings.Contains(got, "token="+output.Sentinel) {
		t.Errorf("expected token=%s in redacted output; got %q", output.Sentinel, got)
	}
}

// TestRedaction_TopLevelCobraErrorNeverLeaksToken covers the path where
// cobra itself fails (unknown subcommand, unknown flag) before
// PersistentPreRunE has a chance to install the typed-error renderer.
// renderTerminalError must still construct the redactor from the parsed
// --token value so the failure banner is scrubbed.
func TestRedaction_TopLevelCobraErrorNeverLeaksToken(t *testing.T) {
	withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "--token", secretSentinel, "--json", "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected cobra error for unknown command; got nil")
	}
	assertNoLeak(t, "unknown-cmd-json", stdout, stderr)

	stdout, stderr, err = runRootArgs(t, "--token", secretSentinel, "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected cobra error for unknown command (human); got nil")
	}
	assertNoLeak(t, "unknown-cmd-human", stdout, stderr)
}
