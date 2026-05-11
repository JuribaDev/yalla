package cli

// Multipart-specific extension of the US-0011 secret-leak regression net
// in redaction_security_test.go. The multipart code path adds two new
// vectors the JSON-only tests cannot cover:
//
//   1. File bytes flow through the CLI ahead of the request, so any
//      future regression that prints the request body (panics, verbose
//      logging, dry-run rendering) could surface binary payload content.
//   2. Multipart bodies travel as text/binary blobs through
//      `apiCallDryRunDoc.BodyText`, not `json.RawMessage`. The text path
//      must still go through the same redactor as every other writer.
//
// These tests assert that the configured `secretSentinel`, the literal
// "Authorization: ..."/`X-API-Key: ...` patterns, and the file content
// itself never leak into stdout, stderr, or any rendered envelope —
// regardless of whether the request is a dry-run or hits a representative
// failure-status server.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

// fileSecret is a long, recognisable byte sequence injected into the
// multipart file fixture. The redactor would NOT scrub this on its own
// (it is not a registered secret and does not match the bearer/api-key
// regex) — the test passes only if buildMultipartRequestBody substitutes
// the redaction sentinel for the file content before the bytes ever
// reach the renderer. That is the contract this test locks.
const fileSecret = "yalla-test-FILE-CONTENT-DO-NOT-LEAK-0123456789-payload-marker"

func TestRedaction_Multipart_DryRunNeverLeaksTokenOrFile(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, secretSentinel)

	tmpFile := filepath.Join(t.TempDir(), "secret.zip")
	if err := os.WriteFile(tmpFile, []byte(fileSecret), 0o600); err != nil {
		t.Fatalf("seed secret file: %v", err)
	}

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := fmt.Sprintf(`{
        "body":  {"applicationId": "abc"},
        "files": {"zip": %q}
    }`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	for _, mode := range []struct {
		name string
		args []string
	}{
		{name: "json", args: []string{"--json", "api", "call", "application-dropDeployment", "--input", inputPath, "--dry-run"}},
		{name: "human", args: []string{"api", "call", "application-dropDeployment", "--input", inputPath, "--dry-run"}},
		{name: "json+verbose", args: []string{"--json", "--verbose", "api", "call", "application-dropDeployment", "--input", inputPath, "--dry-run"}},
	} {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			stdout, stderr, err := runRootArgs(t, mode.args...)
			if err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
			}
			assertNoLeak(t, "multipart dry-run "+mode.name, stdout, stderr)
			combined := stdout + stderr
			if strings.Contains(combined, fileSecret) {
				t.Errorf("%s: file content leaked into output: %q", mode.name, combined)
			}
			if !strings.Contains(stdout+stderr, output.Sentinel) {
				t.Errorf("%s: expected redaction sentinel somewhere in output", mode.name)
			}
		})
	}
}

func TestRedaction_Multipart_AuthErrorEnvelopeNeverEchoesToken(t *testing.T) {
	// Upstream returns 401 with an error envelope that echoes the
	// presented X-API-Key value verbatim — a real-world failure mode
	// the redactor protects against on the response side.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid api key","echoed":%q}`, got)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, secretSentinel)

	tmpFile := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(tmpFile, []byte(fileSecret), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := fmt.Sprintf(`{"body":{"applicationId":"abc"},"files":{"zip":%q}}`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err == nil {
		t.Fatal("expected 401 → error")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	assertNoLeak(t, "multipart 401 error envelope", stdout, stderr)
	// The file content is sent on the wire (live request, not dry-run),
	// but the renderer only surfaces a *response* body hint — file bytes
	// never traverse the error path. The fileSecret must not appear in
	// stderr.
	if strings.Contains(stderr, fileSecret) {
		t.Errorf("file content leaked into error envelope: %q", stderr)
	}
}

func TestRedaction_Multipart_UpstreamLeakedTokenScrubbed(t *testing.T) {
	// Belt-and-braces: an upstream that drops the secret literal into its
	// response body must still see it scrubbed before stderr. The token
	// is registered with the redactor via t.Setenv, so any verbatim copy
	// (no matter the surrounding bytes) gets the sentinel substitution.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `{"error":"internal","leaked_token":%q}`, secretSentinel)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, secretSentinel)

	tmpFile := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(tmpFile, []byte("ok"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := fmt.Sprintf(`{"body":{"applicationId":"abc"},"files":{"zip":%q}}`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err == nil {
		t.Fatal("expected 500 → error")
	}
	assertNoLeak(t, "multipart upstream leak", stdout, stderr)
	if !strings.Contains(stderr, output.Sentinel) {
		t.Errorf("expected redaction sentinel in stderr; got %q", stderr)
	}
}
