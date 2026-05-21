package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestAuthStatus_JSONReportsReadyWhenConfigured(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	var env struct {
		SchemaVersion string        `json:"schema_version"`
		Data          authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if !env.Data.Ready {
		t.Errorf("ready = false; want true (token + base_url both set)")
	}
	if !env.Data.Token.Set {
		t.Error("token.set = false; want true")
	}
	if env.Data.Token.Value != "" {
		t.Errorf("token value leaked into JSON: %q", env.Data.Token.Value)
	}
	if env.Data.Token.Source != config.SourceEnv {
		t.Errorf("token.source = %q, want %q", env.Data.Token.Source, config.SourceEnv)
	}
	if env.Data.BaseURL.Value != "https://dokploy.example.com" {
		t.Errorf("base_url value = %q", env.Data.BaseURL.Value)
	}
	if env.Data.Reason != "" {
		t.Errorf("reason = %q, want empty when ready", env.Data.Reason)
	}
}

func TestAuthStatus_JSONReportsNotReadyWhenTokenMissing(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Ready {
		t.Error("ready = true; want false (token missing)")
	}
	if env.Data.Token.Set {
		t.Error("token.set = true; want false")
	}
	if !strings.Contains(env.Data.Reason, "E_AUTH") {
		t.Errorf("reason = %q, want to mention E_AUTH", env.Data.Reason)
	}
}

func TestAuthStatus_JSONReportsNotReadyWhenBaseURLMissing(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, _, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Ready {
		t.Error("ready = true; want false (base_url missing)")
	}
	if !strings.Contains(env.Data.Reason, "E_CONFIG") {
		t.Errorf("reason = %q, want to mention E_CONFIG", env.Data.Reason)
	}
}

func TestAuthStatus_HumanNeverEchoesToken(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "supersecret-token-value")

	stdout, stderr, err := runRootArgs(t, "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, "supersecret-token-value") {
		t.Errorf("token leaked: %q", combined)
	}
	if !strings.Contains(stdout, "configured") {
		t.Errorf("expected token line to read 'configured'; got %q", stdout)
	}
	if !strings.Contains(stdout, "ready: yes") {
		t.Errorf("expected ready line; got %q", stdout)
	}
}

func TestAuthStatus_HumanWithoutTokenSaysNotReady(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")

	stdout, _, err := runRootArgs(t, "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout, "ready: no") {
		t.Errorf("expected 'ready: no'; got %q", stdout)
	}
	if !strings.Contains(stdout, "not set") {
		t.Errorf("expected 'not set' for missing token; got %q", stdout)
	}
}

func TestAuthStatus_NoInputDoesNotPrompt(t *testing.T) {
	withTempConfig(t, "")
	streams, stdout, _ := testStreams()
	streams.In = blockingReader{}
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--no-input", "--json", "auth", "status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("expected JSON output on stdout")
	}
}

func TestAuthLogin_TokenStdinStoresURLAndTokenThenVerifies(t *testing.T) {
	keyring.MockInit()
	path := withTempConfig(t, "")
	const token = "login-secret-token-value"

	var seenPath, seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"principal_id":"usr_1","organization_id":"org_1","role":"owner","grants":[],"disabled":false}}`))
	}))
	t.Cleanup(srv.Close)

	streams, stdout, stderr := testStreams()
	streams.In = strings.NewReader(token + "\n")
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--json", "auth", "login", "--url", srv.URL, "--token-stdin"})
	if err := cmd.Execute(); err != nil {
		_ = renderTerminalError(streams, flags, err)
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr.String())
	}

	if strings.Contains(stdout.String()+stderr.String(), token) {
		t.Fatalf("token leaked into output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if seenPath != "/v1/me" {
		t.Errorf("verification path = %q, want /v1/me", seenPath)
	}
	if seenAuth != "Bearer "+token {
		t.Errorf("verification authorization = %q, want bearer token from stdin", seenAuth)
	}
	stored, err := keyring.Get("yalla", srv.URL)
	if err != nil {
		t.Fatalf("keyring get: %v", err)
	}
	if stored != token {
		t.Errorf("stored token = %q, want stdin token", stored)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(body), "base_url: "+srv.URL) {
		t.Errorf("config missing URL; body=%q", string(body))
	}

	var env struct {
		Data authLoginDoc `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout.String())
	}
	if env.Data.URL != srv.URL || env.Data.Token.Source != string(config.SourceCredentialStore) {
		t.Errorf("unexpected login payload: %+v", env.Data)
	}
	if env.Data.User.ID != "usr_1" || env.Data.ActiveOrganizationID != "org_1" {
		t.Errorf("verification identity not surfaced: %+v", env.Data)
	}
}

func TestAuthLogin_TokenStdinRedactsVerificationFailure(t *testing.T) {
	keyring.MockInit()
	withTempConfig(t, "")
	const token = "stdin-secret-token-validated-12345"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad token: " + strings.TrimPrefix(r.Header.Get(api.HeaderAuthorization), "Bearer ")))
	}))
	t.Cleanup(srv.Close)

	streams, stdout, stderr := testStreams()
	streams.In = strings.NewReader(token)
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--json", "auth", "login", "--url", srv.URL, "--token-stdin", "--store", "config"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute returned nil for failed verification")
	}
	_ = renderTerminalError(streams, flags, err)

	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty on failed login; got %q", stdout.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatalf("stdin token leaked into verification error: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), output.Sentinel) {
		t.Fatalf("expected redaction sentinel in stderr; got %q", stderr.String())
	}
}

func TestAuthStatus_ReportsCredentialStoreToken(t *testing.T) {
	keyring.MockInit()
	withTempConfig(t, "base_url: https://stored.example.com\n")
	if err := keyring.Set("yalla", "https://stored.example.com", "stored-token-value"); err != nil {
		t.Fatalf("keyring set: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	var env struct {
		Data authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if !env.Data.Ready {
		t.Fatalf("ready = false; payload=%+v", env.Data)
	}
	if env.Data.Token.Source != config.SourceCredentialStore {
		t.Errorf("token.source = %q, want %q", env.Data.Token.Source, config.SourceCredentialStore)
	}
	if strings.Contains(stdout+stderr, "stored-token-value") {
		t.Errorf("credential-store token leaked: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestAuthLogout_RemovesTokenForActiveURL(t *testing.T) {
	keyring.MockInit()
	withTempConfig(t, "base_url: https://stored.example.com\n")
	if err := keyring.Set("yalla", "https://stored.example.com", "stored-token-value"); err != nil {
		t.Fatalf("keyring set: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "logout")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if _, err := keyring.Get("yalla", "https://stored.example.com"); err == nil {
		t.Fatal("token still present after logout")
	}
	var env struct {
		Data authLogoutDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.URL != "https://stored.example.com" || !env.Data.Removed {
		t.Errorf("unexpected logout payload: %+v", env.Data)
	}
}

func TestAuthLogout_ConfigTokenSucceedsWhenKeyringUnsupported(t *testing.T) {
	keyring.MockInitWithError(keyring.ErrUnsupportedPlatform)
	t.Cleanup(keyring.MockInit)
	path := withTempConfig(t, "base_url: https://stored.example.com\ntoken: plaintext-token-value\n")

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "logout")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if strings.Contains(stdout+stderr, "plaintext-token-value") {
		t.Fatalf("token leaked into logout output: stdout=%q stderr=%q", stdout, stderr)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(body), "plaintext-token-value") {
		t.Fatalf("config token was not cleared: %q", string(body))
	}
	var env struct {
		Data authLogoutDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if !env.Data.Removed || env.Data.Token.Source != string(config.SourceFile) {
		t.Errorf("unexpected logout payload: %+v", env.Data)
	}
}
