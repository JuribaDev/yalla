package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// roundTripperFunc is a minimal http.RoundTripper helper for tests that
// need to control transport-level behaviour (e.g. forcing a CodeNetwork
// classification without depending on platform-specific dial timeouts).
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// fakeNetError is a non-timeout error returned by the stub transport so
// the api package's classifier maps it to CodeNetwork (CodeTimeout is
// covered by a separate test that drives an actual deadline).
type fakeNetError struct{ msg string }

func (e *fakeNetError) Error() string { return e.msg }

// setupAPICallServer is the canonical test harness for `yalla api call`.
// It spins up an httptest.Server with the supplied handler, points
// YALLA_BASE_URL at it, and seeds a fake YALLA_TOKEN so the executor
// does not reject auth-required operations up front. The server is
// auto-closed via t.Cleanup.
//
// Wire paths exercised by tests include the spec-declared server path
// (e.g. "/api") because the factory transparently injects it when the
// user-supplied BaseURL has no path of its own — exactly mirroring what
// happens in production. Use [coverageWirePath] to compute the expected
// path so tests stay portable when the spec moves the server prefix.
func setupAPICallServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, "test-token-value")
	return srv
}

// coverageWirePath returns the URL path the live executor will hit for
// an operation path. It mirrors the production join logic
// ([api.NewClient] + [api.Client.resolvePath]) so per-op tests stay
// readable: callers compare `seenPath` against `coverageWirePath(op)`
// without re-implementing the prefix rule.
func coverageWirePath(opPath string) string {
	prefix := api.Default().ServerPath
	if prefix == "" {
		return opPath
	}
	if opPath == "" {
		return prefix
	}
	return prefix + opPath
}

func TestAPICall_Success_JSON(t *testing.T) {
	var (
		seenMethod string
		seenPath   string
		seenAPIKey string
		seenAuth   string
	)
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-12345")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"projects":[{"id":"p1"}]}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	if seenMethod != http.MethodGet {
		t.Errorf("server method = %q, want GET", seenMethod)
	}
	wantPath := coverageWirePath("/project.all")
	if seenPath != wantPath {
		t.Errorf("server path = %q, want %q", seenPath, wantPath)
	}
	if seenAPIKey != "test-token-value" {
		t.Errorf("%s header = %q, want test-token-value", api.DefaultAPIKeyHeader, seenAPIKey)
	}
	// The Bearer transport was retired in favour of the spec-declared
	// apiKey header; assert it is no longer present so a regression that
	// re-attaches Authorization fails loudly.
	if seenAuth != "" {
		t.Errorf("Authorization header should be empty under apiKey scheme; got %q", seenAuth)
	}

	var env struct {
		SchemaVersion string            `json:"schema_version"`
		Data          apiCallSuccessDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.OperationID != "project-all" {
		t.Errorf("operation_id = %q", env.Data.OperationID)
	}
	if env.Data.Status != http.StatusOK {
		t.Errorf("status = %d", env.Data.Status)
	}
	if env.Data.Method != http.MethodGet {
		t.Errorf("method = %q", env.Data.Method)
	}
	if env.Data.RequestID != "req-12345" {
		t.Errorf("request_id = %q", env.Data.RequestID)
	}
	if env.Data.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", env.Data.Attempts)
	}
	if !strings.Contains(string(env.Data.Body), `"projects"`) {
		t.Errorf("body missing payload: %s", string(env.Data.Body))
	}
}

func TestAPICall_DryRun_PrintsResolvedRequest(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inputPath, []byte(`{"body":{"applicationId":"abc"}}`), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-deploy",
		"--input", inputPath, "--dry-run")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}

	var env struct {
		Data apiCallDryRunDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if !env.Data.DryRun {
		t.Error("dry_run = false; expected true")
	}
	if env.Data.Method != http.MethodPost {
		t.Errorf("method = %q", env.Data.Method)
	}
	// Dry-run URL mirrors live behaviour: a bare-host BaseURL gets the
	// spec's server path ("/api") prepended so agents diffing dry-run vs
	// live see byte-identical URLs.
	if env.Data.URL != "https://dokploy.example.com/api/application.deploy" {
		t.Errorf("url = %q", env.Data.URL)
	}
	// The active scheme is apiKey-in-header, so the redacted entry lives
	// under the canonicalised "X-Api-Key" key. http.Header canonicalises
	// dashes to title-case at JSON marshal time.
	apiKey := env.Data.Headers[http.CanonicalHeaderKey(api.DefaultAPIKeyHeader)]
	if len(apiKey) != 1 || !strings.Contains(apiKey[0], output.Sentinel) {
		t.Errorf("%s should be redacted; got %v", api.DefaultAPIKeyHeader, apiKey)
	}
	if _, ok := env.Data.Headers["Authorization"]; ok {
		t.Errorf("Authorization should not appear in dry-run under apiKey scheme; headers=%v", env.Data.Headers)
	}
	if !strings.Contains(string(env.Data.Body), "applicationId") {
		t.Errorf("body missing applicationId: %s", string(env.Data.Body))
	}
}

func TestAPICall_DryRun_NeverEchoesToken(t *testing.T) {
	const secretToken = "supersecret-bearer-value"
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, secretToken)

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all", "--dry-run")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, secretToken) {
		t.Errorf("token leaked into dry-run output: %q", combined)
	}
	if !strings.Contains(stdout, output.Sentinel) {
		t.Errorf("expected redaction sentinel; got %q", stdout)
	}
}

func TestAPICall_400_MapsToInvalidInput(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"validation failed"}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected E_INVALID_INPUT in stderr; got %q", stderr)
	}
	if !strings.Contains(stderr, "yalla.error.v1") {
		t.Errorf("expected yalla.error.v1 envelope in stderr; got %q", stderr)
	}
}

func TestAPICall_401_MapsToAuth(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeAuth)) {
		t.Errorf("expected E_AUTH in stderr; got %q", stderr)
	}
}

func TestAPICall_500_MapsToServer(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeServer)) {
		t.Errorf("expected E_SERVER in stderr; got %q", stderr)
	}
}

func TestAPICall_NetworkTimeout_MapsToTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Sleep significantly longer than the per-attempt timeout the
		// factory override below installs. The api package's transport
		// classifier maps the resulting net.Error timeout to CodeTimeout.
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, "test-token-value")

	orig := apiCallClientFactory
	t.Cleanup(func() { apiCallClientFactory = orig })
	apiCallClientFactory = func(args apiCallClientArgs) (*api.Client, error) {
		return api.NewClient(api.ClientConfig{
			BaseURL:    args.Config.BaseURL,
			Token:      args.Config.Token,
			UserAgent:  "yalla-test",
			Timeout:    50 * time.Millisecond,
			MaxRetries: 0,
		})
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeTimeout)) {
		t.Errorf("expected E_TIMEOUT in stderr; got %q", stderr)
	}
}

func TestAPICall_NetworkError_MapsToCodeNetwork(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	orig := apiCallClientFactory
	t.Cleanup(func() { apiCallClientFactory = orig })
	var attempts atomic.Int32
	apiCallClientFactory = func(args apiCallClientArgs) (*api.Client, error) {
		return api.NewClient(api.ClientConfig{
			BaseURL:   args.Config.BaseURL,
			Token:     args.Config.Token,
			UserAgent: "yalla-test",
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				attempts.Add(1)
				return nil, &fakeNetError{msg: "stub network refused"}
			}),
		})
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected network error")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeNetwork)) {
		t.Errorf("expected E_NETWORK in stderr; got %q", stderr)
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (POST is non-idempotent → no retries)", attempts.Load())
	}
}

func TestAPICall_UnknownOperation_NotFound(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")
	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "definitely-not-an-operation")
	if err == nil {
		t.Fatal("expected error for unknown operation")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeNotFound)) {
		t.Errorf("expected E_NOT_FOUND in stderr; got %q", stderr)
	}
}

func TestAPICall_NoInput_DoesNotPrompt(t *testing.T) {
	// blockingReader.Read panics if consulted, so any path that touches
	// stdin while --no-input is set fails loudly. The dry-run path for a
	// no-body operation must complete without ever reading stdin.
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	streams, stdout, stderr := testStreams()
	streams.In = blockingReader{}
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--no-input", "--json", "api", "call", "project-all", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		_ = renderTerminalError(streams, flags, err)
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("expected JSON envelope on stdout; got nothing")
	}
}

func TestAPICall_RejectsUnknownInputField(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inputPath, []byte(`{"bdoy":"oops"}`), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-deploy",
		"--input", inputPath, "--dry-run")
	if err == nil {
		t.Fatal("expected error for unknown input field")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected E_INVALID_INPUT in stderr; got %q", stderr)
	}
}

func TestAPICall_StdinInput_ReadsAndForwardsBody(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	streams, stdout, stderr := testStreams()
	streams.In = strings.NewReader(`{"body":{"hello":"world"}}`)
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--json", "api", "call", "application-deploy",
		"--input", "-", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		_ = renderTerminalError(streams, flags, err)
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr.String())
	}

	var env struct {
		Data apiCallDryRunDoc `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout.String())
	}
	if !strings.Contains(string(env.Data.Body), `"hello":"world"`) {
		t.Errorf("body missing payload: %s", string(env.Data.Body))
	}
}

func TestAPICall_QueryParamsForwardedToServer(t *testing.T) {
	var seenQuery url.Values
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inputPath, []byte(`{"query":{"projectId":["p1"]}}`), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	if _, stderr, err := runRootArgs(t, "--json", "api", "call", "project-one",
		"--input", inputPath); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if seenQuery.Get("projectId") != "p1" {
		t.Errorf("server did not see projectId=p1; got %v", seenQuery)
	}
}

func TestAPICall_RequiresBaseURL(t *testing.T) {
	// No env set: the loader resolves an empty BaseURL. Non-dry-run calls
	// must fail fast with CodeConfig before constructing a client so the
	// agent receives a deterministic exit code 3.
	t.Setenv(config.EnvToken, "test-token-value")
	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected error for missing base URL")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeConfig)) {
		t.Errorf("expected E_CONFIG in stderr; got %q", stderr)
	}
}

func TestAPICall_RequiresAuthToken(t *testing.T) {
	// BaseURL set but no token: the executor should refuse before sending
	// a request when the operation requires auth, returning CodeAuth.
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-all")
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeAuth)) {
		t.Errorf("expected E_AUTH in stderr; got %q", stderr)
	}
}

func TestAPICall_RequiredBodyMissing_InvalidInput(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	// application-deploy requires a request body. Calling it without one
	// (and without --dry-run skipping the check is moot — the body check
	// runs before the dry-run branch) must surface CodeInvalidInput.
	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-deploy", "--dry-run")
	if err == nil {
		t.Fatal("expected error for missing required body")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected E_INVALID_INPUT in stderr; got %q", stderr)
	}
}

func TestSubstitutePathParams(t *testing.T) {
	got, err := substitutePathParams("/foo/{id}/bar/{name}", map[string]string{
		"id":   "abc",
		"name": "with space",
	})
	if err != nil {
		t.Fatalf("substitutePathParams: %v", err)
	}
	const want = "/foo/abc/bar/with%20space"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSubstitutePathParams_MissingIsInvalidInput(t *testing.T) {
	_, err := substitutePathParams("/foo/{id}", nil)
	if err == nil {
		t.Fatal("expected error for missing path param")
	}
	var typed *yerr.Error
	if !errorAs(err, &typed) {
		t.Fatalf("error is not *yerr.Error: %T", err)
	}
	if typed.Code != yerr.CodeInvalidInput {
		t.Errorf("code = %q, want %q", typed.Code, yerr.CodeInvalidInput)
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"application/problem+json":        true,
		"text/plain":                      false,
		"":                                false,
	}
	for in, want := range cases {
		if got := isJSONContentType(in); got != want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsIdempotentMethod(t *testing.T) {
	cases := map[string]bool{
		http.MethodGet:    true,
		http.MethodHead:   true,
		http.MethodPost:   false,
		http.MethodPut:    false,
		http.MethodDelete: false,
		http.MethodPatch:  false,
	}
	for m, want := range cases {
		if got := isIdempotentMethod(m); got != want {
			t.Errorf("isIdempotentMethod(%q) = %v, want %v", m, got, want)
		}
	}
}

// errorAs is a tiny inline shim around stdlib errors.As to keep the test
// file's import block focused on the cli package's typical helpers. We
// avoid depending on the internal/errors package's traversal directly so
// this test stays close to how a script using the CLI would inspect the
// JSON envelope's `code` field.
func errorAs(err error, target any) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if e, ok := err.(*yerr.Error); ok {
			if t, ok := target.(**yerr.Error); ok {
				*t = e
				return true
			}
			return false
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
