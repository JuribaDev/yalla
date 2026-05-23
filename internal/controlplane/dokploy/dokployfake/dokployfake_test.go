package dokployfake_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/output"
)

// call sends a request to the fake and returns the status code and raw body.
// A nil body sends no request body; an empty token sends no Authorization
// header.
func call(t *testing.T, srv *dokployfake.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	return callCtx(t, context.Background(), srv, method, path, token, body)
}

func callCtx(t *testing.T, ctx context.Context, srv *dokployfake.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, srv.URL()+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, raw
}

// decode unmarshals raw JSON into a generic map, failing the test on error.
func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode JSON %q: %v", raw, err)
	}
	return out
}

// idOf decodes raw and returns its "id" string field, failing the test when
// the field is absent or not a string.
func idOf(t *testing.T, raw []byte) string {
	t.Helper()
	id, ok := decode(t, raw)["id"].(string)
	if !ok {
		t.Fatalf("response has no string id field: %s", raw)
	}
	return id
}

// errCode decodes raw as a Dokploy-style error envelope and returns its
// error.code string.
func errCode(t *testing.T, raw []byte) string {
	t.Helper()
	obj, ok := decode(t, raw)["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error object: %s", raw)
	}
	code, ok := obj["code"].(string)
	if !ok {
		t.Fatalf("error object has no string code: %s", raw)
	}
	return code
}

// seedService creates a full org -> project -> environment -> application
// chain on srv and returns the application's service ID.
func seedService(t *testing.T, srv *dokployfake.Server) string {
	t.Helper()
	tok := srv.Token()

	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)
	orgID := idOf(t, raw)

	status, raw = call(t, srv, http.MethodPost, "/api/projects", tok,
		map[string]any{"organization_id": orgID, "name": "store"})
	requireStatus(t, status, http.StatusCreated, raw)
	projID := idOf(t, raw)

	status, raw = call(t, srv, http.MethodPost, "/api/environments", tok,
		map[string]any{"project_id": projID, "name": "production"})
	requireStatus(t, status, http.StatusCreated, raw)
	envID := idOf(t, raw)

	status, raw = call(t, srv, http.MethodPost, "/api/applications", tok,
		map[string]any{"environment_id": envID, "name": "api"})
	requireStatus(t, status, http.StatusCreated, raw)
	return idOf(t, raw)
}

func requireStatus(t *testing.T, got, want int, raw []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d (body: %s)", got, want, raw)
	}
}

func TestCreateHierarchyDeterministicIDs(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)
	if id := decode(t, raw)["id"]; id != "org_1" {
		t.Fatalf("organization id = %v, want org_1", id)
	}

	status, raw = call(t, srv, http.MethodPost, "/api/projects", tok,
		map[string]any{"organization_id": "org_1", "name": "store"})
	requireStatus(t, status, http.StatusCreated, raw)
	if id := decode(t, raw)["id"]; id != "proj_1" {
		t.Fatalf("project id = %v, want proj_1", id)
	}

	status, raw = call(t, srv, http.MethodPost, "/api/environments", tok,
		map[string]any{"project_id": "proj_1", "name": "production"})
	requireStatus(t, status, http.StatusCreated, raw)
	if id := decode(t, raw)["id"]; id != "env_1" {
		t.Fatalf("environment id = %v, want env_1", id)
	}

	for _, tc := range []struct {
		path   string
		body   map[string]any
		wantID string
	}{
		{"/api/applications", map[string]any{"environment_id": "env_1", "name": "api"}, "app_1"},
		{"/api/compose", map[string]any{"environment_id": "env_1", "name": "stack"}, "compose_1"},
		{"/api/databases", map[string]any{"environment_id": "env_1", "name": "pg", "engine": "postgres"}, "db_1"},
	} {
		status, raw = call(t, srv, http.MethodPost, tc.path, tok, tc.body)
		requireStatus(t, status, http.StatusCreated, raw)
		if id := decode(t, raw)["id"]; id != tc.wantID {
			t.Fatalf("%s id = %v, want %s", tc.path, id, tc.wantID)
		}
	}

	// A domain and a deployment round out the worker's provisioning surface.
	status, raw = call(t, srv, http.MethodPost, "/api/domains", tok,
		map[string]any{"service_id": "app_1", "host": "api.acme.test", "https": true})
	requireStatus(t, status, http.StatusCreated, raw)
	if id := decode(t, raw)["id"]; id != "domain_1" {
		t.Fatalf("domain id = %v, want domain_1", id)
	}

	status, raw = call(t, srv, http.MethodPost, "/api/deployments", tok,
		map[string]any{"service_id": "app_1"})
	requireStatus(t, status, http.StatusCreated, raw)
	dep := decode(t, raw)
	if dep["id"] != "dep_1" || dep["status"] != dokployfake.DeploymentSucceeded {
		t.Fatalf("deployment = %v, want id dep_1 status succeeded", dep)
	}
}

func TestTwoServersAreIndependentAndDeterministic(t *testing.T) {
	t.Parallel()
	first := dokployfake.New()
	defer first.Close()
	second := dokployfake.New()
	defer second.Close()

	body := map[string]any{"name": "acme"}
	s1, r1 := call(t, first, http.MethodPost, "/api/organizations", first.Token(), body)
	s2, r2 := call(t, second, http.MethodPost, "/api/organizations", second.Token(), body)
	requireStatus(t, s1, http.StatusCreated, r1)
	requireStatus(t, s2, http.StatusCreated, r2)

	// Two independent servers given the same call sequence mint the same
	// deterministic IDs, yet never share state.
	if decode(t, r1)["id"] != "org_1" || decode(t, r2)["id"] != "org_1" {
		t.Fatalf("expected both servers to mint org_1, got %s and %s", r1, r2)
	}
	if first.RequestCount() != 1 || second.RequestCount() != 1 {
		t.Fatalf("request counts not isolated: first=%d second=%d",
			first.RequestCount(), second.RequestCount())
	}
}

func TestGetReadsBackResources(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	svcID := seedService(t, srv)

	status, raw := call(t, srv, http.MethodGet, "/api/applications/"+svcID, srv.Token(), nil)
	requireStatus(t, status, http.StatusOK, raw)
	svc := decode(t, raw)
	if svc["id"] != svcID || svc["type"] != dokployfake.ServiceApplication {
		t.Fatalf("service = %v, want id %s type application", svc, svcID)
	}
	if svc["status"] != dokployfake.StatusRunning {
		t.Fatalf("service status = %v, want running", svc["status"])
	}

	status, raw = call(t, srv, http.MethodGet, "/api/services/"+svcID+"/status", srv.Token(), nil)
	requireStatus(t, status, http.StatusOK, raw)
	if st := decode(t, raw)["status"]; st != dokployfake.StatusRunning {
		t.Fatalf("status = %v, want running", st)
	}
}

func TestValidationFailures(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	// Missing required field.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok, map[string]any{})
	requireStatus(t, status, http.StatusBadRequest, raw)
	if code := errCode(t, raw); code != "bad_request" {
		t.Fatalf("error code = %v, want bad_request", code)
	}

	// A database needs an engine.
	srv.Reset()
	envID := seedEnvironment(t, srv)
	status, raw = call(t, srv, http.MethodPost, "/api/databases", tok,
		map[string]any{"environment_id": envID, "name": "pg"})
	requireStatus(t, status, http.StatusBadRequest, raw)

	// Malformed JSON body.
	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/api/organizations",
		strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	requireStatus(t, resp.StatusCode, http.StatusBadRequest, body)

	// Unknown field is rejected (DisallowUnknownFields).
	status, raw = call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme", "surprise": true})
	requireStatus(t, status, http.StatusBadRequest, raw)
}

func seedEnvironment(t *testing.T, srv *dokployfake.Server) string {
	t.Helper()
	tok := srv.Token()
	_, raw := call(t, srv, http.MethodPost, "/api/organizations", tok, map[string]any{"name": "acme"})
	orgID := idOf(t, raw)
	_, raw = call(t, srv, http.MethodPost, "/api/projects", tok,
		map[string]any{"organization_id": orgID, "name": "store"})
	projID := idOf(t, raw)
	_, raw = call(t, srv, http.MethodPost, "/api/environments", tok,
		map[string]any{"project_id": projID, "name": "production"})
	return idOf(t, raw)
}

func TestNotFound(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	// Unknown resource ID.
	status, raw := call(t, srv, http.MethodGet, "/api/organizations/org_404", tok, nil)
	requireStatus(t, status, http.StatusNotFound, raw)

	// Creating a child under a missing parent.
	status, raw = call(t, srv, http.MethodPost, "/api/projects", tok,
		map[string]any{"organization_id": "org_404", "name": "store"})
	requireStatus(t, status, http.StatusNotFound, raw)

	// An unrouted path is a JSON 404, not net/http's plain-text default.
	status, raw = call(t, srv, http.MethodGet, "/api/unknown", tok, nil)
	requireStatus(t, status, http.StatusNotFound, raw)
	if _, ok := decode(t, raw)["error"]; !ok {
		t.Fatalf("unrouted 404 is not a JSON error envelope: %s", raw)
	}
}

func TestConflict(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	body := map[string]any{"name": "acme"}
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok, body)
	requireStatus(t, status, http.StatusCreated, raw)

	status, raw = call(t, srv, http.MethodPost, "/api/organizations", tok, body)
	requireStatus(t, status, http.StatusConflict, raw)
	if code := errCode(t, raw); code != "conflict" {
		t.Fatalf("error code = %v, want conflict", code)
	}
}

func TestAuthRequired(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	body := map[string]any{"name": "acme"}

	// No credentials.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", "", body)
	requireStatus(t, status, http.StatusUnauthorized, raw)

	// Wrong credentials.
	status, raw = call(t, srv, http.MethodPost, "/api/organizations", "dkp_wrong_token_value", body)
	requireStatus(t, status, http.StatusUnauthorized, raw)

	// Correct credentials.
	status, raw = call(t, srv, http.MethodPost, "/api/organizations", srv.Token(), body)
	requireStatus(t, status, http.StatusCreated, raw)
}

func TestCustomToken(t *testing.T) {
	t.Parallel()
	const token = "dkp_custom_token_abcdef0123456789"
	srv := dokployfake.New(dokployfake.WithToken(token))
	defer srv.Close()

	if srv.Token() != token {
		t.Fatalf("Token() = %q, want %q", srv.Token(), token)
	}
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", token, map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)

	// The default token must no longer work.
	status, raw = call(t, srv, http.MethodPost, "/api/organizations", dokployfake.DefaultToken,
		map[string]any{"name": "other"})
	requireStatus(t, status, http.StatusUnauthorized, raw)
}

func TestFaultInjectionStatusCodes(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	statuses := []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests,
		http.StatusInternalServerError,
	}
	for _, want := range statuses {
		srv.QueueFault(dokployfake.StatusFault(want))
	}
	// Faults are consumed FIFO, one per request, regardless of the route.
	for _, want := range statuses {
		status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
			map[string]any{"name": "acme"})
		requireStatus(t, status, want, raw)
		if _, ok := decode(t, raw)["error"]; !ok {
			t.Fatalf("fault %d response is not a JSON error envelope: %s", want, raw)
		}
	}
	// The queue is now empty; the next request succeeds normally.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)
}

func TestFaultInjectionMalformedJSON(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()

	srv.QueueFault(dokployfake.MalformedJSONFault())
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", srv.Token(),
		map[string]any{"name": "acme"})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var sink map[string]any
	if err := json.Unmarshal(raw, &sink); err == nil {
		t.Fatalf("malformed fault body decoded cleanly, want a JSON error: %s", raw)
	}
}

func TestFaultInjectionTimeout(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()

	// A short timeout fault completes deterministically with 504.
	srv.QueueFault(dokployfake.TimeoutFault(time.Millisecond))
	status, raw := call(t, srv, http.MethodGet, "/api/organizations/org_1", srv.Token(), nil)
	requireStatus(t, status, http.StatusGatewayTimeout, raw)

	// A long timeout fault outlasts the caller's deadline: the request fails
	// client-side, exactly as a slow upstream would present to the worker.
	srv.QueueFault(dokployfake.TimeoutFault(5 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL()+"/api/organizations/org_1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("expected the request to fail against a hung upstream, got nil error")
	}
}

func TestRequestRecordingRedactsCredentials(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	// The request body deliberately echoes the bearer token to prove the
	// recorder scrubs secrets out of recorded bodies, not just headers.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme", "note": "token=" + tok})
	requireStatus(t, status, http.StatusBadRequest, raw) // unknown field rejected, but still recorded

	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(reqs))
	}
	rec := reqs[0]
	if rec.Method != http.MethodPost || rec.Path != "/api/organizations" {
		t.Fatalf("recorded request = %s %s, want POST /api/organizations", rec.Method, rec.Path)
	}
	if rec.AuthHeader != output.Sentinel {
		t.Fatalf("AuthHeader = %q, want the redaction sentinel", rec.AuthHeader)
	}
	if got := rec.Headers.Get("Authorization"); got != output.Sentinel {
		t.Fatalf("recorded Authorization header = %q, want the redaction sentinel", got)
	}
	if strings.Contains(rec.Body, tok) {
		t.Fatalf("recorded body leaked the bearer token: %s", rec.Body)
	}
	// Nothing the fake exposes about the request may contain the raw token.
	for _, field := range []string{rec.AuthHeader, rec.Body, rec.Headers.Get("Authorization")} {
		if strings.Contains(field, tok) {
			t.Fatalf("recorded request leaked the bearer token in %q", field)
		}
	}
}

func TestSetDeploymentAndServiceStatus(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()
	svcID := seedService(t, srv)

	status, raw := call(t, srv, http.MethodPost, "/api/deployments", tok,
		map[string]any{"service_id": svcID})
	requireStatus(t, status, http.StatusCreated, raw)
	depID := idOf(t, raw)

	if !srv.SetDeploymentStatus(depID, dokployfake.DeploymentFailed) {
		t.Fatal("SetDeploymentStatus reported the deployment missing")
	}
	if srv.SetDeploymentStatus("dep_missing", dokployfake.DeploymentFailed) {
		t.Fatal("SetDeploymentStatus accepted a missing deployment")
	}
	status, raw = call(t, srv, http.MethodGet, "/api/deployments/"+depID, tok, nil)
	requireStatus(t, status, http.StatusOK, raw)
	if st := decode(t, raw)["status"]; st != dokployfake.DeploymentFailed {
		t.Fatalf("deployment status = %v, want failed", st)
	}

	if !srv.SetServiceStatus(svcID, "crashed") {
		t.Fatal("SetServiceStatus reported the service missing")
	}
	status, raw = call(t, srv, http.MethodGet, "/api/services/"+svcID+"/status", tok, nil)
	requireStatus(t, status, http.StatusOK, raw)
	if st := decode(t, raw)["status"]; st != "crashed" {
		t.Fatalf("service status = %v, want crashed", st)
	}

	// Deployment logs are deterministic and readable.
	status, raw = call(t, srv, http.MethodGet, "/api/deployments/"+depID+"/logs", tok, nil)
	requireStatus(t, status, http.StatusOK, raw)
	lines, ok := decode(t, raw)["lines"].([]any)
	if !ok || len(lines) == 0 {
		t.Fatalf("deployment logs = %s, want non-empty lines", raw)
	}
}

func TestResetClearsState(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	_, _ = call(t, srv, http.MethodPost, "/api/organizations", tok, map[string]any{"name": "acme"})
	srv.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))
	srv.Reset()

	if srv.RequestCount() != 0 {
		t.Fatalf("RequestCount after Reset = %d, want 0", srv.RequestCount())
	}
	// The queued fault was cleared, so the next request is served normally,
	// and IDs restart from 1.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok, map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)
	if id := decode(t, raw)["id"]; id != "org_1" {
		t.Fatalf("organization id after Reset = %v, want org_1", id)
	}
}

// TestFakeDokployContractDeterministicHierarchyIDs is the canonical
// determinism half of the BE-0386 fake-Dokploy contract pair. The
// PRD's `go test -run TestFakeDokploy ./...` filter binds to the
// `TestFakeDokploy` prefix, so this function name is part of the
// public contract — a rename to a name that does not match the
// prefix silently de-gates the fake-Dokploy suite for any caller
// relying on the filter (CI, verify.sh, CONTRIBUTING.md,
// SECURITY.md, ralph/prd.json).
//
// Two independent `dokployfake.New()` servers each provisioned with
// the same org -> project -> environment -> application sequence
// MUST mint byte-identical resource IDs at every level, while keeping
// their own per-server state isolated. The determinism is what makes
// the fake usable as a deterministic fixture (AC2) — every test that
// drives the same call sequence sees the same IDs across runs and
// across goroutines, so failures are reproducible from the recorded
// log alone, no "flaky on Tuesday" mystery to chase.
func TestFakeDokployContractDeterministicHierarchyIDs(t *testing.T) {
	t.Parallel()
	first := dokployfake.New()
	defer first.Close()
	second := dokployfake.New()
	defer second.Close()

	// chain provisions a full org -> project -> environment ->
	// application -> deployment hierarchy against srv and returns
	// the resource IDs at every level in stable order so a divergence
	// between the two servers points the caller at the exact layer
	// that drifted.
	chain := func(srv *dokployfake.Server) []string {
		t.Helper()
		tok := srv.Token()

		_, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
			map[string]any{"name": "acme"})
		orgID := idOf(t, raw)
		_, raw = call(t, srv, http.MethodPost, "/api/projects", tok,
			map[string]any{"organization_id": orgID, "name": "store"})
		projID := idOf(t, raw)
		_, raw = call(t, srv, http.MethodPost, "/api/environments", tok,
			map[string]any{"project_id": projID, "name": "production"})
		envID := idOf(t, raw)
		_, raw = call(t, srv, http.MethodPost, "/api/applications", tok,
			map[string]any{"environment_id": envID, "name": "api"})
		appID := idOf(t, raw)
		_, raw = call(t, srv, http.MethodPost, "/api/deployments", tok,
			map[string]any{"service_id": appID})
		depID := idOf(t, raw)
		return []string{orgID, projID, envID, appID, depID}
	}

	firstIDs := chain(first)
	secondIDs := chain(second)

	if len(firstIDs) != len(secondIDs) {
		t.Fatalf("hierarchy length differs: first=%d second=%d", len(firstIDs), len(secondIDs))
	}
	wantIDs := []string{"org_1", "proj_1", "env_1", "app_1", "dep_1"}
	for i, want := range wantIDs {
		if firstIDs[i] != want {
			t.Errorf("first server hierarchy[%d] = %q, want %q", i, firstIDs[i], want)
		}
		if secondIDs[i] != want {
			t.Errorf("second server hierarchy[%d] = %q, want %q", i, secondIDs[i], want)
		}
		if firstIDs[i] != secondIDs[i] {
			t.Errorf("hierarchy[%d] diverges between independent servers: first=%q second=%q",
				i, firstIDs[i], secondIDs[i])
		}
	}

	// Per-server request counts MUST remain isolated — determinism
	// applies to the issued IDs, not to a shared global counter. Each
	// chain submits 5 POSTs.
	if first.RequestCount() != 5 || second.RequestCount() != 5 {
		t.Errorf("request counts not isolated: first=%d second=%d (want 5/5)",
			first.RequestCount(), second.RequestCount())
	}
}

// TestFakeDokployContractRecordedRequestsRedactCredentials is the
// canonical credential-redaction half of the BE-0386 fake-Dokploy
// contract pair. The PRD's `go test -run TestFakeDokploy ./...`
// filter binds to the `TestFakeDokploy` prefix, so this function
// name is part of the public contract — a rename silently de-gates
// the suite.
//
// The fake's recorder is the single seam between a worker test and
// any operator who reads a CI log: every recorded request MUST have
// its Authorization header replaced by the redaction sentinel, and
// no recorded body may carry the bearer token verbatim — even when
// the caller deliberately echoes the token into a request body
// (AC8). The contract holds across every kind of request the worker
// might issue (creates that succeed, creates that 4xx, GETs that
// return read-back state), not just the happy path.
func TestFakeDokployContractRecordedRequestsRedactCredentials(t *testing.T) {
	t.Parallel()
	srv := dokployfake.New()
	defer srv.Close()
	tok := srv.Token()

	// 1. A successful create.
	status, raw := call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "acme"})
	requireStatus(t, status, http.StatusCreated, raw)
	orgID := idOf(t, raw)

	// 2. A GET that reads the resource back — recorder still records.
	status, raw = call(t, srv, http.MethodGet, "/api/organizations/"+orgID, tok, nil)
	requireStatus(t, status, http.StatusOK, raw)

	// 3. A request whose body intentionally echoes the bearer token
	//    so a recorder that only scrubs headers would leak. The
	//    DisallowUnknownFields validator rejects the body with 400,
	//    but the request is still recorded — exactly the failure-path
	//    case AC8 protects.
	status, raw = call(t, srv, http.MethodPost, "/api/organizations", tok,
		map[string]any{"name": "leaky", "note": "token=" + tok})
	requireStatus(t, status, http.StatusBadRequest, raw)

	reqs := srv.Requests()
	if len(reqs) != 3 {
		t.Fatalf("recorded %d requests, want 3", len(reqs))
	}
	for i, rec := range reqs {
		if rec.AuthHeader != output.Sentinel {
			t.Errorf("recorded request %d (%s %s): AuthHeader = %q, want redaction sentinel",
				i, rec.Method, rec.Path, rec.AuthHeader)
		}
		if got := rec.Headers.Get("Authorization"); got != output.Sentinel {
			t.Errorf("recorded request %d (%s %s): Headers[Authorization] = %q, want redaction sentinel",
				i, rec.Method, rec.Path, got)
		}
		if strings.Contains(rec.Body, tok) {
			t.Errorf("recorded request %d (%s %s) leaked the bearer token in body: %s",
				i, rec.Method, rec.Path, rec.Body)
		}
		// Nothing the recorder exposes about the request may contain
		// the raw token in any field — header, body, or any other
		// projection a future field could add.
		for name, field := range map[string]string{
			"AuthHeader":     rec.AuthHeader,
			"Body":           rec.Body,
			"Header[Auth]":   rec.Headers.Get("Authorization"),
			"Header[Bearer]": rec.Headers.Get("Bearer"),
		} {
			if strings.Contains(field, tok) {
				t.Errorf("recorded request %d (%s %s) leaked bearer in %s: %q",
					i, rec.Method, rec.Path, name, field)
			}
		}
	}
}
