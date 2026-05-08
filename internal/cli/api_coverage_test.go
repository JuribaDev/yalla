package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// apiCoverageCase locks the per-operation contract that every Dokploy
// API operation story (API-0001 onward in `ralph/prd.json`) signs off on.
//
// The harness below loops over `coveredAPIOperations` and runs the same
// five-part check for each entry: registry presence (ID/method/path/tag
// invariant), schema reachability, manifest inclusion, an httptest-backed
// success exchange, and at least one representative failure path. Adding
// coverage for a new API-XXXX story therefore only ever means appending
// one struct literal — never duplicating boilerplate.
type apiCoverageCase struct {
	// StoryID is the PRD identifier (e.g. "API-0001"). Used in subtest
	// names so a failing assertion points back to the story it gates.
	StoryID string

	// OperationID is the OpenAPI operationId surfaced by the registry,
	// e.g. "admin-setupMonitoring".
	OperationID string

	// Method, Path, and Tag are the registry-level invariants the story's
	// acceptance criteria explicitly call out. Any spec drift between
	// `data/openapi.json` and the story manifest must fail this test
	// before it can ship.
	Method string
	Path   string
	Tag    string

	// SampleBody is a representative JSON request body for operations
	// that declare `requestBody.required = true`. The bytes are sent
	// verbatim to the httptest server so the success path exercises real
	// JSON serialisation, content-type negotiation, and body forwarding.
	// Operations with no body leave this nil.
	SampleBody json.RawMessage

	// SampleQuery / SamplePathParams cover the equivalent acceptance
	// criteria for operations that declare query parameters or
	// `{placeholder}` path segments. The harness ignores empty maps so
	// most operations do not need to populate them.
	SampleQuery      map[string][]string
	SamplePathParams map[string]string

	// SuccessStatus is the HTTP status the httptest server returns for
	// the success leg. Defaults to 200 when zero so most cases stay
	// short.
	SuccessStatus int

	// SuccessResponse is the JSON document returned by the httptest
	// server on success. Defaults to `{}` so omitting it keeps the body
	// valid JSON.
	SuccessResponse string

	// FailureStatus is the HTTP status code the failure leg returns.
	// Defaults to 401 (the most representative failure for an
	// authenticated Dokploy operation) when zero.
	FailureStatus int

	// FailureCode is the typed yerr.Code the renderer must surface for
	// FailureStatus. Defaults to yerr.CodeAuth when empty.
	FailureCode yerr.Code
}

// coveredAPIOperations is the append-only registry of API-XXXX stories
// that have shipped per-operation contract coverage. Each subsequent
// API story adds exactly one entry here; the harness below proves the
// invariants automatically.
//
// Keep entries sorted by StoryID for diff-friendliness.
var coveredAPIOperations = []apiCoverageCase{
	{
		StoryID:     "API-0001",
		OperationID: "admin-setupMonitoring",
		Method:      http.MethodPost,
		Path:        "/admin.setupMonitoring",
		Tag:         "admin",
		// Mirrors the schema in `data/openapi.json` for /admin.setupMonitoring:
		// the only required top-level field is `metricsConfig`, which itself
		// requires `server` (with `refreshRate`) and `containers`. We supply
		// a minimal-but-valid shape so a future schema validator will not
		// reject the fixture.
		SampleBody: json.RawMessage(`{
			"metricsConfig": {
				"server": {
					"refreshRate": 5,
					"port": 4500,
					"cronJob": "*/5 * * * *",
					"urlCallback": "https://example.test/callback",
					"thresholds": {
						"cpu": 80,
						"memory": 80
					}
				},
				"containers": {
					"refreshRate": 30,
					"services": {
						"include": ["dokploy"],
						"exclude": []
					}
				}
			}
		}`),
		SuccessResponse: `{"ok":true}`,
	},
	{
		StoryID:     "API-0002",
		OperationID: "ai-create",
		Method:      http.MethodPost,
		Path:        "/ai.create",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.create:
		// every top-level field (`name`, `apiUrl`, `apiKey`, `model`,
		// `isEnabled`) is required, so the fixture supplies all five
		// with deterministic-but-clearly-fake values. The bytes only
		// ever live in a per-test `t.TempDir()` so the placeholder
		// `apiKey` does not leak between cases.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-ai-create-0002",
			"apiUrl": "https://example.test/v1",
			"apiKey": "fake-api-key-coverage-0002",
			"model": "gpt-test",
			"isEnabled": true
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`.
		// Keep the body empty-object so the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0003",
		OperationID: "ai-delete",
		Method:      http.MethodPost,
		Path:        "/ai.delete",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.delete: the
		// only required field is `aiId` (string). Keep the fixture
		// minimal-but-valid so a future schema validator wired into the
		// harness still accepts it.
		SampleBody: json.RawMessage(`{
			"aiId": "ai-cov-delete-0003"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other ai/* and application/* peers. We keep an
		// empty-object body so the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0011",
		OperationID: "application-cancelDeployment",
		Method:      http.MethodPost,
		Path:        "/application.cancelDeployment",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.cancelDeployment: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-cancel-deploy-0011"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`.
		// We keep an empty-object body so the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0012",
		OperationID: "application-cleanQueues",
		Method:      http.MethodPost,
		Path:        "/application.cleanQueues",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.cleanQueues: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-clean-queues-0012"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching application-cancelDeployment. We keep an empty-object body
		// so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0013",
		OperationID: "application-clearDeployments",
		Method:      http.MethodPost,
		Path:        "/application.clearDeployments",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.clearDeployments: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-clear-deploys-0013"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching application-cancelDeployment / application-cleanQueues.
		// We keep an empty-object body so the success-leg envelope
		// assertion stays focused on `data.method` / `data.status`
		// rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0014",
		OperationID: "application-create",
		Method:      http.MethodPost,
		Path:        "/application.create",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.create:
		// the required top-level fields are `name` and `environmentId`. The
		// optional `appName`, `description`, and `serverId` fields are also
		// supplied with deterministic-but-clearly-fake values so the wire
		// fixture exercises the full create payload, not just the minimum.
		// `description` and `serverId` use anyOf [string, null]; we send the
		// string variant so the fixture remains valid against either branch
		// once a future schema validator is wired into the harness.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-app-create-0014",
			"appName": "yalla-cov-app-create-0014",
			"description": "API-0014 fixture for application-create coverage",
			"environmentId": "env-cov-app-create-0014",
			"serverId": "srv-cov-app-create-0014"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
}

// TestAPICoverage_RegistryInvariants asserts that every covered story's
// operationId is present in the embedded OpenAPI registry with exactly
// the method, path, and tag the PRD declared. This catches spec drift
// (e.g. a future Dokploy revision renaming an endpoint) before the binary
// ships.
func TestAPICoverage_RegistryInvariants(t *testing.T) {
	reg := api.Default()
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			op, ok := reg.Get(tc.OperationID)
			if !ok {
				t.Fatalf("registry missing operationId %q", tc.OperationID)
			}
			if op.Method != tc.Method {
				t.Errorf("method = %q, want %q", op.Method, tc.Method)
			}
			if op.Path != tc.Path {
				t.Errorf("path = %q, want %q", op.Path, tc.Path)
			}
			if op.Tag != tc.Tag {
				t.Errorf("tag = %q, want %q", op.Tag, tc.Tag)
			}
		})
	}
}

// TestAPICoverage_SchemaCommandWorks asserts the dedicated
// `yalla schema get <operationId> --json` command resolves every covered
// operation and emits the documented envelope. This is the
// "Schema command works: yalla schema get …" line item from each
// API-XXXX story's acceptance criteria.
func TestAPICoverage_SchemaCommandWorks(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			stdout, stderr, err := runRootArgs(t, "--json", "schema", "get", tc.OperationID)
			if err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
			}

			var env struct {
				SchemaVersion string `json:"schema_version"`
				Data          struct {
					OperationID string `json:"operation_id"`
					Method      string `json:"method"`
					Path        string `json:"path"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("decode: %v; raw=%q", err, stdout)
			}
			if env.SchemaVersion != output.SuccessSchema {
				t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
			}
			if env.Data.OperationID != tc.OperationID {
				t.Errorf("data.operation_id = %q, want %q", env.Data.OperationID, tc.OperationID)
			}
			if env.Data.Method != tc.Method {
				t.Errorf("data.method = %q, want %q", env.Data.Method, tc.Method)
			}
			if env.Data.Path != tc.Path {
				t.Errorf("data.path = %q, want %q", env.Data.Path, tc.Path)
			}
		})
	}
}

// TestAPICoverage_ManifestListsOperation asserts the `yalla manifest`
// envelope advertises every covered operation. The aggregate
// `TestManifest_JSONIncludesEveryAPIOperation` already locks the full
// set; this per-story check is intentionally redundant so a single
// failing assertion points at the right PRD entry.
func TestAPICoverage_ManifestListsOperation(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr should be empty; got %q", stderr)
	}

	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	listed := make(map[string]struct{}, len(env.Data.Operations.IDs))
	for _, id := range env.Data.Operations.IDs {
		listed[id] = struct{}{}
	}
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			if _, ok := listed[tc.OperationID]; !ok {
				t.Errorf("manifest operations.ids missing %q", tc.OperationID)
			}
		})
	}
}

// TestAPICoverage_SuccessRoundTrip drives `yalla api call <operationId>
// --json` through an httptest.Server for every covered operation and
// asserts the contract: stable success envelope, deterministic body
// forwarding, and the registry-declared method/path on the wire.
//
// This is the success leg of the PRD's
// "Add unit or contract tests using httptest fixtures for success and
//
//	at least one representative failure path." line item.
func TestAPICoverage_SuccessRoundTrip(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			runAPICoverageSuccess(t, tc)
		})
	}
}

// TestAPICoverage_RepresentativeFailure exercises the failure leg of the
// same acceptance criterion. We default to a 401 → CodeAuth mapping
// because every covered Dokploy operation today requires authentication;
// stories may override the status/code via the case fields.
func TestAPICoverage_RepresentativeFailure(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			runAPICoverageFailure(t, tc)
		})
	}
}

// runAPICoverageSuccess is the body of the success-leg subtest. It is
// extracted so individual cases can call it directly from a future
// per-operation test file when a story needs richer assertions than
// the default harness offers.
func runAPICoverageSuccess(t *testing.T, tc apiCoverageCase) {
	t.Helper()

	wantStatus := tc.SuccessStatus
	if wantStatus == 0 {
		wantStatus = http.StatusOK
	}
	wantBody := tc.SuccessResponse
	if wantBody == "" {
		wantBody = "{}"
	}

	var (
		seenMethod      string
		seenPath        string
		seenAuth        string
		seenContentType string
		seenQuery       url.Values
		seenBody        []byte
	)
	srv := setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenAuth = r.Header.Get("Authorization")
		seenContentType = r.Header.Get("Content-Type")
		seenQuery = r.URL.Query()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server read body: %v", err)
		}
		seenBody = body
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-coverage-"+tc.OperationID)
		w.WriteHeader(wantStatus)
		_, _ = w.Write([]byte(wantBody))
	})
	_ = srv

	args := []string{"--json", "api", "call", tc.OperationID}
	args = append(args, buildCoverageInputArgs(t, tc)...)

	stdout, stderr, err := runRootArgs(t, args...)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	if seenMethod != tc.Method {
		t.Errorf("server method = %q, want %q", seenMethod, tc.Method)
	}
	resolvedPath, err := substitutePathParams(tc.Path, tc.SamplePathParams)
	if err != nil {
		t.Fatalf("substitutePathParams: %v", err)
	}
	if seenPath != resolvedPath {
		t.Errorf("server path = %q, want %q", seenPath, resolvedPath)
	}
	if seenAuth != "Bearer test-token-value" {
		t.Errorf("Authorization header = %q, want Bearer test-token-value", seenAuth)
	}
	if len(tc.SampleBody) > 0 {
		if !strings.HasPrefix(seenContentType, "application/json") {
			t.Errorf("Content-Type = %q, want application/json…", seenContentType)
		}
		if len(seenBody) == 0 {
			t.Errorf("server received empty body; expected forwarded request")
		} else {
			// The CLI forwards the bytes verbatim; round-trip through the
			// JSON decoder so whitespace differences do not cause flakes.
			var got, want any
			if err := json.Unmarshal(seenBody, &got); err != nil {
				t.Errorf("server body is not valid JSON: %v (raw=%q)", err, string(seenBody))
			}
			if err := json.Unmarshal(tc.SampleBody, &want); err != nil {
				t.Fatalf("test fixture body is not valid JSON: %v", err)
			}
			gotBytes, _ := json.Marshal(got)
			wantBytes, _ := json.Marshal(want)
			if string(gotBytes) != string(wantBytes) {
				t.Errorf("server body mismatch:\n got=%s\nwant=%s", string(gotBytes), string(wantBytes))
			}
		}
	}
	for k, want := range tc.SampleQuery {
		if got := seenQuery[k]; !equalStringSlice(got, want) {
			t.Errorf("query[%q] = %v, want %v", k, got, want)
		}
	}

	var env struct {
		SchemaVersion string            `json:"schema_version"`
		Data          apiCallSuccessDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.OperationID != tc.OperationID {
		t.Errorf("data.operation_id = %q, want %q", env.Data.OperationID, tc.OperationID)
	}
	if env.Data.Status != wantStatus {
		t.Errorf("data.status = %d, want %d", env.Data.Status, wantStatus)
	}
	if env.Data.Method != tc.Method {
		t.Errorf("data.method = %q, want %q", env.Data.Method, tc.Method)
	}
}

// runAPICoverageFailure is the body of the failure-leg subtest, kept
// public-by-test-package so future per-operation files can reuse it.
func runAPICoverageFailure(t *testing.T, tc apiCoverageCase) {
	t.Helper()

	failStatus := tc.FailureStatus
	if failStatus == 0 {
		failStatus = http.StatusUnauthorized
	}
	failCode := tc.FailureCode
	if failCode == "" {
		failCode = yerr.CodeAuth
	}

	srv := setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(failStatus)
		_, _ = w.Write([]byte(`{"error":"representative failure"}`))
	})
	_ = srv

	args := []string{"--json", "api", "call", tc.OperationID}
	args = append(args, buildCoverageInputArgs(t, tc)...)

	stdout, stderr, err := runRootArgs(t, args...)
	if err == nil {
		t.Fatalf("expected failure for status %d", failStatus)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	if !strings.Contains(stderr, string(failCode)) {
		t.Errorf("expected %q in stderr; got %q", failCode, stderr)
	}
	if !strings.Contains(stderr, yerr.SchemaVersion) {
		t.Errorf("expected %q envelope in stderr; got %q", yerr.SchemaVersion, stderr)
	}
}

// buildCoverageInputArgs writes the case's path/query/body into a temp
// `--input` JSON file and returns the matching CLI flags. Empty cases
// return no extra args so operations without inputs stay terse.
func buildCoverageInputArgs(t *testing.T, tc apiCoverageCase) []string {
	t.Helper()
	if len(tc.SampleBody) == 0 && len(tc.SampleQuery) == 0 && len(tc.SamplePathParams) == 0 {
		return nil
	}
	doc := struct {
		PathParams map[string]string   `json:"path_params,omitempty"`
		Query      map[string][]string `json:"query,omitempty"`
		Body       json.RawMessage     `json:"body,omitempty"`
	}{
		PathParams: tc.SamplePathParams,
		Query:      tc.SampleQuery,
		Body:       tc.SampleBody,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal coverage input: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, tc.OperationID+".json")
	// 0o600 mirrors the production redactor pattern so a stray --input
	// fixture cannot leak a secret to other users on the host.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write coverage input: %v", err)
	}
	return []string{"--input", path}
}

// equalStringSlice is a non-allocating slice equality helper used by the
// query-parameter assertion. We deliberately avoid reflect.DeepEqual so
// the failure messages above stay readable.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
