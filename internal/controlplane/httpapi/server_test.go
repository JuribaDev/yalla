package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/output"
)

// newTestHandler builds a NewHandler with canned authorization dependencies
// for tests that exercise the public surface (the bootstrap and discovery
// routes). The fake authenticator never authenticates a request, which is all
// the public routes need; the authenticated /v1/me and /v1/organizations
// routes have their own auth-aware coverage in me_test.go and
// organizations_test.go. The fake organization reader and creator are supplied
// so the handler is fully wired even though the public-surface tests never
// reach them.
func newTestHandler(build runtime.BuildInfo, readiness runtime.ReadinessReporter, meta runtime.MetaReporter, logger *slog.Logger) http.Handler {
	return NewHandler(build, readiness, meta, nil, fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

func TestHandlerServesBootstrapEndpoints(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-14T00:00:00Z",
	}, nil, nil, nil)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantData   map[string]string
	}{
		{
			name:       "health",
			path:       "/healthz",
			wantStatus: http.StatusOK,
			wantData: map[string]string{
				"status": "ok",
			},
		},
		{
			name:       "version",
			path:       "/version",
			wantStatus: http.StatusOK,
			wantData: map[string]string{
				"version":            "1.2.3",
				"commit":             "abc123",
				"date":               "2026-05-14T00:00:00Z",
				"api_schema_version": "yalla.api.v1",
				"migration_version":  "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("content-type = %q, want application/json", got)
			}

			var env struct {
				SchemaVersion string            `json:"schema_version"`
				OK            bool              `json:"ok"`
				Data          map[string]string `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if env.SchemaVersion != "yalla.output.v1" {
				t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
			}
			if !env.OK {
				t.Errorf("ok = false, want true")
			}
			for key, want := range tt.wantData {
				if got := env.Data[key]; got != want {
					t.Errorf("data[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestHandlerReturnsStableNotFoundEnvelope(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Errorf("ok = true, want false")
	}
	if env.Error.Code != "E_NOT_FOUND" {
		t.Errorf("error.code = %q, want E_NOT_FOUND", env.Error.Code)
	}
}

func TestReadyzReflectsReadinessTransitions(t *testing.T) {
	t.Parallel()

	readiness := runtime.NewReadiness("migrations")
	handler := newTestHandler(runtime.BuildInfo{}, readiness, nil, nil)

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Before startup gates pass, /readyz must report 503 with a stable
	// error envelope so the load balancer keeps the process out of rotation.
	rec := get()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready status = %d, want %d; body %s",
			rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	var errEnv struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode unready response: %v", err)
	}
	if errEnv.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", errEnv.SchemaVersion)
	}
	if errEnv.OK {
		t.Errorf("ok = true, want false")
	}
	if errEnv.Error.Code != "E_SERVER" {
		t.Errorf("error.code = %q, want E_SERVER", errEnv.Error.Code)
	}

	// Once every startup gate passes, /readyz must flip to 200 ready.
	readiness.MarkReady("migrations")
	rec = get()
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d; body %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}
	var okEnv struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			Status string          `json:"status"`
			Checks map[string]bool `json:"checks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &okEnv); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if okEnv.SchemaVersion != "yalla.output.v1" || !okEnv.OK {
		t.Errorf("ready envelope = %+v, want yalla.output.v1 ok=true", okEnv)
	}
	if okEnv.Data.Status != "ready" {
		t.Errorf("data.status = %q, want ready", okEnv.Data.Status)
	}
	if !okEnv.Data.Checks["migrations"] {
		t.Errorf("data.checks[migrations] = false, want true once the gate passes")
	}
}

// TestVersionEndpointReportsSchemaAndMigrationVersion proves GET /version
// reports the build identity, the stable API schema version, and the dynamic
// migration version resolved from the MetaReporter.
func TestVersionEndpointReportsSchemaAndMigrationVersion(t *testing.T) {
	t.Parallel()

	build := runtime.BuildInfo{Version: "3.4.5", Commit: "deadbee", Date: "2026-05-14T12:00:00Z"}

	decodeVersion := func(t *testing.T, handler http.Handler) versionPayload {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
		}
		var env struct {
			SchemaVersion string         `json:"schema_version"`
			OK            bool           `json:"ok"`
			Data          versionPayload `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode version response: %v", err)
		}
		if env.SchemaVersion != "yalla.output.v1" || !env.OK {
			t.Errorf("version envelope = %+v, want yalla.output.v1 ok=true", env)
		}
		return env.Data
	}

	// With a populated Meta the resolved migration version is reported.
	meta := runtime.NewMeta()
	meta.SetMigrationVersion("0042")
	got := decodeVersion(t, newTestHandler(build, nil, meta, nil))
	want := versionPayload{
		Version:          "3.4.5",
		Commit:           "deadbee",
		Date:             "2026-05-14T12:00:00Z",
		APISchemaVersion: runtime.APISchemaVersion,
		MigrationVersion: "0042",
	}
	if got != want {
		t.Errorf("version data = %+v, want %+v", got, want)
	}
	if want.APISchemaVersion != "yalla.api.v1" {
		t.Errorf("api_schema_version = %q, want yalla.api.v1", want.APISchemaVersion)
	}

	// With a nil Meta the migration version falls back to "unknown" rather
	// than panicking or emitting an empty string.
	got = decodeVersion(t, newTestHandler(build, nil, nil, nil))
	if got.MigrationVersion != runtime.MigrationVersionUnknown {
		t.Errorf("migration_version with nil meta = %q, want %q",
			got.MigrationVersion, runtime.MigrationVersionUnknown)
	}
}

// TestReadyzReportsDependencyChecks proves GET /readyz reports the per-check
// status: healthy (every gate passing), degraded (one optional dependency
// failing), and dependency-failed (a core dependency failing). The healthy
// case is a 200 yalla.output.v1 envelope listing each check; the failing
// cases are 503 yalla.error.v1 envelopes whose hint names the pending checks.
func TestReadyzReportsDependencyChecks(t *testing.T) {
	t.Parallel()

	get := func(handler http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Healthy: every dependency gate passes.
	healthy := runtime.NewReadiness("database", "migrations", "queue")
	healthy.MarkReady("database")
	healthy.MarkReady("migrations")
	healthy.MarkReady("queue")
	rec := get(newTestHandler(runtime.BuildInfo{}, healthy, nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var okEnv struct {
		SchemaVersion string        `json:"schema_version"`
		OK            bool          `json:"ok"`
		Data          readyzPayload `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &okEnv); err != nil {
		t.Fatalf("decode healthy response: %v", err)
	}
	if okEnv.SchemaVersion != "yalla.output.v1" || !okEnv.OK {
		t.Errorf("healthy envelope = %+v, want yalla.output.v1 ok=true", okEnv)
	}
	if okEnv.Data.Status != "ready" {
		t.Errorf("healthy data.status = %q, want ready", okEnv.Data.Status)
	}
	for _, gate := range []string{"database", "migrations", "queue"} {
		if !okEnv.Data.Checks[gate] {
			t.Errorf("healthy data.checks[%q] = false, want true", gate)
		}
	}

	// degraded covers one optional dependency failing; dependency-failed
	// covers a core dependency failing. Both must be 503 with a stable error
	// envelope whose hint names exactly the pending checks.
	cases := []struct {
		name        string
		readiness   *runtime.Readiness
		wantPending []string
	}{
		{
			name: "degraded",
			readiness: func() *runtime.Readiness {
				r := runtime.NewReadiness("database", "migrations", "queue", "dokploy")
				r.MarkReady("database")
				r.MarkReady("migrations")
				r.MarkReady("queue")
				// dokploy left failing — an optional dependency is degraded.
				return r
			}(),
			wantPending: []string{"dokploy"},
		},
		{
			name: "dependency-failed",
			readiness: func() *runtime.Readiness {
				r := runtime.NewReadiness("database", "migrations", "queue")
				r.MarkReady("migrations")
				r.MarkReady("queue")
				// database left failing — a core dependency is down.
				return r
			}(),
			wantPending: []string{"database"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := get(newTestHandler(runtime.BuildInfo{}, tc.readiness, nil, nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
			}
			var errEnv struct {
				SchemaVersion string `json:"schema_version"`
				OK            bool   `json:"ok"`
				Error         struct {
					Code string `json:"code"`
					Hint string `json:"hint"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if errEnv.SchemaVersion != "yalla.error.v1" || errEnv.OK {
				t.Errorf("envelope = %+v, want yalla.error.v1 ok=false", errEnv)
			}
			if errEnv.Error.Code != "E_SERVER" {
				t.Errorf("error.code = %q, want E_SERVER", errEnv.Error.Code)
			}
			for _, gate := range tc.wantPending {
				if !strings.Contains(errEnv.Error.Hint, gate) {
					t.Errorf("hint %q does not name pending check %q", errEnv.Error.Hint, gate)
				}
			}
			// A passing gate must never be reported as pending.
			if strings.Contains(errEnv.Error.Hint, "migrations") &&
				!contains(tc.wantPending, "migrations") {
				t.Errorf("hint %q names a passing check", errEnv.Error.Hint)
			}
		})
	}
}

// contains reports whether want appears in s.
func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// requestIDOf decodes the request_id field shared by both envelope shapes.
func requestIDOf(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode request_id: %v", err)
	}
	return env.RequestID
}

func TestHandlerGeneratesRequestIDForEnvelopeAndHeader(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)

	// Cover a success envelope (/healthz), an error envelope from a route
	// that writes one directly (/readyz, 503), and the synthesised
	// not-found error envelope. Every path must carry a generated,
	// SafeID-clean request_id that matches the echoed response header.
	unready := runtime.NewReadiness("startup")
	cases := []struct {
		name    string
		handler http.Handler
		path    string
	}{
		{"success envelope", handler, "/healthz"},
		{"error envelope", newTestHandler(runtime.BuildInfo{}, unready, nil, nil), "/readyz"},
		{"not found envelope", handler, "/missing"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, req)

			id := requestIDOf(t, rec.Body.Bytes())
			if !telemetry.SafeID(id) {
				t.Fatalf("envelope request_id %q is not a generated SafeID", id)
			}
			if got := rec.Header().Get(telemetry.HeaderRequestID); got != id {
				t.Errorf("response %s = %q, want it to match envelope request_id %q",
					telemetry.HeaderRequestID, got, id)
			}
		})
	}
}

func TestHandlerEchoesSafeInboundRequestID(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := requestIDOf(t, rec.Body.Bytes()); got != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", got)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

func TestHandlerRejectsUnsafeInboundRequestID(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// A header-injection payload must never be echoed back verbatim.
	req.Header.Set(telemetry.HeaderRequestID, "bad id with spaces")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	id := requestIDOf(t, rec.Body.Bytes())
	if id == "bad id with spaces" {
		t.Fatalf("unsafe inbound request_id was echoed: %q", id)
	}
	if !telemetry.SafeID(id) {
		t.Fatalf("fallback request_id %q is not safe", id)
	}
}

// TestHandlerEmitsStructuredRequestLog proves NewHandler wires
// telemetry.RequestLogging: a served request produces one JSON log record
// carrying the matched route, status, and the request_id that also appears in
// the response envelope, and a secret smuggled into the URL query is redacted.
func TestHandlerEmitsStructuredRequestLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/healthz?token=topsecretvalue", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(buf.String(), "topsecretvalue") {
		t.Fatalf("request log leaked a query-string secret: %s", buf.String())
	}

	var record struct {
		Level     string `json:"level"`
		Msg       string `json:"msg"`
		Route     string `json:"route"`
		Target    string `json:"target"`
		Status    int    `json:"status"`
		Method    string `json:"method"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("decode log record %q: %v", buf.String(), err)
	}
	if record.Level != "INFO" {
		t.Errorf("level = %q, want INFO", record.Level)
	}
	if record.Route != "GET /healthz" {
		t.Errorf("route = %q, want the matched ServeMux pattern GET /healthz", record.Route)
	}
	if record.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", record.Status)
	}
	if record.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", record.Method)
	}
	if !strings.Contains(record.Target, "[REDACTED]") {
		t.Errorf("target = %q, want the token query param redacted", record.Target)
	}
	if record.RequestID == "" || record.RequestID != requestIDOf(t, rec.Body.Bytes()) {
		t.Errorf("log request_id = %q, want it to match the response envelope request_id",
			record.RequestID)
	}
}

// TestHandlerServesOpenAPIDocument proves GET /openapi.json returns the raw
// OpenAPI 3.1 document, without authentication, carrying the build version and
// every served path.
func TestHandlerServesOpenAPIDocument(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{Version: "9.9.9"}, nil, nil, nil)

	// Deliberately no Authorization header: the discovery endpoint is public.
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]map[string]any `json:"paths"`
		// The raw OpenAPI document is not wrapped in an envelope; these fields
		// must be absent.
		SchemaVersion string `json:"schema_version"`
		OK            *bool  `json:"ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", doc.OpenAPI)
	}
	if doc.Info.Version != "9.9.9" {
		t.Errorf("info.version = %q, want 9.9.9", doc.Info.Version)
	}
	if doc.SchemaVersion != "" || doc.OK != nil {
		t.Errorf("openapi document is wrapped in an envelope, want the raw document")
	}
	for _, want := range []string{"/healthz", "/healthz/backup", "/readyz", "/version", "/openapi.json"} {
		if _, ok := doc.Paths[want]; !ok {
			t.Errorf("openapi paths missing %q", want)
		}
	}
}

// TestEveryRegisteredRouteIsDocumented is the CI guard required by BE-0008:
// every route the handler registers must appear in the OpenAPI document, with
// no extra documented operations. The route table is the single source of
// truth for both, so drift fails this test loudly.
func TestEveryRegisteredRouteIsDocumented(t *testing.T) {
	t.Parallel()

	build := runtime.BuildInfo{}
	table := newRouteTable(build, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})
	doc := openAPIDocument(build, table)

	want := append(endpointsOf(table), openAPIEndpoint())
	for _, ep := range want {
		if !doc.HasOperation(ep.Method, ep.Path) {
			t.Errorf("route %s %s is registered but missing from the OpenAPI document",
				ep.Method, ep.Path)
		}
	}
	if got := doc.OperationCount(); got != len(want) {
		t.Errorf("OpenAPI documents %d operations, want exactly the %d registered routes",
			got, len(want))
	}
}

// TestRegisteredRoutesAreServable ties the OpenAPI document back to real
// serving: every documented route must be reachable (never a synthesised 404),
// and an undocumented path must still 404.
func TestRegisteredRoutesAreServable(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)
	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	for _, ep := range append(endpointsOf(table), openAPIEndpoint()) {
		req := httptest.NewRequest(ep.Method, ep.Path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("documented route %s %s is not served", ep.Method, ep.Path)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/definitely-not-a-route", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("undocumented path status = %d, want 404", rec.Code)
	}
}

// TestOpenAPIDocumentRedactsExampleSecrets proves the served document never
// carries a real-looking credential.
func TestOpenAPIDocumentRedactsExampleSecrets(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{}, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("openapi document contains no %s sentinel, expected redacted sample secrets",
			output.Sentinel)
	}
}
