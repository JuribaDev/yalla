package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestHandlerServesBootstrapEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-14T00:00:00Z",
	}, nil, nil)

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
			name:       "ready",
			path:       "/readyz",
			wantStatus: http.StatusOK,
			wantData: map[string]string{
				"status": "ready",
			},
		},
		{
			name:       "version",
			path:       "/version",
			wantStatus: http.StatusOK,
			wantData: map[string]string{
				"version": "1.2.3",
				"commit":  "abc123",
				"date":    "2026-05-14T00:00:00Z",
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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)
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
	handler := NewHandler(runtime.BuildInfo{}, readiness, nil)

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
		SchemaVersion string            `json:"schema_version"`
		OK            bool              `json:"ok"`
		Data          map[string]string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &okEnv); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if okEnv.SchemaVersion != "yalla.output.v1" || !okEnv.OK {
		t.Errorf("ready envelope = %+v, want yalla.output.v1 ok=true", okEnv)
	}
	if okEnv.Data["status"] != "ready" {
		t.Errorf("data.status = %q, want ready", okEnv.Data["status"])
	}
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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)

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
		{"error envelope", NewHandler(runtime.BuildInfo{}, unready, nil), "/readyz"},
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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)

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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)

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
	handler := NewHandler(runtime.BuildInfo{}, nil, logger)

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

	handler := NewHandler(runtime.BuildInfo{Version: "9.9.9"}, nil, nil)

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
	for _, want := range []string{"/healthz", "/readyz", "/version", "/openapi.json"} {
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
	table := newRouteTable(build, nil)
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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)
	table := newRouteTable(runtime.BuildInfo{}, nil)

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

	handler := NewHandler(runtime.BuildInfo{}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("openapi document contains no %s sentinel, expected redacted sample secrets",
			output.Sentinel)
	}
}
