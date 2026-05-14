package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

func TestHandlerServesBootstrapEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-14T00:00:00Z",
	}, nil)

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

	handler := NewHandler(runtime.BuildInfo{}, nil)
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
	handler := NewHandler(runtime.BuildInfo{}, readiness)

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

	handler := NewHandler(runtime.BuildInfo{}, nil)

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
		{"error envelope", NewHandler(runtime.BuildInfo{}, unready), "/readyz"},
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

	handler := NewHandler(runtime.BuildInfo{}, nil)

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

	handler := NewHandler(runtime.BuildInfo{}, nil)

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
