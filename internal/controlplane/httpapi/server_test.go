package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

func TestHandlerServesBootstrapEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-14T00:00:00Z",
	})

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

	handler := NewHandler(runtime.BuildInfo{})
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
