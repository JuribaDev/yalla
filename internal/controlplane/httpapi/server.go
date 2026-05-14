package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// NewHandler builds the bootstrap HTTP surface for the Yalla control-plane
// API. It intentionally starts small; feature packages add routes through this
// boundary as their PRD stories are implemented.
func NewHandler(build runtime.BuildInfo) http.Handler {
	mux := http.NewServeMux()
	build = build.Normalized()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, http.StatusOK, map[string]string{
			"version": build.Version,
			"commit":  build.Commit,
			"date":    build.Date,
		})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&notFoundRecorder{ResponseWriter: w, request: r}, r)
	})
}

type successEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          any    `json:"data"`
}

type errorEnvelope struct {
	SchemaVersion string       `json:"schema_version"`
	OK            bool         `json:"ok"`
	Error         errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func writeData(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, successEnvelope{
		SchemaVersion: output.SuccessSchema,
		OK:            true,
		Data:          data,
	})
}

func writeError(w http.ResponseWriter, status int, err *yerr.Error) {
	payload := errorPayload{
		Code:    string(err.Code),
		Message: err.Message,
		Hint:    err.Hint,
	}
	writeJSON(w, status, errorEnvelope{
		SchemaVersion: yerr.SchemaVersion,
		OK:            false,
		Error:         payload,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type notFoundRecorder struct {
	http.ResponseWriter
	request *http.Request
	wrote   bool
	drop    bool
}

func (r *notFoundRecorder) WriteHeader(status int) {
	if status == http.StatusNotFound && !r.wrote {
		r.wrote = true
		r.drop = true
		writeError(r.ResponseWriter, http.StatusNotFound, yerr.New(yerr.CodeNotFound, "route not found"))
		return
	}
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *notFoundRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	if r.drop {
		return len(b), nil
	}
	return r.ResponseWriter.Write(b)
}
