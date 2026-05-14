// Package httpapi exposes the Yalla Control Plane HTTP API surface.
package httpapi

import (
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// NewHandler builds the bootstrap HTTP surface for the Yalla control-plane
// API. It intentionally starts small; feature packages add routes through this
// boundary as their PRD stories are implemented.
//
// readiness gates the /readyz endpoint: until every startup dependency
// (migrations, database connectivity, and similar checks) has passed,
// /readyz reports 503 so the load balancer keeps the process out of
// rotation. A nil readiness is treated as always-ready, which suits tests
// and processes with no startup dependencies.
//
// Every response — success or error — is rendered through the apienvelope
// package so the wire contract (yalla.output.v1 / yalla.error.v1) stays
// deterministic. Handlers never marshal JSON directly.
func NewHandler(build runtime.BuildInfo, readiness runtime.ReadinessReporter) http.Handler {
	mux := http.NewServeMux()
	build = build.Normalized()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Liveness: the process is running and can serve HTTP. It does not
		// depend on downstream dependencies — that is what /readyz is for.
		apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if readiness == nil || readiness.Ready() {
			apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{"status": "ready"})
			return
		}
		// Not ready yet: report 503 with a stable error envelope so probes
		// and agents see a deterministic code while startup completes. The
		// 503 status is an explicit override of the code's default mapping
		// because "not ready yet" is a liveness signal, not an upstream fault.
		apienvelope.WriteErrorStatus(w, http.StatusServiceUnavailable, requestID(r),
			yerr.New(yerr.CodeServer, "service is not ready").
				WithHint("startup dependency checks have not passed yet"))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{
			"version": build.Version,
			"commit":  build.Commit,
			"date":    build.Date,
		})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&notFoundRecorder{ResponseWriter: w, request: r}, r)
	})
}

// requestID resolves the correlation ID for a request. Until the request-ID
// middleware story (BE-0006) lands there is no generated ID, so this returns
// the empty string; the envelope still carries the request_id field so the
// wire shape is stable today and gains a value transparently later.
func requestID(_ *http.Request) string { return "" }

// notFoundRecorder intercepts the ServeMux's plain-text 404 so unmatched
// routes still return the stable yalla.error.v1 envelope.
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
		apienvelope.WriteError(r.ResponseWriter, requestID(r.request),
			yerr.New(yerr.CodeNotFound, "route not found"))
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
