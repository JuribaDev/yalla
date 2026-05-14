// Package httpapi exposes the Yalla Control Plane HTTP API surface.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
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
//
// The whole surface is wrapped in two layers of middleware. telemetry.Correlate
// is the outermost: it resolves the request_id / correlation_id for every
// request (honouring safe inbound X-Request-Id / X-Correlation-Id headers,
// generating fresh values otherwise) before any handler runs, so requestID can
// read the resolved value straight off the request context. telemetry.RequestLogging
// sits just inside it and emits one structured, redacted log record per request.
//
// logger receives the per-request structured log records. A nil logger is
// accepted — request logging is silently disabled — which suits tests and
// embedders that do not exercise the logging path.
//
// Routes come from the newRouteTable single source of truth: NewHandler
// registers every entry on the mux and generates the OpenAPI document
// (GET /openapi.json) from the same table, so a served route is always a
// documented route.
func NewHandler(build runtime.BuildInfo, readiness runtime.ReadinessReporter, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	build = build.Normalized()

	table := newRouteTable(build, readiness)

	// Generate the OpenAPI document once, from the route table, at startup.
	doc := openAPIDocument(build, table)
	docJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		// The document is built from static, deterministic data, so a marshal
		// failure is a programming error in the openapi package, not a runtime
		// condition. Fail fast at startup rather than serve a broken contract.
		panic("httpapi: marshal OpenAPI document: " + err.Error())
	}

	// Fold the discovery endpoint back into the served table. Its handler
	// emits the raw OpenAPI document — deliberately not a yalla.output.v1
	// envelope, because OpenAPI tooling expects the standard format — and it
	// requires no authentication so agents can discover the contract.
	table = append(table, apiRoute{
		endpoint: openAPIEndpoint(),
		handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(docJSON)
		},
	})

	for _, rt := range table {
		mux.HandleFunc(rt.endpoint.Method+" "+rt.endpoint.Path, rt.handler)
	}

	routed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&notFoundRecorder{ResponseWriter: w, request: r}, r)
	})
	return telemetry.Correlate(telemetry.RequestLogging(logger)(routed))
}

// requestID resolves the request identifier for a request. telemetry.Correlate
// wraps the whole handler, so by the time any route runs the request context
// always carries a resolved, SafeID-clean request_id — either echoed from a
// safe inbound X-Request-Id header or freshly generated.
func requestID(r *http.Request) string { return telemetry.RequestID(r.Context()) }

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
