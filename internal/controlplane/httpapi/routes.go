package httpapi

import (
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/openapi"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// OpenAPI operation tags. They group endpoints in the published document.
const (
	tagOperations = "operations"
	tagMeta       = "meta"
)

// apiRoute couples a served HTTP route with the OpenAPI metadata that
// documents it. The route table returned by newRouteTable is the single
// source of truth: NewHandler registers every entry on the mux *and* feeds the
// same entries into the generated OpenAPI document, so a route can never be
// served without being documented. TestEveryRegisteredRouteIsDocumented
// enforces that invariant in CI.
type apiRoute struct {
	endpoint openapi.Endpoint
	handler  http.HandlerFunc
}

// newRouteTable returns every API route paired with its OpenAPI metadata. The
// /openapi.json route is intentionally absent — its handler is built from the
// document these routes describe, so openAPIDocument folds it back in (see
// openAPIEndpoint) and NewHandler registers it last.
func newRouteTable(build runtime.BuildInfo, readiness runtime.ReadinessReporter) []apiRoute {
	build = build.Normalized()

	return []apiRoute{
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/healthz",
				OperationID:        "getHealthz",
				Summary:            "Liveness probe",
				Description:        "Reports process liveness without touching any downstream dependency. Load balancers use it to decide whether the process is alive.",
				Tags:               []string{tagOperations},
				SuccessDescription: "The process is alive and serving HTTP.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Liveness: the process is running and can serve HTTP. It does
				// not depend on downstream dependencies — that is /readyz.
				apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{"status": "ok"})
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/readyz",
				OperationID:        "getReadyz",
				Summary:            "Readiness probe",
				Description:        "Reports whether every startup dependency check has passed. Returns 503 with a yalla.error.v1 envelope until the process is ready, 200 afterwards.",
				Tags:               []string{tagOperations},
				SuccessDescription: "Every startup dependency check has passed.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				if readiness == nil || readiness.Ready() {
					apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{"status": "ready"})
					return
				}
				// Not ready yet: report 503 with a stable error envelope so
				// probes and agents see a deterministic code while startup
				// completes. The 503 is an explicit override of the code's
				// default mapping because "not ready yet" is a liveness
				// signal, not an upstream fault.
				apienvelope.WriteErrorStatus(w, http.StatusServiceUnavailable, requestID(r),
					yerr.New(yerr.CodeServer, "service is not ready").
						WithHint("startup dependency checks have not passed yet"))
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/version",
				OperationID:        "getVersion",
				Summary:            "Build version",
				Description:        "Returns the build-time identity of the running process: semantic version, source commit, and build date.",
				Tags:               []string{tagMeta},
				SuccessDescription: "The build identity of the running process.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{
					"version": build.Version,
					"commit":  build.Commit,
					"date":    build.Date,
				})
			},
		},
	}
}

// openAPIEndpoint is the OpenAPI metadata for GET /openapi.json. It is kept
// out of newRouteTable because its handler is constructed from the very
// document these endpoints describe; openAPIDocument folds it back in so the
// published document still lists the discovery endpoint itself.
func openAPIEndpoint() openapi.Endpoint {
	return openapi.Endpoint{
		Method:             http.MethodGet,
		Path:               "/openapi.json",
		OperationID:        "getOpenAPIDocument",
		Summary:            "OpenAPI document",
		Description:        "Returns the OpenAPI 3.1 document describing this API. Served without authentication so tools and agents can discover the contract. The body is the raw OpenAPI document, not a yalla.output.v1 envelope, because OpenAPI tooling expects the standard format.",
		Tags:               []string{tagMeta},
		SuccessDescription: "The OpenAPI 3.1 document for this API.",
		SuccessSchema:      openapi.SchemaOpenAPIDocument,
	}
}

// endpointsOf projects the OpenAPI metadata out of a route table.
func endpointsOf(table []apiRoute) []openapi.Endpoint {
	eps := make([]openapi.Endpoint, 0, len(table)+1)
	for _, rt := range table {
		eps = append(eps, rt.endpoint)
	}
	return eps
}

// openAPIDocument assembles the published OpenAPI document from the route
// table. It appends openAPIEndpoint so the document lists the discovery
// endpoint itself, keeping "served routes" and "documented routes" identical.
func openAPIDocument(build runtime.BuildInfo, table []apiRoute) openapi.Document {
	build = build.Normalized()
	eps := append(endpointsOf(table), openAPIEndpoint())
	return openapi.Build(openapi.Info{
		Title:       "Yalla Control Plane API",
		Version:     build.Version,
		Description: "Intent-based API for managing Dokploy-backed infrastructure. Customers, agents, and CI call this control plane; they never call Dokploy directly.",
	}, eps)
}
