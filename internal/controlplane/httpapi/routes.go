package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/openapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// OpenAPI operation tags. They group endpoints in the published document.
const (
	tagOperations = "operations"
	tagMeta       = "meta"
	tagIdentity   = "identity"
)

// apiRoute couples a served HTTP route with the OpenAPI metadata that
// documents it. The route table returned by newRouteTable is the single
// source of truth: NewHandler registers every entry on the mux *and* feeds the
// same entries into the generated OpenAPI document, so a route can never be
// served without being documented. TestEveryRegisteredRouteIsDocumented
// enforces that invariant in CI.
//
// When endpoint.RequiresAuth is true, NewHandler wraps handler in RequireAuth
// for endpoint.RequiredAction. resolver derives the policy.Resource the request
// acts on from its path and query parameters; a nil resolver authorizes against
// the principal's own organization scope, which suits self and organization-root
// actions that have no deeper target.
type apiRoute struct {
	endpoint openapi.Endpoint
	handler  http.HandlerFunc
	resolver ResourceResolver
}

// healthzPayload is the data block of the GET /healthz success envelope.
type healthzPayload struct {
	Status string `json:"status"`
}

// readyzPayload is the data block of the GET /readyz success envelope. Checks
// names every startup dependency gate and whether it is passing, so operators
// and agents can see exactly which dependency is degraded. Gate names are
// fixed, non-secret identifiers (for example "database", "migrations",
// "queue", "dokploy").
type readyzPayload struct {
	Status string          `json:"status"`
	Checks map[string]bool `json:"checks"`
}

// versionPayload is the data block of the GET /version success envelope. It
// carries both the build identity (Version/Commit/Date) and the contract
// identity: APISchemaVersion is the stable API contract version and
// MigrationVersion is the applied database schema version.
type versionPayload struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Date             string `json:"date"`
	APISchemaVersion string `json:"api_schema_version"`
	MigrationVersion string `json:"migration_version"`
}

// newRouteTable returns every API route paired with its OpenAPI metadata. The
// /openapi.json route is intentionally absent — its handler is built from the
// document these routes describe, so openAPIDocument folds it back in (see
// openAPIEndpoint) and NewHandler registers it last.
//
// readiness drives /readyz; meta drives the dynamic fields of /version. Both
// may be nil: a nil readiness is treated as always-ready and a nil meta
// reports an unknown migration version, which suits tests and processes with
// no startup dependencies wired yet.
func newRouteTable(build runtime.BuildInfo, readiness runtime.ReadinessReporter, meta runtime.MetaReporter) []apiRoute {
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
				apienvelope.WriteData(w, http.StatusOK, requestID(r), healthzPayload{Status: "ok"})
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/readyz",
				OperationID:        "getReadyz",
				Summary:            "Readiness probe",
				Description:        "Reports whether every startup dependency check — database connectivity, migration state, queue readiness, and the Dokploy dependency when configured — has passed. Returns 200 with the per-check status once ready, or 503 with a yalla.error.v1 envelope naming the pending checks until then.",
				Tags:               []string{tagOperations},
				SuccessDescription: "Every startup dependency check has passed; the data block reports each check.",
			},
			handler: readyzHandler(readiness),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/version",
				OperationID:        "getVersion",
				Summary:            "Build and contract version",
				Description:        "Returns the running process identity: build version, source commit, build date, the stable API schema version, and the applied database migration version.",
				Tags:               []string{tagMeta},
				SuccessDescription: "The build and contract identity of the running process.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				migrationVersion := runtime.MigrationVersionUnknown
				if meta != nil {
					migrationVersion = meta.MigrationVersion()
				}
				apienvelope.WriteData(w, http.StatusOK, requestID(r), versionPayload{
					Version:          build.Version,
					Commit:           build.Commit,
					Date:             build.Date,
					APISchemaVersion: runtime.APISchemaVersion,
					MigrationVersion: migrationVersion,
				})
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/me",
				OperationID:        "getMe",
				Summary:            "Current principal identity",
				Description:        "Returns the identity of the authenticated principal — its id, kind, home organization, organization role, and scoped grants — exactly as the control plane resolved it from the request credential. The response is derived from the authenticated principal alone and never reveals another tenant's data. It carries no credential material.",
				Tags:               []string{tagIdentity},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAuthMe),
				SuccessDescription: "The authenticated principal's identity.",
			},
			// A nil resolver authorizes against the principal's own organization
			// scope. auth.me is a CapSelf action — allowed for any authenticated,
			// enabled principal — so the endpoint has no deeper resource target.
			handler: meHandler(),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/me/organizations",
				OperationID:        "getMeOrganizations",
				Summary:            "Organizations visible to the current principal",
				Description:        "Lists the organizations the authenticated principal can see through the control plane, with the principal's organization-wide role and scoped grants in each. The response is derived from the authenticated principal alone — its home organization and scoped grants — and never reveals another tenant's data. It carries no credential material. A principal is bound to a single home organization, so the list has one entry today; the array shape is forward-compatible with credentials that may span organizations later.",
				Tags:               []string{tagIdentity},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAuthOrgs),
				SuccessDescription: "The organizations visible to the authenticated principal.",
			},
			// A nil resolver authorizes against the principal's own organization
			// scope. auth.orgs is a CapSelf action — allowed for any
			// authenticated, enabled principal — and the endpoint only ever
			// reports the principal's own organization, so it has no deeper
			// resource target.
			handler: meOrganizationsHandler(),
		},
	}
}

// readyzHandler builds the GET /readyz handler. When every startup gate is
// passing it renders a 200 yalla.output.v1 envelope listing each check; while
// any gate is still failing it renders a 503 yalla.error.v1 envelope whose
// hint names the pending checks. The 503 is an explicit override of the error
// code's default status because "not ready yet" is a liveness signal, not an
// upstream fault. A nil reporter is treated as always-ready, which suits
// tests and processes with no startup dependencies.
func readyzHandler(readiness runtime.ReadinessReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]bool{}
		ready := true
		if readiness != nil {
			checks = readiness.Snapshot()
			ready = readiness.Ready()
		}
		if ready {
			apienvelope.WriteData(w, http.StatusOK, requestID(r), readyzPayload{
				Status: "ready",
				Checks: checks,
			})
			return
		}
		// Not ready yet: report 503 with a stable error envelope so probes and
		// agents see a deterministic code while startup completes. The hint
		// names the pending checks — fixed, non-secret gate identifiers — so
		// operators can see which dependency is blocking readiness.
		hint := "startup dependency checks have not passed yet"
		if pending := pendingChecks(checks); len(pending) > 0 {
			hint = "pending dependency checks: " + strings.Join(pending, ", ")
		}
		apienvelope.WriteErrorStatus(w, http.StatusServiceUnavailable, requestID(r),
			yerr.New(yerr.CodeServer, "service is not ready").WithHint(hint))
	}
}

// pendingChecks returns the sorted names of every check that is not passing.
// Check names are fixed, non-secret identifiers, so they are safe to surface
// in an error hint.
func pendingChecks(checks map[string]bool) []string {
	pending := make([]string, 0, len(checks))
	for name, passing := range checks {
		if !passing {
			pending = append(pending, name)
		}
	}
	sort.Strings(pending)
	return pending
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
