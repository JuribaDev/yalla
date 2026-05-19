// Package httpapi exposes the Yalla Control Plane HTTP API surface.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
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
// meta supplies the dynamic fields of GET /version — principally the applied
// database migration version, which is unknown until the process connects to
// Postgres. A nil meta reports an unknown migration version, which suits
// tests and processes with no persistence layer wired yet.
//
// logger receives the per-request structured log records. A nil logger is
// accepted — request logging is silently disabled — which suits tests and
// embedders that do not exercise the logging path.
//
// authenticator and engine back the per-route authorization middleware: every
// route whose OpenAPI metadata declares RequiresAuth is wrapped in RequireAuth
// for its declared action before it is registered, so an authenticated route
// is structurally impossible to serve without authentication. Registering an
// authenticated route with a nil authenticator or engine is a wiring error and
// panics at startup rather than serving an unprotected endpoint.
//
// orgs backs the store-reading endpoints (GET /v1/organizations), creator backs
// POST /v1/organizations, updater backs PATCH /v1/organizations/{org_id},
// deleter backs DELETE /v1/organizations/{org_id}, members backs GET
// /v1/organizations/{org_id}/members, memberCreator backs POST
// /v1/organizations/{org_id}/members, memberUpdater backs PATCH
// /v1/organizations/{org_id}/members/{member_id}, memberRemover backs
// DELETE /v1/organizations/{org_id}/members/{member_id}, limits backs GET
// /v1/organizations/{org_id}/limits, limitsUpdater backs PATCH
// /v1/organizations/{org_id}/limits, usage backs GET
// /v1/organizations/{org_id}/usage, auditEvents backs GET
// /v1/organizations/{org_id}/audit-events, orgVariables backs GET
// /v1/organizations/{org_id}/variables, orgVariableReplacer backs PUT
// /v1/organizations/{org_id}/variables, orgVariablePatcher backs PATCH
// /v1/organizations/{org_id}/variables/{key}, orgVariableDeleter backs
// DELETE /v1/organizations/{org_id}/variables/{key}, apiKeys backs GET
// /v1/organizations/{org_id}/api-keys, apiKeyCreator backs POST
// /v1/organizations/{org_id}/api-keys, apiKeyUpdater backs PATCH
// /v1/organizations/{org_id}/api-keys/{key_id}, apiKeyRevoker backs
// DELETE /v1/organizations/{org_id}/api-keys/{key_id},
// projectGrants backs GET /v1/projects/{project_id}/grants,
// projectGrantReplacer backs PUT /v1/projects/{project_id}/grants,
// projectVariables backs GET /v1/projects/{project_id}/variables,
// projectVariableReplacer backs PUT /v1/projects/{project_id}/variables,
// projectEnvironments backs GET /v1/projects/{project_id}/environments,
// environmentCreator backs POST /v1/projects/{project_id}/environments,
// environmentReader backs GET /v1/environments/{environment_id},
// environmentUpdater backs PATCH /v1/environments/{environment_id},
// environmentDeleter backs DELETE /v1/environments/{environment_id},
// environmentGrants backs GET /v1/environments/{environment_id}/grants,
// and environmentGrantReplacer backs PUT
// /v1/environments/{environment_id}/grants.
// All are narrow ports, not the concrete store, so the HTTP surface stays
// unit-testable with fakes; cmd/yalla-api wires the real
// store.OrganizationReader, store.OrganizationService,
// store.MembershipReader, store.MembershipService, store.LimitsReader,
// store.LimitsService, store.UsageReader, store.AuditEventReader,
// store.OrganizationVariableReader, store.OrganizationVariableService,
// store.APIKeyReader, store.APIKeyService, store.ProjectReader,
// store.ProjectService, store.ProjectGrantReader, and
// store.ProjectGrantService, store.EnvironmentGrantReader, and
// store.EnvironmentGrantService at startup.
// A nil orgs, creator, updater,
// deleter, members, memberCreator, memberUpdater, memberRemover, limits,
// limitsUpdater, usage, auditEvents, orgVariables, orgVariableReplacer,
// orgVariablePatcher, orgVariableDeleter, apiKeys, apiKeyCreator,
// apiKeyUpdater, apiKeyRevoker, projectGrants, projectGrantReplacer,
// projectVariables, projectVariableReplacer, projectEnvironments,
// environmentCreator, environmentReader, environmentUpdater,
// environmentDeleter, environmentCloner, environmentGrants, or
// environmentGrantReplacer still registers its route — the handler reports
// a typed internal error rather
// than a misleading empty list or a silently dropped write — which suits
// tests and tooling that only exercise the public surface.
//
// rateLimiter is the optional throughput gate wired between RequireAuth
// and the route handler. A nil value installs a no-op wrapper, which suits
// tests and embedders that exercise the routing surface without enforcing
// any cap. The middleware runs INSIDE RequireAuth so the resolved
// principal is on the request context when the limiter decides — that is
// what lets the gate bill the org and key buckets for authenticated
// requests while falling back to the IP bucket for public endpoints, and
// what lets it recognise the internal-worker exemption.
//
// Routes come from the newRouteTable single source of truth: NewHandler
// registers every entry on the mux and generates the OpenAPI document
// (GET /openapi.json) from the same table, so a served route is always a
// documented route.
func NewHandler(build runtime.BuildInfo, readiness runtime.ReadinessReporter, meta runtime.MetaReporter, backupReporter backup.Reporter, authenticator Authenticator, engine *policy.Engine, orgs OrganizationReader, creator OrganizationCreator, updater OrganizationUpdater, deleter OrganizationDeleter, members MembershipReader, memberCreator MembershipCreator, memberUpdater MembershipUpdater, memberRemover MembershipRemover, limits LimitsReader, limitsUpdater LimitsUpdater, usage UsageReader, auditEvents AuditEventReader, orgVariables OrganizationVariableReader, orgVariableReplacer OrganizationVariableReplacer, orgVariablePatcher OrganizationVariablePatcher, orgVariableDeleter OrganizationVariableDeleter, apiKeys APIKeyReader, apiKeyCreator APIKeyCreator, apiKeyUpdater APIKeyUpdater, apiKeyRevoker APIKeyRevoker, apiKeyRotator APIKeyRotator, projects ProjectReader, projectCreator ProjectCreator, projectUpdater ProjectUpdater, projectDeleter ProjectDeleter, projectRestorer ProjectRestorer, projectGrants ProjectGrantReader, projectGrantReplacer ProjectGrantReplacer, projectVariables ProjectVariableReader, projectVariableReplacer ProjectVariableReplacer, projectEnvironments ProjectEnvironmentReader, environmentCreator EnvironmentCreator, environmentReader EnvironmentReader, environmentUpdater EnvironmentUpdater, environmentDeleter EnvironmentDeleter, environmentCloner EnvironmentCloner, environmentGrants EnvironmentGrantReader, environmentGrantReplacer EnvironmentGrantReplacer, environmentVariables EnvironmentVariableReader, environmentVariableReplacer EnvironmentVariableReplacer, environmentServices EnvironmentServiceReader, environmentServiceCreator EnvironmentServiceCreator, services ServiceReader, serviceUpdater ServiceUpdater, serviceDeleter ServiceDeleter, serviceRestorer ServiceRestorer, serviceRestarter ServiceRestarter, serviceStarter ServiceStarter, serviceStopper ServiceStopper, serviceLogReader ServiceLogReader, serviceMetricsReader ServiceMetricsReader, serviceDomainReader ServiceDomainReader, serviceDomainCreator ServiceDomainCreator, serviceDomainUpdater ServiceDomainUpdater, serviceDomainDeleter ServiceDomainDeleter, serviceBackupReader ServiceBackupReader, serviceBackupCreator ServiceBackupCreator, serviceBackupUpdater ServiceBackupUpdater, serviceBackupRunner ServiceBackupRunner, serviceBackupDeleter ServiceBackupDeleter, serviceVariables ServiceVariableReader, serviceVariableReplacer ServiceVariableReplacer, deploymentCreator DeploymentCreator, deploymentLister DeploymentLister, deploymentGetter DeploymentGetter, deploymentCanceler DeploymentCanceler, deploymentRollbacker DeploymentRollbacker, breakGlass BreakGlassController, logger *slog.Logger, rateLimiter RateLimiter, routeOptions ...any) http.Handler {
	mux := http.NewServeMux()
	build = build.Normalized()
	var previewCreator PreviewCreator
	var jobReader JobReader
	var driftFindings DriftFindingReader
	var dokployRefs DokployRefReader
	var adminDokployReconciler AdminDokployReconciler
	var adminDokployImporter AdminDokployImporter
	httpMetrics := telemetry.DefaultHTTPMetrics
	for _, opt := range routeOptions {
		switch v := opt.(type) {
		case PreviewCreator:
			previewCreator = v
		case JobReader:
			jobReader = v
		case DriftFindingReader:
			driftFindings = v
		case DokployRefReader:
			dokployRefs = v
		case AdminDokployReconciler:
			adminDokployReconciler = v
		case AdminDokployImporter:
			adminDokployImporter = v
		case *telemetry.HTTPMetrics:
			if v != nil {
				httpMetrics = v
			}
		}
	}

	if backupReporter == nil {
		// A nil reporter is treated as Unconfigured so the /healthz/backup
		// route is always served — operators can wire the backup integration
		// later without rebuilding the binary, and tests that do not exercise
		// the backup probe can pass nil unchanged.
		backupReporter = backup.Unconfigured()
	}

	table := newRouteTable(build, readiness, meta, backupReporter, orgs, creator, updater, deleter, members, memberCreator, memberUpdater, memberRemover, limits, limitsUpdater, usage, auditEvents, orgVariables, orgVariableReplacer, orgVariablePatcher, orgVariableDeleter, apiKeys, apiKeyCreator, apiKeyUpdater, apiKeyRevoker, apiKeyRotator, projects, projectCreator, projectUpdater, projectDeleter, projectRestorer, projectGrants, projectGrantReplacer, projectVariables, projectVariableReplacer, projectEnvironments, environmentCreator, environmentReader, environmentUpdater, environmentDeleter, environmentCloner, environmentGrants, environmentGrantReplacer, environmentVariables, environmentVariableReplacer, environmentServices, environmentServiceCreator, services, serviceUpdater, serviceDeleter, serviceRestorer, serviceRestarter, serviceStarter, serviceStopper, serviceLogReader, serviceMetricsReader, serviceDomainReader, serviceDomainCreator, serviceDomainUpdater, serviceDomainDeleter, serviceBackupReader, serviceBackupCreator, serviceBackupUpdater, serviceBackupRunner, serviceBackupDeleter, serviceVariables, serviceVariableReplacer, deploymentCreator, deploymentLister, deploymentGetter, deploymentCanceler, deploymentRollbacker, breakGlass, previewCreator, jobReader, driftFindings, dokployRefs, adminDokployReconciler, adminDokployImporter, httpMetrics)

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

	rateLimit := RateLimit(rateLimiter, logger)
	for _, rt := range table {
		h := http.Handler(rt.handler)
		// Rate limiting wraps the handler INSIDE the auth gate so the
		// resolved principal (organization id, API key id, auth method)
		// is on the request context when the limiter decides. A public
		// endpoint runs the same wrapper, but with no principal on
		// context the limiter falls back to the IP bucket alone.
		h = rateLimit(h)
		if rt.endpoint.RequiresAuth {
			if authenticator == nil || engine == nil {
				// A misconfigured handler must never serve an authenticated
				// route unprotected. Fail fast at startup, the same way a
				// broken OpenAPI document does above.
				panic("httpapi: authenticated route " + rt.endpoint.Method + " " + rt.endpoint.Path +
					" registered without an authenticator or policy engine")
			}
			h = RequireAuth(authenticator, engine, policy.Action(rt.endpoint.RequiredAction), rt.resolver)(h)
		}
		mux.HandleFunc(rt.endpoint.Method+" "+rt.endpoint.Path, h.ServeHTTP)
	}

	routed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&notFoundRecorder{ResponseWriter: w, request: r}, r)
	})
	return telemetry.Correlate(telemetry.RequestLogging(logger)(telemetry.RequestMetrics(httpMetrics)(routed)))
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
