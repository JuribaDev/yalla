package httpapi

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	"github.com/JuribaDev/yalla/internal/controlplane/openapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// OpenAPI operation tags. They group endpoints in the published document.
const (
	tagOperations    = "operations"
	tagMeta          = "meta"
	tagIdentity      = "identity"
	tagOrganizations = "organizations"
	tagMembers       = "members"
	tagLimits        = "limits"
	tagUsage         = "usage"
	tagAuditEvents   = "audit-events"
	tagAPIKeys       = "api-keys"
	tagVariables     = "variables"
	tagProjects      = "projects"
	tagEnvironments  = "environments"
	tagServices      = "services"
	tagDeployments   = "deployments"
	tagJobs          = "jobs"
	tagAdmin         = "admin"
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

type metricsSnapshot struct {
	telemetry.HTTPMetricsSnapshot
	DokployDependencySnapshot telemetry.DokployDependencyMetricsSnapshot        `json:"dokploy_dependencies"`
	QuotaUsageSnapshot        telemetry.QuotaUsageMetricsSnapshot               `json:"quota_usage"`
	AuditEventSnapshot        telemetry.AuditEventMetricsSnapshot               `json:"audit_events"`
	PolicyDecisionSnapshot    telemetry.PolicyDecisionMetricsSnapshot           `json:"policy_decisions"`
	TraceSpanSnapshot         telemetry.TraceSpanMetricsSnapshot                `json:"trace_spans"`
	SlowQuerySnapshot         telemetry.SlowQueryMetricsSnapshot                `json:"slow_queries"`
	ReadinessSnapshot         telemetry.ReadinessDegradationSnapshot            `json:"readiness_degradation"`
	SLOBurnRateSnapshot       telemetry.SLOBurnRateMetricsSnapshot              `json:"slo_burn_rates"`
	DeadLetterAlertSnapshot   telemetry.DeadLetterAlertMetricsSnapshot          `json:"dead_letter_alerts"`
	ReconciliationDriftAlerts telemetry.ReconciliationDriftAlertMetricsSnapshot `json:"reconciliation_drift_alerts"`
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

// backupHealthPayload is the data block of the GET /healthz/backup success
// envelope. The endpoint is unauthenticated (operators and probes consume
// it) and never reveals tenant data — only the operational backup
// timestamp the operator's external pipeline wrote to the configured
// status file.
//
// Field semantics:
//   - Configured is true when an operator has wired YALLA_BACKUP_STATUS_FILE.
//     When false, every remaining field is omitted and the operator sees an
//     explicit "no backup integration is wired on this process" answer.
//   - Fresh reports whether the most recent backup landed within the
//     YALLA_BACKUP_MAX_AGE window. A zero MaxAge disables the predicate and
//     Fresh is always true so operators can deploy the probe before
//     committing to a threshold without flapping.
//   - LastSuccessAt is the RFC3339 timestamp the operator's pipeline wrote
//     to the status file. It is omitted when no successful backup has been
//     recorded yet (a freshly provisioned environment).
//   - AgeSeconds and MaxAgeSeconds project the durations as integers so
//     scripts and Prometheus exporters do not have to parse Go's duration
//     string format. Both are omitted when LastSuccessAt is omitted.
type backupHealthPayload struct {
	Configured    bool   `json:"configured"`
	Fresh         bool   `json:"fresh"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	AgeSeconds    *int64 `json:"age_seconds,omitempty"`
	MaxAgeSeconds *int64 `json:"max_age_seconds,omitempty"`
	Detail        string `json:"detail,omitempty"`
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
//
// orgs backs the organization read endpoints, creator backs POST
// /v1/organizations, updater backs PATCH /v1/organizations/{org_id}, deleter
// backs DELETE /v1/organizations/{org_id}, members backs GET
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
// /v1/organizations/{org_id}/api-keys and GET
// /v1/organizations/{org_id}/api-keys/{key_id}, apiKeyCreator backs POST
// /v1/organizations/{org_id}/api-keys, apiKeyUpdater backs PATCH
// /v1/organizations/{org_id}/api-keys/{key_id}, apiKeyRevoker backs
// DELETE /v1/organizations/{org_id}/api-keys/{key_id}, and apiKeyRotator
// backs POST /v1/organizations/{org_id}/api-keys/{key_id}/rotate.
// projectCreator backs POST /v1/projects, projectUpdater backs PATCH
// /v1/projects/{project_id}, projectDeleter backs DELETE
// /v1/projects/{project_id}, projectRestorer backs POST
// /v1/projects/{project_id}/restore, projectGrants backs GET
// /v1/projects/{project_id}/grants, projectGrantReplacer backs PUT
// /v1/projects/{project_id}/grants, environmentGrantReplacer backs PUT
// /v1/environments/{environment_id}/grants, projectVariables backs GET
// /v1/projects/{project_id}/variables, projectVariableReplacer backs
// PUT /v1/projects/{project_id}/variables, projectEnvironments backs
// GET /v1/projects/{project_id}/environments, environmentCreator
// backs POST /v1/projects/{project_id}/environments,
// environmentReader backs GET /v1/environments/{environment_id},
// environmentUpdater backs PATCH /v1/environments/{environment_id},
// environmentDeleter backs DELETE /v1/environments/{environment_id},
// environmentCloner backs
// POST /v1/environments/{environment_id}/clone,
// environmentVariables backs GET
// /v1/environments/{environment_id}/variables,
// environmentVariableReplacer backs PUT
// /v1/environments/{environment_id}/variables, and
// environmentServices backs GET
// /v1/environments/{environment_id}/services.
// serviceRestorer backs POST /v1/services/{service_id}/restore.
// serviceVariables backs GET /v1/services/{service_id}/variables.
// deploymentCreator backs POST /v1/services/{service_id}/deployments.
// deploymentLister backs GET /v1/services/{service_id}/deployments.
// deploymentGetter backs GET /v1/deployments/{deployment_id}.
// deploymentCanceler backs POST /v1/deployments/{deployment_id}/cancel.
// deploymentRollbacker backs POST /v1/services/{service_id}/rollback.
// serviceRestarter backs POST /v1/services/{service_id}/restart.
// serviceStarter backs POST /v1/services/{service_id}/start.
// serviceStopper backs POST /v1/services/{service_id}/stop.
// serviceLogReader backs GET /v1/services/{service_id}/logs.
// serviceMetricsReader backs GET /v1/services/{service_id}/metrics.
// serviceDomainReader backs GET /v1/services/{service_id}/domains.
// serviceBackupReader backs GET /v1/services/{service_id}/backups.
// serviceBackupCreator backs POST /v1/services/{service_id}/backups.
// serviceBackupRunner backs POST
// /v1/services/{service_id}/backups/{backup_id}/run.
// serviceBackupUpdater backs PATCH
// /v1/services/{service_id}/backups/{backup_id}.
// serviceBackupDeleter backs DELETE
// /v1/services/{service_id}/backups/{backup_id}.
// serviceDomainCreator backs POST /v1/services/{service_id}/domains.
// serviceDomainUpdater backs PATCH
// /v1/services/{service_id}/domains/{domain_id}.
// serviceDomainDeleter backs DELETE
// /v1/services/{service_id}/domains/{domain_id}.
// Any may be nil for tests and tooling that only inspect the route
// table's metadata; a request that actually reaches a handler with a
// nil dependency is reported as a typed internal error rather than a
// misleading empty list or a silently dropped write.
func newRouteTable(build runtime.BuildInfo, readiness runtime.ReadinessReporter, meta runtime.MetaReporter, backupReporter backup.Reporter, orgs OrganizationReader, creator OrganizationCreator, updater OrganizationUpdater, deleter OrganizationDeleter, members MembershipReader, memberCreator MembershipCreator, memberUpdater MembershipUpdater, memberRemover MembershipRemover, limits LimitsReader, limitsUpdater LimitsUpdater, usage UsageReader, auditEvents AuditEventReader, orgVariables OrganizationVariableReader, orgVariableReplacer OrganizationVariableReplacer, orgVariablePatcher OrganizationVariablePatcher, orgVariableDeleter OrganizationVariableDeleter, apiKeys APIKeyReader, apiKeyCreator APIKeyCreator, apiKeyUpdater APIKeyUpdater, apiKeyRevoker APIKeyRevoker, apiKeyRotator APIKeyRotator, projects ProjectReader, projectCreator ProjectCreator, projectUpdater ProjectUpdater, projectDeleter ProjectDeleter, projectRestorer ProjectRestorer, projectGrants ProjectGrantReader, projectGrantReplacer ProjectGrantReplacer, projectVariables ProjectVariableReader, projectVariableReplacer ProjectVariableReplacer, projectEnvironments ProjectEnvironmentReader, environmentCreator EnvironmentCreator, environmentReader EnvironmentReader, environmentUpdater EnvironmentUpdater, environmentDeleter EnvironmentDeleter, environmentCloner EnvironmentCloner, environmentGrants EnvironmentGrantReader, environmentGrantReplacer EnvironmentGrantReplacer, environmentVariables EnvironmentVariableReader, environmentVariableReplacer EnvironmentVariableReplacer, environmentServices EnvironmentServiceReader, environmentServiceCreator EnvironmentServiceCreator, services ServiceReader, serviceUpdater ServiceUpdater, serviceDeleter ServiceDeleter, serviceRestorer ServiceRestorer, serviceRestarter ServiceRestarter, serviceStarter ServiceStarter, serviceStopper ServiceStopper, serviceLogReader ServiceLogReader, serviceMetricsReader ServiceMetricsReader, serviceDomainReader ServiceDomainReader, serviceDomainCreator ServiceDomainCreator, serviceDomainUpdater ServiceDomainUpdater, serviceDomainDeleter ServiceDomainDeleter, serviceBackupReader ServiceBackupReader, serviceBackupCreator ServiceBackupCreator, serviceBackupUpdater ServiceBackupUpdater, serviceBackupRunner ServiceBackupRunner, serviceBackupDeleter ServiceBackupDeleter, serviceVariables ServiceVariableReader, serviceVariableReplacer ServiceVariableReplacer, deploymentCreator DeploymentCreator, deploymentLister DeploymentLister, deploymentGetter DeploymentGetter, deploymentCanceler DeploymentCanceler, deploymentRollbacker DeploymentRollbacker, breakGlass BreakGlassController, routeOptions ...any) []apiRoute {
	build = build.Normalized()
	var previewCreator PreviewCreator
	var jobReader JobReader
	var jobRetrier JobRetrier
	var jobCanceler JobCanceler
	var driftFindings DriftFindingReader
	var dokployRefs DokployRefReader
	var adminDokployReconciler AdminDokployReconciler
	var adminDokployImporter AdminDokployImporter
	var adminConfigDryRunner AdminConfigDryRunner
	var adminPlanManager AdminPlanManager
	var adminSubscriptionManager AdminSubscriptionManager
	var adminMeteringSourceManager AdminMeteringSourceManager
	var adminMetricDefinitionManager AdminMetricDefinitionManager
	var adminAttributionRuleManager AdminAttributionRuleManager
	httpMetrics := telemetry.DefaultHTTPMetrics
	dokployMetrics := telemetry.DefaultDokployDependencyMetrics
	quotaMetrics := telemetry.DefaultQuotaUsageMetrics
	auditMetrics := telemetry.DefaultAuditEventMetrics
	policyMetrics := telemetry.DefaultPolicyDecisionMetrics
	traceMetrics := telemetry.DefaultTraceSpanMetrics
	slowQueryMetrics := telemetry.DefaultSlowQueryMetrics
	readinessMetrics := telemetry.DefaultReadinessDegradationMetrics
	sloBurnRateMetrics := telemetry.DefaultSLOBurnRateMetrics
	deadLetterAlertMetrics := telemetry.DefaultDeadLetterAlertMetrics
	reconciliationDriftAlertMetrics := telemetry.DefaultReconciliationDriftAlertMetrics
	for _, opt := range routeOptions {
		if v, ok := opt.(PreviewCreator); ok {
			previewCreator = v
		}
		if v, ok := opt.(JobReader); ok {
			jobReader = v
		}
		if v, ok := opt.(JobRetrier); ok {
			jobRetrier = v
		}
		if v, ok := opt.(JobCanceler); ok {
			jobCanceler = v
		}
		if v, ok := opt.(DriftFindingReader); ok {
			driftFindings = v
		}
		if v, ok := opt.(DokployRefReader); ok {
			dokployRefs = v
		}
		if v, ok := opt.(AdminDokployReconciler); ok {
			adminDokployReconciler = v
		}
		if v, ok := opt.(AdminDokployImporter); ok {
			adminDokployImporter = v
		}
		if v, ok := opt.(AdminConfigDryRunner); ok {
			adminConfigDryRunner = v
		}
		if v, ok := opt.(AdminPlanManager); ok {
			adminPlanManager = v
		}
		if v, ok := opt.(AdminSubscriptionManager); ok {
			adminSubscriptionManager = v
		}
		if v, ok := opt.(AdminMeteringSourceManager); ok {
			adminMeteringSourceManager = v
		}
		if v, ok := opt.(AdminMetricDefinitionManager); ok {
			adminMetricDefinitionManager = v
		}
		if v, ok := opt.(AdminAttributionRuleManager); ok {
			adminAttributionRuleManager = v
		}
		if v, ok := opt.(*telemetry.HTTPMetrics); ok && v != nil {
			httpMetrics = v
		}
		if v, ok := opt.(*telemetry.DokployDependencyMetrics); ok && v != nil {
			dokployMetrics = v
		}
		if v, ok := opt.(*telemetry.QuotaUsageMetrics); ok && v != nil {
			quotaMetrics = v
		}
		if v, ok := opt.(*telemetry.AuditEventMetrics); ok && v != nil {
			auditMetrics = v
		}
		if v, ok := opt.(*telemetry.PolicyDecisionMetrics); ok && v != nil {
			policyMetrics = v
		}
		if v, ok := opt.(*telemetry.TraceSpanMetrics); ok && v != nil {
			traceMetrics = v
		}
		if v, ok := opt.(*telemetry.SlowQueryMetrics); ok && v != nil {
			slowQueryMetrics = v
		}
		if v, ok := opt.(*telemetry.ReadinessDegradationMetrics); ok && v != nil {
			readinessMetrics = v
		}
		if v, ok := opt.(*telemetry.SLOBurnRateMetrics); ok && v != nil {
			sloBurnRateMetrics = v
		}
		if v, ok := opt.(*telemetry.DeadLetterAlertMetrics); ok && v != nil {
			deadLetterAlertMetrics = v
		}
		if v, ok := opt.(*telemetry.ReconciliationDriftAlertMetrics); ok && v != nil {
			reconciliationDriftAlertMetrics = v
		}
	}

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
				Path:               "/metrics",
				OperationID:        "getMetrics",
				Summary:            "Read operational metrics",
				Description:        "Returns a yalla.output.v1 envelope containing low-cardinality HTTP request metrics, distributed trace-span metrics, private Dokploy dependency metrics, quota usage decision metrics, audit-log append metrics, policy authorization decision metrics, datastore slow-query metrics, readiness degradation metrics, SLO burn-rate alert metrics, provisioning dead-letter alert metrics, and reconciliation drift alert metrics for this process. HTTP series are grouped by method, matched route pattern, status code, and status class; trace spans are grouped by span name, kind, matched route, component, outcome, status class, and stable error code; Dokploy dependency series are grouped by method, normalized endpoint template, outcome, status class, stable error code, and retryability; quota usage series are grouped by quota resource, enforcement mode, decision outcome, and bounded reason; audit event series are grouped by action, resource kind, allow/deny decision, append outcome, bounded reason, and stable error code; policy decision series are grouped by action, resource kind, allow/deny decision, and stable policy reason; slow-query series are grouped only by store operation, SQL statement kind, and success/error outcome; readiness series are grouped by dependency check, passing/failing status, and bounded reason; SLO burn-rate series are grouped by objective, window, severity, firing status, and source signal; dead-letter alert series are grouped by job_type, reason, severity, and firing status; reconciliation drift alert series are grouped by drift_kind, action_type, reason, severity, and firing status. Request ids, correlation ids, organization ids, principal ids, job ids, actor ids, and resource ids describe only the most recent sample in a series so operators can join aggregates to structured logs, audit rows, drift findings, or job rows during incidents without turning high-cardinality identifiers into dashboard labels. Operators should use trace_spans to find slow or failing spans by route/component/outcome, slow_queries to identify datastore pressure by statement kind, readiness_degradation to identify the failing startup dependency gate, slo_burn_rates to identify budget-consuming API or worker objectives, dead_letter_alerts to page on jobs that exhausted their retry budget before joining the latest job_id/request_id/correlation_id to structured logs and the job row, and reconciliation_drift_alerts to identify dangerous or persistent safe drift before opening the support-only drift findings view for the latest organization/service hints. Secrets in request targets, Dokploy endpoint values, SQL text, submitted signal names, job failure summaries, and reconciliation error strings are redacted or bounded before storage, and metric identifiers are emitted only when they pass the safe correlation-id character set.",
				Tags:               []string{tagOperations},
				SuccessDescription: "The current in-process operational metric snapshot.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteData(w, http.StatusOK, requestID(r), metricsSnapshot{
					HTTPMetricsSnapshot:       httpMetrics.Snapshot(),
					DokployDependencySnapshot: dokployMetrics.Snapshot(),
					QuotaUsageSnapshot:        quotaMetrics.Snapshot(),
					AuditEventSnapshot:        auditMetrics.Snapshot(),
					PolicyDecisionSnapshot:    policyMetrics.Snapshot(),
					TraceSpanSnapshot:         traceMetrics.Snapshot(),
					SlowQuerySnapshot:         slowQueryMetrics.Snapshot(),
					ReadinessSnapshot:         readinessMetrics.Snapshot(),
					SLOBurnRateSnapshot:       sloBurnRateMetrics.Snapshot(),
					DeadLetterAlertSnapshot:   deadLetterAlertMetrics.Snapshot(),
					ReconciliationDriftAlerts: reconciliationDriftAlertMetrics.Snapshot(),
				})
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
			handler: readyzHandler(readiness, readinessMetrics),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/healthz/backup",
				OperationID:        "getHealthzBackup",
				Summary:            "Database backup health probe",
				Description:        "Reports the timestamp of the most recent successful Yalla source-of-truth database backup, as written by the operator's backup pipeline to YALLA_BACKUP_STATUS_FILE. Returns 200 with configured=false when the integration is not wired on this process, 200 with the timestamp and freshness verdict when it is, and 503 with a yalla.error.v1 envelope when the status source is unreadable. Unauthenticated; never reveals tenant data.",
				Tags:               []string{tagOperations},
				SuccessDescription: "Backup status snapshot. Empty when configured=false; otherwise carries last_success_at (when a successful backup has been recorded) and the freshness verdict.",
			},
			handler: backupHealthHandler(backupReporter),
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
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/organizations",
				OperationID:        "listOrganizations",
				Summary:            "Organizations visible to the caller",
				Description:        "Lists the organizations the authenticated principal can see through the control plane, as the source-of-truth database stores them — each with its id, slug, display name, and lifecycle timestamps. A principal is bound to a single home organization, so the list has one entry today; the array shape is forward-compatible with credentials that may span organizations later. The response carries no credential material and never reveals another tenant's data: the read is scoped to the principal's own home organization with no caller-supplied parameter that could point it elsewhere.",
				Tags:               []string{tagOrganizations},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionOrganizationRead),
				SuccessDescription: "The organizations visible to the authenticated principal.",
			},
			// A nil resolver authorizes action organization.read against the
			// principal's own organization scope. The endpoint carries no path
			// parameter and the handler only ever reads the principal's home
			// organization, so there is no deeper or cross-tenant resource
			// target to resolve.
			handler: organizationsHandler(orgs),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/projects",
				OperationID:        "listProjects",
				Summary:            "Projects visible to the caller",
				Description:        "Lists the projects the authenticated principal can see through the control plane, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, slug, display name, optimistic-concurrency version, and lifecycle timestamps. The endpoint carries no path parameter and the handler only ever reads the principal's own home organization's projects, so the tenant boundary is structural: there is no caller-supplied parameter that could point the read at another tenant. Projects are returned in deterministic (slug, id) order so a given set of rows always renders the same response. Action project.read is authorized against the principal's home organization before the handler runs — a CapRead action gated by an organization-wide role (owner, admin, developer, viewer, ci) or, for cross-tenant reads, a support principal; a grant-only principal whose grants are narrower than the home organization is rejected at the boundary because the policy engine asks whether the grant scope contains the resource scope, never the reverse, so a project-, environment-, or service-level grant cannot list sibling projects, unrelated environments, or parent secrets through this endpoint. The response carries no credential material — a projects row stores no secrets — and an organization with no projects is the deterministic empty list every list endpoint returns.",
				Tags:               []string{tagProjects},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionProjectRead),
				SuccessDescription: "The projects visible to the authenticated principal.",
			},
			// A nil resolver authorizes action project.read against the
			// principal's own organization scope. The endpoint carries no path
			// parameter and the handler only ever reads the principal's home
			// organization's projects, so there is no deeper or cross-tenant
			// resource target to resolve.
			handler: listProjectsHandler(projects),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/projects",
				OperationID:        "createProject",
				Summary:            "Create a project",
				Description:        "Creates a project — the second level of Yalla's Organization -> Project -> Environment -> Service hierarchy — inside the authenticated principal's home organization. The request body supplies the caller-minted canonical project id (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug the project is addressed by within its organization, and the human-authored display name. Every field is validated before any database work; an invalid request never opens a transaction. The project row, the durable provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created project can never exist without its provisioning job or its audit trail, and a duplicate slug rolls the whole transaction back as a deterministic 409. Action project.create is authorized against the principal's home organization before the handler runs: project.create is a CapWrite action, so the gate admits organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only), and denies a grant-only principal whose grants are narrower than the home organization — a project-, environment-, or service-level grant cannot create a sibling project through this endpoint. The response carries no credential material.",
				Tags:               []string{tagProjects},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionProjectCreate),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The project was created.",
			},
			// A nil resolver authorizes action project.create against the
			// principal's own organization scope. The created project does
			// not exist yet, so there is no deeper resource target to
			// resolve; the handler creates only inside the principal's home
			// organization, so the tenant boundary is structural — there is
			// no caller input that could point the write at another tenant.
			handler: createProjectHandler(projectCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/config/dry-run",
				OperationID:        "dryRunAdminConfig",
				Summary:            "Dry-run backoffice config",
				Description:        "Validates a candidate backoffice runtime configuration payload before publish. The request supplies the config domain, an optional config_set_id, the candidate payload, and optional simulate_organization_ids for impact simulation. Action config.publish is required because the dry-run validates a production-impacting publish candidate. The response is always a yalla.output.v1 envelope for a well-formed dry-run request: candidate defects are returned as stable blocking_errors and warnings so operators and agents can fix every issue in one pass. Malformed request shape and unknown selected organizations still return typed yalla.error.v1 errors. Secret-looking credential_ref values are rejected without echoing the submitted value.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionConfigPublish),
				SuccessDescription: "The dry-run validation report.",
			},
			handler: dryRunAdminConfigHandler(adminConfigDryRunner),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/plans",
				OperationID:        "createAdminPlan",
				Summary:            "Create a draft pricing plan",
				Description:        "Creates a draft backoffice pricing-plan version. The plan catalog is global operator-owned configuration, not tenant data; action pricing.manage is required. The draft is not runtime-active until it is published.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The draft plan was created.",
			},
			handler: createAdminPlanHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPatch,
				Path:               "/v1/admin/plans/{plan_id}",
				OperationID:        "editAdminPlan",
				Summary:            "Edit a pricing plan draft",
				Description:        "Creates or updates an editable draft replacement for the addressed pricing-plan version without mutating the active version in place. Published plan versions remain reproducible for historical invoices.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The plan version to edit."}},
				SuccessDescription: "The edited draft plan.",
			},
			handler: editAdminPlanHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/plans/{plan_id}/publish",
				OperationID:        "publishAdminPlan",
				Summary:            "Publish a pricing plan draft",
				Description:        "Publishes the addressed draft plan version and archives any previously active version for the same slug and billing period in the same transaction.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionConfigPublish),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The draft plan version to publish."}},
				SuccessDescription: "The plan version is active.",
			},
			handler: publishAdminPlanHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/plans/{plan_id}/archive",
				OperationID:        "archiveAdminPlan",
				Summary:            "Archive a pricing plan",
				Description:        "Archives the addressed plan version while preserving it for invoice and subscription audit reads.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionConfigPublish),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The plan version to archive."}},
				SuccessDescription: "The plan version was archived.",
			},
			handler: archiveAdminPlanHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/plans/{plan_id}/rollback",
				OperationID:        "rollbackAdminPlan",
				Summary:            "Rollback a pricing plan",
				Description:        "Publishes a new active version copied from the addressed historical plan version, then archives the previously active version for the same slug and billing period.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionConfigPublish),
				SuccessStatus:      http.StatusCreated,
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The historical plan version to restore from."}},
				SuccessDescription: "A rollback plan version was published.",
			},
			handler: rollbackAdminPlanHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/plans/{plan_id}/entitlements/{entitlement_key}",
				OperationID:        "upsertAdminPlanEntitlement",
				Summary:            "Configure a pricing-plan entitlement",
				Description:        "Creates or replaces one entitlement on a backoffice pricing-plan version. The request configures the stable entitlement key, included value, enforcement mode, unit, warning threshold, upgrade hint, and overage behavior metadata. Plan entitlements are global operator-owned configuration; action pricing.manage is required.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The plan version to configure."}, {Name: "entitlement_key", Description: "The entitlement key to create or replace."}},
				SuccessDescription: "The entitlement was configured.",
			},
			handler: upsertAdminPlanEntitlementHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/plans/{plan_id}/entitlements/{entitlement_key}/rename",
				OperationID:        "renameAdminPlanEntitlement",
				Summary:            "Rename a pricing-plan entitlement",
				Description:        "Renames one entitlement key on a pricing-plan version. Because entitlement keys are public compatibility contracts used by runtime quota, billing, subscriptions, and customer-facing limits, the request must carry an impact_validation_id from a completed migration-impact validation run before any key is changed.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The plan version to modify."}, {Name: "entitlement_key", Description: "The existing entitlement key."}},
				SuccessDescription: "The entitlement key was renamed.",
			},
			handler: renameAdminPlanEntitlementHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodDelete,
				Path:               "/v1/admin/plans/{plan_id}/entitlements/{entitlement_key}",
				OperationID:        "deleteAdminPlanEntitlement",
				Summary:            "Delete a pricing-plan entitlement",
				Description:        "Deletes one entitlement from a pricing-plan version. Deletion requires impact_validation_id because removing a key can affect runtime quota enforcement, customer limits output, billing exports, and accepted subscriptions.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "plan_id", Description: "The plan version to modify."}, {Name: "entitlement_key", Description: "The entitlement key to remove."}},
				SuccessDescription: "The entitlement was deleted.",
			},
			handler: deleteAdminPlanEntitlementHandler(adminPlanManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/organizations/{org_id}/subscription",
				OperationID:        "setAdminOrganizationSubscription",
				Summary:            "Set organization subscription",
				Description:        "Creates or replaces the current subscription assignment for one organization. Pricing administrators can change the accepted immutable plan id, lifecycle status, current period, trial and cancellation state, billing provider identifiers, and redacted metadata. Runtime entitlement cache entries are invalidated by the subscription row revision used by the resolver.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "org_id", Description: "The organization whose subscription assignment is changed."}},
				SuccessDescription: "The organization subscription was persisted and audited.",
			},
			handler:  setAdminSubscriptionHandler(adminSubscriptionManager),
			resolver: organizationIDResolver,
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/organizations/{org_id}/subscription/entitlements/{entitlement_key}",
				OperationID:        "upsertAdminOrganizationSubscriptionEntitlement",
				Summary:            "Upsert subscription entitlement",
				Description:        "Creates or replaces an organization-specific subscription override or emergency-admin add-on with effective dates and an audited reason. Secret-looking metadata keys are redacted before persistence and response rendering.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionPricingManage),
				PathParams:         []openapi.PathParam{{Name: "org_id", Description: "The organization whose entitlement override is changed."}, {Name: "entitlement_key", Description: "The entitlement key to override."}},
				SuccessDescription: "The organization entitlement override was persisted and audited.",
			},
			handler:  upsertAdminSubscriptionEntitlementHandler(adminSubscriptionManager),
			resolver: organizationIDResolver,
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/metering/sources/{source_key}",
				OperationID:        "upsertAdminMeteringSource",
				Summary:            "Configure a metering source",
				Description:        "Creates or replaces one backoffice metering source configuration for Traefik, Prometheus, Dokploy, container, storage, or backup metering. Credentials are write-only: submitted credential_value is sealed at rest and never returned in the response. Action metering.manage is required.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "source_key", Description: "Stable metering source key."}},
				SuccessDescription: "The metering source was persisted and audited.",
			},
			handler: upsertAdminMeteringSourceHandler(adminMeteringSourceManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/admin/metering/attribution/rules/{rule_key}",
				OperationID:        "getAdminAttributionRule",
				Summary:            "Get an attribution rule",
				Description:        "Returns one backoffice attribution rule used to map metric labels or Dokploy identifiers onto Yalla resources. Action metering.manage is required.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "rule_key", Description: "Stable attribution rule key."}},
				SuccessDescription: "The attribution rule.",
			},
			handler: getAdminAttributionRuleHandler(adminAttributionRuleManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/metering/attribution/rules/{rule_key}",
				OperationID:        "upsertAdminAttributionRule",
				Summary:            "Configure an attribution rule",
				Description:        "Creates or replaces one audited attribution rule for Traefik service labels, Dokploy appName patterns, or explicit dokploy_refs. Unknown or ambiguous samples never become billable automatically; the rule controls whether they are quarantined for review or ignored.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "rule_key", Description: "Stable attribution rule key."}},
				SuccessDescription: "The attribution rule was persisted and audited.",
			},
			handler: upsertAdminAttributionRuleHandler(adminAttributionRuleManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/metering/attribution/dry-run",
				OperationID:        "dryRunAdminAttributionRules",
				Summary:            "Dry-run attribution rules",
				Description:        "Evaluates candidate or currently published attribution rules against submitted sample metrics without mutating state. The response reports deterministic attribute, quarantine, and ignore decisions; quarantined samples remain a successful yalla.output.v1 dry-run result.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				SuccessDescription: "The attribution dry-run report.",
			},
			handler: dryRunAdminAttributionRulesHandler(adminAttributionRuleManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/admin/metering/definitions/{metric_key}",
				OperationID:        "getAdminMetricDefinition",
				Summary:            "Get a metric definition",
				Description:        "Returns the current backoffice metric definition for one tracked metric, including unit, source, aggregation function, aggregation window, billing-grade flag, retention, enforcement link, enabled state, and version. Action metering.manage is required.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "metric_key", Description: "Stable tracked metric key."}},
				SuccessDescription: "The current metric definition.",
			},
			handler: getAdminMetricDefinitionHandler(adminMetricDefinitionManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPut,
				Path:               "/v1/admin/metering/definitions/{metric_key}",
				OperationID:        "upsertAdminMetricDefinition",
				Summary:            "Configure a metric definition",
				Description:        "Creates or updates one published tracked metric definition. Billing-grade unit changes require allow_new_version=true so historical usage remains bound to its original unit and a new version is published instead of mutating history.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "metric_key", Description: "Stable tracked metric key."}},
				SuccessDescription: "The metric definition was persisted and audited.",
			},
			handler: upsertAdminMetricDefinitionHandler(adminMetricDefinitionManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodDelete,
				Path:               "/v1/admin/metering/definitions/{metric_key}",
				OperationID:        "disableAdminMetricDefinition",
				Summary:            "Disable a metric definition",
				Description:        "Disables the current metric definition without deleting version history. Runtime aggregators load only enabled current definitions.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "metric_key", Description: "Stable tracked metric key."}},
				SuccessDescription: "The metric definition was disabled and audited.",
			},
			handler: disableAdminMetricDefinitionHandler(adminMetricDefinitionManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/metering/sources/{source_key}/test",
				OperationID:        "testAdminMeteringSource",
				Summary:            "Test a metering source",
				Description:        "Performs a side-effect-free reachability check against the configured metering source endpoint and returns a stable success or failure report without exposing credentials.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionMeteringManage),
				PathParams:         []openapi.PathParam{{Name: "source_key", Description: "Stable metering source key."}},
				SuccessDescription: "The source connection test report.",
			},
			handler: testAdminMeteringSourceHandler(adminMeteringSourceManager),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "getProject",
				Summary:        "Get a project",
				Description:    "Returns the project named by the {project_id} path parameter, as the source-of-truth database stores it — its id, the id of the organization that owns it, slug, display name, optimistic-concurrency version, and lifecycle timestamps. Action project.read is authorized against the (home organization, project_id) resource before the handler runs: project.read is a CapRead action, so the gate admits the principal's organization-wide roles (owner, admin, developer, viewer, ci) and a support principal performing a read; it also admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project), but denies a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's data. The response carries no credential material — a projects row stores no secrets.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to retrieve.",
				}},
				SuccessDescription: "The requested project.",
			},
			// projectIDResolver authorizes action project.read against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so
			// a scoped grant that names THIS project authorizes the read
			// while a grant that names only a SIBLING project does not.
			// The organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant project_id still hits
			// the tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary.
			resolver: projectIDResolver,
			handler:  getProjectHandler(projects),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "updateProject",
				Summary:        "Update a project",
				Description:    "Updates the project named by the {project_id} path parameter in the source-of-truth database. The request body is a partial update: it may carry a new canonical slug, a new human-authored display name, or both — every supplied field is validated before any database work, and a patch that names no field is rejected with a stable 400. The request body intentionally exposes no organization_id field: the tenant is derived from the authenticated principal's home organization, never from the body or path query. Action project.update is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never mutating another tenant's data. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The updated project row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to update.",
				}},
				SuccessDescription: "The updated project.",
			},
			// projectIDResolver authorizes action project.update against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// write while a grant that names only a SIBLING project does
			// not. The organization id is taken from the principal's home
			// org (never the caller), so a cross-tenant project_id still
			// hits the tenant-scoped repository query and surfaces as a
			// 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  updateProjectHandler(projectUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "deleteProject",
				Summary:        "Schedule a project for deletion",
				Description:    "Schedules the project named by the {project_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the project's deletion_scheduled_at stamp is set and the destructive teardown — the ON DELETE CASCADE that removes its environments, services, and audit log — is carried out by a later worker story, so the project and its audit trail still exist when this returns. Action project.delete is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never scheduling another tenant's data for teardown. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Scheduling deletion for a project already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction: a scheduled deletion can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectDelete),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to schedule for deletion.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The project was scheduled for deletion.",
			},
			// projectIDResolver authorizes action project.delete against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// teardown while a grant that names only a SIBLING project
			// does not. The organization id is taken from the principal's
			// home org (never the caller), so a cross-tenant project_id
			// still hits the tenant-scoped repository query and surfaces
			// as a 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  deleteProjectHandler(projectDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/projects/{project_id}/restore",
				OperationID:    "restoreProject",
				Summary:        "Restore a soft-deleted project",
				Description:    "Restores the project named by the {project_id} path parameter that was previously scheduled for deletion by DELETE /v1/projects/{project_id} but has not yet been destructively torn down by the worker. The restore is the inverse of the soft-delete: it clears the project's deletion_scheduled_at stamp in the source-of-truth database so the project is live again, and its environments, services, and audit trail (which the destructive teardown has not yet cascaded away) are recovered intact. Action project.restore is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.restore is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never restoring another tenant's data. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Restoring a project that is not currently scheduled for deletion is a stable 409: the caller's view of the resource lifecycle is stale, so a silent success would write a misleading audit record. The clear-stamp write and an immutable audit record naming the authenticated principal are committed in one transaction: a restore can never be persisted without its audit trail. The request body is empty. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectRestore),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to restore from soft-deletion.",
				}},
				SuccessDescription: "The project was restored from soft-deletion.",
			},
			// projectIDResolver authorizes action project.restore against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// restore while a grant that names only a SIBLING project
			// does not. The organization id is taken from the principal's
			// home org (never the caller), so a cross-tenant project_id
			// still hits the tenant-scoped repository query and surfaces
			// as a 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  restoreProjectHandler(projectRestorer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/grants",
				OperationID:    "listProjectGrants",
				Summary:        "List project grants",
				Description:    "Lists the scoped grants attached to the project named by the {project_id} path parameter, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, the id of the project it targets, the principal it confers a role on, the role it confers, optional further (environment, service) scoping, optimistic-concurrency version, and lifecycle timestamps. Grants narrow or widen a principal's authority below the organization level: a developer with a project-scoped Viewer grant for one project cannot mutate sibling projects, and a viewer with a project-scoped Admin grant for one project can mutate it without becoming an admin of the whole organization. Action project.grants.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.grants.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci) and admits a scoped grant that covers the resource (a project-scoped Viewer grant for THAT project, an environment- or service-scoped grant under it) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no grants is a deterministic empty list. The response carries no credential material — a grants row stores only structural identifiers and a role enum.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectGrantsRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose grants to list.",
				}},
				SuccessDescription: "The grants attached to the project.",
			},
			// projectIDResolver authorizes action project.grants.read against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so a
			// scoped grant that names THIS project authorizes the read while
			// a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectGrantsHandler(projectGrants),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/projects/{project_id}/grants",
				OperationID:    "replaceProjectGrants",
				Summary:        "Replace project grants",
				Description:    "Replaces the scoped grants attached to the project named by the {project_id} path parameter in one transaction. The request body supplies the complete replacement set — every grant absent from the body is removed, every grant present is upserted on its scope tuple (principal_id, environment_id, service_id), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every grant of this project\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing grants field, blank principal_id, unknown principal_kind, unknown role, duplicate scope tuple, service-scope without environment) never opens a transaction. Action project.grants.write is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.grants.write is a CapAdmin action, so the gate admits the principal's organization-wide admin roles (owner, admin) or a scoped grant that covers the resource (a project-scoped Admin grant for THAT project) while denying viewer, developer, ci, support, and grants that name only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. project.grants.write is a CapAdmin action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's grants. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the project existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted grants in the same stable wire shape GET /v1/projects/{project_id}/grants returns — every column projected onto the deterministic (principal_id, environment_id NULLS FIRST, service_id NULLS FIRST, id) order. A grant carries no credential material — the schema stores only structural identifiers and a role enum.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectGrantsWrite),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose grants to replace.",
				}},
				SuccessDescription: "The grants attached to the project after the replace.",
			},
			// projectIDResolver authorizes action project.grants.write against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so a
			// scoped admin grant that names THIS project authorizes the write
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller — there is no organization id in the request body),
			// so a cross-tenant project_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. project.grants.write is a CapAdmin action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot replace grants in another tenant.
			resolver: projectIDResolver,
			handler:  replaceProjectGrantsHandler(projectGrantReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/variables",
				OperationID:    "listProjectVariables",
				Summary:        "List project variables",
				Description:    "Lists the project-scoped environment variables configured for the project named by the {project_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, the id of the organization that owns it, the id of the project it targets, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Project-scoped variables are the second-from-lowest precedence layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here is a project-wide default every service in the project inherits unless overridden by a higher-scope variable, and it shadows any organization-scoped variable of the same key for services inside the project. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own project-wide defaults. Action env.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: env.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci) and admits a scoped grant that covers the resource (a project-scoped Viewer grant for THAT project, an environment- or service-scoped grant under it) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no variables is a deterministic empty list.",
				Tags:           []string{tagProjects, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose variables to list.",
				}},
				SuccessDescription: "The variables of the project.",
			},
			// projectIDResolver authorizes action env.read against the
			// (principal home organization, {project_id}) resource the path
			// names, not merely the principal's home organization, so a
			// scoped grant that names THIS project authorizes the read while
			// a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectVariablesHandler(projectVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/projects/{project_id}/variables",
				OperationID:    "replaceProjectVariables",
				Summary:        "Replace project variables",
				Description:    "Replaces the project-scoped environment variables attached to the project named by the {project_id} path parameter in one transaction. The request body supplies the complete replacement set — every variable absent from the body is removed, every variable present is upserted on (organization_id, project_id, key), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every project-scoped variable\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing variables field, non-POSIX key, duplicate key, oversize value, invalid UTF-8, NUL byte in value) never opens a transaction. Action env.write is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: env.write is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) or a scoped grant that covers the resource (a project-scoped Developer / Admin / Owner grant for THAT project, an environment- or service-scoped grant under it) while denying viewer, support, and grants that name only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. env.write is a CapWrite action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's variables. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the project existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted variables in the same stable wire shape GET /v1/projects/{project_id}/variables returns — every column projected onto the deterministic (key, id) order. Secret values are still redacted on the wire to the sentinel, so PUT cannot leak a secret value the customer just submitted; non-secret values project verbatim.",
				Tags:           []string{tagProjects, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose variables to replace.",
				}},
				SuccessDescription: "The variables of the project after the replace.",
			},
			// projectIDResolver authorizes action env.write against the
			// (principal home organization, {project_id}) resource the path
			// names, not merely the principal's home organization, so a
			// scoped write grant that names THIS project authorizes the write
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller — there is no organization id in the request body),
			// so a cross-tenant project_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. env.write is a CapWrite action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot replace variables in another tenant.
			resolver: projectIDResolver,
			handler:  replaceProjectVariablesHandler(projectVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/environments",
				OperationID:    "listProjectEnvironments",
				Summary:        "List project environments",
				Description:    "Lists the environments configured for the project named by the {project_id} path parameter, in deterministic (slug, id) order. Each entry carries the environment's id, the id of the organization that owns it, the id of the project it belongs to, slug (unique within the project), display name, optimistic-concurrency version, and lifecycle timestamps. Environments are the third layer of the Organization -> Project -> Environment -> Service hierarchy the Dokploy provisioning model mirrors; an environment groups the services that share a deployment target (for example production, staging, preview) within a project. Action environment.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: a CapRead action gated by an organization-wide role (owner, admin, developer, viewer, ci) or a scoped grant that covers the resource (a project-, environment-, or service-scoped grant inside this project) while a grant that names only a sibling project, an unrelated environment, or an unrelated service is rejected at the boundary because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no environments is a deterministic empty list. The response carries no credential material — the environments table stores only structural identifiers, a slug, a display name, an optimistic-concurrency version, and lifecycle timestamps.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose environments to list.",
				}},
				SuccessDescription: "The environments of the project.",
			},
			// projectIDResolver authorizes action environment.read against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so
			// a scoped grant that names THIS project authorizes the read
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectEnvironmentsHandler(projectEnvironments),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/projects/{project_id}/environments",
				OperationID:    "createProjectEnvironment",
				Summary:        "Create a project environment",
				Description:    "Creates an environment — the third level of Yalla's Organization -> Project -> Environment -> Service hierarchy — inside the project named by the {project_id} path parameter. The request body supplies the caller-minted canonical environment id (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug the environment is addressed by within its project, and the human-authored display name. Every field is validated before any database work; an invalid request never opens a transaction. The environment row, the durable provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created environment can never exist without its provisioning job or its audit trail, and a duplicate slug within the same project rolls the whole transaction back as a deterministic 409. Action environment.create is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: environment.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci), admits a scoped grant that covers the project (a project-scoped Admin grant for THIS project, an environment- or service-scoped grant under it), denies viewer (CapRead only), denies support (CapRead-only — support is a deliberate cross-tenant READ exception, never a write one), and denies a grant that names only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the store-layer project existence check, never disguised as a 200 or a 403 that would confirm the foreign project's existence. The response carries no credential material.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project the new environment will belong to.",
				}},
				SuccessDescription: "The environment was created.",
			},
			// projectIDResolver authorizes action environment.create against
			// the (principal home organization, {project_id}) resource the
			// path names, so a scoped grant that names THIS project
			// authorizes the write while a grant that names only a SIBLING
			// project does not. The organization id on the persistence
			// input is taken from the principal's home org (never the
			// caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary — never disguised as a 200 with an
			// environment minted under another tenant. environment.create
			// is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot create environments in another tenant.
			resolver: projectIDResolver,
			handler:  createProjectEnvironmentHandler(environmentCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/projects/{project_id}/previews",
				OperationID:    "createPreview",
				Summary:        "Create preview environment",
				Description:    "Creates an ephemeral preview environment under the project named by the {project_id} path parameter. The request body supplies the caller-minted preview row id, the caller-minted environment id for the cloned preview environment, the source environment id to clone from, a canonical slug for the new environment, a display name, a change reference, and an optional expiry timestamp. The request body intentionally exposes no organization_id or project_id field: the organization is derived from the authenticated principal's home organization and the project comes from the path, so cross-tenant ids reach the tenant-scoped store as deterministic not-found errors. The source environment must belong to the same project, the clone is stored as kind=preview, the preview_environments lifecycle row wraps that clone, the provisioning job is enqueued, and an immutable audit event names the actor, all in one store unit of work. Action preview.create is authorized against the (principal home organization, {project_id}) resource before the handler runs; it is a CapDeploy action, so viewer and support principals cannot create previews.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionPreviewCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project the preview will belong to.",
				}},
				SuccessDescription: "The preview environment was created.",
			},
			resolver: projectIDResolver,
			handler:  createPreviewHandler(previewCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/previews",
				OperationID:    "listProjectPreviews",
				Summary:        "List project preview environments",
				Description:    "Lists the preview environments under the project named by the {project_id} path parameter in deterministic creation order. Each entry carries the preview lifecycle row, the wrapped preview environment id, the source environment id, display name, change reference, status, optional expiry, optional teardown marker, version, and lifecycle timestamps. Action preview.read is authorized against the (principal home organization, {project_id}) resource before the handler runs, so organization-wide read roles and scoped grants covering this project can list previews while sibling-project grants cannot. A cross-tenant or unknown project_id reaches the tenant-scoped store with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. The response carries no credential material.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionPreviewRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose preview environments to list.",
				}},
				SuccessDescription: "The preview environments of the project.",
			},
			resolver: projectIDResolver,
			handler:  listProjectPreviewsHandler(previewCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/projects/{project_id}/previews/{preview_id}",
				OperationID:    "deletePreview",
				Summary:        "Delete preview environment",
				Description:    "Schedules the preview environment named by {preview_id} under the project named by {project_id} for worker-driven teardown. The handler derives organization scope from the authenticated principal, authorizes action preview.delete against the parent project resource, then asks the store service to verify the tenant-scoped project and preview row, stamp deletion_scheduled_at, enqueue the delete_preview_environment provisioning job, and append the immutable audit event in one transaction. A cross-tenant or unknown project_id/preview_id reaches the tenant-scoped store with the principal's home organization id and surfaces as a deterministic 404. The response carries the scheduled preview lifecycle row in the stable yalla.output.v1 envelope.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionPreviewDelete),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project that owns the preview environment.",
				}, {
					Name:        "preview_id",
					Description: "The id of the preview environment to schedule for deletion.",
				}},
				SuccessDescription: "The preview environment was scheduled for deletion.",
			},
			resolver: projectIDResolver,
			handler:  deletePreviewHandler(previewCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "getEnvironment",
				Summary:        "Get an environment",
				Description:    "Returns the environment named by the {environment_id} path parameter, as the source-of-truth database stores it — its id, the id of the organization that owns it, the id of the project it belongs to, slug, display name, optimistic-concurrency version, and lifecycle timestamps. Environments are the third layer of the Organization -> Project -> Environment -> Service hierarchy the Dokploy provisioning model mirrors. Action environment.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use the parent-scoped GET /v1/projects/{project_id}/environments to address an environment by its (project, environment) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped GetByID query, never revealing another tenant's environment. The response carries no credential material — the environments table itself stores only structural identifiers, a slug, a display name, an optimistic-concurrency version, and lifecycle timestamps; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to return.",
				}},
				SuccessDescription: "The requested environment.",
			},
			// environmentIDResolver authorizes action environment.read
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// environment_id still hits the tenant-scoped GetByID query
			// and surfaces as a 404 at the persistence boundary. The
			// path carries no parent project_id, so the resource scope
			// pins only OrganizationID and EnvironmentID — project- and
			// environment-scoped grants are denied at the policy
			// boundary by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto the parent-scoped
			// /v1/projects/{project_id}/environments route.
			resolver: environmentIDResolver,
			handler:  getEnvironmentHandler(environmentReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "updateEnvironment",
				Summary:        "Update an environment",
				Description:    "Partially updates the environment named by the {environment_id} path parameter, as the source-of-truth database stores it. The request body is a partial-update document: both slug and display_name are optional pointers, so omitting a field leaves it unchanged. A patch that names no updatable field is a stable 400 — a mutation that changes nothing is a client error, not a silent success. Every supplied field is validated before any database work; an invalid request never opens a transaction. The desired-state write and an immutable audit record naming the authenticated principal are committed in one transaction — an update can never be persisted without its audit trail, and a duplicate slug within the same project rolls the whole transaction back as a deterministic 409. Action environment.update is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule; principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition. The response carries no credential material — the environments table itself stores no secrets; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to update.",
				}},
				SuccessDescription: "The environment was updated.",
			},
			// environmentIDResolver authorizes action environment.update
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// environment_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence boundary.
			// The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.update is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot mutate
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  updateEnvironmentHandler(environmentUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "deleteEnvironment",
				Summary:        "Schedule an environment for deletion",
				Description:    "Schedules the environment named by the {environment_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the environment's deletion_scheduled_at stamp is set and the destructive teardown — the ON DELETE CASCADE that removes its services and audit log — is carried out by a later worker story, so the environment and its audit trail still exist when this returns. Action environment.delete is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Scheduling deletion for an environment already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction: a scheduled deletion can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentDelete),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to schedule for deletion.",
				}},
				SuccessDescription: "The environment was scheduled for deletion.",
			},
			// environmentIDResolver authorizes action environment.delete
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// environment_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence boundary.
			// The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.delete is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot mutate
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  deleteEnvironmentHandler(environmentDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/environments/{environment_id}/clone",
				OperationID:    "cloneEnvironment",
				Summary:        "Clone an environment",
				Description:    "Clones the environment named by the {environment_id} path parameter into a new environment that inherits the source environment's parent project — the new environment lives in the same Organization -> Project -> Environment -> Service hierarchy as its source, never crossing a tenant or project boundary. The request body supplies the caller-minted canonical id for the new environment (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug it is addressed by within the inherited project, and its human-authored display name. The request body intentionally exposes no organization_id, project_id, or source_environment_id field: the organization is derived from the authenticated principal's home organization, the source environment_id comes from the {environment_id} path parameter, and the new environment inherits the source's project_id — there is no caller-supplied parameter that could redirect the clone at another tenant or another project. Every supplied field is validated before any database work; an invalid request never opens a transaction. The new environment row, the provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal and the source environment are committed in one transaction — a cloned environment can never exist without its provisioning job or its audit trail, and a duplicate slug within the inherited project rolls the whole transaction back as a deterministic 409. Action environment.create is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown source {environment_id} reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. A source environment already scheduled for teardown is rejected as a deterministic 409 — a lifecycle-dead row is not a valid clone source. The new environment's id must differ from the source environment's id; cloning onto the same id is a stable 400. The response carries no credential material — the environments table itself stores no secrets; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies. (Variables and secrets are not yet copied across by this endpoint; a later worker story owns that propagation, so the clone here writes only the structural row.) The response mirrors the new row's authoritative version into the ETag response header so the caller can echo it back as the next If-Match precondition without re-reading the row.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the source environment to clone from.",
				}},
				SuccessDescription: "The environment was cloned.",
			},
			// environmentIDResolver authorizes action environment.create
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// source environment_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. The path carries no parent project_id, so the
			// resource scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.create is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot clone
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  cloneEnvironmentHandler(environmentCloner),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}/grants",
				OperationID:    "listEnvironmentGrants",
				Summary:        "List environment grants",
				Description:    "Lists the scoped grants attached to the environment named by the {environment_id} path parameter, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, the id of the environment it targets, the principal it confers a role on, the role it confers, optional further (service) scoping, optimistic-concurrency version, and lifecycle timestamps. Environment grants narrow or widen a principal's authority below the project level: a developer with an environment-scoped Viewer grant for one environment cannot mutate sibling environments, and a viewer with an environment-scoped Admin grant for one environment can mutate it without becoming an admin of the whole project. Action environment.grants.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must address grants through a parent-scoped route. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's environment existence check, never disguised as an empty success. An environment with no grants is a deterministic empty list. The response carries no credential material — a grants row stores only structural identifiers and a role enum.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentGrantsRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose grants to list.",
				}},
				SuccessDescription: "The grants attached to the environment.",
			},
			// environmentIDResolver authorizes action
			// environment.grants.read against the (principal home
			// organization, {environment_id}) resource the path names,
			// not merely the principal's home organization. The
			// organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant environment_id
			// still hits the tenant-scoped repository query and
			// surfaces as a 404 at the persistence boundary. The path
			// carries no parent project_id, so the resource scope
			// pins only OrganizationID and EnvironmentID — project-,
			// environment-, and service-scoped grants are denied at
			// the policy boundary by design (the engine's covers()
			// rule), forcing scoped-grant-only principals onto
			// parent-scoped routes.
			resolver: environmentIDResolver,
			handler:  listEnvironmentGrantsHandler(environmentGrants),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/environments/{environment_id}/grants",
				OperationID:    "replaceEnvironmentGrants",
				Summary:        "Replace environment grants",
				Description:    "Replaces the scoped grants attached to the environment named by the {environment_id} path parameter in one transaction. The request body supplies the complete replacement set — every grant absent from the body is removed, every grant present is upserted on its (principal_id, service_id) scope tuple — so a PUT with the same set is structurally idempotent. An explicit empty array means \"clear every grant of this environment\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing grants field, blank principal_id, unknown principal_kind, unknown role, duplicate scope tuple) never opens a transaction. Action environment.grants.write is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.grants.write is a CapAdmin action, so the gate admits the owner and admin roles, or a principal holding a scope-covering admin grant, and denies viewer, developer, ci, and support principals at the policy boundary. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); scoped-grant-only principals must address grants through a parent-scoped route. The grant upserts, the bulk delete-by-exclusion that drops every grant absent from the replacement set, and the immutable audit record naming the authenticated principal are committed in one transaction, so a partial replace can never be observed and an orphaned audit record is impossible. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404. The response carries no credential material — a grants row stores only structural identifiers and a role enum — and the success body is the same wire shape GET /v1/environments/{environment_id}/grants returns — every column projected onto the deterministic (principal_id, service_id NULLS FIRST, id) order.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentGrantsWrite),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose grants to replace.",
				}},
				SuccessDescription: "The grants attached to the environment after the replace.",
			},
			// environmentIDResolver authorizes action
			// environment.grants.write against the (principal home
			// organization, {environment_id}) resource the path names.
			// The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.grants.write is a
			// CapAdmin action and has no cross-tenant support exception
			// — unlike CapRead actions, a support principal cannot
			// replace environment grants in another tenant.
			resolver: environmentIDResolver,
			handler:  replaceEnvironmentGrantsHandler(environmentGrantReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}/variables",
				OperationID:    "listEnvironmentVariables",
				Summary:        "List environment variables",
				Description:    "Lists the environment-scoped variables configured for the environment named by the {environment_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, the id of the organization that owns it, the id of the environment it targets, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Environment-scoped variables are the third-from-lowest precedence layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here is an environment-wide default every service in the environment inherits unless overridden by a higher-scope (service) variable, and it shadows the project-scoped variable of the same key for services inside the environment, which in turn shadows the organization-scoped variable of the same key. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own environment-wide defaults. Action env.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: env.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address an environment-scoped variable list. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's environment existence check, never disguised as an empty success. An environment with no variables is a deterministic empty list.",
				Tags:           []string{tagEnvironments, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose variables to list.",
				}},
				SuccessDescription: "The variables of the environment.",
			},
			// environmentIDResolver authorizes action env.read against the
			// (principal home organization, {environment_id}) resource the
			// path names, not merely the principal's home organization, so
			// org-wide read roles authorize the read and scoped grants
			// pinning a ProjectID do not (covers() is one-way). The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant environment_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: environmentIDResolver,
			handler:  listEnvironmentVariablesHandler(environmentVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/environments/{environment_id}/variables",
				OperationID:    "replaceEnvironmentVariables",
				Summary:        "Replace environment variables",
				Description:    "Replaces the environment-scoped variables attached to the environment named by the {environment_id} path parameter in one transaction. The request body supplies the complete replacement set — every variable absent from the body is removed, every variable present is upserted on (organization_id, environment_id, key), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every environment-scoped variable\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing variables field, non-POSIX key, duplicate key, oversize value, invalid UTF-8, NUL byte in value) never opens a transaction. Action env.write is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: env.write is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) while denying viewer and support (the latter is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address an environment-scoped variable replace. env.write is a CapWrite action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's variables. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the environment existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted variables in the same stable wire shape GET /v1/environments/{environment_id}/variables returns — every column projected onto the deterministic (key, id) order. Secret values are still redacted on the wire to the sentinel, so PUT cannot leak a secret value the customer just submitted; non-secret values project verbatim.",
				Tags:           []string{tagEnvironments, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose variables to replace.",
				}},
				SuccessDescription: "The variables of the environment after the replace.",
			},
			// environmentIDResolver authorizes action env.write against the
			// (principal home organization, {environment_id}) resource the
			// path names. The path carries no parent project_id, so the
			// resource scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are denied
			// at the policy boundary by design (the engine's covers()
			// rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. env.write is a CapWrite action and has
			// no cross-tenant support exception — unlike CapRead actions,
			// the support principal cannot replace variables in another
			// tenant. The organization id is taken from the principal's
			// home org (never the caller — there is no organization id in
			// the request body), so a cross-tenant environment_id still
			// hits the tenant-scoped repository query and surfaces as a
			// 404 at the persistence boundary.
			resolver: environmentIDResolver,
			handler:  replaceEnvironmentVariablesHandler(environmentVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}/services",
				OperationID:    "listEnvironmentServices",
				Summary:        "List environment services",
				Description:    "Lists the services configured under the environment named by the {environment_id} path parameter — the fourth and lowest level of Yalla's Organization -> Project -> Environment -> Service hierarchy — in deterministic (slug, id) order. Each entry carries the service's id, the id of the organization that owns it, the id of the project it belongs to, the id of the environment it targets, slug, display name, kind taxonomy ('application', 'database', or 'compose'), optimistic-concurrency version, and lifecycle timestamps. The wire shape carries no credential material — a services row stores no secrets; service-scoped variables, deployment artifacts, and other secret-bearing resources live behind their own endpoints (later stories) where the redaction policy applies. Action service.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: service.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address an environment-scoped service list. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's environment existence check, never disguised as an empty success. An environment with no services is a deterministic empty list.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose services to list.",
				}},
				SuccessDescription: "The services of the environment.",
			},
			// environmentIDResolver authorizes action service.read against
			// the (principal home organization, {environment_id}) resource
			// the path names, not merely the principal's home organization,
			// so org-wide read roles authorize the read and scoped grants
			// pinning a ProjectID do not (covers() is one-way). The
			// organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant environment_id still
			// hits the tenant-scoped reader and surfaces as a 404 at the
			// persistence boundary.
			resolver: environmentIDResolver,
			handler:  listEnvironmentServicesHandler(environmentServices),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/environments/{environment_id}/services",
				OperationID:    "createEnvironmentService",
				Summary:        "Create an environment service",
				Description:    "Creates a service under the environment named by the {environment_id} path parameter — the fourth and lowest level of Yalla's Organization -> Project -> Environment -> Service hierarchy. The request body supplies the caller-minted canonical id for the new service (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug it is addressed by within the parent environment, its human-authored display name, and its Dokploy kind taxonomy ('application', 'database', or 'compose') — the database CHECK confines kind to that closed set. The request body intentionally exposes no organization_id, project_id, or environment_id field: the organization is derived from the authenticated principal's home organization, the environment_id comes from the {environment_id} path parameter, and the new service inherits its parent environment's project_id — there is no caller-supplied parameter that could redirect the create at another tenant or another project. Every supplied field is validated before any database work; an invalid request never opens a transaction. The new service row, the provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created service can never exist without its provisioning job or its audit trail, and a duplicate slug within the parent environment rolls the whole transaction back as a deterministic 409. Action service.create is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: service.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. The response carries no credential material — the services table itself stores no secrets; service-scoped variables and other secret-bearing resources live behind their own endpoints (later stories) where the redaction policy applies.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment the new service belongs to.",
				}},
				SuccessDescription: "The service was created.",
			},
			// environmentIDResolver authorizes action service.create against
			// the (principal home organization, {environment_id}) resource
			// the path names, not merely the principal's home organization.
			// The organization id is taken from the principal's home org
			// (never the caller — there is no organization id in the
			// request body), so a cross-tenant environment_id still hits
			// the tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary. The path carries no parent
			// project_id, so the resource scope pins only OrganizationID
			// and EnvironmentID — project-, environment-, and
			// service-scoped grants are denied at the policy boundary by
			// design (the engine's covers() rule), forcing scoped-grant-
			// only principals onto parent-scoped routes. service.create is
			// a CapWrite action and has no cross-tenant support exception
			// — unlike CapRead actions, a support principal cannot create
			// services in another tenant.
			resolver: environmentIDResolver,
			handler:  createEnvironmentServiceHandler(environmentServiceCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}",
				OperationID:    "getService",
				Summary:        "Get a service",
				Description:    "Returns the service named by the {service_id} path parameter, as the source-of-truth database stores it — its id, the id of the organization that owns it, the id of the project it belongs to, the id of the environment it targets, slug, display name, kind taxonomy ('application', 'database', or 'compose'), optimistic-concurrency version, and lifecycle timestamps. Services are the fourth and lowest level of Yalla's Organization -> Project -> Environment -> Service hierarchy the Dokploy provisioning model mirrors. Action service.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped GetByID query, never revealing another tenant's service. The response carries no credential material — the services table itself stores only structural identifiers, a slug, a display name, the kind taxonomy, an optimistic-concurrency version, and lifecycle timestamps; service-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to return.",
				}},
				SuccessDescription: "The requested service.",
			},
			// serviceIDResolver authorizes action service.read against
			// the (principal home organization, {service_id}) resource
			// the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// service_id still hits the tenant-scoped GetByID query and
			// surfaces as a 404 at the persistence boundary. The path
			// carries no parent project_id, so the resource scope pins
			// only OrganizationID and ServiceID — project-, environment-,
			// and service-scoped grants are denied at the policy boundary
			// by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto parent-scoped routes.
			resolver: serviceIDResolver,
			handler:  getServiceHandler(services),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/services/{service_id}",
				OperationID:    "updateService",
				Summary:        "Update a service",
				Description:    "Partially updates the service named by the {service_id} path parameter, as the source-of-truth database stores it. The request body is a partial-update document: both slug and display_name are optional pointers, so omitting a field leaves it unchanged. A patch that names no updatable field is a stable 400 — a mutation that changes nothing is a client error, not a silent success. Every supplied field is validated before any database work; an invalid request never opens a transaction. The desired-state write and an immutable audit record naming the authenticated principal are committed in one transaction — an update can never be persisted without its audit trail, and a duplicate slug within the same environment rolls the whole transaction back as a deterministic 409. Kind is closed Dokploy taxonomy and is not mutable through this endpoint; reparenting onto another project or environment is a separate, deliberate operation behind a different action constant. Action service.update is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition. The response carries no credential material — the services table itself stores no secrets; service-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to update.",
				}},
				SuccessDescription: "The service was updated.",
			},
			// serviceIDResolver authorizes action service.update against
			// the (principal home organization, {service_id}) resource
			// the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id still hits the tenant-scoped repository query
			// and surfaces as a 404 at the persistence boundary. The
			// path carries no parent project_id or environment_id, so
			// the resource scope pins only OrganizationID and
			// ServiceID — project-, environment-, and service-scoped
			// grants are denied at the policy boundary by design (the
			// engine's covers() rule), forcing scoped-grant-only
			// principals onto parent-scoped routes. service.update is
			// a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, a support principal
			// cannot mutate services in another tenant.
			resolver: serviceIDResolver,
			handler:  updateServiceHandler(serviceUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/services/{service_id}",
				OperationID:    "deleteService",
				Summary:        "Schedule a service for deletion",
				Description:    "Schedules the service named by the {service_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the service's deletion_scheduled_at stamp is set and the destructive teardown — the worker job that retires the Dokploy object backing the service and eventually removes the row and its audit log — is carried out by a later worker story, so the service and its audit trail still exist when this returns. Action service.delete is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Scheduling deletion for a service already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction: a scheduled deletion can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceDelete),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to schedule for deletion.",
				}},
				SuccessDescription: "The service was scheduled for deletion.",
			},
			// serviceIDResolver authorizes action service.delete against
			// the (principal home organization, {service_id}) resource
			// the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// service_id still hits the tenant-scoped repository query
			// and surfaces as a 404 at the persistence boundary. The
			// path carries no parent project_id or environment_id, so
			// the resource scope pins only OrganizationID and
			// ServiceID — project-, environment-, and service-scoped
			// grants are denied at the policy boundary by design (the
			// engine's covers() rule), forcing scoped-grant-only
			// principals onto parent-scoped routes. service.delete is
			// a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, a support principal
			// cannot mutate services in another tenant.
			resolver: serviceIDResolver,
			handler:  deleteServiceHandler(serviceDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/restore",
				OperationID:    "restoreService",
				Summary:        "Restore a soft-deleted service",
				Description:    "Restores the service named by the {service_id} path parameter that was previously scheduled for deletion by DELETE /v1/services/{service_id} but has not yet been destructively torn down by the worker. The restore is the inverse of the soft-delete: it clears the service's deletion_scheduled_at stamp in the source-of-truth database so the service is live again, and its audit trail (which the destructive teardown has not yet cascaded away) is recovered intact. Action service.restore is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.restore is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never restoring another tenant's data. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Restoring a service that is not currently scheduled for deletion is a stable 409: the caller's view of the resource lifecycle is stale, so a silent success would write a misleading audit record. The clear-stamp write and an immutable audit record naming the authenticated principal are committed in one transaction: a restore can never be persisted without its audit trail. The request body is empty. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceRestore),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to restore from soft-deletion.",
				}},
				SuccessDescription: "The service was restored from soft-deletion.",
			},
			// serviceIDResolver authorizes action service.restore against
			// the (principal home organization, {service_id}) resource
			// the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// service_id still hits the tenant-scoped repository query
			// and surfaces as a 404 at the persistence boundary. The
			// path carries no parent project_id or environment_id, so
			// the resource scope pins only OrganizationID and
			// ServiceID — project-, environment-, and service-scoped
			// grants are denied at the policy boundary by design (the
			// engine's covers() rule), forcing scoped-grant-only
			// principals onto parent-scoped routes. service.restore is
			// a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, a support principal
			// cannot mutate services in another tenant.
			resolver: serviceIDResolver,
			handler:  restoreServiceHandler(serviceRestorer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/rendered",
				OperationID:    "getServiceRendered",
				Summary:        "Get a service's rendered desired-state preview",
				Description:    "Returns the rendered desired-state PREVIEW for the service named by the {service_id} path parameter — the deterministic projection of how the source-of-truth row reaches the worker (Dokploy resource name, Dokploy service type, and structural identity labels) — so an agent can verify what the control plane will hand to provisioning before any mutation runs. The renderer is the identity layer today: the Dokploy resource name is the canonical Docker-safe '<slug>-<dokploy-id>' deterministic from the row's display_name and id, the service type mirrors the row's closed kind taxonomy ('application', 'database', or 'compose'), and the labels carry only Yalla-canonical hierarchy ids (yalla.organization_id, yalla.project_id, yalla.environment_id, yalla.service_id) the worker stamps onto every provisioned Dokploy object. The merged environment-variable set, build settings, resource limits, and requested domains live in their own per-level tables and are scheduled into later stories; the public projection deliberately carries no values for them today and the 'rendered' block is forward-compatible (only new fields are added later). Action service.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped GetByID query, never revealing another tenant's service. The response carries no credential material — the services table itself stores no secrets, the rendered projection contains only structural identifiers and the deterministic Dokploy resource name derived from the row's display_name and id, and service-scoped variables (rendered values verbatim) live behind their own /variables endpoints where the per-route redaction policy applies; rendered values never appear in this endpoint's payload.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to render.",
				}},
				SuccessDescription: "The rendered desired-state preview of the requested service.",
			},
			// serviceIDResolver authorizes action service.read against
			// the (principal home organization, {service_id}) resource
			// the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// service_id still hits the tenant-scoped GetByID query and
			// surfaces as a 404 at the persistence boundary. The path
			// carries no parent project_id, so the resource scope pins
			// only OrganizationID and ServiceID — project-, environment-,
			// and service-scoped grants are denied at the policy boundary
			// by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto parent-scoped routes.
			resolver: serviceIDResolver,
			handler:  getServiceRenderedHandler(services),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/variables",
				OperationID:    "listServiceVariables",
				Summary:        "List service variables",
				Description:    "Lists the service-scoped environment variables configured for the service named by the {service_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, the id of the organization that owns it, the id of the service it targets, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Service-scoped variables are the highest-precedence (lowest-level) layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here shadows the environment-, project-, and organization-scoped variables of the same key for that service only — a key set here cannot leak into sibling services in the same environment, the same project, or the same tenant. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own service-scoped values. Action env.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: env.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service-scoped variable list. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's service existence check, never disguised as an empty success. A service with no variables is a deterministic empty list.",
				Tags:           []string{tagServices, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose variables to list.",
				}},
				SuccessDescription: "The variables of the service.",
			},
			// serviceIDResolver authorizes action env.read against the
			// (principal home organization, {service_id}) resource the
			// path names, not merely the principal's home organization,
			// so org-wide read roles authorize the read and scoped
			// grants pinning a ProjectID do not (covers() is one-way).
			// The organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant service_id still
			// hits the tenant-scoped repository query and surfaces as a
			// 404 at the persistence boundary.
			resolver: serviceIDResolver,
			handler:  listServiceVariablesHandler(serviceVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/services/{service_id}/variables",
				OperationID:    "replaceServiceVariables",
				Summary:        "Replace service variables",
				Description:    "Replaces the service-scoped variables attached to the service named by the {service_id} path parameter in one transaction. The request body supplies the complete replacement set — every variable absent from the body is removed, every variable present is upserted on (organization_id, service_id, key), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every service-scoped variable\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing variables field, non-POSIX key, duplicate key, oversize value, invalid UTF-8, NUL byte in value) never opens a transaction. Action env.write is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: env.write is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) while denying viewer and support (the latter is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service-scoped variable replace. env.write is a CapWrite action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's variables. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the service existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted variables in the same stable wire shape GET /v1/services/{service_id}/variables returns — every column projected onto the deterministic (key, id) order. Secret values are still redacted on the wire to the sentinel, so PUT cannot leak a secret value the customer just submitted; non-secret values project verbatim.",
				Tags:           []string{tagServices, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose variables to replace.",
				}},
				SuccessDescription: "The variables of the service after the replace.",
			},
			// serviceIDResolver authorizes action env.write against the
			// (principal home organization, {service_id}) resource the path
			// names. The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and ServiceID — project-,
			// environment-, and service-scoped grants are denied at the
			// policy boundary by design (the engine's covers() rule),
			// forcing scoped-grant-only principals onto parent-scoped
			// routes. env.write is a CapWrite action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot replace variables in another tenant.
			// The organization id is taken from the principal's home org
			// (never the caller — there is no organization id in the
			// request body), so a cross-tenant service_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: serviceIDResolver,
			handler:  replaceServiceVariablesHandler(serviceVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/deployments",
				OperationID:    "createServiceDeployment",
				Summary:        "Create a service deployment",
				Description:    "Records customer intent to deploy the service named by the {service_id} path parameter and enqueues the durable provisioning job that mirrors the intent into Dokploy. The request body supplies the closed-set Dokploy-aligned source taxonomy ('git', 'image', or 'manual'), the customer-supplied source reference (a Git branch / commit, an image reference, or an optional manual label), and the per-organization idempotency_key that makes a retried POST structurally idempotent — a second request with the same key returns the previously persisted deployment verbatim, never a duplicate Dokploy provisioning job. The request body intentionally exposes no organization_id, project_id, environment_id, or service_id field: the organization is derived from the authenticated principal's home organization, the service comes from the {service_id} path parameter, and the deployment inherits its parent service's project_id and environment_id from the persisted row — there is no caller-supplied parameter that could redirect the create at another tenant, another project, or another environment. Every supplied field is validated before any database work; an invalid request never opens a transaction. The deployment row, the provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created deployment can never exist without its provisioning job or its audit trail, and a duplicate idempotency_key within the same organization rolls the whole transaction back as the deterministic idempotent return. Action deployment.create is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: deployment.create is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. A service already scheduled for deletion is a deterministic 409 — a deployment cannot land on a service whose teardown is queued. The response carries no credential material — the deployments table itself stores no secrets, the source reference is the customer-supplied value the worker mirrors verbatim into Dokploy, and the error summary the worker writes when a deployment fails is run through the output redactor before persistence so tokens, API keys, and rendered environment variable values can never reach the column.",
				Tags:           []string{tagServices, tagDeployments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDeploymentCreate),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the new deployment targets.",
				}},
				SuccessDescription: "The deployment was accepted and a provisioning job was enqueued.",
			},
			// serviceIDResolver authorizes action deployment.create against
			// the (principal home organization, {service_id}) resource the
			// path names. The path carries no parent project_id, so the
			// resource scope pins only OrganizationID and ServiceID —
			// project-, environment-, and service-scoped grants are denied
			// at the policy boundary by design (the engine's covers() rule),
			// forcing scoped-grant-only principals onto parent-scoped
			// routes. deployment.create is a CapDeploy action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot create deployments in another tenant.
			// The organization id is taken from the principal's home org
			// (never the caller — there is no organization id in the
			// request body), so a cross-tenant service_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: serviceIDResolver,
			handler:  createServiceDeploymentHandler(deploymentCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/jobs",
				OperationID:        "listJobs",
				Summary:            "List provisioning jobs",
				Description:        "Lists durable provisioning jobs owned by the authenticated principal's organization, newest first. Optional project_id, environment_id, service_id, status, and limit query parameters narrow the view; environment filters require project_id and service filters require both project_id and environment_id so scoped grants are evaluated against the same hierarchy the database enforces. The response carries source-of-truth job metadata only: structural resource ids, closed-set status, retry/lease bookkeeping, redacted error_summary, non-secret payload references, and request/correlation ids. Action job.read is a CapRead action evaluated against the organization or supplied resource filter scope before the store is read.",
				Tags:               []string{tagJobs},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionJobRead),
				SuccessDescription: "The provisioning jobs visible at the requested scope.",
			},
			resolver: jobListResolver,
			handler:  listJobsHandler(jobReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/jobs/{job_id}",
				OperationID:    "getJob",
				Summary:        "Get a provisioning job",
				Description:    "Returns the durable provisioning job named by the {job_id} path parameter. The authorization resolver first resolves the job row inside the authenticated principal's tenant and evaluates action job.read against the row's owning scope (organization, project, environment, or service) so scoped grants can read jobs they actually cover while sibling grants are denied before the response handler runs. A cross-tenant or unknown job id reaches the tenant-scoped repository lookup as the principal's home organization and surfaces as a deterministic 404, never another tenant's job. The response carries source-of-truth job metadata only: structural resource ids, closed-set status, retry/lease bookkeeping, redacted error_summary, non-secret payload references, and request/correlation ids.",
				Tags:           []string{tagJobs},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionJobRead),
				PathParams: []openapi.PathParam{{
					Name:        "job_id",
					Description: "The id of the provisioning job to fetch.",
				}},
				SuccessDescription: "The provisioning job visible at the requested scope.",
			},
			resolver: jobIDResolver(jobReader),
			handler:  getJobHandler(jobReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/jobs/{job_id}/retry",
				OperationID:    "retryJob",
				Summary:        "Retry a provisioning job",
				Description:    "Re-issues the failed, cancelled, or dead-lettered provisioning job named by the {job_id} path parameter as a fresh queued job. The authorization resolver first resolves the source job inside the authenticated principal's tenant and evaluates action job.retry against the row's owning scope (organization, project, environment, or service) so scoped deploy grants can retry only jobs they actually cover. The request body carries a caller idempotency_key scoped to this source job plus an optional redacted reason; a retry with the same key returns the same queued retry job rather than duplicating a Dokploy mutation. A cross-tenant or unknown job id reaches the tenant-scoped repository lookup as the principal's home organization and surfaces as a deterministic 404, never another tenant's job. Succeeded, queued, running, and retrying jobs are rejected with a stable conflict because there is no terminal failure to re-issue. The response carries source-of-truth job metadata only: structural resource ids, closed-set status, retry/lease bookkeeping, redacted error_summary, non-secret payload references, and request/correlation ids.",
				Tags:           []string{tagJobs},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionJobRetry),
				PathParams: []openapi.PathParam{{
					Name:        "job_id",
					Description: "The id of the provisioning job to retry.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The queued retry job.",
			},
			resolver: jobIDResolver(jobReader),
			handler:  retryJobHandler(jobRetrier),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/jobs/{job_id}/cancel",
				OperationID:    "cancelJob",
				Summary:        "Cancel a provisioning job",
				Description:    "Cancels the queued, running, or retrying provisioning job named by the {job_id} path parameter. The authorization resolver first resolves the job inside the authenticated principal's tenant and evaluates action job.cancel against the row's owning scope (organization, project, environment, or service) so scoped deploy grants can cancel only jobs they actually cover. The optional request body reason is redacted before persistence. A cross-tenant or unknown job id reaches the tenant-scoped repository lookup as the principal's home organization and surfaces as a deterministic 404, never another tenant's job. Terminal jobs reject cancellation through the provisioning-job state machine. The response carries source-of-truth job metadata only: structural resource ids, closed-set status, retry/lease bookkeeping, redacted error_summary, non-secret payload references, and request/correlation ids.",
				Tags:           []string{tagJobs},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionJobCancel),
				PathParams: []openapi.PathParam{{
					Name:        "job_id",
					Description: "The id of the provisioning job to cancel.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The cancelled provisioning job.",
			},
			resolver: jobIDResolver(jobReader),
			handler:  cancelJobHandler(jobCanceler),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/deployments",
				OperationID:    "listServiceDeployments",
				Summary:        "List service deployments",
				Description:    "Lists every deployment owned by the service named by the {service_id} path parameter, in reverse chronological order (created_at DESC, id DESC as tiebreaker) so an agent observing the response sees a stable ordering across calls and the most recent deployment first. The response carries no credential material — the deployments table itself stores no secrets, the source reference is the customer-supplied value the worker mirrors verbatim into Dokploy, and the worker-written error summary on a failed deployment is run through the output redactor before persistence so tokens, API keys, and rendered environment variable values can never reach the column. Action deployment.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: deployment.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci); the support principal's deliberate cross-tenant read exception does NOT apply here because the resource scope is pinned to the principal's own home organization, not the path service's tenant. The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository's service existence check, never disguised as an empty success — so an agent cannot probe for the existence of another tenant's service through this list. A live service with no deployments is the deterministic empty list every list endpoint returns. The list is bounded by an internal ceiling; an explicit pagination story will add cursor parameters in a later release without changing the wire shape.",
				Tags:           []string{tagServices, tagDeployments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDeploymentRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose deployments to list.",
				}},
				SuccessDescription: "The deployments of the service.",
			},
			// serviceIDResolver authorizes action deployment.read against
			// the (principal home organization, {service_id}) resource the
			// path names. The path carries no parent project_id, so the
			// resource scope pins only OrganizationID and ServiceID —
			// project-, environment-, and service-scoped grants are denied
			// at the policy boundary by design (the engine's covers() rule),
			// forcing scoped-grant-only principals onto parent-scoped
			// routes. deployment.read is a CapRead action, but because the
			// resolver pins the resource to the principal's own home
			// organization, the support principal's cross-tenant read
			// exception does NOT apply — a cross-tenant service_id reaches
			// the tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary, never another tenant's deployments.
			resolver: serviceIDResolver,
			handler:  listServiceDeploymentsHandler(deploymentLister),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/deployments/{deployment_id}",
				OperationID:    "getServiceDeployment",
				Summary:        "Get a service deployment",
				Description:    "Returns the single deployment named by the {deployment_id} path parameter. The response carries the deployment's id, the id of the organization that owns it, the id of the project it belongs to, the id of the environment it targets, the id of the service it deploys, the closed-set source taxonomy ('git', 'image', or 'manual'), the customer-supplied source reference (a branch / commit / image reference — never tokens), the closed-set lifecycle status ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'rolled_back'), the principal who requested the deployment, the per-organization idempotency key, the optimistic-concurrency version, the request and correlation identifiers the audit trail and the worker job share, and the lifecycle timestamps (created_at, updated_at, and the omitempty started_at / finished_at the worker writes as the deployment converges). The worker-written error_code and error_message fields on a failed deployment are run through the output redactor before persistence so tokens, API keys, and rendered environment variable values can never reach the column; the wire shape projects them verbatim. The response carries no credential material — the deployments table itself stores no secrets, the source reference is the customer-supplied value the worker mirrors verbatim into Dokploy, and the error summary is already redacted at the persistence boundary. Action deployment.read is authorized against the (principal home organization) Deployment resource before the handler runs: deployment.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci); the support principal's deliberate cross-tenant read exception does NOT apply here because deploymentIDResolver pins the resource scope to the principal's own home organization, not the path deployment's tenant. The bare path carries only the deployment_id (the policy.Scope hierarchy stops at ServiceID, so the deployment_id itself is not a scope leg), so project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route family to address a deployment by its (project, environment, service, deployment) tuple. A cross-tenant or unknown deployment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never disguised as a 200 with another tenant's data and never as a 403 that would confirm existence.",
				Tags:           []string{tagDeployments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDeploymentRead),
				PathParams: []openapi.PathParam{{
					Name:        "deployment_id",
					Description: "The id of the deployment to fetch.",
				}},
				SuccessDescription: "The deployment row owned by the principal's home organization.",
			},
			// deploymentIDResolver authorizes action deployment.read
			// against the (principal home organization) Deployment
			// resource. The policy.Scope hierarchy stops at ServiceID,
			// so the deployment_id from the path is NOT a scope leg;
			// the resolver pins only OrganizationID, and the engine's
			// covers() rule denies every project-, environment-, and
			// service-scoped grant at the boundary (the grant pins a
			// leg the resource leaves empty) — forcing scoped-grant-only
			// principals onto a parent-scoped route. deployment.read is
			// a CapRead action, but because the resolver pins the
			// resource to the principal's own home organization, the
			// support principal's cross-tenant read exception does NOT
			// apply — a cross-tenant deployment_id reaches the
			// tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary, never another tenant's
			// deployment.
			resolver: deploymentIDResolver,
			handler:  getServiceDeploymentHandler(deploymentGetter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/deployments/{deployment_id}/cancel",
				OperationID:    "cancelServiceDeployment",
				Summary:        "Cancel a service deployment",
				Description:    "Transitions the deployment named by the {deployment_id} path parameter from a non-terminal lifecycle status ('queued' or 'running') to the terminal 'cancelled' status, stamping finished_at in the same UPDATE so the database lifecycle-consistency CHECK remains satisfied. The cancellation is durable: the desired-state row update and an immutable audit record naming the authenticated principal are committed in one transaction, so a cancelled deployment can never exist without its audit trail. The worker observes the cancelled status to stop any in-flight Dokploy provisioning in a later worker story; the cancellation through this endpoint is the customer's authoritative intent, recorded against the source-of-truth row. Action deployment.cancel is authorized against the (principal home organization) Deployment resource before the handler runs: deployment.cancel is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The bare path carries only the deployment_id (the policy.Scope hierarchy stops at ServiceID, so the deployment_id itself is not a scope leg), so project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route family to address a deployment by its (project, environment, service, deployment) tuple. A cross-tenant or unknown deployment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never disguised as a 200 with another tenant's data and never as a 403 that would confirm existence. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. A deployment already in a terminal lifecycle status (succeeded, failed, cancelled, or rolled_back) is rejected as a deterministic 409 — never a silent success that would emit a duplicate audit event for an already-cancelled row. The request body is empty. The response carries no credential material — the deployments table itself stores no secrets, the source reference is the customer-supplied value the worker mirrors verbatim into Dokploy, and the worker-written error_message on a failed deployment is run through the output redactor before persistence so tokens, API keys, and rendered environment variable values can never reach the column. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition without re-reading the row.",
				Tags:           []string{tagDeployments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDeploymentCancel),
				PathParams: []openapi.PathParam{{
					Name:        "deployment_id",
					Description: "The id of the deployment to cancel.",
				}},
				SuccessDescription: "The deployment row with its lifecycle status transitioned to 'cancelled'.",
			},
			// deploymentIDResolver authorizes action deployment.cancel
			// against the (principal home organization) Deployment
			// resource. The policy.Scope hierarchy stops at ServiceID,
			// so the deployment_id from the path is NOT a scope leg;
			// the resolver pins only OrganizationID, and the engine's
			// covers() rule denies every project-, environment-, and
			// service-scoped grant at the boundary (the grant pins a
			// leg the resource leaves empty) — forcing scoped-grant-
			// only principals onto a parent-scoped route.
			// deployment.cancel is a CapDeploy action, so there is no
			// cross-tenant support exception — a support principal
			// cannot cancel another tenant's deployment, and even
			// same-tenant support is denied (CapRead-only, never
			// CapDeploy). A cross-tenant deployment_id reaches the
			// tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary, never another tenant's
			// deployment.
			resolver: deploymentIDResolver,
			handler:  cancelServiceDeploymentHandler(deploymentCanceler),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/rollback",
				OperationID:    "rollbackServiceDeployment",
				Summary:        "Roll back a service to a previous deployment",
				Description:    "Records customer intent to roll the service named by the {service_id} path parameter back to a previously persisted terminal-succeeded deployment, and enqueues the durable provisioning job that mirrors the rollback into Dokploy. The request body supplies the target_deployment_id (the previously persisted deployment whose source / source_ref the new rollback deployment will copy verbatim — the target MUST belong to the same (organization, service) as the path service) and the per-organization idempotency_key that makes a retried POST structurally idempotent — a second request with the same key returns the previously persisted rollback deployment verbatim, never a duplicate Dokploy provisioning job. The request body intentionally exposes no organization_id, project_id, environment_id, or service_id field: the organization is derived from the authenticated principal's home organization, the service comes from the {service_id} path parameter, and the new deployment inherits its parent service's project_id and environment_id from the persisted row — there is no caller-supplied parameter that could redirect the rollback at another tenant, another project, or another environment. Every supplied field is validated before any database work; an invalid request never opens a transaction. The new deployment row, the provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal (Action 'deployment.rollback', Metadata carrying target_deployment_id so an auditor can trace which deployment was rolled back to) are committed in one transaction — a rolled-back deployment can never exist without its provisioning job or its audit trail, and a duplicate idempotency_key within the same organization rolls the whole transaction back as the deterministic idempotent return. Action deployment.rollback is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: deployment.rollback is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. A target_deployment_id that belongs to ANOTHER tenant — or to a different service in the same tenant — is also reported as 404, never disguised as a 200 that would let a caller probe for cross-service deployment ids through this endpoint. A target in any non-succeeded lifecycle state ('queued', 'running', 'failed', 'cancelled', or 'rolled_back') is rejected as a deterministic 409 — a rollback target must be a known-good deployment. A service already scheduled for deletion is a deterministic 409 — a rollback cannot land on a service whose teardown is queued. The response carries no credential material — the deployments table itself stores no secrets, the source / source_ref are copied verbatim from the persisted target deployment (already redacted at its own create time), and the worker-written error_message on a failed deployment is run through the output redactor before persistence so tokens, API keys, and rendered environment variable values can never reach the column.",
				Tags:           []string{tagServices, tagDeployments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDeploymentRollback),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to roll back.",
				}},
				SuccessDescription: "The rollback deployment was accepted and a provisioning job was enqueued.",
			},
			// serviceIDResolver authorizes action deployment.rollback
			// against the (principal home organization, {service_id})
			// resource the path names. The path carries no parent
			// project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-,
			// and service-scoped grants are denied at the policy
			// boundary by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto parent-scoped routes.
			// deployment.rollback is a CapDeploy action and has no
			// cross-tenant support exception — unlike CapRead actions,
			// the support principal cannot roll back deployments in
			// another tenant. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence
			// boundary. A target_deployment_id that belongs to
			// another tenant or to a different service in the same
			// tenant is also reported as 404 — never disguised as a
			// 200 that would let a caller probe for cross-service
			// deployment ids through this endpoint.
			resolver: serviceIDResolver,
			handler:  rollbackServiceDeploymentHandler(deploymentRollbacker),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/restart",
				OperationID:    "restartService",
				Summary:        "Restart a service",
				Description:    "Records customer intent to restart the service named by the {service_id} path parameter and enqueues the durable provisioning job that mirrors the restart into Dokploy. The restart targets the entire service: the worker re-launches its containers against the already-persisted desired state — the service row's source, source_ref, and rendered environment do not change. The request body is empty: restart is a fire-and-forget signal that carries no caller-supplied parameters. Action service.restart is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.restart is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. A service already scheduled for deletion is a deterministic 409 — a restart cannot land on a service whose teardown is queued. The provisioning job that mirrors the restart into Dokploy and an immutable audit record naming the authenticated principal (Action 'service.restart', Metadata carrying service_id / project_id / environment_id) commit in one transaction — a restart audit record can never exist without its provisioning job. The response carries no credential material — the services table itself stores no secrets, and service-scoped variables live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceRestart),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to restart.",
				}},
				SuccessDescription: "The restart was accepted and a provisioning job was enqueued.",
			},
			// serviceIDResolver authorizes action service.restart
			// against the (principal home organization, {service_id})
			// resource the path names. The path carries no parent
			// project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-,
			// and service-scoped grants are denied at the policy
			// boundary by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto parent-scoped routes.
			// service.restart is a CapDeploy action and has no
			// cross-tenant support exception — unlike CapRead actions,
			// the support principal cannot restart services in another
			// tenant. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  restartServiceHandler(serviceRestarter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/start",
				OperationID:    "startService",
				Summary:        "Start a service",
				Description:    "Records customer intent to start the service named by the {service_id} path parameter and enqueues the durable provisioning job that mirrors the start into Dokploy. The start targets the entire service: the worker brings the already-persisted desired state back up — the service row's source, source_ref, and rendered environment do not change. The request body is empty: start is a fire-and-forget signal that carries no caller-supplied parameters. Action service.start is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.start is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. A service already scheduled for deletion is a deterministic 409 — a start cannot land on a service whose teardown is queued. The provisioning job that mirrors the start into Dokploy and an immutable audit record naming the authenticated principal (Action 'service.start', Metadata carrying service_id / project_id / environment_id) commit in one transaction — a start audit record can never exist without its provisioning job. The response carries no credential material — the services table itself stores no secrets, and service-scoped variables live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceStart),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to start.",
				}},
				SuccessDescription: "The start was accepted and a provisioning job was enqueued.",
			},
			// serviceIDResolver authorizes action service.start against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. service.start is a CapDeploy action
			// and has no cross-tenant support exception — unlike CapRead
			// actions, the support principal cannot start services in
			// another tenant. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id still hits the tenant-scoped repository query
			// and surfaces as a 404 at the persistence boundary.
			resolver: serviceIDResolver,
			handler:  startServiceHandler(serviceStarter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/stop",
				OperationID:    "stopService",
				Summary:        "Stop a service",
				Description:    "Records customer intent to stop the service named by the {service_id} path parameter and enqueues the durable provisioning job that mirrors the stop into Dokploy. The stop targets the entire service: the worker halts its containers against the already-persisted desired state — the service row's source, source_ref, and rendered environment do not change, and a subsequent start brings the same desired state back up. The request body is empty: stop is a fire-and-forget signal that carries no caller-supplied parameters. Action service.stop is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: service.stop is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. A service already scheduled for deletion is a deterministic 409 — a stop cannot land on a service whose teardown is queued. The provisioning job that mirrors the stop into Dokploy and an immutable audit record naming the authenticated principal (Action 'service.stop', Metadata carrying service_id / project_id / environment_id) commit in one transaction — a stop audit record can never exist without its provisioning job. The response carries no credential material — the services table itself stores no secrets, and service-scoped variables live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionServiceStop),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service to stop.",
				}},
				SuccessDescription: "The stop was accepted and a provisioning job was enqueued.",
			},
			// serviceIDResolver authorizes action service.stop against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. service.stop is a CapDeploy action
			// and has no cross-tenant support exception — unlike CapRead
			// actions, the support principal cannot stop services in
			// another tenant. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id still hits the tenant-scoped repository query
			// and surfaces as a 404 at the persistence boundary.
			resolver: serviceIDResolver,
			handler:  stopServiceHandler(serviceStopper),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/logs",
				OperationID:    "listServiceLogs",
				Summary:        "Read service logs",
				Description:    "Returns the most recent log lines for the service named by the {service_id} path parameter. The response is a bounded list (an optional ?limit= query parameter clamps the page in the range [1, 1000]; an absent value defaults to 100) — every line carries an occurred_at RFC3339 timestamp, the stream name from the closed set {stdout, stderr, system}, and the literal byte message the worker emitted. Action logs.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant log reads remain available through endpoints whose path carries an explicit {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped existence check, never revealing another tenant's service. A malformed, non-positive, or larger-than-ceiling limit is rejected as a stable 400 E_VALIDATION before any database work runs. The response carries no credential material — the placeholder reader never produces content from secret-bearing tables, and the eventual Dokploy log adapter is responsible for rendering-environment redaction at its layer; an empty lines slice marshals as [] (never null) so an agent does not need to special-case the absent-vs-empty distinction.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLogsRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose logs to return.",
				}},
				SuccessDescription: "The most recent log lines for the service.",
			},
			// serviceIDResolver authorizes action logs.read against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. logs.read is a CapRead action;
			// however, the resolver pins the resource to the
			// principal's home org (not the path service's tenant), so
			// the support cross-tenant read exception does not apply
			// through this endpoint by construction. The organization
			// id is taken from the principal's home org, so a
			// cross-tenant service_id still hits the tenant-scoped
			// existence check and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  listServiceLogsHandler(serviceLogReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/metrics",
				OperationID:    "listServiceMetrics",
				Summary:        "Read service metrics",
				Description:    "Returns the most recent metric samples for the service named by the {service_id} path parameter. The response is a bounded list (an optional ?limit= query parameter clamps the page in the range [1, 1000]; an absent value defaults to 100) — every sample carries a stable metric name (drawn from the usage-metric ladder: http_requests, http_response_bytes, http_request_bytes, http_rps_peak_1m, latency_p95_ms, container_cpu_millicore_seconds, container_memory_mb_hours, storage_gb_month, build_minutes, and so on), an occurred_at RFC3339 timestamp, a numeric value, and a unit-of-measure string. This endpoint is operational, not billing-grade: the authoritative usage counters for billing live in usage_counters and the reconciliation worker; this surface is a customer-visible read-through of recently observed samples and never doubles as the billing oracle. Action metrics.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant metric reads remain available through endpoints whose path carries an explicit {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped existence check, never revealing another tenant's service. A malformed, non-positive, or larger-than-ceiling limit is rejected as a stable 400 E_VALIDATION before any database work runs. The response carries no credential material — the placeholder reader never produces content from secret-bearing tables, and the eventual Traefik/Dokploy metrics adapter is responsible for label attribution at its layer; an empty samples slice marshals as [] (never null) so an agent does not need to special-case the absent-vs-empty distinction.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMetricsRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose metrics to return.",
				}},
				SuccessDescription: "The most recent metric samples for the service.",
			},
			// serviceIDResolver authorizes action metrics.read against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. metrics.read is a CapRead action;
			// however, the resolver pins the resource to the
			// principal's home org (not the path service's tenant), so
			// the support cross-tenant read exception does not apply
			// through this endpoint by construction. The organization
			// id is taken from the principal's home org, so a
			// cross-tenant service_id still hits the tenant-scoped
			// existence check and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  listServiceMetricsHandler(serviceMetricsReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/domains",
				OperationID:    "listServiceDomains",
				Summary:        "List service domains",
				Description:    "Lists the public-facing domain rows bound to the service named by the {service_id} path parameter — every entry carries a stable id, the hostname / path / port routing tuple, the https flag, and the certificate_type (lets-encrypt, custom, none) so an agent can branch without re-fetching. The response carries no credential material: the certificate_type column names the issuance behavior only, and the actual certificate material is held by the worker / Dokploy layer and never round-tripped through this endpoint. Action domain.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant domain reads remain available through endpoints whose path carries an explicit {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped existence check, never revealing another tenant's service. An empty domains slice marshals as [] (never null) so an agent does not need to special-case the absent-vs-empty distinction.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDomainRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose domains to return.",
				}},
				SuccessDescription: "The domain rows bound to the service.",
			},
			// serviceIDResolver authorizes action domain.read against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. domain.read is a CapRead action;
			// however, the resolver pins the resource to the
			// principal's home org (not the path service's tenant), so
			// the support cross-tenant read exception does not apply
			// through this endpoint by construction. The organization
			// id is taken from the principal's home org, so a
			// cross-tenant service_id still hits the tenant-scoped
			// existence check and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  listServiceDomainsHandler(serviceDomainReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/domains",
				OperationID:    "createServiceDomain",
				Summary:        "Create a service domain",
				Description:    "Creates a public-facing domain row bound to the service named by the {service_id} path parameter. The request body carries the caller-supplied domain id (an idempotent retry under the (hostname, path) uniqueness constraint), the (hostname, path) routing tuple, the inbound port, the https flag, and the certificate_type (\"lets-encrypt\", \"custom\", or \"none\") that drives TLS issuance behavior in the worker — the actual certificate material is held by the worker / Dokploy layer and never round-tripped through this endpoint. The request body intentionally exposes no organization_id, project_id, environment_id, or service_id field: the organization is derived from the authenticated principal's home organization, the service comes from the {service_id} path parameter, and the new domain inherits its parent service's transitive parents from the persisted services row — there is no caller-supplied parameter that could redirect the create at another tenant. Every supplied field is validated before any database work; an invalid request never opens a transaction. The domain row and an immutable audit record naming the authenticated principal are committed in one transaction — a created domain can never exist without its audit trail, and a duplicate (hostname, path) tuple anywhere in the cluster is rejected at the database UNIQUE constraint as a typed apierr.Conflict whose customer-facing message never echoes the submitted value. Action domain.create is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: domain.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDomainCreate),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the new domain is bound to.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The persisted service domain.",
			},
			// serviceIDResolver authorizes action domain.create against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. domain.create is a CapWrite action,
			// so the support cross-tenant exception (CapRead + CapSupport
			// only) does not apply through this endpoint by construction.
			// The organization id is taken from the principal's home
			// org, so a cross-tenant service_id still hits the tenant-
			// scoped existence check and surfaces as a 404 at the
			// persistence boundary.
			resolver: serviceIDResolver,
			handler:  createServiceDomainHandler(serviceDomainCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/services/{service_id}/domains/{domain_id}",
				OperationID:    "updateServiceDomain",
				Summary:        "Update a service domain",
				Description:    "Partially updates the public-facing domain row identified by the {domain_id} path parameter under the service named by the {service_id} path parameter. The request body is a partial-update document — hostname, path, port, https, and certificate_type are optional pointers, so omitting a field leaves it unchanged. A patch that names no updatable field is a stable 400 — a mutation that changes nothing is a client error, not a silent success. Every supplied field is validated before any database work; an invalid request never opens a transaction. The desired-state write and an immutable audit record naming the authenticated principal are committed in one transaction — an update can never be persisted without its audit trail, and a (hostname, path) collision anywhere in the cluster rolls the whole transaction back as a deterministic 409. Reparenting onto another service is intentionally not exposed through this endpoint: a service domain belongs to exactly one service for its lifetime. Action domain.update is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: domain.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead + CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id or domain_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's row. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition. The response carries no credential material — the service_domains table itself stores no secrets; the certificate_type column names the issuance behavior only (the actual certificate material is held by the worker / Dokploy layer and never round-trips through this endpoint).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDomainUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the domain is bound to.",
				}, {
					Name:        "domain_id",
					Description: "The id of the service domain to update.",
				}},
				SuccessDescription: "The persisted service domain after the update.",
			},
			// serviceIDResolver authorizes action domain.update against
			// the (principal home organization, {service_id}) resource
			// the path names — the {domain_id} path parameter does not
			// widen the policy scope, the parent service is the
			// authoritative authorization target. The path carries no
			// parent project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-, and
			// service-scoped grants are denied at the policy boundary by
			// design (the engine's covers() rule), forcing scoped-grant-
			// only principals onto parent-scoped routes. domain.update is
			// a CapWrite action, so the support cross-tenant exception
			// (CapRead + CapSupport only) does not apply through this
			// endpoint by construction. The organization id is taken
			// from the principal's home org, so a cross-tenant
			// service_id or domain_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  updateServiceDomainHandler(serviceDomainUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/services/{service_id}/domains/{domain_id}",
				OperationID:    "deleteServiceDomain",
				Summary:        "Delete a service domain",
				Description:    "Removes the public-facing domain row identified by the {domain_id} path parameter under the service named by the {service_id} path parameter. The DELETE has no request body. The row is removed outright — service domains have no soft-delete column because a public-facing hostname route is a routing artefact, not a continuing audit-trail tie that must outlive the resource; an audit trail of the deletion lives independently of the row. The desired-state delete and an immutable audit record naming the authenticated principal are committed in one transaction — a delete can never be persisted without its audit trail. Action domain.delete is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: domain.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead + CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id or domain_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's row. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response carries the deleted domain row as a snapshot so the caller can confirm what was destroyed; it carries no credential material — the service_domains table itself stores no secrets; the certificate_type column names the issuance behavior only (the actual certificate material is held by the worker / Dokploy layer and never round-trips through this endpoint).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionDomainDelete),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the domain is bound to.",
				}, {
					Name:        "domain_id",
					Description: "The id of the service domain to delete.",
				}},
				SuccessDescription: "The deleted service domain snapshot.",
			},
			// serviceIDResolver authorizes action domain.delete against
			// the (principal home organization, {service_id}) resource
			// the path names — the {domain_id} path parameter does not
			// widen the policy scope, the parent service is the
			// authoritative authorization target. The path carries no
			// parent project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-, and
			// service-scoped grants are denied at the policy boundary by
			// design (the engine's covers() rule), forcing scoped-grant-
			// only principals onto parent-scoped routes. domain.delete is
			// a CapWrite action, so the support cross-tenant exception
			// (CapRead + CapSupport only) does not apply through this
			// endpoint by construction. The organization id is taken
			// from the principal's home org, so a cross-tenant
			// service_id or domain_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  deleteServiceDomainHandler(serviceDomainDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/services/{service_id}/backups",
				OperationID:    "listServiceBackups",
				Summary:        "List service backups",
				Description:    "Lists the backup-policy rows bound to the service named by the {service_id} path parameter — every entry carries a stable id, the display_name, the cron-style schedule, the retention_count, the enabled flag, the closed-set status ('disabled', 'pending', 'running', 'succeeded', 'failed'), and the optional last_run_at / last_succeeded_at the worker projects onto the row as it drives Dokploy backups. The response carries no credential material: the schedule column is a cron-style expression, and the backup artefact bytes themselves never round-trip through this endpoint (they live in the worker / Dokploy / object-storage layer). Action backup.read is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path service's tenant; support cross-tenant backup reads remain available through endpoints whose path carries an explicit {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped existence check, never revealing another tenant's service. An empty backups slice marshals as [] (never null) so an agent does not need to special-case the absent-vs-empty distinction.",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionBackupRead),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service whose backup policies to return.",
				}},
				SuccessDescription: "The backup-policy rows bound to the service.",
			},
			// serviceIDResolver authorizes action backup.read against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. backup.read is a CapRead action;
			// however, the resolver pins the resource to the
			// principal's home org (not the path service's tenant), so
			// the support cross-tenant read exception does not apply
			// through this endpoint by construction. The organization
			// id is taken from the principal's home org, so a
			// cross-tenant service_id still hits the tenant-scoped
			// existence check and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  listServiceBackupsHandler(serviceBackupReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/backups",
				OperationID:    "createServiceBackup",
				Summary:        "Create a service backup",
				Description:    "Creates a backup-policy row bound to the service named by the {service_id} path parameter. The request body carries the caller-supplied backup id (an idempotent retry under the primary-key uniqueness constraint), the human-authored display_name, the cron-style schedule the worker interprets when it next plans a run, the retention_count bounding how many succeeded runs the worker retains before pruning the oldest, and the enabled flag (defaulting to true) toggling whether the worker takes any action on the row. The request body intentionally exposes no organization_id, project_id, environment_id, or service_id field: the organization is derived from the authenticated principal's home organization, the service comes from the {service_id} path parameter, and the new backup row inherits its parent service's transitive parents from the persisted services row — there is no caller-supplied parameter that could redirect the create at another tenant. Every supplied field is validated before any database work; an invalid request never opens a transaction. The backup row lands with status='pending' (the customer-facing create never sets the closed-set status — the worker is the authority for transitions between 'running' and {'succeeded', 'failed'}). The backup row and an immutable audit record naming the authenticated principal are committed in one transaction — a created backup can never exist without its audit trail, and a duplicate backup id is rejected at the database PRIMARY KEY as a typed apierr.Conflict whose customer-facing message never echoes the submitted id. Action backup.create is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: backup.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's service. The response carries no credential material: the schedule column is a cron-style expression, and the backup artefact bytes themselves never round-trip through this endpoint (they live in the worker / Dokploy / object-storage layer).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionBackupCreate),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the new backup is bound to.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The persisted service backup.",
			},
			// serviceIDResolver authorizes action backup.create against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. backup.create is a CapWrite action,
			// so the support cross-tenant exception (CapRead + CapSupport
			// only) does not apply through this endpoint by construction.
			// The organization id is taken from the principal's home
			// org, so a cross-tenant service_id still hits the tenant-
			// scoped existence check and surfaces as a 404 at the
			// persistence boundary.
			resolver: serviceIDResolver,
			handler:  createServiceBackupHandler(serviceBackupCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/services/{service_id}/backups/{backup_id}",
				OperationID:    "updateServiceBackup",
				Summary:        "Update a service backup",
				Description:    "Partially updates the backup-policy row identified by the {backup_id} path parameter under the service named by the {service_id} path parameter. The request body is a partial-update document — display_name, schedule, retention_count, and enabled are optional pointers, so omitting a field leaves it unchanged. A patch that names no updatable field is a stable 400 — a mutation that changes nothing is a client error, not a silent success. The mutable surface is intentionally narrow: status is NOT exposed through this endpoint — the worker is the authority for transitions between 'running' and {'succeeded', 'failed'}, and the customer toggle for 'stop running this policy' is the enabled flag, not the status enum. Every supplied field is validated before any database work; an invalid request never opens a transaction. The desired-state write and an immutable audit record naming the authenticated principal are committed in one transaction — an update can never be persisted without its audit trail. Reparenting onto another service is intentionally not exposed through this endpoint: a backup policy belongs to exactly one service for its lifetime. Action backup.update is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: backup.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead + CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id or backup_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's row. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition. The response carries no credential material: the schedule column is a cron-style expression, and the backup artefact bytes themselves never round-trip through this endpoint (they live in the worker / Dokploy / object-storage layer).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionBackupUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the backup policy belongs to.",
				}, {
					Name:        "backup_id",
					Description: "The id of the backup policy to update.",
				}},
				SuccessDescription: "The persisted service backup after the update.",
			},
			// serviceIDResolver authorizes action backup.update against
			// the (principal home organization, {service_id}) resource
			// the path names — the {backup_id} path parameter does not
			// widen the policy scope, the parent service is the
			// authoritative authorization target. The path carries no
			// parent project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-, and
			// service-scoped grants are denied at the policy boundary by
			// design (the engine's covers() rule), forcing scoped-grant-
			// only principals onto parent-scoped routes. backup.update
			// is a CapWrite action, so the support cross-tenant exception
			// (CapRead + CapSupport only) does not apply through this
			// endpoint by construction. The organization id is taken
			// from the principal's home org, so a cross-tenant
			// service_id or backup_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  updateServiceBackupHandler(serviceBackupUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/services/{service_id}/backups/{backup_id}/run",
				OperationID:    "runServiceBackup",
				Summary:        "Run a service backup",
				Description:    "Records customer intent to trigger a manual run of the backup-policy row named by ({service_id}, {backup_id}) and flips the row's status to 'pending' so the worker picks it up on its next scheduling pass. The request body is empty: backup.run is a fire-and-forget signal that targets a single backup-policy row and carries no caller-supplied parameters. Action backup.run is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: backup.run is a CapDeploy action, so the gate admits the principal's organization-wide deploy roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead+CapSupport — support is a deliberate cross-tenant READ exception, never a deploy one). The path carries no parent project_id or environment_id, so the policy engine cannot pin those legs of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id or backup_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository queries, never revealing another tenant's service or backup. A backup whose enabled flag is false is a deterministic 409 — a disabled policy cannot be manually run; the customer must PATCH the row to enabled=true first. A backup whose status is already 'running' is likewise a deterministic 409 — a concurrent run would double-enqueue work the worker has already accepted. The status flip and an immutable audit record naming the authenticated principal (Action 'backup.run', Metadata carrying service_id / status_before / status_after) commit in one transaction — a run audit record can never exist without the desired-state flip. The response carries no credential material: the schedule column is a cron-style expression, and the backup artefact bytes themselves never round-trip through this endpoint (they live in the worker / Dokploy / object-storage layer).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionBackupRun),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{
					{
						Name:        "service_id",
						Description: "The id of the service the backup policy belongs to.",
					},
					{
						Name:        "backup_id",
						Description: "The id of the backup policy to run.",
					},
				},
				SuccessDescription: "The manual run was accepted and the backup row was flipped to pending.",
			},
			// serviceIDResolver authorizes action backup.run against
			// the (principal home organization, {service_id}) resource
			// the path names. The path carries no parent project_id, so
			// the resource scope pins only OrganizationID and ServiceID
			// — project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. backup.run is a CapDeploy action
			// and has no cross-tenant support exception — unlike CapRead
			// actions, the support principal cannot trigger backups in
			// another tenant. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// service_id or backup_id still hits the tenant-scoped
			// repository queries and surfaces as a 404 at the
			// persistence boundary.
			resolver: serviceIDResolver,
			handler:  runServiceBackupHandler(serviceBackupRunner),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/services/{service_id}/backups/{backup_id}",
				OperationID:    "deleteServiceBackup",
				Summary:        "Delete a service backup",
				Description:    "Removes the backup-policy row identified by the {backup_id} path parameter under the service named by the {service_id} path parameter. The DELETE has no request body. The row is removed outright — service backups have no soft-delete column because a backup-policy row is desired-state configuration, not a continuing audit-trail tie that must outlive the resource; an audit trail of the deletion lives independently of the row. The desired-state delete and an immutable audit record naming the authenticated principal are committed in one transaction — a delete can never be persisted without its audit trail. Action backup.delete is authorized against the (principal home organization, {service_id}) resource the path names before the handler runs: backup.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer (CapRead only), denies support (CapRead + CapSupport — support is a deliberate cross-tenant READ exception, never a write one). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address a service by its (project, environment, service) tuple. A cross-tenant or unknown service_id or backup_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's row. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response carries the deleted backup row as a snapshot so the caller can confirm what was destroyed; it carries no credential material — the service_backups table itself stores no secrets (the actual backup artefact bytes live in the worker / Dokploy / object-storage layer and never round-trip through this endpoint).",
				Tags:           []string{tagServices},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionBackupDelete),
				PathParams: []openapi.PathParam{{
					Name:        "service_id",
					Description: "The id of the service the backup policy belongs to.",
				}, {
					Name:        "backup_id",
					Description: "The id of the backup policy to delete.",
				}},
				SuccessDescription: "The deleted service backup snapshot.",
			},
			// serviceIDResolver authorizes action backup.delete against
			// the (principal home organization, {service_id}) resource
			// the path names — the {backup_id} path parameter does not
			// widen the policy scope, the parent service is the
			// authoritative authorization target. The path carries no
			// parent project_id, so the resource scope pins only
			// OrganizationID and ServiceID — project-, environment-, and
			// service-scoped grants are denied at the policy boundary by
			// design (the engine's covers() rule), forcing scoped-grant-
			// only principals onto parent-scoped routes. backup.delete is
			// a CapWrite action, so the support cross-tenant exception
			// (CapRead + CapSupport only) does not apply through this
			// endpoint by construction. The organization id is taken
			// from the principal's home org, so a cross-tenant
			// service_id or backup_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary.
			resolver: serviceIDResolver,
			handler:  deleteServiceBackupHandler(serviceBackupDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/admin/organizations/{org_id}/dokploy-refs",
				OperationID:    "listAdminOrganizationDokployRefs",
				Summary:        "List organization Dokploy refs",
				Description:    "Lists the tenant-scoped Yalla-to-Dokploy mapping rows for the organization named by the {org_id} path parameter. Action support.manage is required before any mapping row is read; support principals may target another organization through the policy engine's CapSupport cross-tenant exception, while non-support principals are denied before the handler reaches persistence. The store-backed reader verifies the target organization exists, so an unknown organization is a deterministic 404 rather than an empty mapping list.",
				Tags:           []string{tagAdmin},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAdminRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose Dokploy refs are listed.",
				}},
				SuccessDescription: "The organization's Dokploy mapping refs.",
			},
			resolver: organizationIDResolver,
			handler:  listAdminDokployRefsHandler(dokployRefs),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/admin/dokploy/drift",
				OperationID:        "listAdminDokployDrift",
				Summary:            "List Dokploy drift findings",
				Description:        "Lists persisted Dokploy drift findings for the organization named by the optional organization_id query parameter, defaulting to the authenticated principal's home organization. Optional project_id, environment_id, service_id, status, and limit filters narrow the tenant-scoped result. Action support.manage is required before any drift rows are read; support principals may target another organization through the policy engine's CapSupport cross-tenant exception, while non-support principals are denied before the handler reaches persistence.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAdminReconcile),
				SuccessDescription: "The matching drift findings, newest first.",
			},
			resolver: adminDokployDriftResolver,
			handler:  listAdminDokployDriftHandler(driftFindings),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/dokploy/reconcile",
				OperationID:        "reconcileAdminDokploy",
				Summary:            "Run Dokploy reconciliation",
				Description:        "Runs the support-only reconciliation workflow for the organization named by the optional organization_id query parameter, defaulting to the authenticated principal's home organization. The JSON body may repeat organization_id for typed clients and may set dry_run. Cross-tenant reconciliation must name the target organization in the query parameter so action support.manage is authorized against the real tenant before any reconcile work runs.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAdminReconcile),
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The reconciliation run summary.",
			},
			resolver: adminDokployDriftResolver,
			handler:  reconcileAdminDokployHandler(adminDokployReconciler),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/dokploy/import",
				OperationID:        "importAdminDokploy",
				Summary:            "Import Dokploy resources",
				Description:        "Queues the support-only Dokploy import workflow for the organization named by the optional organization_id query parameter, defaulting to the authenticated principal's home organization. The JSON body supplies the Dokploy organization id, an explicit Yalla owner binding, and a per-organization idempotency_key for the durable import job. Cross-tenant import must name the target organization in the query parameter so action support.manage is authorized against the real tenant before any job or audit row is written.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAdminImport),
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The queued import job and target binding.",
			},
			resolver: adminDokployDriftResolver,
			handler:  importAdminDokployHandler(adminDokployImporter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/admin/break-glass",
				OperationID:        "startAdminBreakGlassSession",
				Summary:            "Start an admin break-glass session",
				Description:        "Starts a time-bounded internal-support break-glass session targeting the organization named by the optional organization_id query parameter, defaulting to the authenticated principal's home organization. The JSON body must carry a non-empty reason and positive ttl_seconds, and may repeat organization_id when it matches the query target. Cross-tenant break-glass must name organization_id in the query string so action support.manage is authorized against the real target before the handler decodes or writes data. The persisted session row and immutable elevated-access audit event are committed together by the store unit of work.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAdminBreakGlass),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The persisted break-glass session.",
			},
			resolver: adminBreakGlassResolver,
			handler:  startAdminBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodDelete,
				Path:               "/v1/admin/break-glass/{session_id}",
				OperationID:        "revokeAdminBreakGlassSession",
				Summary:            "Revoke an admin break-glass session",
				Description:        "Ends an active internal-support break-glass session selected by {session_id}. The target organization is named by the optional organization_id query parameter, defaulting to the authenticated principal's home organization; cross-tenant revocation must name organization_id in the query string so action support.manage is authorized against the real target before the handler mutates data. The store-layer unit of work marks the row revoked and appends another immutable elevated-access audit event in the same transaction. A session that is already revoked or has elapsed is a typed 409 Conflict; a session id that does not exist within the selected organization is a typed 404 NotFound.",
				Tags:               []string{tagAdmin},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAdminBreakGlass),
				PathParams:         []openapi.PathParam{{Name: "session_id", Description: "The id of the break-glass session to revoke."}},
				SuccessDescription: "The revoked break-glass session.",
			},
			resolver: adminBreakGlassResolver,
			handler:  revokeAdminBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/break-glass",
				OperationID:    "startBreakGlassSession",
				Summary:        "Start a break-glass session",
				Description:    "Starts a time-bounded internal-support break-glass session targeting the organization named by the {org_id} path parameter. The request body must carry a non-empty reason (operator-authored justification — an incident or ticket id) and a positive ttl_seconds. The session row and an immutable audit event stamped with elevated_access=true are committed in one transaction, so a session can never exist without its audit trail. The store layer caps ttl_seconds at the documented break-glass maximum. Action support.manage is a CapSupport action authorized against the {org_id} path parameter before the handler runs; only a principal holding the support capability may start a session, and a non-support principal trying to start one is rejected with a deterministic 403. The break-glass mechanism is access-only and never mints customer credentials.",
				Tags:           []string{tagAdmin},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAdminBreakGlass),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization the support principal is reaching into.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The persisted break-glass session.",
			},
			// organizationIDResolver authorizes action support.manage
			// against the organization the {org_id} path parameter names. A
			// support principal acting cross-tenant is the deliberate
			// ReasonAllowedBySupport path; any non-support principal is
			// rejected at the policy boundary before the handler runs.
			resolver: organizationIDResolver,
			handler:  startBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/break-glass",
				OperationID:    "listBreakGlassSessions",
				Summary:        "List break-glass sessions",
				Description:    "Lists the break-glass sessions targeting the organization named by the {org_id} path parameter, newest first, capped at ?limit= (default 50, max 200). Each entry carries the session id, target organization, actor principal, reason, lifecycle status, started_at/expires_at, the optional revoked_at, and a computed active flag. The endpoint never returns credential material; reasons are persisted with known secret transport patterns scrubbed and projected verbatim. Action support.manage is authorized against the {org_id} path parameter before the handler runs.",
				Tags:           []string{tagAdmin},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAdminBreakGlass),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose break-glass sessions are listed.",
				}},
				SuccessDescription: "The break-glass sessions targeting the organization.",
			},
			resolver: organizationIDResolver,
			handler:  listBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/break-glass/{session_id}",
				OperationID:    "getBreakGlassSession",
				Summary:        "Get a break-glass session",
				Description:    "Returns a single break-glass session by id scoped to the organization named by the {org_id} path parameter, or a typed 404 if no such session exists within that tenant. Tenant scoping is enforced at both the policy boundary and the persistence layer, so a cross-tenant session id can never reveal another tenant's row.",
				Tags:           []string{tagAdmin},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAdminBreakGlass),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the session targets."},
					{Name: "session_id", Description: "The id of the break-glass session to retrieve."},
				},
				SuccessDescription: "The requested break-glass session.",
			},
			resolver: organizationIDResolver,
			handler:  getBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/break-glass/{session_id}",
				OperationID:    "revokeBreakGlassSession",
				Summary:        "Revoke a break-glass session",
				Description:    "Ends an active break-glass session early. The store-layer unit of work marks the row revoked and appends another immutable audit event stamped with elevated_access=true inside the same transaction. A session that is already revoked or has elapsed is a typed 409 Conflict; a session id that does not exist within the named organization is a typed 404 NotFound. The response carries the revoked session row so an agent has the authoritative timestamps without a follow-up GET.",
				Tags:           []string{tagAdmin},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAdminBreakGlass),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the session targets."},
					{Name: "session_id", Description: "The id of the break-glass session to revoke."},
				},
				SuccessDescription: "The revoked break-glass session.",
			},
			resolver: organizationIDResolver,
			handler:  revokeBreakGlassHandler(breakGlass, nil),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "getOrganization",
				Summary:        "Get an organization",
				Description:    "Returns the organization named by the {org_id} path parameter, as the source-of-truth database stores it — its id, slug, display name, and lifecycle timestamps. Action organization.read is authorized against the organization the path names before the handler runs: a principal requesting an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's data. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to retrieve.",
				}},
				SuccessDescription: "The requested organization.",
			},
			// organizationIDResolver authorizes action organization.read against
			// the organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data.
			resolver: organizationIDResolver,
			handler:  getOrganizationHandler(orgs),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/organizations",
				OperationID:        "createOrganization",
				Summary:            "Create an organization",
				Description:        "Creates an organization — the tenant root of Yalla's Organization -> Project -> Environment -> Service hierarchy — in the source-of-truth database. The request body supplies the canonical slug and the human-authored display name; both are validated before any database work, so an invalid request never opens a transaction. The organization row and an immutable audit record naming the authenticated principal are committed in one transaction: a created organization can never exist without its audit trail. The response carries no credential material.",
				Tags:               []string{tagOrganizations},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionOrganizationCreate),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The organization was created.",
			},
			// A nil resolver authorizes action organization.create against the
			// principal's own organization scope. organization.create is a
			// CapSelf action — permitted for any authenticated, enabled
			// principal — and the created organization does not exist yet, so
			// there is no deeper resource target to resolve.
			handler: createOrganizationHandler(creator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "updateOrganization",
				Summary:        "Update an organization",
				Description:    "Updates the organization named by the {org_id} path parameter in the source-of-truth database. The request body is a partial update: it may carry a new canonical slug, a new human-authored display name, or both — every supplied field is validated before any database work, and a patch that names no field is rejected with a stable 400. Action organization.update is authorized against the organization the path names before the handler runs: a principal updating an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's data. The updated organization row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to update.",
				}},
				SuccessDescription: "The updated organization.",
			},
			// organizationIDResolver authorizes action organization.update
			// against the organization the {org_id} path parameter names, not
			// merely the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any data.
			resolver: organizationIDResolver,
			handler:  updateOrganizationHandler(updater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "deleteOrganization",
				Summary:        "Schedule an organization for deletion",
				Description:    "Schedules the organization named by the {org_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the organization's deletion_scheduled_at stamp is set and the destructive teardown — the cascade that removes its projects, environments, services, and audit log — is carried out by a later worker story, so the organization and its audit trail still exist when this returns. Action organization.delete is authorized against the organization the path names before the handler runs: a principal deleting an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never affect another tenant's data. Scheduling deletion for an organization already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationDelete),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to schedule for deletion.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The organization was scheduled for deletion.",
			},
			// organizationIDResolver authorizes action organization.delete
			// against the organization the {org_id} path parameter names, not
			// merely the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any data.
			resolver: organizationIDResolver,
			handler:  deleteOrganizationHandler(deleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/members",
				OperationID:    "listOrganizationMembers",
				Summary:        "List members of an organization",
				Description:    "Lists the memberships of the organization named by the {org_id} path parameter, joined with each member's global user identity — user id, email, display name, role, role version, and lifecycle timestamps. Action members.read is authorized against the organization the path names before the handler runs: a principal listing members outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's members. The response carries no credential material — a membership row stores a role, never a secret — and the list is ordered deterministically by creation time then user id so a given set of rows always renders the same response.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose members are listed.",
				}},
				SuccessDescription: "The memberships of the organization.",
			},
			// organizationIDResolver authorizes action members.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies.
			resolver: organizationIDResolver,
			handler:  listMembersHandler(members),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/members",
				OperationID:    "addOrganizationMember",
				Summary:        "Add a member to an organization",
				Description:    "Adds an existing global user to the organization named by the {org_id} path parameter, with the requested organization-wide role, in the source-of-truth database. The request body supplies the user identifier and the role; both are validated before any database work, so an invalid request never opens a transaction. Action members.manage is authorized against the organization the path names before the handler runs: a principal adding a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. The memberships row and an immutable audit record naming the authenticated principal are committed in one transaction: a created membership can never exist without its audit trail. The role must be one of owner, admin, or member; a user that does not exist is a stable 404, and a user that is already a member of the organization is a stable 409. The response carries no credential material.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to add the member to.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The membership was created.",
			},
			// organizationIDResolver authorizes action members.manage against
			// the organization the {org_id} path parameter names, not merely
			// the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any
			// data. members.manage is a CapManage action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot manage members of another tenant.
			resolver: organizationIDResolver,
			handler:  addMemberHandler(memberCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "getOrganizationMember",
				Summary:        "Get a member of an organization",
				Description:    "Returns the single membership of the organization named by the {org_id} path parameter for the user named by the {member_id} path parameter, joined with that user's global identity — user id, email, display name, role, role version, and lifecycle timestamps. Action members.read is authorized against the organization the path names before the handler runs: a principal reading a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's membership. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The response carries no credential material — a membership row stores a role, never a secret.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersRead),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is read."},
				},
				SuccessDescription: "The membership of the organization.",
			},
			// organizationIDResolver authorizes action members.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  getMemberHandler(members),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "updateOrganizationMember",
				Summary:        "Update a member of an organization",
				Description:    "Updates the role of the member named by ({org_id}, {member_id}) in the source-of-truth database. The request body supplies the new role; it is validated before any database work, so an invalid request never opens a transaction. Action members.manage is authorized against the organization the path names before the handler runs: a principal updating a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The role update atomically bumps the member's role_version, which invalidates every outstanding session token issued to the member — making a single role change a complete session sweep without a denylist. The updated membership row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The role must be one of owner, admin, or member. The response carries no credential material.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is updated."},
				},
				SuccessDescription: "The updated membership.",
			},
			// memberIDResolver authorizes action members.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// members.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot manage members of another tenant.
			resolver: memberIDResolver,
			handler:  updateMemberHandler(memberUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "removeOrganizationMember",
				Summary:        "Remove a member from an organization",
				Description:    "Removes the member named by ({org_id}, {member_id}) from the source-of-truth database. The deletion is immediate, not scheduled: the memberships row is dropped and an immutable audit record naming the authenticated principal — and capturing the role the member held at removal time — is committed in the same transaction, so the audit trail of who removed whom survives the row. Action members.manage is authorized against the organization the path names before the handler runs: a principal removing a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The response carries the membership exactly as it stood at the moment of removal, in the same wire shape every other membership endpoint returns; it carries no credential material — a membership row stores a role, never a secret.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is removed."},
				},
				SuccessDescription: "The removed membership.",
			},
			// memberIDResolver authorizes action members.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// members.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot manage members of another tenant.
			resolver: memberIDResolver,
			handler:  removeMemberHandler(memberRemover),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/limits",
				OperationID:    "getOrganizationLimits",
				Summary:        "Get effective limits of an organization",
				Description:    "Returns customer-visible effective limits for the organization named by the {org_id} path parameter, in deterministic resource order. When the organization has a current accepted subscription, the response is resolved from pricing-plan entitlements plus subscription or emergency-admin overrides; otherwise it falls back to legacy quota policies. Each entry carries the resource dimension, numeric ceiling, current used_value, enforcement mode (hard, soft, metered, or disabled), source scope (plan, subscription_override, emergency_admin, organization, or plan_default), reset_period when a billing period is known, and stable warning_thresholds. Internal provider ids, plan ids, subscription ids, override ids, and override reasons are never returned. Action limits.read is authorized against the organization the path names before the handler runs, and the persistence read is tenant scoped so cross-tenant ids cannot reveal another tenant's limits.",
				Tags:           []string{tagLimits},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose effective limits are read.",
				}},
				SuccessDescription: "The effective limits of the organization.",
			},
			// organizationIDResolver authorizes action limits.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listLimitsHandler(limits),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/limits",
				OperationID:    "updateOrganizationLimits",
				Summary:        "Update organization-scoped quota limits",
				Description:    "Upserts the organization-scoped quota policies of the organization named by the {org_id} path parameter in the source-of-truth database. The request body carries a non-empty list of {resource, limit_value, enforcement_mode} entries; each entry creates an organization override for the named quota dimension if none exists, or overwrites the limit_value and enforcement_mode of the existing override otherwise. Plan defaults are untouched: this endpoint is the customer-facing override surface. Every entry is validated before any database work (resource must be in the closed quota_resource set, limit_value must be zero or positive, and enforcement_mode if supplied must be one of hard, soft, metered, or disabled — empty defaults to hard, matching the schema), and a patch with no entries or a duplicated resource is itself a stable 400 — a mutation that changes nothing or is internally inconsistent is a client error, not a silent success. Action limits.write is authorized against the organization the path names before the handler runs: a principal updating limits outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's limits, and unlike limits.read (a CapRead action) limits.write has NO cross-tenant support exception — only an owner or admin in the tenant can update limits, never a support principal. An {org_id} with no row is the typed 404 the repository produces. The organization-scoped policy upserts and an immutable audit record naming the authenticated principal and the affected resources are committed in one transaction, then the effective limits are re-read inside the same transaction so the response always reflects exactly the state that just persisted. The response carries no credential material — quota dimensions and counts are not sensitive — and uses the same stable wire shape GET /v1/organizations/{org_id}/limits returns.",
				Tags:           []string{tagLimits},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsWrite),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose limits are updated.",
				}},
				SuccessDescription: "The effective limits of the organization after the upsert.",
			},
			// organizationIDResolver authorizes action limits.write against
			// the organization the {org_id} path parameter names, not merely
			// the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any
			// data. limits.write is a CapAdmin action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot update limits in another tenant.
			resolver: organizationIDResolver,
			handler:  updateLimitsHandler(limitsUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/usage",
				OperationID:    "getOrganizationUsage",
				Summary:        "Get current resource usage of an organization",
				Description:    "Returns customer-visible usage for the organization named by the {org_id} path parameter, paired with the effective limit configured for each resource when one applies. When the organization has a current accepted subscription, the response includes the current billing period, entitlement-backed counters, warning_thresholds, and an empty trend_summaries array reserved for the later usage-events aggregation contract; otherwise it falls back to legacy quota-policy usage. Each usage entry carries the resource dimension, live used_value counter, nullable limit object, and stable warning thresholds. Internal provider ids, plan ids, subscription ids, override ids, and override reasons are never returned. Action limits.read is authorized against the organization the path names before the handler runs, and the persistence read is tenant scoped so cross-tenant ids cannot reveal another tenant's usage.",
				Tags:           []string{tagUsage},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose current resource usage is read.",
				}},
				SuccessDescription: "The current resource usage of the organization.",
			},
			// organizationIDResolver authorizes action limits.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listUsageHandler(usage),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/audit-events",
				OperationID:    "listOrganizationAuditEvents",
				Summary:        "List audit events of an organization",
				Description:    "Returns the most recent audit events recorded for the organization named by the {org_id} path parameter, newest first, capped at the effective page size. Every event is one immutable authorization decision the control plane recorded — both allowed and denied — and carries the action that was attempted, the verdict (allowed or denied), the stable policy reason for that verdict, the actor that triggered it (a user, an API key, an internal service account, or null for an unauthenticated denied request), the resource the action named (or null for an organization-root or self action), the request id and correlation id the request travelled under, the ip address and user agent the request arrived with, and a free-form metadata map of diff/context detail. Every value reaches this endpoint already redacted at the persistence boundary — secret-shaped metadata keys (token, secret, password, credential, ...) are replaced wholesale with the redaction sentinel, every other metadata value, ip address, and user agent is scrubbed through the structural redactor, all before AuditRepository.Append persists the row — so a secret can structurally never reach the wire. Action audit.read is authorized against the organization the path names before the handler runs: a principal reading audit events outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's decisions. audit.read is a CapAdmin action: a viewer, developer, or ci principal cannot list the organization's audit log; only an owner or admin in the tenant (and a support principal performing a cross-tenant read) can. The read is tenant scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a tenant with no audit history would, never another tenant's events. The endpoint accepts an optional ?limit= query parameter in the range [1, 200]; an absent value defaults to 50, and a malformed or out-of-range value is rejected as a stable 400.",
				Tags:           []string{tagAuditEvents},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAuditRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose audit events are listed.",
				}},
				SuccessDescription: "The most recent audit events of the organization, newest first.",
			},
			// organizationIDResolver authorizes action audit.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for read actions.
			resolver: organizationIDResolver,
			handler:  listAuditEventsHandler(auditEvents),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/variables",
				OperationID:    "listOrganizationVariables",
				Summary:        "List organization-scoped variables",
				Description:    "Lists the organization-scoped variables configured for the organization named by the {org_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Organization-scoped variables are the lowest-precedence layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here is the organization-wide default every service in the tenant inherits unless overridden by a higher-scope variable. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own organization-wide defaults. Action env.read is authorized against the organization the path names before the handler runs: a principal listing variables outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's configuration. The read is tenant-scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a tenant with no configured variables would, never another tenant's data.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose variables are listed.",
				}},
				SuccessDescription: "The organization-scoped variables of the organization.",
			},
			// organizationIDResolver authorizes action env.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for read actions.
			resolver: organizationIDResolver,
			handler:  listOrganizationVariablesHandler(orgVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/organizations/{org_id}/variables",
				OperationID:    "replaceOrganizationVariables",
				Summary:        "Replace organization-scoped variables",
				Description:    "Replaces the organization-scoped variables of the organization named by the {org_id} path parameter in the source-of-truth database. The request body carries the complete variable set the caller wants installed; the unit of work upserts every entry on (organization_id, key) — preserving the row's id and bumping its optimistic-concurrency version through the schema's bump_version trigger when a row already exists — and deletes every variable not named in the body, so the tenant's post-condition is exactly the submitted set. An explicit empty array clears every organization-scoped variable; omitting the variables field altogether is a stable 400 (so a misencoded request is never a silent clear). Each entry is validated before any database work: a key that is not a POSIX environment variable name ([A-Za-z_][A-Za-z0-9_]*) or that exceeds the length ceiling, a duplicated key, a value that is not valid UTF-8, a value carrying an embedded NUL byte, or a value above the per-kind size ceiling (32 KiB for plain values, larger for is_secret=true entries) each surfaces as a stable apierr.InvalidInput naming the offending field path — never echoing the submitted value, so a secret can never reach a validation reason. Action env.write is authorized against the organization the path names before the handler runs: a principal replacing variables outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can replace variables. An {org_id} with no organizations row is the typed 404 the repository produces. The replacement set, the bulk delete of the rest, and an immutable audit record naming the authenticated principal (with metadata that records only variable and secret counts, never variable keys or values) are committed in one transaction, then the committed variables are re-read inside the same transaction so the response always reflects exactly the state that just persisted. The response carries the persisted variables in the same stable wire shape GET /v1/organizations/{org_id}/variables returns; secret values are ALWAYS redacted on the wire as the redaction sentinel — a customer can never read a secret value back through this endpoint by design, including immediately after submitting it.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose variables are replaced.",
				}},
				SuccessDescription: "The organization-scoped variables of the organization after the replace.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot replace variables in another tenant.
			resolver: organizationIDResolver,
			handler:  replaceOrganizationVariablesHandler(orgVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/variables/{key}",
				OperationID:    "patchOrganizationVariable",
				Summary:        "Patch an organization-scoped variable",
				Description:    "Patches the organization-scoped variable named by the {key} path parameter inside the organization named by the {org_id} path parameter. The request body is a partial update over the mutable fields — value and is_secret — and omitting a field leaves the corresponding column unchanged; a PATCH that names neither field is itself a stable 400, so a mutation that changes nothing is never a silent success. Each supplied field is validated before any database work: a value that is not valid UTF-8 or that carries an embedded NUL byte each surfaces as a stable apierr.InvalidInput naming the offending field path — never echoing the submitted value, so a secret can never reach a validation reason. The per-kind size ceiling (32 KiB for plain values, 64 KiB for is_secret=true entries) is enforced against the final post-patch state inside the transaction so a demotion to is_secret=false cannot smuggle a value above the non-secret ceiling. Action env.write is authorized against the organization the path names before the handler runs: a principal patching a variable outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can patch a variable. An {org_id} with no organizations row, or a {key} that does not exist in this tenant (the persistence read filters by organization_id first, so a cross-tenant key is indistinguishable from a missing row), is the typed 404 the repository produces. The single-row update and an immutable audit record naming the authenticated principal (with metadata that records only the variable's stable id and the closed-set names of the fields the patch changed — never the customer-supplied key or value) are committed in one transaction, then the committed row is returned so the response always reflects exactly the state that just persisted. The response carries the persisted variable in the same stable wire shape GET /v1/organizations/{org_id}/variables returns; secret values are ALWAYS redacted on the wire as the redaction sentinel — a customer can never read a secret value back through this endpoint by design, including immediately after submitting it.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization whose variable is patched."},
					{Name: "key", Description: "The POSIX environment variable name of the organization-scoped variable to patch."},
				},
				SuccessDescription: "The organization-scoped variable after the patch.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot patch a variable in another tenant. The {key} path
			// parameter does not change the policy scope: variables live
			// inside the organization and are addressed by name; the policy
			// boundary is the organization the path names.
			resolver: organizationIDResolver,
			handler:  patchOrganizationVariableHandler(orgVariablePatcher),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/variables/{key}",
				OperationID:    "deleteOrganizationVariable",
				Summary:        "Delete an organization-scoped variable",
				Description:    "Removes the organization-scoped variable named by the {key} path parameter from the organization named by the {org_id} path parameter. Action env.write is authorized against the organization the path names before the handler runs: a principal deleting a variable outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can delete a variable. An {org_id} with no organizations row, or a {key} that does not exist in this tenant (the persistence delete filters by organization_id first, so a cross-tenant key is indistinguishable from a missing row), is the typed 404 the repository produces. The single-row delete and an immutable audit record naming the authenticated principal (with metadata that records only the variable's stable id — never the customer-supplied key or value) are committed in one transaction, so a deletion can never be persisted without its audit trail. The response carries the variable exactly as it stood at the moment of removal, in the same stable wire shape every other variable endpoint returns; secret values are still redacted to the sentinel on the wire, so a DELETE cannot leak a secret value the customer had previously stored. The row is gone from the database by the time the response reaches the wire; an audit trail of the deletion lives independently of the row.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization whose variable is deleted."},
					{Name: "key", Description: "The POSIX environment variable name of the organization-scoped variable to delete."},
				},
				SuccessDescription: "The organization-scoped variable as it stood at the moment of removal.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot delete a variable in another tenant. The {key} path
			// parameter does not change the policy scope: variables live
			// inside the organization and are addressed by name; the policy
			// boundary is the organization the path names.
			resolver: organizationIDResolver,
			handler:  deleteOrganizationVariableHandler(orgVariableDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/api-keys",
				OperationID:    "listOrganizationAPIKeys",
				Summary:        "List API keys of an organization",
				Description:    "Lists the API keys owned by the organization named by the {org_id} path parameter, in deterministic creation order — each entry carries the key's id, public prefix, name, scopes, ownership identifiers (the user who minted it and the optional owning service account), and lifecycle timestamps. Action keys.read is authorized against the organization the path names before the handler runs: a principal listing API keys outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's keys. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint. keys.read is a CapAdmin action: a viewer or developer cannot list the organization's keys; only an owner or admin in the tenant (and a support principal performing a cross-tenant read) can.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose API keys are listed.",
				}},
				SuccessDescription: "The API keys owned by the organization.",
			},
			// organizationIDResolver authorizes action keys.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listAPIKeysHandler(apiKeys),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "getOrganizationAPIKey",
				Summary:        "Get an API key of an organization",
				Description:    "Returns the single API key named by ({org_id}, {key_id}) from the source-of-truth database — its id, public prefix, name, scopes, ownership identifiers (the user who minted it and the optional owning service account), and lifecycle timestamps. Action keys.read is authorized against the organization the path names before the handler runs: a principal reading a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's keys. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint. keys.read is a CapAdmin action: a viewer or developer cannot read the organization's keys; only an owner or admin in the tenant can — and unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysRead),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to read."},
				},
				SuccessDescription: "The API key identified by ({org_id}, {key_id}).",
			},
			// organizationIDResolver authorizes action keys.read against the
			// organization the {org_id} path parameter names, so a cross-tenant
			// id is denied at the policy boundary before the handler reads any
			// data. keys.read is a CapAdmin action, so the support cross-tenant
			// exception (a CapRead-only allow) does not apply — privileged
			// Yalla support that needs key visibility goes through the explicit
			// break-glass admin tooling, not this customer-facing endpoint.
			resolver: organizationIDResolver,
			handler:  getAPIKeyHandler(apiKeys),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/api-keys",
				OperationID:    "createOrganizationAPIKey",
				Summary:        "Create an API key for an organization",
				Description:    "Mints a fresh API key for the organization named by the {org_id} path parameter and persists it through the store-layer unit of work. The request body supplies the human-authored name, the machine-readable scopes (may be empty), an optional RFC 3339 expires_at, and an optional service_account_id that transfers ownership of the key from the authenticated user to a non-human principal; every field is validated before any database work, so an invalid request never opens a transaction. Action keys.manage is authorized against the organization the path names before the handler runs: a principal minting a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never plant a credential in another tenant. The credential primitive is generated server-side (a client cannot supply its own prefix or hash), the api_keys row and an immutable audit record naming the authenticated principal are committed in one transaction, and a service_account_id that does not exist in the target tenant rolls the whole transaction back as a stable 404. The response carries the persisted key projection and — exactly once — the plaintext token; the secret never reaches a log line, an audit record, or any subsequent read endpoint, so a key not captured at creation time is unrecoverable by design. keys.manage is a CapManage action: a viewer or developer cannot mint keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization the API key is minted in.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The API key was minted; the plaintext token is shown exactly once.",
			},
			// organizationIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler mints any credential.
			// keys.manage is a CapManage action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal cannot
			// mint keys in another tenant.
			resolver: organizationIDResolver,
			handler:  createAPIKeyHandler(apiKeyCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "updateOrganizationAPIKey",
				Summary:        "Update an API key of an organization",
				Description:    "Updates the mutable fields of the API key named by ({org_id}, {key_id}) in the source-of-truth database. The request body supplies the new name and/or scopes; each value is validated before any database work, so an invalid request never opens a transaction, and a patch that names no mutable field is itself a stable 400 — a mutation that changes nothing is a client error, not a silent success. Action keys.manage is authorized against the organization the path names before the handler runs: a principal updating a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's keys. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. The updated row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint, so an update endpoint can never reveal or rotate a credential. keys.manage is a CapManage action: a viewer or developer cannot update keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to update."},
				},
				SuccessDescription: "The updated API key.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// keys.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot update keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  updateAPIKeyHandler(apiKeyUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "revokeOrganizationAPIKey",
				Summary:        "Revoke an API key of an organization",
				Description:    "Revokes the API key named by ({org_id}, {key_id}) in the source-of-truth database. Revocation is the customer-facing soft delete for an API key: the api_keys row stays in the database so the audit trail of who minted it remains linked to a live row, but the credential is permanently unusable from that moment on — every subsequent authentication attempt fails through the same uniform invalid-credentials path. There is no un-revoke; a retired key can only be replaced by a fresh mint. Action keys.manage is authorized against the organization the path names before the handler runs: a principal revoking a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never retire another tenant's credential. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. Revoking a key that is already revoked is a stable 409 — the caller's view of the resource lifecycle is stale, not a silent success that would write a misleading audit record. The revocation stamp and an immutable audit record naming the authenticated principal are committed in one transaction: a revocation can never be persisted without its audit trail. The response carries the api key exactly as it stood at the moment of revocation, in the same wire shape every other api-key endpoint returns; it carries no credential material — the secret hash is never projected onto the wire and the plaintext token is shown to its owner once at creation and never reaches this endpoint, so a revocation endpoint can never reveal a credential. keys.manage is a CapManage action: a viewer or developer cannot revoke keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to revoke."},
				},
				SuccessDescription: "The API key was revoked.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// keys.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot revoke keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  revokeAPIKeyHandler(apiKeyRevoker),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}/rotate",
				OperationID:    "rotateOrganizationAPIKey",
				Summary:        "Rotate an API key of an organization",
				Description:    "Rotates the credential body of the API key named by ({org_id}, {key_id}) in the source-of-truth database. Rotation swaps the credential primitives (the public prefix and the one-way secret hash) in place: the api_keys row keeps its id, name, scopes, ownership identifiers (created_by, service_account_id), and lifecycle stamps (expires_at) — only the credential body changes. The OLD credential body becomes permanently unusable from the moment the row is committed: the prefix-lookup authentication path only ever sees the row's current prefix, so every subsequent authentication attempt with the old token misses through the same uniform invalid-credentials path that a non-existent key produces. The new credential primitive is generated server-side (a client cannot supply its own prefix or hash). Action keys.manage is authorized against the organization the path names before the handler runs: a principal rotating a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never rotate another tenant's credential. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. Rotating a key that is revoked or expired is a stable 409 — the caller's view of the resource lifecycle is stale, and a fresh credential body cannot revive a row that is permanently out of authentication service; the customer must mint a new key through POST /v1/organizations/{org_id}/api-keys instead. The rotated row and an immutable audit record naming the authenticated principal are committed in one transaction: a rotation can never be persisted without its audit trail. The response carries the rotated api-key projection and — exactly once — the plaintext token of the new credential body; the secret never reaches a log line, an audit record, or any subsequent read endpoint, so a rotated credential not captured at rotation time is unrecoverable by design. keys.manage is a CapManage action: a viewer or developer cannot rotate keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to rotate."},
				},
				SuccessDescription: "The API key was rotated; the plaintext token of the new credential body is shown exactly once.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mints any
			// credential. keys.manage is a CapManage action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot rotate keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  rotateAPIKeyHandler(apiKeyRotator),
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
func readyzHandler(readiness runtime.ReadinessReporter, metrics *telemetry.ReadinessDegradationMetrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]bool{}
		ready := true
		if readiness != nil {
			checks = readiness.Snapshot()
			ready = readiness.Ready()
		}
		recordReadinessMetrics(r, metrics, checks)
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

func recordReadinessMetrics(r *http.Request, metrics *telemetry.ReadinessDegradationMetrics, checks map[string]bool) {
	if metrics == nil {
		return
	}
	for check, passing := range checks {
		status := "passing"
		reason := "ready"
		if !passing {
			status = "failing"
			reason = "pending"
		}
		metrics.RecordReadinessProbe(r.Context(), telemetry.ReadinessDegradationObservation{
			Check:  check,
			Status: status,
			Reason: reason,
		})
	}
}

// backupHealthHandler builds the GET /healthz/backup handler. The probe is
// always served — a nil or unconfigured reporter renders a 200 envelope
// with configured=false rather than a 404, so operators can deploy the
// integration without changing the route table.
//
// Error path: a reporter that fails to read or parse its source returns a
// non-sentinel error and the handler renders a 503 yalla.error.v1 envelope
// (CodeUnavailable). The error message is the package-level redacted
// string from internal/controlplane/backup — it names the configured path
// but never echoes the file's content, so an accidentally-misconfigured
// pipeline that wrote a secret to the status file cannot leak it through
// the probe.
//
// Sentinel path: backup.ErrNoBackupRecorded (the file does not exist yet
// because the first backup has not landed) renders a 200 envelope with
// configured=true and the last_success_at field omitted — a freshly
// provisioned environment is healthy, it just has no backup history yet.
func backupHealthHandler(reporter backup.Reporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if reporter == nil {
			reporter = backup.Unconfigured()
		}
		status, err := reporter.Status(ctx)

		// Sentinel: the source is wired but has no successful backup yet.
		// Render 200 with a fresh=false verdict so a Prometheus alert wired
		// to fresh==false fires immediately on a brand-new environment.
		if errors.Is(err, backup.ErrNoBackupRecorded) {
			payload := backupHealthPayload{
				Configured: true,
				// A configured-but-empty source is not fresh by definition.
				// Operators expect their first backup; surface that here.
				Fresh:  false,
				Detail: "no successful backup recorded yet",
			}
			if status.MaxAge > 0 {
				secs := int64(status.MaxAge.Seconds())
				payload.MaxAgeSeconds = &secs
			}
			apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
			return
		}

		if err != nil {
			// Treat a context cancellation as a client-driven cancel; every
			// other failure is a backend availability problem. The error's
			// message is already redacted by the backup package — it names
			// the path but never echoes the file's content.
			if ctxErr := ctx.Err(); ctxErr != nil {
				apienvelope.WriteErrorStatus(w, 499, requestID(r),
					yerr.New(yerr.CodeCanceled, "request canceled while reading backup status"))
				return
			}
			apienvelope.WriteErrorStatus(w, http.StatusServiceUnavailable, requestID(r),
				yerr.New(yerr.CodeUnavailable, "backup status is unavailable").
					WithHint("the operator backup-status source is unreadable or malformed; check the pipeline that writes YALLA_BACKUP_STATUS_FILE"))
			return
		}

		payload := backupHealthPayload{
			Configured: status.Configured,
			Fresh:      status.Fresh(),
		}
		if !status.LastSuccessAt.IsZero() {
			payload.LastSuccessAt = status.LastSuccessAt.UTC().Format(rfc3339UTC)
			age := int64(status.Age.Seconds())
			payload.AgeSeconds = &age
		}
		if status.MaxAge > 0 {
			secs := int64(status.MaxAge.Seconds())
			payload.MaxAgeSeconds = &secs
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// rfc3339UTC is the timestamp format the /healthz/backup probe emits. It is
// time.RFC3339 with a Z suffix because Status.LastSuccessAt is forced to
// UTC by the backup package, so the wire shape is stable across
// deployment timezones.
const rfc3339UTC = "2006-01-02T15:04:05Z"

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
