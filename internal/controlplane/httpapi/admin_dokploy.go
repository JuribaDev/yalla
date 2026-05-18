package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoDriftFindingReader = errors.New("httpapi: no drift finding reader configured")
var errNoDokployRefReader = errors.New("httpapi: no dokploy ref reader configured")
var errNoAdminDokployReconciler = errors.New("httpapi: no admin dokploy reconciler configured")
var errNoAdminDokployImporter = errors.New("httpapi: no admin dokploy importer configured")

const (
	driftFindingListDefaultLimit = 50
	driftFindingListMaxLimit     = 200
	adminImportIdempotencyMaxLen = 128
)

// DriftFindingReader is the narrow read port for GET
// /v1/admin/dokploy/drift. The store-backed adapter verifies the target
// organization and any supplied descendant filters before listing rows.
type DriftFindingReader interface {
	ListDriftFindings(ctx context.Context, organizationID string, query store.DriftFindingListQuery) ([]store.DriftFinding, error)
}

// DokployRefReader is the narrow read port for GET
// /v1/admin/organizations/{org_id}/dokploy-refs. The store-backed adapter
// verifies the target organization exists before listing tenant-scoped mapping
// rows.
type DokployRefReader interface {
	ListDokployRefs(ctx context.Context, organizationID string) ([]store.DokployRef, error)
}

// AdminDokployReconciler is the narrow mutating port for POST
// /v1/admin/dokploy/reconcile. Implementations own the concrete
// store/Dokploy/audit transaction boundaries; the HTTP layer only validates
// the target organization, forwards request correlation, and renders the
// stable public result.
type AdminDokployReconciler interface {
	ReconcileDokploy(ctx context.Context, req AdminDokployReconcileRequest) (AdminDokployReconcileResult, error)
}

// AdminDokployImporter is the narrow mutating port for POST
// /v1/admin/dokploy/import. Implementations own the store/audit/job
// transaction; the HTTP layer validates target shape and renders the queued
// job contract.
type AdminDokployImporter interface {
	ImportDokploy(ctx context.Context, in store.ImportDokployInput) (store.ProvisioningJob, error)
}

// AdminDokployReconcileRequest carries the validated reconcile target and
// request correlation data from the HTTP layer into the concrete runner.
type AdminDokployReconcileRequest struct {
	OrganizationID string
	ActorID        string
	RequestID      string
	CorrelationID  string
	DryRun         bool
}

// AdminDokployReconcileResult is the stable runner summary projected into the
// POST /v1/admin/dokploy/reconcile response envelope.
type AdminDokployReconcileResult struct {
	OrganizationID string
	DryRun         bool
	Repaired       int
	Reviewed       int
	Quarantined    int
	Failures       []AdminDokployReconcileFailure
}

// AdminDokployReconcileFailure is a redaction-safe per-action failure summary.
type AdminDokployReconcileFailure struct {
	ActionType string `json:"action_type"`
	DriftKind  string `json:"drift_kind"`
	Reason     string `json:"reason"`
	ServiceID  string `json:"service_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// AdminDokployReconcileResultFromEngine converts the pure reconcile engine's
// result into the HTTP runner result shape without exposing env-var values.
func AdminDokployReconcileResultFromEngine(organizationID string, dryRun bool, result reconcile.Result) AdminDokployReconcileResult {
	failures := make([]AdminDokployReconcileFailure, 0, len(result.Failures))
	for _, f := range result.Failures {
		failure := AdminDokployReconcileFailure{
			ActionType: string(f.Action.Type),
			DriftKind:  string(f.Action.Kind),
			Reason:     string(f.Action.Reason),
			ServiceID:  string(f.Action.Service.ServiceID),
		}
		if f.Err != nil {
			failure.Error = f.Err.Error()
		}
		failures = append(failures, failure)
	}
	return AdminDokployReconcileResult{
		OrganizationID: organizationID,
		DryRun:         dryRun,
		Repaired:       result.Repaired,
		Reviewed:       result.Reviewed,
		Quarantined:    result.Quarantined,
		Failures:       failures,
	}
}

type listAdminDokployDriftPayload struct {
	Findings []driftFindingResource `json:"findings"`
}

type listAdminDokployRefsPayload struct {
	OrganizationID string               `json:"organization_id"`
	Refs           []dokployRefResource `json:"refs"`
}

type adminDokployReconcileRequestBody struct {
	OrganizationID string `json:"organization_id,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

type adminDokployImportRequestBody struct {
	OrganizationID         string `json:"organization_id,omitempty"`
	YallaOrganizationID    string `json:"yalla_organization_id,omitempty"`
	DokployOrganizationID  string `json:"dokploy_organization_id"`
	AssignmentDokployOrgID string `json:"assignment_dokploy_org_id,omitempty"`
	IdempotencyKey         string `json:"idempotency_key"`
}

type adminDokployReconcilePayload struct {
	OrganizationID string                         `json:"organization_id"`
	DryRun         bool                           `json:"dry_run"`
	Repaired       int                            `json:"repaired"`
	Reviewed       int                            `json:"reviewed"`
	Quarantined    int                            `json:"quarantined"`
	FailureCount   int                            `json:"failure_count"`
	Failures       []AdminDokployReconcileFailure `json:"failures"`
}

type adminDokployImportPayload struct {
	OrganizationID        string      `json:"organization_id"`
	YallaOrganizationID   string      `json:"yalla_organization_id"`
	DokployOrganizationID string      `json:"dokploy_organization_id"`
	Job                   jobResource `json:"job"`
}

type driftFindingResource struct {
	ID                string     `json:"id"`
	OrganizationID    string     `json:"organization_id"`
	Status            string     `json:"status"`
	Kind              string     `json:"kind"`
	Reason            string     `json:"reason"`
	Level             string     `json:"level"`
	ProjectID         string     `json:"project_id,omitempty"`
	EnvironmentID     string     `json:"environment_id,omitempty"`
	ServiceID         string     `json:"service_id,omitempty"`
	ServiceDomainID   string     `json:"service_domain_id,omitempty"`
	EnvVarKey         string     `json:"env_var_key,omitempty"`
	DokployResourceID string     `json:"dokploy_resource_id,omitempty"`
	ParentDokployID   string     `json:"parent_dokploy_id,omitempty"`
	RequestID         string     `json:"request_id,omitempty"`
	CorrelationID     string     `json:"correlation_id,omitempty"`
	DetectedAt        time.Time  `json:"detected_at"`
	ResolvedAt        *time.Time `json:"resolved_at"`
	ResolvedByActorID string     `json:"resolved_by_actor_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type dokployRefResource struct {
	ID              int64     `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	YallaKind       string    `json:"yalla_kind"`
	YallaID         string    `json:"yalla_id"`
	DokployResource string    `json:"dokploy_resource"`
	DokployID       string    `json:"dokploy_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func driftFindingResourceOf(f store.DriftFinding) driftFindingResource {
	return driftFindingResource{
		ID:                f.ID,
		OrganizationID:    f.OrganizationID,
		Status:            f.Status.String(),
		Kind:              f.Kind.String(),
		Reason:            f.Reason.String(),
		Level:             f.Level.String(),
		ProjectID:         f.ProjectID,
		EnvironmentID:     f.EnvironmentID,
		ServiceID:         f.ServiceID,
		ServiceDomainID:   f.ServiceDomainID,
		EnvVarKey:         f.EnvVarKey,
		DokployResourceID: f.DokployResourceID,
		ParentDokployID:   f.ParentDokployID,
		RequestID:         f.RequestID,
		CorrelationID:     f.CorrelationID,
		DetectedAt:        f.DetectedAt,
		ResolvedAt:        f.ResolvedAt,
		ResolvedByActorID: f.ResolvedByActorID,
		CreatedAt:         f.CreatedAt,
		UpdatedAt:         f.UpdatedAt,
	}
}

func dokployRefResourceOf(ref store.DokployRef) dokployRefResource {
	return dokployRefResource{
		ID:              ref.ID,
		OrganizationID:  ref.OrganizationID,
		YallaKind:       ref.YallaKind.String(),
		YallaID:         ref.YallaID,
		DokployResource: ref.DokployResource.String(),
		DokployID:       ref.DokployID,
		CreatedAt:       ref.CreatedAt,
		UpdatedAt:       ref.UpdatedAt,
	}
}

func adminDokployDriftResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{
		OrganizationID: r.URL.Query().Get("organization_id"),
		ProjectID:      r.URL.Query().Get("project_id"),
		EnvironmentID:  r.URL.Query().Get("environment_id"),
		ServiceID:      r.URL.Query().Get("service_id"),
	}
	if scope.OrganizationID == "" {
		if p, ok := policy.PrincipalFromContext(r.Context()); ok {
			scope.OrganizationID = p.OrganizationID
		}
	}
	kind := domain.KindOrganization
	switch {
	case scope.ServiceID != "":
		kind = domain.KindService
	case scope.EnvironmentID != "":
		kind = domain.KindEnvironment
	case scope.ProjectID != "":
		kind = domain.KindProject
	}
	return policy.Resource{Kind: kind, Scope: scope}
}

func listAdminDokployDriftHandler(reader DriftFindingReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDriftFindingReader))
			return
		}

		orgID, query, err := parseDriftFindingListQuery(r, p.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		findings, err := reader.ListDriftFindings(r.Context(), orgID, query)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]driftFindingResource, 0, len(findings))
		for _, f := range findings {
			out = append(out, driftFindingResourceOf(f))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listAdminDokployDriftPayload{Findings: out})
	}
}

func listAdminDokployRefsHandler(reader DokployRefReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := policy.PrincipalFromContext(r.Context()); !ok {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDokployRefReader))
			return
		}

		orgID := r.PathValue("org_id")
		if err := validateOrganizationIDField("org_id", orgID); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		refs, err := reader.ListDokployRefs(r.Context(), orgID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]dokployRefResource, 0, len(refs))
		for _, ref := range refs {
			out = append(out, dokployRefResourceOf(ref))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listAdminDokployRefsPayload{
			OrganizationID: orgID,
			Refs:           out,
		})
	}
}

func reconcileAdminDokployHandler(reconciler AdminDokployReconciler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reconciler == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminDokployReconciler))
			return
		}

		var body adminDokployReconcileRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		orgID, err := parseAdminDokployReconcileTarget(r, p.OrganizationID, body.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		result, err := reconciler.ReconcileDokploy(r.Context(), AdminDokployReconcileRequest{
			OrganizationID: orgID,
			ActorID:        p.ID,
			RequestID:      requestID(r),
			CorrelationID:  telemetry.CorrelationID(r.Context()),
			DryRun:         body.DryRun,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if result.OrganizationID == "" {
			result.OrganizationID = orgID
		}
		failures := result.Failures
		if failures == nil {
			failures = []AdminDokployReconcileFailure{}
		}
		payload := adminDokployReconcilePayload{
			OrganizationID: result.OrganizationID,
			DryRun:         result.DryRun,
			Repaired:       result.Repaired,
			Reviewed:       result.Reviewed,
			Quarantined:    result.Quarantined,
			FailureCount:   len(failures),
			Failures:       failures,
		}
		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), payload)
	}
}

func importAdminDokployHandler(importer AdminDokployImporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if importer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminDokployImporter))
			return
		}

		var body adminDokployImportRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		orgID, yallaOrgID, err := parseAdminDokployImportTarget(r, p.OrganizationID, body.OrganizationID, body.YallaOrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		dokployOrgID, assignmentDokployOrgID, idempotencyKey, err := validateAdminDokployImportBody(body)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		job, err := importer.ImportDokploy(r.Context(), store.ImportDokployInput{
			OrganizationID:         orgID,
			YallaOrganizationID:    yallaOrgID,
			DokployOrganizationID:  dokployOrgID,
			AssignmentDokployOrgID: assignmentDokployOrgID,
			IdempotencyKey:         idempotencyKey,
			ActorID:                p.ID,
			ActorKind:              string(p.Kind),
			ActorOrgID:             p.OrganizationID,
			RequestID:              requestID(r),
			CorrelationID:          telemetry.CorrelationID(r.Context()),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), adminDokployImportPayload{
			OrganizationID:        orgID,
			YallaOrganizationID:   yallaOrgID,
			DokployOrganizationID: dokployOrgID,
			Job:                   jobResourceOf(job),
		})
	}
}

func parseDriftFindingListQuery(r *http.Request, defaultOrganizationID string) (string, store.DriftFindingListQuery, error) {
	values := r.URL.Query()
	orgID := values.Get("organization_id")
	if orgID == "" {
		orgID = defaultOrganizationID
	}
	query := store.DriftFindingListQuery{
		ProjectID:     values.Get("project_id"),
		EnvironmentID: values.Get("environment_id"),
		ServiceID:     values.Get("service_id"),
		Limit:         driftFindingListDefaultLimit,
	}
	if values.Get("limit") != "" {
		n, err := strconv.Atoi(values.Get("limit"))
		if err != nil {
			return "", store.DriftFindingListQuery{}, apierr.InvalidInput(apierr.FieldViolation{Field: "limit", Reason: "must be a positive integer"})
		}
		if n < 1 || n > driftFindingListMaxLimit {
			return "", store.DriftFindingListQuery{}, apierr.InvalidInput(apierr.FieldViolation{Field: "limit", Reason: "must be between 1 and " + strconv.Itoa(driftFindingListMaxLimit)})
		}
		query.Limit = n
	}
	if rawStatus := values.Get("status"); rawStatus != "" {
		status := store.DriftFindingStatus(rawStatus)
		switch status {
		case store.DriftFindingStatusOpen, store.DriftFindingStatusResolved:
			query.Status = status
		default:
			return "", store.DriftFindingListQuery{}, apierr.InvalidInput(apierr.FieldViolation{Field: "status", Reason: "must be open or resolved"})
		}
	}
	if query.EnvironmentID != "" && query.ProjectID == "" {
		return "", store.DriftFindingListQuery{}, apierr.InvalidInput(apierr.FieldViolation{Field: "project_id", Reason: "is required when environment_id is supplied"})
	}
	if query.ServiceID != "" && (query.ProjectID == "" || query.EnvironmentID == "") {
		return "", store.DriftFindingListQuery{}, apierr.InvalidInput(apierr.FieldViolation{Field: "service_id", Reason: "requires project_id and environment_id"})
	}
	return orgID, query, nil
}

func parseAdminDokployReconcileTarget(r *http.Request, defaultOrganizationID, bodyOrganizationID string) (string, error) {
	queryOrganizationID := r.URL.Query().Get("organization_id")
	orgID := queryOrganizationID
	if orgID == "" {
		orgID = defaultOrganizationID
	}
	if bodyOrganizationID != "" {
		if queryOrganizationID != "" && bodyOrganizationID != queryOrganizationID {
			return "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must match query organization_id"})
		}
		if queryOrganizationID == "" && bodyOrganizationID != defaultOrganizationID {
			return "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must be supplied as a query parameter for cross-tenant reconciliation"})
		}
		orgID = bodyOrganizationID
	}
	parsed, err := domain.ParseID(orgID)
	if err != nil || parsed.Kind() != domain.KindOrganization {
		return "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must be a valid organization id"})
	}
	return orgID, nil
}

func parseAdminDokployImportTarget(r *http.Request, defaultOrganizationID, bodyOrganizationID, bodyYallaOrganizationID string) (string, string, error) {
	queryOrganizationID := r.URL.Query().Get("organization_id")
	orgID := queryOrganizationID
	if orgID == "" {
		orgID = defaultOrganizationID
	}
	if bodyOrganizationID != "" {
		if queryOrganizationID != "" && bodyOrganizationID != queryOrganizationID {
			return "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must match query organization_id"})
		}
		if queryOrganizationID == "" && bodyOrganizationID != defaultOrganizationID {
			return "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must be supplied as a query parameter for cross-tenant import"})
		}
		orgID = bodyOrganizationID
	}
	if err := validateOrganizationIDField("organization_id", orgID); err != nil {
		return "", "", err
	}

	yallaOrgID := bodyYallaOrganizationID
	if yallaOrgID == "" {
		yallaOrgID = orgID
	}
	if yallaOrgID != orgID {
		return "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "yalla_organization_id", Reason: "must match organization_id"})
	}
	if err := validateOrganizationIDField("yalla_organization_id", yallaOrgID); err != nil {
		return "", "", err
	}
	return orgID, yallaOrgID, nil
}

func validateAdminDokployImportBody(body adminDokployImportRequestBody) (string, string, string, error) {
	dokployOrgID := strings.TrimSpace(body.DokployOrganizationID)
	if dokployOrgID == "" {
		return "", "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "dokploy_organization_id", Reason: "required"})
	}
	assignmentDokployOrgID := strings.TrimSpace(body.AssignmentDokployOrgID)
	if assignmentDokployOrgID == "" {
		assignmentDokployOrgID = dokployOrgID
	}
	if assignmentDokployOrgID != dokployOrgID {
		return "", "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "assignment_dokploy_org_id", Reason: "must match dokploy_organization_id"})
	}
	idempotencyKey := strings.TrimSpace(body.IdempotencyKey)
	if idempotencyKey == "" {
		return "", "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "idempotency_key", Reason: "must not be blank"})
	}
	if len(idempotencyKey) > adminImportIdempotencyMaxLen {
		return "", "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "idempotency_key", Reason: "must be at most 128 characters"})
	}
	return dokployOrgID, assignmentDokployOrgID, idempotencyKey, nil
}

func validateOrganizationIDField(field, value string) error {
	parsed, err := domain.ParseID(value)
	if err != nil || parsed.Kind() != domain.KindOrganization {
		return apierr.InvalidInput(apierr.FieldViolation{Field: field, Reason: "must be a valid organization id"})
	}
	return nil
}
