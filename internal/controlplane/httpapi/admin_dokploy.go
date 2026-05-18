package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

var errNoDriftFindingReader = errors.New("httpapi: no drift finding reader configured")

const (
	driftFindingListDefaultLimit = 50
	driftFindingListMaxLimit     = 200
)

// DriftFindingReader is the narrow read port for GET
// /v1/admin/dokploy/drift. The store-backed adapter verifies the target
// organization and any supplied descendant filters before listing rows.
type DriftFindingReader interface {
	ListDriftFindings(ctx context.Context, organizationID string, query store.DriftFindingListQuery) ([]store.DriftFinding, error)
}

type listAdminDokployDriftPayload struct {
	Findings []driftFindingResource `json:"findings"`
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
