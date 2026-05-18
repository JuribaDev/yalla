package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoPreviewCreator = errors.New("httpapi: no preview creator configured")

// PreviewCreator is the narrow store port POST
// /v1/projects/{project_id}/previews depends on.
type PreviewCreator interface {
	Create(ctx context.Context, in store.CreatePreviewEnvironmentInput) (store.PreviewEnvironment, error)
}

type createPreviewRequest struct {
	PreviewID           string     `json:"preview_id"`
	EnvironmentID       string     `json:"environment_id"`
	SourceEnvironmentID string     `json:"source_environment_id"`
	Slug                string     `json:"slug"`
	DisplayName         string     `json:"display_name"`
	ChangeRef           string     `json:"change_ref"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

type createPreviewPayload struct {
	Preview previewEnvironment `json:"preview"`
}

type previewEnvironment struct {
	ID                  string    `json:"id"`
	OrganizationID      string    `json:"organization_id"`
	ProjectID           string    `json:"project_id"`
	EnvironmentID       string    `json:"environment_id"`
	SourceEnvironmentID string    `json:"source_environment_id"`
	DisplayName         string    `json:"display_name"`
	ChangeRef           string    `json:"change_ref"`
	Status              string    `json:"status"`
	ExpiresAt           *string   `json:"expires_at,omitempty"`
	DeletionScheduledAt *string   `json:"deletion_scheduled_at,omitempty"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func previewEnvironmentOf(p store.PreviewEnvironment) previewEnvironment {
	out := previewEnvironment{
		ID:                  p.ID,
		OrganizationID:      p.OrganizationID,
		ProjectID:           p.ProjectID,
		EnvironmentID:       p.EnvironmentID,
		SourceEnvironmentID: p.SourceEnvironmentID,
		DisplayName:         p.DisplayName,
		ChangeRef:           p.ChangeRef,
		Status:              p.Status,
		Version:             p.Version,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	}
	if p.ExpiresAt != nil {
		expires := p.ExpiresAt.UTC().Format(time.RFC3339Nano)
		out.ExpiresAt = &expires
	}
	if p.DeletionScheduledAt != nil {
		scheduled := p.DeletionScheduledAt.UTC().Format(time.RFC3339Nano)
		out.DeletionScheduledAt = &scheduled
	}
	return out
}

func createPreviewHandler(creator PreviewCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPreviewCreator))
			return
		}

		var req createPreviewRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		preview, err := creator.Create(r.Context(), store.CreatePreviewEnvironmentInput{
			OrganizationID:      p.OrganizationID,
			ProjectID:           r.PathValue("project_id"),
			PreviewID:           req.PreviewID,
			EnvironmentID:       req.EnvironmentID,
			SourceEnvironmentID: req.SourceEnvironmentID,
			Slug:                req.Slug,
			DisplayName:         req.DisplayName,
			ChangeRef:           req.ChangeRef,
			ExpiresAt:           req.ExpiresAt,
			ActorID:             p.ID,
			ActorKind:           string(p.Kind),
			ActorOrgID:          p.OrganizationID,
			RequestID:           correlation.RequestID,
			CorrelationID:       correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createPreviewPayload{
			Preview: previewEnvironmentOf(preview),
		})
	}
}
