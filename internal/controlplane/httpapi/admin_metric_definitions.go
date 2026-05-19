package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoAdminMetricDefinitionManager = errors.New("httpapi: no admin metric definition manager configured")

// AdminMetricDefinitionUpsertInput is the validated write payload passed to the
// backoffice metric definition manager.
type AdminMetricDefinitionUpsertInput = store.UpsertMetricDefinitionInput

// AdminMetricDefinitionManager owns backoffice metric definition configuration.
type AdminMetricDefinitionManager interface {
	UpsertMetricDefinition(ctx context.Context, key string, in AdminMetricDefinitionUpsertInput, auditCtx store.AdminMetricDefinitionAuditContext) (store.MetricDefinition, error)
	GetMetricDefinition(ctx context.Context, key string) (store.MetricDefinition, error)
	DisableMetricDefinition(ctx context.Context, key string, auditCtx store.AdminMetricDefinitionAuditContext) (store.MetricDefinition, error)
}

type adminMetricDefinitionUpsertRequestBody struct {
	Unit                     string                          `json:"unit"`
	Source                   string                          `json:"source"`
	AggregationFunction      store.MetricAggregationFunction `json:"aggregation_function"`
	AggregationWindowSeconds int                             `json:"aggregation_window_seconds,omitempty"`
	BillingGrade             bool                            `json:"billing_grade"`
	RetentionDays            int                             `json:"retention_days,omitempty"`
	EnforcementLink          string                          `json:"enforcement_link,omitempty"`
	Enabled                  bool                            `json:"enabled"`
	AllowNewVersion          bool                            `json:"allow_new_version,omitempty"`
}

type adminMetricDefinitionPayload struct {
	ID                       string `json:"id"`
	Key                      string `json:"key"`
	Version                  int    `json:"version"`
	Unit                     string `json:"unit"`
	Source                   string `json:"source"`
	AggregationFunction      string `json:"aggregation_function"`
	AggregationWindowSeconds int    `json:"aggregation_window_seconds"`
	BillingGrade             bool   `json:"billing_grade"`
	RetentionDays            int    `json:"retention_days"`
	EnforcementLink          string `json:"enforcement_link"`
	Enabled                  bool   `json:"enabled"`
	Revision                 int64  `json:"revision"`
	PublishedAt              string `json:"published_at,omitempty"`
	SupersededAt             string `json:"superseded_at,omitempty"`
	CreatedAt                string `json:"created_at,omitempty"`
	UpdatedAt                string `json:"updated_at,omitempty"`
}

func upsertAdminMetricDefinitionHandler(manager AdminMetricDefinitionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminMetricDefinitionManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("metric_key"))
		var body adminMetricDefinitionUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminMetricDefinitionAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		def, err := manager.UpsertMetricDefinition(r.Context(), key, AdminMetricDefinitionUpsertInput{
			Unit:                     body.Unit,
			Source:                   body.Source,
			AggregationFunction:      body.AggregationFunction,
			AggregationWindowSeconds: body.AggregationWindowSeconds,
			BillingGrade:             body.BillingGrade,
			RetentionDays:            body.RetentionDays,
			EnforcementLink:          body.EnforcementLink,
			Enabled:                  body.Enabled,
			AllowNewVersion:          body.AllowNewVersion,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminMetricDefinitionResponse(def))
	}
}

func getAdminMetricDefinitionHandler(manager AdminMetricDefinitionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminMetricDefinitionManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("metric_key"))
		def, err := manager.GetMetricDefinition(r.Context(), key)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminMetricDefinitionResponse(def))
	}
}

func disableAdminMetricDefinitionHandler(manager AdminMetricDefinitionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminMetricDefinitionManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("metric_key"))
		auditCtx, err := adminMetricDefinitionAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		def, err := manager.DisableMetricDefinition(r.Context(), key, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminMetricDefinitionResponse(def))
	}
}

func adminMetricDefinitionAuditContext(r *http.Request) (store.AdminMetricDefinitionAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok {
		return store.AdminMetricDefinitionAuditContext{}, apierr.Unauthenticated("admin metric definition operation requires an authenticated principal")
	}
	return store.AdminMetricDefinitionAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     string(principal.Kind),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        strings.TrimSpace(r.Header.Get("X-Yalla-Reason")),
	}, nil
}

func adminMetricDefinitionResponse(def store.MetricDefinition) adminMetricDefinitionPayload {
	out := adminMetricDefinitionPayload{
		ID:                       def.ID,
		Key:                      def.Key,
		Version:                  def.Version,
		Unit:                     def.Unit,
		Source:                   def.Source,
		AggregationFunction:      string(def.AggregationFunction),
		AggregationWindowSeconds: def.AggregationWindowSeconds,
		BillingGrade:             def.BillingGrade,
		RetentionDays:            def.RetentionDays,
		EnforcementLink:          def.EnforcementLink,
		Enabled:                  def.Enabled,
		Revision:                 def.Revision,
		PublishedAt:              formatAdminMetricDefinitionTime(def.PublishedAt),
		CreatedAt:                formatAdminMetricDefinitionTime(def.CreatedAt),
		UpdatedAt:                formatAdminMetricDefinitionTime(def.UpdatedAt),
	}
	if def.SupersededAt != nil {
		out.SupersededAt = formatAdminMetricDefinitionTime(*def.SupersededAt)
	}
	return out
}

func formatAdminMetricDefinitionTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
