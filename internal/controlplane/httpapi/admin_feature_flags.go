package httpapi

import (
	"context"
	"encoding/json"
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

var errNoAdminFeatureFlagManager = errors.New("httpapi: no admin feature flag manager configured")

// AdminFeatureFlagUpsertInput is the validated write payload passed to the
// backoffice feature-flag manager.
type AdminFeatureFlagUpsertInput = store.UpsertFeatureFlagInput

// AdminFeatureFlagEvaluateInput is the deterministic evaluation context.
type AdminFeatureFlagEvaluateInput = store.FeatureFlagEvaluationContext

// AdminFeatureFlagManager owns backoffice feature flag configuration.
type AdminFeatureFlagManager interface {
	UpsertFeatureFlag(ctx context.Context, key string, in AdminFeatureFlagUpsertInput, auditCtx store.AdminFeatureFlagAuditContext) (store.FeatureFlag, error)
	GetFeatureFlag(ctx context.Context, key string) (store.FeatureFlag, error)
	EvaluateFeatureFlag(ctx context.Context, key string, evalCtx AdminFeatureFlagEvaluateInput, auditCtx store.AdminFeatureFlagAuditContext) (store.FeatureFlagEvaluation, error)
}

type adminFeatureFlagUpsertRequestBody struct {
	ValueType         store.FeatureFlagValueType `json:"value_type"`
	DefaultValue      json.RawMessage            `json:"default_value"`
	TargetingRules    []store.FeatureFlagRule    `json:"targeting_rules,omitempty"`
	RolloutPercentage int                        `json:"rollout_percentage,omitempty"`
	AdminSensitive    bool                       `json:"admin_sensitive"`
	Enabled           bool                       `json:"enabled"`
}

type adminFeatureFlagPayload struct {
	ID                string                  `json:"id"`
	FlagKey           string                  `json:"flag_key"`
	ValueType         string                  `json:"value_type"`
	DefaultValue      json.RawMessage         `json:"default_value"`
	TargetingRules    []store.FeatureFlagRule `json:"targeting_rules"`
	RolloutPercentage int                     `json:"rollout_percentage"`
	AdminSensitive    bool                    `json:"admin_sensitive"`
	Enabled           bool                    `json:"enabled"`
	Revision          int64                   `json:"revision"`
	CreatedAt         string                  `json:"created_at,omitempty"`
	UpdatedAt         string                  `json:"updated_at,omitempty"`
}

func upsertAdminFeatureFlagHandler(manager AdminFeatureFlagManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminFeatureFlagManager))
			return
		}
		var body adminFeatureFlagUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminFeatureFlagAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		flag, err := manager.UpsertFeatureFlag(r.Context(), strings.TrimSpace(r.PathValue("flag_key")), AdminFeatureFlagUpsertInput{
			ValueType:         body.ValueType,
			DefaultValue:      body.DefaultValue,
			TargetingRules:    body.TargetingRules,
			RolloutPercentage: body.RolloutPercentage,
			AdminSensitive:    body.AdminSensitive,
			Enabled:           body.Enabled,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminFeatureFlagResponse(flag))
	}
}

func getAdminFeatureFlagHandler(manager AdminFeatureFlagManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminFeatureFlagManager))
			return
		}
		flag, err := manager.GetFeatureFlag(r.Context(), strings.TrimSpace(r.PathValue("flag_key")))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminFeatureFlagResponse(flag))
	}
}

func evaluateAdminFeatureFlagHandler(manager AdminFeatureFlagManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminFeatureFlagManager))
			return
		}
		var body AdminFeatureFlagEvaluateInput
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminFeatureFlagAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := manager.EvaluateFeatureFlag(r.Context(), strings.TrimSpace(r.PathValue("flag_key")), body, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func adminFeatureFlagAuditContext(r *http.Request) (store.AdminFeatureFlagAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminFeatureFlagAuditContext{}, apierr.Unauthenticated("admin feature flag operation requires an authenticated principal")
	}
	return store.AdminFeatureFlagAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        r.Header.Get("X-Yalla-Reason"),
	}, nil
}

func adminFeatureFlagResponse(flag store.FeatureFlag) adminFeatureFlagPayload {
	out := adminFeatureFlagPayload{
		ID:                flag.ID,
		FlagKey:           flag.FlagKey,
		ValueType:         string(flag.ValueType),
		DefaultValue:      flag.DefaultValue,
		TargetingRules:    flag.TargetingRules,
		RolloutPercentage: flag.RolloutPercentage,
		AdminSensitive:    flag.AdminSensitive,
		Enabled:           flag.Enabled,
		Revision:          flag.Revision,
	}
	if out.TargetingRules == nil {
		out.TargetingRules = []store.FeatureFlagRule{}
	}
	if !flag.CreatedAt.IsZero() {
		out.CreatedAt = flag.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !flag.UpdatedAt.IsZero() {
		out.UpdatedAt = flag.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}
