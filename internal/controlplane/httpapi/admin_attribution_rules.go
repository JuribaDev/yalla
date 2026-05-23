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

var errNoAdminAttributionRuleManager = errors.New("httpapi: no admin attribution rule manager configured")

// AdminAttributionRuleUpsertInput is the validated write payload passed to the
// backoffice attribution-rule manager.
type AdminAttributionRuleUpsertInput = store.UpsertAttributionRuleInput

// AdminAttributionRuleDryRunInput is the side-effect-free dry-run payload.
type AdminAttributionRuleDryRunInput = store.AttributionDryRunInput

// AdminAttributionRuleDryRunResult is the stable dry-run report payload.
type AdminAttributionRuleDryRunResult = store.AttributionDryRunResult

// AdminAttributionRuleManager owns backoffice attribution rule configuration.
type AdminAttributionRuleManager interface {
	UpsertAttributionRule(ctx context.Context, key string, in AdminAttributionRuleUpsertInput, auditCtx store.AdminAttributionRuleAuditContext) (store.AttributionRule, error)
	GetAttributionRule(ctx context.Context, key string) (store.AttributionRule, error)
	DryRunAttributionRules(ctx context.Context, in AdminAttributionRuleDryRunInput) (AdminAttributionRuleDryRunResult, error)
}

type adminAttributionRuleUpsertRequestBody struct {
	Source              store.AttributionRuleSource     `json:"source"`
	Priority            int                             `json:"priority,omitempty"`
	MatchKind           store.AttributionRuleMatchKind  `json:"match_kind"`
	LabelKey            string                          `json:"label_key,omitempty"`
	Pattern             string                          `json:"pattern,omitempty"`
	DokployResource     string                          `json:"dokploy_resource,omitempty"`
	MinConfidence       store.AttributionRuleConfidence `json:"min_confidence,omitempty"`
	QuarantineUnmatched bool                            `json:"quarantine_unmatched"`
	QuarantineAmbiguous bool                            `json:"quarantine_ambiguous"`
	Enabled             bool                            `json:"enabled"`
}

type adminAttributionRulePayload struct {
	ID                  string `json:"id"`
	RuleKey             string `json:"rule_key"`
	Source              string `json:"source"`
	Priority            int    `json:"priority"`
	MatchKind           string `json:"match_kind"`
	LabelKey            string `json:"label_key,omitempty"`
	Pattern             string `json:"pattern,omitempty"`
	DokployResource     string `json:"dokploy_resource,omitempty"`
	MinConfidence       string `json:"min_confidence"`
	QuarantineUnmatched bool   `json:"quarantine_unmatched"`
	QuarantineAmbiguous bool   `json:"quarantine_ambiguous"`
	Enabled             bool   `json:"enabled"`
	Revision            int64  `json:"revision"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

func upsertAdminAttributionRuleHandler(manager AdminAttributionRuleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminAttributionRuleManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("rule_key"))
		var body adminAttributionRuleUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminAttributionRuleAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		rule, err := manager.UpsertAttributionRule(r.Context(), key, AdminAttributionRuleUpsertInput{
			Source:              body.Source,
			Priority:            body.Priority,
			MatchKind:           body.MatchKind,
			LabelKey:            body.LabelKey,
			Pattern:             body.Pattern,
			DokployResource:     body.DokployResource,
			MinConfidence:       body.MinConfidence,
			QuarantineUnmatched: body.QuarantineUnmatched,
			QuarantineAmbiguous: body.QuarantineAmbiguous,
			Enabled:             body.Enabled,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminAttributionRuleResponse(rule))
	}
}

func getAdminAttributionRuleHandler(manager AdminAttributionRuleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminAttributionRuleManager))
			return
		}
		rule, err := manager.GetAttributionRule(r.Context(), strings.TrimSpace(r.PathValue("rule_key")))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminAttributionRuleResponse(rule))
	}
}

func dryRunAdminAttributionRulesHandler(manager AdminAttributionRuleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminAttributionRuleManager))
			return
		}
		var body AdminAttributionRuleDryRunInput
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := manager.DryRunAttributionRules(r.Context(), body)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func adminAttributionRuleAuditContext(r *http.Request) (store.AdminAttributionRuleAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminAttributionRuleAuditContext{}, apierr.Unauthenticated("admin attribution rule operation requires an authenticated principal")
	}
	return store.AdminAttributionRuleAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        r.Header.Get("X-Yalla-Reason"),
	}, nil
}

func adminAttributionRuleResponse(rule store.AttributionRule) adminAttributionRulePayload {
	out := adminAttributionRulePayload{
		ID:                  rule.ID,
		RuleKey:             rule.RuleKey,
		Source:              string(rule.Source),
		Priority:            rule.Priority,
		MatchKind:           string(rule.MatchKind),
		LabelKey:            rule.LabelKey,
		Pattern:             rule.Pattern,
		DokployResource:     rule.DokployResource,
		MinConfidence:       string(rule.MinConfidence),
		QuarantineUnmatched: rule.QuarantineUnmatched,
		QuarantineAmbiguous: rule.QuarantineAmbiguous,
		Enabled:             rule.Enabled,
		Revision:            rule.Revision,
	}
	if !rule.CreatedAt.IsZero() {
		out.CreatedAt = rule.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !rule.UpdatedAt.IsZero() {
		out.UpdatedAt = rule.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}
