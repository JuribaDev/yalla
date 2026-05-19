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

var errNoAdminOveragePolicyManager = errors.New("httpapi: no admin overage policy manager configured")

// AdminOveragePolicyUpsertInput is the validated write payload passed to the
// backoffice overage policy manager.
type AdminOveragePolicyUpsertInput = store.UpsertOveragePolicyInput

// AdminOveragePolicyManager owns backoffice overage policy configuration.
type AdminOveragePolicyManager interface {
	UpsertOveragePolicy(ctx context.Context, in AdminOveragePolicyUpsertInput, auditCtx store.AdminOveragePolicyAuditContext) (store.OveragePolicy, error)
}

type adminOveragePolicyUpsertRequestBody struct {
	Mode        store.OveragePolicyMode `json:"mode"`
	EffectiveAt time.Time               `json:"effective_at"`
}

type adminOveragePolicyPayload struct {
	ID             string `json:"id"`
	Scope          string `json:"scope"`
	PlanID         string `json:"plan_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	EntitlementKey string `json:"entitlement_key"`
	Mode           string `json:"mode"`
	EffectiveAt    string `json:"effective_at"`
	Reason         string `json:"reason,omitempty"`
	Revision       int64  `json:"revision"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

func upsertAdminGlobalOveragePolicyHandler(manager AdminOveragePolicyManager) http.HandlerFunc {
	return upsertAdminOveragePolicyHandler(manager, store.OveragePolicyScopeGlobal)
}

func upsertAdminPlanOveragePolicyHandler(manager AdminOveragePolicyManager) http.HandlerFunc {
	return upsertAdminOveragePolicyHandler(manager, store.OveragePolicyScopePlan)
}

func upsertAdminOrganizationOveragePolicyHandler(manager AdminOveragePolicyManager) http.HandlerFunc {
	return upsertAdminOveragePolicyHandler(manager, store.OveragePolicyScopeOrganization)
}

func upsertAdminOveragePolicyHandler(manager AdminOveragePolicyManager, scope store.OveragePolicyScope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminOveragePolicyManager))
			return
		}
		var body adminOveragePolicyUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in := AdminOveragePolicyUpsertInput{
			Scope:          scope,
			PlanID:         strings.TrimSpace(r.PathValue("plan_id")),
			OrganizationID: strings.TrimSpace(r.PathValue("org_id")),
			EntitlementKey: strings.TrimSpace(r.PathValue("entitlement_key")),
			Mode:           body.Mode,
			EffectiveAt:    body.EffectiveAt,
		}
		if err := validateAdminOveragePolicyInput(in); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminOveragePolicyAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		policy, err := manager.UpsertOveragePolicy(r.Context(), in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminOveragePolicyResponse(policy))
	}
}

func adminOveragePolicyAuditContext(r *http.Request) (store.AdminOveragePolicyAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminOveragePolicyAuditContext{}, apierr.Unauthenticated("admin overage policy operation requires an authenticated principal")
	}
	return store.AdminOveragePolicyAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        strings.TrimSpace(r.Header.Get("X-Yalla-Reason")),
	}, nil
}

func validateAdminOveragePolicyInput(in AdminOveragePolicyUpsertInput) error {
	var violations []apierr.FieldViolation
	if !validAdminOveragePolicyScope(in.Scope) {
		violations = append(violations, apierr.FieldViolation{Field: "scope", Reason: "must be global, plan, or organization"})
	}
	if !validAdminEntitlementKey(in.EntitlementKey) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if !validAdminOverageBehavior(string(in.Mode)) {
		violations = append(violations, apierr.FieldViolation{Field: "mode", Reason: "must be allow, warn, block, or require_admin_review"})
	}
	if in.EffectiveAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "effective_at", Reason: "must not be zero"})
	}
	switch in.Scope {
	case store.OveragePolicyScopeGlobal:
		if in.PlanID != "" || in.OrganizationID != "" {
			violations = append(violations, apierr.FieldViolation{Field: "scope", Reason: "global policies must not include a target id"})
		}
	case store.OveragePolicyScopePlan:
		if strings.TrimSpace(in.PlanID) == "" {
			violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
		}
	case store.OveragePolicyScopeOrganization:
		if strings.TrimSpace(in.OrganizationID) == "" {
			violations = append(violations, apierr.FieldViolation{Field: "org_id", Reason: "must not be blank"})
		}
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func adminOveragePolicyResponse(policy store.OveragePolicy) adminOveragePolicyPayload {
	out := adminOveragePolicyPayload{
		ID:             policy.ID,
		Scope:          string(policy.Scope),
		EntitlementKey: policy.EntitlementKey,
		Mode:           string(policy.Mode),
		EffectiveAt:    policy.EffectiveAt.UTC().Format(time.RFC3339Nano),
		Reason:         policy.Reason,
		Revision:       policy.Revision,
	}
	if policy.PlanID != nil {
		out.PlanID = *policy.PlanID
	}
	if policy.OrganizationID != nil {
		out.OrganizationID = *policy.OrganizationID
	}
	if !policy.CreatedAt.IsZero() {
		out.CreatedAt = policy.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !policy.UpdatedAt.IsZero() {
		out.UpdatedAt = policy.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func validAdminOveragePolicyScope(s store.OveragePolicyScope) bool {
	switch s {
	case store.OveragePolicyScopeGlobal, store.OveragePolicyScopePlan, store.OveragePolicyScopeOrganization:
		return true
	default:
		return false
	}
}
