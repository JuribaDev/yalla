package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// OveragePolicyScope identifies the layer where an overage decision applies.
type OveragePolicyScope string

const (
	// OveragePolicyScopeGlobal applies to every plan and organization unless a narrower policy exists.
	OveragePolicyScopeGlobal OveragePolicyScope = "global"
	// OveragePolicyScopePlan applies to one pricing plan version.
	OveragePolicyScopePlan OveragePolicyScope = "plan"
	// OveragePolicyScopeOrganization applies to one organization and has highest runtime precedence.
	OveragePolicyScopeOrganization OveragePolicyScope = "organization"
)

func (s OveragePolicyScope) valid() bool {
	switch s {
	case OveragePolicyScopeGlobal, OveragePolicyScopePlan, OveragePolicyScopeOrganization:
		return true
	default:
		return false
	}
}

// OveragePolicyMode is the published decision behavior for metered overage.
type OveragePolicyMode string

const (
	// OveragePolicyModeAllow permits overage without warning.
	OveragePolicyModeAllow OveragePolicyMode = "allow"
	// OveragePolicyModeWarn permits overage while recording a warning decision.
	OveragePolicyModeWarn OveragePolicyMode = "warn"
	// OveragePolicyModeBlock marks overage as blocked for runtime/billing decisions.
	OveragePolicyModeBlock OveragePolicyMode = "block"
	// OveragePolicyModeRequireAdminReview marks overage for manual review.
	OveragePolicyModeRequireAdminReview OveragePolicyMode = "require_admin_review"
)

func (m OveragePolicyMode) valid() bool {
	switch m {
	case OveragePolicyModeAllow, OveragePolicyModeWarn, OveragePolicyModeBlock, OveragePolicyModeRequireAdminReview:
		return true
	default:
		return false
	}
}

func (m OveragePolicyMode) restrictive() bool {
	switch m {
	case OveragePolicyModeBlock, OveragePolicyModeRequireAdminReview:
		return true
	default:
		return false
	}
}

// OveragePolicy is one versioned published policy row.
type OveragePolicy struct {
	ID             string
	Scope          OveragePolicyScope
	PlanID         *string
	OrganizationID *string
	EntitlementKey string
	Mode           OveragePolicyMode
	EffectiveAt    time.Time
	Reason         string
	ActorID        string
	ActorKind      string
	RequestID      string
	CorrelationID  string
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpsertOveragePolicyInput is the backoffice write contract.
type UpsertOveragePolicyInput struct {
	Scope          OveragePolicyScope
	PlanID         string
	OrganizationID string
	EntitlementKey string
	Mode           OveragePolicyMode
	EffectiveAt    time.Time
}

// OveragePolicyRepository persists and resolves published overage policy.
type OveragePolicyRepository struct{}

// NewOveragePolicyRepository returns a stateless overage policy repository.
func NewOveragePolicyRepository() *OveragePolicyRepository { return &OveragePolicyRepository{} }

const overagePolicyColumns = `id, scope, plan_id, organization_id, entitlement_key, mode, effective_at, reason, actor_id, actor_kind, request_id, correlation_id, revision, created_at, updated_at`

// Upsert inserts a new effective policy version or replaces the exact same
// effective-at version for a scope target.
func (r *OveragePolicyRepository) Upsert(ctx context.Context, tx *Tx, in UpsertOveragePolicyInput, auditCtx AdminOveragePolicyAuditContext) (OveragePolicy, error) {
	if tx == nil {
		return OveragePolicy{}, apierr.Internal(errors.New("store: OveragePolicyRepository.Upsert called with a nil transaction"))
	}
	policy, err := buildOveragePolicyToUpsert(in, auditCtx)
	if err != nil {
		return OveragePolicy{}, err
	}
	policy.ID, err = newOpaqueStoreID("ovpol")
	if err != nil {
		return OveragePolicy{}, apierr.Internal(err)
	}
	revision, err := r.nextRevision(ctx, tx, policy)
	if err != nil {
		return OveragePolicy{}, err
	}
	policy.Revision = revision
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_overage_policies
		    (id, scope, plan_id, organization_id, entitlement_key, mode, effective_at, reason,
		     actor_id, actor_kind, request_id, correlation_id, revision)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (scope, plan_id, organization_id, entitlement_key, effective_at) DO UPDATE
		    SET mode = EXCLUDED.mode,
		        reason = EXCLUDED.reason,
		        actor_id = EXCLUDED.actor_id,
		        actor_kind = EXCLUDED.actor_kind,
		        request_id = EXCLUDED.request_id,
		        correlation_id = EXCLUDED.correlation_id,
		        revision = EXCLUDED.revision
		 RETURNING `+overagePolicyColumns,
		policy.ID, policy.Scope, policy.PlanID, policy.OrganizationID, policy.EntitlementKey,
		policy.Mode, policy.EffectiveAt, policy.Reason, policy.ActorID, policy.ActorKind,
		policy.RequestID, policy.CorrelationID, policy.Revision,
	)
	out, err := scanOveragePolicy(row)
	if err != nil {
		return OveragePolicy{}, mapWriteError(err, "upsert overage policy")
	}
	return out, nil
}

// ResolveRuntime returns the effective policy for an entitlement at time at.
// Precedence is organization override, then plan override, then global default.
func (r *OveragePolicyRepository) ResolveRuntime(ctx context.Context, q Querier, organizationID, planID, entitlementKey string, at time.Time) (OveragePolicy, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	row := q.QueryRow(ctx,
		`SELECT `+overagePolicyColumns+`
		   FROM admin_overage_policies
		  WHERE entitlement_key = $1
		    AND effective_at <= $2
		    AND (
		         (scope = 'organization' AND organization_id = $3)
		      OR (scope = 'plan' AND plan_id = $4)
		      OR (scope = 'global')
		    )
		  ORDER BY
		    CASE scope WHEN 'organization' THEN 2 WHEN 'plan' THEN 1 ELSE 0 END DESC,
		    effective_at DESC,
		    created_at DESC,
		    id DESC
		  LIMIT 1`,
		strings.TrimSpace(entitlementKey), at, strings.TrimSpace(organizationID), strings.TrimSpace(planID),
	)
	out, err := scanOveragePolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OveragePolicy{}, apierr.NotFound("overage_policy", entitlementKey)
	}
	if err != nil {
		return OveragePolicy{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListRuntimePublished returns policies effective at at in deterministic order.
func (r *OveragePolicyRepository) ListRuntimePublished(ctx context.Context, q Querier, at time.Time) ([]OveragePolicy, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	rows, err := q.Query(ctx,
		`SELECT `+overagePolicyColumns+`
		   FROM admin_overage_policies
		  WHERE effective_at <= $1
		  ORDER BY scope, COALESCE(plan_id, ''), COALESCE(organization_id, ''), entitlement_key, effective_at DESC, id DESC`,
		at,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []OveragePolicy
	for rows.Next() {
		policy, scanErr := scanOveragePolicy(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *OveragePolicyRepository) nextRevision(ctx context.Context, tx *Tx, policy OveragePolicy) (int64, error) {
	var revision int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(max(revision), 0) + 1
		   FROM admin_overage_policies
		  WHERE scope = $1
		    AND entitlement_key = $2
		    AND COALESCE(plan_id, '') = COALESCE($3, '')
		    AND COALESCE(organization_id, '') = COALESCE($4, '')`,
		policy.Scope, policy.EntitlementKey, policy.PlanID, policy.OrganizationID,
	).Scan(&revision)
	if err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return revision, nil
}

func buildOveragePolicyToUpsert(in UpsertOveragePolicyInput, auditCtx AdminOveragePolicyAuditContext) (OveragePolicy, error) {
	scope := OveragePolicyScope(strings.TrimSpace(string(in.Scope)))
	key := strings.TrimSpace(in.EntitlementKey)
	mode := OveragePolicyMode(strings.TrimSpace(string(in.Mode)))
	effectiveAt := in.EffectiveAt.UTC()
	var violations []apierr.FieldViolation
	if !scope.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "scope", Reason: "must be global, plan, or organization"})
	}
	if !validEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if !mode.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "mode", Reason: "must be allow, warn, block, or require_admin_review"})
	}
	if effectiveAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "effective_at", Reason: "must not be zero"})
	}
	planID := cleanPolicyTarget(in.PlanID)
	orgID := cleanPolicyTarget(in.OrganizationID)
	switch scope {
	case OveragePolicyScopeGlobal:
		if planID != nil || orgID != nil {
			violations = append(violations, apierr.FieldViolation{Field: "scope", Reason: "global policies must not include plan_id or organization_id"})
		}
	case OveragePolicyScopePlan:
		if planID == nil || orgID != nil {
			violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "plan policies require only plan_id"})
		}
	case OveragePolicyScopeOrganization:
		if orgID == nil || planID != nil {
			violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "organization policies require only organization_id"})
		}
	}
	if mode.restrictive() && effectiveAt.Before(time.Now().UTC()) {
		violations = append(violations, apierr.FieldViolation{Field: "effective_at", Reason: "restrictive policies must not be retroactive"})
	}
	reason := output.NewRedactor().Redact(strings.TrimSpace(auditCtx.Reason))
	if reason != "" {
		switch {
		case !utf8.ValidString(reason):
			violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be valid UTF-8"})
		case len(reason) > 500:
			violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be at most 500 bytes"})
		}
	}
	if len(violations) > 0 {
		return OveragePolicy{}, apierr.InvalidInput(violations...)
	}
	return OveragePolicy{
		Scope:          scope,
		PlanID:         planID,
		OrganizationID: orgID,
		EntitlementKey: key,
		Mode:           mode,
		EffectiveAt:    effectiveAt,
		Reason:         reason,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
	}, nil
}

func cleanPolicyTarget(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func scanOveragePolicy(row pgx.Row) (OveragePolicy, error) {
	var policy OveragePolicy
	err := row.Scan(
		&policy.ID, &policy.Scope, &policy.PlanID, &policy.OrganizationID,
		&policy.EntitlementKey, &policy.Mode, &policy.EffectiveAt, &policy.Reason,
		&policy.ActorID, &policy.ActorKind, &policy.RequestID, &policy.CorrelationID,
		&policy.Revision, &policy.CreatedAt, &policy.UpdatedAt,
	)
	return policy, err
}
