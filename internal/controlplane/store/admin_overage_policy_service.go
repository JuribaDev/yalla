package store

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const adminOveragePolicyResourceKind = "overage_policy"

// AdminOveragePolicyAuditContext carries operator identity for overage policy
// changes.
type AdminOveragePolicyAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminOveragePolicyService composes global/plan/org policy writes with audit.
type AdminOveragePolicyService struct {
	store    *Store
	orgs     *OrganizationRepository
	plans    *PricingPlanRepository
	policies *OveragePolicyRepository
	audit    *AuditRepository
}

// NewAdminOveragePolicyService builds an audited overage policy manager.
func NewAdminOveragePolicyService(s *Store, orgs *OrganizationRepository, plans *PricingPlanRepository, policies *OveragePolicyRepository, audit *AuditRepository) (*AdminOveragePolicyService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if plans == nil {
		return nil, errors.New("store: nil pricing plan repository")
	}
	if policies == nil {
		return nil, errors.New("store: nil overage policy repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminOveragePolicyService{store: s, orgs: orgs, plans: plans, policies: policies, audit: audit}, nil
}

// UpsertOveragePolicy creates or replaces one effective policy version.
func (svc *AdminOveragePolicyService) UpsertOveragePolicy(ctx context.Context, in UpsertOveragePolicyInput, auditCtx AdminOveragePolicyAuditContext) (OveragePolicy, error) {
	auditCtx, err := validateAdminOveragePolicyAuditContext(auditCtx)
	if err != nil {
		return OveragePolicy{}, err
	}
	var out OveragePolicy
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		switch in.Scope {
		case OveragePolicyScopePlan:
			if _, err := svc.plans.Get(ctx, tx, in.PlanID); err != nil {
				return err
			}
		case OveragePolicyScopeOrganization:
			if _, err := svc.orgs.Get(ctx, tx, in.OrganizationID); err != nil {
				return err
			}
		}
		policy, err := svc.policies.Upsert(ctx, tx, in, auditCtx)
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminOveragePolicyAuditEvent(auditCtx, policy)); err != nil {
			return err
		}
		out = policy
		return nil
	})
	return out, err
}

func validateAdminOveragePolicyAuditContext(in AdminOveragePolicyAuditContext) (AdminOveragePolicyAuditContext, error) {
	out := AdminOveragePolicyAuditContext{
		ActorOrgID:    strings.TrimSpace(in.ActorOrgID),
		ActorID:       strings.TrimSpace(in.ActorID),
		ActorKind:     strings.TrimSpace(in.ActorKind),
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
		Reason:        strings.TrimSpace(in.Reason),
	}
	var violations []apierr.FieldViolation
	if out.ActorOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_org_id", Reason: "must not be blank"})
	}
	if out.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must not be blank"})
	}
	if out.ActorKind == "" {
		out.ActorKind = "user"
	}
	if out.RequestID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must not be blank"})
	}
	if out.CorrelationID == "" {
		out.CorrelationID = out.RequestID
	}
	if len(violations) > 0 {
		return AdminOveragePolicyAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminOveragePolicyAuditEvent(auditCtx AdminOveragePolicyAuditContext, policy OveragePolicy) AuditEvent {
	metadata := map[string]string{
		"scope":           string(policy.Scope),
		"entitlement_key": policy.EntitlementKey,
		"mode":            string(policy.Mode),
		"effective_at":    policy.EffectiveAt.UTC().Format(timeFormatRFC3339Nano()),
		"revision":        strconv.FormatInt(policy.Revision, 10),
	}
	if policy.PlanID != nil {
		metadata["plan_id"] = *policy.PlanID
	}
	if policy.OrganizationID != nil {
		metadata["organization_id"] = *policy.OrganizationID
	}
	if policy.Reason != "" {
		metadata["reason"] = policy.Reason
	}
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditEventActorKind(auditCtx.ActorKind),
		Action:         "admin.overage_policy.upsert",
		ResourceKind:   adminOveragePolicyResourceKind,
		ResourceID:     policy.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "allowed",
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata:       metadata,
	}
}

func timeFormatRFC3339Nano() string { return "2006-01-02T15:04:05.999999999Z07:00" }
