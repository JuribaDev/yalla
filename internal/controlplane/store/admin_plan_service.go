package store

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const adminPlanResourceKind = "plan"

// AdminPlanAuditContext carries the operator/request identity recorded next to
// every backoffice plan mutation.
type AdminPlanAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
}

// AdminPlanService composes global pricing-plan mutations with immutable
// audit records. Plan catalog rows are operator-owned global configuration, so
// audit rows are filed under the admin principal's organization.
type AdminPlanService struct {
	store *Store
	orgs  *OrganizationRepository
	plans *PricingPlanRepository
	audit *AuditRepository
}

// NewAdminPlanService builds an audited backoffice plan manager.
func NewAdminPlanService(s *Store, orgs *OrganizationRepository, plans *PricingPlanRepository, audit *AuditRepository) (*AdminPlanService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if plans == nil {
		return nil, errors.New("store: nil pricing plan repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminPlanService{store: s, orgs: orgs, plans: plans, audit: audit}, nil
}

// CreatePlan creates a draft plan version and records the admin action.
func (svc *AdminPlanService) CreatePlan(ctx context.Context, in CreatePlanInput, auditCtx AdminPlanAuditContext) (Plan, error) {
	auditCtx, err := validateAdminPlanAuditContext(auditCtx)
	if err != nil {
		return Plan{}, err
	}
	in.Status = PlanStatusDraft
	var out Plan
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		plan, err := svc.plans.Create(ctx, tx, in)
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminPlanAuditEvent(auditCtx, "admin.plan.create", plan, "create")); err != nil {
			return err
		}
		out = plan
		return nil
	})
	return out, err
}

// EditPlan creates the next draft version without changing the active version.
func (svc *AdminPlanService) EditPlan(ctx context.Context, id string, in UpdatePlanInput, auditCtx AdminPlanAuditContext) (Plan, error) {
	auditCtx, err := validateAdminPlanAuditContext(auditCtx)
	if err != nil {
		return Plan{}, err
	}
	in.Status = PlanStatusDraft
	var out Plan
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		plan, err := svc.plans.CreateDraftFrom(ctx, tx, id, in)
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminPlanAuditEvent(auditCtx, "admin.plan.edit", plan, "edit")); err != nil {
			return err
		}
		out = plan
		return nil
	})
	return out, err
}

// PublishPlan promotes a draft to active.
func (svc *AdminPlanService) PublishPlan(ctx context.Context, id string, auditCtx AdminPlanAuditContext) (Plan, error) {
	return svc.planLifecycle(ctx, id, auditCtx, "admin.plan.publish", "publish", svc.plans.Publish)
}

// ArchivePlan archives a plan version.
func (svc *AdminPlanService) ArchivePlan(ctx context.Context, id string, auditCtx AdminPlanAuditContext) (Plan, error) {
	return svc.planLifecycle(ctx, id, auditCtx, "admin.plan.archive", "archive", svc.plans.Archive)
}

// RollbackPlan publishes a new active version copied from a historical plan.
func (svc *AdminPlanService) RollbackPlan(ctx context.Context, id string, auditCtx AdminPlanAuditContext) (Plan, error) {
	return svc.planLifecycle(ctx, id, auditCtx, "admin.plan.rollback", "rollback", svc.plans.Rollback)
}

func (svc *AdminPlanService) planLifecycle(ctx context.Context, id string, auditCtx AdminPlanAuditContext, action, operation string, run func(context.Context, *Tx, string) (Plan, error)) (Plan, error) {
	auditCtx, err := validateAdminPlanAuditContext(auditCtx)
	if err != nil {
		return Plan{}, err
	}
	var out Plan
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		plan, err := run(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminPlanAuditEvent(auditCtx, action, plan, operation)); err != nil {
			return err
		}
		out = plan
		return nil
	})
	return out, err
}

func validateAdminPlanAuditContext(in AdminPlanAuditContext) (AdminPlanAuditContext, error) {
	in.ActorOrgID = strings.TrimSpace(in.ActorOrgID)
	in.ActorID = strings.TrimSpace(in.ActorID)
	in.ActorKind = strings.TrimSpace(in.ActorKind)
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.CorrelationID = strings.TrimSpace(in.CorrelationID)
	var violations []apierr.FieldViolation
	if in.ActorOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_org_id", Reason: "must not be blank"})
	}
	if in.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must not be blank"})
	}
	if in.ActorKind == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_kind", Reason: "must not be blank"})
	}
	if in.RequestID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must not be blank"})
	}
	if in.CorrelationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "correlation_id", Reason: "must not be blank"})
	}
	if len(violations) > 0 {
		return AdminPlanAuditContext{}, apierr.InvalidInput(violations...)
	}
	return in, nil
}

func adminPlanAuditEvent(auditCtx AdminPlanAuditContext, action string, plan Plan, operation string) AuditEvent {
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         action,
		ResourceKind:   adminPlanResourceKind,
		ResourceID:     plan.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "allowed",
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":      operation,
			"slug":           plan.Slug,
			"billing_period": plan.BillingPeriod.String(),
			"status":         plan.Status.String(),
			"version":        strconv.Itoa(plan.Version),
		},
	}
}
