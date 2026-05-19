package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const adminSubscriptionResourceKind = "subscription"
const adminSubscriptionEntitlementResourceKind = "subscription_entitlement"

// AdminSubscriptionService composes support-owned subscription assignment and
// entitlement override mutations with immutable audit events.
type AdminSubscriptionService struct {
	store *Store
	orgs  *OrganizationRepository
	plans *PricingPlanRepository
	subs  *SubscriptionRepository
	audit *AuditRepository
}

// NewAdminSubscriptionService builds an audited backoffice subscription manager.
func NewAdminSubscriptionService(s *Store, orgs *OrganizationRepository, plans *PricingPlanRepository, subs *SubscriptionRepository, audit *AuditRepository) (*AdminSubscriptionService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if plans == nil {
		return nil, errors.New("store: nil pricing plan repository")
	}
	if subs == nil {
		return nil, errors.New("store: nil subscription repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminSubscriptionService{store: s, orgs: orgs, plans: plans, subs: subs, audit: audit}, nil
}

// SetSubscription creates or replaces the organization's current accepted plan
// assignment and records the support action in the same transaction.
func (svc *AdminSubscriptionService) SetSubscription(ctx context.Context, organizationID string, in CreateSubscriptionInput, auditCtx AdminPlanAuditContext) (Subscription, error) {
	auditCtx, err := validateAdminPlanAuditContext(auditCtx)
	if err != nil {
		return Subscription{}, err
	}
	orgID := strings.TrimSpace(organizationID)
	if orgID == "" {
		return Subscription{}, apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	in.OrganizationID = orgID

	var out Subscription
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		if _, err := svc.orgs.Get(ctx, tx, orgID); err != nil {
			return err
		}
		if _, err := svc.plans.Get(ctx, tx, in.PlanID); err != nil {
			return err
		}

		current, err := svc.subs.CurrentForOrganization(ctx, tx, orgID, time.Now().UTC())
		var sub Subscription
		operation := "update"
		if err == nil {
			sub, err = svc.subs.Update(ctx, tx, current.ID, in)
		} else if isNotFoundError(err) {
			operation = "create"
			sub, err = svc.subs.Create(ctx, tx, in)
		}
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminSubscriptionAuditEvent(auditCtx, sub, operation)); err != nil {
			return err
		}
		out = sub
		return nil
	})
	return out, err
}

// UpsertSubscriptionEntitlement creates or replaces one effective-windowed
// organization override and records the support action in the same transaction.
func (svc *AdminSubscriptionService) UpsertSubscriptionEntitlement(ctx context.Context, organizationID string, in UpsertSubscriptionEntitlementInput, auditCtx AdminPlanAuditContext) (SubscriptionEntitlement, error) {
	auditCtx, err := validateAdminPlanAuditContext(auditCtx)
	if err != nil {
		return SubscriptionEntitlement{}, err
	}
	orgID := strings.TrimSpace(organizationID)
	if orgID == "" {
		return SubscriptionEntitlement{}, apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	in.OrganizationID = orgID
	in.ActorID = auditCtx.ActorID
	in.ActorKind = auditCtx.ActorKind
	in.RequestID = auditCtx.RequestID
	in.CorrelationID = auditCtx.CorrelationID

	var out SubscriptionEntitlement
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		if _, err := svc.orgs.Get(ctx, tx, orgID); err != nil {
			return err
		}
		if in.Source == EntitlementSourceSubscriptionOverride {
			if _, err := svc.subs.Get(ctx, tx, orgID, in.SubscriptionID); err != nil {
				return err
			}
		}
		ent, err := svc.subs.UpsertEntitlement(ctx, tx, in)
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, adminSubscriptionEntitlementAuditEvent(auditCtx, ent)); err != nil {
			return err
		}
		out = ent
		return nil
	})
	return out, err
}

func adminSubscriptionAuditEvent(auditCtx AdminPlanAuditContext, sub Subscription, operation string) AuditEvent {
	metadata := map[string]string{
		"operation":            operation,
		"plan_id":              sub.PlanID,
		"status":               string(sub.Status),
		"current_period_start": sub.CurrentPeriodStart.UTC().Format(time.RFC3339Nano),
		"current_period_end":   sub.CurrentPeriodEnd.UTC().Format(time.RFC3339Nano),
		"provider":             sub.Provider,
		"cancel_at_period_end": strconv.FormatBool(sub.CancelAtPeriodEnd),
	}
	if sub.CanceledAt != nil {
		metadata["canceled_at"] = sub.CanceledAt.UTC().Format(time.RFC3339Nano)
	}
	if sub.TrialEndsAt != nil {
		metadata["trial_ends_at"] = sub.TrialEndsAt.UTC().Format(time.RFC3339Nano)
	}
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         "admin.subscription.set",
		ResourceKind:   adminSubscriptionResourceKind,
		ResourceID:     sub.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "allowed",
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata:       metadata,
	}
}

func adminSubscriptionEntitlementAuditEvent(auditCtx AdminPlanAuditContext, ent SubscriptionEntitlement) AuditEvent {
	metadata := map[string]string{
		"operation":        "upsert",
		"source":           string(ent.Source),
		"entitlement_key":  ent.EntitlementKey,
		"enforcement_mode": string(ent.EnforcementMode),
		"effective_from":   ent.EffectiveFrom.UTC().Format(time.RFC3339Nano),
	}
	if ent.LimitValue != nil {
		metadata["limit_value"] = strconv.FormatInt(*ent.LimitValue, 10)
	}
	if ent.SubscriptionID != nil {
		metadata["subscription_id"] = *ent.SubscriptionID
	}
	if ent.EffectiveUntil != nil {
		metadata["effective_until"] = ent.EffectiveUntil.UTC().Format(time.RFC3339Nano)
	}
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         "admin.subscription.entitlement.upsert",
		ResourceKind:   adminSubscriptionEntitlementResourceKind,
		ResourceID:     ent.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "allowed",
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata:       metadata,
	}
}
