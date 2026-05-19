package store

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// DefaultPlan is the plan name LimitsReader uses when none is supplied. A
// real plans table is a later story; until it lands, every organization is
// treated as on the same default plan, mirroring the placeholder
// internal/controlplane/quota.StaticPlanResolver uses.
const DefaultPlan = "default"

// PlanLookup resolves the billing plan name for an organization, observing
// the same Querier as the surrounding read transaction so it sees exactly the
// state the read commits against. Its signature is deliberately the same as
// internal/controlplane/quota.PlanResolver.Plan so a single placeholder can
// be reused across both layers without a cross-package dependency from store
// onto quota — store is the lower of the two layers.
//
// A nil PlanLookup falls back to DefaultPlan, which matches the placeholder
// behaviour the rest of the backend uses today.
type PlanLookup func(ctx context.Context, q Querier, organizationID string) (string, error)

// LimitsReader is the store-backed read adapter for the limits surface: the
// persistence surface the httpapi layer needs to render
// GET /v1/organizations/{org_id}/limits. It mirrors OrganizationReader and
// MembershipReader — it composes the QuotaRepository rather than issuing its
// own SQL, so the tenant-scoping guarantees the repository proves in its
// integration tests are inherited for free, and every method opens its own
// short-lived read transaction through Store.Read.
type LimitsReader struct {
	store    *Store
	repo     *QuotaRepository
	subs     *SubscriptionRepository
	planFunc PlanLookup
	clock    func() time.Time
}

// NewLimitsReader builds a LimitsReader over store. plans resolves the
// organization's plan name; pass nil to use the DefaultPlan placeholder. The
// constructor returns an error for a nil store so a misconfigured adapter
// fails at construction rather than on its first request.
func NewLimitsReader(s *Store, plans PlanLookup) (*LimitsReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &LimitsReader{store: s, repo: NewQuotaRepository(), subs: NewSubscriptionRepository(), planFunc: plans, clock: time.Now}, nil
}

// ListEffectiveLimits returns the effective limits configured for
// organizationID in deterministic resource order, reading them inside a
// short-lived read-only transaction. The plan name is resolved through the
// configured PlanLookup (or DefaultPlan when none was supplied) and is
// observed inside the same transaction the limits resolution runs in, so a
// caller can never see a plan/limits pair that did not coexist at the same
// moment. The read is tenant scoped at the repository: a cross-tenant id
// simply matches no rows and yields an empty list, never another
// organization's limits.
func (r *LimitsReader) ListEffectiveLimits(ctx context.Context, organizationID string) ([]EffectiveQuotaLimit, error) {
	var limits []EffectiveQuotaLimit
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		at := r.clock().UTC()
		current, ok, err := readCurrentSubscriptionView(ctx, q, organizationID, at)
		if err != nil {
			return err
		}
		if ok {
			entitlements, err := r.subs.ResolveEntitlements(ctx, q, organizationID, at)
			if err != nil {
				return err
			}
			usage, err := quotaUsageCounterMap(ctx, q, organizationID)
			if err != nil {
				return err
			}
			limits = effectiveLimitsFromEntitlements(entitlements, usage, current)
			return nil
		}
		plan, planErr := r.resolvePlan(ctx, q, organizationID)
		if planErr != nil {
			return planErr
		}
		var listErr error
		limits, listErr = r.repo.ListEffectiveLimits(ctx, q, organizationID, plan)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return limits, nil
}

func effectiveLimitsFromEntitlements(entitlements []EffectiveEntitlement, usage map[QuotaResource]int64, current currentSubscriptionView) []EffectiveQuotaLimit {
	out := make([]EffectiveQuotaLimit, 0, len(entitlements))
	for _, ent := range entitlements {
		resource := QuotaResource(ent.EntitlementKey)
		if !resource.Valid() {
			continue
		}
		limit := int64(0)
		if ent.LimitValue != nil {
			limit = *ent.LimitValue
		}
		start := current.CurrentPeriodStart
		end := current.CurrentPeriodEnd
		out = append(out, EffectiveQuotaLimit{
			Resource:          resource,
			LimitValue:        limit,
			EnforcementMode:   ent.EnforcementMode,
			Scope:             entitlementScope(ent.Source),
			UsedValue:         usage[resource],
			ResetPeriodStart:  &start,
			ResetPeriodEnd:    &end,
			WarningThresholds: warningThresholdCopy(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Resource < out[j].Resource
	})
	return out
}

// resolvePlan resolves the plan name through the configured PlanLookup, with
// the DefaultPlan fallback applied either when no lookup was wired or when
// the lookup returned an empty string — so a misconfigured resolver can never
// erase the floor every tenant is meant to inherit.
func (r *LimitsReader) resolvePlan(ctx context.Context, q Querier, organizationID string) (string, error) {
	if r.planFunc == nil {
		return DefaultPlan, nil
	}
	plan, err := r.planFunc(ctx, q, organizationID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(plan) == "" {
		return DefaultPlan, nil
	}
	return plan, nil
}
