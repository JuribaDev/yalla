package store

import (
	"context"
	"errors"
	"strings"
)

// UsageReader is the store-backed read adapter for the usage surface: the
// persistence surface the httpapi layer needs to render
// GET /v1/organizations/{org_id}/usage. It mirrors LimitsReader — it composes
// the QuotaRepository rather than issuing its own SQL, so the tenant-scoping
// guarantees the repository proves in its integration tests are inherited
// for free, and every method opens its own short-lived read transaction
// through Store.Read.
type UsageReader struct {
	store    *Store
	repo     *QuotaRepository
	planFunc PlanLookup
}

// NewUsageReader builds a UsageReader over store. plans resolves the
// organization's plan name; pass nil to use the DefaultPlan placeholder. The
// constructor returns an error for a nil store so a misconfigured adapter
// fails at construction rather than on its first request.
func NewUsageReader(s *Store, plans PlanLookup) (*UsageReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &UsageReader{store: s, repo: NewQuotaRepository(), planFunc: plans}, nil
}

// ListOrganizationUsage returns the current usage counters configured for
// organizationID in deterministic resource order, paired with the effective
// limit (when one is configured) and the scope that produced it. The plan
// name is resolved through the configured PlanLookup (or DefaultPlan when
// none was supplied) and is observed inside the same read transaction the
// usage resolution runs in, so a caller can never see a plan/usage pair that
// did not coexist at the same moment. The read is tenant scoped at the
// repository: a cross-tenant id simply matches no rows and yields an empty
// list, never another organization's counters.
func (r *UsageReader) ListOrganizationUsage(ctx context.Context, organizationID string) ([]OrganizationResourceUsage, error) {
	var usage []OrganizationResourceUsage
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		plan, planErr := r.resolvePlan(ctx, q, organizationID)
		if planErr != nil {
			return planErr
		}
		var listErr error
		usage, listErr = r.repo.ListOrganizationUsage(ctx, q, organizationID, plan)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return usage, nil
}

// resolvePlan resolves the plan name through the configured PlanLookup, with
// the DefaultPlan fallback applied either when no lookup was wired or when
// the lookup returned an empty string — so a misconfigured resolver can
// never erase the floor every tenant is meant to inherit. Its behaviour is
// deliberately identical to LimitsReader.resolvePlan so a future plans table
// can be wired into both adapters through a single PlanLookup constructor
// without subtle drift between the limits and usage projections.
func (r *UsageReader) resolvePlan(ctx context.Context, q Querier, organizationID string) (string, error) {
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
