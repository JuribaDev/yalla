// Package quota evaluates entitlements, reservations, and usage limits.
//
// The Checker is the quota checker service: the store.QuotaReserver the
// repository unit of work composes between its authorization check and its
// desired-state write. Reserve runs inside the caller's transaction, so the
// headroom check and the reservation it records commit or roll back atomically
// with the resource they guard — the check can never be separated from the
// write, and, because a hard-enforced limit locks the tenant's usage counter
// row FOR UPDATE, two concurrent units of work can never both over-allocate.
package quota

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/entitlements"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// DefaultReservationTTL is how long a reservation stays active before it is
// treated as expired if its unit of work neither commits nor releases it. It
// is deliberately short: a crashed job must not strand a tenant's quota.
const DefaultReservationTTL = 15 * time.Minute

// DefaultPlan is the plan name a StaticPlanResolver reports for every
// organization until a real plans table exists.
const DefaultPlan = "default"

// PlanResolver resolves the billing plan name for an organization. The Checker
// uses it to fall back to a plan-default limit when an organization has no
// override. It receives the same store.Querier as the surrounding unit of
// work, so it observes exactly the state the transaction will commit against.
//
// A real plans table is a later story; until it lands, StaticPlanResolver
// reports one plan name for every organization.
type PlanResolver interface {
	Plan(ctx context.Context, q store.Querier, organizationID string) (string, error)
}

// PlanResolverFunc adapts a function to PlanResolver.
type PlanResolverFunc func(context.Context, store.Querier, string) (string, error)

// Plan resolves the organization's plan.
func (f PlanResolverFunc) Plan(ctx context.Context, q store.Querier, organizationID string) (string, error) {
	return f(ctx, q, organizationID)
}

// StaticPlanResolver reports the same plan name for every organization. It is
// the placeholder PlanResolver until a plans table lands.
type StaticPlanResolver string

// Plan reports the static plan name.
func (p StaticPlanResolver) Plan(context.Context, store.Querier, string) (string, error) {
	return string(p), nil
}

// ExceededDetail is the structured, recoverable explanation behind a quota
// rejection: the resource that was exhausted and the four numbers that drove
// the decision. It is wrapped as the cause of the apierr.QuotaExceeded error so
// a caller can recover it with DetailOf without parsing the message. It carries
// no secrets — quota dimensions and counts are not sensitive.
type ExceededDetail struct {
	Resource  string
	Current   int64
	Reserved  int64
	Requested int64
	Limit     int64
}

// Error renders the detail as a single diagnostic line.
func (d ExceededDetail) Error() string {
	return fmt.Sprintf("quota exceeded for %s: %d in use, %d reserved, %d requested, limit %d",
		d.Resource, d.Current, d.Reserved, d.Requested, d.Limit)
}

// DetailOf recovers the ExceededDetail wrapped in a quota-rejection error. The
// boolean is false when err was not produced by a quota rejection.
func DetailOf(err error) (ExceededDetail, bool) {
	var d ExceededDetail
	if errors.As(err, &d) {
		return d, true
	}
	return ExceededDetail{}, false
}

// Checker is Yalla's quota checker service. It satisfies store.QuotaReserver.
type Checker struct {
	repo         *store.QuotaRepository
	plans        PlanResolver
	entitlements *entitlements.Resolver
	ttl          time.Duration
	now          func() time.Time
}

// Compile-time proof that *Checker is a usable QuotaReserver for the store
// unit of work.
var _ store.QuotaReserver = (*Checker)(nil)

// Option customises a Checker at construction.
type Option func(*Checker)

// WithReservationTTL overrides how long a recorded reservation stays active.
// The duration must be positive.
func WithReservationTTL(d time.Duration) Option {
	return func(c *Checker) { c.ttl = d }
}

// WithClock overrides the Checker's time source. It exists for deterministic
// tests; production callers should leave the default of time.Now.
func WithClock(now func() time.Time) Option {
	return func(c *Checker) { c.now = now }
}

// WithEntitlementResolver makes the checker prefer pricing entitlements over
// legacy quota_policies for dimensions whose entitlement key matches the quota
// resource. If no entitlement exists for a resource, the checker falls back to
// quota_policies so older deployments keep their existing behaviour.
func WithEntitlementResolver(resolver *entitlements.Resolver) Option {
	return func(c *Checker) { c.entitlements = resolver }
}

// NewChecker wires a Checker from its dependencies. It returns a typed error if
// any dependency is nil or any option is invalid, so a misconfigured checker
// fails at construction rather than on its first request.
func NewChecker(repo *store.QuotaRepository, plans PlanResolver, opts ...Option) (*Checker, error) {
	if repo == nil {
		return nil, errors.New("quota: nil quota repository")
	}
	if plans == nil {
		return nil, errors.New("quota: nil plan resolver")
	}
	c := &Checker{repo: repo, plans: plans, ttl: DefaultReservationTTL, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	if c.ttl <= 0 {
		return nil, errors.New("quota: reservation TTL must be positive")
	}
	if c.now == nil {
		return nil, errors.New("quota: nil clock")
	}
	return c, nil
}

// Reserve enforces the organization's limit for one unit of resource and, when
// there is headroom, records an active reservation inside tx. It is the
// count-axis convenience wrapper around ReserveAmount with amount=1 — every
// per-subtype counting dimension (projects, environments, services,
// applications, compose_stacks, databases, domains, preview_environments,
// service_accounts) reaches the same lock + sum + insert path through it.
func (c *Checker) Reserve(ctx context.Context, tx *store.Tx, organizationID, resource string) error {
	return c.ReserveAmount(ctx, tx, organizationID, resource, 1)
}

// ReserveAmount enforces the organization's limit for amount units of resource
// and, when there is headroom, records an active reservation inside tx. It
// satisfies the store.QuotaReserver port and is the dimensional path used by
// magnitude quotas (cpu_millicores, memory_mb, storage_gb, monthly_deployments,
// and other capacity bounds whose allocation is variable per request).
//
// The decision is: an organization may allocate amount more units of a
// resource when current usage plus all active reservations plus this request
// stays within the effective limit. For a hard-enforced limit ReserveAmount
// locks the tenant's usage counter row first, so a concurrent reserve for the
// same tenant and resource blocks until this transaction settles and can
// never race past the limit. A soft or metered limit is recorded but never
// rejected; a disabled limit — and a resource with no policy configured at
// all — is allowed without recording a reservation.
//
// An exhausted hard limit is returned as a typed apierr.QuotaExceeded error
// (HTTP 429) whose hint names the current, reserved, requested, and limit
// counts and whose wrapped cause is a recoverable ExceededDetail.
//
// amount must be strictly positive. A zero or negative magnitude is a wiring
// error (the call site asked for nothing or a negative allocation) and is
// rejected as Internal — the right way to release a reservation is the
// dedicated release path, not a negative ReserveAmount.
func (c *Checker) ReserveAmount(ctx context.Context, tx *store.Tx, organizationID, resource string, amount int64) error {
	if tx == nil {
		return apierr.Internal(errors.New("quota: ReserveAmount called with a nil transaction"))
	}
	if amount <= 0 {
		return apierr.Internal(fmt.Errorf("quota: ReserveAmount called with non-positive amount %d", amount))
	}
	orgID := strings.TrimSpace(organizationID)
	if orgID == "" {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be empty",
		})
	}
	res := store.QuotaResource(strings.TrimSpace(resource))
	if !res.Valid() {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field:  "resource",
			Reason: "is not a recognised quota dimension",
		})
	}

	requested := amount

	limit, found, err := c.effectiveLimit(ctx, tx, orgID, res)
	if err != nil {
		return err
	}
	if !found {
		// No policy configured for this dimension at either scope: the
		// resource is unconstrained, so there is nothing to reserve or reject.
		return nil
	}

	switch limit.EnforcementMode {
	case store.EnforcementModeDisabled:
		return nil
	case store.EnforcementModeHard:
		// Lock the usage counter row so a concurrent reserve for the same
		// tenant and resource serialises behind this one.
		current, err := c.repo.LockUsage(ctx, tx, orgID, res)
		if err != nil {
			return err
		}
		reserved, err := c.repo.SumActiveReservations(ctx, tx, orgID, res, c.now())
		if err != nil {
			return err
		}
		if current+reserved+requested > limit.LimitValue {
			return quotaExceeded(limit, current, reserved, requested)
		}
	case store.EnforcementModeSoft, store.EnforcementModeMetered:
		// Recorded for metering and visibility, but never rejected.
	default:
		return apierr.Internal(fmt.Errorf("quota: unknown enforcement mode %q", limit.EnforcementMode))
	}

	if _, err := c.repo.InsertReservation(ctx, tx, store.QuotaReservation{
		OrganizationID: orgID,
		Resource:       res,
		Amount:         requested,
		Status:         store.ReservationStatusActive,
		ExpiresAt:      c.now().Add(c.ttl),
	}); err != nil {
		return err
	}
	return nil
}

func (c *Checker) effectiveLimit(ctx context.Context, tx *store.Tx, orgID string, res store.QuotaResource) (store.QuotaLimit, bool, error) {
	if c.entitlements != nil {
		snapshot, err := c.entitlements.ResolveWithQuerier(ctx, tx, orgID, c.now())
		if err != nil {
			return store.QuotaLimit{}, false, err
		}
		if ent, ok := snapshot.Get(res.String()); ok {
			if ent.EnforcementMode == store.EnforcementModeHard && ent.Value == nil {
				return store.QuotaLimit{}, false, apierr.Internal(fmt.Errorf("quota: hard entitlement %q has no limit value", res))
			}
			limit := int64(0)
			if ent.Value != nil {
				limit = *ent.Value
			}
			return store.QuotaLimit{
				Resource:        res,
				LimitValue:      limit,
				EnforcementMode: ent.EnforcementMode,
				EntitlementKey:  ent.Key,
				ResetPeriodFrom: timePtr(ent.PeriodStart),
				ResetPeriodTo:   timePtr(ent.PeriodEnd),
			}, true, nil
		}
	}

	plan, err := c.plans.Plan(ctx, tx, orgID)
	if err != nil {
		return store.QuotaLimit{}, false, err
	}
	return c.repo.EffectiveLimit(ctx, tx, orgID, plan, res)
}

// quotaExceeded builds the typed rejection error for an exhausted hard limit:
// an apierr.QuotaExceeded whose hint carries every count behind the decision
// and whose wrapped cause is a recoverable ExceededDetail.
func quotaExceeded(limit store.QuotaLimit, current, reserved, requested int64) error {
	resource := limit.Resource
	entitlementKey := strings.TrimSpace(limit.EntitlementKey)
	if entitlementKey == "" {
		entitlementKey = resource.String()
	}
	detail := ExceededDetail{
		Resource:  resource.String(),
		Current:   current,
		Reserved:  reserved,
		Requested: requested,
		Limit:     limit.LimitValue,
	}
	err := apierr.QuotaExceeded(resource.String(), limit.LimitValue).
		WithDetail(apierr.DetailKeyQuotaEntitlementKey, entitlementKey).
		WithDetail(apierr.DetailKeyQuotaCurrent, strconv.FormatInt(current, 10)).
		WithDetail(apierr.DetailKeyQuotaReserved, strconv.FormatInt(reserved, 10)).
		WithDetail(apierr.DetailKeyQuotaRequested, strconv.FormatInt(requested, 10)).
		WithHintf("%s quota exhausted: %d in use, %d reserved, %d requested, limit %d; release usage or request a higher quota",
			resource, current, reserved, requested, limit.LimitValue).
		Wrap(detail)
	if limit.ResetPeriodFrom != nil && !limit.ResetPeriodFrom.IsZero() {
		err = err.WithDetail(apierr.DetailKeyQuotaResetPeriodFrom, limit.ResetPeriodFrom.UTC().Format(time.RFC3339))
	}
	if limit.ResetPeriodTo != nil && !limit.ResetPeriodTo.IsZero() {
		err = err.WithDetail(apierr.DetailKeyQuotaResetPeriodTo, limit.ResetPeriodTo.UTC().Format(time.RFC3339))
	}
	return err
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
