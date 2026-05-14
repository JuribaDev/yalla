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
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
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
	repo  *store.QuotaRepository
	plans PlanResolver
	ttl   time.Duration
	now   func() time.Time
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
// there is headroom, records an active reservation inside tx. It satisfies the
// store.QuotaReserver port.
//
// The decision is: an organization may allocate one more unit of a resource
// when current usage plus all active reservations plus this request stays
// within the effective limit. For a hard-enforced limit Reserve locks the
// tenant's usage counter row first, so a concurrent reserve for the same
// tenant and resource blocks until this transaction settles and can never race
// past the limit. A soft or metered limit is recorded but never rejected; a
// disabled limit — and a resource with no policy configured at all — is allowed
// without recording a reservation.
//
// An exhausted hard limit is returned as a typed apierr.QuotaExceeded error
// (HTTP 429) whose hint names the current, reserved, requested, and limit
// counts and whose wrapped cause is a recoverable ExceededDetail.
func (c *Checker) Reserve(ctx context.Context, tx *store.Tx, organizationID, resource string) error {
	if tx == nil {
		return apierr.Internal(errors.New("quota: Reserve called with a nil transaction"))
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

	const requested = int64(1)

	plan, err := c.plans.Plan(ctx, tx, orgID)
	if err != nil {
		return err
	}

	limit, found, err := c.repo.EffectiveLimit(ctx, tx, orgID, plan, res)
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
			return quotaExceeded(res, current, reserved, requested, limit.LimitValue)
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

// quotaExceeded builds the typed rejection error for an exhausted hard limit:
// an apierr.QuotaExceeded whose hint carries every count behind the decision
// and whose wrapped cause is a recoverable ExceededDetail.
func quotaExceeded(res store.QuotaResource, current, reserved, requested, limit int64) error {
	detail := ExceededDetail{
		Resource:  res.String(),
		Current:   current,
		Reserved:  reserved,
		Requested: requested,
		Limit:     limit,
	}
	return apierr.QuotaExceeded(res.String(), limit).
		WithHintf("%s quota exhausted: %d in use, %d reserved, %d requested, limit %d; release usage or request a higher quota",
			res, current, reserved, requested, limit).
		Wrap(detail)
}
