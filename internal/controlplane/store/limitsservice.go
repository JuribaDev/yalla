package store

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The action recorded on the audit event for PATCH
// /v1/organizations/{org_id}/limits. It is kept as a plain string here so the
// store layer takes no build dependency on internal/controlplane/policy; the
// HTTP authorization middleware authorizes the same action before the handler
// is reached, and the policy matrix tests keep the two values in sync.
const limitsWriteAction = "limits.write"

// LimitUpdate is one organization-scoped quota override the caller asks to
// upsert. Resource names a closed-set quota dimension; LimitValue is the
// numeric ceiling (>= 0); EnforcementMode is one of the closed
// EnforcementMode values, or empty to default to EnforcementModeHard. The
// service validates each field before any database work — an invalid request
// never opens a transaction — and the resource name is the only value ever
// reflected back to the caller (it is a closed-set identifier, not credential
// material).
type LimitUpdate struct {
	Resource        QuotaResource
	LimitValue      int64
	EnforcementMode EnforcementMode
}

// UpdateLimitsInput is the input to LimitsService.UpdateLimits. OrganizationID
// names the tenant whose organization-scoped overrides are upserted. Items is
// the (non-empty) set of overrides the caller asks to apply, in caller order.
// The Actor* and correlation fields describe the authenticated principal and
// are recorded verbatim on the audit event; they are plain strings so the
// store layer takes no build dependency on the policy or telemetry packages —
// the httpapi handler, which already holds the resolved principal and the
// request correlation, fills them in.
type UpdateLimitsInput struct {
	OrganizationID string
	Items          []LimitUpdate
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// LimitsService is the unit-of-work orchestrator for PATCH
// /v1/organizations/{org_id}/limits. UpdateLimits composes — in a fixed order,
// inside one transaction — a tenant-scoped existence check on the target
// organization, one organization-scoped quota policy upsert per requested
// override, and the immutable audit record. Because every step shares the
// *Tx opened by Store.Write, a failure in any of them rolls the others back:
// a partial application of a multi-resource patch and an orphaned audit
// record are both impossible.
//
// The service also re-reads the resulting effective limits inside the same
// transaction (so the response always shows the limits that just committed),
// using LimitsReader's PlanLookup convention — a nil planFunc falls back to
// DefaultPlan, exactly like the read-side adapter — so a misconfigured plan
// resolver cannot make the write-side return a different plan default than
// the read-side does.
type LimitsService struct {
	store    *Store
	orgs     *OrganizationRepository
	quotas   *QuotaRepository
	audit    AuditAppender
	planFunc PlanLookup
}

// NewLimitsService wires a LimitsService from its dependencies. plans resolves
// the organization's plan name for the post-write re-read; pass nil to use
// the DefaultPlan placeholder, mirroring NewLimitsReader. The constructor
// returns an error for any nil required dependency so a misconfigured service
// fails at construction rather than on its first request.
func NewLimitsService(s *Store, orgs *OrganizationRepository, quotas *QuotaRepository, audit AuditAppender, plans PlanLookup) (*LimitsService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case quotas == nil:
		return nil, errors.New("store: nil quota repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &LimitsService{store: s, orgs: orgs, quotas: quotas, audit: audit, planFunc: plans}, nil
}

// UpdateLimits validates in, then runs the update-limits unit of work inside
// one transaction: verify the organization exists (so a missing tenant is a
// typed NotFound rather than the same generic constraint violation as a bad
// resource), upsert each organization-scoped policy, append the audit event,
// and re-read the effective limits in deterministic order. Validation runs
// before the transaction is opened, so an invalid request never touches the
// database. An {org_id} with no row is the typed NotFound the repository
// produces; any database constraint violation rolls the whole transaction
// back as a typed Conflict, so a misleading partial update and an orphaned
// audit record are both impossible.
func (svc *LimitsService) UpdateLimits(ctx context.Context, in UpdateLimitsInput) ([]EffectiveQuotaLimit, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}

	items, err := buildLimitsUpdate(in.Items)
	if err != nil {
		return nil, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the organization whose limits were updated. A missing actor organization
	// is a wiring error (an authenticated request always carries one), not
	// client input, so it is reported as Internal rather than a validation
	// failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: LimitsService.UpdateLimits requires an actor organization for the audit record"))
	}

	// updated_resources names which closed-set resource dimensions the patch
	// touched, sorted for a deterministic audit projection. It is value-free
	// metadata — a closed-set identifier list, not a submitted value — so it
	// is safe to record verbatim.
	resources := make([]string, 0, len(items))
	for _, item := range items {
		resources = append(resources, string(item.Resource))
	}
	sort.Strings(resources)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         limitsWriteAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     organizationID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for limits.write",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		Metadata:       map[string]string{"updated_resources": strings.Join(resources, ",")},
	}

	var updated []EffectiveQuotaLimit
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// A pre-check for the target organization turns a missing tenant
		// into the typed NotFound the rest of the API surface returns,
		// instead of the FK constraint violation that mapWriteError would
		// otherwise collapse to a 409 Conflict — distinguishing "no such
		// tenant" from "your patch collided with a constraint" is what makes
		// this endpoint diagnosable.
		if _, getErr := svc.orgs.Get(ctx, tx, organizationID); getErr != nil {
			return getErr
		}
		for _, item := range items {
			if upErr := svc.quotas.UpsertOrganizationPolicy(ctx, tx, organizationID, item.Resource, item.LimitValue, item.EnforcementMode); upErr != nil {
				return upErr
			}
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the effective limits inside the same transaction so the
		// response always reflects exactly the state that committed. The
		// plan lookup observes the same Querier, matching the read-side
		// adapter's coherence guarantee.
		plan, planErr := svc.resolvePlan(ctx, tx, organizationID)
		if planErr != nil {
			return planErr
		}
		limits, listErr := svc.quotas.ListEffectiveLimits(ctx, tx, organizationID, plan)
		if listErr != nil {
			return listErr
		}
		updated = limits
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return updated, nil
}

// resolvePlan resolves the plan name through the configured PlanLookup, with
// the DefaultPlan fallback applied either when no lookup was wired or when
// the lookup returned an empty string — so a misconfigured resolver can never
// erase the floor every tenant is meant to inherit.
func (svc *LimitsService) resolvePlan(ctx context.Context, q Querier, organizationID string) (string, error) {
	if svc.planFunc == nil {
		return DefaultPlan, nil
	}
	plan, err := svc.planFunc(ctx, q, organizationID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(plan) == "" {
		return DefaultPlan, nil
	}
	return plan, nil
}

// buildLimitsUpdate validates and normalises the caller-supplied items. It is
// split out from UpdateLimits so the validation rules are unit testable
// without a database, and so an invalid request is rejected before a
// transaction is ever opened. A patch that names no item is itself a
// validation failure — a mutation that changes nothing is a client error,
// not a silent success. On failure it returns a typed apierr.InvalidInput
// carrying stable field paths — never the submitted values — so the
// rejection can name the offending field without leaking input.
//
// Each item is rejected when its Resource is not in the closed quota_resource
// set, when LimitValue is negative, when EnforcementMode is set but not in
// the closed quota_enforcement_mode set, or when the same Resource appears
// more than once in the patch. A blank EnforcementMode defaults to
// EnforcementModeHard, mirroring the schema default for an INSERT.
func buildLimitsUpdate(in []LimitUpdate) ([]LimitUpdate, error) {
	var violations []apierr.FieldViolation
	if len(in) == 0 {
		violations = append(violations, apierr.FieldViolation{
			Field:  "limits",
			Reason: "must contain at least one entry",
		})
		return nil, apierr.InvalidInput(violations...)
	}

	out := make([]LimitUpdate, 0, len(in))
	seen := make(map[QuotaResource]struct{}, len(in))
	for i, item := range in {
		// Use dotted-index field paths so the agent-facing reason can pinpoint
		// the offending entry without echoing any value.
		switch {
		case strings.TrimSpace(string(item.Resource)) == "":
			violations = append(violations, apierr.FieldViolation{
				Field:  "limits[" + itoa(i) + "].resource",
				Reason: "must not be blank",
			})
			continue
		case !item.Resource.Valid():
			violations = append(violations, apierr.FieldViolation{
				Field:  "limits[" + itoa(i) + "].resource",
				Reason: "must be a known quota resource",
			})
			continue
		}
		if _, dup := seen[item.Resource]; dup {
			violations = append(violations, apierr.FieldViolation{
				Field:  "limits[" + itoa(i) + "].resource",
				Reason: "must not be repeated in the same patch",
			})
			continue
		}
		seen[item.Resource] = struct{}{}

		if item.LimitValue < 0 {
			violations = append(violations, apierr.FieldViolation{
				Field:  "limits[" + itoa(i) + "].limit_value",
				Reason: "must be zero or positive",
			})
			continue
		}

		mode := item.EnforcementMode
		if mode == "" {
			mode = EnforcementModeHard
		}
		if !validEnforcementMode(mode) {
			violations = append(violations, apierr.FieldViolation{
				Field:  "limits[" + itoa(i) + "].enforcement_mode",
				Reason: "must be one of hard, soft, metered, or disabled",
			})
			continue
		}

		out = append(out, LimitUpdate{
			Resource:        item.Resource,
			LimitValue:      item.LimitValue,
			EnforcementMode: mode,
		})
	}

	if len(violations) > 0 {
		return nil, apierr.InvalidInput(violations...)
	}
	return out, nil
}

// validEnforcementMode reports whether m is one of the closed enforcement
// modes the quota_enforcement_mode Postgres DOMAIN accepts.
func validEnforcementMode(m EnforcementMode) bool {
	switch m {
	case EnforcementModeHard, EnforcementModeSoft, EnforcementModeMetered, EnforcementModeDisabled:
		return true
	}
	return false
}

// itoa renders a non-negative int as a decimal string without pulling in
// strconv at the call site (keeps the field-path construction obviously
// allocation-free for small indices).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
