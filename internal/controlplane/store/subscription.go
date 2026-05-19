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

// SubscriptionStatus is the lifecycle state of an organization's accepted plan.
type SubscriptionStatus string

const (
	// SubscriptionStatusTrialing is a current trial period with plan entitlements active.
	SubscriptionStatusTrialing = "trialing"
	// SubscriptionStatusActive is a current paid/manual subscription.
	SubscriptionStatusActive = "active"
	// SubscriptionStatusPastDue keeps access active while billing recovery runs.
	SubscriptionStatusPastDue = "past_due"
	// SubscriptionStatusCanceled is terminal for runtime entitlement resolution.
	SubscriptionStatusCanceled = "canceled"
)

func (s SubscriptionStatus) valid() bool {
	switch s {
	case SubscriptionStatusTrialing, SubscriptionStatusActive, SubscriptionStatusPastDue, SubscriptionStatusCanceled:
		return true
	default:
		return false
	}
}

// EntitlementOverrideSource identifies the layer that produced a non-plan entitlement.
type EntitlementOverrideSource string

const (
	// EntitlementSourcePlan marks a plan default in resolved runtime output.
	EntitlementSourcePlan EntitlementOverrideSource = "plan"
	// EntitlementSourceSubscriptionOverride marks an organization-specific override tied to a subscription.
	EntitlementSourceSubscriptionOverride EntitlementOverrideSource = "subscription_override"
	// EntitlementSourceEmergencyAdmin marks an emergency admin override that outranks subscription overrides.
	EntitlementSourceEmergencyAdmin EntitlementOverrideSource = "emergency_admin"
)

func (s EntitlementOverrideSource) validOverride() bool {
	switch s {
	case EntitlementSourceSubscriptionOverride, EntitlementSourceEmergencyAdmin:
		return true
	default:
		return false
	}
}

// Subscription binds one organization to one immutable plan version.
type Subscription struct {
	ID                     string
	OrganizationID         string
	PlanID                 string
	Status                 SubscriptionStatus
	CurrentPeriodStart     time.Time
	CurrentPeriodEnd       time.Time
	Provider               string
	ProviderCustomerID     *string
	ProviderSubscriptionID *string
	CancelAtPeriodEnd      bool
	CanceledAt             *time.Time
	TrialEndsAt            *time.Time
	Metadata               []byte
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// SubscriptionEntitlement is one effective-windowed override for an organization.
type SubscriptionEntitlement struct {
	ID              string
	OrganizationID  string
	SubscriptionID  *string
	Source          EntitlementOverrideSource
	EntitlementKey  string
	LimitValue      *int64
	EnforcementMode EnforcementMode
	Reason          string
	ActorID         string
	ActorKind       string
	RequestID       string
	CorrelationID   string
	EffectiveFrom   time.Time
	EffectiveUntil  *time.Time
	Metadata        []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// EffectiveEntitlement is the deterministic runtime view after resolving plan
// defaults, subscription overrides, and emergency admin overrides.
type EffectiveEntitlement struct {
	EntitlementKey  string
	LimitValue      *int64
	EnforcementMode EnforcementMode
	Source          EntitlementOverrideSource
	PlanID          string
	SubscriptionID  string
	OverrideID      string
	PeriodStart     time.Time
	PeriodEnd       time.Time
}

// CreateSubscriptionInput describes the accepted plan version for an organization.
type CreateSubscriptionInput struct {
	SubscriptionID         string
	OrganizationID         string
	PlanID                 string
	Status                 SubscriptionStatus
	CurrentPeriodStart     time.Time
	CurrentPeriodEnd       time.Time
	Provider               string
	ProviderCustomerID     *string
	ProviderSubscriptionID *string
	CancelAtPeriodEnd      bool
	CanceledAt             *time.Time
	TrialEndsAt            *time.Time
	Metadata               []byte
}

// UpsertSubscriptionEntitlementInput describes one override row.
type UpsertSubscriptionEntitlementInput struct {
	EntitlementID   string
	OrganizationID  string
	SubscriptionID  string
	Source          EntitlementOverrideSource
	EntitlementKey  string
	LimitValue      *int64
	EnforcementMode EnforcementMode
	Reason          string
	ActorID         string
	ActorKind       string
	RequestID       string
	CorrelationID   string
	EffectiveFrom   time.Time
	EffectiveUntil  *time.Time
	Metadata        []byte
}

// SubscriptionRepository is the persistence and resolver surface for accepted
// plans and entitlement overrides.
type SubscriptionRepository struct{}

// NewSubscriptionRepository returns a stateless subscription repository.
func NewSubscriptionRepository() *SubscriptionRepository { return &SubscriptionRepository{} }

const subscriptionColumns = `id, organization_id, plan_id, status, current_period_start, current_period_end, provider, provider_customer_id, provider_subscription_id, cancel_at_period_end, canceled_at, trial_ends_at, metadata, created_at, updated_at`

const subscriptionEntitlementColumns = `id, organization_id, subscription_id, source, entitlement_key, limit_value, enforcement_mode, reason, actor_id, actor_kind, request_id, correlation_id, effective_from, effective_until, metadata, created_at, updated_at`

// Create inserts an organization's accepted plan row.
func (r *SubscriptionRepository) Create(ctx context.Context, tx *Tx, in CreateSubscriptionInput) (Subscription, error) {
	if tx == nil {
		return Subscription{}, apierr.Internal(errors.New("store: SubscriptionRepository.Create called with a nil transaction"))
	}
	sub, err := buildSubscriptionToCreate(in)
	if err != nil {
		return Subscription{}, err
	}
	if sub.ID == "" {
		sub.ID, err = newOpaqueStoreID("sub")
		if err != nil {
			return Subscription{}, apierr.Internal(err)
		}
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO subscriptions
		    (id, organization_id, plan_id, status, current_period_start, current_period_end, provider,
		     provider_customer_id, provider_subscription_id, cancel_at_period_end, canceled_at, trial_ends_at, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING `+subscriptionColumns,
		sub.ID, sub.OrganizationID, sub.PlanID, sub.Status, sub.CurrentPeriodStart, sub.CurrentPeriodEnd,
		sub.Provider, sub.ProviderCustomerID, sub.ProviderSubscriptionID, sub.CancelAtPeriodEnd,
		sub.CanceledAt, sub.TrialEndsAt, sub.Metadata,
	).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.Status, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.Provider, &sub.ProviderCustomerID, &sub.ProviderSubscriptionID, &sub.CancelAtPeriodEnd,
		&sub.CanceledAt, &sub.TrialEndsAt, &sub.Metadata, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err != nil {
		return Subscription{}, mapWriteError(err, "create subscription")
	}
	return sub, nil
}

// Get reads one tenant-scoped subscription by id.
func (r *SubscriptionRepository) Get(ctx context.Context, q Querier, organizationID, id string) (Subscription, error) {
	var sub Subscription
	err := q.QueryRow(ctx,
		`SELECT `+subscriptionColumns+`
		   FROM subscriptions
		  WHERE organization_id = $1
		    AND id = $2`,
		strings.TrimSpace(organizationID), strings.TrimSpace(id),
	).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.Status, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.Provider, &sub.ProviderCustomerID, &sub.ProviderSubscriptionID, &sub.CancelAtPeriodEnd,
		&sub.CanceledAt, &sub.TrialEndsAt, &sub.Metadata, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, apierr.NotFound("subscription", id)
	}
	if err != nil {
		return Subscription{}, apierr.StoreUnavailable(err)
	}
	return sub, nil
}

// CurrentForOrganization reads the current runtime subscription for an
// organization. Canceled and out-of-period rows are historical and do not
// count as current for this helper.
func (r *SubscriptionRepository) CurrentForOrganization(ctx context.Context, q Querier, organizationID string, at time.Time) (Subscription, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var sub Subscription
	err := q.QueryRow(ctx,
		`SELECT `+subscriptionColumns+`
		   FROM subscriptions
		  WHERE organization_id = $1
		    AND status IN ('trialing', 'active', 'past_due')
		    AND current_period_start <= $2
		    AND current_period_end > $2
		  ORDER BY current_period_start DESC, created_at DESC, id DESC
		  LIMIT 1`,
		strings.TrimSpace(organizationID), at,
	).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.Status, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.Provider, &sub.ProviderCustomerID, &sub.ProviderSubscriptionID, &sub.CancelAtPeriodEnd,
		&sub.CanceledAt, &sub.TrialEndsAt, &sub.Metadata, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, apierr.NotFound("subscription", organizationID)
	}
	if err != nil {
		return Subscription{}, apierr.StoreUnavailable(err)
	}
	return sub, nil
}

// Update replaces mutable subscription assignment fields on a tenant-scoped
// row. The accepted plan row remains an immutable plan version; this method
// only changes which plan version the organization is assigned to.
func (r *SubscriptionRepository) Update(ctx context.Context, tx *Tx, id string, in CreateSubscriptionInput) (Subscription, error) {
	if tx == nil {
		return Subscription{}, apierr.Internal(errors.New("store: SubscriptionRepository.Update called with a nil transaction"))
	}
	sub, err := buildSubscriptionToCreate(in)
	if err != nil {
		return Subscription{}, err
	}
	sub.ID = strings.TrimSpace(id)
	if sub.ID == "" {
		return Subscription{}, apierr.InvalidInput(apierr.FieldViolation{Field: "subscription_id", Reason: "must not be blank"})
	}
	err = tx.QueryRow(ctx,
		`UPDATE subscriptions
		    SET plan_id = $3,
		        status = $4,
		        current_period_start = $5,
		        current_period_end = $6,
		        provider = $7,
		        provider_customer_id = $8,
		        provider_subscription_id = $9,
		        cancel_at_period_end = $10,
		        canceled_at = $11,
		        trial_ends_at = $12,
		        metadata = $13
		  WHERE organization_id = $1
		    AND id = $2
		 RETURNING `+subscriptionColumns,
		sub.OrganizationID, sub.ID, sub.PlanID, sub.Status, sub.CurrentPeriodStart, sub.CurrentPeriodEnd,
		sub.Provider, sub.ProviderCustomerID, sub.ProviderSubscriptionID, sub.CancelAtPeriodEnd,
		sub.CanceledAt, sub.TrialEndsAt, sub.Metadata,
	).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.Status, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.Provider, &sub.ProviderCustomerID, &sub.ProviderSubscriptionID, &sub.CancelAtPeriodEnd,
		&sub.CanceledAt, &sub.TrialEndsAt, &sub.Metadata, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, apierr.NotFound("subscription", id)
	}
	if err != nil {
		return Subscription{}, mapWriteError(err, "update subscription")
	}
	return sub, nil
}

// UpsertEntitlement creates or replaces one override row by id.
func (r *SubscriptionRepository) UpsertEntitlement(ctx context.Context, tx *Tx, in UpsertSubscriptionEntitlementInput) (SubscriptionEntitlement, error) {
	if tx == nil {
		return SubscriptionEntitlement{}, apierr.Internal(errors.New("store: SubscriptionRepository.UpsertEntitlement called with a nil transaction"))
	}
	ent, err := buildSubscriptionEntitlementToUpsert(in)
	if err != nil {
		return SubscriptionEntitlement{}, err
	}
	if ent.ID == "" {
		ent.ID, err = newOpaqueStoreID("sent")
		if err != nil {
			return SubscriptionEntitlement{}, apierr.Internal(err)
		}
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO subscription_entitlements
		    (id, organization_id, subscription_id, source, entitlement_key, limit_value, enforcement_mode,
		     reason, actor_id, actor_kind, request_id, correlation_id, effective_from, effective_until, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (id) DO UPDATE
		    SET limit_value = EXCLUDED.limit_value,
		        enforcement_mode = EXCLUDED.enforcement_mode,
		        reason = EXCLUDED.reason,
		        actor_id = EXCLUDED.actor_id,
		        actor_kind = EXCLUDED.actor_kind,
		        request_id = EXCLUDED.request_id,
		        correlation_id = EXCLUDED.correlation_id,
		        effective_from = EXCLUDED.effective_from,
		        effective_until = EXCLUDED.effective_until,
		        metadata = EXCLUDED.metadata
		 RETURNING `+subscriptionEntitlementColumns,
		ent.ID, ent.OrganizationID, ent.SubscriptionID, ent.Source, ent.EntitlementKey, ent.LimitValue,
		ent.EnforcementMode, ent.Reason, ent.ActorID, ent.ActorKind, ent.RequestID, ent.CorrelationID,
		ent.EffectiveFrom, ent.EffectiveUntil, ent.Metadata,
	).Scan(
		&ent.ID, &ent.OrganizationID, &ent.SubscriptionID, &ent.Source, &ent.EntitlementKey, &ent.LimitValue,
		&ent.EnforcementMode, &ent.Reason, &ent.ActorID, &ent.ActorKind, &ent.RequestID, &ent.CorrelationID,
		&ent.EffectiveFrom, &ent.EffectiveUntil, &ent.Metadata, &ent.CreatedAt, &ent.UpdatedAt,
	)
	if err != nil {
		return SubscriptionEntitlement{}, mapWriteError(err, "upsert subscription entitlement")
	}
	return ent, nil
}

// ResolveEntitlements returns the active runtime entitlements for an organization.
//
// Precedence is deterministic and public-contract relevant:
// plan defaults < subscription overrides < emergency admin overrides. Within
// one override layer, the newest active effective_from wins, then newest row
// creation time, then id as a stable tie-breaker.
func (r *SubscriptionRepository) ResolveEntitlements(ctx context.Context, q Querier, organizationID string, at time.Time) ([]EffectiveEntitlement, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	rows, err := q.Query(ctx,
		`WITH current_subscription AS (
		    SELECT id, plan_id, current_period_start, current_period_end
		      FROM subscriptions
		     WHERE organization_id = $1
		       AND status IN ('trialing', 'active', 'past_due')
		       AND current_period_start <= $2
		       AND current_period_end > $2
		     ORDER BY current_period_start DESC, created_at DESC, id DESC
		     LIMIT 1
		 ),
		 candidates AS (
		    SELECT pe.entitlement_key,
		           pe.limit_value,
		           pe.enforcement_mode,
		           'plan'::text AS source,
		           cs.plan_id,
		           cs.id AS subscription_id,
		           NULL::text AS override_id,
		           cs.current_period_start,
		           cs.current_period_end,
		           0 AS precedence,
		           pe.created_at,
		           pe.id
		      FROM current_subscription cs
		      JOIN plan_entitlements pe ON pe.plan_id = cs.plan_id
		    UNION ALL
		    SELECT se.entitlement_key,
		           se.limit_value,
		           se.enforcement_mode,
		           se.source::text AS source,
		           cs.plan_id,
		           cs.id AS subscription_id,
		           se.id AS override_id,
		           cs.current_period_start,
		           cs.current_period_end,
		           CASE se.source WHEN 'subscription_override' THEN 1 ELSE 2 END AS precedence,
		           se.effective_from AS created_at,
		           se.id
		      FROM current_subscription cs
		      JOIN subscription_entitlements se
		        ON se.organization_id = $1
		       AND (
		            (se.source = 'subscription_override' AND se.subscription_id = cs.id)
		         OR (se.source = 'emergency_admin' AND se.subscription_id IS NULL)
		       )
		       AND se.effective_from <= $2
		       AND (se.effective_until IS NULL OR se.effective_until > $2)
		 )
		 SELECT DISTINCT ON (entitlement_key)
		        entitlement_key, limit_value, enforcement_mode, source, plan_id, subscription_id, COALESCE(override_id, ''), current_period_start, current_period_end
		   FROM candidates
		  ORDER BY entitlement_key, precedence DESC, created_at DESC, id DESC`,
		strings.TrimSpace(organizationID), at,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	out := make([]EffectiveEntitlement, 0)
	for rows.Next() {
		var ent EffectiveEntitlement
		if err := rows.Scan(
			&ent.EntitlementKey, &ent.LimitValue, &ent.EnforcementMode, &ent.Source,
			&ent.PlanID, &ent.SubscriptionID, &ent.OverrideID, &ent.PeriodStart, &ent.PeriodEnd,
		); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		out = append(out, ent)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// EntitlementRevision returns a deterministic change token for the rows that
// can affect organizationID's resolved entitlement snapshot. The resolver uses
// it to validate its cache before replaying a snapshot.
func (r *SubscriptionRepository) EntitlementRevision(ctx context.Context, q Querier, organizationID string, at time.Time) (string, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var revision string
	err := q.QueryRow(ctx,
		`WITH current_subscription AS (
		    SELECT id, plan_id, updated_at
		      FROM subscriptions
		     WHERE organization_id = $1
		       AND status IN ('trialing', 'active', 'past_due')
		       AND current_period_start <= $2
		       AND current_period_end > $2
		     ORDER BY current_period_start DESC, created_at DESC, id DESC
		     LIMIT 1
		 ),
		 stamps AS (
		    SELECT updated_at FROM current_subscription
		    UNION ALL
		    SELECT p.updated_at
		      FROM current_subscription cs
		      JOIN plans p ON p.id = cs.plan_id
		    UNION ALL
		    SELECT pe.updated_at
		      FROM current_subscription cs
		      JOIN plan_entitlements pe ON pe.plan_id = cs.plan_id
		    UNION ALL
		    SELECT se.updated_at
		      FROM current_subscription cs
		      JOIN subscription_entitlements se
		        ON se.organization_id = $1
		       AND (
		            (se.source = 'subscription_override' AND se.subscription_id = cs.id)
		         OR (se.source = 'emergency_admin' AND se.subscription_id IS NULL)
		       )
		 )
		 SELECT COALESCE(
		        to_char(max(updated_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || ':' || count(*)::text,
		        'no-current-subscription:0'
		    )
		   FROM stamps`,
		strings.TrimSpace(organizationID), at,
	).Scan(&revision)
	if err != nil {
		return "", apierr.StoreUnavailable(err)
	}
	return revision, nil
}

// PlanLookup returns the accepted plan slug for the organization at read time.
func (r *SubscriptionRepository) PlanLookup(ctx context.Context, q Querier, organizationID string) (string, error) {
	var slug string
	err := q.QueryRow(ctx,
		`SELECT p.slug
		   FROM subscriptions s
		   JOIN plans p ON p.id = s.plan_id
		  WHERE s.organization_id = $1
		    AND s.status IN ('trialing', 'active', 'past_due')
		    AND s.current_period_start <= now()
		    AND s.current_period_end > now()
		  ORDER BY s.current_period_start DESC, s.created_at DESC, s.id DESC
		  LIMIT 1`,
		strings.TrimSpace(organizationID),
	).Scan(&slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPlan, nil
	}
	if err != nil {
		return "", apierr.StoreUnavailable(err)
	}
	return slug, nil
}

func buildSubscriptionToCreate(in CreateSubscriptionInput) (Subscription, error) {
	var violations []apierr.FieldViolation
	id := strings.TrimSpace(in.SubscriptionID)
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	planID := strings.TrimSpace(in.PlanID)
	if planID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !in.Status.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "must be trialing, active, past_due, or canceled"})
	}
	if in.CurrentPeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "current_period_start", Reason: "must not be zero"})
	}
	if !in.CurrentPeriodEnd.After(in.CurrentPeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "current_period_end", Reason: "must be after current_period_start"})
	}
	if in.Status == SubscriptionStatusCanceled && in.CanceledAt == nil {
		violations = append(violations, apierr.FieldViolation{Field: "canceled_at", Reason: "must be set when status is canceled"})
	}
	if in.Status == SubscriptionStatusTrialing && in.TrialEndsAt == nil {
		violations = append(violations, apierr.FieldViolation{Field: "trial_ends_at", Reason: "must be set when status is trialing"})
	}
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = "manual"
	}
	if !validProviderKey(provider) {
		violations = append(violations, apierr.FieldViolation{Field: "provider", Reason: "must be a canonical provider key"})
	}
	if len(violations) > 0 {
		return Subscription{}, apierr.InvalidInput(violations...)
	}
	metadata := in.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	return Subscription{
		ID:                     id,
		OrganizationID:         organizationID,
		PlanID:                 planID,
		Status:                 in.Status,
		CurrentPeriodStart:     in.CurrentPeriodStart,
		CurrentPeriodEnd:       in.CurrentPeriodEnd,
		Provider:               provider,
		ProviderCustomerID:     cleanOptionalString(in.ProviderCustomerID),
		ProviderSubscriptionID: cleanOptionalString(in.ProviderSubscriptionID),
		CancelAtPeriodEnd:      in.CancelAtPeriodEnd,
		CanceledAt:             in.CanceledAt,
		TrialEndsAt:            in.TrialEndsAt,
		Metadata:               metadata,
	}, nil
}

func buildSubscriptionEntitlementToUpsert(in UpsertSubscriptionEntitlementInput) (SubscriptionEntitlement, error) {
	var violations []apierr.FieldViolation
	id := strings.TrimSpace(in.EntitlementID)
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	subscriptionID := strings.TrimSpace(in.SubscriptionID)
	if !in.Source.validOverride() {
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be subscription_override or emergency_admin"})
	}
	if in.Source == EntitlementSourceSubscriptionOverride && subscriptionID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must be set for subscription overrides"})
	}
	if in.Source == EntitlementSourceEmergencyAdmin && subscriptionID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must be blank for emergency admin overrides"})
	}
	key := strings.TrimSpace(in.EntitlementKey)
	if !validEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if in.LimitValue != nil && *in.LimitValue < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "limit_value", Reason: "must not be negative"})
	}
	if !validPlanEnforcementMode(in.EnforcementMode) {
		violations = append(violations, apierr.FieldViolation{Field: "enforcement_mode", Reason: "must be hard, soft, metered, or disabled"})
	}
	reason := output.NewRedactor().Redact(strings.TrimSpace(in.Reason))
	if reason == "" || !utf8.ValidString(reason) {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be non-empty valid UTF-8"})
	} else if len(reason) > 500 {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be at most 500 bytes"})
	}
	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" || len(actorID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must be 1 to 128 bytes"})
	}
	actorKind := strings.TrimSpace(in.ActorKind)
	if !validActorKind(actorKind) {
		violations = append(violations, apierr.FieldViolation{Field: "actor_kind", Reason: "must be a known actor kind"})
	}
	requestID := strings.TrimSpace(in.RequestID)
	if requestID == "" || len(requestID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must be 1 to 128 bytes"})
	}
	correlationID := strings.TrimSpace(in.CorrelationID)
	if correlationID == "" || len(correlationID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "correlation_id", Reason: "must be 1 to 128 bytes"})
	}
	if in.EffectiveFrom.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "effective_from", Reason: "must not be zero"})
	}
	if in.EffectiveUntil != nil && !in.EffectiveUntil.After(in.EffectiveFrom) {
		violations = append(violations, apierr.FieldViolation{Field: "effective_until", Reason: "must be after effective_from"})
	}
	if len(violations) > 0 {
		return SubscriptionEntitlement{}, apierr.InvalidInput(violations...)
	}
	metadata := in.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	var subID *string
	if subscriptionID != "" {
		subID = &subscriptionID
	}
	return SubscriptionEntitlement{
		ID:              id,
		OrganizationID:  organizationID,
		SubscriptionID:  subID,
		Source:          in.Source,
		EntitlementKey:  key,
		LimitValue:      in.LimitValue,
		EnforcementMode: in.EnforcementMode,
		Reason:          reason,
		ActorID:         actorID,
		ActorKind:       actorKind,
		RequestID:       requestID,
		CorrelationID:   correlationID,
		EffectiveFrom:   in.EffectiveFrom,
		EffectiveUntil:  in.EffectiveUntil,
		Metadata:        metadata,
	}, nil
}

func validProviderKey(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-'
		if !ok {
			return false
		}
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func cleanOptionalString(v *string) *string {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		return nil
	}
	return &s
}

func validActorKind(kind string) bool {
	switch kind {
	case "user", "api_key", "service_account", "worker", "system":
		return true
	default:
		return false
	}
}
