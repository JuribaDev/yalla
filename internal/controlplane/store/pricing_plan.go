package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/jackc/pgx/v5"
)

// PlanStatus is the lifecycle state for a versioned pricing plan row. Updating
// a plan creates a new row version; archived rows remain as audit anchors for
// future subscriptions.
type PlanStatus string

const (
	// PlanStatusDraft is a version being prepared but not offered to new customers.
	PlanStatusDraft PlanStatus = "draft"
	// PlanStatusActive is the current offerable version for a slug and period.
	PlanStatusActive PlanStatus = "active"
	// PlanStatusArchived is retained for subscriptions that accepted that version.
	PlanStatusArchived PlanStatus = "archived"
)

func (s PlanStatus) String() string { return string(s) }

func (s PlanStatus) valid() bool {
	switch s {
	case PlanStatusDraft, PlanStatusActive, PlanStatusArchived:
		return true
	default:
		return false
	}
}

// BillingPeriod is the billing cadence a plan version applies to.
type BillingPeriod string

const (
	// BillingPeriodMonthly bills the plan every calendar month.
	BillingPeriodMonthly BillingPeriod = "monthly"
	// BillingPeriodAnnual bills the plan once per year.
	BillingPeriodAnnual BillingPeriod = "annual"
	// BillingPeriodCustom marks enterprise/manual cadences outside fixed periods.
	BillingPeriodCustom BillingPeriod = "custom"
)

func (p BillingPeriod) String() string { return string(p) }

func (p BillingPeriod) valid() bool {
	switch p {
	case BillingPeriodMonthly, BillingPeriodAnnual, BillingPeriodCustom:
		return true
	default:
		return false
	}
}

// Plan is one immutable version of a package in the pricing catalog. The
// current package is selected by (slug, billing_period, status=active); accepted
// subscriptions should hold onto the specific ID and Version.
type Plan struct {
	ID            string
	Slug          string
	Name          string
	Status        PlanStatus
	BillingPeriod BillingPeriod
	DisplayOrder  int
	Version       int
	ArchivedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// PlanEntitlement is one default entitlement attached to a plan version.
type PlanEntitlement struct {
	ID              string
	PlanID          string
	EntitlementKey  string
	LimitValue      *int64
	EnforcementMode EnforcementMode
	Metadata        []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreatePlanInput is the mutable catalog data needed to create one plan version.
type CreatePlanInput struct {
	Slug          string
	Name          string
	Status        PlanStatus
	BillingPeriod BillingPeriod
	DisplayOrder  int
	Version       int
}

// UpdatePlanInput describes the replacement version created by Update.
type UpdatePlanInput struct {
	Name         string
	Status       PlanStatus
	DisplayOrder int
}

// UpsertPlanEntitlementInput describes one default entitlement for a plan version.
type UpsertPlanEntitlementInput struct {
	PlanID          string
	EntitlementKey  string
	LimitValue      *int64
	EnforcementMode EnforcementMode
	Metadata        []byte
}

// PricingPlanRepository is the persistence surface for plans and plan_entitlements.
type PricingPlanRepository struct{}

// NewPricingPlanRepository returns a stateless pricing plan repository.
func NewPricingPlanRepository() *PricingPlanRepository { return &PricingPlanRepository{} }

const planColumns = `id, slug, name, status, billing_period, display_order, version, archived_at, created_at, updated_at`

const planEntitlementColumns = `id, plan_id, entitlement_key, limit_value, enforcement_mode, metadata, created_at, updated_at`

// Create inserts one plan version and returns the database-stamped row.
func (r *PricingPlanRepository) Create(ctx context.Context, tx *Tx, in CreatePlanInput) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.Create called with a nil transaction"))
	}
	plan, err := buildPlanToCreate(in)
	if err != nil {
		return Plan{}, err
	}
	planID, err := newOpaqueStoreID("plan")
	if err != nil {
		return Plan{}, apierr.Internal(err)
	}
	plan.ID = planID
	return r.insertPlan(ctx, tx, plan)
}

// Get reads one plan version by id.
func (r *PricingPlanRepository) Get(ctx context.Context, q Querier, id string) (Plan, error) {
	var plan Plan
	err := q.QueryRow(ctx,
		`SELECT `+planColumns+` FROM plans WHERE id = $1`,
		strings.TrimSpace(id),
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, apierr.NotFound("plan", id)
	}
	if err != nil {
		return Plan{}, apierr.StoreUnavailable(err)
	}
	return plan, nil
}

// GetBySlugVersion reads the exact accepted version for a package and billing period.
func (r *PricingPlanRepository) GetBySlugVersion(ctx context.Context, q Querier, slug string, period BillingPeriod, version int) (Plan, error) {
	var plan Plan
	err := q.QueryRow(ctx,
		`SELECT `+planColumns+` FROM plans WHERE slug = $1 AND billing_period = $2 AND version = $3`,
		strings.TrimSpace(slug), period, version,
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, apierr.NotFound("plan", slug)
	}
	if err != nil {
		return Plan{}, apierr.StoreUnavailable(err)
	}
	return plan, nil
}

// ListActive returns offerable plans in display order.
func (r *PricingPlanRepository) ListActive(ctx context.Context, q Querier) ([]Plan, error) {
	rows, err := q.Query(ctx,
		`SELECT `+planColumns+`
		   FROM plans
		  WHERE status = 'active'
		  ORDER BY display_order, slug, billing_period`,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	var plans []Plan
	for rows.Next() {
		var plan Plan
		if err := rows.Scan(
			&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
			&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
		); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		plans = append(plans, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return plans, nil
}

// Update archives the addressed plan row and inserts the next version. The old
// row remains immutable enough for accepted subscriptions to audit against it;
// entitlements are cloned onto the new version and can then be changed with
// UpsertEntitlement.
func (r *PricingPlanRepository) Update(ctx context.Context, tx *Tx, id string, in UpdatePlanInput) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.Update called with a nil transaction"))
	}
	update, err := validatePlanUpdate(in)
	if err != nil {
		return Plan{}, err
	}

	current, err := r.lockPlan(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return Plan{}, err
	}
	if current.Status == PlanStatusArchived {
		return Plan{}, apierr.Conflict("archived plan versions cannot be updated")
	}

	if _, err := tx.Exec(ctx,
		`UPDATE plans
		    SET status = 'archived', archived_at = now()
		  WHERE id = $1`,
		current.ID,
	); err != nil {
		return Plan{}, mapWriteError(err, "archive current plan version")
	}

	newPlanID, err := newOpaqueStoreID("plan")
	if err != nil {
		return Plan{}, apierr.Internal(err)
	}
	next := Plan{
		ID:            newPlanID,
		Slug:          current.Slug,
		Name:          update.Name,
		Status:        update.Status,
		BillingPeriod: current.BillingPeriod,
		DisplayOrder:  update.DisplayOrder,
		Version:       current.Version + 1,
	}
	inserted, err := r.insertPlan(ctx, tx, next)
	if err != nil {
		return Plan{}, err
	}
	if err := r.cloneEntitlements(ctx, tx, current.ID, inserted.ID); err != nil {
		return Plan{}, err
	}
	return inserted, nil
}

// CreateDraftFrom creates the next draft version for the addressed plan
// without archiving the currently active version. It is the backoffice edit
// path: runtime readers keep using the active row until an operator publishes
// the draft.
func (r *PricingPlanRepository) CreateDraftFrom(ctx context.Context, tx *Tx, id string, in UpdatePlanInput) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.CreateDraftFrom called with a nil transaction"))
	}
	update, err := validatePlanUpdate(in)
	if err != nil {
		return Plan{}, err
	}
	current, err := r.lockPlan(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return Plan{}, err
	}
	if current.Status == PlanStatusArchived {
		return Plan{}, apierr.Conflict("archived plan versions cannot be edited")
	}
	nextVersion, err := r.nextVersion(ctx, tx, current.Slug, current.BillingPeriod)
	if err != nil {
		return Plan{}, err
	}
	newPlanID, err := newOpaqueStoreID("plan")
	if err != nil {
		return Plan{}, apierr.Internal(err)
	}
	next := Plan{
		ID:            newPlanID,
		Slug:          current.Slug,
		Name:          update.Name,
		Status:        PlanStatusDraft,
		BillingPeriod: current.BillingPeriod,
		DisplayOrder:  update.DisplayOrder,
		Version:       nextVersion,
	}
	inserted, err := r.insertPlan(ctx, tx, next)
	if err != nil {
		return Plan{}, err
	}
	if err := r.cloneEntitlements(ctx, tx, current.ID, inserted.ID); err != nil {
		return Plan{}, err
	}
	return inserted, nil
}

// Publish promotes a draft to active and archives the previously active
// version for the same slug and billing period in the same transaction.
func (r *PricingPlanRepository) Publish(ctx context.Context, tx *Tx, id string) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.Publish called with a nil transaction"))
	}
	plan, err := r.lockPlan(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return Plan{}, err
	}
	if plan.Status == PlanStatusArchived {
		return Plan{}, apierr.Conflict("archived plan versions cannot be published")
	}
	if plan.Status == PlanStatusActive {
		return plan, nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE plans
		    SET status = 'archived', archived_at = now()
		  WHERE slug = $1
		    AND billing_period = $2
		    AND status = 'active'
		    AND id <> $3`,
		plan.Slug, plan.BillingPeriod, plan.ID,
	); err != nil {
		return Plan{}, mapWriteError(err, "archive active plan version")
	}
	err = tx.QueryRow(ctx,
		`UPDATE plans
		    SET status = 'active', archived_at = NULL
		  WHERE id = $1
		  RETURNING `+planColumns,
		plan.ID,
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if err != nil {
		return Plan{}, mapWriteError(err, "publish plan")
	}
	return plan, nil
}

// Rollback copies a historical plan version into a new active version.
func (r *PricingPlanRepository) Rollback(ctx context.Context, tx *Tx, sourceID string) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.Rollback called with a nil transaction"))
	}
	source, err := r.lockPlan(ctx, tx, strings.TrimSpace(sourceID))
	if err != nil {
		return Plan{}, err
	}
	nextVersion, err := r.nextVersion(ctx, tx, source.Slug, source.BillingPeriod)
	if err != nil {
		return Plan{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE plans
		    SET status = 'archived', archived_at = now()
		  WHERE slug = $1
		    AND billing_period = $2
		    AND status = 'active'`,
		source.Slug, source.BillingPeriod,
	); err != nil {
		return Plan{}, mapWriteError(err, "archive active plan version")
	}
	newPlanID, err := newOpaqueStoreID("plan")
	if err != nil {
		return Plan{}, apierr.Internal(err)
	}
	next := Plan{
		ID:            newPlanID,
		Slug:          source.Slug,
		Name:          source.Name,
		Status:        PlanStatusActive,
		BillingPeriod: source.BillingPeriod,
		DisplayOrder:  source.DisplayOrder,
		Version:       nextVersion,
	}
	inserted, err := r.insertPlan(ctx, tx, next)
	if err != nil {
		return Plan{}, err
	}
	if err := r.cloneEntitlements(ctx, tx, source.ID, inserted.ID); err != nil {
		return Plan{}, err
	}
	return inserted, nil
}

// Archive marks a plan version archived while preserving it for audit reads.
func (r *PricingPlanRepository) Archive(ctx context.Context, tx *Tx, id string) (Plan, error) {
	if tx == nil {
		return Plan{}, apierr.Internal(errors.New("store: PricingPlanRepository.Archive called with a nil transaction"))
	}
	plan, err := r.lockPlan(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return Plan{}, err
	}
	if plan.Status == PlanStatusArchived {
		return plan, nil
	}
	err = tx.QueryRow(ctx,
		`UPDATE plans
		    SET status = 'archived', archived_at = now()
		  WHERE id = $1
		  RETURNING `+planColumns,
		plan.ID,
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if err != nil {
		return Plan{}, mapWriteError(err, "archive plan")
	}
	return plan, nil
}

// UpsertEntitlement creates or replaces one entitlement on a plan version.
func (r *PricingPlanRepository) UpsertEntitlement(ctx context.Context, tx *Tx, in UpsertPlanEntitlementInput) (PlanEntitlement, error) {
	if tx == nil {
		return PlanEntitlement{}, apierr.Internal(errors.New("store: PricingPlanRepository.UpsertEntitlement called with a nil transaction"))
	}
	ent, err := buildPlanEntitlementToUpsert(in)
	if err != nil {
		return PlanEntitlement{}, err
	}
	entID, err := newOpaqueStoreID("pent")
	if err != nil {
		return PlanEntitlement{}, apierr.Internal(err)
	}
	ent.ID = entID
	err = tx.QueryRow(ctx,
		`INSERT INTO plan_entitlements
		    (id, plan_id, entitlement_key, limit_value, enforcement_mode, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (plan_id, entitlement_key) DO UPDATE
		    SET limit_value = EXCLUDED.limit_value,
		        enforcement_mode = EXCLUDED.enforcement_mode,
		        metadata = EXCLUDED.metadata
		 RETURNING `+planEntitlementColumns,
		ent.ID, ent.PlanID, ent.EntitlementKey, ent.LimitValue, ent.EnforcementMode, ent.Metadata,
	).Scan(
		&ent.ID, &ent.PlanID, &ent.EntitlementKey, &ent.LimitValue, &ent.EnforcementMode,
		&ent.Metadata, &ent.CreatedAt, &ent.UpdatedAt,
	)
	if err != nil {
		return PlanEntitlement{}, mapWriteError(err, "upsert plan entitlement")
	}
	return ent, nil
}

// RenameEntitlement changes an entitlement key on a plan version after the
// caller has performed migration-impact validation.
func (r *PricingPlanRepository) RenameEntitlement(ctx context.Context, tx *Tx, planID, fromKey, toKey string) (PlanEntitlement, error) {
	if tx == nil {
		return PlanEntitlement{}, apierr.Internal(errors.New("store: PricingPlanRepository.RenameEntitlement called with a nil transaction"))
	}
	planID = strings.TrimSpace(planID)
	fromKey = strings.TrimSpace(fromKey)
	toKey = strings.TrimSpace(toKey)
	var violations []apierr.FieldViolation
	if planID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !validEntitlementKey(fromKey) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if !validEntitlementKey(toKey) {
		violations = append(violations, apierr.FieldViolation{Field: "new_entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if fromKey == toKey {
		violations = append(violations, apierr.FieldViolation{Field: "new_entitlement_key", Reason: "must differ from entitlement_key"})
	}
	if len(violations) > 0 {
		return PlanEntitlement{}, apierr.InvalidInput(violations...)
	}

	var ent PlanEntitlement
	err := tx.QueryRow(ctx,
		`UPDATE plan_entitlements
		    SET entitlement_key = $3
		  WHERE plan_id = $1 AND entitlement_key = $2
		  RETURNING `+planEntitlementColumns,
		planID, fromKey, toKey,
	).Scan(
		&ent.ID, &ent.PlanID, &ent.EntitlementKey, &ent.LimitValue, &ent.EnforcementMode,
		&ent.Metadata, &ent.CreatedAt, &ent.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlanEntitlement{}, apierr.NotFound("plan_entitlement", fromKey)
	}
	if err != nil {
		return PlanEntitlement{}, mapWriteError(err, "rename plan entitlement")
	}
	return ent, nil
}

// DeleteEntitlement removes one entitlement from a plan version after the
// caller has performed migration-impact validation.
func (r *PricingPlanRepository) DeleteEntitlement(ctx context.Context, tx *Tx, planID, key string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: PricingPlanRepository.DeleteEntitlement called with a nil transaction"))
	}
	planID = strings.TrimSpace(planID)
	key = strings.TrimSpace(key)
	var violations []apierr.FieldViolation
	if planID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !validEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM plan_entitlements
		  WHERE plan_id = $1 AND entitlement_key = $2`,
		planID, key,
	)
	if err != nil {
		return mapWriteError(err, "delete plan entitlement")
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("plan_entitlement", key)
	}
	return nil
}

// ListEntitlements returns a plan version's entitlements in key order.
func (r *PricingPlanRepository) ListEntitlements(ctx context.Context, q Querier, planID string) ([]PlanEntitlement, error) {
	rows, err := q.Query(ctx,
		`SELECT `+planEntitlementColumns+`
		   FROM plan_entitlements
		  WHERE plan_id = $1
		  ORDER BY entitlement_key`,
		strings.TrimSpace(planID),
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	var out []PlanEntitlement
	for rows.Next() {
		var ent PlanEntitlement
		if err := rows.Scan(
			&ent.ID, &ent.PlanID, &ent.EntitlementKey, &ent.LimitValue, &ent.EnforcementMode,
			&ent.Metadata, &ent.CreatedAt, &ent.UpdatedAt,
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

func (r *PricingPlanRepository) insertPlan(ctx context.Context, tx *Tx, plan Plan) (Plan, error) {
	err := tx.QueryRow(ctx,
		`INSERT INTO plans
		    (id, slug, name, status, billing_period, display_order, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+planColumns,
		plan.ID, plan.Slug, plan.Name, plan.Status, plan.BillingPeriod, plan.DisplayOrder, plan.Version,
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if err != nil {
		return Plan{}, mapWriteError(err, "create plan")
	}
	return plan, nil
}

func (r *PricingPlanRepository) lockPlan(ctx context.Context, tx *Tx, id string) (Plan, error) {
	var plan Plan
	err := tx.QueryRow(ctx,
		`SELECT `+planColumns+` FROM plans WHERE id = $1 FOR UPDATE`,
		id,
	).Scan(
		&plan.ID, &plan.Slug, &plan.Name, &plan.Status, &plan.BillingPeriod,
		&plan.DisplayOrder, &plan.Version, &plan.ArchivedAt, &plan.CreatedAt, &plan.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, apierr.NotFound("plan", id)
	}
	if err != nil {
		return Plan{}, apierr.StoreUnavailable(err)
	}
	return plan, nil
}

func (r *PricingPlanRepository) cloneEntitlements(ctx context.Context, tx *Tx, fromPlanID, toPlanID string) error {
	rows, err := tx.Query(ctx,
		`SELECT entitlement_key, limit_value, enforcement_mode, metadata
		   FROM plan_entitlements
		  WHERE plan_id = $1
		  ORDER BY entitlement_key`,
		fromPlanID,
	)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}

	var inputs []UpsertPlanEntitlementInput
	for rows.Next() {
		var in UpsertPlanEntitlementInput
		in.PlanID = toPlanID
		if err := rows.Scan(&in.EntitlementKey, &in.LimitValue, &in.EnforcementMode, &in.Metadata); err != nil {
			rows.Close()
			return apierr.StoreUnavailable(err)
		}
		inputs = append(inputs, in)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return apierr.StoreUnavailable(err)
	}
	rows.Close()

	for _, in := range inputs {
		if _, err := r.UpsertEntitlement(ctx, tx, in); err != nil {
			return err
		}
	}
	return nil
}

func (r *PricingPlanRepository) nextVersion(ctx context.Context, q Querier, slug string, period BillingPeriod) (int, error) {
	var current int
	if err := q.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0)
		   FROM plans
		  WHERE slug = $1 AND billing_period = $2`,
		slug, period,
	).Scan(&current); err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return current + 1, nil
}

func buildPlanToCreate(in CreatePlanInput) (Plan, error) {
	var violations []apierr.FieldViolation
	slug, ok := cleanPlanSlug(in.Slug)
	if !ok {
		violations = append(violations, apierr.FieldViolation{Field: "slug", Reason: "must be a canonical plan slug"})
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must not be blank"})
	} else if !utf8.ValidString(name) {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be valid UTF-8"})
	} else if len(name) > 120 {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be at most 120 bytes"})
	}
	status := in.Status
	if status == "" {
		status = PlanStatusDraft
	}
	if !status.valid() || status == PlanStatusArchived {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "must be draft or active for a new plan"})
	}
	if !in.BillingPeriod.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "billing_period", Reason: "must be monthly, annual, or custom"})
	}
	version := in.Version
	if version == 0 {
		version = 1
	}
	if version < 1 {
		violations = append(violations, apierr.FieldViolation{Field: "version", Reason: "must be greater than zero"})
	}
	if in.DisplayOrder < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "display_order", Reason: "must not be negative"})
	}
	if len(violations) > 0 {
		return Plan{}, apierr.InvalidInput(violations...)
	}
	return Plan{
		Slug:          slug,
		Name:          name,
		Status:        status,
		BillingPeriod: in.BillingPeriod,
		DisplayOrder:  in.DisplayOrder,
		Version:       version,
	}, nil
}

func validatePlanUpdate(in UpdatePlanInput) (UpdatePlanInput, error) {
	var violations []apierr.FieldViolation
	name := strings.TrimSpace(in.Name)
	if name == "" {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must not be blank"})
	} else if !utf8.ValidString(name) {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be valid UTF-8"})
	} else if len(name) > 120 {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be at most 120 bytes"})
	}
	status := in.Status
	if status == "" {
		status = PlanStatusActive
	}
	if !status.valid() || status == PlanStatusArchived {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "must be draft or active for a new plan version"})
	}
	if in.DisplayOrder < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "display_order", Reason: "must not be negative"})
	}
	if len(violations) > 0 {
		return UpdatePlanInput{}, apierr.InvalidInput(violations...)
	}
	return UpdatePlanInput{Name: name, Status: status, DisplayOrder: in.DisplayOrder}, nil
}

func buildPlanEntitlementToUpsert(in UpsertPlanEntitlementInput) (PlanEntitlement, error) {
	var violations []apierr.FieldViolation
	planID := strings.TrimSpace(in.PlanID)
	if planID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
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
	if len(violations) > 0 {
		return PlanEntitlement{}, apierr.InvalidInput(violations...)
	}
	metadata := in.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	return PlanEntitlement{
		ID:              "",
		PlanID:          planID,
		EntitlementKey:  key,
		LimitValue:      in.LimitValue,
		EnforcementMode: in.EnforcementMode,
		Metadata:        metadata,
	}, nil
}

func cleanPlanSlug(raw string) (string, bool) {
	slug := strings.TrimSpace(strings.ToLower(raw))
	if slug == "" || len(slug) > 63 {
		return "", false
	}
	normalized, err := domain.NormalizeSlug(slug)
	if err != nil || normalized.String() != slug {
		return "", false
	}
	return slug, true
}

func validEntitlementKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for i, r := range key {
		ok := r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' ||
			r == '_' || r == '.' || r == '-'
		if !ok {
			return false
		}
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validPlanEnforcementMode(mode EnforcementMode) bool {
	switch mode {
	case EnforcementModeHard, EnforcementModeSoft, EnforcementModeMetered, EnforcementModeDisabled:
		return true
	default:
		return false
	}
}

func newOpaqueStoreID(prefix string) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(buf[:]), nil
}
