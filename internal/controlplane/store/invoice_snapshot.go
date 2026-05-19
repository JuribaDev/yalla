package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// InvoiceSnapshotStatus is the lifecycle for a billing-period invoice basis.
type InvoiceSnapshotStatus string

const (
	// InvoiceSnapshotStatusClosed marks a finalized billing-period invoice basis.
	InvoiceSnapshotStatusClosed InvoiceSnapshotStatus = "closed"
	// InvoiceSnapshotStatusReopened marks a snapshot superseded for an audited correction.
	InvoiceSnapshotStatusReopened InvoiceSnapshotStatus = "reopened"
)

func (s InvoiceSnapshotStatus) valid() bool {
	switch s {
	case InvoiceSnapshotStatusClosed, InvoiceSnapshotStatusReopened:
		return true
	default:
		return false
	}
}

// InvoiceSnapshotExportStatus mirrors the linked provider export state.
type InvoiceSnapshotExportStatus string

const (
	// InvoiceSnapshotExportStatusNone means no provider export was linked.
	InvoiceSnapshotExportStatusNone InvoiceSnapshotExportStatus = "none"
	// InvoiceSnapshotExportStatusPending means the linked export awaits provider acceptance.
	InvoiceSnapshotExportStatusPending InvoiceSnapshotExportStatus = "pending"
	// InvoiceSnapshotExportStatusSucceeded means the linked export was accepted.
	InvoiceSnapshotExportStatusSucceeded InvoiceSnapshotExportStatus = "succeeded"
	// InvoiceSnapshotExportStatusFailed means the linked export failed and may retry.
	InvoiceSnapshotExportStatusFailed InvoiceSnapshotExportStatus = "failed"
)

func invoiceSnapshotExportStatusFromBilling(status BillingExportStatus) InvoiceSnapshotExportStatus {
	switch status {
	case BillingExportStatusPending:
		return InvoiceSnapshotExportStatusPending
	case BillingExportStatusSucceeded:
		return InvoiceSnapshotExportStatusSucceeded
	case BillingExportStatusFailed:
		return InvoiceSnapshotExportStatusFailed
	default:
		return InvoiceSnapshotExportStatusNone
	}
}

func (s InvoiceSnapshotExportStatus) valid() bool {
	switch s {
	case InvoiceSnapshotExportStatusNone, InvoiceSnapshotExportStatusPending, InvoiceSnapshotExportStatusSucceeded, InvoiceSnapshotExportStatusFailed:
		return true
	default:
		return false
	}
}

// InvoiceSnapshot is an immutable-ish invoice basis for one closed billing
// period. Corrections reopen the row and create a later close_version rather
// than mutating the original item quantities.
type InvoiceSnapshot struct {
	ID                  string
	OrganizationID      string
	SubscriptionID      string
	BillingExportID     *string
	PeriodStart         time.Time
	PeriodEnd           time.Time
	Status              InvoiceSnapshotStatus
	CloseVersion        int
	AggregationVersion  int
	ClosedAt            time.Time
	ReopenedAt          *time.Time
	ReopenedByActorID   *string
	PlanID              string
	PlanSlug            string
	PlanVersion         int
	EntitlementRevision string
	UsageEventChecksum  string
	AdjustmentChecksum  string
	ExportStatus        InvoiceSnapshotExportStatus
	RequestID           string
	CorrelationID       string
	Items               []InvoiceSnapshotItem
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// InvoiceSnapshotItem freezes one usage counter plus any late adjustments.
type InvoiceSnapshotItem struct {
	ID                 string
	OrganizationID     string
	SnapshotID         string
	CounterID          string
	Key                string
	Unit               string
	Source             string
	CounterQuantity    float64
	AdjustmentQuantity float64
	FinalQuantity      float64
	AggregationVersion int
	EntitlementKey     *string
	OveragePolicyMode  *string
	OverageDecision    *string
	IncludedQuantity   *float64
	OverageQuantity    *float64
	CreatedAt          time.Time
}

// CloseInvoiceSnapshotInput identifies the billing period to close.
type CloseInvoiceSnapshotInput struct {
	OrganizationID     string
	SubscriptionID     string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	ClosedAt           time.Time
	AggregationVersion int
	RequestID          string
	CorrelationID      string
}

// ReopenInvoiceSnapshotInput records an audited administrative correction.
type ReopenInvoiceSnapshotInput struct {
	OrganizationID string
	SnapshotID     string
	ActorID        string
	ActorKind      string
	Reason         string
	ReopenedAt     time.Time
	RequestID      string
	CorrelationID  string
}

// InvoiceSnapshotRepository persists invoice-period close snapshots.
type InvoiceSnapshotRepository struct{}

// NewInvoiceSnapshotRepository returns a stateless invoice snapshot repository.
func NewInvoiceSnapshotRepository() *InvoiceSnapshotRepository { return &InvoiceSnapshotRepository{} }

const invoiceSnapshotSelectColumns = `s.id, s.organization_id, s.subscription_id, s.billing_export_id, s.period_start, s.period_end, s.status, s.close_version, s.aggregation_version, s.closed_at, s.reopened_at, s.reopened_by_actor_id, s.plan_id, s.plan_slug, s.plan_version, s.entitlement_revision, s.usage_event_checksum, s.adjustment_checksum, COALESCE(b.status, s.export_status) AS export_status, s.request_id, s.correlation_id, s.created_at, s.updated_at`

const invoiceSnapshotReturningColumns = `id, organization_id, subscription_id, billing_export_id, period_start, period_end, status, close_version, aggregation_version, closed_at, reopened_at, reopened_by_actor_id, plan_id, plan_slug, plan_version, entitlement_revision, usage_event_checksum, adjustment_checksum, export_status, request_id, correlation_id, created_at, updated_at`

const invoiceSnapshotItemColumns = `id, organization_id, snapshot_id, counter_id, key, unit, source, counter_quantity, adjustment_quantity, final_quantity, aggregation_version, entitlement_key, overage_policy_mode, overage_decision, included_quantity, overage_quantity, created_at`

type invoiceSnapshotSubscription struct {
	Subscription
	PlanSlug    string
	PlanVersion int
}

// Close closes the billing period, prepares the provider-neutral export, and
// stores a reproducible item snapshot from frozen usage counters.
func (r *InvoiceSnapshotRepository) Close(ctx context.Context, tx *Tx, in CloseInvoiceSnapshotInput) (InvoiceSnapshot, error) {
	if tx == nil {
		return InvoiceSnapshot{}, apierr.Internal(errors.New("store: InvoiceSnapshotRepository.Close called with a nil transaction"))
	}
	input, err := buildCloseInvoiceSnapshotInput(in)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	sub, err := r.lockSubscription(ctx, tx, input.OrganizationID, input.SubscriptionID)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	latest, hasLatest, err := r.lockLatest(ctx, tx, input.OrganizationID, input.SubscriptionID, input.PeriodStart, input.PeriodEnd)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	if hasLatest && latest.Status == InvoiceSnapshotStatusClosed {
		return r.Get(ctx, tx, latest.OrganizationID, latest.ID)
	}
	closeVersion := 1
	if hasLatest {
		closeVersion = latest.CloseVersion + 1
	}
	entitlementRevision, err := NewSubscriptionRepository().EntitlementRevision(ctx, tx, input.OrganizationID, input.PeriodStart)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	usageChecksum, err := r.usageEventChecksum(ctx, tx, input)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	adjustmentChecksum, err := r.adjustmentChecksum(ctx, tx, input)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	export, err := NewBillingExportRepository().Prepare(ctx, tx, PrepareBillingExportInput{
		OrganizationID: input.OrganizationID,
		SubscriptionID: input.SubscriptionID,
		Provider:       sub.Provider,
		PeriodStart:    input.PeriodStart,
		PeriodEnd:      input.PeriodEnd,
		RequestedAt:    input.ClosedAt,
	})
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	snapshotID, err := newOpaqueStoreID("inv")
	if err != nil {
		return InvoiceSnapshot{}, apierr.Internal(err)
	}
	exportStatus := invoiceSnapshotExportStatusFromBilling(export.Status)
	inserted, err := scanInvoiceSnapshot(tx.QueryRow(ctx,
		`INSERT INTO invoice_snapshots
		    (id, organization_id, subscription_id, billing_export_id, period_start, period_end,
		     close_version, aggregation_version, closed_at, plan_id, plan_slug, plan_version,
		     entitlement_revision, usage_event_checksum, adjustment_checksum, export_status,
		     request_id, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		 RETURNING `+invoiceSnapshotReturningColumns,
		snapshotID, input.OrganizationID, input.SubscriptionID, export.ID, input.PeriodStart, input.PeriodEnd,
		closeVersion, input.AggregationVersion, input.ClosedAt, sub.PlanID, sub.PlanSlug, sub.PlanVersion,
		entitlementRevision, usageChecksum, adjustmentChecksum, exportStatus, input.RequestID, input.CorrelationID,
	))
	if err != nil {
		return InvoiceSnapshot{}, mapWriteError(err, "close invoice snapshot")
	}
	if err := r.snapshotItems(ctx, tx, inserted); err != nil {
		return InvoiceSnapshot{}, err
	}
	return r.Get(ctx, tx, inserted.OrganizationID, inserted.ID)
}

// ReopenForCorrection marks a closed snapshot as superseded by an audited
// correction workflow. New close attempts create the next close_version.
func (r *InvoiceSnapshotRepository) ReopenForCorrection(ctx context.Context, tx *Tx, in ReopenInvoiceSnapshotInput) (InvoiceSnapshot, error) {
	if tx == nil {
		return InvoiceSnapshot{}, apierr.Internal(errors.New("store: InvoiceSnapshotRepository.ReopenForCorrection called with a nil transaction"))
	}
	input, reason, err := buildReopenInvoiceSnapshotInput(in)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	updated, err := scanInvoiceSnapshot(tx.QueryRow(ctx,
		`UPDATE invoice_snapshots s
		    SET status = 'reopened',
		        reopened_at = $3,
		        reopened_by_actor_id = $4
		   FROM billing_exports b
		  WHERE s.organization_id = $1
		    AND s.id = $2
		    AND s.status = 'closed'
		    AND b.organization_id = s.organization_id
		    AND b.id = s.billing_export_id
		 RETURNING `+invoiceSnapshotSelectColumns,
		input.OrganizationID, input.SnapshotID, input.ReopenedAt, input.ActorID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return InvoiceSnapshot{}, apierr.NotFound("invoice_snapshot", input.SnapshotID)
	}
	if err != nil {
		return InvoiceSnapshot{}, mapWriteError(err, "reopen invoice snapshot")
	}
	_, err = NewAuditRepository().Append(ctx, tx, AuditEvent{
		OrganizationID: input.OrganizationID,
		ActorID:        input.ActorID,
		ActorKind:      input.ActorKind,
		Action:         "billing.invoice_snapshot.reopen",
		ResourceKind:   "invoice_snapshot",
		ResourceID:     updated.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         reason,
		RequestID:      input.RequestID,
		CorrelationID:  input.CorrelationID,
		Metadata: map[string]string{
			"reason":        reason,
			"close_version": fmt.Sprintf("%d", updated.CloseVersion),
			"period_start":  updated.PeriodStart.Format(time.RFC3339),
			"period_end":    updated.PeriodEnd.Format(time.RFC3339),
		},
	})
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	return r.Get(ctx, tx, updated.OrganizationID, updated.ID)
}

// Get reads one tenant-scoped invoice snapshot plus frozen items.
func (r *InvoiceSnapshotRepository) Get(ctx context.Context, q Querier, organizationID, id string) (InvoiceSnapshot, error) {
	snapshot, err := scanInvoiceSnapshot(q.QueryRow(ctx,
		`SELECT `+invoiceSnapshotSelectColumns+`
		   FROM invoice_snapshots s
		   LEFT JOIN billing_exports b
		     ON b.organization_id = s.organization_id
		    AND b.id = s.billing_export_id
		  WHERE s.organization_id = $1 AND s.id = $2`,
		strings.TrimSpace(organizationID), strings.TrimSpace(id),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return InvoiceSnapshot{}, apierr.NotFound("invoice_snapshot", id)
	}
	if err != nil {
		return InvoiceSnapshot{}, apierr.StoreUnavailable(err)
	}
	items, err := r.listItems(ctx, q, snapshot.OrganizationID, snapshot.ID)
	if err != nil {
		return InvoiceSnapshot{}, err
	}
	snapshot.Items = items
	return snapshot, nil
}

func buildCloseInvoiceSnapshotInput(in CloseInvoiceSnapshotInput) (CloseInvoiceSnapshotInput, error) {
	out := CloseInvoiceSnapshotInput{
		OrganizationID:     strings.TrimSpace(in.OrganizationID),
		SubscriptionID:     strings.TrimSpace(in.SubscriptionID),
		PeriodStart:        in.PeriodStart.UTC(),
		PeriodEnd:          in.PeriodEnd.UTC(),
		ClosedAt:           in.ClosedAt.UTC(),
		AggregationVersion: in.AggregationVersion,
		RequestID:          strings.TrimSpace(in.RequestID),
		CorrelationID:      strings.TrimSpace(in.CorrelationID),
	}
	var violations []apierr.FieldViolation
	if out.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if out.SubscriptionID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must not be blank"})
	}
	if out.PeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_start", Reason: "must not be zero"})
	}
	if out.PeriodEnd.IsZero() || !out.PeriodEnd.After(out.PeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must be after period_start"})
	}
	if out.ClosedAt.IsZero() || out.ClosedAt.Before(out.PeriodEnd) {
		violations = append(violations, apierr.FieldViolation{Field: "closed_at", Reason: "must be at or after period_end"})
	}
	if out.AggregationVersion <= 0 {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_version", Reason: "must be positive"})
	}
	if out.RequestID == "" || len(out.RequestID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must be 1 to 128 bytes"})
	}
	if out.CorrelationID == "" || len(out.CorrelationID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "correlation_id", Reason: "must be 1 to 128 bytes"})
	}
	if len(violations) > 0 {
		return CloseInvoiceSnapshotInput{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func buildReopenInvoiceSnapshotInput(in ReopenInvoiceSnapshotInput) (ReopenInvoiceSnapshotInput, string, error) {
	out := ReopenInvoiceSnapshotInput{
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		SnapshotID:     strings.TrimSpace(in.SnapshotID),
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		ReopenedAt:     in.ReopenedAt.UTC(),
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}
	reason := output.NewRedactor().Redact(strings.TrimSpace(in.Reason))
	var violations []apierr.FieldViolation
	if out.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if out.SnapshotID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "snapshot_id", Reason: "must not be blank"})
	}
	if out.ActorID == "" || len(out.ActorID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must be 1 to 128 bytes"})
	}
	if !validActorKind(out.ActorKind) {
		violations = append(violations, apierr.FieldViolation{Field: "actor_kind", Reason: "must be a known actor kind"})
	}
	if reason == "" || len(reason) > 500 {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be 1 to 500 bytes after redaction"})
	}
	if out.ReopenedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "reopened_at", Reason: "must not be zero"})
	}
	if out.RequestID == "" || len(out.RequestID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must be 1 to 128 bytes"})
	}
	if out.CorrelationID == "" || len(out.CorrelationID) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "correlation_id", Reason: "must be 1 to 128 bytes"})
	}
	if len(violations) > 0 {
		return ReopenInvoiceSnapshotInput{}, "", apierr.InvalidInput(violations...)
	}
	return out, reason, nil
}

func (r *InvoiceSnapshotRepository) lockSubscription(ctx context.Context, q Querier, organizationID, subscriptionID string) (invoiceSnapshotSubscription, error) {
	var sub invoiceSnapshotSubscription
	err := q.QueryRow(ctx,
		`SELECT s.id, s.organization_id, s.plan_id, s.status, s.current_period_start, s.current_period_end,
		        s.provider, s.provider_customer_id, s.provider_subscription_id, s.cancel_at_period_end,
		        s.canceled_at, s.trial_ends_at, s.metadata, s.created_at, s.updated_at,
		        p.slug, p.version
		   FROM subscriptions s
		   JOIN plans p ON p.id = s.plan_id
		  WHERE s.organization_id = $1 AND s.id = $2
		  FOR UPDATE`,
		organizationID, subscriptionID,
	).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.Status, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.Provider, &sub.ProviderCustomerID, &sub.ProviderSubscriptionID, &sub.CancelAtPeriodEnd,
		&sub.CanceledAt, &sub.TrialEndsAt, &sub.Metadata, &sub.CreatedAt, &sub.UpdatedAt,
		&sub.PlanSlug, &sub.PlanVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return invoiceSnapshotSubscription{}, apierr.NotFound("subscription", subscriptionID)
	}
	if err != nil {
		return invoiceSnapshotSubscription{}, apierr.StoreUnavailable(err)
	}
	return sub, nil
}

func (r *InvoiceSnapshotRepository) lockLatest(ctx context.Context, q Querier, organizationID, subscriptionID string, periodStart, periodEnd time.Time) (InvoiceSnapshot, bool, error) {
	snapshot, err := scanInvoiceSnapshot(q.QueryRow(ctx,
		`SELECT `+invoiceSnapshotSelectColumns+`
		   FROM invoice_snapshots s
		   LEFT JOIN billing_exports b
		     ON b.organization_id = s.organization_id
		    AND b.id = s.billing_export_id
		  WHERE s.organization_id = $1
		    AND s.subscription_id = $2
		    AND s.period_start = $3
		    AND s.period_end = $4
		  ORDER BY s.close_version DESC
		  LIMIT 1
		  FOR UPDATE OF s`,
		organizationID, subscriptionID, periodStart, periodEnd,
	))
	if err == nil {
		return snapshot, true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return InvoiceSnapshot{}, false, nil
	}
	return InvoiceSnapshot{}, false, apierr.StoreUnavailable(err)
}

func (r *InvoiceSnapshotRepository) snapshotItems(ctx context.Context, tx *Tx, snapshot InvoiceSnapshot) error {
	rows, err := tx.Query(ctx,
		`SELECT c.id, c.key, c.unit, c.source, c.quantity,
		        COALESCE(SUM(a.delta_quantity), 0)::double precision AS adjustment_quantity,
		        c.aggregation_version, c.entitlement_key, c.overage_policy_mode, c.overage_decision,
		        c.included_quantity, c.overage_quantity
		   FROM usage_counters c
		   LEFT JOIN usage_counter_adjustments a
		     ON a.organization_id = c.organization_id
		    AND a.counter_id = c.id
		  WHERE c.organization_id = $1
		    AND c.period_start = $2
		    AND c.period_end = $3
		  GROUP BY c.id, c.key, c.unit, c.source, c.quantity, c.aggregation_version,
		           c.entitlement_key, c.overage_policy_mode, c.overage_decision,
		           c.included_quantity, c.overage_quantity
		  ORDER BY c.key, c.unit, c.source`,
		snapshot.OrganizationID, snapshot.PeriodStart, snapshot.PeriodEnd,
	)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	for rows.Next() {
		var counterID, key, unit, source string
		var counterQuantity, adjustmentQuantity float64
		var aggregationVersion int
		var entitlementKey, overagePolicyMode, overageDecision *string
		var includedQuantity, overageQuantity *float64
		if err := rows.Scan(&counterID, &key, &unit, &source, &counterQuantity, &adjustmentQuantity, &aggregationVersion, &entitlementKey, &overagePolicyMode, &overageDecision, &includedQuantity, &overageQuantity); err != nil {
			return apierr.StoreUnavailable(err)
		}
		if nonFinite(counterQuantity) || nonFinite(adjustmentQuantity) {
			return apierr.Internal(errors.New("store: non-finite invoice snapshot quantity"))
		}
		itemID, err := newOpaqueStoreID("invi")
		if err != nil {
			return apierr.Internal(err)
		}
		finalQuantity := counterQuantity + adjustmentQuantity
		if _, err := tx.Exec(ctx,
			`INSERT INTO invoice_snapshot_items
			    (id, organization_id, snapshot_id, counter_id, key, unit, source,
			     counter_quantity, adjustment_quantity, final_quantity, aggregation_version,
			     entitlement_key, overage_policy_mode, overage_decision, included_quantity, overage_quantity)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			 ON CONFLICT (organization_id, snapshot_id, counter_id) DO NOTHING`,
			itemID, snapshot.OrganizationID, snapshot.ID, counterID, key, unit, source,
			counterQuantity, adjustmentQuantity, finalQuantity, aggregationVersion,
			entitlementKey, overagePolicyMode, overageDecision, includedQuantity, overageQuantity,
		); err != nil {
			return mapWriteError(err, "snapshot invoice item")
		}
	}
	if err := rows.Err(); err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

func (r *InvoiceSnapshotRepository) usageEventChecksum(ctx context.Context, q Querier, in CloseInvoiceSnapshotInput) (string, error) {
	var checksum string
	err := q.QueryRow(ctx,
		`SELECT COALESCE(md5(string_agg(id || ':' || resource::text || ':' || event_type || ':' || quantity::text || ':' || unit || ':' || source || ':' || occurred_at::text, '|' ORDER BY id)), md5(''))
		   FROM usage_events
		  WHERE organization_id = $1
		    AND period_start = $2
		    AND period_end = $3`,
		in.OrganizationID, in.PeriodStart, in.PeriodEnd,
	).Scan(&checksum)
	if err != nil {
		return "", apierr.StoreUnavailable(err)
	}
	return checksum, nil
}

func (r *InvoiceSnapshotRepository) adjustmentChecksum(ctx context.Context, q Querier, in CloseInvoiceSnapshotInput) (string, error) {
	var checksum string
	err := q.QueryRow(ctx,
		`SELECT COALESCE(md5(string_agg(id || ':' || counter_id || ':' || delta_quantity::text || ':' || aggregation_version::text || ':' || reason, '|' ORDER BY id)), md5(''))
		   FROM usage_counter_adjustments
		  WHERE organization_id = $1
		    AND period_start = $2
		    AND period_end = $3`,
		in.OrganizationID, in.PeriodStart, in.PeriodEnd,
	).Scan(&checksum)
	if err != nil {
		return "", apierr.StoreUnavailable(err)
	}
	return checksum, nil
}

func (r *InvoiceSnapshotRepository) listItems(ctx context.Context, q Querier, organizationID, snapshotID string) ([]InvoiceSnapshotItem, error) {
	rows, err := q.Query(ctx,
		`SELECT `+invoiceSnapshotItemColumns+`
		   FROM invoice_snapshot_items
		  WHERE organization_id = $1 AND snapshot_id = $2
		  ORDER BY key, unit, source, counter_id`,
		organizationID, snapshotID,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	items := []InvoiceSnapshotItem{}
	for rows.Next() {
		item, err := scanInvoiceSnapshotItem(rows)
		if err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return items, nil
}

func scanInvoiceSnapshot(row pgx.Row) (InvoiceSnapshot, error) {
	var snapshot InvoiceSnapshot
	var status, exportStatus string
	var reopenedAt *time.Time
	if err := row.Scan(
		&snapshot.ID, &snapshot.OrganizationID, &snapshot.SubscriptionID, &snapshot.BillingExportID,
		&snapshot.PeriodStart, &snapshot.PeriodEnd, &status, &snapshot.CloseVersion,
		&snapshot.AggregationVersion, &snapshot.ClosedAt, &reopenedAt, &snapshot.ReopenedByActorID,
		&snapshot.PlanID, &snapshot.PlanSlug, &snapshot.PlanVersion, &snapshot.EntitlementRevision,
		&snapshot.UsageEventChecksum, &snapshot.AdjustmentChecksum, &exportStatus,
		&snapshot.RequestID, &snapshot.CorrelationID, &snapshot.CreatedAt, &snapshot.UpdatedAt,
	); err != nil {
		return InvoiceSnapshot{}, err
	}
	snapshot.Status = InvoiceSnapshotStatus(status)
	if !snapshot.Status.valid() {
		return InvoiceSnapshot{}, apierr.Internal(errors.New("store: invalid invoice snapshot status"))
	}
	snapshot.ExportStatus = InvoiceSnapshotExportStatus(exportStatus)
	if !snapshot.ExportStatus.valid() {
		return InvoiceSnapshot{}, apierr.Internal(errors.New("store: invalid invoice snapshot export status"))
	}
	snapshot.PeriodStart = snapshot.PeriodStart.UTC()
	snapshot.PeriodEnd = snapshot.PeriodEnd.UTC()
	snapshot.ClosedAt = snapshot.ClosedAt.UTC()
	snapshot.CreatedAt = snapshot.CreatedAt.UTC()
	snapshot.UpdatedAt = snapshot.UpdatedAt.UTC()
	if reopenedAt != nil {
		reopened := reopenedAt.UTC()
		snapshot.ReopenedAt = &reopened
	}
	return snapshot, nil
}

func scanInvoiceSnapshotItem(row pgx.Row) (InvoiceSnapshotItem, error) {
	var item InvoiceSnapshotItem
	if err := row.Scan(
		&item.ID, &item.OrganizationID, &item.SnapshotID, &item.CounterID,
		&item.Key, &item.Unit, &item.Source, &item.CounterQuantity,
		&item.AdjustmentQuantity, &item.FinalQuantity, &item.AggregationVersion,
		&item.EntitlementKey, &item.OveragePolicyMode, &item.OverageDecision,
		&item.IncludedQuantity, &item.OverageQuantity, &item.CreatedAt,
	); err != nil {
		return InvoiceSnapshotItem{}, err
	}
	item.CreatedAt = item.CreatedAt.UTC()
	return item, nil
}

func nonFinite(v float64) bool {
	return math.IsNaN(v) || math.IsInf(v, 0)
}
