package store

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

var billingProviderSecretPattern = regexp.MustCompile(`(?i)\b(?:sk|pk|rk|whsec|tok|key)_(?:live|test|prod|secret)?[A-Za-z0-9_=-]{8,}\b`)

// BillingExportStatus is the durable lifecycle for provider export attempts.
type BillingExportStatus string

const (
	// BillingExportStatusPending is a prepared export that has not been accepted by a provider.
	BillingExportStatusPending BillingExportStatus = "pending"
	// BillingExportStatusSucceeded is an export accepted by the provider.
	BillingExportStatusSucceeded BillingExportStatus = "succeeded"
	// BillingExportStatusFailed is an export attempt that failed and may retry after NextAttemptAt.
	BillingExportStatusFailed BillingExportStatus = "failed"
)

func (s BillingExportStatus) valid() bool {
	switch s {
	case BillingExportStatusPending, BillingExportStatusSucceeded, BillingExportStatusFailed:
		return true
	default:
		return false
	}
}

// BillingExport is the provider-neutral export group for one organization,
// subscription, billing period, and provider.
type BillingExport struct {
	ID                 string
	OrganizationID     string
	SubscriptionID     string
	Provider           string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	Status             BillingExportStatus
	AttemptCount       int
	RequestedAt        time.Time
	LastAttemptAt      *time.Time
	NextAttemptAt      *time.Time
	ExportedAt         *time.Time
	ProviderResponseID *string
	LastErrorSummary   *string
	Items              []BillingExportItem
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// LogValue emits only safe export diagnostics. Provider responses can contain
// remote object identifiers, but never credentials; error summaries are still
// redacted because provider SDKs often echo transport context.
func (e BillingExport) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("subscription_id", e.SubscriptionID),
		slog.String("provider", e.Provider),
		slog.String("status", string(e.Status)),
		slog.Int("attempt_count", e.AttemptCount),
		slog.Int("item_count", len(e.Items)),
	}
	if e.ProviderResponseID != nil {
		attrs = append(attrs, slog.String("provider_response_id", *e.ProviderResponseID))
	}
	if e.LastErrorSummary != nil {
		attrs = append(attrs, slog.String("last_error_summary", redactBillingExportSummary(*e.LastErrorSummary)))
	}
	return slog.GroupValue(attrs...)
}

// BillingExportItem snapshots one usage counter into an export so provider
// retries submit the same billing basis even if counters are replayed later.
type BillingExportItem struct {
	ID                string
	OrganizationID    string
	ExportID          string
	CounterID         string
	Key               string
	Unit              string
	Quantity          float64
	Source            string
	EntitlementKey    *string
	OveragePolicyMode *string
	OverageDecision   *string
	IncludedQuantity  *float64
	OverageQuantity   *float64
	CreatedAt         time.Time
}

// PrepareBillingExportInput identifies the export group to create or replay.
type PrepareBillingExportInput struct {
	OrganizationID string
	SubscriptionID string
	Provider       string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	RequestedAt    time.Time
}

// MarkBillingExportSucceededInput records the provider's accepted response.
type MarkBillingExportSucceededInput struct {
	OrganizationID     string
	ExportID           string
	ProviderResponseID string
	ExportedAt         time.Time
}

// MarkBillingExportFailedInput records a provider failure and schedules retry.
type MarkBillingExportFailedInput struct {
	OrganizationID string
	ExportID       string
	FailedAt       time.Time
	RetryAfter     time.Duration
	ErrorSummary   string
}

// BillingExportRepository persists provider-neutral billing export attempts.
type BillingExportRepository struct{}

// NewBillingExportRepository returns a stateless billing export repository.
func NewBillingExportRepository() *BillingExportRepository { return &BillingExportRepository{} }

const billingExportColumns = `id, organization_id, subscription_id, provider, period_start, period_end, status, attempt_count, requested_at, last_attempt_at, next_attempt_at, exported_at, provider_response_id, last_error_summary, created_at, updated_at`

const billingExportItemColumns = `id, organization_id, export_id, counter_id, key, unit, quantity, source, entitlement_key, overage_policy_mode, overage_decision, included_quantity, overage_quantity, created_at`

// Prepare creates the idempotent export group and snapshots all counters for
// that organization and billing period. A duplicate group returns the existing
// export and never creates a second provider-bound work item.
func (r *BillingExportRepository) Prepare(ctx context.Context, tx *Tx, in PrepareBillingExportInput) (BillingExport, error) {
	if tx == nil {
		return BillingExport{}, apierr.Internal(errors.New("store: BillingExportRepository.Prepare called with a nil transaction"))
	}
	input, err := buildPrepareBillingExportInput(in)
	if err != nil {
		return BillingExport{}, err
	}
	if err := r.validateSubscription(ctx, tx, input.OrganizationID, input.SubscriptionID); err != nil {
		return BillingExport{}, err
	}
	id, err := newOpaqueStoreID("bexp")
	if err != nil {
		return BillingExport{}, apierr.Internal(err)
	}
	export, inserted, err := r.insertOrGet(ctx, tx, id, input)
	if err != nil {
		return BillingExport{}, err
	}
	if inserted {
		if err := r.snapshotItems(ctx, tx, export); err != nil {
			return BillingExport{}, err
		}
	}
	return r.Get(ctx, tx, export.OrganizationID, export.ID)
}

// Get reads one tenant-scoped export plus its item snapshot.
func (r *BillingExportRepository) Get(ctx context.Context, q Querier, organizationID, id string) (BillingExport, error) {
	export, err := scanBillingExport(q.QueryRow(ctx,
		`SELECT `+billingExportColumns+`
		   FROM billing_exports
		  WHERE organization_id = $1 AND id = $2`,
		strings.TrimSpace(organizationID), strings.TrimSpace(id),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return BillingExport{}, apierr.NotFound("billing_export", id)
	}
	if err != nil {
		return BillingExport{}, apierr.StoreUnavailable(err)
	}
	items, err := r.listItems(ctx, q, export.OrganizationID, export.ID)
	if err != nil {
		return BillingExport{}, err
	}
	export.Items = items
	return export, nil
}

// MarkSucceeded records the provider response id for an accepted export.
func (r *BillingExportRepository) MarkSucceeded(ctx context.Context, tx *Tx, in MarkBillingExportSucceededInput) (BillingExport, error) {
	if tx == nil {
		return BillingExport{}, apierr.Internal(errors.New("store: BillingExportRepository.MarkSucceeded called with a nil transaction"))
	}
	organizationID := strings.TrimSpace(in.OrganizationID)
	exportID := strings.TrimSpace(in.ExportID)
	responseID := strings.TrimSpace(in.ProviderResponseID)
	exportedAt := in.ExportedAt.UTC()
	var violations []apierr.FieldViolation
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if exportID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "export_id", Reason: "must not be blank"})
	}
	if responseID == "" || len(responseID) > 200 {
		violations = append(violations, apierr.FieldViolation{Field: "provider_response_id", Reason: "must be between 1 and 200 characters"})
	}
	if exportedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "exported_at", Reason: "must not be zero"})
	}
	if len(violations) > 0 {
		return BillingExport{}, apierr.InvalidInput(violations...)
	}
	if _, err := scanBillingExport(tx.QueryRow(ctx,
		`UPDATE billing_exports
		    SET status = 'succeeded',
		        provider_response_id = $3,
		        exported_at = $4,
		        last_attempt_at = $4,
		        next_attempt_at = NULL,
		        last_error_summary = NULL
		  WHERE organization_id = $1 AND id = $2
		 RETURNING `+billingExportColumns,
		organizationID, exportID, responseID, exportedAt,
	)); errors.Is(err, pgx.ErrNoRows) {
		return BillingExport{}, apierr.NotFound("billing_export", exportID)
	} else if err != nil {
		return BillingExport{}, mapWriteError(err, "mark billing export succeeded")
	}
	return r.Get(ctx, tx, organizationID, exportID)
}

// MarkFailed records a provider failure and schedules the next retry.
func (r *BillingExportRepository) MarkFailed(ctx context.Context, tx *Tx, in MarkBillingExportFailedInput) (BillingExport, error) {
	if tx == nil {
		return BillingExport{}, apierr.Internal(errors.New("store: BillingExportRepository.MarkFailed called with a nil transaction"))
	}
	organizationID := strings.TrimSpace(in.OrganizationID)
	exportID := strings.TrimSpace(in.ExportID)
	failedAt := in.FailedAt.UTC()
	summary := strings.TrimSpace(redactBillingExportSummary(in.ErrorSummary))
	if len(summary) > 500 {
		summary = summary[:500]
	}
	var violations []apierr.FieldViolation
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if exportID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "export_id", Reason: "must not be blank"})
	}
	if failedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "failed_at", Reason: "must not be zero"})
	}
	if in.RetryAfter <= 0 {
		violations = append(violations, apierr.FieldViolation{Field: "retry_after", Reason: "must be positive"})
	}
	if len(violations) > 0 {
		return BillingExport{}, apierr.InvalidInput(violations...)
	}
	next := failedAt.Add(in.RetryAfter).UTC()
	if _, err := scanBillingExport(tx.QueryRow(ctx,
		`UPDATE billing_exports
		    SET status = 'failed',
		        attempt_count = attempt_count + 1,
		        last_attempt_at = $3,
		        next_attempt_at = $4,
		        last_error_summary = $5
		  WHERE organization_id = $1 AND id = $2
		 RETURNING `+billingExportColumns,
		organizationID, exportID, failedAt, next, summary,
	)); errors.Is(err, pgx.ErrNoRows) {
		return BillingExport{}, apierr.NotFound("billing_export", exportID)
	} else if err != nil {
		return BillingExport{}, mapWriteError(err, "mark billing export failed")
	}
	return r.Get(ctx, tx, organizationID, exportID)
}

func redactBillingExportSummary(summary string) string {
	summary = output.NewRedactor().Redact(summary)
	return billingProviderSecretPattern.ReplaceAllString(summary, output.Sentinel)
}

func buildPrepareBillingExportInput(in PrepareBillingExportInput) (PrepareBillingExportInput, error) {
	out := PrepareBillingExportInput{
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		SubscriptionID: strings.TrimSpace(in.SubscriptionID),
		Provider:       strings.TrimSpace(in.Provider),
		PeriodStart:    in.PeriodStart.UTC(),
		PeriodEnd:      in.PeriodEnd.UTC(),
		RequestedAt:    in.RequestedAt.UTC(),
	}
	var violations []apierr.FieldViolation
	if out.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if out.SubscriptionID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must not be blank"})
	}
	if out.Provider == "" || !validProviderKey(out.Provider) {
		violations = append(violations, apierr.FieldViolation{Field: "provider", Reason: "must be a canonical provider key"})
	}
	if out.PeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_start", Reason: "must not be zero"})
	}
	if out.PeriodEnd.IsZero() || !out.PeriodEnd.After(out.PeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must be after period_start"})
	}
	if out.RequestedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "requested_at", Reason: "must not be zero"})
	}
	if len(violations) > 0 {
		return PrepareBillingExportInput{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func (r *BillingExportRepository) validateSubscription(ctx context.Context, q Querier, organizationID, subscriptionID string) error {
	var ok bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM subscriptions
		    WHERE organization_id = $1 AND id = $2
		 )`, organizationID, subscriptionID).Scan(&ok); err != nil {
		return apierr.StoreUnavailable(err)
	}
	if !ok {
		return apierr.NotFound("subscription", subscriptionID)
	}
	return nil
}

func (r *BillingExportRepository) insertOrGet(ctx context.Context, tx *Tx, id string, in PrepareBillingExportInput) (BillingExport, bool, error) {
	export, err := scanBillingExport(tx.QueryRow(ctx,
		`INSERT INTO billing_exports
		    (id, organization_id, subscription_id, provider, period_start, period_end, requested_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (organization_id, subscription_id, period_start, period_end, provider)
		 DO NOTHING
		 RETURNING `+billingExportColumns,
		id, in.OrganizationID, in.SubscriptionID, in.Provider, in.PeriodStart, in.PeriodEnd, in.RequestedAt,
	))
	if err == nil {
		return export, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return BillingExport{}, false, mapWriteError(err, "prepare billing export")
	}
	export, err = scanBillingExport(tx.QueryRow(ctx,
		`SELECT `+billingExportColumns+`
		   FROM billing_exports
		  WHERE organization_id = $1
		    AND subscription_id = $2
		    AND period_start = $3
		    AND period_end = $4
		    AND provider = $5
		  FOR UPDATE`,
		in.OrganizationID, in.SubscriptionID, in.PeriodStart, in.PeriodEnd, in.Provider,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return BillingExport{}, false, apierr.Internal(errors.New("store: billing export idempotency row vanished"))
	}
	if err != nil {
		return BillingExport{}, false, apierr.StoreUnavailable(err)
	}
	return export, false, nil
}

func (r *BillingExportRepository) snapshotItems(ctx context.Context, tx *Tx, export BillingExport) error {
	rows, err := tx.Query(ctx,
		`SELECT id, key, unit, quantity, source, entitlement_key, overage_policy_mode, overage_decision, included_quantity, overage_quantity
		   FROM usage_counters
		  WHERE organization_id = $1
		    AND period_start = $2
		    AND period_end = $3
		  ORDER BY key, unit, source`,
		export.OrganizationID, export.PeriodStart, export.PeriodEnd,
	)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	for rows.Next() {
		var counterID, key, unit, source string
		var entitlementKey, overagePolicyMode, overageDecision *string
		var includedQuantity, overageQuantity *float64
		var quantity float64
		if err := rows.Scan(&counterID, &key, &unit, &quantity, &source, &entitlementKey, &overagePolicyMode, &overageDecision, &includedQuantity, &overageQuantity); err != nil {
			return apierr.StoreUnavailable(err)
		}
		if math.IsNaN(quantity) || math.IsInf(quantity, 0) {
			return apierr.Internal(errors.New("store: non-finite billing export item quantity"))
		}
		itemID, err := newOpaqueStoreID("bexpi")
		if err != nil {
			return apierr.Internal(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO billing_export_items
			    (id, organization_id, export_id, counter_id, key, unit, quantity, source,
			     entitlement_key, overage_policy_mode, overage_decision, included_quantity, overage_quantity)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			 ON CONFLICT (organization_id, export_id, counter_id) DO NOTHING`,
			itemID, export.OrganizationID, export.ID, counterID, key, unit, quantity, source,
			entitlementKey, overagePolicyMode, overageDecision, includedQuantity, overageQuantity,
		); err != nil {
			return mapWriteError(err, "snapshot billing export item")
		}
	}
	if err := rows.Err(); err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

func (r *BillingExportRepository) listItems(ctx context.Context, q Querier, organizationID, exportID string) ([]BillingExportItem, error) {
	rows, err := q.Query(ctx,
		`SELECT `+billingExportItemColumns+`
		   FROM billing_export_items
		  WHERE organization_id = $1 AND export_id = $2
		  ORDER BY key, unit, source, counter_id`,
		organizationID, exportID,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	items := []BillingExportItem{}
	for rows.Next() {
		item, err := scanBillingExportItem(rows)
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

func scanBillingExport(row pgx.Row) (BillingExport, error) {
	var export BillingExport
	var lastAttemptAt, nextAttemptAt, exportedAt *time.Time
	if err := row.Scan(
		&export.ID, &export.OrganizationID, &export.SubscriptionID, &export.Provider,
		&export.PeriodStart, &export.PeriodEnd, &export.Status, &export.AttemptCount,
		&export.RequestedAt, &lastAttemptAt, &nextAttemptAt, &exportedAt,
		&export.ProviderResponseID, &export.LastErrorSummary, &export.CreatedAt, &export.UpdatedAt,
	); err != nil {
		return BillingExport{}, err
	}
	export.PeriodStart = export.PeriodStart.UTC()
	export.PeriodEnd = export.PeriodEnd.UTC()
	export.RequestedAt = export.RequestedAt.UTC()
	export.CreatedAt = export.CreatedAt.UTC()
	export.UpdatedAt = export.UpdatedAt.UTC()
	if lastAttemptAt != nil {
		v := lastAttemptAt.UTC()
		export.LastAttemptAt = &v
	}
	if nextAttemptAt != nil {
		v := nextAttemptAt.UTC()
		export.NextAttemptAt = &v
	}
	if exportedAt != nil {
		v := exportedAt.UTC()
		export.ExportedAt = &v
	}
	if !export.Status.valid() {
		return BillingExport{}, apierr.Internal(errors.New("store: invalid billing export status"))
	}
	return export, nil
}

func scanBillingExportItem(row pgx.Row) (BillingExportItem, error) {
	var item BillingExportItem
	if err := row.Scan(
		&item.ID, &item.OrganizationID, &item.ExportID, &item.CounterID,
		&item.Key, &item.Unit, &item.Quantity, &item.Source,
		&item.EntitlementKey, &item.OveragePolicyMode, &item.OverageDecision,
		&item.IncludedQuantity, &item.OverageQuantity, &item.CreatedAt,
	); err != nil {
		return BillingExportItem{}, err
	}
	item.CreatedAt = item.CreatedAt.UTC()
	return item, nil
}
