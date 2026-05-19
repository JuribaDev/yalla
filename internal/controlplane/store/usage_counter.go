package store

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// UsageCounter is the billing-period aggregate derived from append-only
// usage_events. Key is the stable metering dimension, usually a QuotaResource
// string.
type UsageCounter struct {
	ID                 string
	OrganizationID     string
	Key                string
	Unit               string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	Quantity           float64
	Source             string
	AggregationVersion int
	LastAggregatedAt   time.Time
	ClosedAt           *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UsageCounterAdjustment records late-arriving usage for a period whose
// counter had already been closed by a prior aggregation.
type UsageCounterAdjustment struct {
	ID                  string
	OrganizationID      string
	CounterID           string
	Key                 string
	Unit                string
	Source              string
	PeriodStart         time.Time
	PeriodEnd           time.Time
	DeltaQuantity       float64
	AggregationVersion  int
	Reason              string
	LastEventOccurredAt *time.Time
	CreatedAt           time.Time
}

// AggregateUsageCountersInput selects one organization and billing period to
// aggregate. AggregatedAt is caller-controlled so workers can replay periods
// deterministically in tests and backfills.
type AggregateUsageCountersInput struct {
	OrganizationID     string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	AggregatedAt       time.Time
	AggregationVersion int
}

// UsageCounterAggregationResult reports counters touched and adjustment rows
// created by one aggregation replay.
type UsageCounterAggregationResult struct {
	Counters    []UsageCounter
	Adjustments []UsageCounterAdjustment
}

// UsageCounterRepository aggregates append-only usage events into period
// counters and late-event adjustment records.
type UsageCounterRepository struct{}

// NewUsageCounterRepository constructs a stateless usage counter repository.
func NewUsageCounterRepository() *UsageCounterRepository { return &UsageCounterRepository{} }

const usageCounterColumns = `id, organization_id, key, unit, period_start, period_end, quantity, source, aggregation_version, last_aggregated_at, closed_at, created_at, updated_at`

const usageCounterAdjustmentColumns = `id, organization_id, counter_id, key, unit, source, period_start, period_end, delta_quantity, aggregation_version, reason, last_event_occurred_at, created_at`

type usageEventAggregate struct {
	key                 string
	unit                string
	source              string
	quantity            float64
	lastEventOccurredAt *time.Time
}

// AggregateUsageEvents recomputes counters for one organization/period from
// usage_events. Replays are idempotent: open periods are overwritten with the
// deterministic sum; closed periods keep the frozen counter and append only the
// net new late-event delta not already represented by prior adjustments.
func (r *UsageCounterRepository) AggregateUsageEvents(ctx context.Context, tx *Tx, in AggregateUsageCountersInput) (UsageCounterAggregationResult, error) {
	if tx == nil {
		return UsageCounterAggregationResult{}, apierr.Internal(errors.New("store: UsageCounterRepository.AggregateUsageEvents called with a nil transaction"))
	}
	input, err := buildAggregateUsageCountersInput(in)
	if err != nil {
		return UsageCounterAggregationResult{}, err
	}
	if err := r.validateOrganization(ctx, tx, input.OrganizationID); err != nil {
		return UsageCounterAggregationResult{}, err
	}
	aggregates, err := r.usageEventAggregates(ctx, tx, input)
	if err != nil {
		return UsageCounterAggregationResult{}, err
	}
	result := UsageCounterAggregationResult{
		Counters:    make([]UsageCounter, 0, len(aggregates)),
		Adjustments: []UsageCounterAdjustment{},
	}
	for _, aggregate := range aggregates {
		counter, adjustment, err := r.applyAggregate(ctx, tx, input, aggregate)
		if err != nil {
			return UsageCounterAggregationResult{}, err
		}
		result.Counters = append(result.Counters, counter)
		if adjustment != nil {
			result.Adjustments = append(result.Adjustments, *adjustment)
		}
	}
	return result, nil
}

func buildAggregateUsageCountersInput(in AggregateUsageCountersInput) (AggregateUsageCountersInput, error) {
	out := AggregateUsageCountersInput{
		OrganizationID:     strings.TrimSpace(in.OrganizationID),
		PeriodStart:        in.PeriodStart.UTC(),
		PeriodEnd:          in.PeriodEnd.UTC(),
		AggregatedAt:       in.AggregatedAt.UTC(),
		AggregationVersion: in.AggregationVersion,
	}
	var violations []apierr.FieldViolation
	if out.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if out.PeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_start", Reason: "must not be zero"})
	}
	if out.PeriodEnd.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must not be zero"})
	}
	if !out.PeriodStart.IsZero() && !out.PeriodEnd.IsZero() && !out.PeriodEnd.After(out.PeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must be after period_start"})
	}
	if out.AggregatedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "aggregated_at", Reason: "must not be zero"})
	}
	if out.AggregationVersion <= 0 {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_version", Reason: "must be positive"})
	}
	if len(violations) > 0 {
		return AggregateUsageCountersInput{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func (r *UsageCounterRepository) validateOrganization(ctx context.Context, q Querier, organizationID string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)`, organizationID).Scan(&ok); err != nil {
		return apierr.StoreUnavailable(err)
	}
	if !ok {
		return apierr.NotFound("organization", organizationID)
	}
	return nil
}

func (r *UsageCounterRepository) usageEventAggregates(ctx context.Context, q Querier, in AggregateUsageCountersInput) ([]usageEventAggregate, error) {
	rows, err := q.Query(ctx,
		`SELECT resource::text AS key,
		        unit,
		        source,
		        COALESCE(SUM(quantity), 0)::double precision AS quantity,
		        MAX(occurred_at) AS last_event_occurred_at
		   FROM usage_events
		  WHERE organization_id = $1
		    AND period_start = $2
		    AND period_end = $3
		    AND event_type IN ('committed', 'consumed', 'adjusted')
		  GROUP BY resource, unit, source
		  ORDER BY resource, unit, source`,
		in.OrganizationID, in.PeriodStart, in.PeriodEnd,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	var aggregates []usageEventAggregate
	for rows.Next() {
		var aggregate usageEventAggregate
		if err := rows.Scan(&aggregate.key, &aggregate.unit, &aggregate.source, &aggregate.quantity, &aggregate.lastEventOccurredAt); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		if math.IsNaN(aggregate.quantity) || math.IsInf(aggregate.quantity, 0) {
			return nil, apierr.Internal(errors.New("store: non-finite usage aggregate"))
		}
		aggregates = append(aggregates, aggregate)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return aggregates, nil
}

func (r *UsageCounterRepository) applyAggregate(ctx context.Context, tx *Tx, in AggregateUsageCountersInput, aggregate usageEventAggregate) (UsageCounter, *UsageCounterAdjustment, error) {
	closed := !in.AggregatedAt.Before(in.PeriodEnd)
	counter, exists, err := r.lockCounter(ctx, tx, in, aggregate)
	if err != nil {
		return UsageCounter{}, nil, err
	}
	if !closed || !exists {
		counter, err := r.upsertOpenCounter(ctx, tx, in, aggregate, closed)
		return counter, nil, err
	}

	adjusted, err := r.adjustedQuantity(ctx, tx, counter)
	if err != nil {
		return UsageCounter{}, nil, err
	}
	delta := aggregate.quantity - counter.Quantity - adjusted
	if delta == 0 {
		counter, err = r.touchClosedCounter(ctx, tx, counter.ID, in.AggregatedAt, in.AggregationVersion)
		return counter, nil, err
	}
	adjustment, err := r.insertAdjustment(ctx, tx, in, counter, aggregate, delta)
	if err != nil {
		return UsageCounter{}, nil, err
	}
	counter, err = r.touchClosedCounter(ctx, tx, counter.ID, in.AggregatedAt, in.AggregationVersion)
	if err != nil {
		return UsageCounter{}, nil, err
	}
	return counter, &adjustment, nil
}

func (r *UsageCounterRepository) lockCounter(ctx context.Context, q Querier, in AggregateUsageCountersInput, aggregate usageEventAggregate) (UsageCounter, bool, error) {
	counter, err := scanUsageCounter(q.QueryRow(ctx,
		`SELECT `+usageCounterColumns+`
		   FROM usage_counters
		  WHERE organization_id = $1
		    AND key = $2
		    AND unit = $3
		    AND period_start = $4
		    AND period_end = $5
		    AND source = $6
		  FOR UPDATE`,
		in.OrganizationID, aggregate.key, aggregate.unit, in.PeriodStart, in.PeriodEnd, aggregate.source,
	))
	if err == nil {
		return counter, true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageCounter{}, false, nil
	}
	return UsageCounter{}, false, apierr.StoreUnavailable(err)
}

func (r *UsageCounterRepository) upsertOpenCounter(ctx context.Context, tx *Tx, in AggregateUsageCountersInput, aggregate usageEventAggregate, closed bool) (UsageCounter, error) {
	id, err := newOpaqueStoreID("ucnt")
	if err != nil {
		return UsageCounter{}, apierr.Internal(err)
	}
	var closedAt *time.Time
	if closed {
		closedAt = &in.AggregatedAt
	}
	counter, err := scanUsageCounter(tx.QueryRow(ctx,
		`INSERT INTO usage_counters
		    (id, organization_id, key, unit, period_start, period_end, quantity, source,
		     aggregation_version, last_aggregated_at, closed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (organization_id, key, unit, period_start, period_end, source)
		 DO UPDATE SET
		    quantity = EXCLUDED.quantity,
		    aggregation_version = EXCLUDED.aggregation_version,
		    last_aggregated_at = EXCLUDED.last_aggregated_at,
		    closed_at = COALESCE(usage_counters.closed_at, EXCLUDED.closed_at)
		 RETURNING `+usageCounterColumns,
		id, in.OrganizationID, aggregate.key, aggregate.unit, in.PeriodStart, in.PeriodEnd, aggregate.quantity,
		aggregate.source, in.AggregationVersion, in.AggregatedAt, closedAt,
	))
	if err != nil {
		return UsageCounter{}, mapWriteError(err, "aggregate usage counter")
	}
	return counter, nil
}

func (r *UsageCounterRepository) adjustedQuantity(ctx context.Context, q Querier, counter UsageCounter) (float64, error) {
	var adjusted float64
	if err := q.QueryRow(ctx,
		`SELECT COALESCE(SUM(delta_quantity), 0)::double precision
		   FROM usage_counter_adjustments
		  WHERE organization_id = $1 AND counter_id = $2`,
		counter.OrganizationID, counter.ID,
	).Scan(&adjusted); err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return adjusted, nil
}

func (r *UsageCounterRepository) insertAdjustment(ctx context.Context, tx *Tx, in AggregateUsageCountersInput, counter UsageCounter, aggregate usageEventAggregate, delta float64) (UsageCounterAdjustment, error) {
	id, err := newOpaqueStoreID("ucadj")
	if err != nil {
		return UsageCounterAdjustment{}, apierr.Internal(err)
	}
	adjustment, err := scanUsageCounterAdjustment(tx.QueryRow(ctx,
		`INSERT INTO usage_counter_adjustments
		    (id, organization_id, counter_id, key, unit, source, period_start, period_end,
		     delta_quantity, aggregation_version, reason, last_event_occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'late_event', $11)
		 RETURNING `+usageCounterAdjustmentColumns,
		id, counter.OrganizationID, counter.ID, counter.Key, counter.Unit, counter.Source,
		counter.PeriodStart, counter.PeriodEnd, delta, in.AggregationVersion, aggregate.lastEventOccurredAt,
	))
	if err != nil {
		return UsageCounterAdjustment{}, mapWriteError(err, "create usage counter adjustment")
	}
	return adjustment, nil
}

func (r *UsageCounterRepository) touchClosedCounter(ctx context.Context, tx *Tx, counterID string, aggregatedAt time.Time, aggregationVersion int) (UsageCounter, error) {
	counter, err := scanUsageCounter(tx.QueryRow(ctx,
		`UPDATE usage_counters
		    SET last_aggregated_at = $2,
		        aggregation_version = $3,
		        closed_at = COALESCE(closed_at, $2)
		  WHERE id = $1
		 RETURNING `+usageCounterColumns,
		counterID, aggregatedAt, aggregationVersion,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageCounter{}, apierr.NotFound("usage_counter", counterID)
	}
	if err != nil {
		return UsageCounter{}, mapWriteError(err, "update usage counter aggregation marker")
	}
	return counter, nil
}

func scanUsageCounter(row pgx.Row) (UsageCounter, error) {
	var counter UsageCounter
	var closedAt *time.Time
	if err := row.Scan(
		&counter.ID, &counter.OrganizationID, &counter.Key, &counter.Unit,
		&counter.PeriodStart, &counter.PeriodEnd, &counter.Quantity, &counter.Source,
		&counter.AggregationVersion, &counter.LastAggregatedAt, &closedAt,
		&counter.CreatedAt, &counter.UpdatedAt,
	); err != nil {
		return UsageCounter{}, err
	}
	counter.PeriodStart = counter.PeriodStart.UTC()
	counter.PeriodEnd = counter.PeriodEnd.UTC()
	counter.LastAggregatedAt = counter.LastAggregatedAt.UTC()
	counter.CreatedAt = counter.CreatedAt.UTC()
	counter.UpdatedAt = counter.UpdatedAt.UTC()
	if closedAt != nil {
		closed := closedAt.UTC()
		counter.ClosedAt = &closed
	}
	return counter, nil
}

func scanUsageCounterAdjustment(row pgx.Row) (UsageCounterAdjustment, error) {
	var adjustment UsageCounterAdjustment
	var lastEventOccurredAt *time.Time
	if err := row.Scan(
		&adjustment.ID, &adjustment.OrganizationID, &adjustment.CounterID,
		&adjustment.Key, &adjustment.Unit, &adjustment.Source,
		&adjustment.PeriodStart, &adjustment.PeriodEnd, &adjustment.DeltaQuantity,
		&adjustment.AggregationVersion, &adjustment.Reason, &lastEventOccurredAt,
		&adjustment.CreatedAt,
	); err != nil {
		return UsageCounterAdjustment{}, err
	}
	adjustment.PeriodStart = adjustment.PeriodStart.UTC()
	adjustment.PeriodEnd = adjustment.PeriodEnd.UTC()
	adjustment.CreatedAt = adjustment.CreatedAt.UTC()
	if lastEventOccurredAt != nil {
		last := lastEventOccurredAt.UTC()
		adjustment.LastEventOccurredAt = &last
	}
	return adjustment, nil
}
