package store

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// LateEventMode identifies how aggregators handle samples that arrive after a
// billing or usage period is closed.
type LateEventMode string

const (
	// LateEventModeIgnore drops late samples after the close window.
	LateEventModeIgnore LateEventMode = "ignore"
	// LateEventModeAdjust records late samples as closed-period adjustments.
	LateEventModeAdjust LateEventMode = "adjust"
	// LateEventModeQuarantine keeps late samples out of billing until review.
	LateEventModeQuarantine LateEventMode = "quarantine"
)

func (m LateEventMode) valid() bool {
	switch m {
	case LateEventModeIgnore, LateEventModeAdjust, LateEventModeQuarantine:
		return true
	default:
		return false
	}
}

// UsageAggregationSchedule is the runtime contract aggregators consume.
type UsageAggregationSchedule struct {
	ID                         string
	ScheduleKey                string
	Version                    int
	Source                     string
	MetricKey                  string
	AggregationIntervalSeconds int
	ReplayLookbackSeconds      int
	CloseDelaySeconds          int
	LateEventMode              LateEventMode
	Enabled                    bool
	Revision                   int64
	PublishedAt                time.Time
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

// LogValue emits the non-secret schedule fields for structured logs.
func (s UsageAggregationSchedule) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", s.ID),
		slog.String("schedule_key", s.ScheduleKey),
		slog.Int("version", s.Version),
		slog.String("source", s.Source),
		slog.String("metric_key", s.MetricKey),
		slog.Int("aggregation_interval_seconds", s.AggregationIntervalSeconds),
		slog.String("late_event_mode", string(s.LateEventMode)),
		slog.Bool("enabled", s.Enabled),
		slog.Int64("revision", s.Revision),
	)
}

// UpsertUsageAggregationScheduleInput is the backoffice write contract for
// aggregation schedules.
type UpsertUsageAggregationScheduleInput struct {
	Source                     string
	MetricKey                  string
	AggregationIntervalSeconds int
	ReplayLookbackSeconds      int
	CloseDelaySeconds          int
	LateEventMode              LateEventMode
	Enabled                    bool
}

// UsageAggregationScheduleRepository persists global backoffice aggregation
// schedules.
type UsageAggregationScheduleRepository struct{}

// NewUsageAggregationScheduleRepository returns a stateless repository.
func NewUsageAggregationScheduleRepository() *UsageAggregationScheduleRepository {
	return &UsageAggregationScheduleRepository{}
}

const usageAggregationScheduleColumns = `id, schedule_key, version, source, metric_key, aggregation_interval_seconds, replay_lookback_seconds, close_delay_seconds, late_event_mode, enabled, revision, published_at, created_at, updated_at`

var usageScheduleKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}$`)
var usageScheduleTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}$`)

// Upsert creates or updates one schedule. Each update increments the public
// version so aggregators can reload safely without dropping in-flight work.
func (r *UsageAggregationScheduleRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertUsageAggregationScheduleInput) (UsageAggregationSchedule, error) {
	if tx == nil {
		return UsageAggregationSchedule{}, apierr.Internal(errors.New("store: UsageAggregationScheduleRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateUsageAggregationScheduleUpsert(key, in)
	if err != nil {
		return UsageAggregationSchedule{}, err
	}

	current, err := r.lockCurrent(ctx, tx, key)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return UsageAggregationSchedule{}, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return r.insert(ctx, tx, key, input)
	}

	row := tx.QueryRow(ctx,
		`UPDATE admin_usage_aggregation_schedules
		    SET source = $2,
		        metric_key = $3,
		        aggregation_interval_seconds = $4,
		        replay_lookback_seconds = $5,
		        close_delay_seconds = $6,
		        late_event_mode = $7,
		        enabled = $8,
		        version = version + 1,
		        revision = revision + 1
		  WHERE id = $1
		  RETURNING `+usageAggregationScheduleColumns,
		current.ID, input.Source, input.MetricKey, input.AggregationIntervalSeconds, input.ReplayLookbackSeconds, input.CloseDelaySeconds, input.LateEventMode, input.Enabled)
	out, scanErr := scanUsageAggregationSchedule(row)
	if scanErr != nil {
		return UsageAggregationSchedule{}, mapWriteError(scanErr, "the usage aggregation schedule could not be saved")
	}
	return out, nil
}

// Disable marks a schedule disabled without deleting history.
func (r *UsageAggregationScheduleRepository) Disable(ctx context.Context, tx *Tx, key string) (UsageAggregationSchedule, error) {
	if tx == nil {
		return UsageAggregationSchedule{}, apierr.Internal(errors.New("store: UsageAggregationScheduleRepository.Disable called with a nil transaction"))
	}
	key = strings.TrimSpace(key)
	current, err := r.lockCurrent(ctx, tx, key)
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	row := tx.QueryRow(ctx,
		`UPDATE admin_usage_aggregation_schedules
		    SET enabled = false,
		        version = version + 1,
		        revision = revision + 1
		  WHERE id = $1
		  RETURNING `+usageAggregationScheduleColumns,
		current.ID)
	out, scanErr := scanUsageAggregationSchedule(row)
	if scanErr != nil {
		return UsageAggregationSchedule{}, mapWriteError(scanErr, "the usage aggregation schedule could not be disabled")
	}
	return out, nil
}

// Get returns one current schedule by key.
func (r *UsageAggregationScheduleRepository) Get(ctx context.Context, q Querier, key string) (UsageAggregationSchedule, error) {
	key = strings.TrimSpace(key)
	row := q.QueryRow(ctx,
		`SELECT `+usageAggregationScheduleColumns+`
		   FROM admin_usage_aggregation_schedules
		  WHERE schedule_key = $1`,
		key)
	out, err := scanUsageAggregationSchedule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageAggregationSchedule{}, apierr.NotFound("usage_aggregation_schedule", key)
	}
	if err != nil {
		return UsageAggregationSchedule{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListRuntimeEnabled returns enabled schedules in deterministic order for
// runtime aggregators.
func (r *UsageAggregationScheduleRepository) ListRuntimeEnabled(ctx context.Context, q Querier, _ time.Time) ([]UsageAggregationSchedule, error) {
	rows, err := q.Query(ctx,
		`SELECT `+usageAggregationScheduleColumns+`
		   FROM admin_usage_aggregation_schedules
		  WHERE enabled = true
		  ORDER BY source ASC, metric_key ASC, schedule_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []UsageAggregationSchedule
	for rows.Next() {
		s, scanErr := scanUsageAggregationSchedule(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *UsageAggregationScheduleRepository) lockCurrent(ctx context.Context, tx *Tx, key string) (UsageAggregationSchedule, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+usageAggregationScheduleColumns+`
		   FROM admin_usage_aggregation_schedules
		  WHERE schedule_key = $1
		  FOR UPDATE`,
		key)
	out, err := scanUsageAggregationSchedule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageAggregationSchedule{}, pgx.ErrNoRows
	}
	if err != nil {
		return UsageAggregationSchedule{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *UsageAggregationScheduleRepository) insert(ctx context.Context, tx *Tx, key string, in UpsertUsageAggregationScheduleInput) (UsageAggregationSchedule, error) {
	id, err := newOpaqueStoreID("usched")
	if err != nil {
		return UsageAggregationSchedule{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_usage_aggregation_schedules
		    (id, schedule_key, version, source, metric_key, aggregation_interval_seconds, replay_lookback_seconds, close_delay_seconds, late_event_mode, enabled)
		 VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING `+usageAggregationScheduleColumns,
		id, key, in.Source, in.MetricKey, in.AggregationIntervalSeconds, in.ReplayLookbackSeconds, in.CloseDelaySeconds, in.LateEventMode, in.Enabled)
	out, scanErr := scanUsageAggregationSchedule(row)
	if scanErr != nil {
		return UsageAggregationSchedule{}, mapWriteError(scanErr, "the usage aggregation schedule could not be saved")
	}
	return out, nil
}

func validateUsageAggregationScheduleUpsert(key string, in UpsertUsageAggregationScheduleInput) (string, UpsertUsageAggregationScheduleInput, error) {
	key = strings.TrimSpace(key)
	in.Source = strings.TrimSpace(in.Source)
	in.MetricKey = strings.TrimSpace(in.MetricKey)
	var violations []apierr.FieldViolation
	if !usageScheduleKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "schedule_key", Reason: "must be a stable lowercase token"})
	}
	if !usageScheduleTokenPattern.MatchString(in.Source) {
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be a stable lowercase token"})
	}
	if !usageScheduleTokenPattern.MatchString(in.MetricKey) {
		violations = append(violations, apierr.FieldViolation{Field: "metric_key", Reason: "must be a stable lowercase token"})
	}
	if in.AggregationIntervalSeconds == 0 {
		in.AggregationIntervalSeconds = 3600
	}
	if in.AggregationIntervalSeconds < 60 || in.AggregationIntervalSeconds > 2678400 {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_interval_seconds", Reason: "must be between 60 and 2678400"})
	}
	if in.ReplayLookbackSeconds < 0 || in.ReplayLookbackSeconds > 2678400 {
		violations = append(violations, apierr.FieldViolation{Field: "replay_lookback_seconds", Reason: "must be between 0 and 2678400"})
	}
	if in.CloseDelaySeconds < 0 || in.CloseDelaySeconds > 2678400 {
		violations = append(violations, apierr.FieldViolation{Field: "close_delay_seconds", Reason: "must be between 0 and 2678400"})
	}
	if !in.LateEventMode.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "late_event_mode", Reason: "must be one of ignore, adjust, quarantine"})
	}
	if len(violations) > 0 {
		return "", UpsertUsageAggregationScheduleInput{}, apierr.InvalidInput(violations...)
	}
	return key, in, nil
}

func scanUsageAggregationSchedule(row pgx.Row) (UsageAggregationSchedule, error) {
	var out UsageAggregationSchedule
	err := row.Scan(
		&out.ID,
		&out.ScheduleKey,
		&out.Version,
		&out.Source,
		&out.MetricKey,
		&out.AggregationIntervalSeconds,
		&out.ReplayLookbackSeconds,
		&out.CloseDelaySeconds,
		&out.LateEventMode,
		&out.Enabled,
		&out.Revision,
		&out.PublishedAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	return out, nil
}
