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

// MetricAggregationFunction identifies how raw samples collapse into a billing
// or enforcement window.
type MetricAggregationFunction string

const (
	// MetricAggregationSum sums every sample in the aggregation window.
	MetricAggregationSum MetricAggregationFunction = "sum"
	// MetricAggregationMax keeps the largest sample in the aggregation window.
	MetricAggregationMax MetricAggregationFunction = "max"
	// MetricAggregationAvg averages samples in the aggregation window.
	MetricAggregationAvg MetricAggregationFunction = "avg"
	// MetricAggregationP95 keeps the p95 sample value in the aggregation window.
	MetricAggregationP95 MetricAggregationFunction = "p95"
	// MetricAggregationLast keeps the latest sample in the aggregation window.
	MetricAggregationLast MetricAggregationFunction = "last"
)

func (f MetricAggregationFunction) valid() bool {
	switch f {
	case MetricAggregationSum, MetricAggregationMax, MetricAggregationAvg, MetricAggregationP95, MetricAggregationLast:
		return true
	default:
		return false
	}
}

// MetricDefinition is the published runtime contract for one tracked metric.
type MetricDefinition struct {
	ID                       string
	Key                      string
	Version                  int
	Unit                     string
	Source                   string
	AggregationFunction      MetricAggregationFunction
	AggregationWindowSeconds int
	BillingGrade             bool
	RetentionDays            int
	EnforcementLink          string
	Enabled                  bool
	Revision                 int64
	PublishedAt              time.Time
	SupersededAt             *time.Time
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

// LogValue emits the non-secret metric definition fields for structured logs.
func (d MetricDefinition) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", d.ID),
		slog.String("key", d.Key),
		slog.Int("version", d.Version),
		slog.String("unit", d.Unit),
		slog.String("source", d.Source),
		slog.String("aggregation_function", string(d.AggregationFunction)),
		slog.Bool("billing_grade", d.BillingGrade),
		slog.Bool("enabled", d.Enabled),
		slog.Int64("revision", d.Revision),
	)
}

// UpsertMetricDefinitionInput is the backoffice write contract for tracked
// metric definitions.
type UpsertMetricDefinitionInput struct {
	Unit                     string
	Source                   string
	AggregationFunction      MetricAggregationFunction
	AggregationWindowSeconds int
	BillingGrade             bool
	RetentionDays            int
	EnforcementLink          string
	Enabled                  bool
	AllowNewVersion          bool
}

// MetricDefinitionRepository persists global backoffice metric definitions.
type MetricDefinitionRepository struct{}

// NewMetricDefinitionRepository returns a stateless metric definition repository.
func NewMetricDefinitionRepository() *MetricDefinitionRepository {
	return &MetricDefinitionRepository{}
}

const metricDefinitionColumns = `id, metric_key, version, unit, source, aggregation_function, aggregation_window_seconds, billing_grade, retention_days, enforcement_link, enabled, revision, published_at, superseded_at, created_at, updated_at`

var metricDefinitionKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}$`)
var metricDefinitionTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}$`)
var metricDefinitionUnitPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
var metricDefinitionLinkPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,159}$`)

// Upsert creates or updates the current definition. Billing-grade unit changes
// are rejected unless AllowNewVersion is set; when allowed, the old row is
// superseded and a new version is published.
func (r *MetricDefinitionRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertMetricDefinitionInput) (MetricDefinition, error) {
	if tx == nil {
		return MetricDefinition{}, apierr.Internal(errors.New("store: MetricDefinitionRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateMetricDefinitionUpsert(key, in)
	if err != nil {
		return MetricDefinition{}, err
	}

	current, err := r.lockCurrent(ctx, tx, key)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return MetricDefinition{}, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return r.insertVersion(ctx, tx, key, 1, input)
	}

	unitChanged := current.Unit != input.Unit
	if current.BillingGrade && unitChanged && !input.AllowNewVersion {
		return MetricDefinition{}, apierr.Conflict("billing-grade metric unit changes require a new version")
	}
	if current.BillingGrade && unitChanged {
		if err := r.supersede(ctx, tx, current.ID); err != nil {
			return MetricDefinition{}, err
		}
		return r.insertVersion(ctx, tx, key, current.Version+1, input)
	}

	row := tx.QueryRow(ctx,
		`UPDATE admin_metric_definitions
		    SET unit = $2,
		        source = $3,
		        aggregation_function = $4,
		        aggregation_window_seconds = $5,
		        billing_grade = $6,
		        retention_days = $7,
		        enforcement_link = $8,
		        enabled = $9,
		        revision = revision + 1
		  WHERE id = $1
		  RETURNING `+metricDefinitionColumns,
		current.ID, input.Unit, input.Source, input.AggregationFunction, input.AggregationWindowSeconds, input.BillingGrade, input.RetentionDays, input.EnforcementLink, input.Enabled)
	out, scanErr := scanMetricDefinition(row)
	if scanErr != nil {
		return MetricDefinition{}, mapWriteError(scanErr, "the metric definition could not be saved")
	}
	return out, nil
}

// Disable marks the current definition disabled without deleting history.
func (r *MetricDefinitionRepository) Disable(ctx context.Context, tx *Tx, key string) (MetricDefinition, error) {
	if tx == nil {
		return MetricDefinition{}, apierr.Internal(errors.New("store: MetricDefinitionRepository.Disable called with a nil transaction"))
	}
	key = strings.TrimSpace(key)
	current, err := r.lockCurrent(ctx, tx, key)
	if err != nil {
		return MetricDefinition{}, err
	}
	row := tx.QueryRow(ctx,
		`UPDATE admin_metric_definitions
		    SET enabled = false,
		        revision = revision + 1
		  WHERE id = $1
		  RETURNING `+metricDefinitionColumns,
		current.ID)
	out, scanErr := scanMetricDefinition(row)
	if scanErr != nil {
		return MetricDefinition{}, mapWriteError(scanErr, "the metric definition could not be disabled")
	}
	return out, nil
}

// Get returns the current definition for key.
func (r *MetricDefinitionRepository) Get(ctx context.Context, q Querier, key string) (MetricDefinition, error) {
	key = strings.TrimSpace(key)
	row := q.QueryRow(ctx,
		`SELECT `+metricDefinitionColumns+`
		   FROM admin_metric_definitions
		  WHERE metric_key = $1
		    AND superseded_at IS NULL`,
		key)
	out, err := scanMetricDefinition(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return MetricDefinition{}, apierr.NotFound("metric_definition", key)
	}
	if err != nil {
		return MetricDefinition{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListRuntimePublished returns enabled current definitions in deterministic
// order for aggregators and billing workers.
func (r *MetricDefinitionRepository) ListRuntimePublished(ctx context.Context, q Querier, _ time.Time) ([]MetricDefinition, error) {
	rows, err := q.Query(ctx,
		`SELECT `+metricDefinitionColumns+`
		   FROM admin_metric_definitions
		  WHERE enabled = true
		    AND superseded_at IS NULL
		  ORDER BY source ASC, metric_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []MetricDefinition
	for rows.Next() {
		def, scanErr := scanMetricDefinition(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, def)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *MetricDefinitionRepository) lockCurrent(ctx context.Context, tx *Tx, key string) (MetricDefinition, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+metricDefinitionColumns+`
		   FROM admin_metric_definitions
		  WHERE metric_key = $1
		    AND superseded_at IS NULL
		  FOR UPDATE`,
		key)
	out, err := scanMetricDefinition(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return MetricDefinition{}, pgx.ErrNoRows
	}
	if err != nil {
		return MetricDefinition{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *MetricDefinitionRepository) insertVersion(ctx context.Context, tx *Tx, key string, version int, in UpsertMetricDefinitionInput) (MetricDefinition, error) {
	id, err := newOpaqueStoreID("mdef")
	if err != nil {
		return MetricDefinition{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_metric_definitions
		    (id, metric_key, version, unit, source, aggregation_function, aggregation_window_seconds, billing_grade, retention_days, enforcement_link, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING `+metricDefinitionColumns,
		id, key, version, in.Unit, in.Source, in.AggregationFunction, in.AggregationWindowSeconds, in.BillingGrade, in.RetentionDays, in.EnforcementLink, in.Enabled)
	out, scanErr := scanMetricDefinition(row)
	if scanErr != nil {
		return MetricDefinition{}, mapWriteError(scanErr, "the metric definition could not be saved")
	}
	return out, nil
}

func (r *MetricDefinitionRepository) supersede(ctx context.Context, tx *Tx, id string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE admin_metric_definitions
		    SET superseded_at = now(),
		        revision = revision + 1
		  WHERE id = $1
		    AND superseded_at IS NULL`,
		id)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	if tag.RowsAffected() == 0 {
		return apierr.Conflict("metric definition was changed concurrently")
	}
	return nil
}

func validateMetricDefinitionUpsert(key string, in UpsertMetricDefinitionInput) (string, UpsertMetricDefinitionInput, error) {
	key = strings.TrimSpace(key)
	in.Unit = strings.TrimSpace(in.Unit)
	in.Source = strings.TrimSpace(in.Source)
	in.EnforcementLink = strings.TrimSpace(in.EnforcementLink)
	var violations []apierr.FieldViolation
	if !metricDefinitionKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "metric_key", Reason: "must be a stable lowercase token"})
	}
	if !metricDefinitionUnitPattern.MatchString(in.Unit) {
		violations = append(violations, apierr.FieldViolation{Field: "unit", Reason: "must be a stable lowercase token"})
	}
	if !metricDefinitionTokenPattern.MatchString(in.Source) {
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be a stable lowercase token"})
	}
	if !in.AggregationFunction.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_function", Reason: "must be one of sum, max, avg, p95, last"})
	}
	if in.AggregationWindowSeconds == 0 {
		in.AggregationWindowSeconds = 60
	}
	if in.AggregationWindowSeconds < 1 || in.AggregationWindowSeconds > 2678400 {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_window_seconds", Reason: "must be between 1 and 2678400"})
	}
	if in.RetentionDays == 0 {
		in.RetentionDays = 400
	}
	if in.RetentionDays < 1 || in.RetentionDays > 3650 {
		violations = append(violations, apierr.FieldViolation{Field: "retention_days", Reason: "must be between 1 and 3650"})
	}
	if in.EnforcementLink != "" && !metricDefinitionLinkPattern.MatchString(in.EnforcementLink) {
		violations = append(violations, apierr.FieldViolation{Field: "enforcement_link", Reason: "must be a stable lowercase token"})
	}
	if in.BillingGrade && in.AggregationFunction == MetricAggregationLast {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_function", Reason: "billing-grade metrics cannot use last"})
	}
	if len(violations) > 0 {
		return "", UpsertMetricDefinitionInput{}, apierr.InvalidInput(violations...)
	}
	return key, in, nil
}

func scanMetricDefinition(row pgx.Row) (MetricDefinition, error) {
	var out MetricDefinition
	err := row.Scan(
		&out.ID,
		&out.Key,
		&out.Version,
		&out.Unit,
		&out.Source,
		&out.AggregationFunction,
		&out.AggregationWindowSeconds,
		&out.BillingGrade,
		&out.RetentionDays,
		&out.EnforcementLink,
		&out.Enabled,
		&out.Revision,
		&out.PublishedAt,
		&out.SupersededAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return MetricDefinition{}, err
	}
	return out, nil
}
