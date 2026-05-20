package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// UsageEventType identifies why a usage event was written. The values mirror
// usage_events.event_type.
type UsageEventType string

const (
	// UsageEventTypeReserved records a temporary quota or usage reservation.
	UsageEventTypeReserved UsageEventType = "reserved"
	// UsageEventTypeCommitted records a reservation becoming billable usage.
	UsageEventTypeCommitted UsageEventType = "committed"
	// UsageEventTypeReleased records a reservation being released.
	UsageEventTypeReleased UsageEventType = "released"
	// UsageEventTypeExpired records a reservation expiring unused.
	UsageEventTypeExpired UsageEventType = "expired"
	// UsageEventTypeConsumed records directly observed usage.
	UsageEventTypeConsumed UsageEventType = "consumed"
	// UsageEventTypeAdjusted records an explicit correction to prior usage.
	UsageEventTypeAdjusted UsageEventType = "adjusted"
)

func (t UsageEventType) valid() bool {
	switch t {
	case UsageEventTypeReserved, UsageEventTypeCommitted, UsageEventTypeReleased, UsageEventTypeExpired, UsageEventTypeConsumed, UsageEventTypeAdjusted:
		return true
	default:
		return false
	}
}

// UsageEvent is the append-only raw usage record consumed by later billing
// counter aggregation. Resource is the metered quota/billing dimension; the
// optional project/environment/service fields pin the event to a tenant-owned
// resource scope when attribution is known.
type UsageEvent struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Resource       QuotaResource
	EventType      UsageEventType
	Quantity       float64
	Unit           string
	Source         string
	IdempotencyKey string
	ReservationID  string
	RequestID      string
	Metadata       map[string]string
	OccurredAt     time.Time
	PeriodStart    *time.Time
	PeriodEnd      *time.Time
	CreatedAt      time.Time
}

// AppendUsageEventInput is the validated write contract for UsageEventRepository.Append.
type AppendUsageEventInput struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Resource       QuotaResource
	EventType      UsageEventType
	Quantity       float64
	Unit           string
	Source         string
	IdempotencyKey string
	ReservationID  string
	RequestID      string
	Metadata       map[string]string
	OccurredAt     time.Time
}

// UsageEventRepository writes append-only billing and metering events.
type UsageEventRepository struct{}

// NewUsageEventRepository constructs a stateless usage event repository.
func NewUsageEventRepository() *UsageEventRepository { return &UsageEventRepository{} }

const usageEventColumns = `id, organization_id, project_id, environment_id, service_id, resource, event_type, quantity, unit, source, idempotency_key, reservation_id, request_id, metadata, occurred_at, period_start, period_end, created_at`

// Append inserts one usage event and returns the persisted row. If an event
// already exists for (organization, source, idempotency_key), the existing row
// is returned and no second event is written.
func (r *UsageEventRepository) Append(ctx context.Context, tx *Tx, in AppendUsageEventInput) (UsageEvent, error) {
	if tx == nil {
		return UsageEvent{}, apierr.Internal(errors.New("store: UsageEventRepository.Append called with a nil transaction"))
	}
	event, err := buildUsageEventToAppend(in)
	if err != nil {
		return UsageEvent{}, err
	}
	if event.ID == "" {
		event.ID, err = newOpaqueStoreID("uevt")
		if err != nil {
			return UsageEvent{}, apierr.Internal(err)
		}
	}
	if err := r.validateScope(ctx, tx, event); err != nil {
		return UsageEvent{}, err
	}
	periodStart, periodEnd, err := resolveUsageEventPeriod(ctx, tx, event.OrganizationID, event.OccurredAt)
	if err != nil {
		return UsageEvent{}, err
	}
	event.PeriodStart = &periodStart
	event.PeriodEnd = &periodEnd
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return UsageEvent{}, apierr.Internal(err)
	}

	var idemKey *string
	if event.IdempotencyKey != "" {
		idemKey = &event.IdempotencyKey
	}
	var projectID, environmentID, serviceID, reservationID *string
	if event.ProjectID != "" {
		projectID = &event.ProjectID
	}
	if event.EnvironmentID != "" {
		environmentID = &event.EnvironmentID
	}
	if event.ServiceID != "" {
		serviceID = &event.ServiceID
	}
	if event.ReservationID != "" {
		reservationID = &event.ReservationID
	}

	inserted, err := scanUsageEvent(tx.QueryRow(ctx,
		`INSERT INTO usage_events
		    (id, organization_id, project_id, environment_id, service_id, resource, event_type,
		     delta, quantity, unit, source, idempotency_key, reservation_id, request_id, metadata,
		     occurred_at, period_start, period_end)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		 ON CONFLICT (organization_id, source, idempotency_key)
		   WHERE idempotency_key IS NOT NULL
		 DO NOTHING
		 RETURNING `+usageEventColumns,
		event.ID, event.OrganizationID, projectID, environmentID, serviceID, string(event.Resource), string(event.EventType),
		int64(event.Quantity), event.Quantity, event.Unit, event.Source, idemKey, reservationID, event.RequestID, metadata,
		event.OccurredAt, periodStart, periodEnd,
	))
	if err == nil {
		return inserted, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return UsageEvent{}, mapWriteError(err, "append usage event")
	}
	return r.getByIdempotency(ctx, tx, event.OrganizationID, event.Source, event.IdempotencyKey)
}

func (r *UsageEventRepository) getByIdempotency(ctx context.Context, q Querier, organizationID, source, idempotencyKey string) (UsageEvent, error) {
	if idempotencyKey == "" {
		return UsageEvent{}, apierr.Internal(errors.New("store: usage event insert returned no row without idempotency key conflict"))
	}
	event, err := scanUsageEvent(q.QueryRow(ctx,
		`SELECT `+usageEventColumns+`
		   FROM usage_events
		  WHERE organization_id = $1 AND source = $2 AND idempotency_key = $3`,
		organizationID, source, idempotencyKey,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageEvent{}, apierr.Internal(errors.New("store: usage event idempotency conflict row vanished"))
	}
	if err != nil {
		return UsageEvent{}, apierr.StoreUnavailable(err)
	}
	return event, nil
}

func (r *UsageEventRepository) validateScope(ctx context.Context, q Querier, event UsageEvent) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)`, event.OrganizationID).Scan(&ok); err != nil {
		return apierr.StoreUnavailable(err)
	}
	if !ok {
		return apierr.NotFound("organization", event.OrganizationID)
	}
	if event.ProjectID != "" {
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM projects WHERE organization_id = $1 AND id = $2)`,
			event.OrganizationID, event.ProjectID).Scan(&ok); err != nil {
			return apierr.StoreUnavailable(err)
		}
		if !ok {
			return apierr.NotFound("project", event.ProjectID)
		}
	}
	if event.EnvironmentID != "" {
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM environments WHERE organization_id = $1 AND project_id = $2 AND id = $3)`,
			event.OrganizationID, event.ProjectID, event.EnvironmentID).Scan(&ok); err != nil {
			return apierr.StoreUnavailable(err)
		}
		if !ok {
			return apierr.NotFound("environment", event.EnvironmentID)
		}
	}
	if event.ServiceID != "" {
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM services WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3 AND id = $4)`,
			event.OrganizationID, event.ProjectID, event.EnvironmentID, event.ServiceID).Scan(&ok); err != nil {
			return apierr.StoreUnavailable(err)
		}
		if !ok {
			return apierr.NotFound("service", event.ServiceID)
		}
	}
	return nil
}

func buildUsageEventToAppend(in AppendUsageEventInput) (UsageEvent, error) {
	event := UsageEvent{
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		ProjectID:      strings.TrimSpace(in.ProjectID),
		EnvironmentID:  strings.TrimSpace(in.EnvironmentID),
		ServiceID:      strings.TrimSpace(in.ServiceID),
		Resource:       in.Resource,
		EventType:      in.EventType,
		Quantity:       in.Quantity,
		Unit:           strings.TrimSpace(in.Unit),
		Source:         strings.TrimSpace(in.Source),
		IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
		ReservationID:  strings.TrimSpace(in.ReservationID),
		RequestID:      strings.TrimSpace(in.RequestID),
		OccurredAt:     in.OccurredAt.UTC(),
		Metadata:       redactUsageEventMetadata(in.Metadata),
	}
	var violations []apierr.FieldViolation
	if event.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if !event.Resource.Valid() {
		violations = append(violations, apierr.FieldViolation{Field: "resource", Reason: "must be a known usage resource"})
	}
	if !event.EventType.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "event_type", Reason: "must be a known usage event type"})
	}
	if event.Unit == "" || !validProviderKey(event.Unit) {
		violations = append(violations, apierr.FieldViolation{Field: "unit", Reason: "must be a canonical unit key"})
	}
	if event.Source == "" || !validProviderKey(event.Source) {
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be a canonical source key"})
	}
	if len(event.IdempotencyKey) > 200 {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "must be at most 200 characters"})
	}
	if event.EnvironmentID != "" && event.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "must be set when environment_id is set"})
	}
	if event.ServiceID != "" && (event.ProjectID == "" || event.EnvironmentID == "") {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "requires project_id and environment_id"})
	}
	if event.OccurredAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "occurred_at", Reason: "must not be zero"})
	}
	if math.IsNaN(event.Quantity) || math.IsInf(event.Quantity, 0) {
		violations = append(violations, apierr.FieldViolation{Field: "quantity", Reason: "must be finite"})
	} else if event.EventType == UsageEventTypeAdjusted {
		if event.Quantity == 0 {
			violations = append(violations, apierr.FieldViolation{Field: "quantity", Reason: "must be non-zero for adjustment events"})
		}
	} else if event.Quantity < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "quantity", Reason: "must be non-negative unless event_type is adjusted"})
	}
	if len(violations) > 0 {
		return UsageEvent{}, apierr.InvalidInput(violations...)
	}
	return event, nil
}

func resolveUsageEventPeriod(ctx context.Context, q Querier, organizationID string, occurredAt time.Time) (time.Time, time.Time, error) {
	var start, end time.Time
	err := q.QueryRow(ctx,
		`SELECT current_period_start, current_period_end
		   FROM subscriptions
		  WHERE organization_id = $1
		    AND status IN ('trialing', 'active', 'past_due')
		    AND current_period_start <= $2
		    AND current_period_end > $2
		  ORDER BY current_period_start DESC, created_at DESC, id DESC
		  LIMIT 1`,
		organizationID, occurredAt,
	).Scan(&start, &end)
	if err == nil {
		return start.UTC(), end.UTC(), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, time.Time{}, apierr.StoreUnavailable(err)
	}
	utc := occurredAt.UTC()
	start = time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
	end = start.AddDate(0, 1, 0)
	return start, end, nil
}

func redactUsageEventMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	redactor := output.NewRedactor()
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		if usageMetadataKeyIsSecret(key) {
			out[key] = output.Sentinel
			continue
		}
		out[key] = redactor.Redact(v)
	}
	return out
}

func usageMetadataKeyIsSecret(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	normalized := strings.NewReplacer("-", "_", ".", "_").Replace(key)
	for _, marker := range []string{
		"token",
		"secret",
		"password",
		"credential",
		"cookie",
		"api_key",
		"apikey",
		"authorization",
		"private_key",
		"tls_key",
		"database_url",
		"connection_string",
		"connection_uri",
		"postgres_url",
		"postgresql_url",
		"mysql_url",
		"redis_url",
	} {
		if strings.Contains(key, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}
	if normalized == "dsn" || strings.HasSuffix(normalized, "_dsn") {
		return true
	}
	return false
}

func scanUsageEvent(row pgx.Row) (UsageEvent, error) {
	var (
		event          UsageEvent
		projectID      *string
		environmentID  *string
		serviceID      *string
		resource       string
		eventType      string
		idempotencyKey *string
		reservationID  *string
		metadata       []byte
		periodStart    time.Time
		periodEnd      time.Time
	)
	if err := row.Scan(
		&event.ID, &event.OrganizationID, &projectID, &environmentID, &serviceID,
		&resource, &eventType, &event.Quantity, &event.Unit, &event.Source,
		&idempotencyKey, &reservationID, &event.RequestID, &metadata, &event.OccurredAt,
		&periodStart, &periodEnd, &event.CreatedAt,
	); err != nil {
		return UsageEvent{}, err
	}
	if projectID != nil {
		event.ProjectID = *projectID
	}
	if environmentID != nil {
		event.EnvironmentID = *environmentID
	}
	if serviceID != nil {
		event.ServiceID = *serviceID
	}
	if idempotencyKey != nil {
		event.IdempotencyKey = *idempotencyKey
	}
	if reservationID != nil {
		event.ReservationID = *reservationID
	}
	event.Resource = QuotaResource(resource)
	event.EventType = UsageEventType(eventType)
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			return UsageEvent{}, apierr.StoreUnavailable(err)
		}
	}
	if event.Metadata == nil {
		event.Metadata = map[string]string{}
	}
	event.PeriodStart = &periodStart
	event.PeriodEnd = &periodEnd
	return event, nil
}
