package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const adminUsageAggregationScheduleResourceKind = "usage_aggregation_schedule"

// AdminUsageAggregationScheduleAuditContext carries operator identity for
// aggregation schedule changes.
type AdminUsageAggregationScheduleAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminUsageAggregationScheduleService composes schedule writes with immutable
// audit records.
type AdminUsageAggregationScheduleService struct {
	store     *Store
	orgs      *OrganizationRepository
	schedules *UsageAggregationScheduleRepository
	audit     *AuditRepository
}

// NewAdminUsageAggregationScheduleService builds an audited aggregation
// schedule manager.
func NewAdminUsageAggregationScheduleService(s *Store, orgs *OrganizationRepository, schedules *UsageAggregationScheduleRepository, audit *AuditRepository) (*AdminUsageAggregationScheduleService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if schedules == nil {
		return nil, errors.New("store: nil usage aggregation schedule repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminUsageAggregationScheduleService{store: s, orgs: orgs, schedules: schedules, audit: audit}, nil
}

// UpsertUsageAggregationSchedule creates or updates one schedule and records
// the change in the audit log.
func (svc *AdminUsageAggregationScheduleService) UpsertUsageAggregationSchedule(ctx context.Context, key string, in UpsertUsageAggregationScheduleInput, auditCtx AdminUsageAggregationScheduleAuditContext) (UsageAggregationSchedule, error) {
	auditCtx, err := validateAdminUsageAggregationScheduleAuditContext(auditCtx)
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	var out UsageAggregationSchedule
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		schedule, err := svc.schedules.Upsert(ctx, tx, key, in)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminUsageAggregationScheduleAuditEvent(auditCtx, schedule, "admin.usage_aggregation_schedule.upsert", "upsert"))
		if err != nil {
			return err
		}
		out = schedule
		return nil
	})
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	return out, nil
}

// GetUsageAggregationSchedule returns the current schedule by key.
func (svc *AdminUsageAggregationScheduleService) GetUsageAggregationSchedule(ctx context.Context, key string) (UsageAggregationSchedule, error) {
	var out UsageAggregationSchedule
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		out, err = svc.schedules.Get(ctx, q, key)
		return err
	})
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	return out, nil
}

// DisableUsageAggregationSchedule disables one schedule and records the
// lifecycle change in the audit log.
func (svc *AdminUsageAggregationScheduleService) DisableUsageAggregationSchedule(ctx context.Context, key string, auditCtx AdminUsageAggregationScheduleAuditContext) (UsageAggregationSchedule, error) {
	auditCtx, err := validateAdminUsageAggregationScheduleAuditContext(auditCtx)
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	var out UsageAggregationSchedule
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		schedule, err := svc.schedules.Disable(ctx, tx, key)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminUsageAggregationScheduleAuditEvent(auditCtx, schedule, "admin.usage_aggregation_schedule.disable", "disable"))
		if err != nil {
			return err
		}
		out = schedule
		return nil
	})
	if err != nil {
		return UsageAggregationSchedule{}, err
	}
	return out, nil
}

func validateAdminUsageAggregationScheduleAuditContext(in AdminUsageAggregationScheduleAuditContext) (AdminUsageAggregationScheduleAuditContext, error) {
	out := AdminUsageAggregationScheduleAuditContext{
		ActorOrgID:    strings.TrimSpace(in.ActorOrgID),
		ActorID:       strings.TrimSpace(in.ActorID),
		ActorKind:     strings.TrimSpace(in.ActorKind),
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
		Reason:        strings.TrimSpace(in.Reason),
	}
	var violations []apierr.FieldViolation
	if out.ActorOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_org_id", Reason: "must not be blank"})
	}
	if out.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must not be blank"})
	}
	if out.ActorKind == "" {
		out.ActorKind = "user"
	}
	if out.RequestID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must not be blank"})
	}
	if out.CorrelationID == "" {
		out.CorrelationID = out.RequestID
	}
	if len(violations) > 0 {
		return AdminUsageAggregationScheduleAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminUsageAggregationScheduleAuditEvent(auditCtx AdminUsageAggregationScheduleAuditContext, schedule UsageAggregationSchedule, action, operation string) AuditEvent {
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditEventActorKind(auditCtx.ActorKind),
		Action:         action,
		ResourceKind:   adminUsageAggregationScheduleResourceKind,
		ResourceID:     schedule.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         auditCtx.Reason,
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":                    operation,
			"schedule_key":                 schedule.ScheduleKey,
			"version":                      itoa(schedule.Version),
			"source":                       schedule.Source,
			"metric_key":                   schedule.MetricKey,
			"aggregation_interval_seconds": itoa(schedule.AggregationIntervalSeconds),
			"replay_lookback_seconds":      itoa(schedule.ReplayLookbackSeconds),
			"close_delay_seconds":          itoa(schedule.CloseDelaySeconds),
			"late_event_mode":              string(schedule.LateEventMode),
			"enabled":                      boolString(schedule.Enabled),
			"reason":                       auditCtx.Reason,
		},
	}
}
