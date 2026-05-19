package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const adminMetricDefinitionResourceKind = "metric_definition"

// AdminMetricDefinitionAuditContext carries operator identity for metric
// definition changes.
type AdminMetricDefinitionAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminMetricDefinitionService composes metric definition writes with immutable
// audit records.
type AdminMetricDefinitionService struct {
	store *Store
	orgs  *OrganizationRepository
	defs  *MetricDefinitionRepository
	audit *AuditRepository
}

// NewAdminMetricDefinitionService builds an audited metric definition manager.
func NewAdminMetricDefinitionService(s *Store, orgs *OrganizationRepository, defs *MetricDefinitionRepository, audit *AuditRepository) (*AdminMetricDefinitionService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if defs == nil {
		return nil, errors.New("store: nil metric definition repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminMetricDefinitionService{store: s, orgs: orgs, defs: defs, audit: audit}, nil
}

// UpsertMetricDefinition creates or updates one metric definition and records
// the change in the audit log.
func (svc *AdminMetricDefinitionService) UpsertMetricDefinition(ctx context.Context, key string, in UpsertMetricDefinitionInput, auditCtx AdminMetricDefinitionAuditContext) (MetricDefinition, error) {
	auditCtx, err := validateAdminMetricDefinitionAuditContext(auditCtx)
	if err != nil {
		return MetricDefinition{}, err
	}
	var out MetricDefinition
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		def, err := svc.defs.Upsert(ctx, tx, key, in)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminMetricDefinitionAuditEvent(auditCtx, def, "admin.metric_definition.upsert", "upsert"))
		if err != nil {
			return err
		}
		out = def
		return nil
	})
	if err != nil {
		return MetricDefinition{}, err
	}
	return out, nil
}

// GetMetricDefinition returns the current metric definition by key.
func (svc *AdminMetricDefinitionService) GetMetricDefinition(ctx context.Context, key string) (MetricDefinition, error) {
	var out MetricDefinition
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		out, err = svc.defs.Get(ctx, q, key)
		return err
	})
	if err != nil {
		return MetricDefinition{}, err
	}
	return out, nil
}

// DisableMetricDefinition disables one metric definition and records the
// lifecycle change in the audit log.
func (svc *AdminMetricDefinitionService) DisableMetricDefinition(ctx context.Context, key string, auditCtx AdminMetricDefinitionAuditContext) (MetricDefinition, error) {
	auditCtx, err := validateAdminMetricDefinitionAuditContext(auditCtx)
	if err != nil {
		return MetricDefinition{}, err
	}
	var out MetricDefinition
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		def, err := svc.defs.Disable(ctx, tx, key)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminMetricDefinitionAuditEvent(auditCtx, def, "admin.metric_definition.disable", "disable"))
		if err != nil {
			return err
		}
		out = def
		return nil
	})
	if err != nil {
		return MetricDefinition{}, err
	}
	return out, nil
}

func validateAdminMetricDefinitionAuditContext(in AdminMetricDefinitionAuditContext) (AdminMetricDefinitionAuditContext, error) {
	out := AdminMetricDefinitionAuditContext{
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
		return AdminMetricDefinitionAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminMetricDefinitionAuditEvent(auditCtx AdminMetricDefinitionAuditContext, def MetricDefinition, action, operation string) AuditEvent {
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         action,
		ResourceKind:   adminMetricDefinitionResourceKind,
		ResourceID:     def.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         auditCtx.Reason,
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":                  operation,
			"metric_key":                 def.Key,
			"version":                    itoa(def.Version),
			"unit":                       def.Unit,
			"source":                     def.Source,
			"aggregation_function":       string(def.AggregationFunction),
			"aggregation_window_seconds": itoa(def.AggregationWindowSeconds),
			"billing_grade":              boolString(def.BillingGrade),
			"retention_days":             itoa(def.RetentionDays),
			"enforcement_link":           def.EnforcementLink,
			"enabled":                    boolString(def.Enabled),
			"reason":                     auditCtx.Reason,
		},
	}
}
