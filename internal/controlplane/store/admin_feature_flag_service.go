package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

const adminFeatureFlagResourceKind = "feature_flag"

// AdminFeatureFlagAuditContext carries operator identity for feature flag
// changes and admin-sensitive evaluations.
type AdminFeatureFlagAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminFeatureFlagService composes flag writes with audit rows and caches
// runtime evaluation inputs.
type AdminFeatureFlagService struct {
	store *Store
	orgs  *OrganizationRepository
	flags *FeatureFlagRepository
	audit *AuditRepository

	mu     sync.RWMutex
	cached []FeatureFlag
}

// NewAdminFeatureFlagService builds an audited feature-flag manager.
func NewAdminFeatureFlagService(s *Store, orgs *OrganizationRepository, flags *FeatureFlagRepository, audit *AuditRepository) (*AdminFeatureFlagService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if flags == nil {
		return nil, errors.New("store: nil feature flag repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminFeatureFlagService{store: s, orgs: orgs, flags: flags, audit: audit}, nil
}

// UpsertFeatureFlag creates or replaces one feature flag and records an audit row.
func (svc *AdminFeatureFlagService) UpsertFeatureFlag(ctx context.Context, key string, in UpsertFeatureFlagInput, auditCtx AdminFeatureFlagAuditContext) (FeatureFlag, error) {
	auditCtx, err := validateAdminFeatureFlagAuditContext(auditCtx)
	if err != nil {
		return FeatureFlag{}, err
	}
	var out FeatureFlag
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		flag, err := svc.flags.Upsert(ctx, tx, key, in)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminFeatureFlagAuditEvent(auditCtx, flag, "admin.feature_flag.upsert", "upsert"))
		if err != nil {
			return err
		}
		out = flag
		return nil
	})
	if err != nil {
		return FeatureFlag{}, err
	}
	svc.invalidate()
	return out, nil
}

// GetFeatureFlag returns one current flag by key.
func (svc *AdminFeatureFlagService) GetFeatureFlag(ctx context.Context, key string) (FeatureFlag, error) {
	var out FeatureFlag
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		out, err = svc.flags.Get(ctx, q, key)
		return err
	})
	if err != nil {
		return FeatureFlag{}, err
	}
	return out, nil
}

// EvaluateFeatureFlag evaluates a flag against the runtime context.
func (svc *AdminFeatureFlagService) EvaluateFeatureFlag(ctx context.Context, key string, evalCtx FeatureFlagEvaluationContext, auditCtx AdminFeatureFlagAuditContext) (FeatureFlagEvaluation, error) {
	key = strings.TrimSpace(key)
	flags, err := svc.runtimeFlags(ctx)
	if err != nil {
		return FeatureFlagEvaluation{}, err
	}
	for _, flag := range flags {
		if flag.FlagKey != key {
			continue
		}
		out := evaluateFeatureFlag(flag, evalCtx)
		if flag.AdminSensitive {
			normalizedAuditCtx, err := validateAdminFeatureFlagAuditContext(auditCtx)
			if err != nil {
				return FeatureFlagEvaluation{}, err
			}
			if err := svc.auditEvaluation(ctx, normalizedAuditCtx, flag); err != nil {
				return FeatureFlagEvaluation{}, err
			}
			out.EvaluationAudited = true
		}
		return out, nil
	}
	return FeatureFlagEvaluation{}, apierr.NotFound("feature_flag", key)
}

func (svc *AdminFeatureFlagService) runtimeFlags(ctx context.Context) ([]FeatureFlag, error) {
	svc.mu.RLock()
	cached := append([]FeatureFlag(nil), svc.cached...)
	svc.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	var flags []FeatureFlag
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		flags, err = svc.flags.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	})
	if err != nil {
		return nil, err
	}
	svc.mu.Lock()
	svc.cached = append([]FeatureFlag(nil), flags...)
	svc.mu.Unlock()
	return flags, nil
}

func (svc *AdminFeatureFlagService) invalidate() {
	svc.mu.Lock()
	svc.cached = nil
	svc.mu.Unlock()
}

func (svc *AdminFeatureFlagService) auditEvaluation(ctx context.Context, auditCtx AdminFeatureFlagAuditContext, flag FeatureFlag) error {
	return svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, adminFeatureFlagAuditEvent(auditCtx, flag, "admin.feature_flag.evaluate", "evaluate"))
		return err
	})
}

func validateAdminFeatureFlagAuditContext(in AdminFeatureFlagAuditContext) (AdminFeatureFlagAuditContext, error) {
	out := AdminFeatureFlagAuditContext{
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
		return AdminFeatureFlagAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminFeatureFlagAuditEvent(auditCtx AdminFeatureFlagAuditContext, flag FeatureFlag, action, operation string) AuditEvent {
	redactor := output.NewRedactor()
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         action,
		ResourceKind:   adminFeatureFlagResourceKind,
		ResourceID:     flag.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         redactor.Redact(auditCtx.Reason),
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":          operation,
			"flag_key":           flag.FlagKey,
			"value_type":         string(flag.ValueType),
			"enabled":            boolString(flag.Enabled),
			"admin_sensitive":    boolString(flag.AdminSensitive),
			"rollout_percentage": itoa(flag.RolloutPercentage),
			"revision":           itoa(int(flag.Revision)),
			"reason":             redactor.Redact(auditCtx.Reason),
		},
	}
}
