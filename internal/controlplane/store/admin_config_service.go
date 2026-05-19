package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

const (
	adminConfigResourceKind = "admin_config"
)

// AdminConfigAuditContext carries the operator/request identity that must be
// written next to every backoffice configuration change.
type AdminConfigAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminConfigService composes admin configuration mutations with immutable
// audit records. The underlying config tables are global operator-owned state,
// so audit rows are filed under the admin principal's organization.
type AdminConfigService struct {
	store *Store
	orgs  *OrganizationRepository
	repo  *AdminConfigRepository
	audit *AuditRepository
}

// NewAdminConfigService builds an audited backoffice config service.
func NewAdminConfigService(s *Store, orgs *OrganizationRepository, repo *AdminConfigRepository, audit *AuditRepository) (*AdminConfigService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if repo == nil {
		return nil, errors.New("store: nil admin config repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminConfigService{store: s, orgs: orgs, repo: repo, audit: audit}, nil
}

// CreateSet creates a config set and records the admin change in one commit.
func (svc *AdminConfigService) CreateSet(ctx context.Context, in CreateAdminConfigSetInput, auditCtx AdminConfigAuditContext) (AdminConfigSet, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigSet{}, err
	}
	var out AdminConfigSet
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		set, err := svc.repo.CreateSet(ctx, tx, in)
		if err != nil {
			return err
		}
		meta := adminConfigAuditMetadata(adminConfigAuditMetadataInput{
			Operation:   "create_set",
			ConfigSetID: set.ID,
			Domain:      string(set.Domain),
			Reason:      auditCtx.Reason,
			After: map[string]any{
				"id":          set.ID,
				"slug":        set.Slug,
				"domain":      string(set.Domain),
				"name":        set.Name,
				"description": set.Description,
			},
		})
		if _, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.create_set", set.ID, meta)); err != nil {
			return err
		}
		out = set
		return nil
	})
	if err != nil {
		return AdminConfigSet{}, err
	}
	return out, nil
}

// CreateDraft creates the next editable version and records a redacted payload
// diff. Secret-looking values are replaced before they reach audit metadata.
func (svc *AdminConfigService) CreateDraft(ctx context.Context, in CreateAdminConfigDraftInput, auditCtx AdminConfigAuditContext) (AdminConfigVersion, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	var out AdminConfigVersion
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		set, err := svc.repo.lockSet(ctx, tx, strings.TrimSpace(in.ConfigSetID))
		if err != nil {
			return err
		}
		version, err := svc.repo.CreateDraft(ctx, tx, in)
		if err != nil {
			return err
		}
		meta := adminConfigVersionAuditMetadata("create_draft", set, nil, version, auditCtx.Reason, nil, "")
		if _, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.create_draft", version.ID, meta)); err != nil {
			return err
		}
		out = version
		return nil
	})
	if err != nil {
		return AdminConfigVersion{}, err
	}
	return out, nil
}

// Publish converts a draft into a published candidate and records before/after
// metadata including the effective timestamp.
func (svc *AdminConfigService) Publish(ctx context.Context, id string, in PublishAdminConfigVersionInput, auditCtx AdminConfigAuditContext) (AdminConfigVersion, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	var out AdminConfigVersion
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		before, err := svc.repo.lockVersion(ctx, tx, strings.TrimSpace(id))
		if err != nil {
			return err
		}
		set, err := svc.repo.lockSet(ctx, tx, before.ConfigSetID)
		if err != nil {
			return err
		}
		published, err := svc.repo.Publish(ctx, tx, before.ID, in)
		if err != nil {
			return err
		}
		meta := adminConfigVersionAuditMetadata("publish", set, &before, published, auditCtx.Reason, published.EffectiveAt, "")
		if _, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.publish", published.ID, meta)); err != nil {
			return err
		}
		out = published
		return nil
	})
	if err != nil {
		return AdminConfigVersion{}, err
	}
	return out, nil
}

// Rollback publishes a new version copied from an older version and records
// both the operator reason and the rollback target.
func (svc *AdminConfigService) Rollback(ctx context.Context, configSetID, sourceVersionID string, in RollbackAdminConfigInput, auditCtx AdminConfigAuditContext) (AdminConfigVersion, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	var out AdminConfigVersion
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		set, err := svc.repo.lockSet(ctx, tx, strings.TrimSpace(configSetID))
		if err != nil {
			return err
		}
		source, err := svc.repo.getVersionInSet(ctx, tx, set.ID, strings.TrimSpace(sourceVersionID))
		if err != nil {
			return err
		}
		rollback, err := svc.repo.Rollback(ctx, tx, set.ID, source.ID, in)
		if err != nil {
			return err
		}
		rollbackTarget := ""
		if rollback.RollbackOfVersionID != nil {
			rollbackTarget = *rollback.RollbackOfVersionID
		}
		meta := adminConfigVersionAuditMetadata("rollback", set, &source, rollback, auditCtx.Reason, rollback.EffectiveAt, rollbackTarget)
		if _, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.rollback", rollback.ID, meta)); err != nil {
			return err
		}
		out = rollback
		return nil
	})
	if err != nil {
		return AdminConfigVersion{}, err
	}
	return out, nil
}

// Archive marks a version as archived and records the lifecycle transition.
func (svc *AdminConfigService) Archive(ctx context.Context, id string, auditCtx AdminConfigAuditContext) (AdminConfigVersion, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	var out AdminConfigVersion
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		before, err := svc.repo.lockVersion(ctx, tx, strings.TrimSpace(id))
		if err != nil {
			return err
		}
		set, err := svc.repo.lockSet(ctx, tx, before.ConfigSetID)
		if err != nil {
			return err
		}
		archived, err := svc.repo.Archive(ctx, tx, before.ID)
		if err != nil {
			return err
		}
		meta := adminConfigVersionAuditMetadata("archive", set, &before, archived, auditCtx.Reason, nil, "")
		if _, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.archive", archived.ID, meta)); err != nil {
			return err
		}
		out = archived
		return nil
	})
	if err != nil {
		return AdminConfigVersion{}, err
	}
	return out, nil
}

// AuditAdminConfigDenied records a refused backoffice configuration action.
func (svc *AdminConfigService) AuditAdminConfigDenied(ctx context.Context, auditCtx AdminConfigAuditContext, action, resourceID, denialReason string) error {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return err
	}
	action = strings.TrimSpace(action)
	if action == "" {
		action = "admin.config"
	}
	denialReason = strings.TrimSpace(denialReason)
	if denialReason == "" {
		denialReason = "authorization denied"
	}
	return svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, AuditEvent{
			OrganizationID: auditCtx.ActorOrgID,
			ActorID:        auditCtx.ActorID,
			ActorKind:      auditCtx.ActorKind,
			Action:         action,
			ResourceKind:   adminConfigResourceKind,
			ResourceID:     strings.TrimSpace(resourceID),
			Decision:       AuditDecisionDenied,
			Reason:         denialReason,
			RequestID:      auditCtx.RequestID,
			CorrelationID:  auditCtx.CorrelationID,
			Metadata: map[string]string{
				"operation": "denied",
				"reason":    auditCtx.Reason,
			},
		})
		return err
	})
}

type adminConfigAuditMetadataInput struct {
	Operation      string
	ConfigSetID    string
	VersionID      string
	Domain         string
	Reason         string
	EffectiveAt    *time.Time
	RollbackTarget string
	Before         any
	After          any
}

func adminConfigVersionAuditMetadata(operation string, set AdminConfigSet, before *AdminConfigVersion, after AdminConfigVersion, reason string, effectiveAt *time.Time, rollbackTarget string) map[string]string {
	var beforePayload any
	if before != nil {
		beforePayload = adminConfigVersionAuditShape(*before)
	}
	return adminConfigAuditMetadata(adminConfigAuditMetadataInput{
		Operation:      operation,
		ConfigSetID:    set.ID,
		VersionID:      after.ID,
		Domain:         string(set.Domain),
		Reason:         reason,
		EffectiveAt:    effectiveAt,
		RollbackTarget: rollbackTarget,
		Before:         beforePayload,
		After:          adminConfigVersionAuditShape(after),
	})
}

func adminConfigVersionAuditShape(v AdminConfigVersion) map[string]any {
	return map[string]any{
		"id":                     v.ID,
		"config_set_id":          v.ConfigSetID,
		"version":                v.Version,
		"status":                 string(v.Status),
		"payload":                decodeAdminConfigAuditPayload(v.Payload),
		"effective_at":           formatAuditTimePtr(v.EffectiveAt),
		"published_by":           stringPtrValue(v.PublishedBy),
		"rollback_of_version_id": stringPtrValue(v.RollbackOfVersionID),
		"rollback_reason":        v.RollbackReason,
	}
}

func adminConfigAuditMetadata(in adminConfigAuditMetadataInput) map[string]string {
	before := redactAdminConfigAuditValue(in.Before)
	after := redactAdminConfigAuditValue(in.After)
	meta := map[string]string{
		"operation":      strings.TrimSpace(in.Operation),
		"config_set_id":  strings.TrimSpace(in.ConfigSetID),
		"version_id":     strings.TrimSpace(in.VersionID),
		"domain":         strings.TrimSpace(in.Domain),
		"reason":         output.NewRedactor().Redact(strings.TrimSpace(in.Reason)),
		"changed_fields": mustAuditJSON(changedAdminConfigFields(before, after)),
		"before":         mustAuditJSON(before),
		"after":          mustAuditJSON(after),
	}
	if in.EffectiveAt != nil {
		meta["effective_at"] = in.EffectiveAt.UTC().Format(time.RFC3339Nano)
	}
	if strings.TrimSpace(in.RollbackTarget) != "" {
		meta["rollback_target_version_id"] = strings.TrimSpace(in.RollbackTarget)
	}
	return meta
}

func adminConfigAuditEvent(auditCtx AdminConfigAuditContext, action, resourceID string, metadata map[string]string) AuditEvent {
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         action,
		ResourceKind:   adminConfigResourceKind,
		ResourceID:     resourceID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for " + action,
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata:       metadata,
	}
}

func validateAdminConfigAuditContext(in AdminConfigAuditContext) (AdminConfigAuditContext, error) {
	out := AdminConfigAuditContext{
		ActorOrgID:    strings.TrimSpace(in.ActorOrgID),
		ActorID:       strings.TrimSpace(in.ActorID),
		ActorKind:     strings.TrimSpace(in.ActorKind),
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
		Reason:        strings.TrimSpace(in.Reason),
	}
	var violations []apierr.FieldViolation
	if out.ActorOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_org_id", Reason: "is required"})
	}
	if out.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "is required"})
	}
	if out.ActorKind == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_kind", Reason: "is required"})
	}
	if out.Reason == "" {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "is required"})
	}
	if len(violations) > 0 {
		return AdminConfigAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func decodeAdminConfigAuditPayload(raw []byte) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return map[string]any{"_invalid_json": true}
	}
	return v
}

func redactAdminConfigAuditValue(v any) any {
	return redactAdminConfigAuditValueAt("", v)
}

func redactAdminConfigAuditValueAt(path string, v any) any {
	switch typed := v.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			childPath := joinAuditPath(path, key)
			if isSecretAuditKey(key) {
				out[key] = output.Sentinel
				continue
			}
			out[key] = redactAdminConfigAuditValueAt(childPath, value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, value := range typed {
			out[i] = redactAdminConfigAuditValueAt(fmt.Sprintf("%s[%d]", path, i), value)
		}
		return out
	case string:
		if isSecretAuditKey(path) {
			return output.Sentinel
		}
		return output.NewRedactor().Redact(typed)
	default:
		return typed
	}
}

func changedAdminConfigFields(before, after any) []string {
	changes := make(map[string]struct{})
	collectAdminConfigChanges("", before, after, changes)
	out := make([]string, 0, len(changes))
	for field := range changes {
		out = append(out, field)
	}
	sort.Strings(out)
	return out
}

func collectAdminConfigChanges(path string, before, after any, changes map[string]struct{}) {
	if fmt.Sprintf("%#v", before) == fmt.Sprintf("%#v", after) {
		return
	}
	beforeMap, beforeIsMap := before.(map[string]any)
	afterMap, afterIsMap := after.(map[string]any)
	if beforeIsMap || afterIsMap {
		keys := make(map[string]struct{})
		for key := range beforeMap {
			keys[key] = struct{}{}
		}
		for key := range afterMap {
			keys[key] = struct{}{}
		}
		for key := range keys {
			collectAdminConfigChanges(joinAuditPath(path, key), beforeMap[key], afterMap[key], changes)
		}
		return
	}
	if path == "" {
		path = "$"
	}
	changes[path] = struct{}{}
}

func isSecretAuditKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"secret", "token", "password", "credential", "cookie", "api_key", "apikey", "private_key", "client_secret", "dsn"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func joinAuditPath(parent, key string) string {
	key = strings.TrimSpace(key)
	if parent == "" {
		return key
	}
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func mustAuditJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func formatAuditTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func stringPtrValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
