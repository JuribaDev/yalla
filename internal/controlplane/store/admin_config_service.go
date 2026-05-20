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
	yerr "github.com/JuribaDev/yalla/internal/errors"
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

// Export returns a deterministic, non-secret manifest for every admin config
// set and version. The manifest omits source IDs so imports always create new
// target-environment history.
func (svc *AdminConfigService) Export(ctx context.Context, in AdminConfigExportInput, auditCtx AdminConfigAuditContext) (AdminConfigExportManifest, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigExportManifest{}, err
	}
	sourceEnvironment := cleanConfigPromotionEnvironment(in.SourceEnvironment)
	if sourceEnvironment == "" {
		return AdminConfigExportManifest{}, apierr.InvalidInput(apierr.FieldViolation{Field: "source_environment", Reason: "must not be blank"})
	}

	manifest := AdminConfigExportManifest{
		SchemaVersion:     AdminConfigExportSchemaVersion,
		SourceEnvironment: sourceEnvironment,
		ExportedAt:        time.Now().UTC(),
		ConfigSets:        []AdminConfigExportSet{},
	}
	err = svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		sets, err := svc.repo.listSets(ctx, q)
		if err != nil {
			return err
		}
		for _, set := range sets {
			versions, err := svc.repo.listVersionsForSet(ctx, q, set.ID)
			if err != nil {
				return err
			}
			versionByID := make(map[string]int, len(versions))
			for _, version := range versions {
				versionByID[version.ID] = version.Version
			}
			exportSet := AdminConfigExportSet{
				Slug:        set.Slug,
				Domain:      set.Domain,
				Name:        set.Name,
				Description: set.Description,
				Versions:    make([]AdminConfigExportVersion, 0, len(versions)),
			}
			for _, version := range versions {
				payload, err := sanitizeAdminConfigExportPayload(version.Payload)
				if err != nil {
					return err
				}
				exportVersion := AdminConfigExportVersion{
					Version:        version.Version,
					Status:         version.Status,
					Payload:        payload,
					RollbackReason: version.RollbackReason,
					CreatedAt:      version.CreatedAt,
					UpdatedAt:      version.UpdatedAt,
				}
				if version.EffectiveAt != nil {
					effectiveAt := version.EffectiveAt.UTC()
					exportVersion.EffectiveAt = &effectiveAt
				}
				if version.PublishedBy != nil {
					exportVersion.PublishedBy = *version.PublishedBy
				}
				if version.RollbackOfVersionID != nil {
					exportVersion.RollbackOfVersion = versionByID[*version.RollbackOfVersionID]
				}
				if version.ArchivedAt != nil || version.Status == AdminConfigStatusArchived {
					exportVersion.Archived = true
				}
				exportSet.Versions = append(exportSet.Versions, exportVersion)
			}
			manifest.ConfigSets = append(manifest.ConfigSets, exportSet)
		}
		return nil
	})
	if err != nil {
		return AdminConfigExportManifest{}, err
	}
	if err := svc.auditAdminConfigPromotion(ctx, auditCtx, "admin.config.export", "export", sourceEnvironment, "", len(manifest.ConfigSets), nil); err != nil {
		return AdminConfigExportManifest{}, err
	}
	return manifest, nil
}

// Import validates and optionally applies an exported manifest. Applying an
// import creates new config-set/version rows in the target environment history
// rather than rewriting source IDs or mutating historical versions.
func (svc *AdminConfigService) Import(ctx context.Context, in AdminConfigImportInput, auditCtx AdminConfigAuditContext) (AdminConfigImportReport, error) {
	auditCtx, err := validateAdminConfigAuditContext(auditCtx)
	if err != nil {
		return AdminConfigImportReport{}, err
	}
	normalized, err := normalizeAdminConfigImportInput(in)
	if err != nil {
		return AdminConfigImportReport{}, err
	}

	report, err := svc.planAdminConfigImport(ctx, normalized)
	if err != nil {
		return AdminConfigImportReport{}, err
	}
	if !report.Valid {
		return report, nil
	}
	if normalized.DryRun {
		return report, nil
	}

	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		for _, manifestSet := range normalized.Manifest.ConfigSets {
			targetSet, err := svc.repo.getSetByDomainSlug(ctx, tx, manifestSet.Domain, manifestSet.Slug)
			if err != nil {
				if yerr := apierrCode(err); yerr != "" && yerr != "E_NOT_FOUND" {
					return err
				}
				targetSet, err = svc.repo.CreateSet(ctx, tx, CreateAdminConfigSetInput{
					Slug:        manifestSet.Slug,
					Domain:      manifestSet.Domain,
					Name:        manifestSet.Name,
					Description: manifestSet.Description,
				})
				if err != nil {
					return err
				}
			}
			targetVersionByManifestVersion := map[int]string{}
			for _, manifestVersion := range manifestSet.Versions {
				rollbackTargetID := ""
				if manifestVersion.RollbackOfVersion > 0 {
					rollbackTargetID = targetVersionByManifestVersion[manifestVersion.RollbackOfVersion]
				}
				imported, err := svc.repo.importVersion(ctx, tx, targetSet.ID, manifestVersion, rollbackTargetID, auditCtx.ActorID)
				if err != nil {
					return err
				}
				targetVersionByManifestVersion[manifestVersion.Version] = imported.ID
			}
		}
		meta := map[string]string{
			"operation":          "import",
			"source_environment": normalized.Manifest.SourceEnvironment,
			"target_environment": normalized.TargetEnvironment,
			"reason":             output.NewRedactor().Redact(auditCtx.Reason),
			"changes":            mustAuditJSON(report.Changes),
		}
		_, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, "admin.config.import", normalized.TargetEnvironment, meta))
		return err
	})
	if err != nil {
		return AdminConfigImportReport{}, err
	}
	report.Applied = true
	return report, nil
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
			ActorKind:      auditEventActorKind(auditCtx.ActorKind),
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

func (svc *AdminConfigService) planAdminConfigImport(ctx context.Context, in AdminConfigImportInput) (AdminConfigImportReport, error) {
	report := AdminConfigImportReport{
		Valid:             true,
		Applied:           false,
		TargetEnvironment: in.TargetEnvironment,
		SourceEnvironment: in.Manifest.SourceEnvironment,
		Changes:           []AdminConfigImportChange{},
		MissingSecretRefs: []string{},
		BlockingErrors:    []AdminConfigImportIssue{},
	}
	requiredRefs := adminConfigManifestSecretRefs(in.Manifest)
	available := map[string]struct{}{}
	for _, ref := range in.AvailableSecretRefs {
		available[ref] = struct{}{}
	}
	for _, ref := range requiredRefs {
		if _, ok := available[ref]; !ok {
			report.MissingSecretRefs = append(report.MissingSecretRefs, ref)
			report.BlockingErrors = append(report.BlockingErrors, AdminConfigImportIssue{
				Code:    "missing_secret_ref",
				Field:   "available_secret_refs",
				Message: "required secret reference is not available in target environment",
			})
		}
	}

	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		for _, manifestSet := range in.Manifest.ConfigSets {
			importMax := maxManifestVersion(manifestSet.Versions)
			targetSet, err := svc.repo.getSetByDomainSlug(ctx, q, manifestSet.Domain, manifestSet.Slug)
			if err != nil {
				if code := apierrCode(err); code == "E_NOT_FOUND" {
					report.Changes = append(report.Changes, AdminConfigImportChange{Operation: "create_set", Slug: manifestSet.Slug, Domain: manifestSet.Domain, ToVersion: importMax})
					continue
				}
				return err
			}
			versions, err := svc.repo.listVersionsForSet(ctx, q, targetSet.ID)
			if err != nil {
				return err
			}
			targetMax := maxAdminConfigVersion(versions)
			if targetMax > importMax && !in.AllowDowngrade {
				report.BlockingErrors = append(report.BlockingErrors, AdminConfigImportIssue{
					Code:    "unsafe_downgrade",
					Field:   "manifest.config_sets",
					Message: "target environment already has a newer config version",
				})
				report.Changes = append(report.Changes, AdminConfigImportChange{Operation: "blocked_downgrade", Slug: manifestSet.Slug, Domain: manifestSet.Domain, FromVersion: targetMax, ToVersion: importMax})
				continue
			}
			report.Changes = append(report.Changes, AdminConfigImportChange{Operation: "append_versions", Slug: manifestSet.Slug, Domain: manifestSet.Domain, FromVersion: targetMax, ToVersion: importMax})
		}
		return nil
	})
	if err != nil {
		return AdminConfigImportReport{}, err
	}
	if len(report.BlockingErrors) > 0 {
		report.Valid = false
	}
	if !report.Valid && !in.DryRun {
		for _, issue := range report.BlockingErrors {
			if issue.Code == "unsafe_downgrade" {
				return AdminConfigImportReport{}, apierr.Conflict(issue.Message)
			}
		}
	}
	return report, nil
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
		ActorKind:      auditEventActorKind(auditCtx.ActorKind),
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

func (svc *AdminConfigService) auditAdminConfigPromotion(ctx context.Context, auditCtx AdminConfigAuditContext, action, operation, sourceEnvironment, targetEnvironment string, setCount int, changes []AdminConfigImportChange) error {
	return svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		meta := map[string]string{
			"operation":          operation,
			"source_environment": sourceEnvironment,
			"target_environment": targetEnvironment,
			"reason":             output.NewRedactor().Redact(auditCtx.Reason),
			"config_set_count":   fmt.Sprintf("%d", setCount),
		}
		if changes != nil {
			meta["changes"] = mustAuditJSON(changes)
		}
		resourceID := sourceEnvironment
		if targetEnvironment != "" {
			resourceID = targetEnvironment
		}
		_, err := svc.audit.Append(ctx, tx, adminConfigAuditEvent(auditCtx, action, resourceID, meta))
		return err
	})
}

func normalizeAdminConfigImportInput(in AdminConfigImportInput) (AdminConfigImportInput, error) {
	out := AdminConfigImportInput{
		TargetEnvironment:   cleanConfigPromotionEnvironment(in.TargetEnvironment),
		Manifest:            in.Manifest,
		DryRun:              in.DryRun,
		AvailableSecretRefs: cleanStringSet(in.AvailableSecretRefs),
		AllowDowngrade:      in.AllowDowngrade,
	}
	var violations []apierr.FieldViolation
	if out.TargetEnvironment == "" {
		violations = append(violations, apierr.FieldViolation{Field: "target_environment", Reason: "must not be blank"})
	}
	if out.Manifest.SchemaVersion != AdminConfigExportSchemaVersion {
		violations = append(violations, apierr.FieldViolation{Field: "manifest.schema_version", Reason: "must be " + AdminConfigExportSchemaVersion})
	}
	out.Manifest.SourceEnvironment = cleanConfigPromotionEnvironment(out.Manifest.SourceEnvironment)
	if out.Manifest.SourceEnvironment == "" {
		violations = append(violations, apierr.FieldViolation{Field: "manifest.source_environment", Reason: "must not be blank"})
	}
	if out.Manifest.ConfigSets == nil {
		out.Manifest.ConfigSets = []AdminConfigExportSet{}
	}
	for i, set := range out.Manifest.ConfigSets {
		field := fmt.Sprintf("manifest.config_sets[%d]", i)
		slug, ok := cleanAdminConfigSlug(set.Slug)
		if !ok {
			violations = append(violations, apierr.FieldViolation{Field: field + ".slug", Reason: "must be a canonical config slug"})
		}
		out.Manifest.ConfigSets[i].Slug = slug
		if !set.Domain.valid() {
			violations = append(violations, apierr.FieldViolation{Field: field + ".domain", Reason: "must be pricing, metering, billing, quota, or features"})
		}
		if strings.TrimSpace(set.Name) == "" {
			violations = append(violations, apierr.FieldViolation{Field: field + ".name", Reason: "must not be blank"})
		}
		out.Manifest.ConfigSets[i].Name = strings.TrimSpace(set.Name)
		out.Manifest.ConfigSets[i].Description = strings.TrimSpace(set.Description)
		if len(set.Versions) == 0 {
			violations = append(violations, apierr.FieldViolation{Field: field + ".versions", Reason: "must contain at least one version"})
		}
		versionNumbers := map[int]struct{}{}
		for _, version := range set.Versions {
			if version.Version > 0 {
				versionNumbers[version.Version] = struct{}{}
			}
		}
		for j, version := range set.Versions {
			versionField := fmt.Sprintf("%s.versions[%d]", field, j)
			if version.Version <= 0 {
				violations = append(violations, apierr.FieldViolation{Field: versionField + ".version", Reason: "must be positive"})
			}
			if version.RollbackOfVersion < 0 {
				violations = append(violations, apierr.FieldViolation{Field: versionField + ".rollback_of_version", Reason: "must be positive"})
			}
			if version.RollbackOfVersion > 0 {
				if _, ok := versionNumbers[version.RollbackOfVersion]; !ok {
					violations = append(violations, apierr.FieldViolation{Field: versionField + ".rollback_of_version", Reason: "must reference a version in the same config set"})
				}
			}
			switch version.Status {
			case AdminConfigStatusDraft, AdminConfigStatusPublished, AdminConfigStatusArchived:
			default:
				violations = append(violations, apierr.FieldViolation{Field: versionField + ".status", Reason: "must be draft, published, or archived"})
			}
			payload, err := normalizeConfigPayload(version.Payload)
			if err != nil {
				violations = append(violations, apierr.FieldViolation{Field: versionField + ".payload", Reason: "must be valid JSON"})
			} else {
				out.Manifest.ConfigSets[i].Versions[j].Payload = payload
			}
			if version.Status != AdminConfigStatusDraft && version.EffectiveAt == nil {
				violations = append(violations, apierr.FieldViolation{Field: versionField + ".effective_at", Reason: "must be set for published or archived versions"})
			}
		}
	}
	if len(violations) > 0 {
		return AdminConfigImportInput{}, apierr.InvalidInput(violations...)
	}
	sortAdminConfigManifest(out.Manifest)
	return out, nil
}

func cleanConfigPromotionEnvironment(raw string) string {
	env := strings.TrimSpace(strings.ToLower(raw))
	if env == "" || len(env) > 64 {
		return ""
	}
	for _, r := range env {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return ""
	}
	return env
}

func cleanStringSet(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		cleaned := strings.TrimSpace(value)
		if cleaned == "" {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		out = append(out, cleaned)
	}
	sort.Strings(out)
	return out
}

func sanitizeAdminConfigExportPayload(raw []byte) (json.RawMessage, error) {
	normalized, err := normalizeConfigPayload(raw)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(normalized, &decoded); err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	redacted := redactAdminConfigExportValue("", decoded)
	out, err := json.Marshal(redacted)
	if err != nil {
		return nil, apierr.Internal(err)
	}
	return json.RawMessage(out), nil
}

func redactAdminConfigExportValue(path string, v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			childPath := joinAuditPath(path, key)
			if isSecretReferenceKey(key) {
				out[key] = value
				continue
			}
			if isSecretAuditKey(key) {
				out[key] = output.Sentinel
				continue
			}
			out[key] = redactAdminConfigExportValue(childPath, value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, value := range typed {
			out[i] = redactAdminConfigExportValue(fmt.Sprintf("%s[%d]", path, i), value)
		}
		return out
	case string:
		if isSecretAuditKey(path) && !isSecretReferenceKey(path) {
			return output.Sentinel
		}
		return typed
	default:
		return typed
	}
}

func isSecretReferenceKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "credential_ref", "credential_refs", "secret_ref", "secret_refs", "auth_reference":
		return true
	default:
		return false
	}
}

func adminConfigManifestSecretRefs(manifest AdminConfigExportManifest) []string {
	seen := map[string]struct{}{}
	for _, set := range manifest.ConfigSets {
		for _, version := range set.Versions {
			var decoded any
			if err := json.Unmarshal(version.Payload, &decoded); err != nil {
				continue
			}
			collectAdminConfigSecretRefs(decoded, seen)
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func collectAdminConfigSecretRefs(v any, seen map[string]struct{}) {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "credential_ref", "secret_ref", "auth_reference":
				if ref, ok := value.(string); ok && strings.TrimSpace(ref) != "" {
					seen[strings.TrimSpace(ref)] = struct{}{}
				}
			case "credential_refs", "secret_refs":
				if refs, ok := value.([]any); ok {
					for _, item := range refs {
						if ref, ok := item.(string); ok && strings.TrimSpace(ref) != "" {
							seen[strings.TrimSpace(ref)] = struct{}{}
						}
					}
				}
			}
			collectAdminConfigSecretRefs(value, seen)
		}
	case []any:
		for _, item := range typed {
			collectAdminConfigSecretRefs(item, seen)
		}
	}
}

func maxManifestVersion(versions []AdminConfigExportVersion) int {
	max := 0
	for _, version := range versions {
		if version.Version > max {
			max = version.Version
		}
	}
	return max
}

func maxAdminConfigVersion(versions []AdminConfigVersion) int {
	max := 0
	for _, version := range versions {
		if version.Version > max {
			max = version.Version
		}
	}
	return max
}

func sortAdminConfigManifest(manifest AdminConfigExportManifest) {
	sort.Slice(manifest.ConfigSets, func(i, j int) bool {
		if manifest.ConfigSets[i].Domain != manifest.ConfigSets[j].Domain {
			return manifest.ConfigSets[i].Domain < manifest.ConfigSets[j].Domain
		}
		return manifest.ConfigSets[i].Slug < manifest.ConfigSets[j].Slug
	})
	for i := range manifest.ConfigSets {
		sort.Slice(manifest.ConfigSets[i].Versions, func(a, b int) bool {
			return manifest.ConfigSets[i].Versions[a].Version < manifest.ConfigSets[i].Versions[b].Version
		})
	}
}

func apierrCode(err error) yerr.Code {
	if err == nil {
		return ""
	}
	return yerr.From(err).Code
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
