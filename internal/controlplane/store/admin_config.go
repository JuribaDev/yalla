package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/jackc/pgx/v5"
)

// AdminConfigDomain groups a backoffice-owned runtime configuration surface.
type AdminConfigDomain string

const (
	// AdminConfigDomainPricing groups pricing plan and entitlement configuration.
	AdminConfigDomainPricing AdminConfigDomain = "pricing"
	// AdminConfigDomainMetering groups metric sources, definitions, and attribution configuration.
	AdminConfigDomainMetering AdminConfigDomain = "metering"
	// AdminConfigDomainBilling groups billing provider and export configuration.
	AdminConfigDomainBilling AdminConfigDomain = "billing"
	// AdminConfigDomainQuota groups quota and enforcement configuration.
	AdminConfigDomainQuota AdminConfigDomain = "quota"
	// AdminConfigDomainFeatures groups feature flag configuration.
	AdminConfigDomainFeatures AdminConfigDomain = "features"
)

func (d AdminConfigDomain) valid() bool {
	switch d {
	case AdminConfigDomainPricing, AdminConfigDomainMetering, AdminConfigDomainBilling, AdminConfigDomainQuota, AdminConfigDomainFeatures:
		return true
	default:
		return false
	}
}

// AdminConfigStatus is the lifecycle state for one config version.
type AdminConfigStatus string

const (
	// AdminConfigStatusDraft is editable and never used by runtime services.
	AdminConfigStatusDraft AdminConfigStatus = "draft"
	// AdminConfigStatusPublished is immutable runtime configuration once effective.
	AdminConfigStatusPublished AdminConfigStatus = "published"
	// AdminConfigStatusArchived is retained for audit and rollback history.
	AdminConfigStatusArchived AdminConfigStatus = "archived"
)

// AdminConfigSet is a named family of related runtime configuration versions.
type AdminConfigSet struct {
	ID          string
	Slug        string
	Domain      AdminConfigDomain
	Name        string
	Description string
	Revision    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AdminConfigVersion is one draft, published, or archived runtime configuration payload.
type AdminConfigVersion struct {
	ID                  string
	ConfigSetID         string
	Version             int
	Status              AdminConfigStatus
	Payload             []byte
	EffectiveAt         *time.Time
	PublishedAt         *time.Time
	PublishedBy         *string
	RollbackOfVersionID *string
	RollbackReason      string
	ArchivedAt          *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// AdminRuntimeConfigVersion pairs one active published config version with the
// owning set metadata runtime caches need for invalidation and routing.
type AdminRuntimeConfigVersion struct {
	Version  AdminConfigVersion
	Domain   AdminConfigDomain
	Revision int64
}

// CreateAdminConfigSetInput describes a new backoffice configuration family.
type CreateAdminConfigSetInput struct {
	Slug        string
	Domain      AdminConfigDomain
	Name        string
	Description string
}

// CreateAdminConfigDraftInput describes the next editable version for a set.
type CreateAdminConfigDraftInput struct {
	ConfigSetID string
	Payload     []byte
}

// PublishAdminConfigVersionInput stamps a draft as a runtime candidate.
type PublishAdminConfigVersionInput struct {
	EffectiveAt time.Time
	PublishedBy string
}

// RollbackAdminConfigInput creates a published version from an older version.
type RollbackAdminConfigInput struct {
	EffectiveAt     time.Time
	PublishedBy     string
	RollbackVersion string
	RollbackReason  string
}

// AdminConfigRepository is the persistence surface for backoffice runtime config versioning.
type AdminConfigRepository struct{}

// NewAdminConfigRepository returns a stateless admin config repository.
func NewAdminConfigRepository() *AdminConfigRepository { return &AdminConfigRepository{} }

const adminConfigSetColumns = `id, slug, domain, name, description, revision, created_at, updated_at`

const adminConfigVersionColumns = `id, config_set_id, version, status, payload, effective_at, published_at, published_by, rollback_of_version_id, rollback_reason, archived_at, created_at, updated_at`

// CreateSet creates a named family of related backoffice configuration versions.
func (r *AdminConfigRepository) CreateSet(ctx context.Context, tx *Tx, in CreateAdminConfigSetInput) (AdminConfigSet, error) {
	if tx == nil {
		return AdminConfigSet{}, apierr.Internal(errors.New("store: AdminConfigRepository.CreateSet called with a nil transaction"))
	}
	set, err := buildAdminConfigSet(in)
	if err != nil {
		return AdminConfigSet{}, err
	}
	id, err := newOpaqueStoreID("cfg")
	if err != nil {
		return AdminConfigSet{}, apierr.Internal(err)
	}
	set.ID = id
	err = tx.QueryRow(ctx,
		`INSERT INTO admin_config_sets (id, slug, domain, name, description)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+adminConfigSetColumns,
		set.ID, set.Slug, set.Domain, set.Name, set.Description,
	).Scan(&set.ID, &set.Slug, &set.Domain, &set.Name, &set.Description, &set.Revision, &set.CreatedAt, &set.UpdatedAt)
	if err != nil {
		return AdminConfigSet{}, mapWriteError(err, "create admin config set")
	}
	return set, nil
}

// CreateDraft creates the next editable version for a config set.
func (r *AdminConfigRepository) CreateDraft(ctx context.Context, tx *Tx, in CreateAdminConfigDraftInput) (AdminConfigVersion, error) {
	if tx == nil {
		return AdminConfigVersion{}, apierr.Internal(errors.New("store: AdminConfigRepository.CreateDraft called with a nil transaction"))
	}
	configSetID := strings.TrimSpace(in.ConfigSetID)
	payload, err := normalizeConfigPayload(in.Payload)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	if _, err := r.lockSet(ctx, tx, configSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	nextVersion, err := r.nextVersion(ctx, tx, configSetID)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	id, err := newOpaqueStoreID("cfgver")
	if err != nil {
		return AdminConfigVersion{}, apierr.Internal(err)
	}
	var version AdminConfigVersion
	err = tx.QueryRow(ctx,
		`INSERT INTO admin_config_versions (id, config_set_id, version, status, payload)
		 VALUES ($1, $2, $3, 'draft', $4)
		 RETURNING `+adminConfigVersionColumns,
		id, configSetID, nextVersion, payload,
	).Scan(adminConfigVersionScanDest(&version)...)
	if err != nil {
		return AdminConfigVersion{}, mapWriteError(err, "create admin config draft")
	}
	if err := r.bumpRevision(ctx, tx, configSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	return version, nil
}

// Publish converts a draft version into a published runtime candidate.
func (r *AdminConfigRepository) Publish(ctx context.Context, tx *Tx, id string, in PublishAdminConfigVersionInput) (AdminConfigVersion, error) {
	if tx == nil {
		return AdminConfigVersion{}, apierr.Internal(errors.New("store: AdminConfigRepository.Publish called with a nil transaction"))
	}
	input, err := validatePublishAdminConfigInput(in)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	current, err := r.lockVersion(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return AdminConfigVersion{}, err
	}
	if current.Status != AdminConfigStatusDraft {
		return AdminConfigVersion{}, apierr.Conflict("only draft config versions can be published")
	}

	var published AdminConfigVersion
	err = tx.QueryRow(ctx,
		`UPDATE admin_config_versions
		    SET status = 'published',
		        effective_at = $2,
		        published_at = now(),
		        published_by = $3
		  WHERE id = $1
		  RETURNING `+adminConfigVersionColumns,
		current.ID, input.EffectiveAt, input.PublishedBy,
	).Scan(adminConfigVersionScanDest(&published)...)
	if err != nil {
		return AdminConfigVersion{}, mapWriteError(err, "publish admin config version")
	}
	if err := r.bumpRevision(ctx, tx, published.ConfigSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	return published, nil
}

// Rollback creates a new published version by copying an earlier version payload.
func (r *AdminConfigRepository) Rollback(ctx context.Context, tx *Tx, configSetID, sourceVersionID string, in RollbackAdminConfigInput) (AdminConfigVersion, error) {
	if tx == nil {
		return AdminConfigVersion{}, apierr.Internal(errors.New("store: AdminConfigRepository.Rollback called with a nil transaction"))
	}
	input, err := validateRollbackAdminConfigInput(in)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	configSetID = strings.TrimSpace(configSetID)
	if _, err := r.lockSet(ctx, tx, configSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	source, err := r.getVersionInSet(ctx, tx, configSetID, strings.TrimSpace(sourceVersionID))
	if err != nil {
		return AdminConfigVersion{}, err
	}
	if input.RollbackVersion != "" {
		if _, err := r.getVersionInSet(ctx, tx, configSetID, input.RollbackVersion); err != nil {
			return AdminConfigVersion{}, err
		}
	}
	nextVersion, err := r.nextVersion(ctx, tx, configSetID)
	if err != nil {
		return AdminConfigVersion{}, err
	}
	id, err := newOpaqueStoreID("cfgver")
	if err != nil {
		return AdminConfigVersion{}, apierr.Internal(err)
	}
	var rollback AdminConfigVersion
	err = tx.QueryRow(ctx,
		`INSERT INTO admin_config_versions
		    (id, config_set_id, version, status, payload, effective_at, published_at, published_by, rollback_of_version_id, rollback_reason)
		 VALUES ($1, $2, $3, 'published', $4, $5, now(), $6, NULLIF($7, ''), $8)
		 RETURNING `+adminConfigVersionColumns,
		id, configSetID, nextVersion, source.Payload, input.EffectiveAt, input.PublishedBy, input.RollbackVersion, input.RollbackReason,
	).Scan(adminConfigVersionScanDest(&rollback)...)
	if err != nil {
		return AdminConfigVersion{}, mapWriteError(err, "rollback admin config version")
	}
	if err := r.bumpRevision(ctx, tx, configSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	return rollback, nil
}

// Archive marks a version as archived while preserving it for audit reads.
func (r *AdminConfigRepository) Archive(ctx context.Context, tx *Tx, id string) (AdminConfigVersion, error) {
	if tx == nil {
		return AdminConfigVersion{}, apierr.Internal(errors.New("store: AdminConfigRepository.Archive called with a nil transaction"))
	}
	current, err := r.lockVersion(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return AdminConfigVersion{}, err
	}
	if current.Status == AdminConfigStatusArchived {
		return current, nil
	}
	var archived AdminConfigVersion
	err = tx.QueryRow(ctx,
		`UPDATE admin_config_versions
		    SET status = 'archived',
		        archived_at = now()
		  WHERE id = $1
		  RETURNING `+adminConfigVersionColumns,
		current.ID,
	).Scan(adminConfigVersionScanDest(&archived)...)
	if err != nil {
		return AdminConfigVersion{}, mapWriteError(err, "archive admin config version")
	}
	if err := r.bumpRevision(ctx, tx, archived.ConfigSetID); err != nil {
		return AdminConfigVersion{}, err
	}
	return archived, nil
}

// Revision returns the monotonic invalidation token for one config set.
func (r *AdminConfigRepository) Revision(ctx context.Context, q Querier, configSetID string) (int64, error) {
	var revision int64
	err := q.QueryRow(ctx,
		`SELECT revision FROM admin_config_sets WHERE id = $1`,
		strings.TrimSpace(configSetID),
	).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, apierr.NotFound("admin_config_set", configSetID)
	}
	if err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return revision, nil
}

// ListActivePublished returns the active published version for each set at a point in time.
func (r *AdminConfigRepository) ListActivePublished(ctx context.Context, q Querier, at time.Time) ([]AdminConfigVersion, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	rows, err := q.Query(ctx,
		`SELECT DISTINCT ON (config_set_id) `+adminConfigVersionColumns+`
		   FROM admin_config_versions
		  WHERE status = 'published'
		    AND effective_at <= $1
		  ORDER BY config_set_id, effective_at DESC, version DESC, id DESC`,
		at,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	out := make([]AdminConfigVersion, 0)
	for rows.Next() {
		var version AdminConfigVersion
		if err := rows.Scan(adminConfigVersionScanDest(&version)...); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		out = append(out, version)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListActivePublishedRuntime returns active published versions with their set
// domain and revision tokens for runtime config cache reloads.
func (r *AdminConfigRepository) ListActivePublishedRuntime(ctx context.Context, q Querier, at time.Time) ([]AdminRuntimeConfigVersion, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	rows, err := q.Query(ctx,
		`SELECT DISTINCT ON (v.config_set_id)
		        v.id, v.config_set_id, v.version, v.status, v.payload, v.effective_at,
		        v.published_at, v.published_by, v.rollback_of_version_id,
		        v.rollback_reason, v.archived_at, v.created_at, v.updated_at,
		        s.domain, s.revision
		   FROM admin_config_versions v
		   JOIN admin_config_sets s ON s.id = v.config_set_id
		  WHERE v.status = 'published'
		    AND v.effective_at <= $1
		  ORDER BY v.config_set_id, v.effective_at DESC, v.version DESC, v.id DESC`,
		at,
	)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	out := make([]AdminRuntimeConfigVersion, 0)
	for rows.Next() {
		var item AdminRuntimeConfigVersion
		if err := rows.Scan(append(adminConfigVersionScanDest(&item.Version), &item.Domain, &item.Revision)...); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func (r *AdminConfigRepository) lockSet(ctx context.Context, tx *Tx, id string) (AdminConfigSet, error) {
	var set AdminConfigSet
	err := tx.QueryRow(ctx,
		`SELECT `+adminConfigSetColumns+` FROM admin_config_sets WHERE id = $1 FOR UPDATE`,
		id,
	).Scan(&set.ID, &set.Slug, &set.Domain, &set.Name, &set.Description, &set.Revision, &set.CreatedAt, &set.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminConfigSet{}, apierr.NotFound("admin_config_set", id)
	}
	if err != nil {
		return AdminConfigSet{}, apierr.StoreUnavailable(err)
	}
	return set, nil
}

func (r *AdminConfigRepository) lockVersion(ctx context.Context, tx *Tx, id string) (AdminConfigVersion, error) {
	var version AdminConfigVersion
	err := tx.QueryRow(ctx,
		`SELECT `+adminConfigVersionColumns+` FROM admin_config_versions WHERE id = $1 FOR UPDATE`,
		id,
	).Scan(adminConfigVersionScanDest(&version)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminConfigVersion{}, apierr.NotFound("admin_config_version", id)
	}
	if err != nil {
		return AdminConfigVersion{}, apierr.StoreUnavailable(err)
	}
	return version, nil
}

func (r *AdminConfigRepository) getVersionInSet(ctx context.Context, q Querier, configSetID, id string) (AdminConfigVersion, error) {
	var version AdminConfigVersion
	err := q.QueryRow(ctx,
		`SELECT `+adminConfigVersionColumns+`
		   FROM admin_config_versions
		  WHERE config_set_id = $1 AND id = $2`,
		configSetID, id,
	).Scan(adminConfigVersionScanDest(&version)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminConfigVersion{}, apierr.NotFound("admin_config_version", id)
	}
	if err != nil {
		return AdminConfigVersion{}, apierr.StoreUnavailable(err)
	}
	return version, nil
}

func (r *AdminConfigRepository) nextVersion(ctx context.Context, q Querier, configSetID string) (int, error) {
	var next int
	err := q.QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) + 1
		   FROM admin_config_versions
		  WHERE config_set_id = $1`,
		configSetID,
	).Scan(&next)
	if err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return next, nil
}

func (r *AdminConfigRepository) bumpRevision(ctx context.Context, tx *Tx, configSetID string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE admin_config_sets
		    SET revision = revision + 1
		  WHERE id = $1`,
		configSetID,
	)
	if err != nil {
		return mapWriteError(err, "bump admin config revision")
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("admin_config_set", configSetID)
	}
	return nil
}

func adminConfigVersionScanDest(version *AdminConfigVersion) []any {
	return []any{
		&version.ID,
		&version.ConfigSetID,
		&version.Version,
		&version.Status,
		&version.Payload,
		&version.EffectiveAt,
		&version.PublishedAt,
		&version.PublishedBy,
		&version.RollbackOfVersionID,
		&version.RollbackReason,
		&version.ArchivedAt,
		&version.CreatedAt,
		&version.UpdatedAt,
	}
}

func buildAdminConfigSet(in CreateAdminConfigSetInput) (AdminConfigSet, error) {
	var violations []apierr.FieldViolation
	slug, ok := cleanAdminConfigSlug(in.Slug)
	if !ok {
		violations = append(violations, apierr.FieldViolation{Field: "slug", Reason: "must be a canonical config slug"})
	}
	if !in.Domain.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "domain", Reason: "must be pricing, metering, billing, quota, or features"})
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must not be blank"})
	} else if !utf8.ValidString(name) {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be valid UTF-8"})
	} else if len(name) > 120 {
		violations = append(violations, apierr.FieldViolation{Field: "name", Reason: "must be at most 120 bytes"})
	}
	description := strings.TrimSpace(in.Description)
	if !utf8.ValidString(description) {
		violations = append(violations, apierr.FieldViolation{Field: "description", Reason: "must be valid UTF-8"})
	} else if len(description) > 1000 {
		violations = append(violations, apierr.FieldViolation{Field: "description", Reason: "must be at most 1000 bytes"})
	}
	if len(violations) > 0 {
		return AdminConfigSet{}, apierr.InvalidInput(violations...)
	}
	return AdminConfigSet{Slug: slug, Domain: in.Domain, Name: name, Description: description}, nil
}

func validatePublishAdminConfigInput(in PublishAdminConfigVersionInput) (PublishAdminConfigVersionInput, error) {
	var violations []apierr.FieldViolation
	if in.EffectiveAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "effective_at", Reason: "must not be zero"})
	}
	publishedBy := strings.TrimSpace(in.PublishedBy)
	if publishedBy == "" {
		violations = append(violations, apierr.FieldViolation{Field: "published_by", Reason: "must not be blank"})
	} else if !utf8.ValidString(publishedBy) {
		violations = append(violations, apierr.FieldViolation{Field: "published_by", Reason: "must be valid UTF-8"})
	} else if len(publishedBy) > 160 {
		violations = append(violations, apierr.FieldViolation{Field: "published_by", Reason: "must be at most 160 bytes"})
	}
	if len(violations) > 0 {
		return PublishAdminConfigVersionInput{}, apierr.InvalidInput(violations...)
	}
	return PublishAdminConfigVersionInput{EffectiveAt: in.EffectiveAt.UTC(), PublishedBy: publishedBy}, nil
}

func validateRollbackAdminConfigInput(in RollbackAdminConfigInput) (RollbackAdminConfigInput, error) {
	publish, err := validatePublishAdminConfigInput(PublishAdminConfigVersionInput{EffectiveAt: in.EffectiveAt, PublishedBy: in.PublishedBy})
	if err != nil {
		return RollbackAdminConfigInput{}, err
	}
	rollbackVersion := strings.TrimSpace(in.RollbackVersion)
	reason := strings.TrimSpace(in.RollbackReason)
	var violations []apierr.FieldViolation
	if !utf8.ValidString(reason) {
		violations = append(violations, apierr.FieldViolation{Field: "rollback_reason", Reason: "must be valid UTF-8"})
	} else if len(reason) > 1000 {
		violations = append(violations, apierr.FieldViolation{Field: "rollback_reason", Reason: "must be at most 1000 bytes"})
	}
	if len(violations) > 0 {
		return RollbackAdminConfigInput{}, apierr.InvalidInput(violations...)
	}
	return RollbackAdminConfigInput{
		EffectiveAt:     publish.EffectiveAt,
		PublishedBy:     publish.PublishedBy,
		RollbackVersion: rollbackVersion,
		RollbackReason:  reason,
	}, nil
}

func normalizeConfigPayload(raw []byte) ([]byte, error) {
	payload := raw
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	if !json.Valid(payload) {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, payload); err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	return compacted.Bytes(), nil
}

func cleanAdminConfigSlug(raw string) (string, bool) {
	slug := strings.TrimSpace(strings.ToLower(raw))
	if slug == "" || len(slug) > 63 {
		return "", false
	}
	normalized, err := domain.NormalizeSlug(slug)
	if err != nil || normalized.String() != slug {
		return "", false
	}
	return slug, true
}
