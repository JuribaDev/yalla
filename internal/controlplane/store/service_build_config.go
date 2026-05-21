package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

const (
	// BuildTypeStatic describes a static-site/application build.
	BuildTypeStatic = "static"
	// BuildTypeDockerfile describes a Git repository built from a Dockerfile.
	BuildTypeDockerfile = "dockerfile"
	// BuildTypeCompose describes a Docker Compose source bundle.
	BuildTypeCompose = "compose"
	// BuildTypeImage describes a prebuilt container image runtime.
	BuildTypeImage = "image"
)

// ServiceBuildConfig is the tenant-scoped desired build/runtime configuration
// attached to one service.
type ServiceBuildConfig struct {
	OrganizationID string
	ServiceID      string
	BuildType      string
	SourceType     string
	SourceJSON     json.RawMessage
	ConfigJSON     json.RawMessage
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ServiceBuildConfigInput is the validated write shape for service build
// desired state.
type ServiceBuildConfigInput struct {
	BuildType  string          `json:"build_type"`
	SourceType string          `json:"source_type"`
	SourceJSON json.RawMessage `json:"source"`
	ConfigJSON json.RawMessage `json:"config"`
}

// UpdateServiceBuildConfigInput names a build-config replacement with optional
// optimistic concurrency.
type UpdateServiceBuildConfigInput struct {
	OrganizationID string
	ServiceID      string
	BuildConfig    ServiceBuildConfigInput
	IfMatchVersion *int64
}

// ServiceBuildConfigRepository persists service build desired state.
type ServiceBuildConfigRepository struct{}

// NewServiceBuildConfigRepository constructs a repository for service build
// desired state.
func NewServiceBuildConfigRepository() *ServiceBuildConfigRepository {
	return &ServiceBuildConfigRepository{}
}

const serviceBuildConfigColumns = `organization_id, service_id, build_type, source_type, source_json, config_json, version, created_at, updated_at`

// Get returns one service build config for the given tenant and service.
func (r *ServiceBuildConfigRepository) Get(ctx context.Context, q Querier, organizationID, serviceID string) (ServiceBuildConfig, error) {
	row := q.QueryRow(ctx, `SELECT `+serviceBuildConfigColumns+`
	  FROM service_build_configs
	 WHERE organization_id = $1 AND service_id = $2`, strings.TrimSpace(organizationID), strings.TrimSpace(serviceID))
	cfg, err := scanServiceBuildConfig(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceBuildConfig{}, apierr.NotFound("service_build_config", serviceID)
		}
		return ServiceBuildConfig{}, apierr.StoreUnavailable(err)
	}
	return cfg, nil
}

// Upsert inserts or replaces one service build config, enforcing validation and
// optional If-Match version checks.
func (r *ServiceBuildConfigRepository) Upsert(ctx context.Context, tx *Tx, organizationID, serviceID string, in ServiceBuildConfigInput, ifMatch *int64) (ServiceBuildConfig, error) {
	if tx == nil {
		return ServiceBuildConfig{}, apierr.Internal(errors.New("store: ServiceBuildConfigRepository.Upsert called with nil tx"))
	}
	cfg, err := validateServiceBuildConfigInput(organizationID, serviceID, in)
	if err != nil {
		return ServiceBuildConfig{}, err
	}
	if ifMatch != nil {
		current, err := r.Get(ctx, tx, cfg.OrganizationID, cfg.ServiceID)
		if err != nil {
			return ServiceBuildConfig{}, err
		}
		if current.Version != *ifMatch {
			return ServiceBuildConfig{}, apierr.ConflictStale(current.Version)
		}
	}
	row := tx.QueryRow(ctx, `INSERT INTO service_build_configs
	  (organization_id, service_id, build_type, source_type, source_json, config_json)
	  VALUES ($1, $2, $3, $4, $5, $6)
	  ON CONFLICT (organization_id, service_id)
	  DO UPDATE SET build_type = EXCLUDED.build_type,
	                source_type = EXCLUDED.source_type,
	                source_json = EXCLUDED.source_json,
	                config_json = EXCLUDED.config_json
	  RETURNING `+serviceBuildConfigColumns,
		cfg.OrganizationID, cfg.ServiceID, cfg.BuildType, cfg.SourceType, cfg.SourceJSON, cfg.ConfigJSON)
	out, err := scanServiceBuildConfig(row)
	if err != nil {
		return ServiceBuildConfig{}, mapWriteError(err, "the service build config could not be saved")
	}
	return out, nil
}

type serviceBuildConfigScanner interface {
	Scan(dest ...any) error
}

func scanServiceBuildConfig(row serviceBuildConfigScanner) (ServiceBuildConfig, error) {
	var cfg ServiceBuildConfig
	if err := row.Scan(&cfg.OrganizationID, &cfg.ServiceID, &cfg.BuildType, &cfg.SourceType, &cfg.SourceJSON, &cfg.ConfigJSON, &cfg.Version, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
		return ServiceBuildConfig{}, err
	}
	cfg.SourceJSON = append(json.RawMessage(nil), cfg.SourceJSON...)
	cfg.ConfigJSON = append(json.RawMessage(nil), cfg.ConfigJSON...)
	return cfg, nil
}

func validateServiceBuildConfigInput(organizationID, serviceID string, in ServiceBuildConfigInput) (ServiceBuildConfig, error) {
	var violations []apierr.FieldViolation
	orgID := strings.TrimSpace(organizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must be a valid organization id"})
	}
	svcID := strings.TrimSpace(serviceID)
	if id, err := domain.ParseID(svcID); err != nil || id.Kind() != domain.KindService {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be a valid service id"})
	}
	buildType := strings.TrimSpace(in.BuildType)
	sourceType := strings.TrimSpace(in.SourceType)
	if sourceType == "" {
		sourceType = "manual"
	}
	source := normalizeRawObject(in.SourceJSON)
	config := normalizeRawObject(in.ConfigJSON)
	sourceObj := rawObject(source)
	configObj := rawObject(config)
	switch buildType {
	case BuildTypeStatic:
		if stringValue(sourceObj, "repo") == "" && stringValue(sourceObj, "artifact_ref") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "source.repo", Reason: "must be set for static builds unless artifact_ref is provided"})
		}
		if stringValue(configObj, "output_dir") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "config.output_dir", Reason: "must be set for static builds"})
		}
	case BuildTypeDockerfile:
		if stringValue(sourceObj, "repo") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "source.repo", Reason: "must be set for dockerfile builds"})
		}
		if stringValue(configObj, "context") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "config.context", Reason: "must be set for dockerfile builds"})
		}
		if stringValue(configObj, "dockerfile") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "config.dockerfile", Reason: "must be set for dockerfile builds"})
		}
	case BuildTypeCompose:
		if stringValue(sourceObj, "compose_file") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "source.compose_file", Reason: "must be set for compose builds"})
		}
	case BuildTypeImage:
		if stringValue(sourceObj, "image") == "" {
			violations = append(violations, apierr.FieldViolation{Field: "source.image", Reason: "must be set for image builds"})
		}
	default:
		violations = append(violations, apierr.FieldViolation{Field: "build_type", Reason: "must be static, dockerfile, compose, or image"})
	}
	if hasRawSecret(sourceObj) || hasRawSecret(configObj) {
		violations = append(violations, apierr.FieldViolation{Field: "config", Reason: "must reference secrets by *_ref fields only"})
	}
	if len(violations) > 0 {
		return ServiceBuildConfig{}, apierr.InvalidInput(violations...)
	}
	return ServiceBuildConfig{
		OrganizationID: orgID,
		ServiceID:      svcID,
		BuildType:      buildType,
		SourceType:     sourceType,
		SourceJSON:     source,
		ConfigJSON:     config,
	}, nil
}

func normalizeRawObject(raw json.RawMessage) json.RawMessage {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

func rawObject(raw json.RawMessage) map[string]any {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return map[string]any{}
	}
	return obj
}

func stringValue(obj map[string]any, key string) string {
	v, _ := obj[key].(string)
	return strings.TrimSpace(v)
}

func hasRawSecret(obj map[string]any) bool {
	for key, value := range obj {
		lower := strings.ToLower(key)
		if (strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token")) && !strings.HasSuffix(lower, "_ref") {
			if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
				return true
			}
		}
	}
	return false
}
