package store

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// MeteringSourceType identifies a configured metering dependency.
type MeteringSourceType string

const (
	// MeteringSourceTypeTraefik collects Traefik edge/load-balancer metrics.
	MeteringSourceTypeTraefik MeteringSourceType = "traefik"
	// MeteringSourceTypePrometheus collects Prometheus-compatible metrics.
	MeteringSourceTypePrometheus MeteringSourceType = "prometheus"
	// MeteringSourceTypeDokploy collects private Dokploy operational metrics.
	MeteringSourceTypeDokploy MeteringSourceType = "dokploy"
	// MeteringSourceTypeContainer collects container runtime metrics.
	MeteringSourceTypeContainer MeteringSourceType = "container"
	// MeteringSourceTypeStorage collects storage usage metrics.
	MeteringSourceTypeStorage MeteringSourceType = "storage"
	// MeteringSourceTypeBackup collects backup metadata metrics.
	MeteringSourceTypeBackup MeteringSourceType = "backup"
)

func (t MeteringSourceType) valid() bool {
	switch t {
	case MeteringSourceTypeTraefik, MeteringSourceTypePrometheus, MeteringSourceTypeDokploy, MeteringSourceTypeContainer, MeteringSourceTypeStorage, MeteringSourceTypeBackup:
		return true
	default:
		return false
	}
}

// MeteringSource is a global backoffice-owned metering dependency config.
// Credential bytes are write-only: wire projections expose only CredentialSet,
// while internal runtime readers may pass the sealed tuple to a secrets.Provider.
type MeteringSource struct {
	ID                    string
	SourceKey             string
	SourceType            MeteringSourceType
	EndpointURL           string
	AuthScheme            string
	AuthReference         string
	CredentialSet         bool
	SecretProvider        string
	SecretKeyID           string
	SecretCiphertext      []byte
	ScrapeIntervalSeconds int
	QueryIntervalSeconds  int
	TimeoutSeconds        int
	Labels                map[string]string
	Enabled               bool
	Revision              int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// LogValue redacts credential ciphertext and token-bearing endpoint values.
func (s MeteringSource) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", s.ID),
		slog.String("source_key", s.SourceKey),
		slog.String("source_type", string(s.SourceType)),
		slog.String("endpoint_url", output.NewRedactor().Redact(s.EndpointURL)),
		slog.String("auth_scheme", s.AuthScheme),
		slog.String("auth_reference", s.AuthReference),
		slog.Bool("credential_set", s.CredentialSet),
		slog.String("credential_ciphertext", output.Sentinel),
		slog.Bool("enabled", s.Enabled),
		slog.Int64("revision", s.Revision),
	)
}

// UpsertMeteringSourceInput is the write contract for backoffice source config.
// CredentialValue is nil to preserve the existing credential, non-nil empty to
// clear it, and non-nil non-empty to seal and replace it.
type UpsertMeteringSourceInput struct {
	SourceType            MeteringSourceType
	EndpointURL           string
	AuthScheme            string
	AuthReference         string
	CredentialValue       *string
	ScrapeIntervalSeconds int
	QueryIntervalSeconds  int
	TimeoutSeconds        int
	Labels                map[string]string
	Enabled               bool
}

// MeteringSourceCredential stores a sealed write-only credential tuple.
type MeteringSourceCredential struct {
	Touched          bool
	SecretProvider   string
	SecretKeyID      string
	SecretCiphertext []byte
}

// MeteringSourceTestInput lets callers override connection-test timeout.
type MeteringSourceTestInput struct {
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// MeteringSourceTestResult is the stable side-effect-free reachability report.
type MeteringSourceTestResult struct {
	SourceKey     string    `json:"source_key"`
	Status        string    `json:"status"`
	CheckedAt     time.Time `json:"checked_at"`
	LatencyMillis int64     `json:"latency_millis"`
	Message       string    `json:"message,omitempty"`
}

// MeteringSourceRepository persists backoffice metering source configuration.
type MeteringSourceRepository struct{}

// NewMeteringSourceRepository returns a stateless metering source repository.
func NewMeteringSourceRepository() *MeteringSourceRepository { return &MeteringSourceRepository{} }

const meteringSourceColumns = `id, source_key, source_type, endpoint_url, auth_scheme, auth_reference, credential_provider, credential_key_id, credential_ciphertext, scrape_interval_seconds, query_interval_seconds, timeout_seconds, labels, enabled, revision, created_at, updated_at`

var meteringSourceKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Upsert creates or replaces the non-secret configuration. Credential columns
// are changed only when credential.Touched is true.
func (r *MeteringSourceRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertMeteringSourceInput, credential MeteringSourceCredential) (MeteringSource, error) {
	if tx == nil {
		return MeteringSource{}, apierr.Internal(errors.New("store: MeteringSourceRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateMeteringSourceUpsert(key, in)
	if err != nil {
		return MeteringSource{}, err
	}
	labels, err := marshalMeteringSourceLabels(input.Labels)
	if err != nil {
		return MeteringSource{}, err
	}
	id, err := newOpaqueStoreID("msrc")
	if err != nil {
		return MeteringSource{}, apierr.Internal(err)
	}
	provider, keyID, ciphertext := nullableMeteringCredential(credential)
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_metering_sources
		    (id, source_key, source_type, endpoint_url, auth_scheme, auth_reference,
		     credential_value, credential_provider, credential_key_id, credential_ciphertext,
		     scrape_interval_seconds, query_interval_seconds, timeout_seconds, labels, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, '', $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (source_key) DO UPDATE
		    SET source_type = EXCLUDED.source_type,
		        endpoint_url = EXCLUDED.endpoint_url,
		        auth_scheme = EXCLUDED.auth_scheme,
		        auth_reference = EXCLUDED.auth_reference,
		        credential_provider = CASE WHEN $15 THEN EXCLUDED.credential_provider ELSE admin_metering_sources.credential_provider END,
		        credential_key_id = CASE WHEN $15 THEN EXCLUDED.credential_key_id ELSE admin_metering_sources.credential_key_id END,
		        credential_ciphertext = CASE WHEN $15 THEN EXCLUDED.credential_ciphertext ELSE admin_metering_sources.credential_ciphertext END,
		        scrape_interval_seconds = EXCLUDED.scrape_interval_seconds,
		        query_interval_seconds = EXCLUDED.query_interval_seconds,
		        timeout_seconds = EXCLUDED.timeout_seconds,
		        labels = EXCLUDED.labels,
		        enabled = EXCLUDED.enabled,
		        revision = admin_metering_sources.revision + 1
		 RETURNING `+meteringSourceColumns,
		id, key, input.SourceType, input.EndpointURL, input.AuthScheme, input.AuthReference,
		provider, keyID, ciphertext, input.ScrapeIntervalSeconds, input.QueryIntervalSeconds, input.TimeoutSeconds, labels, input.Enabled, credential.Touched)
	source, err := scanMeteringSource(row)
	if err != nil {
		return MeteringSource{}, mapWriteError(err, "the metering source could not be saved")
	}
	return source, nil
}

// Get returns one configured source by stable key.
func (r *MeteringSourceRepository) Get(ctx context.Context, q Querier, key string) (MeteringSource, error) {
	key = strings.TrimSpace(key)
	row := q.QueryRow(ctx,
		`SELECT `+meteringSourceColumns+`
		   FROM admin_metering_sources
		  WHERE source_key = $1`,
		key)
	source, err := scanMeteringSource(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return MeteringSource{}, apierr.NotFound("metering_source", key)
	}
	if err != nil {
		return MeteringSource{}, apierr.StoreUnavailable(err)
	}
	return source, nil
}

// ListRuntimeEnabled returns enabled source configs in deterministic order.
func (r *MeteringSourceRepository) ListRuntimeEnabled(ctx context.Context, q Querier, _ time.Time) ([]MeteringSource, error) {
	rows, err := q.Query(ctx,
		`SELECT `+meteringSourceColumns+`
		   FROM admin_metering_sources
		  WHERE enabled = true
		  ORDER BY source_type ASC, source_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []MeteringSource
	for rows.Next() {
		source, scanErr := scanMeteringSource(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, source)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func validateMeteringSourceUpsert(key string, in UpsertMeteringSourceInput) (string, UpsertMeteringSourceInput, error) {
	key = strings.TrimSpace(key)
	var violations []apierr.FieldViolation
	if !meteringSourceKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "source_key", Reason: "must be a lowercase slug"})
	}
	if !in.SourceType.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "source_type", Reason: "must be one of traefik, prometheus, dokploy, container, storage, backup"})
	}
	in.EndpointURL = strings.TrimSpace(in.EndpointURL)
	if parsed, err := url.ParseRequestURI(in.EndpointURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
		violations = append(violations, apierr.FieldViolation{Field: "endpoint_url", Reason: "must be an absolute http or https URL"})
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		violations = append(violations, apierr.FieldViolation{Field: "endpoint_url", Reason: "must use http or https"})
	}
	in.AuthScheme = strings.TrimSpace(in.AuthScheme)
	if in.AuthScheme == "" {
		in.AuthScheme = "none"
	}
	switch in.AuthScheme {
	case "none", "bearer", "basic", "api_key", "mtls", "custom":
	default:
		violations = append(violations, apierr.FieldViolation{Field: "auth_scheme", Reason: "must be one of none, bearer, basic, api_key, mtls, custom"})
	}
	in.AuthReference = strings.TrimSpace(in.AuthReference)
	if len(in.AuthReference) > 512 {
		violations = append(violations, apierr.FieldViolation{Field: "auth_reference", Reason: "must be at most 512 characters"})
	}
	if in.ScrapeIntervalSeconds == 0 {
		in.ScrapeIntervalSeconds = 60
	}
	if in.QueryIntervalSeconds == 0 {
		in.QueryIntervalSeconds = 300
	}
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 10
	}
	if in.ScrapeIntervalSeconds < 10 || in.ScrapeIntervalSeconds > 86400 {
		violations = append(violations, apierr.FieldViolation{Field: "scrape_interval_seconds", Reason: "must be between 10 and 86400"})
	}
	if in.QueryIntervalSeconds < 10 || in.QueryIntervalSeconds > 86400 {
		violations = append(violations, apierr.FieldViolation{Field: "query_interval_seconds", Reason: "must be between 10 and 86400"})
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 {
		violations = append(violations, apierr.FieldViolation{Field: "timeout_seconds", Reason: "must be between 1 and 300"})
	}
	if len(in.Labels) > 32 {
		violations = append(violations, apierr.FieldViolation{Field: "labels", Reason: "must contain at most 32 entries"})
	}
	for k, v := range in.Labels {
		if strings.TrimSpace(k) == "" || len(k) > 120 {
			violations = append(violations, apierr.FieldViolation{Field: "labels", Reason: "keys must be 1 to 120 characters"})
			break
		}
		if len(v) > 512 {
			violations = append(violations, apierr.FieldViolation{Field: "labels." + k, Reason: "must be at most 512 characters"})
		}
	}
	if len(violations) > 0 {
		return "", UpsertMeteringSourceInput{}, apierr.InvalidInput(violations...)
	}
	if in.Labels == nil {
		in.Labels = map[string]string{}
	}
	return key, in, nil
}

func marshalMeteringSourceLabels(labels map[string]string) ([]byte, error) {
	if labels == nil {
		return []byte(`{}`), nil
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(labels))
	for _, key := range keys {
		out[key] = labels[key]
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "labels", Reason: "must be valid JSON"})
	}
	return b, nil
}

func nullableMeteringCredential(in MeteringSourceCredential) (provider, keyID any, ciphertext any) {
	if !in.Touched || len(in.SecretCiphertext) == 0 {
		return nil, nil, nil
	}
	return in.SecretProvider, in.SecretKeyID, in.SecretCiphertext
}

func scanMeteringSource(row pgx.Row) (MeteringSource, error) {
	var source MeteringSource
	var labels []byte
	var provider, keyID *string
	var ciphertext []byte
	if err := row.Scan(
		&source.ID,
		&source.SourceKey,
		&source.SourceType,
		&source.EndpointURL,
		&source.AuthScheme,
		&source.AuthReference,
		&provider,
		&keyID,
		&ciphertext,
		&source.ScrapeIntervalSeconds,
		&source.QueryIntervalSeconds,
		&source.TimeoutSeconds,
		&labels,
		&source.Enabled,
		&source.Revision,
		&source.CreatedAt,
		&source.UpdatedAt,
	); err != nil {
		return MeteringSource{}, err
	}
	if provider != nil {
		source.SecretProvider = *provider
	}
	if keyID != nil {
		source.SecretKeyID = *keyID
	}
	source.SecretCiphertext = ciphertext
	source.CredentialSet = provider != nil && keyID != nil && len(ciphertext) > 0
	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &source.Labels); err != nil {
			return MeteringSource{}, err
		}
	}
	if source.Labels == nil {
		source.Labels = map[string]string{}
	}
	return source, nil
}
