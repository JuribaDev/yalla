package store

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// BillingProviderType identifies the configured export adapter.
type BillingProviderType string

const (
	// BillingProviderTypeDisabled keeps a provider config as a non-exporting placeholder.
	BillingProviderTypeDisabled BillingProviderType = "disabled"
	// BillingProviderTypeManual writes export batches for operator/manual invoicing.
	BillingProviderTypeManual BillingProviderType = "manual"
	// BillingProviderTypeStripe is the Stripe adapter placeholder contract.
	BillingProviderTypeStripe BillingProviderType = "stripe"
)

func (t BillingProviderType) valid() bool {
	switch t {
	case BillingProviderTypeDisabled, BillingProviderTypeManual, BillingProviderTypeStripe:
		return true
	default:
		return false
	}
}

// BillingProviderConfig is the runtime billing export provider contract.
// Credential bytes are write-only and never appear in HTTP projections.
type BillingProviderConfig struct {
	ID                         string
	ProviderKey                string
	ProviderType               BillingProviderType
	DisplayName                string
	SecretReference            string
	CredentialSet              bool
	SecretProvider             string
	SecretKeyID                string
	SecretCiphertext           []byte
	ExportCadenceSeconds       int
	RetryMaxAttempts           int
	RetryInitialBackoffSeconds int
	DryRun                     bool
	Metadata                   map[string]string
	Enabled                    bool
	Revision                   int64
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

// LogValue emits only non-secret diagnostics.
func (p BillingProviderConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", p.ID),
		slog.String("provider_key", p.ProviderKey),
		slog.String("provider_type", string(p.ProviderType)),
		slog.String("secret_reference", output.NewRedactor().Redact(p.SecretReference)),
		slog.Bool("credential_set", p.CredentialSet),
		slog.String("credential_ciphertext", output.Sentinel),
		slog.Int("export_cadence_seconds", p.ExportCadenceSeconds),
		slog.Int("retry_max_attempts", p.RetryMaxAttempts),
		slog.Bool("dry_run", p.DryRun),
		slog.Bool("enabled", p.Enabled),
		slog.Int64("revision", p.Revision),
	)
}

// UpsertBillingProviderInput is the backoffice write contract.
type UpsertBillingProviderInput struct {
	ProviderType               BillingProviderType
	DisplayName                string
	SecretReference            string
	CredentialValue            *string
	ExportCadenceSeconds       int
	RetryMaxAttempts           int
	RetryInitialBackoffSeconds int
	DryRun                     bool
	Metadata                   map[string]string
	Enabled                    bool
}

// BillingProviderCredential stores a sealed write-only credential tuple.
type BillingProviderCredential struct {
	Touched          bool
	SecretProvider   string
	SecretKeyID      string
	SecretCiphertext []byte
}

// BillingProviderTestInput carries fake counters for side-effect-free mapping tests.
type BillingProviderTestInput struct {
	FakeCounterCount int `json:"fake_counter_count,omitempty"`
}

// BillingProviderTestResult is the stable side-effect-free provider test report.
type BillingProviderTestResult struct {
	ProviderKey      string    `json:"provider_key"`
	ProviderType     string    `json:"provider_type"`
	Status           string    `json:"status"`
	CheckedAt        time.Time `json:"checked_at"`
	FakeCounterCount int       `json:"fake_counter_count"`
	Message          string    `json:"message,omitempty"`
}

// BillingProviderConfigRepository persists global billing provider config.
type BillingProviderConfigRepository struct{}

// NewBillingProviderConfigRepository returns a stateless repository.
func NewBillingProviderConfigRepository() *BillingProviderConfigRepository {
	return &BillingProviderConfigRepository{}
}

const billingProviderColumns = `id, provider_key, provider_type, display_name, secret_reference, credential_provider, credential_key_id, credential_ciphertext, export_cadence_seconds, retry_max_attempts, retry_initial_backoff_seconds, dry_run, metadata, enabled, revision, created_at, updated_at`

var billingProviderKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

// Upsert creates or replaces the non-secret configuration. Credential columns
// change only when credential.Touched is true.
func (r *BillingProviderConfigRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertBillingProviderInput, credential BillingProviderCredential) (BillingProviderConfig, error) {
	if tx == nil {
		return BillingProviderConfig{}, apierr.Internal(errors.New("store: BillingProviderConfigRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateBillingProviderUpsert(key, in)
	if err != nil {
		return BillingProviderConfig{}, err
	}
	metadata, err := marshalBillingProviderMetadata(input.Metadata)
	if err != nil {
		return BillingProviderConfig{}, err
	}
	id, err := newOpaqueStoreID("bprov")
	if err != nil {
		return BillingProviderConfig{}, apierr.Internal(err)
	}
	provider, keyID, ciphertext := nullableBillingCredential(credential)
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_billing_providers
		    (id, provider_key, provider_type, display_name, secret_reference,
		     credential_value, credential_provider, credential_key_id, credential_ciphertext,
		     export_cadence_seconds, retry_max_attempts, retry_initial_backoff_seconds,
		     dry_run, metadata, enabled)
		 VALUES ($1, $2, $3, $4, $5, '', $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (provider_key) DO UPDATE
		    SET provider_type = EXCLUDED.provider_type,
		        display_name = EXCLUDED.display_name,
		        secret_reference = EXCLUDED.secret_reference,
		        credential_provider = CASE WHEN $15 THEN EXCLUDED.credential_provider ELSE admin_billing_providers.credential_provider END,
		        credential_key_id = CASE WHEN $15 THEN EXCLUDED.credential_key_id ELSE admin_billing_providers.credential_key_id END,
		        credential_ciphertext = CASE WHEN $15 THEN EXCLUDED.credential_ciphertext ELSE admin_billing_providers.credential_ciphertext END,
		        export_cadence_seconds = EXCLUDED.export_cadence_seconds,
		        retry_max_attempts = EXCLUDED.retry_max_attempts,
		        retry_initial_backoff_seconds = EXCLUDED.retry_initial_backoff_seconds,
		        dry_run = EXCLUDED.dry_run,
		        metadata = EXCLUDED.metadata,
		        enabled = EXCLUDED.enabled,
		        revision = admin_billing_providers.revision + 1
		 RETURNING `+billingProviderColumns,
		id, key, input.ProviderType, input.DisplayName, input.SecretReference,
		provider, keyID, ciphertext, input.ExportCadenceSeconds, input.RetryMaxAttempts, input.RetryInitialBackoffSeconds,
		input.DryRun, metadata, input.Enabled, credential.Touched)
	out, err := scanBillingProvider(row)
	if err != nil {
		return BillingProviderConfig{}, mapWriteError(err, "the billing provider could not be saved")
	}
	return out, nil
}

// Get returns one configured provider by stable key.
func (r *BillingProviderConfigRepository) Get(ctx context.Context, q Querier, key string) (BillingProviderConfig, error) {
	key = strings.TrimSpace(key)
	row := q.QueryRow(ctx,
		`SELECT `+billingProviderColumns+`
		   FROM admin_billing_providers
		  WHERE provider_key = $1`,
		key)
	out, err := scanBillingProvider(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return BillingProviderConfig{}, apierr.NotFound("billing_provider", key)
	}
	if err != nil {
		return BillingProviderConfig{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListRuntimeEnabled returns enabled exporting providers in deterministic order.
func (r *BillingProviderConfigRepository) ListRuntimeEnabled(ctx context.Context, q Querier, _ time.Time) ([]BillingProviderConfig, error) {
	rows, err := q.Query(ctx,
		`SELECT `+billingProviderColumns+`
		   FROM admin_billing_providers
		  WHERE enabled = true
		    AND provider_type <> 'disabled'
		  ORDER BY provider_type ASC, provider_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []BillingProviderConfig
	for rows.Next() {
		provider, scanErr := scanBillingProvider(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func validateBillingProviderUpsert(key string, in UpsertBillingProviderInput) (string, UpsertBillingProviderInput, error) {
	key = strings.TrimSpace(key)
	var violations []apierr.FieldViolation
	if !billingProviderKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "provider_key", Reason: "must be a stable lowercase token"})
	}
	if !in.ProviderType.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "provider_type", Reason: "must be one of disabled, manual, stripe"})
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if len(in.DisplayName) > 200 {
		violations = append(violations, apierr.FieldViolation{Field: "display_name", Reason: "must be at most 200 characters"})
	}
	in.SecretReference = strings.TrimSpace(in.SecretReference)
	if len(in.SecretReference) > 512 {
		violations = append(violations, apierr.FieldViolation{Field: "secret_reference", Reason: "must be at most 512 characters"})
	}
	if in.ExportCadenceSeconds == 0 {
		in.ExportCadenceSeconds = 86400
	}
	if in.ExportCadenceSeconds < 300 || in.ExportCadenceSeconds > 2678400 {
		violations = append(violations, apierr.FieldViolation{Field: "export_cadence_seconds", Reason: "must be between 300 and 2678400"})
	}
	if in.RetryMaxAttempts == 0 {
		in.RetryMaxAttempts = 3
	}
	if in.RetryMaxAttempts < 0 || in.RetryMaxAttempts > 20 {
		violations = append(violations, apierr.FieldViolation{Field: "retry_max_attempts", Reason: "must be between 0 and 20"})
	}
	if in.RetryInitialBackoffSeconds == 0 {
		in.RetryInitialBackoffSeconds = 60
	}
	if in.RetryInitialBackoffSeconds < 1 || in.RetryInitialBackoffSeconds > 86400 {
		violations = append(violations, apierr.FieldViolation{Field: "retry_initial_backoff_seconds", Reason: "must be between 1 and 86400"})
	}
	if len(in.Metadata) > 32 {
		violations = append(violations, apierr.FieldViolation{Field: "metadata", Reason: "must contain at most 32 entries"})
	}
	for k, v := range in.Metadata {
		if strings.TrimSpace(k) == "" || len(k) > 120 {
			violations = append(violations, apierr.FieldViolation{Field: "metadata", Reason: "keys must be 1 to 120 characters"})
			break
		}
		if len(v) > 512 {
			violations = append(violations, apierr.FieldViolation{Field: "metadata." + k, Reason: "must be at most 512 characters"})
		}
	}
	if len(violations) > 0 {
		return "", UpsertBillingProviderInput{}, apierr.InvalidInput(violations...)
	}
	if in.Metadata == nil {
		in.Metadata = map[string]string{}
	}
	return key, in, nil
}

func marshalBillingProviderMetadata(metadata map[string]string) ([]byte, error) {
	if metadata == nil {
		return []byte(`{}`), nil
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(metadata))
	for _, key := range keys {
		ordered[key] = metadata[key]
	}
	out, err := json.Marshal(ordered)
	if err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "metadata", Reason: "must be a JSON object with string values"})
	}
	return out, nil
}

func nullableBillingCredential(credential BillingProviderCredential) (*string, *string, []byte) {
	if !credential.Touched || credential.SecretProvider == "" || credential.SecretKeyID == "" || len(credential.SecretCiphertext) == 0 {
		return nil, nil, nil
	}
	return &credential.SecretProvider, &credential.SecretKeyID, credential.SecretCiphertext
}

func scanBillingProvider(row pgx.Row) (BillingProviderConfig, error) {
	var out BillingProviderConfig
	var provider, keyID *string
	var ciphertext []byte
	var metadata []byte
	err := row.Scan(
		&out.ID,
		&out.ProviderKey,
		&out.ProviderType,
		&out.DisplayName,
		&out.SecretReference,
		&provider,
		&keyID,
		&ciphertext,
		&out.ExportCadenceSeconds,
		&out.RetryMaxAttempts,
		&out.RetryInitialBackoffSeconds,
		&out.DryRun,
		&metadata,
		&out.Enabled,
		&out.Revision,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return BillingProviderConfig{}, err
	}
	if provider != nil {
		out.SecretProvider = *provider
	}
	if keyID != nil {
		out.SecretKeyID = *keyID
	}
	if len(ciphertext) > 0 {
		out.SecretCiphertext = append([]byte(nil), ciphertext...)
		out.CredentialSet = true
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &out.Metadata); err != nil {
			return BillingProviderConfig{}, err
		}
	}
	if out.Metadata == nil {
		out.Metadata = map[string]string{}
	}
	return out, nil
}
