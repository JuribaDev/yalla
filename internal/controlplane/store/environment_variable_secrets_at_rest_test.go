package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Integration tests for the encryption-at-rest seam BE-0341 added to
// environment_variables. They prove that an EnvironmentVariableService
// configured with a real secrets.AESGCM provider seals every
// is_secret=true value before it reaches the source-of-truth table —
// the on-disk bytea column never holds the plaintext, the routing
// columns name the active provider / key, the wire projection still
// redacts the customer's view, and the audit metadata records only
// counts.
//
// The tests skip cleanly when YALLA_TEST_DATABASE_URL is unset so
// `go test ./...` stays green without Postgres.

// mustEnvAESGCM mints a real AES-256-GCM provider with one fresh key
// per test. Each test runs in parallel and gets its own provider so an
// assertion against the provider's active key id does not bleed across
// tests.
func mustEnvAESGCM(t *testing.T) *secrets.AESGCM {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	provider, err := secrets.NewAESGCM([][]byte{key})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return provider
}

func newEnvironmentVariableServiceWith(t *testing.T, s *store.Store, provider secrets.Provider) *store.EnvironmentVariableService {
	t.Helper()
	svc, err := store.NewEnvironmentVariableService(s,
		store.NewEnvironmentRepository(),
		store.NewEnvironmentVariableRepository(),
		store.NewAuditRepository(),
		provider)
	if err != nil {
		t.Fatalf("NewEnvironmentVariableService: %v", err)
	}
	return svc
}

// TestEnvironmentVariableServiceReplaceSealsSecretValuesAtRest proves the
// load-bearing contract for BE-0341: a customer-supplied secret value
// reaches Postgres only as AES-GCM ciphertext under the active
// provider's key id. The corresponding `value` column for the same row
// is the empty string the CHECK constraint requires, and the wire
// shape redacts to output.Sentinel regardless. Audit metadata records
// only counts — never the customer-supplied key, value, ciphertext,
// provider id, or key id.
func TestEnvironmentVariableServiceReplaceSealsSecretValuesAtRest(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustEnvAESGCM(t)
	svc := newEnvironmentVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "EnvAtRest")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")

	const (
		plainKey      = "REGION"
		plainValue    = "us-east-1"
		secretKey     = "DB_PASSWORD"
		secretValue   = "correct-horse-battery-staple"
		actorID       = "user_actor"
		requestID     = "req_env_atrest_seal"
		correlationID = "corr_env_atrest_seal"
	)
	committed, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables: []store.EnvironmentVariableReplace{
			{Key: plainKey, Value: plainValue, IsSecret: false},
			{Key: secretKey, Value: secretValue, IsSecret: true},
		},
		ActorID:       actorID,
		ActorKind:     "usr",
		ActorOrgID:    org.ID,
		RequestID:     requestID,
		CorrelationID: correlationID,
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if got := len(committed); got != 2 {
		t.Fatalf("committed len = %d, want 2", got)
	}

	// The repository projection always returns the on-disk shape: the
	// secret row's Value is "" (the CHECK pins it) and the encryption
	// metadata is populated. The plaintext value never round-trips
	// through this read path.
	var (
		gotSecret store.EnvironmentVariable
		gotPlain  store.EnvironmentVariable
	)
	for _, v := range committed {
		switch v.Key {
		case secretKey:
			gotSecret = v
		case plainKey:
			gotPlain = v
		}
	}
	if gotSecret.ID == "" {
		t.Fatalf("secret row missing from committed: %#v", committed)
	}
	if !gotSecret.IsSecret {
		t.Errorf("secret row IsSecret = false")
	}
	if gotSecret.Value != "" {
		t.Errorf("secret row Value = %q, want empty (sealed in ciphertext column)", gotSecret.Value)
	}
	if gotSecret.SecretProvider != provider.ProviderID() {
		t.Errorf("secret row SecretProvider = %q, want %q", gotSecret.SecretProvider, provider.ProviderID())
	}
	if gotSecret.SecretKeyID != provider.ActiveKeyID() {
		t.Errorf("secret row SecretKeyID = %q, want %q", gotSecret.SecretKeyID, provider.ActiveKeyID())
	}
	if len(gotSecret.SecretCiphertext) == 0 {
		t.Errorf("secret row SecretCiphertext is empty")
	}
	if bytes.Contains(gotSecret.SecretCiphertext, []byte(secretValue)) {
		t.Errorf("on-disk ciphertext leaks plaintext: ciphertext=%x", gotSecret.SecretCiphertext)
	}
	// The plain row stays plain — the encryption columns must be empty
	// so the CHECK constraint considers the row valid in its non-secret
	// state. This is the negative half of the invariant.
	if gotPlain.IsSecret {
		t.Errorf("plain row IsSecret = true")
	}
	if gotPlain.Value != plainValue {
		t.Errorf("plain row Value = %q, want %q", gotPlain.Value, plainValue)
	}
	if gotPlain.SecretProvider != "" || gotPlain.SecretKeyID != "" || len(gotPlain.SecretCiphertext) != 0 {
		t.Errorf("plain row carries encryption metadata: provider=%q keyID=%q ciphertext_len=%d",
			gotPlain.SecretProvider, gotPlain.SecretKeyID, len(gotPlain.SecretCiphertext))
	}

	// Defence-in-depth: query the raw column directly so a future change
	// to the repository projection cannot mask a regression where the
	// plaintext silently lands in the value column.
	var (
		rawValue      string
		rawIsSecret   bool
		rawProvider   *string
		rawKeyID      *string
		rawCiphertext []byte
	)
	if err := db.QueryRow(ctx,
		`SELECT value, is_secret, secret_provider, secret_key_id, secret_ciphertext
		   FROM environment_variables
		  WHERE organization_id = $1 AND environment_id = $2 AND key = $3`,
		org.ID, env.ID, secretKey).Scan(&rawValue, &rawIsSecret, &rawProvider, &rawKeyID, &rawCiphertext); err != nil {
		t.Fatalf("raw row read: %v", err)
	}
	if rawValue != "" {
		t.Errorf("raw value column for secret row = %q, want empty", rawValue)
	}
	if !rawIsSecret {
		t.Errorf("raw is_secret = false")
	}
	if rawProvider == nil || *rawProvider != provider.ProviderID() {
		t.Errorf("raw secret_provider = %v, want %q", rawProvider, provider.ProviderID())
	}
	if rawKeyID == nil || *rawKeyID != provider.ActiveKeyID() {
		t.Errorf("raw secret_key_id = %v, want %q", rawKeyID, provider.ActiveKeyID())
	}
	if bytes.Contains(rawCiphertext, []byte(secretValue)) {
		t.Errorf("raw ciphertext leaks plaintext")
	}

	// Round-trip: the provider opens the ciphertext back into the
	// original plaintext, proving the seal is reversible by the same
	// process that wrote it (the renderer worker uses the same path).
	opened, openErr := provider.Open(rawCiphertext, *rawKeyID)
	if openErr != nil {
		t.Fatalf("Open: %v", openErr)
	}
	if string(opened) != secretValue {
		t.Errorf("Open round-trip mismatch: got %q", string(opened))
	}

	// Audit-side guarantee: the audit row that documents this Replace
	// never carries the secret value, the ciphertext, the provider id,
	// or the key id. The audit metadata is counts-only by contract.
	// environment_variables Replace audits filed under (org_id,
	// environment_id): resource_kind=env, resource_id={environment_id}.
	var (
		auditAction   string
		auditMetadata []byte
	)
	if err := db.QueryRow(ctx,
		`SELECT action, metadata
		   FROM audit_events
		  WHERE organization_id = $1 AND resource_id = $2
		  ORDER BY occurred_at DESC
		  LIMIT 1`,
		org.ID, env.ID).Scan(&auditAction, &auditMetadata); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if auditAction != "env.write" {
		t.Errorf("audit action = %q, want env.write", auditAction)
	}
	disallowed := []string{secretValue, secretKey, hex.EncodeToString(rawCiphertext), provider.ActiveKeyID(), provider.ProviderID()}
	for _, banned := range disallowed {
		if banned == "" {
			continue
		}
		if bytes.Contains(auditMetadata, []byte(banned)) {
			t.Errorf("audit metadata leaks %q: %s", banned, auditMetadata)
		}
	}
}

// TestEnvironmentVariableServiceReplaceRotatesCiphertextOnRepeatWrite
// proves that a second Replace overwriting an existing secret row
// re-seals the value under a fresh nonce — the on-disk ciphertext
// changes between writes (defence against a regression that
// accidentally re-uses the previously-sealed ciphertext).
func TestEnvironmentVariableServiceReplaceRotatesCiphertextOnRepeatWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustEnvAESGCM(t)
	svc := newEnvironmentVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "EnvRotate")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")

	const (
		secretKey   = "API_TOKEN"
		secretValue = "tok_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables: []store.EnvironmentVariableReplace{
			{Key: secretKey, Value: secretValue, IsSecret: true},
		},
		ActorID:    "usr_actor",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	var firstCiphertext []byte
	if err := db.QueryRow(ctx,
		`SELECT secret_ciphertext FROM environment_variables
		  WHERE organization_id = $1 AND environment_id = $2 AND key = $3`,
		org.ID, env.ID, secretKey).Scan(&firstCiphertext); err != nil {
		t.Fatalf("first ciphertext read: %v", err)
	}

	// Replace again with the SAME plaintext. The upsert MUST go through
	// Seal (fresh nonce per call) so the on-disk bytes differ.
	if _, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables: []store.EnvironmentVariableReplace{
			{Key: secretKey, Value: secretValue, IsSecret: true},
		},
		ActorID:    "usr_actor",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("re-seal Replace: %v", err)
	}

	var secondCiphertext []byte
	if err := db.QueryRow(ctx,
		`SELECT secret_ciphertext FROM environment_variables
		  WHERE organization_id = $1 AND environment_id = $2 AND key = $3`,
		org.ID, env.ID, secretKey).Scan(&secondCiphertext); err != nil {
		t.Fatalf("second ciphertext read: %v", err)
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Errorf("ciphertext did not change between writes (no nonce rotation)")
	}
	opened, openErr := provider.Open(secondCiphertext, provider.ActiveKeyID())
	if openErr != nil {
		t.Fatalf("Open after re-seal: %v", openErr)
	}
	if string(opened) != secretValue {
		t.Errorf("post-re-seal plaintext mismatch: got %q want %q", string(opened), secretValue)
	}
}

// TestEnvironmentVariableServiceReplaceDemotesSecretToPlaintext proves the
// demotion path: a customer Replace overwriting an existing is_secret
// row with is_secret=false yields a row whose plain `value` column
// carries the new plaintext and whose ciphertext columns are NULL —
// the CHECK constraint forbids any other state. This is the only
// customer path that surfaces a previously-sealed plaintext (and only
// for a value the customer just supplied), never a side-effect of a
// read.
func TestEnvironmentVariableServiceReplaceDemotesSecretToPlaintext(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustEnvAESGCM(t)
	svc := newEnvironmentVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "EnvDemote")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")

	const (
		key  = "FEATURE_KEY"
		seed = "feature_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables:      []store.EnvironmentVariableReplace{{Key: key, Value: seed, IsSecret: true}},
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}
	committed, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables:      []store.EnvironmentVariableReplace{{Key: key, Value: seed, IsSecret: false}},
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("Replace demote: %v", err)
	}
	if len(committed) != 1 {
		t.Fatalf("post-demote variables = %+v, want 1", committed)
	}
	demoted := committed[0]
	if demoted.IsSecret {
		t.Errorf("demoted.IsSecret = true")
	}
	if demoted.Value != seed {
		t.Errorf("demoted Value = %q, want %q", demoted.Value, seed)
	}
	if demoted.SecretProvider != "" || demoted.SecretKeyID != "" || len(demoted.SecretCiphertext) != 0 {
		t.Errorf("demoted row still carries encryption metadata: provider=%q keyID=%q ciphertext_len=%d",
			demoted.SecretProvider, demoted.SecretKeyID, len(demoted.SecretCiphertext))
	}

	// Defence in depth: the raw columns must reflect the same shape.
	var (
		isSecret bool
		val      string
		prov     *string
		kid      *string
		ct       []byte
	)
	if err := db.QueryRow(ctx,
		`SELECT is_secret, value, secret_provider, secret_key_id, secret_ciphertext
		   FROM environment_variables WHERE organization_id = $1 AND environment_id = $2 AND key = $3`,
		org.ID, env.ID, key).Scan(&isSecret, &val, &prov, &kid, &ct); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if isSecret || val != seed || prov != nil || kid != nil || ct != nil {
		t.Errorf("raw demoted row drift: is_secret=%v value=%q prov=%v kid=%v ct=%v",
			isSecret, val, prov, kid, ct)
	}
}

// TestEnvironmentVariableSchemaRejectsPlaintextSecretWrite proves the
// database CHECK constraint is the defence-in-depth backstop the
// service relies on. A direct INSERT that tries to set is_secret=true
// with a non-empty plain value (or with NULL ciphertext columns) MUST
// fail with a constraint violation, so a future bug in the application
// layer cannot silently corrupt the at-rest state.
func TestEnvironmentVariableSchemaRejectsPlaintextSecretWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSchemaDefense")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")

	cases := []struct {
		name string
		exec string
		args []any
		mark string
	}{
		{
			name: "plain value with is_secret=true",
			exec: `INSERT INTO environment_variables (id, organization_id, environment_id, key, value, is_secret) VALUES ($1, $2, $3, 'BAD', 'plain', true)`,
			args: []any{"evar_bad_plain_secret", org.ID, env.ID},
			mark: "environment_variables_secret_columns_consistent",
		},
		{
			name: "secret columns set with is_secret=false",
			exec: `INSERT INTO environment_variables (id, organization_id, environment_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, $3, 'BAD2', 'plain', false, 'aesgcm-v1', 'abc', $4)`,
			args: []any{"evar_bad_partial", org.ID, env.ID, []byte{1, 2, 3}},
			mark: "environment_variables_secret_columns_consistent",
		},
		{
			name: "secret with empty ciphertext",
			exec: `INSERT INTO environment_variables (id, organization_id, environment_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, $3, 'BAD3', '', true, 'aesgcm-v1', 'abc', $4)`,
			args: []any{"evar_bad_empty_ct", org.ID, env.ID, []byte{}},
			mark: "environment_variables_secret_columns_consistent",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := db.Exec(ctx, tc.exec, tc.args...)
			if err == nil {
				t.Fatalf("INSERT %q succeeded; want constraint violation", tc.name)
			}
			if !strings.Contains(err.Error(), tc.mark) {
				t.Errorf("error did not name the consistency constraint: %v", err)
			}
		})
	}
}

// TestEnvironmentVariableLogValueRedactsCiphertextAndPlaintext is the
// slog-boundary defence: a log record that captures an
// EnvironmentVariable cannot leak the plaintext OR the sealed
// ciphertext. The provider id and key id are exposed (they are already
// non-secret).
func TestEnvironmentVariableLogValueRedactsCiphertextAndPlaintext(t *testing.T) {
	t.Parallel()
	v := store.EnvironmentVariable{
		ID:               "evar_test",
		OrganizationID:   "org_test",
		EnvironmentID:    "env_test",
		Key:              "API_TOKEN",
		Value:            "",
		IsSecret:         true,
		SecretProvider:   "aesgcm-v1",
		SecretKeyID:      "deadbeefdeadbeef",
		SecretCiphertext: []byte("super-secret-cipher-bytes"),
		Version:          3,
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("variable", slog.Any("v", v))
	rendered := buf.String()
	if !strings.Contains(rendered, output.Sentinel) {
		t.Errorf("LogValue missing Sentinel: %q", rendered)
	}
	if strings.Contains(rendered, string(v.SecretCiphertext)) {
		t.Errorf("LogValue leaked ciphertext: %q", rendered)
	}
	if !strings.Contains(rendered, v.SecretProvider) {
		t.Errorf("LogValue dropped provider id: %q", rendered)
	}
	if !strings.Contains(rendered, v.SecretKeyID) {
		t.Errorf("LogValue dropped key id: %q", rendered)
	}
}

// TestEnvironmentVariableServiceReplaceFailsOnSealError proves the
// service surfaces a seal failure as apierr.Internal rather than
// leaking the plaintext.
func TestEnvironmentVariableServiceReplaceFailsOnSealError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	svc := newEnvironmentVariableServiceWith(t, s, errEnvSealingProvider{})
	org := seedOrg(t, db, f, "EnvSealError")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentVariablesInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Variables: []store.EnvironmentVariableReplace{
			{Key: "BOOM", Value: "the-secret", IsSecret: true},
		},
		ActorID:    "usr_actor",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace returned nil error; want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("Replace error code = %s, want %s", ye.Code, yerr.CodeInternal)
	}
	if strings.Contains(err.Error(), "the-secret") {
		t.Errorf("Replace error leaked plaintext: %v", err)
	}
}

// errEnvSealingProvider implements secrets.Provider but always fails at
// Seal time. Open is never reached on the failure path.
type errEnvSealingProvider struct{}

func (errEnvSealingProvider) ProviderID() string { return "fail-v1" }
func (errEnvSealingProvider) Seal([]byte) ([]byte, string, error) {
	return nil, "", errEnvSealAlwaysFails
}
func (errEnvSealingProvider) Open([]byte, string) ([]byte, error) {
	return nil, errEnvSealAlwaysFails
}

var errEnvSealAlwaysFails = envSealFailureSentinel{}

type envSealFailureSentinel struct{}

func (envSealFailureSentinel) Error() string { return "synthetic seal failure" }
