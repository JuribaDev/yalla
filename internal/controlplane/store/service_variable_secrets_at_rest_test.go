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

// Integration tests for the encryption-at-rest seam BE-0342 added to
// service_variables. They prove that a ServiceVariableService
// configured with a real secrets.AESGCM provider seals every
// is_secret=true value before it reaches the source-of-truth table —
// the on-disk bytea column never holds the plaintext, the routing
// columns name the active provider / key, the wire projection still
// redacts the customer's view, and the audit metadata records only
// counts.
//
// The tests skip cleanly when YALLA_TEST_DATABASE_URL is unset so
// `go test ./...` stays green without Postgres.

// mustSvcAESGCM mints a real AES-256-GCM provider with one fresh key
// per test. Each test runs in parallel and gets its own provider so an
// assertion against the provider's active key id does not bleed across
// tests.
func mustSvcAESGCM(t *testing.T) *secrets.AESGCM {
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

func newServiceVariableServiceWith(t *testing.T, s *store.Store, provider secrets.Provider) *store.ServiceVariableService {
	t.Helper()
	svc, err := store.NewServiceVariableService(s,
		store.NewServiceRepository(),
		store.NewServiceVariableRepository(),
		&recordingJobs{},
		store.NewAuditRepository(),
		provider)
	if err != nil {
		t.Fatalf("NewServiceVariableService: %v", err)
	}
	return svc
}

// TestServiceVariableServiceReplaceSealsSecretValuesAtRest proves the
// load-bearing contract for BE-0342: a customer-supplied secret value
// reaches Postgres only as AES-GCM ciphertext under the active
// provider's key id. The corresponding `value` column for the same row
// is the empty string the CHECK constraint requires, and the wire
// shape redacts to output.Sentinel regardless. Audit metadata records
// only counts — never the customer-supplied key, value, ciphertext,
// provider id, or key id.
func TestServiceVariableServiceReplaceSealsSecretValuesAtRest(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustSvcAESGCM(t)
	svc := newServiceVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "SvcAtRest")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")

	const (
		plainKey      = "REGION"
		plainValue    = "us-east-1"
		secretKey     = "DB_PASSWORD"
		secretValue   = "correct-horse-battery-staple"
		actorID       = "user_actor"
		requestID     = "req_svc_atrest_seal"
		correlationID = "corr_svc_atrest_seal"
	)
	committed, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables: []store.ServiceVariableReplace{
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
		gotSecret store.ServiceVariable
		gotPlain  store.ServiceVariable
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
		   FROM service_variables
		  WHERE organization_id = $1 AND service_id = $2 AND key = $3`,
		org.ID, service.ID, secretKey).Scan(&rawValue, &rawIsSecret, &rawProvider, &rawKeyID, &rawCiphertext); err != nil {
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
	// service_variables Replace audits filed under (org_id,
	// service_id): resource_kind=svc, resource_id={service_id}.
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
		org.ID, service.ID).Scan(&auditAction, &auditMetadata); err != nil {
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

// TestServiceVariableServiceReplaceRotatesCiphertextOnRepeatWrite
// proves that a second Replace overwriting an existing secret row
// re-seals the value under a fresh nonce — the on-disk ciphertext
// changes between writes (defence against a regression that
// accidentally re-uses the previously-sealed ciphertext).
func TestServiceVariableServiceReplaceRotatesCiphertextOnRepeatWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustSvcAESGCM(t)
	svc := newServiceVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "SvcRotate")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")

	const (
		secretKey   = "API_TOKEN"
		secretValue = "tok_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables: []store.ServiceVariableReplace{
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
		`SELECT secret_ciphertext FROM service_variables
		  WHERE organization_id = $1 AND service_id = $2 AND key = $3`,
		org.ID, service.ID, secretKey).Scan(&firstCiphertext); err != nil {
		t.Fatalf("first ciphertext read: %v", err)
	}

	// Replace again with the SAME plaintext. The upsert MUST go through
	// Seal (fresh nonce per call) so the on-disk bytes differ.
	if _, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables: []store.ServiceVariableReplace{
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
		`SELECT secret_ciphertext FROM service_variables
		  WHERE organization_id = $1 AND service_id = $2 AND key = $3`,
		org.ID, service.ID, secretKey).Scan(&secondCiphertext); err != nil {
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

// TestServiceVariableServiceReplaceDemotesSecretToPlaintext proves the
// demotion path: a customer Replace overwriting an existing is_secret
// row with is_secret=false yields a row whose plain `value` column
// carries the new plaintext and whose ciphertext columns are NULL —
// the CHECK constraint forbids any other state. This is the only
// customer path that surfaces a previously-sealed plaintext (and only
// for a value the customer just supplied), never a side-effect of a
// read.
func TestServiceVariableServiceReplaceDemotesSecretToPlaintext(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustSvcAESGCM(t)
	svc := newServiceVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "SvcDemote")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")

	const (
		key  = "FEATURE_KEY"
		seed = "feature_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables:      []store.ServiceVariableReplace{{Key: key, Value: seed, IsSecret: true}},
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}
	committed, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables:      []store.ServiceVariableReplace{{Key: key, Value: seed, IsSecret: false}},
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
		   FROM service_variables WHERE organization_id = $1 AND service_id = $2 AND key = $3`,
		org.ID, service.ID, key).Scan(&isSecret, &val, &prov, &kid, &ct); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if isSecret || val != seed || prov != nil || kid != nil || ct != nil {
		t.Errorf("raw demoted row drift: is_secret=%v value=%q prov=%v kid=%v ct=%v",
			isSecret, val, prov, kid, ct)
	}
}

// TestServiceVariableSchemaRejectsPlaintextSecretWrite proves the
// database CHECK constraint is the defence-in-depth backstop the
// service relies on. A direct INSERT that tries to set is_secret=true
// with a non-empty plain value (or with NULL ciphertext columns) MUST
// fail with a constraint violation, so a future bug in the application
// layer cannot silently corrupt the at-rest state.
func TestServiceVariableSchemaRejectsPlaintextSecretWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSchemaDefense")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")

	cases := []struct {
		name string
		exec string
		args []any
		mark string
	}{
		{
			name: "plain value with is_secret=true",
			exec: `INSERT INTO service_variables (id, organization_id, service_id, key, value, is_secret) VALUES ($1, $2, $3, 'BAD', 'plain', true)`,
			args: []any{"svar_bad_plain_secret", org.ID, service.ID},
			mark: "service_variables_secret_columns_consistent",
		},
		{
			name: "secret columns set with is_secret=false",
			exec: `INSERT INTO service_variables (id, organization_id, service_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, $3, 'BAD2', 'plain', false, 'aesgcm-v1', 'abc', $4)`,
			args: []any{"svar_bad_partial", org.ID, service.ID, []byte{1, 2, 3}},
			mark: "service_variables_secret_columns_consistent",
		},
		{
			name: "secret with empty ciphertext",
			exec: `INSERT INTO service_variables (id, organization_id, service_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, $3, 'BAD3', '', true, 'aesgcm-v1', 'abc', $4)`,
			args: []any{"svar_bad_empty_ct", org.ID, service.ID, []byte{}},
			mark: "service_variables_secret_columns_consistent",
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

// TestServiceVariableLogValueRedactsCiphertextAndPlaintext is the
// slog-boundary defence: a log record that captures a ServiceVariable
// cannot leak the plaintext OR the sealed ciphertext. The provider id
// and key id are exposed (they are already non-secret).
func TestServiceVariableLogValueRedactsCiphertextAndPlaintext(t *testing.T) {
	t.Parallel()
	v := store.ServiceVariable{
		ID:               "svar_test",
		OrganizationID:   "org_test",
		ServiceID:        "svc_test",
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

// TestServiceVariableServiceReplaceFailsOnSealError proves the service
// surfaces a seal failure as apierr.Internal rather than leaking the
// plaintext.
func TestServiceVariableServiceReplaceFailsOnSealError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	svc := newServiceVariableServiceWith(t, s, errSvcSealingProvider{})
	org := seedOrg(t, db, f, "SvcSealError")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")

	_, err := svc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      service.ID,
		Variables: []store.ServiceVariableReplace{
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

// errSvcSealingProvider implements secrets.Provider but always fails at
// Seal time. Open is never reached on the failure path.
type errSvcSealingProvider struct{}

func (errSvcSealingProvider) ProviderID() string { return "fail-v1" }
func (errSvcSealingProvider) Seal([]byte) ([]byte, string, error) {
	return nil, "", errSvcSealAlwaysFails
}
func (errSvcSealingProvider) Open([]byte, string) ([]byte, error) {
	return nil, errSvcSealAlwaysFails
}

var errSvcSealAlwaysFails = svcSealFailureSentinel{}

type svcSealFailureSentinel struct{}

func (svcSealFailureSentinel) Error() string { return "synthetic seal failure" }
