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

// Integration tests for the encryption-at-rest seam added by BE-0339.
// They prove that an OrganizationVariableService configured with a real
// secrets.AESGCM provider seals every is_secret=true value before it
// reaches the source-of-truth table — the on-disk bytea column never
// holds the plaintext, the routing columns name the active provider/
// key, and the wire projection still redacts the customer's view.
//
// The tests skip cleanly when YALLA_TEST_DATABASE_URL is unset so
// `go test ./...` stays green without Postgres.

// mustAESGCM mints a real AES-256-GCM provider with one fresh key per
// test. Each test runs in parallel and gets its own provider so an
// assertion against the provider's active key id does not bleed across
// tests.
func mustAESGCM(t *testing.T) *secrets.AESGCM {
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

func newOrgVariableServiceWith(t *testing.T, s *store.Store, provider secrets.Provider) *store.OrganizationVariableService {
	t.Helper()
	svc, err := store.NewOrganizationVariableService(s,
		store.NewOrganizationRepository(),
		store.NewOrganizationVariableRepository(),
		store.NewAuditRepository(),
		provider)
	if err != nil {
		t.Fatalf("NewOrganizationVariableService: %v", err)
	}
	return svc
}

// TestOrganizationVariableServiceReplaceSealsSecretValuesAtRest proves
// the load-bearing contract for BE-0339: a customer-supplied secret
// value reaches Postgres only as AES-GCM ciphertext under the active
// provider's key id. The corresponding `value` column for the same row
// is the empty string the CHECK constraint requires, and the wire
// shape redacts to output.Sentinel regardless.
func TestOrganizationVariableServiceReplaceSealsSecretValuesAtRest(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustAESGCM(t)
	svc := newOrgVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "AtRest")

	const (
		plainKey      = "REGION"
		plainValue    = "us-east-1"
		secretKey     = "DB_PASSWORD"
		secretValue   = "correct-horse-battery-staple"
		actorID       = "user_actor"
		actorKind     = "user"
		requestID     = "req_atrest_seal"
		correlationID = "corr_atrest_seal"
	)
	committed, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
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
		gotSecret store.OrganizationVariable
		gotPlain  store.OrganizationVariable
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
		   FROM organization_variables
		  WHERE organization_id = $1 AND key = $2`,
		org.ID, secretKey).Scan(&rawValue, &rawIsSecret, &rawProvider, &rawKeyID, &rawCiphertext); err != nil {
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
		org.ID, org.ID).Scan(&auditAction, &auditMetadata); err != nil {
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

// TestOrganizationVariableServicePatchRotatesCiphertextOnEveryWrite
// proves that mutating only the is_secret flag (with no new value) on a
// previously-sealed row re-seals the value under a fresh nonce so a
// future re-key migration can rotate every row without surfacing the
// plaintext to the caller, and that the on-disk ciphertext changes on
// every patch (defence against a regression that accidentally returns
// the previously-sealed ciphertext verbatim).
func TestOrganizationVariableServicePatchRotatesCiphertextOnEveryWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustAESGCM(t)
	svc := newOrgVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "PatchRotate")

	const (
		secretKey   = "API_TOKEN"
		secretValue = "tok_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: secretKey, Value: secretValue, IsSecret: true},
		},
		ActorID:    "usr_actor",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	var firstCiphertext []byte
	if err := db.QueryRow(ctx,
		`SELECT secret_ciphertext FROM organization_variables WHERE organization_id = $1 AND key = $2`,
		org.ID, secretKey).Scan(&firstCiphertext); err != nil {
		t.Fatalf("first ciphertext read: %v", err)
	}

	// Patch only is_secret with no new value. The service Opens the
	// current ciphertext, then re-Seals under the active key — the
	// resulting on-disk bytes MUST differ from the original (fresh
	// nonce) and the wire shape MUST still redact.
	newSecret := true
	patched, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            secretKey,
		IsSecret:       &newSecret,
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if patched.Value != "" {
		t.Errorf("patched.Value = %q, want empty (sealed in ciphertext)", patched.Value)
	}
	if !patched.IsSecret {
		t.Errorf("patched.IsSecret = false")
	}

	var secondCiphertext []byte
	if err := db.QueryRow(ctx,
		`SELECT secret_ciphertext FROM organization_variables WHERE organization_id = $1 AND key = $2`,
		org.ID, secretKey).Scan(&secondCiphertext); err != nil {
		t.Fatalf("second ciphertext read: %v", err)
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Errorf("ciphertext did not change between writes (no nonce rotation)")
	}
	opened, openErr := provider.Open(secondCiphertext, provider.ActiveKeyID())
	if openErr != nil {
		t.Fatalf("Open after patch: %v", openErr)
	}
	if string(opened) != secretValue {
		t.Errorf("post-patch plaintext mismatch: got %q want %q", string(opened), secretValue)
	}
}

// TestOrganizationVariableServicePatchDemotesSecretToPlaintext proves
// the demotion path: a customer flipping is_secret from true to false
// (without providing a new value) yields a row whose plain `value`
// column carries the original plaintext and whose ciphertext columns
// are NULL — the CHECK constraint forbids any other state. This is
// the only customer path that surfaces a previously-sealed plaintext,
// and it is a deliberate operator action, never a side-effect of a
// read.
func TestOrganizationVariableServicePatchDemotesSecretToPlaintext(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	provider := mustAESGCM(t)
	svc := newOrgVariableServiceWith(t, s, provider)
	org := seedOrg(t, db, f, "Demote")

	const (
		key  = "FEATURE_KEY"
		seed = "feature_v1"
	)
	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables:      []store.OrganizationVariableReplace{{Key: key, Value: seed, IsSecret: true}},
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	notSecret := false
	patched, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            key,
		IsSecret:       &notSecret,
		ActorID:        "usr_actor",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("Patch demote: %v", err)
	}
	if patched.IsSecret {
		t.Errorf("patched.IsSecret = true after demotion")
	}
	if patched.Value != seed {
		t.Errorf("demoted Value = %q, want %q", patched.Value, seed)
	}
	if patched.SecretProvider != "" || patched.SecretKeyID != "" || len(patched.SecretCiphertext) != 0 {
		t.Errorf("demoted row still carries encryption metadata: provider=%q keyID=%q ciphertext_len=%d",
			patched.SecretProvider, patched.SecretKeyID, len(patched.SecretCiphertext))
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
		   FROM organization_variables WHERE organization_id = $1 AND key = $2`,
		org.ID, key).Scan(&isSecret, &val, &prov, &kid, &ct); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if isSecret || val != seed || prov != nil || kid != nil || ct != nil {
		t.Errorf("raw demoted row drift: is_secret=%v value=%q prov=%v kid=%v ct=%v",
			isSecret, val, prov, kid, ct)
	}
}

// TestOrganizationVariableSchemaRejectsPlaintextSecretWrite proves the
// database CHECK constraint is the defence-in-depth backstop the
// service relies on. A direct INSERT that tries to set is_secret=true
// with a non-empty plain value (or with NULL ciphertext columns) MUST
// fail with a constraint violation, so a future bug in the application
// layer cannot silently corrupt the at-rest state.
func TestOrganizationVariableSchemaRejectsPlaintextSecretWrite(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SchemaDefense")

	cases := []struct {
		name string
		exec string
		args []any
		mark string
	}{
		{
			name: "plain value with is_secret=true",
			exec: `INSERT INTO organization_variables (id, organization_id, key, value, is_secret) VALUES ($1, $2, 'BAD', 'plain', true)`,
			args: []any{"ovar_bad_plain_secret", org.ID},
			mark: "organization_variables_secret_columns_consistent",
		},
		{
			name: "secret columns set with is_secret=false",
			exec: `INSERT INTO organization_variables (id, organization_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, 'BAD2', 'plain', false, 'aesgcm-v1', 'abc', $3)`,
			args: []any{"ovar_bad_partial", org.ID, []byte{1, 2, 3}},
			mark: "organization_variables_secret_columns_consistent",
		},
		{
			name: "secret with empty ciphertext",
			exec: `INSERT INTO organization_variables (id, organization_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext) VALUES ($1, $2, 'BAD3', '', true, 'aesgcm-v1', 'abc', $3)`,
			args: []any{"ovar_bad_empty_ct", org.ID, []byte{}},
			mark: "organization_variables_secret_columns_consistent",
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

// TestOrganizationVariableLogValueRedactsCiphertextAndPlaintext is the
// slog-boundary defence: a log record that captures an
// OrganizationVariable cannot leak the plaintext OR the sealed
// ciphertext. The provider id and key id are exposed (they are
// already non-secret).
func TestOrganizationVariableLogValueRedactsCiphertextAndPlaintext(t *testing.T) {
	t.Parallel()
	v := store.OrganizationVariable{
		ID:               "ovar_test",
		OrganizationID:   "org_test",
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

// TestOrganizationVariableServiceReplaceFailsOnSealError proves the
// service surfaces a seal failure as apierr.Internal rather than
// leaking the plaintext. We force the failure by injecting a provider
// whose ActiveKey is the zero key — secrets.NewAESGCM rejects the
// zero-byte material, so we use a custom Provider implementation
// instead.
func TestOrganizationVariableServiceReplaceFailsOnSealError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	svc := newOrgVariableServiceWith(t, s, errSealingProvider{})
	org := seedOrg(t, db, f, "SealError")

	_, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
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

// errSealingProvider implements secrets.Provider but always fails at
// Seal time. Open is never reached on the failure path.
type errSealingProvider struct{}

func (errSealingProvider) ProviderID() string { return "fail-v1" }
func (errSealingProvider) Seal([]byte) ([]byte, string, error) {
	return nil, "", errSealAlwaysFails
}
func (errSealingProvider) Open([]byte, string) ([]byte, error) {
	return nil, errSealAlwaysFails
}

var errSealAlwaysFails = sealFailureSentinel{}

type sealFailureSentinel struct{}

func (sealFailureSentinel) Error() string { return "synthetic seal failure" }
