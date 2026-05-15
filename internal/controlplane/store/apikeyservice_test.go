package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for APIKeyService — the mint-api-key unit of work behind
// POST /v1/organizations/{org_id}/api-keys. They prove the api_keys row and
// its immutable audit record are committed atomically, that a missing
// organization or service account surfaces as a typed NotFound, that an
// invalid request never opens a transaction, and — crucially — that no
// plaintext credential ever reaches the database. They run against an
// isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

func newAPIKeyService(t *testing.T, s *store.Store) *store.APIKeyService {
	t.Helper()
	svc, err := store.NewAPIKeyService(
		s,
		store.NewOrganizationRepository(),
		store.NewServiceAccountRepository(),
		store.NewAPIKeyRepository(),
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewAPIKeyService: %v", err)
	}
	return svc
}

func TestAPIKeyServiceCreate(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, target, "ada")

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	svc := newAPIKeyService(t, s)

	created, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID: target.ID,
		Name:           "Ada's CLI key",
		Scopes:         []string{"projects:read", "services:deploy"},
		CreatedBy:      createdBy,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        createdBy,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}, time.Now())
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ID == "" || created.OrganizationID != target.ID {
		t.Errorf("Create returned %+v, want a key in %q", created, target.ID)
	}
	if created.Prefix != gen.Prefix {
		t.Errorf("Create prefix = %q, want %q", created.Prefix, gen.Prefix)
	}
	if created.SecretHash != gen.SecretHash {
		t.Errorf("Create secret_hash mismatch")
	}
	if len(created.Scopes) != 2 {
		t.Errorf("Create scopes = %v, want the two persisted scopes", created.Scopes)
	}
	if created.CreatedBy != createdBy {
		t.Errorf("Create created_by = %q, want %q", created.CreatedBy, createdBy)
	}
	if created.ServiceAccountID != "" {
		t.Errorf("Create service_account_id = %q, want empty for a human-owned key", created.ServiceAccountID)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("Create did not return the database-assigned timestamps")
	}

	// The key is readable back through the GET endpoint's reader.
	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	keys, err := reader.ListAPIKeys(ctx, target.ID)
	if err != nil {
		t.Fatalf("ListAPIKeys returned %v, want nil", err)
	}
	if len(keys) != 1 || keys[0].ID != created.ID {
		t.Errorf("ListAPIKeys returned %+v, want exactly the created key", keys)
	}

	// The audit event is filed under the actor's home organization and
	// names the minted key as its resource. The metadata captures the
	// target tenant, the scope count, and whether the key has an expiry —
	// all non-secret values — so the rendered token, prefix, and hash
	// never appear.
	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the mint", len(events))
	}
	ev := events[0]
	if ev.Action != "keys.manage" {
		t.Errorf("audit action = %q, want keys.manage", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want the minted key id %q", ev.ResourceID, created.ID)
	}
	if ev.ResourceKind != string(domain.KindAPIKey) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindAPIKey)
	}
	if ev.Metadata["organization_id"] != target.ID {
		t.Errorf("audit metadata organization_id = %q, want %q", ev.Metadata["organization_id"], target.ID)
	}
	if ev.Metadata["scope_count"] != "2" {
		t.Errorf("audit metadata scope_count = %q, want 2", ev.Metadata["scope_count"])
	}
	if ev.Metadata["has_expiry"] != "false" {
		t.Errorf("audit metadata has_expiry = %q, want false", ev.Metadata["has_expiry"])
	}
	if _, present := ev.Metadata["service_account_id"]; present {
		t.Errorf("audit metadata contains service_account_id for a human-owned key: %+v", ev.Metadata)
	}
	// No audit metadata field may carry the plaintext token, the prefix, or
	// the secret hash.
	for k, v := range ev.Metadata {
		if v == gen.Prefix || v == gen.SecretHash || v == gen.Token.Reveal() {
			t.Errorf("audit metadata leaks credential material in %q=%q", k, v)
		}
	}
}

// TestAPIKeyServiceCreateWithServiceAccountAndExpiry covers the second-class
// shapes: a service-account-owned key with an expires_at. The audit
// metadata reflects both.
func TestAPIKeyServiceCreateWithServiceAccountAndExpiry(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	saID := seedServiceAccount(t, db, f, target, "ci").ID

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	expires := time.Now().Add(48 * time.Hour).UTC()
	svc := newAPIKeyService(t, s)

	created, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID:   target.ID,
		Name:             "CI deploy key",
		Scopes:           []string{"services:deploy"},
		ExpiresAt:        &expires,
		ServiceAccountID: saID,
		CreatedBy:        actor,
		Prefix:           gen.Prefix,
		SecretHash:       gen.SecretHash,
		ActorID:          actor,
		ActorKind:        string(domain.KindUser),
		ActorOrgID:       target.ID,
		RequestID:        "req_test",
		CorrelationID:    "corr_test",
	}, time.Now())
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ServiceAccountID != saID {
		t.Errorf("Create service_account_id = %q, want %q", created.ServiceAccountID, saID)
	}
	if created.ExpiresAt == nil || !created.ExpiresAt.Equal(expires) {
		t.Errorf("Create expires_at = %v, want %v", created.ExpiresAt, expires)
	}

	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one", len(events))
	}
	if events[0].Metadata["service_account_id"] != saID {
		t.Errorf("audit metadata service_account_id = %q, want %q", events[0].Metadata["service_account_id"], saID)
	}
	if events[0].Metadata["has_expiry"] != "true" {
		t.Errorf("audit metadata has_expiry = %q, want true", events[0].Metadata["has_expiry"])
	}
}

// TestAPIKeyServiceCreateMissingOrgIsNotFound proves a well-formed but
// unknown organization id is the typed NotFound — never a Conflict or an
// Internal — so the HTTP layer renders 404.
func TestAPIKeyServiceCreateMissingOrgIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actorOrg := seedOrg(t, db, f, "actor-co")
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	ghost := f.Organization("ghost")

	svc := newAPIKeyService(t, s)
	_, err = svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID: ghost.ID,
		Name:           "Doomed key",
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        "usr_ada",
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     actorOrg.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}, time.Now())
	if err == nil {
		t.Fatal("Create returned nil, want NotFound for an unknown organization")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Create code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	// The audit record is rolled back with the failure: no row should exist
	// for the actor's organization.
	if events := listAuditEvents(t, s, actorOrg.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — the failed mint must not leave a trail", len(events))
	}
}

// TestAPIKeyServiceCreateUnknownServiceAccountIsNotFound proves a
// service_account_id that does not exist in the target tenant rolls the
// whole transaction back as NotFound. No api_keys row is persisted, no
// audit record survives.
func TestAPIKeyServiceCreateUnknownServiceAccountIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	ghostSA := f.ServiceAccount(target, "ghost-sa").ID

	svc := newAPIKeyService(t, s)
	_, err = svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID:   target.ID,
		Name:             "Doomed CI key",
		ServiceAccountID: ghostSA,
		Prefix:           gen.Prefix,
		SecretHash:       gen.SecretHash,
		ActorID:          "usr_ada",
		ActorKind:        string(domain.KindUser),
		ActorOrgID:       target.ID,
		RequestID:        "req_test",
		CorrelationID:    "corr_test",
	}, time.Now())
	if err == nil {
		t.Fatal("Create returned nil, want NotFound for an unknown service account")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Create code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	reader, _ := store.NewAPIKeyReader(s)
	if keys, _ := reader.ListAPIKeys(ctx, target.ID); len(keys) != 0 {
		t.Errorf("ListAPIKeys = %v, want 0 keys — the failed mint must not leave a row", keys)
	}
}

// TestAPIKeyServiceCreateCrossTenantServiceAccountIsNotFound proves a
// service account that exists in a different tenant cannot be used to mint
// a key inside the target tenant. The repository read is tenant scoped, so
// the cross-tenant id matches no row and surfaces as the same 404 a
// missing id produces.
func TestAPIKeyServiceCreateCrossTenantServiceAccountIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	other := seedOrg(t, db, f, "other-co")
	foreignSA := seedServiceAccount(t, db, f, other, "ci").ID
	gen, _ := auth.Generate()

	svc := newAPIKeyService(t, s)
	_, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID:   target.ID,
		Name:             "Cross-tenant key",
		ServiceAccountID: foreignSA,
		Prefix:           gen.Prefix,
		SecretHash:       gen.SecretHash,
		ActorID:          "usr_ada",
		ActorKind:        string(domain.KindUser),
		ActorOrgID:       target.ID,
		RequestID:        "req_test",
		CorrelationID:    "corr_test",
	}, time.Now())
	if err == nil {
		t.Fatal("Create returned nil, want NotFound for a cross-tenant service account")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Create code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
}

// TestAPIKeyServiceCreateInvalidInputDoesNotOpenTransaction proves the
// validator runs before Store.Write — an obviously-bad request never touches
// the database. We assert this by giving the service a target organization
// that does exist and a malformed name: if the validator did not stop the
// flow, the transaction would open, the org lookup would succeed, and the
// row would insert (or fail at the database). The expected outcome is the
// typed 400 with no key written and no audit row.
func TestAPIKeyServiceCreateInvalidInputDoesNotOpenTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	gen, _ := auth.Generate()

	svc := newAPIKeyService(t, s)
	_, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID: target.ID,
		Name:           "   ", // blank name -> InvalidInput
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        "usr_ada",
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}, time.Now())
	if err == nil {
		t.Fatal("Create returned nil, want InvalidInput")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
		t.Errorf("Create code = %s, want %s", ye.Code, yerr.CodeInvalidInput)
	}

	reader, _ := store.NewAPIKeyReader(s)
	if keys, _ := reader.ListAPIKeys(ctx, target.ID); len(keys) != 0 {
		t.Errorf("ListAPIKeys = %v, want 0 keys", keys)
	}
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0", len(events))
	}
}

// TestAPIKeyServiceCreateDoesNotPersistPlaintext proves no plaintext
// credential ever reaches the database — the api_keys row stores only the
// public Prefix and the one-way SecretHash. This is the central security
// guarantee of the table; it is asserted by reading the raw row back and
// scanning every text column for the plaintext.
func TestAPIKeyServiceCreateDoesNotPersistPlaintext(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, target, "ada")
	gen, _ := auth.Generate()

	svc := newAPIKeyService(t, s)
	created, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID: target.ID,
		Name:           "Ada CLI",
		CreatedBy:      createdBy,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        createdBy,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}, time.Now())
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}

	plaintext := gen.Token.Reveal()
	if plaintext == "" {
		t.Fatal("auth.Generate produced an empty plaintext token; the test pre-condition is broken")
	}
	var leak struct {
		name        string
		prefix      string
		secretHash  string
		scopesGlued string
	}
	if err := db.QueryRow(ctx,
		`SELECT name, prefix, secret_hash, array_to_string(scopes, ',')
		 FROM api_keys WHERE id = $1`,
		created.ID,
	).Scan(&leak.name, &leak.prefix, &leak.secretHash, &leak.scopesGlued); err != nil {
		t.Fatalf("scan persisted api_keys row: %v", err)
	}
	for column, val := range map[string]string{
		"name":        leak.name,
		"prefix":      leak.prefix,
		"secret_hash": leak.secretHash,
		"scopes":      leak.scopesGlued,
	} {
		if val == plaintext {
			t.Errorf("column %q stores the plaintext token", column)
		}
	}
	if leak.prefix != gen.Prefix {
		t.Errorf("persisted prefix = %q, want %q", leak.prefix, gen.Prefix)
	}
	if leak.secretHash != gen.SecretHash {
		t.Errorf("persisted secret_hash != generated hash")
	}
}
