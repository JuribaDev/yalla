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
		&recordingQuota{},
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
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Errorf("Create code = %s, want %s", ye.Code, yerr.CodeValidation)
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

// TestAPIKeyReaderGetAPIKey covers the GET /v1/organizations/{org_id}/api-keys/{key_id}
// adapter behind the httpapi APIKeyReader port. It asserts the happy path
// (the persisted key round-trips through the reader), the tenant-scoped
// not-found path (a key id queried inside a different organization surfaces
// as a typed apierr.NotFound, never another tenant's row), and the
// missing-id path (a fabricated key id is the same typed not-found). The
// reader composes APIKeyRepository.Get, whose tenant scoping is already
// proven in TestAPIKeyRepositoryGetIsTenantScoped — this test pins the
// adapter wiring (Store.Read open-tx + repository call + error mapping) end
// to end.
func TestAPIKeyReaderGetAPIKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	other := seedOrg(t, db, f, "other-co")
	actor := seedUser(t, db, f, target, "ada")
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	svc := newAPIKeyService(t, s)
	created, err := svc.Create(ctx, store.CreateAPIKeyInput{
		OrganizationID: target.ID,
		Name:           "Ada CLI",
		Scopes:         []string{"projects:read"},
		CreatedBy:      actor,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}, time.Now())
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}

	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}

	// Happy path: the owning tenant reads its own key by id and gets the
	// persisted projection back unchanged.
	got, err := reader.GetAPIKey(ctx, target.ID, created.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned %v, want nil", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetAPIKey id = %q, want %q", got.ID, created.ID)
	}
	if got.OrganizationID != target.ID {
		t.Errorf("GetAPIKey organization_id = %q, want %q", got.OrganizationID, target.ID)
	}
	if got.Prefix != gen.Prefix {
		t.Errorf("GetAPIKey prefix = %q, want %q", got.Prefix, gen.Prefix)
	}
	if got.SecretHash != gen.SecretHash {
		t.Errorf("GetAPIKey secret_hash mismatch")
	}
	if got.Name != "Ada CLI" {
		t.Errorf("GetAPIKey name = %q, want %q", got.Name, "Ada CLI")
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "projects:read" {
		t.Errorf("GetAPIKey scopes = %v, want [projects:read]", got.Scopes)
	}

	// Cross-tenant: the other tenant queries by a valid key id that
	// belongs to target — the repository filter scopes the read by
	// organization_id first, so the row simply does not match and the
	// adapter surfaces apierr.NotFound. This is the contract that lets
	// the HTTP handler treat cross-tenant key_id as indistinguishable
	// from a missing row.
	_, err = reader.GetAPIKey(ctx, other.ID, created.ID)
	if err == nil {
		t.Fatal("cross-tenant GetAPIKey returned nil error, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("cross-tenant GetAPIKey code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	// Missing id: a fabricated key id in the owning tenant is the same
	// typed not-found.
	_, err = reader.GetAPIKey(ctx, target.ID, "key_nonexistent")
	if err == nil {
		t.Fatal("missing-id GetAPIKey returned nil error, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("missing-id GetAPIKey code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
}

// seedAPIKeyForUpdate persists an api_keys row directly through the
// repository for the update integration tests. It bypasses APIKeyService.Create
// deliberately: Create's input validation rejects the testutil factory's
// short-suffix ids, but the Update unit of work only cares that the row
// exists — the on-the-wire id format is the auth/HTTP layer's contract,
// not the store's. Using the repository keeps the seed step lightweight and
// every Update test focused on what the unit of work actually does.
func seedAPIKeyForUpdate(t *testing.T, ctx context.Context, s *store.Store, org testutil.Organization, createdBy, name string, scopes []string) store.APIKey {
	t.Helper()
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	f := testutil.NewFactory(t)
	keyID := f.APIKey(testutil.Organization{ID: org.ID}, testutil.User{ID: createdBy}, name).ID
	row := store.APIKey{
		ID:             keyID,
		OrganizationID: org.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		Name:           name,
		Scopes:         scopes,
		CreatedBy:      createdBy,
	}
	repo := store.NewAPIKeyRepository()
	var stored store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		inserted, insErr := repo.Insert(ctx, tx, row)
		if insErr != nil {
			return insErr
		}
		stored = inserted
		return nil
	}); err != nil {
		t.Fatalf("seedAPIKeyForUpdate insert: %v", err)
	}
	return stored
}

// TestAPIKeyServiceUpdateRenamesAndRescopes is the happy path: an api key
// renamed and re-scoped inside the same transaction as its audit event.
// Both the api_keys row and the audit log reflect the mutation, and the
// credential primitives (prefix and secret_hash) are preserved verbatim —
// the PATCH endpoint never rotates a credential.
func TestAPIKeyServiceUpdateRenamesAndRescopes(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read"})

	// seedAPIKeyForUpdate persists through the repository directly, so the
	// audit log is empty before Update runs — the seed is not part of the
	// unit-of-work this test exercises.
	if got := listAuditEvents(t, s, target.ID); len(got) != 0 {
		t.Fatalf("pre-update audit events = %d, want 0", len(got))
	}

	newName := "Ada CLI v2"
	newScopes := []string{"projects:read", "services:deploy"}
	updated, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Name:           &newName,
		Scopes:         &newScopes,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}
	if updated.ID != key.ID {
		t.Errorf("Update id = %q, want %q", updated.ID, key.ID)
	}
	if updated.Name != newName {
		t.Errorf("Update name = %q, want %q", updated.Name, newName)
	}
	if len(updated.Scopes) != 2 {
		t.Errorf("Update scopes = %v, want two persisted scopes", updated.Scopes)
	}
	if !updated.UpdatedAt.After(key.UpdatedAt) {
		t.Errorf("Update updated_at = %v, want strictly after the original %v", updated.UpdatedAt, key.UpdatedAt)
	}
	if updated.Prefix != key.Prefix || updated.SecretHash != key.SecretHash {
		t.Error("Update mutated the credential primitives; prefix and secret_hash must be immutable here")
	}
	if !updated.CreatedAt.Equal(key.CreatedAt) {
		t.Errorf("Update created_at = %v, want %v (immutable)", updated.CreatedAt, key.CreatedAt)
	}

	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly the update record", len(events))
	}
	updateEv := events[0]
	if updateEv.Action != "keys.manage" {
		t.Errorf("update audit action = %q, want keys.manage", updateEv.Action)
	}
	if updateEv.Decision != store.AuditDecisionAllowed {
		t.Errorf("update audit decision = %q, want allowed", updateEv.Decision)
	}
	if updateEv.ResourceID != key.ID {
		t.Errorf("update audit resource_id = %q, want %q", updateEv.ResourceID, key.ID)
	}
	if updateEv.ResourceKind != string(domain.KindAPIKey) {
		t.Errorf("update audit resource_kind = %q, want %q", updateEv.ResourceKind, domain.KindAPIKey)
	}
	if updateEv.Metadata["organization_id"] != target.ID {
		t.Errorf("update audit metadata organization_id = %q, want %q", updateEv.Metadata["organization_id"], target.ID)
	}
	if got := updateEv.Metadata["updated_fields"]; got != "name,scopes" {
		t.Errorf("update audit metadata updated_fields = %q, want %q", got, "name,scopes")
	}
	for k, v := range updateEv.Metadata {
		if v == newName || v == "services:deploy" {
			t.Errorf("update audit metadata leaks a submitted value in %q=%q", k, v)
		}
	}
}

// TestAPIKeyServiceUpdateNameOnlyPreservesScopes asserts that a patch
// naming only `name` preserves the row's existing scopes verbatim — the
// store-layer "leave unchanged" contract for a nil pointer.
func TestAPIKeyServiceUpdateNameOnlyPreservesScopes(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read", "services:deploy"})

	newName := "Renamed"
	updated, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Name:           &newName,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}
	if updated.Name != newName {
		t.Errorf("Update name = %q, want %q", updated.Name, newName)
	}
	if len(updated.Scopes) != 2 {
		t.Errorf("Update scopes = %v, want the original two scopes preserved", updated.Scopes)
	}

	events := listAuditEvents(t, s, target.ID)
	updateEv := events[len(events)-1]
	if got := updateEv.Metadata["updated_fields"]; got != "name" {
		t.Errorf("update audit metadata updated_fields = %q, want %q", got, "name")
	}
}

// TestAPIKeyServiceUpdateScopesOnlyPreservesName mirrors
// TestAPIKeyServiceUpdateNameOnlyPreservesScopes for the scopes-only patch.
func TestAPIKeyServiceUpdateScopesOnlyPreservesName(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read"})

	newScopes := []string{"services:deploy"}
	updated, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Scopes:         &newScopes,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}
	if updated.Name != "Ada CLI" {
		t.Errorf("Update name = %q, want the original name preserved", updated.Name)
	}
	if len(updated.Scopes) != 1 || updated.Scopes[0] != "services:deploy" {
		t.Errorf("Update scopes = %v, want [services:deploy]", updated.Scopes)
	}
}

// TestAPIKeyServiceUpdateEmptyScopesClearsTheArray proves that supplying an
// empty (but non-nil) scopes pointer clears the column to '{}' — the
// deliberate "revoke all scopes" semantic, distinct from omitting the field.
func TestAPIKeyServiceUpdateEmptyScopesClearsTheArray(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read", "services:deploy"})

	emptyScopes := []string{}
	updated, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Scopes:         &emptyScopes,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}
	if len(updated.Scopes) != 0 {
		t.Errorf("Update scopes = %v, want empty slice (all scopes cleared)", updated.Scopes)
	}
}

// TestAPIKeyServiceUpdateEmptyPatchIsInvalid proves a patch with no mutable
// field is the typed InvalidInput the store-layer "no field" rejection
// produces.
func TestAPIKeyServiceUpdateEmptyPatchIsInvalid(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	_, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err == nil {
		t.Fatal("Update(empty patch) error = nil, want InvalidInput")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Errorf("Update code = %s, want %s", ye.Code, yerr.CodeValidation)
	}

	// The rejection is pre-transaction, so no audit row is appended.
	// seedAPIKeyForUpdate uses the repository directly and does not record
	// its own audit row, so the log must be empty.
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — a rejected patch must leave no trail", len(events))
	}
}

// TestAPIKeyServiceUpdateMissingKeyIsNotFound proves a well-formed but
// unknown key id is the typed NotFound the HTTP layer renders as 404. The
// audit log records nothing for the failed update.
func TestAPIKeyServiceUpdateMissingKeyIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)

	ghost := domain.MustNewID(domain.KindAPIKey).String()
	newName := "Doomed rename"
	_, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          ghost,
		Name:           &newName,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err == nil {
		t.Fatal("Update(missing key) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Update code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — a failed update must leave no trail", len(events))
	}
}

// TestAPIKeyServiceUpdateCrossTenantIsNotFound proves a key id from another
// organization is the same typed NotFound — never a 5xx, never a 403, never
// a Conflict — so the endpoint cannot be used as a presence oracle for keys
// in other tenants. The store layer is the defence-in-depth backstop for
// the policy engine's cross-tenant rejection at the request edge.
func TestAPIKeyServiceUpdateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	other := seedOrg(t, db, f, "other")
	actor := seedUser(t, db, f, target, "ada")
	otherActor := seedUser(t, db, f, other, "mallory")
	svc := newAPIKeyService(t, s)

	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	newName := "Stolen"
	_, err := svc.Update(ctx, store.UpdateAPIKeyInput{
		OrganizationID: other.ID,
		KeyID:          key.ID,
		Name:           &newName,
		ActorID:        otherActor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     other.ID,
		RequestID:      "req_update",
		CorrelationID:  "corr_update",
	})
	if err == nil {
		t.Fatal("Update(cross-tenant) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Update cross-tenant code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	// seedAPIKeyForUpdate persists through the repository directly, so the
	// target tenant's audit log is empty before any cross-tenant attempt
	// runs — and remains empty after, because the failed Update never
	// records.
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("target audit events = %d, want 0 — the failed cross-tenant update must leave no trail", len(events))
	}
	if otherEvents := listAuditEvents(t, s, other.ID); len(otherEvents) != 0 {
		t.Errorf("other audit events = %d, want 0 — the failed update must leave no trail", len(otherEvents))
	}

	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	stillThere, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after cross-tenant attempt: %v", err)
	}
	if stillThere.Name != key.Name {
		t.Errorf("api key was mutated by a cross-tenant request; name = %q, want %q", stillThere.Name, key.Name)
	}
}

// TestAPIKeyServiceRevokeMarksKeyAndAudits is the happy path for the
// revoke-api-key unit of work: an api key transitions to revoked inside the
// same transaction as its audit event. The api_keys row gains a revoked_at
// stamp (and a refreshed updated_at), the credential primitives stay
// untouched (rotation is a separate endpoint), and the audit log records the
// transition exactly once with non-leaking metadata.
func TestAPIKeyServiceRevokeMarksKeyAndAudits(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read"})

	if got := listAuditEvents(t, s, target.ID); len(got) != 0 {
		t.Fatalf("pre-revoke audit events = %d, want 0", len(got))
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	revoked, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_revoke",
		CorrelationID:  "corr_revoke",
	}, now)
	if err != nil {
		t.Fatalf("Revoke returned %v, want nil", err)
	}
	if !revoked.IsRevoked() {
		t.Fatal("Revoke returned a row that is not marked revoked")
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(now) {
		t.Errorf("revoked_at = %v, want %v", revoked.RevokedAt, now)
	}
	if revoked.IsUsable(time.Now()) {
		t.Error("a revoked key reports IsUsable = true")
	}
	if !revoked.UpdatedAt.After(key.UpdatedAt) {
		t.Errorf("Revoke updated_at = %v, want strictly after the original %v",
			revoked.UpdatedAt, key.UpdatedAt)
	}
	if revoked.Prefix != key.Prefix || revoked.SecretHash != key.SecretHash {
		t.Error("Revoke mutated the credential primitives; prefix and secret_hash must be immutable")
	}
	if revoked.Name != key.Name {
		t.Errorf("Revoke renamed the key; name = %q, want %q (revocation must not edit other fields)",
			revoked.Name, key.Name)
	}
	keyEvents := listAPIKeyEvents(t, s, target.ID, key.ID)
	if len(keyEvents) != 1 {
		t.Fatalf("api key lifecycle events = %d, want exactly the revoke transition", len(keyEvents))
	}
	keyEvent := keyEvents[0]
	if keyEvent.EventType != store.APIKeyEventTypeRevoked {
		t.Errorf("api key event type = %q, want %q", keyEvent.EventType, store.APIKeyEventTypeRevoked)
	}
	if keyEvent.RequestID != "req_revoke" || keyEvent.CorrelationID != "corr_revoke" {
		t.Errorf("api key event correlation = (%q, %q), want (req_revoke, corr_revoke)",
			keyEvent.RequestID, keyEvent.CorrelationID)
	}

	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly the revoke record", len(events))
	}
	revokeEv := events[0]
	if revokeEv.Action != "keys.manage" {
		t.Errorf("revoke audit action = %q, want keys.manage", revokeEv.Action)
	}
	if revokeEv.Decision != store.AuditDecisionAllowed {
		t.Errorf("revoke audit decision = %q, want allowed", revokeEv.Decision)
	}
	if revokeEv.ResourceID != key.ID {
		t.Errorf("revoke audit resource_id = %q, want %q", revokeEv.ResourceID, key.ID)
	}
	if revokeEv.ResourceKind != string(domain.KindAPIKey) {
		t.Errorf("revoke audit resource_kind = %q, want %q", revokeEv.ResourceKind, domain.KindAPIKey)
	}
	if revokeEv.Metadata["organization_id"] != target.ID {
		t.Errorf("revoke audit metadata organization_id = %q, want %q",
			revokeEv.Metadata["organization_id"], target.ID)
	}
	if revokeEv.Metadata["revoked_at"] != now.Format(time.RFC3339Nano) {
		t.Errorf("revoke audit metadata revoked_at = %q, want %q",
			revokeEv.Metadata["revoked_at"], now.Format(time.RFC3339Nano))
	}
}

// TestAPIKeyServiceRevokeAlreadyRevokedIsConflict proves that re-revoking an
// already-revoked key is a typed Conflict, not a silent success — the
// caller's view of the resource lifecycle is stale, and the audit log
// records the first revocation only.
func TestAPIKeyServiceRevokeAlreadyRevokedIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	first := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_revoke",
		CorrelationID:  "corr_revoke",
	}, first); err != nil {
		t.Fatalf("first Revoke returned %v, want nil", err)
	}

	second := first.Add(time.Hour)
	_, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_revoke_2",
		CorrelationID:  "corr_revoke_2",
	}, second)
	if err == nil {
		t.Fatal("second Revoke returned nil, want Conflict")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("second Revoke code = %s, want %s", ye.Code, yerr.CodeConflict)
	}

	// The audit log must record only the first revocation — the rejected
	// re-revoke must leave no trail.
	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Errorf("audit events = %d, want exactly one (the first revoke)", len(events))
	}
	if events[0].Metadata["revoked_at"] != first.Format(time.RFC3339Nano) {
		t.Errorf("recorded revoked_at = %q, want the first revocation timestamp %q",
			events[0].Metadata["revoked_at"], first.Format(time.RFC3339Nano))
	}

	// The row's revoked_at must still be the first revocation: the second
	// call must not have advanced it.
	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	current, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after rejected re-revoke: %v", err)
	}
	if current.RevokedAt == nil || !current.RevokedAt.Equal(first) {
		t.Errorf("row revoked_at = %v, want %v (first timestamp preserved)", current.RevokedAt, first)
	}
}

func listAPIKeyEvents(t *testing.T, s *store.Store, organizationID, keyID string) []store.APIKeyEvent {
	t.Helper()
	events := store.NewAPIKeyEventRepository()
	var out []store.APIKeyEvent
	if err := s.Read(context.Background(), func(ctx context.Context, q store.Querier) error {
		var err error
		out, err = events.ListByAPIKey(ctx, q, organizationID, keyID)
		return err
	}); err != nil {
		t.Fatalf("list api key events: %v", err)
	}
	return out
}

// TestAPIKeyServiceRevokeMissingKeyIsNotFound proves a well-formed but
// unknown key id is the typed NotFound the HTTP layer renders as 404. The
// audit log records nothing for the failed revocation.
func TestAPIKeyServiceRevokeMissingKeyIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)

	ghost := domain.MustNewID(domain.KindAPIKey).String()
	_, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          ghost,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_revoke",
		CorrelationID:  "corr_revoke",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Revoke(missing key) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Revoke code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — a failed revoke must leave no trail", len(events))
	}
}

// TestAPIKeyServiceRevokeCrossTenantIsNotFound proves a key id from another
// organization is the same typed NotFound — never a 5xx, never a 403, never
// a Conflict — so the endpoint cannot be used as a presence oracle for keys
// in other tenants. The store layer is the defence-in-depth backstop for
// the policy engine's cross-tenant rejection at the request edge.
func TestAPIKeyServiceRevokeCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	other := seedOrg(t, db, f, "other")
	actor := seedUser(t, db, f, target, "ada")
	otherActor := seedUser(t, db, f, other, "mallory")
	svc := newAPIKeyService(t, s)

	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	_, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: other.ID,
		KeyID:          key.ID,
		ActorID:        otherActor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     other.ID,
		RequestID:      "req_revoke",
		CorrelationID:  "corr_revoke",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Revoke(cross-tenant) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Revoke cross-tenant code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("target audit events = %d, want 0 — the failed cross-tenant revoke must leave no trail", len(events))
	}
	if otherEvents := listAuditEvents(t, s, other.ID); len(otherEvents) != 0 {
		t.Errorf("other audit events = %d, want 0 — the failed revoke must leave no trail", len(otherEvents))
	}

	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	stillThere, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after cross-tenant attempt: %v", err)
	}
	if stillThere.IsRevoked() {
		t.Error("api key was revoked by a cross-tenant request; the row must be untouched")
	}
}

// TestAPIKeyServiceRevokeInvalidIDsAreRejected proves the id-shape pre-check
// rejects a blank or non-prefixed identifier as a typed InvalidInput before
// any transaction is opened. The audit log records nothing for a rejected
// request.
func TestAPIKeyServiceRevokeInvalidIDsAreRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)

	for name, in := range map[string]store.RevokeAPIKeyInput{
		"blank org": {
			OrganizationID: "",
			KeyID:          domain.MustNewID(domain.KindAPIKey).String(),
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
		"blank key": {
			OrganizationID: target.ID,
			KeyID:          "",
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
		"non-prefixed key": {
			OrganizationID: target.ID,
			KeyID:          "not-an-api-key-id",
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
	} {
		in := in
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Revoke(ctx, in, time.Now().UTC())
			if err == nil {
				t.Fatalf("Revoke(%s) error = nil, want InvalidInput", name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Errorf("Revoke(%s) code = %s, want %s", name, ye.Code, yerr.CodeValidation)
			}
		})
	}
}

// TestAPIKeyServiceRevokeRequiresActorOrgID proves a missing actor
// organization is rejected as a typed Internal — it can only happen through
// a wiring error in the calling handler, never client input, so it must
// never be disguised as an InvalidInput that a client could believe it
// caused.
func TestAPIKeyServiceRevokeRequiresActorOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	_, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		// ActorOrgID intentionally omitted to simulate a wiring error.
		RequestID:     "req_revoke",
		CorrelationID: "corr_revoke",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Revoke with no actor org error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("Revoke code = %s, want %s", ye.Code, yerr.CodeInternal)
	}
}

// TestAPIKeyServiceRotateSwapsCredentialAndAudits is the happy path of the
// rotate-api-key unit of work: a server-minted (Prefix, SecretHash) pair
// replaces the credential primitives on the row, every other field
// (identity, ownership, scopes, lifecycle) is preserved verbatim, the
// audit log records the rotation under the actor's home organization with
// the new public prefix as non-secret metadata, and the row's
// trigger-refreshed updated_at advances strictly past the original.
func TestAPIKeyServiceRotateSwapsCredentialAndAudits(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", []string{"projects:read"})

	if got := listAuditEvents(t, s, target.ID); len(got) != 0 {
		t.Fatalf("pre-rotate audit events = %d, want 0", len(got))
	}

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	if gen.Prefix == key.Prefix {
		t.Fatalf("auth.Generate returned a prefix identical to the seeded one — entropy failure")
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	rotated, err := svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, now)
	if err != nil {
		t.Fatalf("Rotate returned %v, want nil", err)
	}
	if rotated.Prefix != gen.Prefix {
		t.Errorf("Rotate prefix = %q, want the freshly minted %q", rotated.Prefix, gen.Prefix)
	}
	if rotated.SecretHash != gen.SecretHash {
		t.Errorf("Rotate secret_hash did not match the freshly minted hash")
	}
	if rotated.ID != key.ID || rotated.OrganizationID != key.OrganizationID {
		t.Errorf("Rotate changed identity: got %+v, want id=%q org=%q", rotated, key.ID, key.OrganizationID)
	}
	if rotated.Name != key.Name {
		t.Errorf("Rotate renamed the key: %q -> %q", key.Name, rotated.Name)
	}
	if len(rotated.Scopes) != len(key.Scopes) || (len(rotated.Scopes) > 0 && rotated.Scopes[0] != key.Scopes[0]) {
		t.Errorf("Rotate changed scopes: %v -> %v", key.Scopes, rotated.Scopes)
	}
	if rotated.CreatedBy != key.CreatedBy {
		t.Errorf("Rotate changed created_by: %q -> %q", key.CreatedBy, rotated.CreatedBy)
	}
	if rotated.IsRevoked() {
		t.Error("Rotate flipped revoked_at — rotation must preserve lifecycle")
	}
	if !rotated.UpdatedAt.After(key.UpdatedAt) {
		t.Errorf("Rotate updated_at = %v, want strictly after the original %v",
			rotated.UpdatedAt, key.UpdatedAt)
	}

	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly the rotate record", len(events))
	}
	rotateEv := events[0]
	if rotateEv.Action != "keys.manage" {
		t.Errorf("rotate audit action = %q, want keys.manage", rotateEv.Action)
	}
	if rotateEv.Decision != store.AuditDecisionAllowed {
		t.Errorf("rotate audit decision = %q, want allowed", rotateEv.Decision)
	}
	if rotateEv.ResourceID != key.ID {
		t.Errorf("rotate audit resource_id = %q, want %q", rotateEv.ResourceID, key.ID)
	}
	if rotateEv.ResourceKind != string(domain.KindAPIKey) {
		t.Errorf("rotate audit resource_kind = %q, want %q", rotateEv.ResourceKind, domain.KindAPIKey)
	}
	if rotateEv.Metadata["organization_id"] != target.ID {
		t.Errorf("rotate audit metadata organization_id = %q, want %q",
			rotateEv.Metadata["organization_id"], target.ID)
	}
	if rotateEv.Metadata["rotated_prefix"] != gen.Prefix {
		t.Errorf("rotate audit metadata rotated_prefix = %q, want %q",
			rotateEv.Metadata["rotated_prefix"], gen.Prefix)
	}
	// The secret hash must NEVER appear in the audit metadata.
	for k, v := range rotateEv.Metadata {
		if v == gen.SecretHash {
			t.Errorf("audit metadata field %q leaked the secret hash", k)
		}
	}
}

// TestAPIKeyServiceRotateMissingKeyIsNotFound proves a well-formed but
// unknown key id is the typed NotFound the HTTP layer renders as 404. The
// audit log records nothing for the failed rotation.
func TestAPIKeyServiceRotateMissingKeyIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	ghost := domain.MustNewID(domain.KindAPIKey).String()
	_, err = svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          ghost,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Rotate(missing key) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Rotate code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — a failed rotate must leave no trail", len(events))
	}
}

// TestAPIKeyServiceRotateCrossTenantIsNotFound proves a key id from another
// organization is the same typed NotFound — never a 5xx, never a 403,
// never a Conflict — so the endpoint cannot be used as a presence oracle
// for keys in other tenants. The store layer is the defence-in-depth
// backstop for the policy engine's cross-tenant rejection at the request
// edge, and the target row must remain untouched.
func TestAPIKeyServiceRotateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	other := seedOrg(t, db, f, "other")
	actor := seedUser(t, db, f, target, "ada")
	otherActor := seedUser(t, db, f, other, "mallory")
	svc := newAPIKeyService(t, s)

	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)
	originalPrefix := key.Prefix

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	_, err = svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: other.ID,
		KeyID:          key.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        otherActor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     other.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Rotate(cross-tenant) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("Rotate cross-tenant code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}

	if events := listAuditEvents(t, s, target.ID); len(events) != 0 {
		t.Errorf("target audit events = %d, want 0 — the failed cross-tenant rotate must leave no trail", len(events))
	}
	if otherEvents := listAuditEvents(t, s, other.ID); len(otherEvents) != 0 {
		t.Errorf("other audit events = %d, want 0 — the failed rotate must leave no trail", len(otherEvents))
	}

	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	stillThere, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after cross-tenant attempt: %v", err)
	}
	if stillThere.Prefix != originalPrefix {
		t.Errorf("api key prefix was rotated by a cross-tenant request: %q -> %q", originalPrefix, stillThere.Prefix)
	}
}

// TestAPIKeyServiceRotateRevokedKeyIsConflict proves a rotation against a
// revoked key is a typed Conflict, not a silent success. The customer must
// mint a new key through Create instead — a fresh credential body cannot
// revive a row that is permanently out of authentication service. The
// row's prefix must not change, and the audit log must not record the
// rejected rotation.
func TestAPIKeyServiceRotateRevokedKeyIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	// Revoke the key first so the lifecycle precondition fails on the
	// subsequent Rotate attempt.
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := svc.Revoke(ctx, store.RevokeAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_revoke",
		CorrelationID:  "corr_revoke",
	}, revokedAt); err != nil {
		t.Fatalf("Revoke returned %v, want nil", err)
	}

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	_, err = svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, revokedAt.Add(time.Minute))
	if err == nil {
		t.Fatal("Rotate(revoked key) error = nil, want Conflict")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("Rotate code = %s, want %s", ye.Code, yerr.CodeConflict)
	}

	// The audit log must contain only the revoke record — the rejected
	// rotate must leave no trail.
	events := listAuditEvents(t, s, target.ID)
	if len(events) != 1 {
		t.Errorf("audit events = %d, want exactly the revoke record (no rotate record)", len(events))
	}

	// The row's prefix must still be the original — the rotate must not
	// have persisted any credential change.
	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	current, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after rejected rotate: %v", err)
	}
	if current.Prefix != key.Prefix {
		t.Errorf("row prefix = %q, want %q — rejected rotate must not have changed the credential", current.Prefix, key.Prefix)
	}
}

// TestAPIKeyServiceRotateExpiredKeyIsConflict proves a rotation against a
// key whose expires_at has already passed at now is a typed Conflict.
// Like a revoked key, an expired key cannot be revived by minting a
// fresh credential body; the customer must mint a new key. The expired
// row is seeded directly through the repository so the test is decoupled
// from the Create unit of work's input validator: the property under test
// is the Rotate path's lifecycle precondition, not Create's id-shape
// rules.
func TestAPIKeyServiceRotateExpiredKeyIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)
	originalPrefix := key.Prefix

	// Stamp the row's expires_at to a point we will then advance "now"
	// past. The mutation is a direct UPDATE rather than going through
	// Create with an ExpiresAt to keep this test decoupled from any
	// id-shape validation on the Create input — the property under test
	// is the Rotate path's lifecycle precondition.
	expires := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := db.Exec(ctx, `UPDATE api_keys SET expires_at = $3 WHERE organization_id = $1 AND id = $2`,
		target.ID, key.ID, expires); err != nil {
		t.Fatalf("stamp expires_at: %v", err)
	}

	rotateGen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	// "Now" for the Rotate call is at-or-past the expiry, so the
	// lifecycle precondition fails.
	pastExpiry := expires.Add(time.Hour)
	_, err = svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Prefix:         rotateGen.Prefix,
		SecretHash:     rotateGen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, pastExpiry)
	if err == nil {
		t.Fatal("Rotate(expired key) error = nil, want Conflict")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("Rotate code = %s, want %s", ye.Code, yerr.CodeConflict)
	}

	// The audit log must contain no records — the rejected rotate must
	// leave no trail, and the seed bypassed the audit-appending unit of
	// work.
	events := listAuditEvents(t, s, target.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 — a failed rotate must leave no trail", len(events))
	}

	// The row's prefix must still be the original.
	reader, err := store.NewAPIKeyReader(s)
	if err != nil {
		t.Fatalf("NewAPIKeyReader: %v", err)
	}
	current, err := reader.GetAPIKey(ctx, target.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after rejected rotate: %v", err)
	}
	if current.Prefix != originalPrefix {
		t.Errorf("row prefix = %q, want %q — rejected rotate must not have changed the credential", current.Prefix, originalPrefix)
	}
}

// TestAPIKeyServiceRotateInvalidIDsAreRejected proves the id-shape
// pre-check rejects a blank or non-prefixed identifier as a typed
// InvalidInput before any transaction is opened. The audit log records
// nothing for a rejected request.
func TestAPIKeyServiceRotateInvalidIDsAreRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	for name, in := range map[string]store.RotateAPIKeyInput{
		"blank org": {
			OrganizationID: "",
			KeyID:          domain.MustNewID(domain.KindAPIKey).String(),
			Prefix:         gen.Prefix,
			SecretHash:     gen.SecretHash,
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
		"blank key": {
			OrganizationID: target.ID,
			KeyID:          "",
			Prefix:         gen.Prefix,
			SecretHash:     gen.SecretHash,
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
		"non-prefixed key": {
			OrganizationID: target.ID,
			KeyID:          "not-an-api-key-id",
			Prefix:         gen.Prefix,
			SecretHash:     gen.SecretHash,
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
	} {
		in := in
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Rotate(ctx, in, time.Now().UTC())
			if err == nil {
				t.Fatalf("Rotate(%s) error = nil, want InvalidInput", name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Errorf("Rotate(%s) code = %s, want %s", name, ye.Code, yerr.CodeValidation)
			}
		})
	}
}

// TestAPIKeyServiceRotateRequiresCredentialPrimitives proves an empty
// prefix or secret hash is rejected as a typed Internal — it can only
// happen through a wiring error in the calling handler (the handler is
// expected to always mint the primitives through auth.Generate), never
// client input, so it must never be disguised as an InvalidInput that
// a client could believe it caused.
func TestAPIKeyServiceRotateRequiresCredentialPrimitives(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	for name, in := range map[string]store.RotateAPIKeyInput{
		"blank prefix": {
			OrganizationID: target.ID,
			KeyID:          key.ID,
			Prefix:         "",
			SecretHash:     gen.SecretHash,
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
		"blank secret hash": {
			OrganizationID: target.ID,
			KeyID:          key.ID,
			Prefix:         gen.Prefix,
			SecretHash:     "",
			ActorID:        actor,
			ActorKind:      string(domain.KindUser),
			ActorOrgID:     target.ID,
		},
	} {
		in := in
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Rotate(ctx, in, time.Now().UTC())
			if err == nil {
				t.Fatalf("Rotate(%s) error = nil, want Internal", name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
				t.Errorf("Rotate(%s) code = %s, want %s", name, ye.Code, yerr.CodeInternal)
			}
		})
	}
}

// TestAPIKeyServiceRotateRequiresActorOrgID proves a missing actor
// organization is rejected as a typed Internal — wiring error, never
// disguised as an InvalidInput.
func TestAPIKeyServiceRotateRequiresActorOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	_, err = svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		// ActorOrgID intentionally omitted to simulate a wiring error.
		RequestID:     "req_rotate",
		CorrelationID: "corr_rotate",
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("Rotate with no actor org error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("Rotate code = %s, want %s", ye.Code, yerr.CodeInternal)
	}
}

// TestAPIKeyServiceRotateAuthenticationLookupFollowsNewPrefix is the
// integration property the rotate-endpoint contract depends on: after a
// successful rotation, the previous credential's prefix no longer matches
// any row (FindByPrefix returns the typed NotFound the auth layer maps
// to invalid-credentials), and the row's CURRENT prefix is what the
// authentication lookup finds. Rotation makes the old token immediately
// unusable through the same uniform invalid-credentials path that a
// non-existent key produces.
func TestAPIKeyServiceRotateAuthenticationLookupFollowsNewPrefix(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedUser(t, db, f, target, "ada")
	svc := newAPIKeyService(t, s)
	key := seedAPIKeyForUpdate(t, ctx, s, target, actor, "Ada CLI", nil)
	originalPrefix := key.Prefix

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}

	if _, err := svc.Rotate(ctx, store.RotateAPIKeyInput{
		OrganizationID: target.ID,
		KeyID:          key.ID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        actor,
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     target.ID,
		RequestID:      "req_rotate",
		CorrelationID:  "corr_rotate",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("Rotate returned %v, want nil", err)
	}

	// Drive the prefix-lookup the authenticator uses directly, through the
	// repository, inside a short read transaction. The old prefix must be
	// gone; the new prefix must resolve to the same key id and organization.
	repo := store.NewAPIKeyRepository()
	var (
		oldErr error
		now    store.APIKey
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, oldErr = repo.FindByPrefix(ctx, q, originalPrefix)
		var lookupErr error
		now, lookupErr = repo.FindByPrefix(ctx, q, gen.Prefix)
		return lookupErr
	}); err != nil {
		t.Fatalf("FindByPrefix new = %v, want nil", err)
	}
	if oldErr == nil {
		t.Errorf("FindByPrefix(old prefix) = nil err, want NotFound — rotated credential must be immediately unusable")
	} else if ye := yerr.From(oldErr); ye.Code != yerr.CodeNotFound {
		t.Errorf("FindByPrefix(old prefix) code = %s, want %s", ye.Code, yerr.CodeNotFound)
	}
	if now.ID != key.ID || now.OrganizationID != target.ID {
		t.Errorf("FindByPrefix(new prefix) returned %+v, want id=%q org=%q", now, key.ID, target.ID)
	}
}
