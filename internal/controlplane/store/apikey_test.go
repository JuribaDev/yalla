package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for APIKeyRepository — the persistence layer for API keys.
// They prove the prefix authentication lookup, tenant-scoped reads and
// mutations, lifecycle (expiry / revocation / last-used), conflict mapping, and
// — crucially — that no plaintext credential is ever persisted. They run
// against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

// seedUser inserts a global user row and returns its id, for the api_keys
// created_by foreign key.
func seedUser(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label string) string {
	t.Helper()
	user := f.User(org, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		user.ID, user.Email, user.Name); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return user.ID
}

// newAPIKey builds a persistence-shaped APIKey from a freshly generated
// credential. It returns both the row to persist and the generated key, so a
// test can assert the plaintext token never reaches storage.
func newAPIKey(t *testing.T, f *testutil.Factory, orgID, createdBy string) (store.APIKey, auth.GeneratedKey) {
	t.Helper()
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	keyID := f.APIKey(testutil.Organization{ID: orgID}, testutil.User{ID: createdBy}, "ci").ID
	return store.APIKey{
		ID:             keyID,
		OrganizationID: orgID,
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		Name:           "CI deploy key",
		Scopes:         []string{"projects:read", "services:deploy"},
		CreatedBy:      createdBy,
	}, gen
}

// insertAPIKey persists k through Store.Write and returns the stored row.
func insertAPIKey(ctx context.Context, t *testing.T, s *store.Store, repo *store.APIKeyRepository, k store.APIKey) store.APIKey {
	t.Helper()
	var stored store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, k)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert api key: %v", err)
	}
	return stored
}

func TestAPIKeyRepositoryInsertAndFindByPrefix(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)

	stored := insertAPIKey(ctx, t, s, repo, want)
	if stored.ID != want.ID || stored.Prefix != want.Prefix || stored.SecretHash != want.SecretHash {
		t.Fatalf("Insert returned %+v, want id/prefix/hash from %+v", stored, want)
	}
	if stored.CreatedBy != createdBy {
		t.Errorf("stored.CreatedBy = %q, want %q", stored.CreatedBy, createdBy)
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Error("Insert did not return the database-assigned timestamps")
	}

	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.FindByPrefix(ctx, q, want.Prefix)
		return err
	}); err != nil {
		t.Fatalf("FindByPrefix returned %v, want nil", err)
	}
	if got.ID != want.ID || got.OrganizationID != org.ID {
		t.Errorf("FindByPrefix returned %+v, want id %q in org %q", got, want.ID, org.ID)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("FindByPrefix scopes = %v, want the two persisted scopes", got.Scopes)
	}
}

func TestAPIKeyRepositoryFindByPrefixNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	ctx := context.Background()

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	err = s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, findErr := repo.FindByPrefix(ctx, q, gen.Prefix) // never inserted
		return findErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("FindByPrefix(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestAPIKeyRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyA, _ := newAPIKey(t, f, orgA.ID, "")
	insertAPIKey(ctx, t, s, repo, keyA)

	// orgB must not be able to read orgA's key by id.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgB.ID, keyA.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgA still sees its own key.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgA.ID, keyA.ID)
		return getErr
	}); err != nil {
		t.Errorf("owner Get returned %v, want the key", err)
	}
}

func TestAPIKeyRepositoryListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	for i := 0; i < 3; i++ {
		k, _ := newAPIKey(t, f, orgA.ID, "")
		insertAPIKey(ctx, t, s, repo, k)
	}
	kB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, kB)

	var listA, listB []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		if listA, err = repo.ListByOrganization(ctx, q, orgA.ID); err != nil {
			return err
		}
		listB, err = repo.ListByOrganization(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listA) != 3 {
		t.Errorf("orgA list = %d keys, want 3", len(listA))
	}
	if len(listB) != 1 {
		t.Errorf("orgB list = %d keys, want 1 (tenant scoped)", len(listB))
	}
	for _, k := range listA {
		if k.OrganizationID != orgA.ID {
			t.Errorf("orgA list contains a key owned by %q", k.OrganizationID)
		}
	}
}

func TestAPIKeyRepositoryTouchLastUsed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	key, _ := newAPIKey(t, f, org.ID, "")
	stored := insertAPIKey(ctx, t, s, repo, key)
	if stored.LastUsedAt != nil {
		t.Fatal("a freshly inserted key already has last_used_at set")
	}

	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.TouchLastUsed(ctx, tx, org.ID, key.ID, usedAt)
	}); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}

	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, key.ID)
		return err
	}); err != nil {
		t.Fatalf("Get after TouchLastUsed: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(usedAt) {
		t.Errorf("last_used_at = %v, want %v", got.LastUsedAt, usedAt)
	}

	// A cross-tenant touch must not match the row.
	otherOrg := seedOrg(t, db, f, "intruder")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.TouchLastUsed(ctx, tx, otherOrg.ID, key.ID, usedAt)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant TouchLastUsed error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestAPIKeyRepositoryRevokeIsIdempotentAndTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	key, _ := newAPIKey(t, f, org.ID, "")
	insertAPIKey(ctx, t, s, repo, key)

	firstRevoke := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Revoke(ctx, tx, org.ID, key.ID, firstRevoke)
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revoking again is a no-op success and preserves the first timestamp.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Revoke(ctx, tx, org.ID, key.ID, firstRevoke.Add(time.Hour))
	}); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}

	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, key.ID)
		return err
	}); err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if !got.IsRevoked() {
		t.Fatal("key is not marked revoked after Revoke")
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(firstRevoke) {
		t.Errorf("revoked_at = %v, want the first revocation time %v", got.RevokedAt, firstRevoke)
	}
	if got.IsUsable(time.Now()) {
		t.Error("a revoked key reports IsUsable = true")
	}

	// A cross-tenant revoke must not match the row.
	otherOrg := seedOrg(t, db, f, "intruder")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Revoke(ctx, tx, otherOrg.ID, key.ID, firstRevoke)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Revoke error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestAPIKeyRepositoryInsertDuplicatePrefixConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	first, _ := newAPIKey(t, f, org.ID, "")
	insertAPIKey(ctx, t, s, repo, first)

	// A second key, distinct id, but colliding on the unique prefix.
	dup, _ := newAPIKey(t, f, org.ID, "")
	dup.Prefix = first.Prefix

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, dup)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-prefix Insert error code = %v, want %s", err, yerr.CodeConflict)
	}
}

func TestAPIKeyRepositoryInsertRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()
	if _, err := repo.Insert(context.Background(), nil, store.APIKey{}); err == nil {
		t.Fatal("Insert(nil tx) error = nil, want an error")
	}
}

func TestAPIKeyRepositoryExpiryRoundTrips(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	key, _ := newAPIKey(t, f, org.ID, "")
	key.ExpiresAt = &expiresAt

	insertAPIKey(ctx, t, s, repo, key)

	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.FindByPrefix(ctx, q, key.Prefix)
		return err
	}); err != nil {
		t.Fatalf("FindByPrefix: %v", err)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, expiresAt)
	}
	if !got.IsUsable(time.Now()) {
		t.Error("a not-yet-expired, unrevoked key reports IsUsable = false")
	}
	if got.IsUsable(expiresAt.Add(time.Second)) {
		t.Error("a key reports IsUsable = true past its expiry")
	}
}

func TestAPIKeyPlaintextIsNeverPersisted(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	key, gen := newAPIKey(t, f, org.ID, "")
	insertAPIKey(ctx, t, s, repo, key)

	_, secret, err := auth.ParseToken(gen.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}

	// Concatenate every text-bearing column of the persisted row and prove
	// neither the full plaintext token nor the bare secret body appears in any
	// of them — only the one-way hash and the public prefix are stored.
	var rowText string
	if err := db.QueryRow(ctx, `
		SELECT id || '|' || organization_id || '|' || prefix || '|' ||
		       secret_hash || '|' || name || '|' ||
		       coalesce(created_by, '') || '|' || array_to_string(scopes, ',')
		FROM api_keys WHERE id = $1`, key.ID).Scan(&rowText); err != nil {
		t.Fatalf("read persisted row: %v", err)
	}
	testutil.AssertRedacted(t, rowText, gen.Token.Reveal(), secret)

	if !auth.VerifySecret(secret, key.SecretHash) {
		t.Error("the persisted hash does not verify against the original secret")
	}
}

// TestAPIKeyLifecycleHelpers exercises the pure lifecycle predicates without a
// database, so it runs even when YALLA_TEST_DATABASE_URL is unset.
func TestAPIKeyLifecycleHelpers(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	active := store.APIKey{}
	if active.IsRevoked() || active.IsExpired(now) || !active.IsUsable(now) {
		t.Error("a key with no expiry and no revocation should be usable")
	}

	revoked := store.APIKey{RevokedAt: &past}
	if !revoked.IsRevoked() || revoked.IsUsable(now) {
		t.Error("a revoked key must report IsRevoked and not be usable")
	}

	expired := store.APIKey{ExpiresAt: &past}
	if !expired.IsExpired(now) || expired.IsUsable(now) {
		t.Error("a key past its expiry must report IsExpired and not be usable")
	}

	notYetExpired := store.APIKey{ExpiresAt: &future}
	if notYetExpired.IsExpired(now) || !notYetExpired.IsUsable(now) {
		t.Error("a key before its expiry must be usable")
	}
}
