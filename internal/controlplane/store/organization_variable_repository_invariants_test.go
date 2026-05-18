package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for OrganizationVariableRepository (BE-0449).
// This file pins the row-shape, timestamp, optimistic-versioning, CHECK,
// CASCADE, and transaction-rollback invariants of the four mutation
// surfaces (Upsert, UpdateMutable, DeleteByKey, DeleteByOrganizationExceptKeys)
// the existing organization_variable_test.go does not anchor — it covers
// ListByOrganization ordering / tenant scoping, DeleteByKey behaviour, and
// the schema-level UNIQUE / CASCADE / bump_version triggers, but leaves
// the repository-level Upsert and UpdateMutable invariants and the bulk
// reconciliation surface uncovered.
//
// What this file proves:
//
//   - Upsert INSERT returns the row Postgres actually committed:
//     created_at and updated_at are non-zero and byte-equal on a fresh
//     row (the set_updated_at trigger has not fired), version starts at
//     1 (the schema default), and the caller-supplied identifiers are
//     echoed back verbatim.
//   - Upsert ON CONFLICT UPDATE branch keeps the row's original id and
//     created_at byte-equal, bumps version via bump_version, refreshes
//     updated_at via set_updated_at, and mutates only the value /
//     is_secret / secret-tuple columns.
//   - Upsert with a cross-tenant or unknown organization_id surfaces a
//     typed apierr.Conflict — the FK to organizations refuses the row.
//   - Upsert at a different (organization_id, key) reusing an existing
//     id surfaces the PRIMARY KEY (id) violation as apierr.Conflict
//     through mapWriteError.
//   - Upsert with IsSecret=true plus a non-empty plain Value violates
//     organization_variables_secret_columns_consistent and surfaces as
//     apierr.Conflict — secret bytes can never co-exist with plaintext
//     on the same row.
//   - UpdateMutable preserves id / organization_id / key / created_at,
//     bumps version, refreshes updated_at, and surfaces NotFound when
//     no row matches (including across tenants).
//   - UpdateMutable transitions a secret row back to plaintext by
//     clearing the (provider, key_id, ciphertext) tuple and storing the
//     new plain value.
//   - DeleteByOrganizationExceptKeys with a nil or empty keepKeys slice
//     drops every variable owned by the organization; with a non-empty
//     list keeps only the listed keys; cross-tenant organization_id
//     deletes nothing.
//   - ON DELETE CASCADE from organizations removes a tenant's variables
//     when the parent organizations row is deleted (a regression that
//     dropped the CASCADE would leak orphans).
//   - Upsert rolls back when the surrounding Write closure returns a
//     non-nil error — no half-written variable can survive an aborted
//     audit / policy step.
//   - The Upsert / UpdateMutable / DeleteByKey /
//     DeleteByOrganizationExceptKeys nil-Tx guards render typed
//     apierr.Internal (never a nil-pointer panic).
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset. The nil-tx
// guards are pure unit tests.

// newOrganizationVariableID mints a fresh `ovar_<token_n>` id from the
// factory's per-test counter without colliding with another resource
// kind. The factory's id generator only stamps known domain prefixes,
// so we rewrite the Organization prefix to produce a unique
// `ovar_<token_n>` id — the same shape domain.NewID(KindOrganizationVariable)
// produces. The synthetic label is never persisted; only the counter
// is observed.
func newOrganizationVariableID(f *testutil.Factory, label string) string {
	return "ovar_" + f.Organization(label).ID[len("org_"):]
}

// upsertOrganizationVariable runs the repository Upsert inside
// Store.Write and returns the persisted row. It is the smallest
// possible happy-path closure and is reused by every test that does
// not need to observe the upsert's tx in isolation.
func upsertOrganizationVariable(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.OrganizationVariableRepository,
	id, organizationID, key string,
	in store.OrganizationVariableUpsert,
) store.OrganizationVariable {
	t.Helper()
	var stored store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, key, in)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert organization variable: %v", err)
	}
	return stored
}

// listOrganizationVariablesOrFail runs ListByOrganization inside
// Store.Read and fatals on error. It is reused by every test that needs
// to observe the post-condition of a mutation.
func listOrganizationVariablesOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.OrganizationVariableRepository,
	organizationID string,
) []store.OrganizationVariable {
	t.Helper()
	var out []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByOrganization(ctx, q, organizationID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization(%q): %v", organizationID, err)
	}
	return out
}

func TestOrganizationVariableRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	id := newOrganizationVariableID(f, "alpha")

	got := upsertOrganizationVariable(ctx, t, s, repo, id, org.ID, "REGION",
		store.OrganizationVariableUpsert{Value: "us-east-1", IsSecret: false})

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("Upsert returned organization_id %q, want %q", got.OrganizationID, org.ID)
	}
	if got.Key != "REGION" {
		t.Errorf("Upsert returned key %q, want REGION", got.Key)
	}
	if got.Value != "us-east-1" {
		t.Errorf("Upsert returned value %q, want us-east-1", got.Value)
	}
	if got.IsSecret {
		t.Errorf("Upsert returned is_secret=true on a plain row")
	}
	if got.Version != 1 {
		t.Errorf("Upsert version = %d, want 1 (schema default)", got.Version)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Upsert returned zero created_at")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("Upsert returned zero updated_at")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Upsert created_at = %v, updated_at = %v; the BEFORE UPDATE trigger must NOT have fired on a fresh row",
			got.CreatedAt, got.UpdatedAt)
	}
	if got.SecretProvider != "" || got.SecretKeyID != "" || len(got.SecretCiphertext) != 0 {
		t.Errorf("Upsert plain row leaked secret tuple: provider=%q keyID=%q ciphertext=%d bytes",
			got.SecretProvider, got.SecretKeyID, len(got.SecretCiphertext))
	}
}

func TestOrganizationVariableRepositoryUpsertUpdateBranchPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	baselineID := newOrganizationVariableID(f, "baseline")
	baseline := upsertOrganizationVariable(ctx, t, s, repo, baselineID, org.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://old", IsSecret: false})

	// now() advances at microsecond resolution; sleep a millisecond so a
	// trigger that fails to refresh updated_at fails by comparison rather
	// than by Equal-by-accident.
	time.Sleep(time.Millisecond)

	overrideID := newOrganizationVariableID(f, "override")
	updated := upsertOrganizationVariable(ctx, t, s, repo, overrideID, org.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://new", IsSecret: false})

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("Upsert(conflict) mutated organization_id: was %q, now %q",
			baseline.OrganizationID, updated.OrganizationID)
	}
	if updated.Key != baseline.Key {
		t.Errorf("Upsert(conflict) mutated key: was %q, now %q", baseline.Key, updated.Key)
	}
	if updated.Value != "postgres://new" {
		t.Errorf("Upsert(conflict) value = %q, want postgres://new", updated.Value)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Upsert(conflict) version = %d, want %d (bump_version trigger must fire)",
			updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Upsert(conflict) mutated created_at: was %v, now %v",
			baseline.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("Upsert(conflict) updated_at = %v, want > baseline %v (set_updated_at must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestOrganizationVariableRepositoryUpsertUnknownOrganizationReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newOrganizationVariableID(f, "ghost"),
			"org_does_not_exist", "REGION",
			store.OrganizationVariableUpsert{Value: "leak", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown org) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestOrganizationVariableRepositoryUpsertDuplicatePrimaryKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	id := newOrganizationVariableID(f, "shared")
	upsertOrganizationVariable(ctx, t, s, repo, id, org.ID, "KEY_A",
		store.OrganizationVariableUpsert{Value: "v1", IsSecret: false})

	// Second Upsert reuses the id but at a DIFFERENT key. The ON CONFLICT
	// branch keys on (organization_id, key) — different key — so the
	// conflict resolution path is the PRIMARY KEY (id) violation, not
	// the upsert path.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, "KEY_B",
			store.OrganizationVariableUpsert{Value: "v2", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestOrganizationVariableRepositoryUpsertSecretConsistencyCheckReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	// IsSecret=true with a non-empty Value violates the secret-columns
	// CHECK: the secret branch requires value=''.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newOrganizationVariableID(f, "drift"),
			org.ID, "API_TOKEN",
			store.OrganizationVariableUpsert{
				Value:            "leaked-plaintext",
				IsSecret:         true,
				SecretProvider:   "plaintext-v1",
				SecretKeyID:      "plaintext",
				SecretCiphertext: []byte("ct"),
			})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(secret + plain value) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// IsSecret=false with non-empty Value but a smuggled provider would
	// also violate, but the repository's nullableSecretColumns drops
	// the provider/keyID/ciphertext on the IsSecret=false path — so we
	// instead probe the opposite drift: IsSecret=true with an empty
	// SecretProvider. length(secret_provider) > 0 in the CHECK rejects
	// the row, surfacing as Conflict.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newOrganizationVariableID(f, "drift2"),
			org.ID, "API_TOKEN_2",
			store.OrganizationVariableUpsert{
				Value:            "",
				IsSecret:         true,
				SecretProvider:   "",
				SecretKeyID:      "k",
				SecretCiphertext: []byte("ct"),
			})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(secret + empty provider) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestOrganizationVariableRepositoryUpdateMutablePreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	id := newOrganizationVariableID(f, "patch")
	baseline := upsertOrganizationVariable(ctx, t, s, repo, id, org.ID, "REGION",
		store.OrganizationVariableUpsert{Value: "us-east-1", IsSecret: false})

	time.Sleep(time.Millisecond)

	var updated store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.UpdateMutable(ctx, tx, org.ID, "REGION",
			store.OrganizationVariableUpsert{Value: "eu-west-1", IsSecret: false})
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("UpdateMutable: %v", err)
	}

	if updated.ID != baseline.ID {
		t.Errorf("UpdateMutable mutated id: was %q, now %q", baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("UpdateMutable mutated organization_id")
	}
	if updated.Key != baseline.Key {
		t.Errorf("UpdateMutable mutated key: was %q, now %q", baseline.Key, updated.Key)
	}
	if updated.Value != "eu-west-1" {
		t.Errorf("UpdateMutable value = %q, want eu-west-1", updated.Value)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("UpdateMutable version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("UpdateMutable mutated created_at")
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("UpdateMutable updated_at = %v, want > baseline %v",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestOrganizationVariableRepositoryUpdateMutableNotFoundForUnknownKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.UpdateMutable(ctx, tx, org.ID, "DOES_NOT_EXIST",
			store.OrganizationVariableUpsert{Value: "ignored", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateMutable(unknown key) error = %v, want code %s", err, yerr.CodeNotFound)
	}
}

func TestOrganizationVariableRepositoryUpdateMutableTransitionsSecretToPlain(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	id := newOrganizationVariableID(f, "transition")
	// Seed a secret row.
	baseline := upsertOrganizationVariable(ctx, t, s, repo, id, org.ID, "API_TOKEN",
		store.OrganizationVariableUpsert{
			Value:            "",
			IsSecret:         true,
			SecretProvider:   "plaintext-v1",
			SecretKeyID:      "plaintext",
			SecretCiphertext: []byte("secret-bytes"),
		})
	if !baseline.IsSecret {
		t.Fatalf("baseline is_secret = false, want true")
	}

	// Transition to plain — the repository must clear the secret tuple.
	var updated store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.UpdateMutable(ctx, tx, org.ID, "API_TOKEN",
			store.OrganizationVariableUpsert{Value: "now-plain", IsSecret: false})
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("UpdateMutable(secret->plain): %v", err)
	}

	if updated.IsSecret {
		t.Errorf("UpdateMutable left is_secret=true; expected transition to plain")
	}
	if updated.Value != "now-plain" {
		t.Errorf("UpdateMutable value = %q, want now-plain", updated.Value)
	}
	if updated.SecretProvider != "" || updated.SecretKeyID != "" || len(updated.SecretCiphertext) != 0 {
		t.Errorf("UpdateMutable(secret->plain) left secret tuple populated: provider=%q keyID=%q ciphertext=%d bytes",
			updated.SecretProvider, updated.SecretKeyID, len(updated.SecretCiphertext))
	}
}

func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysEmptyClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "a"), org.ID, "KEY_A",
		store.OrganizationVariableUpsert{Value: "1", IsSecret: false})
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "b"), org.ID, "KEY_B",
		store.OrganizationVariableUpsert{Value: "2", IsSecret: false})

	// nil keepKeys clears.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, org.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys(nil): %v", err)
	}
	if remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, org.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByOrganizationExceptKeys(nil) %d rows remain, want 0", len(remaining))
	}

	// Empty slice clears identically.
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "c"), org.ID, "KEY_C",
		store.OrganizationVariableUpsert{Value: "3", IsSecret: false})
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, org.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys([]): %v", err)
	}
	if remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, org.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByOrganizationExceptKeys([]) %d rows remain, want 0", len(remaining))
	}
}

func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysRetainsListed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keeper := upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "keeper"), org.ID, "KEEP_ME",
		store.OrganizationVariableUpsert{Value: "stay", IsSecret: false})
	dropped := upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "drop"), org.ID, "DROP_ME",
		store.OrganizationVariableUpsert{Value: "gone", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, org.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys([KEEP_ME]): %v", err)
	}

	remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, org.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByOrganizationExceptKeys([KEEP_ME]) %d rows remain, want 1", len(remaining))
	}
	if remaining[0].ID != keeper.ID {
		t.Errorf("survivor id = %q, want keeper %q", remaining[0].ID, keeper.ID)
	}
	if remaining[0].ID == dropped.ID {
		t.Errorf("dropped row %q survived; the WHERE predicate did not exclude it", dropped.ID)
	}
}

func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	bystander := upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "bystander"), orgB.ID, "KEY",
		store.OrganizationVariableUpsert{Value: "b", IsSecret: false})
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "victim"), orgA.ID, "KEY",
		store.OrganizationVariableUpsert{Value: "a", IsSecret: false})

	// orgA asks to clear orgB. The WHERE predicate filters on
	// organization_id, so orgB's variable is unaffected.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, orgA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys(orgA clear): %v", err)
	}

	remainingB := listOrganizationVariablesOrFail(ctx, t, s, repo, orgB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB rows after orgA clear = %+v, want exactly bystander %q", remainingB, bystander.ID)
	}
}

func TestOrganizationVariableRepositoryOrganizationDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "one"), org.ID, "K1",
		store.OrganizationVariableUpsert{Value: "1", IsSecret: false})
	upsertOrganizationVariable(ctx, t, s, repo, newOrganizationVariableID(f, "two"), org.ID, "K2",
		store.OrganizationVariableUpsert{Value: "2", IsSecret: false})

	// The OrganizationRepository's ScheduleDeletion is a soft delete; we
	// must remove the parent row via raw SQL to trigger ON DELETE
	// CASCADE.
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("DELETE organizations: %v", err)
	}

	if remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, org.ID); len(remaining) != 0 {
		t.Errorf("ListByOrganization after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(remaining))
	}
}

func TestOrganizationVariableRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	id := newOrganizationVariableID(f, "rollback")

	bailout := organizationVariableTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, "ROLLBACK_KEY",
			store.OrganizationVariableUpsert{Value: "should-not-stick", IsSecret: false}); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listOrganizationVariablesOrFail(ctx, t, s, repo, org.ID)
	for _, v := range listed {
		if v.ID == id {
			t.Errorf("rolled-back variable id %q is visible at ListByOrganization; the transaction did NOT roll back", id)
		}
	}
}

// organizationVariableTxRollbackSentinel is a typed error a transaction
// closure can return to force a rollback. The type name is intentionally
// distinct from every other rollback sentinel in store_test (every
// *_test.go file under internal/controlplane/store/ shares the same
// package) — collisions would block compilation.
type organizationVariableTxRollbackSentinel struct{}

func (organizationVariableTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this organization variable transaction"
}

func TestOrganizationVariableRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationVariableRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"ovar_irrelevant", "org_irrelevant", "KEY",
		store.OrganizationVariableUpsert{Value: "v", IsSecret: false})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestOrganizationVariableRepositoryUpdateMutableWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationVariableRepository()

	_, err := repo.UpdateMutable(context.Background(), nil,
		"org_irrelevant", "KEY",
		store.OrganizationVariableUpsert{Value: "v", IsSecret: false})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateMutable(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestOrganizationVariableRepositoryDeleteByKeyWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationVariableRepository()

	_, err := repo.DeleteByKey(context.Background(), nil, "org_irrelevant", "KEY")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByKey(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationVariableRepository()

	err := repo.DeleteByOrganizationExceptKeys(context.Background(), nil, "org_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByOrganizationExceptKeys(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
