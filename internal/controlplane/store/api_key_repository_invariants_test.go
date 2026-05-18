package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for APIKeyRepository's CRUD invariants (BE-0433). The
// repository's tenant-scoping contract (Get / ListByOrganization /
// ListByServiceAccount / UpdateMutable / Revoke / RotateCredential /
// TouchLastUsed filter by organization_id before id) and prefix-uniqueness
// conflict mapping are proved in apikey_test.go alongside the
// APIKeyRepository unit-of-work tests. What this file proves are the row-shape
// and lifecycle invariants the api_keys table owes its callers regardless of
// who else is around:
//
//   - Insert returns the row the database actually committed: created_at and
//     updated_at are non-zero and equal on a fresh row (no UPDATE has fired
//     yet, so the api_keys_set_updated_at trigger has not run), the lifecycle
//     stamps (revoked_at / expires_at / last_used_at) are nil on a freshly
//     minted key, scopes round-trips as a non-nil slice (the schema default
//     is NOT NULL DEFAULT '{}'), and the credential primitives the caller
//     supplied (prefix / secret_hash) are echoed back verbatim.
//   - UpdateMutable refreshes updated_at via the BEFORE UPDATE trigger and
//     preserves created_at — the same dual-anchor lifecycle assertion every
//     other domain table's mutation must honor — while leaving every
//     non-mutable column (prefix, secret_hash, created_by,
//     service_account_id, expires_at, revoked_at, last_used_at) byte-identical
//     to the baseline. The mutable surface is exactly {name, scopes}.
//   - Revoke refreshes updated_at and preserves created_at while stamping
//     revoked_at; the COALESCE-idempotent second-call semantics are anchored
//     separately in apikey_test.go's
//     TestAPIKeyRepositoryRevokeIsIdempotentAndTenantScoped, this file
//     anchors the dual-anchor timestamp pair so a future refactor that
//     dropped the trigger does not silently freeze updated_at while keeping
//     every other contract.
//   - RotateCredential refreshes updated_at, preserves created_at, swaps the
//     credential primitives (prefix and secret_hash) for the supplied new
//     values, and leaves identity / ownership / scopes / lifecycle stamps
//     byte-identical — rotation is a credential swap, not a re-mint, so
//     audit trails and outstanding access grants keep pointing at the same
//     key id.
//   - TouchLastUsed refreshes updated_at and preserves created_at while
//     stamping last_used_at; the existing apikey_test.go case anchors the
//     last_used_at value alone, this file pins the dual-anchor pair so the
//     trigger contract holds for the auth path the same way it does for
//     mutation paths.
//   - Insert rolls back when the surrounding Write closure returns a non-nil
//     error: the transaction is the unit of work, and no half-written API
//     key can survive an aborted audit/policy step that runs alongside it.
//     For an api_keys row the rollback proof is doubly load-bearing —
//     api_keys is the only customer-data table whose row body carries a
//     secret-bearing field (secret_hash), so the rollback test must also
//     prove no row anywhere in api_keys still carries the rolled-back
//     secret_hash; a future refactor that switched Insert to a SAVEPOINT
//     or autonomous transaction would otherwise leak the credential primitive
//     even though Get-by-id reports NotFound.
//   - The Insert / UpdateMutable / Revoke / RotateCredential / TouchLastUsed
//     guards against a nil *Tx argument render a typed apierr.Internal —
//     never a nil-pointer panic — so a caller that forgets to open a write
//     transaction is caught by the typed-error contract instead of by
//     SIGSEGV. The pre-existing TestAPIKeyRepositoryInsertRejectsNilTx in
//     apikey_test.go only asserts a non-nil error; this file's typed-code
//     companions are the canonical row in the typed-error matrix the rest
//     of the repository templates use.
//
// Repository tenant isolation (cross-tenant Get / List / UpdateMutable /
// Revoke / RotateCredential / TouchLastUsed, the byte-identical-bystander
// proof, and the secret_hash needle absence in cross-tenant probes) is the
// subject of BE-0434 and will live in api_key_tenant_isolation_test.go.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// TestAPIKeyRepositoryInsertReturnsRowWithTimestamps proves Insert returns
// the row the table actually committed: created_at and updated_at are both
// non-zero and equal to each other (no UPDATE has fired yet, so the
// api_keys_set_updated_at trigger has not run), the lifecycle stamps
// (revoked_at / expires_at / last_used_at) are nil on a freshly minted key,
// scopes round-trips as the caller-supplied non-nil slice, and the
// credential primitives the caller supplied are echoed back verbatim.
func TestAPIKeyRepositoryInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)

	created := insertAPIKey(ctx, t, s, repo, want)

	if created.ID != want.ID {
		t.Errorf("Insert returned id %q, want %q", created.ID, want.ID)
	}
	if created.OrganizationID != want.OrganizationID {
		t.Errorf("Insert returned organization_id %q, want %q", created.OrganizationID, want.OrganizationID)
	}
	if created.Prefix != want.Prefix {
		t.Errorf("Insert returned prefix %q, want %q", created.Prefix, want.Prefix)
	}
	if created.SecretHash != want.SecretHash {
		t.Errorf("Insert returned secret_hash %q, want %q (the caller-supplied hash must round-trip verbatim)",
			created.SecretHash, want.SecretHash)
	}
	if created.Name != want.Name {
		t.Errorf("Insert returned name %q, want %q", created.Name, want.Name)
	}
	if created.CreatedBy != createdBy {
		t.Errorf("Insert returned created_by %q, want %q", created.CreatedBy, createdBy)
	}
	if created.ServiceAccountID != "" {
		t.Errorf("Insert returned service_account_id %q, want empty for a human-minted key",
			created.ServiceAccountID)
	}
	if created.ExpiresAt != nil {
		t.Errorf("Insert returned expires_at %v, want nil on a freshly minted key", created.ExpiresAt)
	}
	if created.RevokedAt != nil {
		t.Errorf("Insert returned revoked_at %v, want nil on a freshly minted key", created.RevokedAt)
	}
	if created.LastUsedAt != nil {
		t.Errorf("Insert returned last_used_at %v, want nil on a freshly minted key", created.LastUsedAt)
	}
	if created.Scopes == nil {
		t.Error("Insert returned scopes = nil; the api_keys.scopes column is NOT NULL DEFAULT '{}', so it must surface as a non-nil slice")
	}
	if len(created.Scopes) != len(want.Scopes) {
		t.Errorf("Insert returned %d scopes, want %d", len(created.Scopes), len(want.Scopes))
	}

	// created_at and updated_at must be non-zero and byte-equal on a freshly
	// inserted row — the BEFORE UPDATE trigger has not yet fired, so the two
	// columns share the INSERT-time clock reading. A trigger that
	// accidentally fired on INSERT would defeat the dual-anchor property the
	// UpdateMutable / Revoke / RotateCredential / TouchLastUsed assertions
	// below rely on.
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("Insert returned zero timestamps: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}
	if !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Insert created_at=%v updated_at=%v: want equal on a fresh row (no UPDATE has fired)",
			created.CreatedAt, created.UpdatedAt)
	}

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value Insert
	// returned.
	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("after-Insert Get returned %v, want nil", err)
	}
	if got.ID != created.ID ||
		got.OrganizationID != created.OrganizationID ||
		got.Prefix != created.Prefix ||
		got.SecretHash != created.SecretHash ||
		got.Name != created.Name ||
		got.CreatedBy != created.CreatedBy ||
		!got.CreatedAt.Equal(created.CreatedAt) ||
		!got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get-after-Insert returned %+v, want %+v", got, created)
	}
}

// TestAPIKeyRepositoryUpdateMutableRefreshesUpdatedAtAndPreservesCreatedAt
// proves a successful UpdateMutable refreshes updated_at via the
// api_keys_set_updated_at BEFORE UPDATE trigger and preserves created_at,
// and that the mutable surface is exactly {name, scopes} — every non-mutable
// column (prefix, secret_hash, created_by, service_account_id, expires_at,
// revoked_at, last_used_at) is byte-identical to the baseline.
func TestAPIKeyRepositoryUpdateMutableRefreshesUpdatedAtAndPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)
	baseline := insertAPIKey(ctx, t, s, repo, want)

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	newName := "renamed deploy key"
	newScopes := []string{"projects:read", "services:read"}

	var updated store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.UpdateMutable(ctx, tx, org.ID, baseline.ID, newName, newScopes)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("UpdateMutable returned %v, want nil", err)
	}

	if updated.Name != newName {
		t.Errorf("UpdateMutable returned name %q, want %q", updated.Name, newName)
	}
	if len(updated.Scopes) != len(newScopes) {
		t.Errorf("UpdateMutable returned %d scopes, want %d", len(updated.Scopes), len(newScopes))
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("UpdateMutable mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if updated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("UpdateMutable updated_at = %v, want >= baseline %v (trigger must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}

	// Non-mutable columns must be byte-identical to the baseline.
	if updated.Prefix != baseline.Prefix {
		t.Errorf("UpdateMutable rotated prefix: was %q, now %q (rotation belongs to RotateCredential)",
			baseline.Prefix, updated.Prefix)
	}
	if updated.SecretHash != baseline.SecretHash {
		t.Errorf("UpdateMutable rotated secret_hash (rotation belongs to RotateCredential)")
	}
	if updated.CreatedBy != baseline.CreatedBy {
		t.Errorf("UpdateMutable rewrote created_by: was %q, now %q", baseline.CreatedBy, updated.CreatedBy)
	}
	if updated.ServiceAccountID != baseline.ServiceAccountID {
		t.Errorf("UpdateMutable rewrote service_account_id: was %q, now %q",
			baseline.ServiceAccountID, updated.ServiceAccountID)
	}
	if !equalTimePtr(updated.ExpiresAt, baseline.ExpiresAt) {
		t.Errorf("UpdateMutable rewrote expires_at: was %v, now %v", baseline.ExpiresAt, updated.ExpiresAt)
	}
	if !equalTimePtr(updated.RevokedAt, baseline.RevokedAt) {
		t.Errorf("UpdateMutable rewrote revoked_at: was %v, now %v", baseline.RevokedAt, updated.RevokedAt)
	}
	if !equalTimePtr(updated.LastUsedAt, baseline.LastUsedAt) {
		t.Errorf("UpdateMutable rewrote last_used_at: was %v, now %v", baseline.LastUsedAt, updated.LastUsedAt)
	}

	// Database read-back confirms the trigger-refreshed updated_at and the
	// preserved created_at are durable, not just the in-memory shape.
	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, baseline.ID)
		return err
	}); err != nil {
		t.Fatalf("post-UpdateMutable Get returned %v, want nil", err)
	}
	if !got.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("post-UpdateMutable Get created_at = %v, want %v", got.CreatedAt, baseline.CreatedAt)
	}
	if !got.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Errorf("post-UpdateMutable Get updated_at = %v, want %v", got.UpdatedAt, updated.UpdatedAt)
	}
}

// TestAPIKeyRepositoryRevokeRefreshesUpdatedAtAndPreservesCreatedAt proves
// Revoke refreshes updated_at via the BEFORE UPDATE trigger, preserves
// created_at, and stamps revoked_at — the same dual-anchor lifecycle
// assertion every other domain table's mutation must honor. The
// idempotent-COALESCE behavior on a second Revoke is anchored separately in
// apikey_test.go's TestAPIKeyRepositoryRevokeIsIdempotentAndTenantScoped;
// this test anchors the dual-anchor timestamp pair specifically.
func TestAPIKeyRepositoryRevokeRefreshesUpdatedAtAndPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)
	baseline := insertAPIKey(ctx, t, s, repo, want)

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	var revoked store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Revoke(ctx, tx, org.ID, baseline.ID, revokedAt)
		if err != nil {
			return err
		}
		revoked = row
		return nil
	}); err != nil {
		t.Fatalf("Revoke returned %v, want nil", err)
	}

	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Errorf("Revoke returned revoked_at = %v, want %v", revoked.RevokedAt, revokedAt)
	}
	if !revoked.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Revoke mutated created_at: was %v, now %v", baseline.CreatedAt, revoked.CreatedAt)
	}
	if revoked.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("Revoke updated_at = %v, want >= baseline %v (trigger must refresh)",
			revoked.UpdatedAt, baseline.UpdatedAt)
	}
	if revoked.Prefix != baseline.Prefix || revoked.SecretHash != baseline.SecretHash {
		t.Errorf("Revoke rotated credential primitives: prefix=%q→%q, secret_hash rotated=%t",
			baseline.Prefix, revoked.Prefix, revoked.SecretHash != baseline.SecretHash)
	}
}

// TestAPIKeyRepositoryRotateCredentialRefreshesUpdatedAtAndPreservesIdentity
// proves RotateCredential refreshes updated_at via the BEFORE UPDATE
// trigger, preserves created_at, and swaps the credential primitives
// (prefix and secret_hash) for the supplied new values while leaving
// identity / ownership / scopes / lifecycle stamps byte-identical to the
// baseline — rotation is a credential swap, not a re-mint, so audit trails
// and outstanding access grants keep pointing at the same key id.
func TestAPIKeyRepositoryRotateCredentialRefreshesUpdatedAtAndPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)
	baseline := insertAPIKey(ctx, t, s, repo, want)

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	// Fresh credential primitives — distinct from baseline's so a no-op
	// implementation (returning the row unchanged) would trip the rotation
	// assertion.
	rotated2, _ := newAPIKey(t, f, org.ID, createdBy)
	newPrefix := rotated2.Prefix
	newSecretHash := rotated2.SecretHash
	if newPrefix == baseline.Prefix || newSecretHash == baseline.SecretHash {
		t.Fatalf("test fixture failed to mint distinct credential primitives: baseline prefix=%q new prefix=%q",
			baseline.Prefix, newPrefix)
	}

	var rotated store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.RotateCredential(ctx, tx, org.ID, baseline.ID, newPrefix, newSecretHash)
		if err != nil {
			return err
		}
		rotated = row
		return nil
	}); err != nil {
		t.Fatalf("RotateCredential returned %v, want nil", err)
	}

	// Credential primitives must be the new values.
	if rotated.Prefix != newPrefix {
		t.Errorf("RotateCredential returned prefix %q, want %q", rotated.Prefix, newPrefix)
	}
	if rotated.SecretHash != newSecretHash {
		t.Errorf("RotateCredential returned secret_hash %q, want %q", rotated.SecretHash, newSecretHash)
	}

	// Dual-anchor timestamp pair.
	if !rotated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("RotateCredential mutated created_at: was %v, now %v", baseline.CreatedAt, rotated.CreatedAt)
	}
	if rotated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("RotateCredential updated_at = %v, want >= baseline %v (trigger must refresh)",
			rotated.UpdatedAt, baseline.UpdatedAt)
	}

	// Identity, ownership, scopes, and lifecycle stamps must be untouched.
	if rotated.ID != baseline.ID {
		t.Errorf("RotateCredential rotated id (re-minted instead of swapping the credential): was %q, now %q",
			baseline.ID, rotated.ID)
	}
	if rotated.OrganizationID != baseline.OrganizationID {
		t.Errorf("RotateCredential rewrote organization_id: was %q, now %q",
			baseline.OrganizationID, rotated.OrganizationID)
	}
	if rotated.Name != baseline.Name {
		t.Errorf("RotateCredential rewrote name: was %q, now %q", baseline.Name, rotated.Name)
	}
	if rotated.CreatedBy != baseline.CreatedBy {
		t.Errorf("RotateCredential rewrote created_by: was %q, now %q", baseline.CreatedBy, rotated.CreatedBy)
	}
	if rotated.ServiceAccountID != baseline.ServiceAccountID {
		t.Errorf("RotateCredential rewrote service_account_id: was %q, now %q",
			baseline.ServiceAccountID, rotated.ServiceAccountID)
	}
	if len(rotated.Scopes) != len(baseline.Scopes) {
		t.Errorf("RotateCredential rewrote scopes: had %d, now %d", len(baseline.Scopes), len(rotated.Scopes))
	}
	if !equalTimePtr(rotated.ExpiresAt, baseline.ExpiresAt) {
		t.Errorf("RotateCredential rewrote expires_at: was %v, now %v", baseline.ExpiresAt, rotated.ExpiresAt)
	}
	if !equalTimePtr(rotated.RevokedAt, baseline.RevokedAt) {
		t.Errorf("RotateCredential rewrote revoked_at: was %v, now %v", baseline.RevokedAt, rotated.RevokedAt)
	}
	if !equalTimePtr(rotated.LastUsedAt, baseline.LastUsedAt) {
		t.Errorf("RotateCredential rewrote last_used_at: was %v, now %v", baseline.LastUsedAt, rotated.LastUsedAt)
	}

	// The baseline prefix must no longer resolve to a row — the prefix index
	// is unique and the rotation reassigned it. FindByPrefix on the baseline
	// prefix must surface NotFound.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, findErr := repo.FindByPrefix(ctx, q, baseline.Prefix)
		return findErr
	}); err == nil {
		t.Error("FindByPrefix(baseline.Prefix) returned nil, want NotFound after RotateCredential swapped the prefix")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("FindByPrefix(baseline.Prefix) error code = %v, want %s", err, yerr.CodeNotFound)
	}

	// The new prefix must resolve to the same key id.
	var rebound store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		rebound, err = repo.FindByPrefix(ctx, q, newPrefix)
		return err
	}); err != nil {
		t.Fatalf("FindByPrefix(newPrefix) returned %v, want nil", err)
	}
	if rebound.ID != baseline.ID {
		t.Errorf("FindByPrefix(newPrefix) returned id %q, want %q (the rotated row)", rebound.ID, baseline.ID)
	}
	if rebound.SecretHash != newSecretHash {
		t.Errorf("FindByPrefix(newPrefix) returned secret_hash %q, want %q", rebound.SecretHash, newSecretHash)
	}
}

// TestAPIKeyRepositoryTouchLastUsedRefreshesUpdatedAtAndPreservesCreatedAt
// proves TouchLastUsed refreshes updated_at via the BEFORE UPDATE trigger
// and preserves created_at — the same dual-anchor lifecycle assertion every
// other domain table's mutation must honor. The existing
// TestAPIKeyRepositoryTouchLastUsed in apikey_test.go anchors the
// last_used_at value alone; this case pins the timestamp pair so the trigger
// contract holds for the auth path too.
func TestAPIKeyRepositoryTouchLastUsedRefreshesUpdatedAtAndPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	want, _ := newAPIKey(t, f, org.ID, createdBy)
	baseline := insertAPIKey(ctx, t, s, repo, want)

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.TouchLastUsed(ctx, tx, org.ID, baseline.ID, usedAt)
	}); err != nil {
		t.Fatalf("TouchLastUsed returned %v, want nil", err)
	}

	var after store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		after, err = repo.Get(ctx, q, org.ID, baseline.ID)
		return err
	}); err != nil {
		t.Fatalf("post-TouchLastUsed Get returned %v, want nil", err)
	}

	if after.LastUsedAt == nil || !after.LastUsedAt.Equal(usedAt) {
		t.Errorf("post-TouchLastUsed last_used_at = %v, want %v", after.LastUsedAt, usedAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("TouchLastUsed mutated created_at: was %v, now %v", baseline.CreatedAt, after.CreatedAt)
	}
	if after.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("TouchLastUsed updated_at = %v, want >= baseline %v (trigger must refresh)",
			after.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestAPIKeyRepositoryInsertRollsBackOnTxRollback proves that an Insert
// whose outer Write returns a non-nil error rolls the row back — the
// transaction is the unit of work, and no half-written API key can survive
// an aborted audit/policy step that runs alongside it. For an api_keys row
// the proof is doubly load-bearing: api_keys is the only customer-data
// table whose row body carries a secret-bearing field (secret_hash), so
// the test must also prove no row anywhere in api_keys still carries the
// rolled-back secret_hash — a future refactor that switched Insert to a
// SAVEPOINT or autonomous transaction would otherwise leak the credential
// primitive even though Get-by-id reports NotFound.
func TestAPIKeyRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	key, _ := newAPIKey(t, f, org.ID, createdBy)

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := apiKeyTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insErr := repo.Insert(ctx, tx, key); insErr != nil {
			return insErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction — both
	// the by-id read path and the by-prefix authentication path must surface
	// NotFound.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.Get(ctx, q, org.ID, key.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back api_key) = %v, want NotFound", getErr)
	}
	prefixErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.FindByPrefix(ctx, q, key.Prefix)
		return rerr
	})
	if ye := yerr.From(prefixErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("FindByPrefix(rolled-back prefix) = %v, want NotFound", prefixErr)
	}

	// The list reader must also report an empty tenant — quota and the
	// admin listing path are the second observable surface a half-written
	// secret-bearing row could surface through.
	var listed []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		listed, err = repo.ListByOrganization(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization after rollback: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListByOrganization after rolled-back Insert returned %d rows, want 0", len(listed))
	}

	// And — the secret-bearing extension specific to api_keys — no row
	// anywhere in api_keys may still carry the rolled-back secret_hash.
	// A SAVEPOINT-or-autonomous-transaction refactor that survived the
	// rollback would surface here even when every per-id read reports
	// NotFound, because the credential primitive is the load-bearing
	// observable the table owes its caller.
	var secretHits int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE secret_hash = $1`, key.SecretHash,
	).Scan(&secretHits); err != nil {
		t.Fatalf("count by secret_hash after rollback: %v", err)
	}
	if secretHits != 0 {
		t.Errorf("api_keys WHERE secret_hash = <rolled-back hash> returned %d rows, want 0 (credential must not survive a rolled-back transaction)",
			secretHits)
	}
	// Same proof on the public prefix — a rolled-back row that survived
	// would be authentication-reachable even if its id was forgotten.
	var prefixHits int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE prefix = $1`, key.Prefix,
	).Scan(&prefixHits); err != nil {
		t.Fatalf("count by prefix after rollback: %v", err)
	}
	if prefixHits != 0 {
		t.Errorf("api_keys WHERE prefix = <rolled-back prefix> returned %d rows, want 0",
			prefixHits)
	}
}

// apiKeyTxRollbackSentinel is a typed error a transaction closure can return
// to force a rollback in TestAPIKeyRepositoryInsertRollsBackOnTxRollback.
// It is local to this test file so callers cannot rely on its identity —
// every *_test.go file under internal/controlplane/store/ shares the same
// store_test package, so the type name is intentionally distinct from
// user_repository_invariants_test.go's errSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// and serviceaccount_repository_invariants_test.go's
// serviceAccountTxRollbackSentinel to avoid a collision.
type apiKeyTxRollbackSentinel struct{}

func (apiKeyTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this api key transaction"
}

// TestAPIKeyRepositoryInsertWithoutTxIsTypedInternal proves the repository's
// nil-Tx guard on Insert renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong. The
// pre-existing TestAPIKeyRepositoryInsertRejectsNilTx in apikey_test.go
// only asserts a non-nil error; this case anchors the typed-code contract
// the rest of the repository templates use.
func TestAPIKeyRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()

	_, err := repo.Insert(context.Background(), nil, store.APIKey{
		ID:             "key_irrelevant",
		OrganizationID: "org_irrelevant",
		Prefix:         "yk_irrelevant",
		SecretHash:     "sh_irrelevant",
		Name:           "Irrelevant",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyRepositoryUpdateMutableWithoutTxIsTypedInternal: same guard,
// UpdateMutable path.
func TestAPIKeyRepositoryUpdateMutableWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()

	_, err := repo.UpdateMutable(context.Background(), nil, "org_irrelevant", "key_irrelevant", "Irrelevant", []string{"projects:read"})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateMutable(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyRepositoryRevokeWithoutTxIsTypedInternal: same guard, Revoke
// path.
func TestAPIKeyRepositoryRevokeWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()

	_, err := repo.Revoke(context.Background(), nil, "org_irrelevant", "key_irrelevant", time.Now().UTC())
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Revoke(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyRepositoryRotateCredentialWithoutTxIsTypedInternal: same guard,
// RotateCredential path.
func TestAPIKeyRepositoryRotateCredentialWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()

	_, err := repo.RotateCredential(context.Background(), nil, "org_irrelevant", "key_irrelevant", "yk_irrelevant", "sh_irrelevant")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("RotateCredential(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyRepositoryTouchLastUsedWithoutTxIsTypedInternal: same guard,
// TouchLastUsed path.
func TestAPIKeyRepositoryTouchLastUsedWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyRepository()

	err := repo.TouchLastUsed(context.Background(), nil, "org_irrelevant", "key_irrelevant", time.Now().UTC())
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("TouchLastUsed(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// equalTimePtr reports whether two *time.Time pointers carry the same value
// (both nil, or both non-nil and time.Equal). It is local to this test file
// so the invariants assertions can express "lifecycle stamp untouched"
// concisely without a third-party deep-equality helper.
func equalTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}
