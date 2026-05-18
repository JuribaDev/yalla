package store_test

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the api_keys table (BE-0434).
// api_keys is a tenant-scoped row whose surface area is wider than the
// BE-0432 service_accounts shape — every column in the mutation set
// (name + scopes, revoked_at, last_used_at, prefix + secret_hash) is
// reached through a method whose WHERE clause must include
// organization_id — but two schema-level facts make its cross-tenant
// proof structurally different from BE-0426 organizations and BE-0432
// service_accounts:
//
//	(a) api_keys.prefix is GLOBALLY UNIQUE (NOT UNIQUE (organization_id,
//	    prefix) — the prefix authentication lookup in FindByPrefix runs
//	    BEFORE the caller's tenant is known, and the schema is what
//	    guarantees the resolved row carries exactly one organization_id).
//	    So the "two tenants share a slug" fixture that load-bears
//	    BE-0432's same-slug Get/Disable/Insert-conflict tests does NOT
//	    apply here: two tenants cannot share a prefix at row level.
//	    The cross-tenant prefix-conflict path is still load-bearing —
//	    orgA Inserting a key whose prefix collides with orgB's already-
//	    persisted key must surface CodeConflict AND leave orgB's
//	    bystander row byte-identical (and, crucially, its secret_hash
//	    untouched) — but the proof anchors on the GLOBAL UNIQUE
//	    constraint, not a per-tenant one.
//	(b) api_keys carries a secret-bearing column — secret_hash — that
//	    the auth layer compares with a constant-time hash check.
//	    Cross-tenant ERROR shapes (Code, Hint, Message, Error() string)
//	    must never contain another tenant's secret_hash, and a
//	    cross-tenant MUTATION must leave the bystander tenant's
//	    secret_hash byte-identical (the secret_hash is not exposed by
//	    the typed Get / List read paths because APIKey.SecretHash is
//	    populated from the row body, so a regression that swapped two
//	    tenants' rows would be observable through the typed read; but
//	    a regression that re-hashed orgB's secret to match orgA's
//	    rotation target would surface only through a raw SQL probe.
//	    Both observable surfaces are anchored below.)
//
// In addition api_keys has no version column (so the BE-0426
// stale-If-Match leg has no surface here — the optimistic-concurrency
// path simply does not exist on this table) and no deletion_scheduled_at
// soft-delete column (the lifecycle flag is revoked_at, which the
// idempotent Revoke method stamps via COALESCE). The acceptance-criteria
// mention of "soft-deleted rows where applicable" therefore has no
// surface here; documenting the deliberate absence keeps a future
// reader from looking for a missing test (mirrors
// serviceaccount_tenant_isolation_test.go's no-soft-delete note for
// service_accounts and user_tenant_isolation_test.go's note for users).
//
// The BEFORE-UPDATE api_keys_set_updated_at trigger refreshes updated_at
// on every matched UPDATE — including a WHERE-less or WHERE-on-id-only
// UPDATE that touched the wrong tenant's row. updated_at is therefore
// the independent anchor that catches a missing tenant predicate even
// when the column writes themselves look correct, and every byte-
// identical-bystander test below asserts the bystander's updated_at
// against its baseline.
//
// FindByPrefix is deliberately NOT exercised here as a cross-tenant
// probe: the method is documented (and its signature pins) as the
// pre-tenant authentication lookup, the prefix column is globally
// unique, and the row it returns carries its own organization_id.
// Its tenant-scoping guarantee is structural — there is no caller-
// tenant parameter to scope against — and the existing
// TestAPIKeyRepositoryInsertAndFindByPrefix in apikey_test.go pins
// the round-trip of OrganizationID through that read path.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Basic Insert / Get / List / TouchLastUsed / Revoke read+write
//     shapes and the plain "another tenant's id is a NotFound" result
//     are proved by apikey_test.go (BE-0425): TestAPIKeyRepositoryGetIsTenantScoped,
//     TestAPIKeyRepositoryListByOrganizationIsTenantScoped,
//     TestAPIKeyRepositoryTouchLastUsed (cross-tenant leg), and
//     TestAPIKeyRepositoryRevokeIsIdempotentAndTenantScoped.
//   - Single-row CRUD invariants (Insert RETURNING shape, dual-anchor
//     updated_at-via-trigger + created_at-preserved for every mutation,
//     same-org duplicate-prefix conflict mapping, rollback-of-secret
//     rule, nil-tx guards on every mutation) are proved by
//     api_key_repository_invariants_test.go (BE-0433).
//   - The cross-tenant cascade-on-organization-delete proof lives in
//     schema_test.go's TestTenantHierarchyCascadeDelete.
//   - The api_keys.service_account_id cross-tenant FK leak proof lives
//     in serviceaccount_test.go's
//     TestServiceAccountAPIKeyCannotCrossTenantBoundary.
//   - The HTTP-layer "another tenant's id is a 404, not a 403" rule is
//     proved by per-endpoint policy matrix and contract tests in httpapi.

// TestAPIKeyRepositoryGetReturnsCorrectRowAcrossTenants proves Get is
// keyed strictly by BOTH (organization_id, id): two API keys, each in a
// distinct tenant, resolve to their own row when looked up by (org, id),
// never each other's. The prefix is structurally distinct (every
// auth.Generate() returns a fresh, globally unique prefix), so the
// shared-slug worst-case fixture from BE-0432 has no analogue at the
// row level — the worst case here is the (organization_id, id) lookup
// itself, which the per-tenant id assertion guards directly.
func TestAPIKeyRepositoryGetReturnsCorrectRowAcrossTenants(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)

	var gotA store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, orgA.ID, keyA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, keyA): %v", err)
	}
	if gotA.ID != keyA.ID || gotA.OrganizationID != orgA.ID || gotA.Prefix != keyA.Prefix {
		t.Errorf("Get(orgA, keyA) = %+v, want id/org/prefix from %+v", gotA, keyA)
	}

	var gotB store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, orgB.ID, keyB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB, keyB): %v", err)
	}
	if gotB.ID != keyB.ID || gotB.OrganizationID != orgB.ID || gotB.Prefix != keyB.Prefix {
		t.Errorf("Get(orgB, keyB) = %+v, want id/org/prefix from %+v", gotB, keyB)
	}

	// The two reads MUST have returned distinct rows — a WHERE-on-id-only
	// mistake that resolved both lookups onto the same row by planner
	// accident would have produced overlapping id/org/prefix triples and
	// this guard catches it even when a per-row equality check
	// coincidentally agreed.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID || gotA.Prefix == gotB.Prefix {
		t.Errorf("Get returned overlapping rows for two distinct keys in two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestAPIKeyRepositoryUpdateMutableOnOrgADoesNotTouchOrgB is the byte-
// identical snapshot proof for UpdateMutable: when orgA UPDATEs the
// mutable surface (name + scopes) on its own key, orgB's bystander key
// must be byte-identical to its baseline across EVERY observable column
// — including the trigger-managed updated_at, which is the independent
// anchor that catches a WHERE-on-id-only UPDATE even when the mutable
// column writes happened to look correct. The secret_hash column is the
// load-bearing extension specific to api_keys: a regression that
// repointed orgA's UPDATE at orgB's row could leak a re-hashed value
// even when scopes round-tripped correctly, and the byte-identical
// secret_hash assertion is the only thing that surfaces that class of
// regression.
func TestAPIKeyRepositoryUpdateMutableOnOrgADoesNotTouchOrgB(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	storedB := insertAPIKey(ctx, t, s, repo, keyB)

	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")
	if baselineB.Name != storedB.Name || len(baselineB.Scopes) != len(storedB.Scopes) {
		t.Fatalf("test setup invariant violated: baseline Get returned a row that differs from Insert RETURNING")
	}

	// Touch orgA's mutable surface with values that DON'T also appear on
	// orgB's row — so a WHERE-on-id-only mistake would surface as orgB's
	// name/scopes drifting toward orgA's new values.
	newName := "orgA renamed by UpdateMutable test"
	newScopes := []string{"projects:read", "projects:write", "services:deploy"}
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateMutable(ctx, tx, orgA.ID, keyA.ID, newName, newScopes)
		return updErr
	}); err != nil {
		t.Fatalf("UpdateMutable(orgA, keyA): %v", err)
	}

	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	afterA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "afterA")
	if afterA.Name != newName {
		t.Errorf("UpdateMutable(orgA) did not rename orgA's row: name = %q, want %q (proof is vacuous if A did not actually change)", afterA.Name, newName)
	}

	// orgB's row must be byte-identical to its baseline — EVERY column.
	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	assertBystanderByteIdentical(t, "UpdateMutable(orgA)", baselineB, afterB)

	// And the secret-bearing extension: the raw secret_hash on orgB's
	// row in the database matches its baseline by direct SQL probe.
	// This catches a regression that bypassed the typed read path and
	// re-hashed orgB's secret to match some UPDATE target.
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "UpdateMutable(orgA)")
}

// TestAPIKeyRepositoryRevokeOnOrgADoesNotTouchOrgB is the byte-identical
// snapshot proof for Revoke. The lifecycle flag (revoked_at) is the
// load-bearing column to assert against: a WHERE-on-id-only mistake
// that stamped revoked_at on orgB's row would silently lock out a
// peer tenant's authentication path. The COALESCE-idempotent semantics
// on the matching path are anchored in apikey_test.go; this test pins
// the cross-tenant non-mutation surface.
func TestAPIKeyRepositoryRevokeOnOrgADoesNotTouchOrgB(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)

	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")
	if baselineB.RevokedAt != nil {
		t.Fatalf("test setup invariant violated: orgB key is already revoked at %v — the revoked_at anchor cannot prove non-mutation", baselineB.RevokedAt)
	}

	revokeAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := writeAPIKey(ctx, s, func(tx *store.Tx) (store.APIKey, error) {
		return repo.Revoke(ctx, tx, orgA.ID, keyA.ID, revokeAt)
	}); err != nil {
		t.Fatalf("Revoke(orgA, keyA): %v", err)
	}

	afterA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "afterA")
	if !afterA.IsRevoked() {
		t.Errorf("Revoke(orgA) did not stamp revoked_at on orgA's row — proof is vacuous")
	}

	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	if afterB.RevokedAt != nil {
		t.Errorf("orgB.revoked_at = %v, want nil — Revoke(orgA) leaked into orgB's lifecycle flag via a WHERE-on-id-only mistake", afterB.RevokedAt)
	}
	assertBystanderByteIdentical(t, "Revoke(orgA)", baselineB, afterB)
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "Revoke(orgA)")
}

// TestAPIKeyRepositoryRotateCredentialOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for RotateCredential. The credential
// primitives (prefix, secret_hash) are the load-bearing columns to
// assert against: a WHERE-on-id-only mistake that swapped orgB's
// prefix/secret_hash for the rotation target would silently invalidate
// a peer tenant's authentication path AND simultaneously hand the new
// credential to whoever owns orgA's key.
func TestAPIKeyRepositoryRotateCredentialOnOrgADoesNotTouchOrgB(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)

	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")

	// New credential primitives for orgA's rotation — distinct from
	// every existing row so a WHERE-on-id-only mistake would surface as
	// orgB's prefix or secret_hash drifting to these values.
	newPrefix := "yk_be0434_rotated_for_orgA"
	newSecretHash := "sh_be0434_rotated_for_orgA_secret_hash"
	if _, err := writeAPIKey(ctx, s, func(tx *store.Tx) (store.APIKey, error) {
		return repo.RotateCredential(ctx, tx, orgA.ID, keyA.ID, newPrefix, newSecretHash)
	}); err != nil {
		t.Fatalf("RotateCredential(orgA, keyA): %v", err)
	}

	afterA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "afterA")
	if afterA.Prefix != newPrefix || afterA.SecretHash != newSecretHash {
		t.Errorf("RotateCredential(orgA) did not swap orgA's credential primitives: prefix=%q secret_hash=%q, want prefix=%q secret_hash=%q (proof is vacuous if A did not actually change)",
			afterA.Prefix, afterA.SecretHash, newPrefix, newSecretHash)
	}

	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	if afterB.Prefix != baselineB.Prefix {
		t.Errorf("orgB.prefix = %q, want %q — RotateCredential(orgA) leaked into orgB's authentication primitive", afterB.Prefix, baselineB.Prefix)
	}
	if afterB.SecretHash != baselineB.SecretHash {
		t.Errorf("orgB.secret_hash drifted after RotateCredential(orgA) — peer tenant's credential body was overwritten")
	}
	assertBystanderByteIdentical(t, "RotateCredential(orgA)", baselineB, afterB)
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "RotateCredential(orgA)")
}

// TestAPIKeyRepositoryTouchLastUsedOnOrgADoesNotTouchOrgB is the byte-
// identical snapshot proof for TouchLastUsed. last_used_at is the
// observability column the rate-limiting / unused-key-cleanup paths
// consume; a leak there would inflate one tenant's signal with peer
// tenant activity.
func TestAPIKeyRepositoryTouchLastUsedOnOrgADoesNotTouchOrgB(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)

	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")
	if baselineB.LastUsedAt != nil {
		t.Fatalf("test setup invariant violated: orgB key already has last_used_at = %v — the last_used_at anchor cannot prove non-mutation", baselineB.LastUsedAt)
	}

	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.TouchLastUsed(ctx, tx, orgA.ID, keyA.ID, usedAt)
	}); err != nil {
		t.Fatalf("TouchLastUsed(orgA, keyA): %v", err)
	}

	afterA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "afterA")
	if afterA.LastUsedAt == nil || !afterA.LastUsedAt.Equal(usedAt) {
		t.Errorf("TouchLastUsed(orgA) did not stamp last_used_at on orgA's row: got %v, want %v (proof is vacuous)", afterA.LastUsedAt, usedAt)
	}

	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	if afterB.LastUsedAt != nil {
		t.Errorf("orgB.last_used_at = %v, want nil — TouchLastUsed(orgA) leaked into orgB's observability stamp", afterB.LastUsedAt)
	}
	assertBystanderByteIdentical(t, "TouchLastUsed(orgA)", baselineB, afterB)
}

// TestAPIKeyRepositoryInsertCrossTenantPrefixConflictDoesNotTouchOrgB
// proves: api_keys.prefix is GLOBALLY UNIQUE, so an Insert by orgA that
// reuses a prefix orgB has already persisted MUST surface CodeConflict
// AND MUST leave orgB's bystander row byte-identical. The conflicting
// INSERT rolling back without partial-write damage is the safety net
// against a regression that resolved the UNIQUE check via a missing
// tenant predicate and silently emitted orgA's row in some other
// tenant's slot. The secret-bearing extension specific to api_keys:
// the rolled-back INSERT must not have left orgA's secret_hash needle
// reachable through a raw SQL probe on any row.
func TestAPIKeyRepositoryInsertCrossTenantPrefixConflictDoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)
	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")

	// orgA tries to insert a key whose prefix collides with orgB's.
	dupForOrgA, _ := newAPIKey(t, f, orgA.ID, "")
	dupForOrgA.Prefix = keyB.Prefix
	// Distinct secret_hash so the rolled-back-secret probe below is not
	// trivially satisfied by the bystander's own hash.
	dupForOrgA.SecretHash = "sh_be0434_cross_tenant_dup_insert_for_orgA"

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, dupForOrgA)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("cross-tenant duplicate-prefix Insert error code = %v, want %s", err, yerr.CodeConflict)
	}
	if msg := strings.TrimSpace(yerr.From(err).Message); msg == "" {
		t.Errorf("cross-tenant duplicate-prefix Insert error has empty Message — callers cannot render a useful response")
	}

	// orgB's bystander row is the critical safety net — every observable
	// column byte-identical to baseline.
	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	assertBystanderByteIdentical(t, "cross-tenant duplicate-prefix Insert", baselineB, afterB)
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "cross-tenant duplicate-prefix Insert")

	// No row in api_keys anywhere may carry orgA's would-have-been
	// secret_hash — the rolled-back Insert must not have survived in
	// any partial form (autonomous-transaction or SAVEPOINT regression).
	var secretHits int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE secret_hash = $1`, dupForOrgA.SecretHash,
	).Scan(&secretHits); err != nil {
		t.Fatalf("count by rolled-back secret_hash: %v", err)
	}
	if secretHits != 0 {
		t.Errorf("api_keys WHERE secret_hash = <orgA rolled-back hash> returned %d rows, want 0 — the failed cross-tenant Insert left a credential body behind", secretHits)
	}

	// And the global table size is exactly the one row we seeded — a
	// rolled-back Insert that landed its row in some other tenant's
	// slot would show up here even if the per-id probe missed it.
	var totalRows int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&totalRows); err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if totalRows != 1 {
		t.Errorf("api_keys total rows = %d, want 1 — the rolled-back cross-tenant Insert leaked a row", totalRows)
	}
}

// TestAPIKeyRepositoryRotateCredentialCrossTenantPrefixConflictDoesNotTouchOrgB
// proves the second prefix-conflict surface — RotateCredential — does
// not leak across tenants either. orgA holds key keyA and tries to
// rotate keyA.prefix to a prefix orgB's keyB already owns. The GLOBAL
// UNIQUE constraint on prefix must surface CodeConflict; orgA's keyA
// must be byte-identical to its pre-rotation baseline (the conflicting
// UPDATE rolled back without partial-write damage); orgB's keyB must
// also be byte-identical (the conflict resolved correctly against the
// owning row without touching it).
func TestAPIKeyRepositoryRotateCredentialCrossTenantPrefixConflictDoesNotTouchOrgB(t *testing.T) {
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
	keyB, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB)

	baselineA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "baselineA")
	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baselineB")

	// orgA rotates keyA's prefix to collide with keyB's prefix.
	rotateTargetSecretHash := "sh_be0434_cross_tenant_rotate_target"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rotErr := repo.RotateCredential(ctx, tx, orgA.ID, keyA.ID, keyB.Prefix, rotateTargetSecretHash)
		return rotErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("cross-tenant RotateCredential prefix-collision error code = %v, want %s", err, yerr.CodeConflict)
	}

	// orgA's keyA rolled back — every column byte-identical to its
	// pre-rotation baseline.
	afterA := getAPIKeyOrFail(ctx, t, s, repo, orgA.ID, keyA.ID, "afterA")
	if afterA.Prefix != baselineA.Prefix || afterA.SecretHash != baselineA.SecretHash {
		t.Errorf("orgA.keyA credential drifted after rolled-back rotation: prefix=%q secret_hash=%q, want prefix=%q secret_hash=%q",
			afterA.Prefix, afterA.SecretHash, baselineA.Prefix, baselineA.SecretHash)
	}
	if !afterA.UpdatedAt.Equal(baselineA.UpdatedAt) {
		t.Errorf("orgA.keyA.updated_at = %v, want %v — the rolled-back rotation refreshed updated_at via the trigger", afterA.UpdatedAt, baselineA.UpdatedAt)
	}

	// orgB's keyB byte-identical — the conflict-detection path did not
	// touch the owning row.
	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterB")
	assertBystanderByteIdentical(t, "cross-tenant RotateCredential prefix-collision", baselineB, afterB)
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "cross-tenant RotateCredential prefix-collision")

	// No row in api_keys anywhere carries the would-be-rotated
	// secret_hash — the rolled-back UPDATE did not survive in any
	// partial form.
	var secretHits int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE secret_hash = $1`, rotateTargetSecretHash,
	).Scan(&secretHits); err != nil {
		t.Fatalf("count by rolled-back rotation secret_hash: %v", err)
	}
	if secretHits != 0 {
		t.Errorf("api_keys WHERE secret_hash = <rolled-back rotation hash> returned %d rows, want 0", secretHits)
	}
}

// TestAPIKeyRepositoryListByOrganizationCountsAreIsolated proves the
// rendered length of ListByOrganization is local to the queried tenant
// — never the global count, never a sum across tenants. orgA has one
// key, orgB has three, orgC has none. A SELECT without the
// WHERE organization_id filter would have returned 4 for every call;
// the per-tenant assertions surface that as three distinct failures.
// The non-overlap guard catches a JOIN that produced the right COUNT
// from the wrong rows.
func TestAPIKeyRepositoryListByOrganizationCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	orgC := seedOrg(t, db, f, "tenant-c") // empty bystander tenant
	keyA, _ := newAPIKey(t, f, orgA.ID, "")
	insertAPIKey(ctx, t, s, repo, keyA)
	keyB1, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB1)
	keyB2, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB2)
	keyB3, _ := newAPIKey(t, f, orgB.ID, "")
	insertAPIKey(ctx, t, s, repo, keyB3)

	var listA, listB, listC []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		if listA, readErr = repo.ListByOrganization(ctx, q, orgA.ID); readErr != nil {
			return readErr
		}
		if listB, readErr = repo.ListByOrganization(ctx, q, orgB.ID); readErr != nil {
			return readErr
		}
		listC, readErr = repo.ListByOrganization(ctx, q, orgC.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listA) != 1 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 1 — peer rows leaked", len(listA))
	}
	if len(listB) != 3 {
		t.Errorf("ListByOrganization(orgB) returned %d rows, want 3", len(listB))
	}
	if len(listC) != 0 {
		t.Errorf("ListByOrganization(orgC) returned %d rows, want 0 — empty-tenant list leaked from peers", len(listC))
	}
	for _, k := range listA {
		if k.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a foreign row: %+v", k)
		}
	}
	for _, k := range listB {
		if k.OrganizationID != orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a foreign row: %+v", k)
		}
	}

	// The two non-empty responses must not overlap — if they did, the
	// WHERE filter is the only thing keeping them apart, and the only
	// way for both calls to share a row is a WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(listB))
	for _, k := range listB {
		seenInB[k.ID] = struct{}{}
	}
	for _, k := range listA {
		if _, overlap := seenInB[k.ID]; overlap {
			t.Errorf("api key %q appears in both List(orgA) and List(orgB) responses", k.ID)
		}
	}

	// The seeded ids land in the expected list — a List that returned
	// the right count from a wrong JOIN would scramble which rows land
	// where.
	wantA := map[string]struct{}{keyA.ID: {}}
	wantB := map[string]struct{}{keyB1.ID: {}, keyB2.ID: {}, keyB3.ID: {}}
	for _, k := range listA {
		if _, ok := wantA[k.ID]; !ok {
			t.Errorf("List(orgA) returned id %q, want only %v", k.ID, wantA)
		}
	}
	for _, k := range listB {
		if _, ok := wantB[k.ID]; !ok {
			t.Errorf("List(orgB) returned id %q, want only %v", k.ID, wantB)
		}
	}
}

// TestAPIKeyRepositoryListByServiceAccountIsTenantScoped proves the
// parent-scoped read path (ListByServiceAccount) is keyed by BOTH
// (organization_id, service_account_id): a probe with the OTHER tenant's
// service_account_id alongside this tenant's organization_id returns an
// empty list — never the other tenant's keys, never a 500 leaking the
// cause. The composite FK on (organization_id, service_account_id)
// prevents a key from physically pointing at a cross-tenant SA, so the
// only structural leak surface here is a WHERE clause that filters by
// service_account_id without anchoring on organization_id; this test
// is the proof against that class of regression.
func TestAPIKeyRepositoryListByServiceAccountIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccount(t, db, f, orgA, "CI A")
	saB := seedServiceAccount(t, db, f, orgB, "CI B")

	// orgA's SA has one key; orgB's SA has two — distinct counts so a
	// SELECT without the WHERE organization_id filter would return 3
	// for every call.
	keyAforSA, _ := newAPIKey(t, f, orgA.ID, "")
	keyAforSA.ServiceAccountID = saA.ID
	insertAPIKey(ctx, t, s, repo, keyAforSA)

	keyB1forSA, _ := newAPIKey(t, f, orgB.ID, "")
	keyB1forSA.ServiceAccountID = saB.ID
	insertAPIKey(ctx, t, s, repo, keyB1forSA)
	keyB2forSA, _ := newAPIKey(t, f, orgB.ID, "")
	keyB2forSA.ServiceAccountID = saB.ID
	insertAPIKey(ctx, t, s, repo, keyB2forSA)

	// Cross-tenant probe: orgA asks for orgB's SA's keys. The composite
	// FK keeps the rows from physically attaching, but the WHERE clause
	// is the only thing keeping the LIST query from returning orgB's
	// keys to an orgA caller. Empty list, no error.
	var crossList []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		crossList, readErr = repo.ListByServiceAccount(ctx, q, orgA.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("cross-tenant ListByServiceAccount: %v", err)
	}
	if len(crossList) != 0 {
		t.Errorf("ListByServiceAccount(orgA.ID, saB.ID) returned %d rows, want 0 — orgB's SA keys leaked to orgA", len(crossList))
	}

	// Mirror: orgB asking for orgA's SA's keys also leaks nothing.
	var crossListReverse []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		crossListReverse, readErr = repo.ListByServiceAccount(ctx, q, orgB.ID, saA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("reverse cross-tenant ListByServiceAccount: %v", err)
	}
	if len(crossListReverse) != 0 {
		t.Errorf("ListByServiceAccount(orgB.ID, saA.ID) returned %d rows, want 0 — orgA's SA keys leaked to orgB", len(crossListReverse))
	}

	// Same-tenant reads return exactly the seeded rows — proves the
	// parent-scoped filter actually does match when the tenant is
	// correct (a no-op repository cannot silently pass the empty-list
	// cross-tenant checks above).
	var ownA, ownB []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		if ownA, readErr = repo.ListByServiceAccount(ctx, q, orgA.ID, saA.ID); readErr != nil {
			return readErr
		}
		ownB, readErr = repo.ListByServiceAccount(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("owner ListByServiceAccount: %v", err)
	}
	if len(ownA) != 1 {
		t.Errorf("ListByServiceAccount(orgA, saA) returned %d rows, want 1", len(ownA))
	}
	if len(ownB) != 2 {
		t.Errorf("ListByServiceAccount(orgB, saB) returned %d rows, want 2", len(ownB))
	}
	for _, k := range ownA {
		if k.OrganizationID != orgA.ID || k.ServiceAccountID != saA.ID {
			t.Errorf("owner ListByServiceAccount(orgA, saA) returned foreign row: %+v", k)
		}
	}
	for _, k := range ownB {
		if k.OrganizationID != orgB.ID || k.ServiceAccountID != saB.ID {
			t.Errorf("owner ListByServiceAccount(orgB, saB) returned foreign row: %+v", k)
		}
	}
}

// TestAPIKeyRepositoryCrossTenantErrorIsIndistinguishableFromUnknownId
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown api-key id produces on every tenant-scoped repository
// surface (Get, UpdateMutable, Revoke, RotateCredential, TouchLastUsed).
// A probing caller who guesses a peer tenant's api-key id cannot infer
// existence from the response: both surfaces emit yerr.CodeNotFound
// with matching Hint values. The Message field is intentionally NOT
// asserted — apierr.NotFound echoes the caller-supplied id back in the
// Message verbatim, so a caller asking about id X always sees X in the
// message (whether X exists in another tenant or doesn't exist at all).
// The leak surface is Code and Hint; Message is the caller's own input.
//
// The api_keys-specific extension: the rendered Error() string of every
// cross-tenant typed error must NOT contain the bystander's secret_hash
// needle. A regression that wired a future error formatter to embed the
// row body would otherwise hand a peer tenant's credential to a probing
// caller. The secret_hash is the load-bearing column to probe for here
// (the prefix is public by design; the hash is not).
func TestAPIKeyRepositoryCrossTenantErrorIsIndistinguishableFromUnknownId(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyB, _ := newAPIKey(t, f, orgB.ID, "") // owned by orgB ONLY
	insertAPIKey(ctx, t, s, repo, keyB)
	baselineB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "baseline")
	secretHashNeedle := baselineB.SecretHash

	const unknownID = "key_no_such_api_key_ever"
	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	revokeAt := usedAt
	const probeNewName = "irrelevant"
	probeScopes := []string{"projects:read"}
	const probePrefix = "yk_irrelevant_probe"
	const probeSecretHash = "sh_irrelevant_probe"

	// Each (path, leg) pair returns (err, label). The leg labels are
	// stable so the indistinguishability assertions below can match
	// across pairs.
	cases := []struct {
		name      string
		crossErr  error
		unknError error
	}{
		{
			name: "Get",
			crossErr: s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				_, err := repo.Get(ctx, q, orgA.ID, keyB.ID)
				return err
			}),
			unknError: s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				_, err := repo.Get(ctx, q, orgA.ID, unknownID)
				return err
			}),
		},
		{
			name: "UpdateMutable",
			crossErr: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.UpdateMutable(ctx, tx, orgA.ID, keyB.ID, probeNewName, probeScopes)
				return err
			}),
			unknError: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.UpdateMutable(ctx, tx, orgA.ID, unknownID, probeNewName, probeScopes)
				return err
			}),
		},
		{
			name: "Revoke",
			crossErr: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.Revoke(ctx, tx, orgA.ID, keyB.ID, revokeAt)
				return err
			}),
			unknError: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.Revoke(ctx, tx, orgA.ID, unknownID, revokeAt)
				return err
			}),
		},
		{
			name: "RotateCredential",
			crossErr: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.RotateCredential(ctx, tx, orgA.ID, keyB.ID, probePrefix, probeSecretHash)
				return err
			}),
			unknError: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.RotateCredential(ctx, tx, orgA.ID, unknownID, probePrefix, probeSecretHash)
				return err
			}),
		},
		{
			name: "TouchLastUsed",
			crossErr: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				return repo.TouchLastUsed(ctx, tx, orgA.ID, keyB.ID, usedAt)
			}),
			unknError: s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				return repo.TouchLastUsed(ctx, tx, orgA.ID, unknownID, usedAt)
			}),
		},
	}

	for _, tc := range cases {
		var yeCross *yerr.Error
		if !stderrors.As(tc.crossErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
			t.Fatalf("%s: cross-tenant error = %v, want a typed E_NOT_FOUND", tc.name, tc.crossErr)
		}
		var yeUnknown *yerr.Error
		if !stderrors.As(tc.unknError, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
			t.Fatalf("%s: unknown-id error = %v, want a typed E_NOT_FOUND", tc.name, tc.unknError)
		}
		if yeCross.Code != yeUnknown.Code {
			t.Errorf("%s: cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", tc.name, yeCross.Code, yeUnknown.Code)
		}
		if yeCross.Hint != yeUnknown.Hint {
			t.Errorf("%s: cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", tc.name, yeCross.Hint, yeUnknown.Hint)
		}

		// Secret-bearing extension: the rendered cross-tenant error must
		// not contain the bystander's secret_hash. Probe every observable
		// surface: Error() (the rendered string), Message (the structured
		// human-readable field), and Hint (the structured agent-facing
		// field). Skip an empty needle since strings.Contains(s, "") is
		// trivially true.
		if secretHashNeedle != "" {
			if strings.Contains(tc.crossErr.Error(), secretHashNeedle) {
				t.Errorf("%s: cross-tenant Error() string contains bystander secret_hash — credential leak", tc.name)
			}
			if strings.Contains(yeCross.Message, secretHashNeedle) {
				t.Errorf("%s: cross-tenant Message contains bystander secret_hash — credential leak", tc.name)
			}
			if strings.Contains(yeCross.Hint, secretHashNeedle) {
				t.Errorf("%s: cross-tenant Hint contains bystander secret_hash — credential leak", tc.name)
			}
		}
	}

	// After every cross-tenant probe above, the targeted bystander row
	// itself is byte-identical to its starting state — neither the
	// cross-tenant read nor any cross-tenant mutation silently mutated
	// its lifecycle stamps, credential primitives, or trigger-managed
	// updated_at.
	afterB := getAPIKeyOrFail(ctx, t, s, repo, orgB.ID, keyB.ID, "afterCrossTenantProbes")
	assertBystanderByteIdentical(t, "cross-tenant indistinguishability probes", baselineB, afterB)
	assertRawSecretHashUnchanged(ctx, t, db, keyB.ID, baselineB.SecretHash, "cross-tenant indistinguishability probes")
}

// --- shared helpers ---
//
// getAPIKeyOrFail reads a key through the typed repository surface and
// fails the test on any error — the test cases use this exclusively for
// reads that are EXPECTED to succeed, so a NotFound here is a setup
// failure (the seeded row went missing) and not a leg under proof.
func getAPIKeyOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.APIKeyRepository, organizationID, keyID, label string) store.APIKey {
	t.Helper()
	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		got, readErr = repo.Get(ctx, q, organizationID, keyID)
		return readErr
	}); err != nil {
		t.Fatalf("%s Get(%q, %q): %v", label, organizationID, keyID, err)
	}
	return got
}

// writeAPIKey runs fn inside a Store.Write transaction and returns the
// row the closure produced. It exists to keep the byte-identical-snapshot
// tests free of repetitive Write boilerplate; the closure body is the
// actually-interesting line.
func writeAPIKey(ctx context.Context, s *store.Store, fn func(tx *store.Tx) (store.APIKey, error)) (store.APIKey, error) {
	var got store.APIKey
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, wErr := fn(tx)
		if wErr != nil {
			return wErr
		}
		got = row
		return nil
	})
	return got, err
}

// assertBystanderByteIdentical asserts every observable column on a
// bystander api_keys row is byte-identical to its baseline. The
// trigger-managed updated_at is included because the api_keys_set_updated_at
// BEFORE-UPDATE trigger refreshes it on every matched UPDATE — including
// a WHERE-less or WHERE-on-id-only UPDATE that touched the wrong tenant's
// row — which is the independent anchor that catches a missing tenant
// predicate even when the column writes themselves look correct.
func assertBystanderByteIdentical(t *testing.T, label string, baseline, after store.APIKey) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.Prefix != baseline.Prefix {
		t.Errorf("%s: bystander.prefix = %q, want %q — authentication primitive drifted", label, after.Prefix, baseline.Prefix)
	}
	if after.SecretHash != baseline.SecretHash {
		t.Errorf("%s: bystander.secret_hash drifted — peer tenant's credential body was overwritten", label)
	}
	if after.Name != baseline.Name {
		t.Errorf("%s: bystander.name = %q, want %q", label, after.Name, baseline.Name)
	}
	if !equalStringSlices(after.Scopes, baseline.Scopes) {
		t.Errorf("%s: bystander.scopes = %v, want %v", label, after.Scopes, baseline.Scopes)
	}
	if after.CreatedBy != baseline.CreatedBy {
		t.Errorf("%s: bystander.created_by = %q, want %q", label, after.CreatedBy, baseline.CreatedBy)
	}
	if after.ServiceAccountID != baseline.ServiceAccountID {
		t.Errorf("%s: bystander.service_account_id = %q, want %q", label, after.ServiceAccountID, baseline.ServiceAccountID)
	}
	if !equalTimePtr(after.ExpiresAt, baseline.ExpiresAt) {
		t.Errorf("%s: bystander.expires_at = %v, want %v", label, after.ExpiresAt, baseline.ExpiresAt)
	}
	if !equalTimePtr(after.RevokedAt, baseline.RevokedAt) {
		t.Errorf("%s: bystander.revoked_at = %v, want %v — lifecycle flag drifted on a peer tenant's key", label, after.RevokedAt, baseline.RevokedAt)
	}
	if !equalTimePtr(after.LastUsedAt, baseline.LastUsedAt) {
		t.Errorf("%s: bystander.last_used_at = %v, want %v — observability stamp drifted on a peer tenant's key", label, after.LastUsedAt, baseline.LastUsedAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// assertRawSecretHashUnchanged probes the raw api_keys.secret_hash
// column directly via the database driver, bypassing the typed
// repository surface. The typed read path's SecretHash field is
// already covered by assertBystanderByteIdentical, but a regression
// that scanned a non-secret column into the struct (or skipped the
// field entirely on Get) would silently make the byte-identical
// assertion pass while the underlying row still drifted. This probe
// is the load-bearing safety net against that class of regression
// specifically for the secret-bearing column.
func assertRawSecretHashUnchanged(ctx context.Context, t *testing.T, db *testutil.DB, keyID, wantSecretHash, label string) {
	t.Helper()
	var got string
	if err := db.QueryRow(ctx, `SELECT secret_hash FROM api_keys WHERE id = $1`, keyID).Scan(&got); err != nil {
		t.Fatalf("%s raw secret_hash probe for key %q: %v", label, keyID, err)
	}
	if got != wantSecretHash {
		t.Errorf("%s: raw secret_hash for key %q drifted from baseline", label, keyID)
	}
}

// equalStringSlices reports whether two string slices carry the same
// values in the same order. It is local to this test file so the
// byte-identical assertions can express "scopes untouched" concisely
// without depending on a third-party deep-equality helper.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
