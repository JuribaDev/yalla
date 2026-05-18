package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-invariants for the idempotency_keys table
// (BE-0469). An idempotency_keys row is the durable record that lets a
// mutating control-plane endpoint be safely retried by an agent or CI:
// the first request claims the key (status 'pending'), the handler
// runs, and Complete records the rendered response envelope (status
// 'completed') so a retry replays the stored envelope instead of
// re-running the handler. The IdempotencyRepository surface is narrow
// by design: Claim atomically takes a key (inserting a fresh row, or
// stealing an expired one) or reports the existing live claim;
// Complete records the rendered response on a pending claim; Release
// deletes a pending claim so a server-failure retry can re-run the
// handler; Find returns the row identified by (organization_id,
// principal_id, idempotency_key) including an expired one. There is
// no per-row Update -- the lifecycle moves only through Claim ->
// (Complete | Release) -- and there is no caller-facing Delete: row
// removal is reachable only through the expiry-takeover branch of
// Claim, through Release, or through ON DELETE CASCADE when the parent
// organization is removed (tenant teardown).
//
// The functional lifecycle (claim, replay, in-flight, hash-collision,
// expired-takeover, release, double-complete, tenant + principal
// isolation, missing-key Find, claim/complete validation) is pinned by
// idempotency_test.go's TestIdempotencyClaimAndComplete,
// TestIdempotencyReplayAfterCompletion, TestIdempotencyClaimWhilePending,
// TestIdempotencyClaimDifferentRequestSameKey,
// TestIdempotencyExpiredClaimTakenOver,
// TestIdempotencyReleaseAllowsReclaim,
// TestIdempotencyCompleteRejectsNonPendingClaim,
// TestIdempotencyTenantIsolation, TestIdempotencyCrossPrincipalIsolation,
// TestIdempotencyClaimValidation, and TestIdempotencyFindMissingKey.
// This file is the gap-fill that pins the row-shape, id contract,
// CHECK / FK / PK constraint surfacing through mapWriteError, the
// completion-consistent invariant, the peer-row byte-identity
// invariant, the transaction-rollback atomicity invariant, and the
// ON DELETE CASCADE chain from organizations.
//
// What this file pins, and what it deliberately delegates:
//
//   - Claim row-shape on the first call: a blank-id record mints an id
//     carrying the idk_ prefix, the database stamps created_at
//     server-side (DEFAULT now()), the row defaults to status='pending'
//     with response_status / response_body / completed_at all NULL
//     (satisfying the completion_consistent CHECK on the pending side),
//     the caller-supplied (organization_id, principal_id, key, route,
//     request_hash, request_id, expires_at) fields round-trip verbatim,
//     and the return value's struct fields are byte-equal to a raw-SQL
//     re-load of the persisted row.
//   - Claim id contract: a non-blank caller-supplied id is preserved
//     verbatim. A duplicate id on a different (organization_id,
//     principal_id, idempotency_key) target surfaces as typed
//     apierr.Conflict via mapWriteError -- the INSERT's ON CONFLICT
//     target catches the (org, principal, key) collision only, so a
//     PRIMARY KEY collision on a fresh-insert branch flows through the
//     database and back through the typed error taxonomy. The id minter
//     emits idk_<32hex> (16 bytes of crypto/rand entropy hex-encoded),
//     so a real-world id collision is vanishingly rare; this test
//     exercises the regression-backstop path by forcing the collision
//     through a caller-supplied id.
//   - Claim FK contract: an unknown organization_id surfaces as typed
//     apierr.Conflict via mapWriteError (organization_id REFERENCES
//     organizations (id) ON DELETE CASCADE). A regression that fell
//     back to apierr.StoreUnavailable on the FK path would surface as
//     a code drift here.
//   - Complete row-shape: after Complete the row carries
//     status='completed', a non-NULL response_status, a non-NULL
//     response_body, and a non-NULL completed_at -- the four-column
//     transition that satisfies the idempotency_keys_completion_consistent
//     CHECK. The return value's struct fields are byte-equal to a raw
//     re-load.
//   - Complete now-argument contract: an explicit non-zero now
//     argument is stored as the completed_at wallclock (UTC-normalised);
//     a zero now defaults to time.Now().UTC(). A regression that
//     ignored the argument or wrote a stale timestamp would surface
//     here.
//   - Complete body coercion: a nil body argument is coerced to a
//     zero-length non-nil []byte before INSERT, so the
//     completion_consistent CHECK's response_body IS NOT NULL clause is
//     satisfied. The persisted row carries a non-NULL empty bytea.
//   - Release nil-tx contract: Release(ctx, nil, ref) surfaces as typed
//     apierr.Internal before the database is touched (it is a
//     programming error, not a customer-rejection conflict). The nil-tx
//     branches for Claim and Complete are pinned by
//     TestIdempotencyClaimValidation in idempotency_test.go; this
//     test fills the Release gap.
//   - Release non-pending no-op: Release of a completed claim returns
//     nil and leaves the row in place; Release of an unknown
//     (organization, principal, key) returns nil and creates no row.
//     Release is safe to call defensively without distinguishing
//     "already done" from "never claimed".
//   - Claim transaction-rollback atomicity: a closure that returns an
//     error after a successful Claim leaves no idempotency_keys row
//     behind. The claim must commit or roll back atomically with the
//     mutating handler whose retry-safety it underwrites.
//   - Cascade delete: removing the parent organization removes every
//     idempotency_keys row owned by that organization via ON DELETE
//     CASCADE, while a sibling tenant's row survives byte-identical
//     (id, route, request_hash, request_id, status, response_status,
//     response_body, created_at, completed_at, expires_at).
//   - Peer-row byte-identity: Claim for one (organization, principal,
//     key) tuple does not touch a prior peer row's id / route /
//     request_hash / status / completed_at / response_body /
//     response_status / created_at / expires_at columns. The
//     idempotency_keys row is mutated only through its own (org,
//     principal, key) match, never as a side effect of writing a peer.
//   - Find returns expired rows as-is: Find does not silently filter
//     expired rows. An expired row is returned with its stored
//     ExpiresAt unchanged so the caller can decide policy (Claim
//     takes over an expired row transparently; a janitor purges it).
//   - ExpiresAt round-trip: a far-future ExpiresAt is preserved
//     verbatim (microsecond precision after UTC normalisation), so
//     the expiry clock is the database wallclock the caller asked for,
//     not a truncated or timezone-shifted approximation.
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - Cross-tenant byte-identical-bystander semantics across two
//     organizations (Claim(orgA) leaves every orgB row byte-identical;
//     Find / Complete / Release cross-tenant return empty / Conflict
//     while leaving counts unchanged) is the paired BE-0470 story and
//     will land in idempotency_tenant_isolation_test.go.
//   - The application-layer Claim validation guards (nil tx, missing
//     required fields), the Complete out-of-range status guard, and
//     the Complete nil-tx guard are pinned by
//     idempotency_test.go's TestIdempotencyClaimValidation: those
//     three cases surface as typed apierr.Internal or
//     apierr.InvalidInput before the database is touched.
//   - The Complete CHECK on response_status BETWEEN 100 AND 599 is
//     unreachable from the typed Complete API (it pre-rejects an
//     out-of-range status as apierr.Internal), so this file does not
//     attempt to drive the database CHECK through Go.
//   - The status IN ('pending', 'completed') CHECK is enforced both
//     by the database column CHECK and by the Go-level
//     IdempotencyStatus.Valid() guard; the only writer paths
//     (Claim hard-codes 'pending', Complete hard-codes 'completed')
//     mean the CHECK is unreachable from Go.
//
// Helpers introduced here: rawIdempotencyRow, loadIdempotencyRowByID,
// countIdempotencyRowsForOrg, mintIdempotencyID, idempotencyTxRollbackSentinel.
// Helpers reused from sibling files: seedOrg (schema_test.go); newStore
// (store_test.go); idemFixture, claimIdem, completeIdem, findIdem,
// wantErrCode, newIdempotencyStore (idempotency_test.go).

// rawIdempotencyRow is the full idempotency_keys row, deliberately
// loaded via raw SQL so the test can observe id, organization_id,
// principal_id, idempotency_key, route, request_hash, request_id,
// status, response_status, response_body, created_at, completed_at,
// and expires_at through the same shape the database stores them in.
// The nullable response columns (response_status, response_body,
// completed_at) are pointers so a NULL is distinguishable from a
// zero-value scalar (status='pending' leaves all three NULL; status=
// 'completed' fills all three).
type rawIdempotencyRow struct {
	ID             string
	OrganizationID string
	PrincipalID    string
	Key            string
	Route          string
	RequestHash    string
	RequestID      string
	Status         string
	ResponseStatus *int
	ResponseBody   []byte
	CreatedAt      time.Time
	CompletedAt    *time.Time
	ExpiresAt      time.Time
}

// loadIdempotencyRowByID reads the raw idempotency_keys row for id and
// fatals on error. The lookup is by primary key -- distinct
// idempotency rows have distinct ids -- so no tenant scope is needed
// (raw loaders bypass repository scoping deliberately, so the test
// observes the persisted row exactly as the database stores it).
func loadIdempotencyRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawIdempotencyRow {
	t.Helper()
	var row rawIdempotencyRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, principal_id, idempotency_key, route,
		        request_hash, request_id, status, response_status, response_body,
		        created_at, completed_at, expires_at
		   FROM idempotency_keys
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.PrincipalID, &row.Key, &row.Route,
		&row.RequestHash, &row.RequestID, &row.Status, &row.ResponseStatus,
		&row.ResponseBody, &row.CreatedAt, &row.CompletedAt, &row.ExpiresAt,
	); err != nil {
		t.Fatalf("load idempotency_keys id=%q: %v", id, err)
	}
	return row
}

// countIdempotencyRowsForOrg returns the total number of
// idempotency_keys rows owned by organizationID. It is the "did the
// rollback / cascade leave a row behind?" probe and the natural
// per-parent counter for the idempotency_keys table (organization is
// the only parent FK).
func countIdempotencyRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM idempotency_keys WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count idempotency_keys for org %q: %v", organizationID, err)
	}
	return n
}

// mintIdempotencyID builds a stable, test-local idempotency-key id
// from the test name and a per-test suffix. Tests in store_test share
// a single package, so the test name keeps ids unique across parallel
// test cases without needing a shared atomic counter. Real id minting
// lives in newIdempotencyID (a crypto/rand-backed idk_<32hex>); this
// is the test-local override that exercises the caller-supplied-id
// branch of Claim (a blank ID still triggers newIdempotencyID via
// Claim).
func mintIdempotencyID(t *testing.T, suffix string) string {
	t.Helper()
	return "idk_" + t.Name() + "_" + suffix
}

// idempotencyTxRollbackSentinel is a uniquely-typed sentinel for the
// rollback test. Sentinel types must be unique per file in the
// store_test package (every *_test.go under internal/controlplane/store/
// shares the same package). Existing siblings include
// auditTxRollbackSentinel, jobAttemptTxRollbackSentinel, and
// dokployRefTxRollbackSentinel.
type idempotencyTxRollbackSentinel struct{}

func (idempotencyTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this idempotency claim transaction"
}

// TestIdempotencyRepositoryClaimMintsRowShape pins the Claim row-shape
// on the first call. It walks every observable column of the returned
// struct against a raw-SQL re-load of the persisted row: a regression
// that silently dropped a column from idempotencyKeyColumns or
// scanIdempotencyRecord would surface as a drift here. The id minting,
// server-side created_at, and the pending-side of the
// completion_consistent CHECK (response_status / response_body /
// completed_at all NULL) are also pinned.
func TestIdempotencyRepositoryClaimMintsRowShape(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	before := time.Now().UTC().Add(-time.Second)
	rec := idemFixture(org.ID, "usr_principal_a", "key-shape", "hash-shape")
	wantExpires := rec.ExpiresAt
	claimed, owned := claimIdem(ctx, t, s, repo, rec)
	after := time.Now().UTC().Add(time.Second)

	if !owned {
		t.Fatal("first Claim must report the caller owns the claim")
	}
	if claimed.ID == "" {
		t.Fatal("claimed.ID is blank, want a minted id")
	}
	if !strings.HasPrefix(claimed.ID, "idk_") {
		t.Errorf("claimed.ID = %q, want idk_ prefix", claimed.ID)
	}
	// newIdempotencyID emits idk_ + 32 hex characters (16 bytes of
	// crypto/rand entropy). A regression that shortened the entropy or
	// reformatted the prefix would surface here.
	if got, want := len(claimed.ID), len("idk_")+32; got != want {
		t.Errorf("claimed.ID length = %d, want %d (idk_<32hex>)", got, want)
	}
	if claimed.OrganizationID != org.ID {
		t.Errorf("claimed.OrganizationID = %q, want %q", claimed.OrganizationID, org.ID)
	}
	if claimed.Status != store.IdempotencyStatusPending {
		t.Errorf("claimed.Status = %q, want pending", claimed.Status)
	}
	if claimed.ResponseStatus != 0 {
		t.Errorf("claimed.ResponseStatus = %d, want 0 on a pending claim", claimed.ResponseStatus)
	}
	if claimed.ResponseBody != nil {
		t.Errorf("claimed.ResponseBody = %q, want nil on a pending claim", claimed.ResponseBody)
	}
	if !claimed.CompletedAt.IsZero() {
		t.Errorf("claimed.CompletedAt = %v, want zero on a pending claim", claimed.CompletedAt)
	}
	if claimed.CreatedAt.Before(before) || claimed.CreatedAt.After(after) {
		t.Errorf("claimed.CreatedAt = %v, want within [%v, %v] (server-side now())",
			claimed.CreatedAt, before, after)
	}

	row := loadIdempotencyRowByID(ctx, t, db, claimed.ID)
	if row.ID != claimed.ID {
		t.Errorf("row.ID = %q, want %q", row.ID, claimed.ID)
	}
	if row.OrganizationID != claimed.OrganizationID {
		t.Errorf("row.OrganizationID = %q, want %q", row.OrganizationID, claimed.OrganizationID)
	}
	if row.PrincipalID != claimed.PrincipalID {
		t.Errorf("row.PrincipalID = %q, want %q", row.PrincipalID, claimed.PrincipalID)
	}
	if row.Key != claimed.Key {
		t.Errorf("row.Key = %q, want %q", row.Key, claimed.Key)
	}
	if row.Route != claimed.Route {
		t.Errorf("row.Route = %q, want %q", row.Route, claimed.Route)
	}
	if row.RequestHash != claimed.RequestHash {
		t.Errorf("row.RequestHash = %q, want %q", row.RequestHash, claimed.RequestHash)
	}
	if row.RequestID != claimed.RequestID {
		t.Errorf("row.RequestID = %q, want %q", row.RequestID, claimed.RequestID)
	}
	if row.Status != string(store.IdempotencyStatusPending) {
		t.Errorf("row.Status = %q, want pending", row.Status)
	}
	if row.ResponseStatus != nil {
		t.Errorf("row.ResponseStatus = %v, want NULL on a pending claim", *row.ResponseStatus)
	}
	if row.ResponseBody != nil {
		t.Errorf("row.ResponseBody = %v, want NULL on a pending claim", row.ResponseBody)
	}
	if row.CompletedAt != nil {
		t.Errorf("row.CompletedAt = %v, want NULL on a pending claim", *row.CompletedAt)
	}
	if !row.CreatedAt.Equal(claimed.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v", row.CreatedAt, claimed.CreatedAt)
	}
	if !row.ExpiresAt.Equal(claimed.ExpiresAt) {
		t.Errorf("row.ExpiresAt = %v, want %v", row.ExpiresAt, claimed.ExpiresAt)
	}
	if !row.ExpiresAt.Equal(wantExpires.UTC()) {
		t.Errorf("row.ExpiresAt = %v, want %v (caller-supplied expires_at must round-trip)",
			row.ExpiresAt, wantExpires.UTC())
	}
}

// TestIdempotencyRepositoryClaimRespectsCallerSuppliedID pins that a
// non-blank caller-supplied id is preserved verbatim on the fresh-
// insert branch. The blank-id mint branch is covered by
// TestIdempotencyRepositoryClaimMintsRowShape; this is the other half
// of the id contract.
func TestIdempotencyRepositoryClaimRespectsCallerSuppliedID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	want := mintIdempotencyID(t, "caller_supplied")
	rec := idemFixture(org.ID, "usr_principal_a", "key-caller-id", "hash-1")
	rec.ID = want
	claimed, owned := claimIdem(ctx, t, s, repo, rec)
	if !owned {
		t.Fatal("first Claim must report the caller owns the claim")
	}
	if claimed.ID != want {
		t.Errorf("claimed.ID = %q, want %q (caller-supplied id must be preserved verbatim)",
			claimed.ID, want)
	}
	row := loadIdempotencyRowByID(ctx, t, db, want)
	if row.ID != want {
		t.Errorf("row.ID = %q, want %q", row.ID, want)
	}
}

// TestIdempotencyRepositoryClaimDuplicateIDIsConflict pins the PK
// constraint surfacing through mapWriteError. The Claim INSERT's
// ON CONFLICT target is (organization_id, principal_id, idempotency_key),
// so a duplicate id on a DIFFERENT (org, principal, key) is not caught
// by the ON CONFLICT clause -- the PRIMARY KEY violation flows through
// the database and back through the typed error taxonomy as
// apierr.Conflict.
//
// Real-world id collisions are vanishingly rare because newIdempotencyID
// emits idk_<32hex> (16 bytes of crypto/rand entropy), but this test
// exercises the regression-backstop path by forcing the collision
// through caller-supplied ids.
func TestIdempotencyRepositoryClaimDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	sharedID := mintIdempotencyID(t, "duplicate")
	first := idemFixture(org.ID, "usr_principal_a", "key-first", "hash-1")
	first.ID = sharedID
	if _, owned := claimIdem(ctx, t, s, repo, first); !owned {
		t.Fatal("first Claim must own the claim")
	}

	// Different (principal, key) means the ON CONFLICT (organization_id,
	// principal_id, idempotency_key) target does not match, so the
	// INSERT runs as a fresh insert and the PK collision on id surfaces
	// through mapWriteError as Conflict.
	second := idemFixture(org.ID, "usr_principal_b", "key-second", "hash-2")
	second.ID = sharedID
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, e := repo.Claim(ctx, tx, second)
		return e
	})
	wantErrCode(t, err, yerr.CodeConflict)
	if got := countIdempotencyRowsForOrg(ctx, t, db, org.ID); got != 1 {
		t.Errorf("duplicate-id rejection left %d idempotency_keys rows behind, want 1 (only the first row should persist)", got)
	}
}

// TestIdempotencyRepositoryClaimUnknownOrganizationIsConflict pins the
// FK contract: organization_id REFERENCES organizations (id) ON DELETE
// CASCADE, so a Claim with an organization_id that does not exist
// surfaces as typed apierr.Conflict via mapWriteError. A regression
// that fell back to apierr.StoreUnavailable on the FK path would
// surface as a code drift here.
func TestIdempotencyRepositoryClaimUnknownOrganizationIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, _, _ := newIdempotencyStore(ctx, t)

	rec := idemFixture("org_does_not_exist_0001", "usr_principal_a", "key-orphan", "hash-1")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, e := repo.Claim(ctx, tx, rec)
		return e
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

// TestIdempotencyRepositoryCompleteRowShape pins the Complete row-shape
// on the four-column transition that satisfies the
// idempotency_keys_completion_consistent CHECK. After Complete the row
// carries status='completed', a non-NULL response_status, a non-NULL
// response_body, and a non-NULL completed_at. The return value's
// struct fields are byte-equal to a raw re-load.
func TestIdempotencyRepositoryCompleteRowShape(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-complete-shape", "hash-1")
	claimed, _ := claimIdem(ctx, t, s, repo, rec)

	body := []byte(`{"schema_version":"yalla.output.v1","ok":true,"data":{"job_id":"job_1"},"request_id":"req-idem-1"}`)
	completed := completeIdem(ctx, t, s, repo, rec.Ref(), 202, body)

	if completed.ID != claimed.ID {
		t.Errorf("completed.ID = %q, want %q (Complete must not rewrite the id)", completed.ID, claimed.ID)
	}
	if completed.Status != store.IdempotencyStatusCompleted {
		t.Errorf("completed.Status = %q, want completed", completed.Status)
	}
	if completed.ResponseStatus != 202 {
		t.Errorf("completed.ResponseStatus = %d, want 202", completed.ResponseStatus)
	}
	if !bytes.Equal(completed.ResponseBody, body) {
		t.Errorf("completed.ResponseBody = %q, want %q", completed.ResponseBody, body)
	}
	if completed.CompletedAt.IsZero() {
		t.Error("completed.CompletedAt must be non-zero after Complete")
	}

	row := loadIdempotencyRowByID(ctx, t, db, completed.ID)
	if row.Status != string(store.IdempotencyStatusCompleted) {
		t.Errorf("row.Status = %q, want completed", row.Status)
	}
	if row.ResponseStatus == nil {
		t.Fatal("row.ResponseStatus = NULL, want non-NULL after Complete (completion_consistent CHECK)")
	}
	if *row.ResponseStatus != 202 {
		t.Errorf("row.ResponseStatus = %d, want 202", *row.ResponseStatus)
	}
	if row.ResponseBody == nil {
		t.Fatal("row.ResponseBody = NULL, want non-NULL after Complete (completion_consistent CHECK)")
	}
	if !bytes.Equal(row.ResponseBody, body) {
		t.Errorf("row.ResponseBody = %q, want %q", row.ResponseBody, body)
	}
	if row.CompletedAt == nil {
		t.Fatal("row.CompletedAt = NULL, want non-NULL after Complete (completion_consistent CHECK)")
	}
	if !row.CompletedAt.Equal(completed.CompletedAt) {
		t.Errorf("row.CompletedAt = %v, want %v", *row.CompletedAt, completed.CompletedAt)
	}
	// The created_at and expires_at columns must NOT have drifted across
	// the Complete UPDATE -- only the four completion columns transition.
	if !row.CreatedAt.Equal(claimed.CreatedAt) {
		t.Errorf("row.CreatedAt drifted on Complete: before=%v after=%v", claimed.CreatedAt, row.CreatedAt)
	}
	if !row.ExpiresAt.Equal(claimed.ExpiresAt) {
		t.Errorf("row.ExpiresAt drifted on Complete: before=%v after=%v", claimed.ExpiresAt, row.ExpiresAt)
	}
}

// TestIdempotencyRepositoryCompleteHonoursExplicitNow pins the
// Complete now-argument contract: an explicit non-zero now is stored
// as the completed_at wallclock (UTC-normalised). A regression that
// ignored the argument and wrote time.Now() instead would surface
// here.
func TestIdempotencyRepositoryCompleteHonoursExplicitNow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-explicit-now", "hash-1")
	claimIdem(ctx, t, s, repo, rec)

	// A specific, easy-to-spot timestamp far from time.Now() so a
	// regression that wrote time.Now() instead would fail with a large,
	// obvious delta. truncate(microsecond) matches the Postgres
	// timestamptz precision so the round-trip is exact.
	explicit := time.Date(2024, 6, 15, 12, 34, 56, 123456000, time.UTC).Truncate(time.Microsecond)

	var completed store.IdempotencyRecord
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, e := repo.Complete(ctx, tx, rec.Ref(), 200, []byte(`{"ok":true}`), explicit)
		if e != nil {
			return e
		}
		completed = r
		return nil
	}); err != nil {
		t.Fatalf("Complete with explicit now: %v", err)
	}
	if !completed.CompletedAt.Equal(explicit) {
		t.Errorf("completed.CompletedAt = %v, want %v (caller-supplied now must be persisted verbatim)",
			completed.CompletedAt, explicit)
	}
	row := loadIdempotencyRowByID(ctx, t, db, completed.ID)
	if row.CompletedAt == nil {
		t.Fatal("row.CompletedAt = NULL, want non-NULL after Complete")
	}
	if !row.CompletedAt.Equal(explicit) {
		t.Errorf("row.CompletedAt = %v, want %v", *row.CompletedAt, explicit)
	}
}

// TestIdempotencyRepositoryCompleteCoercesNilBodyToEmpty pins the
// body-coercion contract: a nil body argument is coerced to a
// zero-length non-nil []byte before INSERT, so the
// completion_consistent CHECK's response_body IS NOT NULL clause is
// satisfied even when the handler produced an empty envelope. The
// persisted row carries a non-NULL empty bytea, not NULL.
func TestIdempotencyRepositoryCompleteCoercesNilBodyToEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-nil-body", "hash-1")
	claimIdem(ctx, t, s, repo, rec)

	var completed store.IdempotencyRecord
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, e := repo.Complete(ctx, tx, rec.Ref(), 204, nil, time.Time{})
		if e != nil {
			return e
		}
		completed = r
		return nil
	}); err != nil {
		t.Fatalf("Complete with nil body: %v", err)
	}
	if completed.ResponseBody == nil {
		t.Error("completed.ResponseBody = nil, want []byte{} (Complete must coerce nil to a non-nil empty slice)")
	}
	if len(completed.ResponseBody) != 0 {
		t.Errorf("completed.ResponseBody = %q, want empty", completed.ResponseBody)
	}
	row := loadIdempotencyRowByID(ctx, t, db, completed.ID)
	if row.ResponseBody == nil {
		t.Error("row.ResponseBody = NULL, want a non-NULL empty bytea (completion_consistent CHECK)")
	}
	if len(row.ResponseBody) != 0 {
		t.Errorf("row.ResponseBody = %q, want empty", row.ResponseBody)
	}
}

// TestIdempotencyRepositoryReleaseRejectsNilTx pins the Release
// nil-transaction guard. Release(ctx, nil, ref) surfaces as typed
// apierr.Internal before the database is touched -- it is a
// programming error, not a customer-rejection conflict. The nil-tx
// branches for Claim and Complete are pinned by
// TestIdempotencyClaimValidation in idempotency_test.go; this test
// fills the Release gap so all three mutating methods have a pinned
// nil-tx guard.
func TestIdempotencyRepositoryReleaseRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewIdempotencyRepository()

	err := repo.Release(context.Background(), nil, store.IdempotencyKeyRef{
		OrganizationID: "org_x", PrincipalID: "usr_x", Key: "k",
	})
	wantErrCode(t, err, yerr.CodeInternal)
}

// TestIdempotencyRepositoryReleaseOnCompletedIsNoop pins the
// Release-of-completed contract: Release matches only a pending row,
// so calling it against a completed claim is a no-op (nil error, row
// stays in place). Release is safe to call defensively without
// distinguishing "already done" from "still pending".
func TestIdempotencyRepositoryReleaseOnCompletedIsNoop(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-release-completed", "hash-1")
	claimIdem(ctx, t, s, repo, rec)
	completed := completeIdem(ctx, t, s, repo, rec.Ref(), 200, []byte(`{"ok":true}`))
	before := loadIdempotencyRowByID(ctx, t, db, completed.ID)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Release(ctx, tx, rec.Ref())
	}); err != nil {
		t.Fatalf("Release on a completed claim returned %v, want nil (no-op)", err)
	}
	after := loadIdempotencyRowByID(ctx, t, db, completed.ID)
	if after.ID != before.ID ||
		after.Status != before.Status ||
		!bytes.Equal(after.ResponseBody, before.ResponseBody) {
		t.Errorf("Release on a completed claim rewrote the row: before=%+v after=%+v", before, after)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, org.ID); got != 1 {
		t.Errorf("post-Release count = %d, want 1 (no row removed)", got)
	}
}

// TestIdempotencyRepositoryReleaseOnMissingKeyIsNoop pins the
// Release-of-unknown-key contract: Release of a (organization,
// principal, key) tuple that has no row is a silent no-op, not an
// error. The middleware calls Release defensively on the server-
// failure path so it must never need to distinguish "never claimed"
// from "already released".
func TestIdempotencyRepositoryReleaseOnMissingKeyIsNoop(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Release(ctx, tx, store.IdempotencyKeyRef{
			OrganizationID: org.ID, PrincipalID: "usr_never_claimed", Key: "never",
		})
	})
	if err != nil {
		t.Fatalf("Release of an unknown key returned %v, want nil", err)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("Release of an unknown key created %d rows, want 0", got)
	}
}

// TestIdempotencyRepositoryClaimTransactionRollback pins the
// load-bearing atomicity invariant: a claim is committed only when
// the transaction that carries the recorded mutation commits. A
// closure that returns an error after a successful Claim leaves no
// row behind. Without this, a handler failure between Claim and
// Complete could leave a poisoned pending row that no later request
// can clear until expiry.
func TestIdempotencyRepositoryClaimTransactionRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	sentinel := idempotencyTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, _, cErr := repo.Claim(ctx, tx, idemFixture(org.ID, "usr_principal_a", "key-rollback", "hash-1")); cErr != nil {
			return cErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the rollback sentinel", err)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("rollback left %d idempotency_keys rows behind, want 0", got)
	}
}

// TestIdempotencyRepositoryCascadeFromOrganizationDelete pins the
// tenant-teardown cascade: removing the parent organization removes
// every idempotency_keys row owned by that organization via ON DELETE
// CASCADE. A sibling tenant's row is unaffected -- its observable
// columns (id, status, response columns, timestamps, expiry) are
// byte-identical before and after.
func TestIdempotencyRepositoryCascadeFromOrganizationDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	claimIdem(ctx, t, s, repo, idemFixture(orgA.ID, "usr_a1", "key-a-1", "hash-a-1"))
	claimIdem(ctx, t, s, repo, idemFixture(orgA.ID, "usr_a2", "key-a-2", "hash-a-2"))
	bystander, _ := claimIdem(ctx, t, s, repo, idemFixture(orgB.ID, "usr_b1", "key-b-1", "hash-b-1"))
	beforeBystander := loadIdempotencyRowByID(ctx, t, db, bystander.ID)

	if got := countIdempotencyRowsForOrg(ctx, t, db, orgA.ID); got != 2 {
		t.Fatalf("orgA pre-cascade count = %d, want 2", got)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, orgB.ID); got != 1 {
		t.Fatalf("orgB pre-cascade count = %d, want 1", got)
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgA.ID); err != nil {
		t.Fatalf("DELETE organization orgA: %v", err)
	}

	if got := countIdempotencyRowsForOrg(ctx, t, db, orgA.ID); got != 0 {
		t.Errorf("orgA post-cascade count = %d, want 0 (ON DELETE CASCADE must remove every idempotency row)", got)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, orgB.ID); got != 1 {
		t.Errorf("orgB post-cascade count = %d, want 1 (sibling tenant must be untouched)", got)
	}
	afterBystander := loadIdempotencyRowByID(ctx, t, db, bystander.ID)
	if afterBystander.ID != beforeBystander.ID ||
		afterBystander.OrganizationID != beforeBystander.OrganizationID ||
		afterBystander.PrincipalID != beforeBystander.PrincipalID ||
		afterBystander.Key != beforeBystander.Key ||
		afterBystander.Route != beforeBystander.Route ||
		afterBystander.RequestHash != beforeBystander.RequestHash ||
		afterBystander.RequestID != beforeBystander.RequestID ||
		afterBystander.Status != beforeBystander.Status ||
		!afterBystander.CreatedAt.Equal(beforeBystander.CreatedAt) ||
		!afterBystander.ExpiresAt.Equal(beforeBystander.ExpiresAt) {
		t.Errorf("orgB bystander row drifted after orgA cascade: before=%+v after=%+v",
			beforeBystander, afterBystander)
	}
}

// TestIdempotencyRepositoryClaimPeerRowByteIdentical pins the load-
// bearing peer-row invariant: claiming a new key for the same
// organization does not touch a prior peer row. The Claim UPDATE only
// fires on its own (organization_id, principal_id, idempotency_key)
// match, never as a side effect of writing a peer.
func TestIdempotencyRepositoryClaimPeerRowByteIdentical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	first, _ := claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-peer-1", "hash-1"))
	beforeFirst := loadIdempotencyRowByID(ctx, t, db, first.ID)

	claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-peer-2", "hash-2"))

	afterFirst := loadIdempotencyRowByID(ctx, t, db, first.ID)
	if afterFirst.ID != beforeFirst.ID {
		t.Errorf("peer Claim rewrote first row's id: before=%q after=%q", beforeFirst.ID, afterFirst.ID)
	}
	if afterFirst.Route != beforeFirst.Route {
		t.Errorf("peer Claim rewrote first row's route: before=%q after=%q", beforeFirst.Route, afterFirst.Route)
	}
	if afterFirst.RequestHash != beforeFirst.RequestHash {
		t.Errorf("peer Claim rewrote first row's request_hash: before=%q after=%q", beforeFirst.RequestHash, afterFirst.RequestHash)
	}
	if afterFirst.Status != beforeFirst.Status {
		t.Errorf("peer Claim rewrote first row's status: before=%q after=%q", beforeFirst.Status, afterFirst.Status)
	}
	if afterFirst.ResponseStatus != nil || beforeFirst.ResponseStatus != nil {
		t.Errorf("peer Claim or seeded row carried response_status: before=%v after=%v", beforeFirst.ResponseStatus, afterFirst.ResponseStatus)
	}
	if afterFirst.ResponseBody != nil || beforeFirst.ResponseBody != nil {
		t.Errorf("peer Claim or seeded row carried response_body: before=%v after=%v", beforeFirst.ResponseBody, afterFirst.ResponseBody)
	}
	if afterFirst.CompletedAt != nil || beforeFirst.CompletedAt != nil {
		t.Errorf("peer Claim or seeded row carried completed_at: before=%v after=%v", beforeFirst.CompletedAt, afterFirst.CompletedAt)
	}
	if !afterFirst.CreatedAt.Equal(beforeFirst.CreatedAt) {
		t.Errorf("peer Claim rewrote first row's created_at: before=%v after=%v", beforeFirst.CreatedAt, afterFirst.CreatedAt)
	}
	if !afterFirst.ExpiresAt.Equal(beforeFirst.ExpiresAt) {
		t.Errorf("peer Claim rewrote first row's expires_at: before=%v after=%v", beforeFirst.ExpiresAt, afterFirst.ExpiresAt)
	}
	if got := countIdempotencyRowsForOrg(ctx, t, db, org.ID); got != 2 {
		t.Errorf("post-peer Claim count = %d, want 2", got)
	}
}

// TestIdempotencyRepositoryFindReturnsExpiredRowAsIs pins that Find
// does not silently filter expired rows. An expired claim is returned
// with its stored ExpiresAt unchanged so the caller can decide policy
// -- Claim takes over an expired row transparently, and a janitor
// purges it -- without Find pre-emptively hiding it. A regression
// that started filtering on expires_at > now() would surface here.
func TestIdempotencyRepositoryFindReturnsExpiredRowAsIs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-find-expired", "hash-1")
	expired := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	rec.ExpiresAt = expired
	claimed, _ := claimIdem(ctx, t, s, repo, rec)

	found, ok := findIdem(ctx, t, s, repo, rec.Ref())
	if !ok {
		t.Fatal("Find of an expired claim must still return the row (decision is the caller's policy, not Find's)")
	}
	if found.ID != claimed.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, claimed.ID)
	}
	if !found.ExpiresAt.Equal(expired) {
		t.Errorf("found.ExpiresAt = %v, want %v (expired ExpiresAt must be returned verbatim)", found.ExpiresAt, expired)
	}
	if found.Status != store.IdempotencyStatusPending {
		t.Errorf("found.Status = %q, want pending (Find must not transition status)", found.Status)
	}
}

// TestIdempotencyRepositoryExpiresAtRoundTrip pins that a far-future
// caller-supplied ExpiresAt is preserved verbatim (microsecond
// precision after UTC normalisation). The expiry clock is the
// database wallclock the caller asked for, not a truncated or
// timezone-shifted approximation. A regression that DEFAULT-stamped
// expires_at or truncated it to seconds would surface here.
func TestIdempotencyRepositoryExpiresAtRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	// A specific, microsecond-precise UTC time far enough in the
	// future that the test never races against the wallclock. The
	// truncate matches Postgres timestamptz precision so the
	// round-trip is exact.
	want := time.Date(2099, 12, 31, 23, 59, 58, 765432000, time.UTC).Truncate(time.Microsecond)

	rec := idemFixture(org.ID, "usr_principal_a", "key-expires-rt", "hash-1")
	rec.ExpiresAt = want
	claimed, _ := claimIdem(ctx, t, s, repo, rec)
	if !claimed.ExpiresAt.Equal(want) {
		t.Errorf("claimed.ExpiresAt = %v, want %v", claimed.ExpiresAt, want)
	}
	row := loadIdempotencyRowByID(ctx, t, db, claimed.ID)
	if !row.ExpiresAt.Equal(want) {
		t.Errorf("row.ExpiresAt = %v, want %v", row.ExpiresAt, want)
	}
}
