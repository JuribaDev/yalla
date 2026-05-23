// Repository-layer tenant-isolation tests for the idempotency_keys
// table (BE-0470). idempotency_keys is the durable claim/replay record
// for mutating control-plane endpoints: the first request claims the
// key (status 'pending') and Complete records the rendered response
// envelope (status 'completed') so a retry replays the stored envelope
// instead of re-running the handler. A row that belongs to one tenant
// is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id) — the only parent FK
//	    idempotency_keys carries;
//	(b) every IdempotencyRepository mutating method having
//	    organization_id as the leading column of its row-matching
//	    predicate: Claim's INSERT … ON CONFLICT target is
//	    (organization_id, principal_id, idempotency_key); Complete's
//	    UPDATE and Release's DELETE both filter
//	    `organization_id = $1 AND principal_id = $2 AND idempotency_key = $3`
//	    BEFORE the row-state predicate runs;
//	(c) Find's read predicate is the same composite tuple — there is no
//	    ListByOrganization (Find is the only read surface) — so a
//	    cross-tenant lookup either resolves the (principal, key) pair
//	    inside the caller's org or returns the typed not-found shape.
//
// The IdempotencyRepository surface this file exercises against the
// cross-tenant boundary is the FULL public claim-protocol surface:
// Claim (upsert with steal-expired branch + global PK), Complete
// (state-transitioning UPDATE), Release (state-conditioned DELETE),
// and Find (composite-tuple read). There is no per-row Update other
// than Complete and no caller-facing Delete other than Release; row
// removal is otherwise reachable only through Claim's expiry-takeover
// branch (in-tenant) or ON DELETE CASCADE on tenant teardown (the
// final probe in this file).
//
// This file pins the cross-tenant gap-fill probes the idempotency_keys
// invariants file (idempotency_repository_invariants_test.go) explicitly
// delegates here:
//
//   - Claim(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns several idempotency rows (pending + completed,
//     varying principals and keys, including a row whose
//     (principal_id, idempotency_key) tuple exactly mirrors the key
//     orgA is about to claim) a Claim on orgA mints a fresh row owned
//     by orgA and leaves every observable column on every orgB row
//     unchanged. A regression that dropped organization_id from the
//     ON CONFLICT target would surface here as orgB's mirror-tuple row
//     being silently rewritten by orgA's UPSERT.
//   - Claim(orgA) per-tenant row-count: orgA's count goes up by one,
//     orgB's count is unchanged. A regression that double-counted
//     across tenants (e.g. an unbounded `SELECT count(*)`) is caught
//     by the count helper independently of the byte-identity helper.
//   - Cross-tenant id-collision is Conflict, bystander byte-identical:
//     idempotency_keys.id is a global PRIMARY KEY. A second Claim
//     under a different tenant attempting to mint the SAME id (and a
//     different (principal_id, idempotency_key) tuple so the ON
//     CONFLICT target does not match) surfaces a PK-violation
//     mapWriteError → apierr.Conflict; orgA's bystander row is
//     byte-identical, and the global row count is unchanged so the
//     rolled-back row did not land in some other tenant's slot.
//   - Complete(orgA, orgB's principal+key) is Conflict, bystander
//     byte-identical: Complete's UPDATE matches zero rows when the
//     organization_id leg of the WHERE excludes orgB's pending claim,
//     so the typed Conflict ("no longer pending") fires WITHOUT
//     reading the foreign row body. orgB's row remains pending and
//     byte-identical — none of its response_status / response_body /
//     completed_at fields leak into orgA's transaction. A regression
//     that dropped organization_id from the Complete WHERE would
//     either rewrite orgB's row (worst case) or silently complete
//     orgA's "claim" with a body it does not own.
//   - Release(orgA, orgB's principal+key) is a no-op, bystander
//     byte-identical: Release's DELETE matches zero rows under the
//     wrong tenant and returns nil (Release is "safe to call
//     defensively" per the repository contract). orgB's pending row
//     remains. A regression that dropped organization_id from the
//     Release WHERE would delete orgB's claim, which the bystander
//     byte-identity check catches as a missing-row.
//   - Find(orgA, orgB's principal+key) is not-found, counts unchanged:
//     Find's WHERE is tenant-scoped first, so a cross-tenant ref
//     resolves to (zero-record, false, nil) — never to orgB's row.
//     The phantom-tenant variant pins the same probe under an
//     organization_id that names no row at all (no FK row is required
//     because Find is a read), AND that the read is side-effect-free
//     against every real tenant's row count.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's idempotency rows. orgB's rows must remain
//     byte-identical to their baselines, including pending vs.
//     completed status, the nullable response_status / response_body /
//     completed_at completion columns, and the database-assigned
//     created_at and caller-supplied expires_at timestamps. The
//     single-bystander variant of this cascade is already pinned by
//     idempotency_repository_invariants_test.go's
//     TestIdempotencyRepositoryCascadeFromOrganizationDelete (which
//     seeds one orgB row); the BE-0470 variant deepens it with a
//     three-row orgB pool covering the pending / completed / expired
//     spread and a byte-identity assertion through
//     assertIdempotencyRowByteIdentical on every bystander row (so a
//     column drift on any persisted shape — including the nullable
//     completion columns — surfaces as a named field diff instead of
//     a single opaque mismatch).
//
// Helpers introduced here: assertIdempotencyRowByteIdentical (the
// raw-row snapshot comparator — necessary because rawIdempotencyRow
// carries nullable *int / *time.Time / []byte completion columns whose
// pending-vs-completed distinction is observable through nil-ness, so
// every byte-identity probe must compare BOTH the pointer-nil-ness
// AND the dereferenced value when present), and
// seedTwoTenantIdempotencyFixture (two-organization fixture, narrower
// than the dokploy_refs equivalent because idempotency_keys has no
// project/environment/service parent chain).
//
// Helpers reused from sibling files: seedOrg (schema_test.go);
// newIdempotencyStore, idemFixture, claimIdem, completeIdem, findIdem,
// wantErrCode (idempotency_test.go); rawIdempotencyRow,
// loadIdempotencyRowByID, countIdempotencyRowsForOrg,
// mintIdempotencyID (idempotency_repository_invariants_test.go).
package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// assertIdempotencyRowByteIdentical compares every column of a
// rawIdempotencyRow pair (the persisted shape, including the nullable
// response_status / response_body / completed_at completion columns
// and the database-assigned created_at + caller-supplied expires_at
// timestamps) and emits a single diagnostic per drift. It is the
// byte-level snapshot probe used after every cross-tenant operation —
// if any orgB row's observable persisted shape drifts after an orgA
// Claim, an orgA Complete, an orgA Release, an orgA Find, or an orgA
// cascade-delete, this helper surfaces it as a named field diff.
//
// Every business column is compared individually so a rewrite of any
// one would surface as a named field diff in the failure message,
// rather than a single opaque "row mismatch" diagnostic. The nullable
// pointer-bearing columns (ResponseStatus, ResponseBody, CompletedAt)
// are compared first by nil-ness — a regression that flipped a
// pending row's completion columns from NULL to a zero-value scalar
// would surface as a nil-vs-non-nil diff — and then by dereferenced
// value when both sides are non-nil.
func assertIdempotencyRowByteIdentical(t *testing.T, label string, baseline, after rawIdempotencyRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.PrincipalID != baseline.PrincipalID {
		t.Errorf("%s: bystander.principal_id = %q, want %q",
			label, after.PrincipalID, baseline.PrincipalID)
	}
	if after.Key != baseline.Key {
		t.Errorf("%s: bystander.idempotency_key = %q, want %q",
			label, after.Key, baseline.Key)
	}
	if after.Route != baseline.Route {
		t.Errorf("%s: bystander.route = %q, want %q",
			label, after.Route, baseline.Route)
	}
	if after.RequestHash != baseline.RequestHash {
		t.Errorf("%s: bystander.request_hash = %q, want %q",
			label, after.RequestHash, baseline.RequestHash)
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: bystander.request_id = %q, want %q",
			label, after.RequestID, baseline.RequestID)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: bystander.status = %q, want %q",
			label, after.Status, baseline.Status)
	}
	switch {
	case after.ResponseStatus == nil && baseline.ResponseStatus == nil:
		// both NULL — the pending side of the completion_consistent CHECK.
	case after.ResponseStatus == nil || baseline.ResponseStatus == nil:
		t.Errorf("%s: bystander.response_status nil-ness drifted: before=%v after=%v",
			label, fmtIntPtr(baseline.ResponseStatus), fmtIntPtr(after.ResponseStatus))
	case *after.ResponseStatus != *baseline.ResponseStatus:
		t.Errorf("%s: bystander.response_status = %d, want %d",
			label, *after.ResponseStatus, *baseline.ResponseStatus)
	}
	switch {
	case after.ResponseBody == nil && baseline.ResponseBody == nil:
		// both NULL — the pending side of the completion_consistent CHECK.
	case after.ResponseBody == nil || baseline.ResponseBody == nil:
		t.Errorf("%s: bystander.response_body nil-ness drifted: before=%v after=%v",
			label, baseline.ResponseBody, after.ResponseBody)
	case !bytes.Equal(after.ResponseBody, baseline.ResponseBody):
		t.Errorf("%s: bystander.response_body = %q, want %q",
			label, after.ResponseBody, baseline.ResponseBody)
	}
	switch {
	case after.CompletedAt == nil && baseline.CompletedAt == nil:
		// both NULL — the pending side of the completion_consistent CHECK.
	case after.CompletedAt == nil || baseline.CompletedAt == nil:
		t.Errorf("%s: bystander.completed_at nil-ness drifted: before=%v after=%v",
			label, fmtTimePtr(baseline.CompletedAt), fmtTimePtr(after.CompletedAt))
	case !after.CompletedAt.Equal(*baseline.CompletedAt):
		t.Errorf("%s: bystander.completed_at = %s, want %s",
			label, after.CompletedAt, baseline.CompletedAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %s, want %s",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.ExpiresAt.Equal(baseline.ExpiresAt) {
		t.Errorf("%s: bystander.expires_at = %s, want %s",
			label, after.ExpiresAt, baseline.ExpiresAt)
	}
}

// fmtIntPtr renders an optional response_status for the byte-identity
// failure message: "<nil>" when unset, "%d" when set. It exists so a
// failing nil-vs-non-nil drift on response_status reads naturally in
// the diagnostic ("before=<nil> after=200" rather than "before=
// 0xc00009a... after=0xc00009a..." pointer noise).
func fmtIntPtr(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return itoaInt(*p)
}

// fmtTimePtr renders an optional completed_at for the byte-identity
// failure message: "<nil>" when unset, the time string when set.
func fmtTimePtr(p *time.Time) string {
	if p == nil {
		return "<nil>"
	}
	return p.String()
}

// itoaInt is a local integer-to-string helper for fmtIntPtr. It avoids
// importing strconv solely for one call site; HTTP status codes are
// three-digit integers so the loop has a bounded constant cost.
func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// twoTenantIdempotencyFixture is the two-organization shape every test
// in this file seeds before the cross-tenant probe runs.
// idempotency_keys has no project/environment/service parent chain
// (its only parent FK is organizations), so the fixture is deliberately
// narrower than the dokploy_refs equivalent.
type twoTenantIdempotencyFixture struct {
	orgA testutil.Organization
	orgB testutil.Organization
}

// seedTwoTenantIdempotencyFixture creates two organizations the
// cross-tenant tests can use as orgA (writer / target) and orgB
// (bystander).
func seedTwoTenantIdempotencyFixture(
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
) twoTenantIdempotencyFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "idem-tenant-a")
	orgB := seedOrg(t, db, f, "idem-tenant-b")
	return twoTenantIdempotencyFixture{orgA: orgA, orgB: orgB}
}

// TestIdempotencyRepositoryClaimOnOrgADoesNotTouchOrgBRows pins the
// load-bearing cross-tenant Claim isolation invariant: when orgB owns
// several idempotency rows — including a row whose (principal_id,
// idempotency_key) tuple exactly mirrors the tuple orgA is about to
// claim — a Claim on orgA mints a fresh row owned by orgA and leaves
// every observable column on every orgB row byte-identical to its
// baseline. The ON CONFLICT target is (organization_id, principal_id,
// idempotency_key), so a regression that dropped organization_id from
// that tuple would resolve the conflict onto orgB's mirror-tuple row
// and silently rewrite it through the DO UPDATE branch — the
// worst-case cross-tenant idempotency data-corruption shape.
func TestIdempotencyRepositoryClaimOnOrgADoesNotTouchOrgBRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	// orgB seeds four rows covering the idempotency_keys shape spread:
	// (1) pending claim with the SAME (principal_id, idempotency_key)
	// orgA will mirror — the load-bearing bystander whose presence on
	// orgB exercises the per-tenant uniqueness of the ON CONFLICT
	// target; (2) completed claim with response envelope persisted
	// (anchors the completion columns against drift); (3) pending
	// claim under a distinct principal; (4) pending claim with a
	// distinct idempotency key — together a regression that touched
	// any one leg surfaces as a named field diff in the assertion
	// loop.
	bravoMirror, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_mirror", "mirror-key", "hash-bravo-mirror"))
	bravoCompleted, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_done", "done-key", "hash-bravo-done"))
	bravoCompletedFinal := completeIdem(ctx, t, s, repo, bravoCompleted.Ref(), 200,
		[]byte(`{"schema_version":"yalla.output.v1","data":{}}`))
	bravoOtherPrincipal, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_other", "mirror-key", "hash-bravo-other-principal"))
	bravoOtherKey, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_mirror", "other-key", "hash-bravo-other-key"))

	baselines := []rawIdempotencyRow{
		loadIdempotencyRowByID(ctx, t, db, bravoMirror.ID),
		loadIdempotencyRowByID(ctx, t, db, bravoCompletedFinal.ID),
		loadIdempotencyRowByID(ctx, t, db, bravoOtherPrincipal.ID),
		loadIdempotencyRowByID(ctx, t, db, bravoOtherKey.ID),
	}

	// orgA mirrors the (principal_id, idempotency_key) tuple bravoMirror
	// already owns under its OWN tenant. The ON CONFLICT target
	// includes organization_id, so this must succeed as a fresh INSERT
	// — never as a DO UPDATE branch fired on orgB's row.
	alpha, owned := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgA.ID, "usr_mirror", "mirror-key", "hash-alpha"))
	if !owned {
		t.Fatalf("Claim(orgA, mirror tuple) returned owned=false — the cross-tenant Claim must mint a fresh row, never resolve the conflict onto orgB's mirror row")
	}
	if alpha.OrganizationID != fix.orgA.ID {
		t.Fatalf("Claim(orgA, mirror tuple) returned org_id %q, want %q",
			alpha.OrganizationID, fix.orgA.ID)
	}
	if alpha.ID == bravoMirror.ID {
		t.Fatalf("Claim(orgA, mirror tuple) returned id %q, equal to orgB mirror row's id — the cross-tenant INSERT must mint a distinct id, never reuse the foreign row's PK",
			alpha.ID)
	}

	// Every orgB row must be byte-identical to its baseline.
	for _, baseline := range baselines {
		after := loadIdempotencyRowByID(ctx, t, db, baseline.ID)
		assertIdempotencyRowByteIdentical(t,
			"orgB bystander after orgA Claim",
			baseline, after)
	}
}

// TestIdempotencyRepositoryClaimOnOrgADoesNotChangeOrgBRowCount pins
// the corollary count probe: a Claim on orgA bumps orgA's per-tenant
// count by one and leaves orgB's count exactly equal to its
// pre-Claim value. The byte-identity test above proves no orgB row
// drifted in place; this test proves no orgB row was minted or
// deleted as a side effect — a regression that double-counted across
// tenants (e.g. an unbounded `SELECT count(*)` driving any background
// reconciliation) would surface here.
func TestIdempotencyRepositoryClaimOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	for i := 0; i < 2; i++ {
		claimIdem(ctx, t, s, repo,
			idemFixture(fix.orgA.ID, "usr_seed", "alpha-seed-key-"+itoaInt(i), "hash-alpha-seed-"+itoaInt(i)))
	}
	for i := 0; i < 5; i++ {
		claimIdem(ctx, t, s, repo,
			idemFixture(fix.orgB.ID, "usr_seed", "bravo-seed-key-"+itoaInt(i), "hash-bravo-seed-"+itoaInt(i)))
	}

	priorAlphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorAlphaCount != 2 {
		t.Fatalf("baseline orgA idempotency_keys count = %d, want 2", priorAlphaCount)
	}
	if priorBravoCount != 5 {
		t.Fatalf("baseline orgB idempotency_keys count = %d, want 5", priorBravoCount)
	}

	claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgA.ID, "usr_writer", "alpha-writer-key", "hash-alpha-writer"))

	afterAlphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID)
	afterBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)
	if afterAlphaCount != priorAlphaCount+1 {
		t.Errorf("after orgA Claim: orgA count = %d, want %d", afterAlphaCount, priorAlphaCount+1)
	}
	if afterBravoCount != priorBravoCount {
		t.Errorf("after orgA Claim: orgB count = %d, want %d (the cross-tenant Claim altered the foreign tenant's row count)",
			afterBravoCount, priorBravoCount)
	}
}

// TestIdempotencyRepositoryClaimCrossTenantIDCollisionIsConflictAndBystanderByteIdentical
// pins that a global PRIMARY KEY collision across tenants surfaces as
// the same typed Conflict the same-tenant collision does, AND that
// the rolled-back failing INSERT leaves orgA's bystander row
// byte-identical, AND that the global idempotency_keys row count does
// not change. The Claim INSERT's ON CONFLICT target is
// (organization_id, principal_id, idempotency_key), so a duplicate id
// minted under a DIFFERENT (principal_id, idempotency_key) tuple does
// NOT resolve through the DO UPDATE branch — the PK violation flows
// through the database and back out through mapWriteError → Conflict.
// A regression that switched the ON CONFLICT target to (id) would
// swallow this collision and silently rewrite orgA's bystander row.
func TestIdempotencyRepositoryClaimCrossTenantIDCollisionIsConflictAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	// orgA mints a row carrying a known caller-supplied id. The id is
	// deterministically derived from the test name so two parallel
	// tests cannot collide on it.
	sharedID := mintIdempotencyID(t, "cross-tenant-collision")
	alphaRec := idemFixture(fix.orgA.ID, "usr_alpha", "alpha-key", "hash-alpha")
	alphaRec.ID = sharedID
	alphaStored, owned := claimIdem(ctx, t, s, repo, alphaRec)
	if !owned {
		t.Fatalf("seed Claim(orgA) returned owned=false")
	}
	if alphaStored.ID != sharedID {
		t.Fatalf("seed Claim(orgA) preserved id %q, want %q", alphaStored.ID, sharedID)
	}
	baseline := loadIdempotencyRowByID(ctx, t, db, alphaStored.ID)

	// Snapshot the global idempotency_keys row count before the
	// collision attempt: a rolled-back PK violation must not land the
	// failing row in some other tenant's slot.
	priorGlobalCount := totalIdempotencyRows(ctx, t, db)

	// orgB attempts to mint a row with the SAME id under its own
	// tenant AND a different (principal_id, idempotency_key) tuple so
	// the ON CONFLICT target does not match — the PRIMARY KEY on (id)
	// catches the collision regardless of organization_id.
	bravoRec := idemFixture(fix.orgB.ID, "usr_bravo", "bravo-key", "hash-bravo")
	bravoRec.ID = sharedID
	_, _, err := func() (store.IdempotencyRecord, bool, error) {
		var (
			rec store.IdempotencyRecord
			c   bool
		)
		werr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			r, claimed, e := repo.Claim(ctx, tx, bravoRec)
			if e != nil {
				return e
			}
			rec, c = r, claimed
			return nil
		})
		return rec, c, werr
	}()
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Fatalf("Claim(cross-tenant id collision) error = %v, want code %s — a duplicate id under a foreign tenant must surface as the same typed Conflict as same-tenant duplicate id",
			err, yerr.CodeConflict)
	}

	// orgA's bystander row must be byte-identical to its baseline.
	after := loadIdempotencyRowByID(ctx, t, db, baseline.ID)
	assertIdempotencyRowByteIdentical(t,
		"orgA bystander after orgB cross-tenant id-collision attempt",
		baseline, after)

	// The rolled-back row did not land in some other tenant's slot:
	// the global row count is unchanged.
	if got := totalIdempotencyRows(ctx, t, db); got != priorGlobalCount {
		t.Errorf("global idempotency_keys count = %d, want %d (a rolled-back cross-tenant PK collision left a row behind)",
			got, priorGlobalCount)
	}
}

// TestIdempotencyRepositoryCompleteCrossTenantIsConflictAndBystanderByteIdentical
// pins that calling Complete with orgA's organization_id but orgB's
// (principal_id, idempotency_key) tuple matches zero rows — Complete's
// WHERE is `organization_id = $1 AND principal_id = $2 AND
// idempotency_key = $3 AND status = 'pending'`, so the cross-tenant
// caller falls off the organization_id leg before the status leg runs,
// and the typed Conflict ("no longer pending") fires WITHOUT touching
// orgB's row. orgB's pending claim remains byte-identical — none of
// its response_status / response_body / completed_at NULL columns are
// rewritten into orgA's response envelope. A regression that dropped
// organization_id from the Complete WHERE would either rewrite orgB's
// row (worst case) or silently complete orgA's "claim" with a body it
// does not own.
func TestIdempotencyRepositoryCompleteCrossTenantIsConflictAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	// orgB owns a pending claim under (usr_shared, shared-key).
	bravoRec, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_shared", "shared-key", "hash-bravo"))
	baseline := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)
	if baseline.Status != "pending" {
		t.Fatalf("baseline orgB row status = %q, want pending", baseline.Status)
	}

	// orgA calls Complete with orgB's (principal, key) but its own
	// organization_id. The UPDATE matches zero rows and the typed
	// Conflict fires.
	crossRef := store.IdempotencyKeyRef{
		OrganizationID: fix.orgA.ID,
		PrincipalID:    "usr_shared",
		Key:            "shared-key",
	}
	completeErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := repo.Complete(ctx, tx, crossRef, 200,
			[]byte(`{"schema_version":"yalla.output.v1","data":{"forged":"orgA-tries-to-complete-orgB-claim"}}`),
			time.Time{})
		return e
	})
	wantErrCode(t, completeErr, yerr.CodeConflict)

	// orgB's row must be byte-identical to its baseline — the cross-
	// tenant Complete must not write its forged envelope into orgB's
	// pending row.
	after := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)
	assertIdempotencyRowByteIdentical(t,
		"orgB bystander after orgA Complete with foreign (principal, key)",
		baseline, after)
}

// TestIdempotencyRepositoryReleaseCrossTenantIsNoopAndBystanderByteIdentical
// pins that calling Release with orgA's organization_id but orgB's
// (principal_id, idempotency_key) tuple deletes zero rows and returns
// nil — Release is "safe to call defensively" per the repository
// contract (a missing or non-pending row is a no-op, not an error).
// orgB's pending row remains byte-identical. A regression that
// dropped organization_id from the Release WHERE would delete orgB's
// claim, which the bystander byte-identity loader catches as a
// missing-row error inside loadIdempotencyRowByID's t.Fatalf.
func TestIdempotencyRepositoryReleaseCrossTenantIsNoopAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	bravoRec, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_shared", "shared-key", "hash-bravo"))
	baseline := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)

	priorBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)

	crossRef := store.IdempotencyKeyRef{
		OrganizationID: fix.orgA.ID,
		PrincipalID:    "usr_shared",
		Key:            "shared-key",
	}
	releaseErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Release(ctx, tx, crossRef)
	})
	if releaseErr != nil {
		t.Fatalf("Release(cross-tenant ref) returned %v, want nil (Release is safe to call defensively under any ref that does not match a pending row)",
			releaseErr)
	}

	// orgB's row must still exist and be byte-identical to its
	// baseline.
	after := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)
	assertIdempotencyRowByteIdentical(t,
		"orgB bystander after orgA Release with foreign (principal, key)",
		baseline, after)
	if got := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after orgA Release: orgB count = %d, want %d (the cross-tenant Release deleted a foreign tenant's row)",
			got, priorBravoCount)
	}
}

// TestIdempotencyRepositoryFindCrossTenantReturnsNotFoundAndPreservesCounts
// pins that Find scoped to orgA's organization_id never resolves a
// row owned by orgB, even when orgB owns a row whose (principal_id,
// idempotency_key) tuple exactly matches the ref orgA supplies. Find's
// WHERE is `organization_id = $1 AND principal_id = $2 AND
// idempotency_key = $3`, so the organization_id leg fires first and
// the read returns (zero-record, false, nil). A regression that
// dropped organization_id from Find would leak orgB's row body —
// including its RequestHash, RequestID, ResponseBody, and any
// completion timestamps — into orgA's caller, the worst-case
// idempotency-key data-leak shape.
func TestIdempotencyRepositoryFindCrossTenantReturnsNotFoundAndPreservesCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	bravoRec, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_shared", "shared-key", "hash-bravo"))
	baseline := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)

	priorAlphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)

	crossRef := store.IdempotencyKeyRef{
		OrganizationID: fix.orgA.ID,
		PrincipalID:    "usr_shared",
		Key:            "shared-key",
	}
	got, ok := findIdem(ctx, t, s, repo, crossRef)
	if ok {
		t.Fatalf("Find(orgA, orgB's principal+key) returned ok=true with %+v — the cross-tenant Find leaked orgB's row body into orgA's caller",
			got)
	}

	// The phantom read must not have touched orgB's row.
	after := loadIdempotencyRowByID(ctx, t, db, bravoRec.ID)
	assertIdempotencyRowByteIdentical(t,
		"orgB bystander after orgA cross-tenant Find",
		baseline, after)
	if alphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID); alphaCount != priorAlphaCount {
		t.Errorf("after orgA Find: orgA count = %d, want %d", alphaCount, priorAlphaCount)
	}
	if bravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID); bravoCount != priorBravoCount {
		t.Errorf("after orgA Find: orgB count = %d, want %d", bravoCount, priorBravoCount)
	}
}

// TestIdempotencyRepositoryFindUnknownTenantReturnsNotFoundAndPreservesCounts
// pins the phantom-tenant variant of Find: a never-persisted org id
// returns (zero-record, false, nil) AND every existing tenant's
// per-org count is unchanged after the read. Find is a read, so no
// FK row is required — the predicate simply matches nothing. A
// regression that turned an unknown org into a 500 / panic, or that
// side-effected an audit / quota row through some shared read-write
// path, would surface here.
func TestIdempotencyRepositoryFindUnknownTenantReturnsNotFoundAndPreservesCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgA.ID, "usr_shared", "shared-key", "hash-alpha"))
	claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_shared", "shared-key", "hash-bravo"))

	priorAlphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)

	phantomRef := store.IdempotencyKeyRef{
		OrganizationID: "org_phantom_does_not_exist",
		PrincipalID:    "usr_shared",
		Key:            "shared-key",
	}
	got, ok := findIdem(ctx, t, s, repo, phantomRef)
	if ok {
		t.Fatalf("Find(phantom org, shared (principal, key)) returned ok=true with %+v — an unknown org id must resolve to (zero, false, nil) and never leak rows from any real tenant",
			got)
	}

	if alphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID); alphaCount != priorAlphaCount {
		t.Errorf("after phantom-org Find: orgA count = %d, want %d (a phantom read side-effected orgA's row pool)",
			alphaCount, priorAlphaCount)
	}
	if bravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID); bravoCount != priorBravoCount {
		t.Errorf("after phantom-org Find: orgB count = %d, want %d (a phantom read side-effected orgB's row pool)",
			bravoCount, priorBravoCount)
	}
}

// TestIdempotencyOrganizationDeleteCascadeIsTenantScoped proves
// orgA's deletion cascades only to orgA's idempotency_keys rows.
// orgB's rows — including pending claims, completed claims with
// response envelopes persisted, and rows with future-dated expires_at
// — must remain byte-identical to their baselines. The
// idempotency_keys.organization_id FK CASCADE on organizations(id) is
// the cascade chain; a regression that dropped the organization_id
// leg of the FK (or scoped the cascade too widely) would surface here
// as either an orgB row vanishing or its columns drifting.
//
// The single-bystander variant of this cascade is already pinned by
// idempotency_repository_invariants_test.go's
// TestIdempotencyRepositoryCascadeFromOrganizationDelete (which seeds
// one orgB row and asserts a handful of column equalities inline);
// the BE-0470 variant deepens it with a three-row orgB pool covering
// the pending / completed / future-expiry spread and a byte-identity
// assertion through assertIdempotencyRowByteIdentical on every
// bystander row (so a column drift on any persisted shape — including
// the nullable completion columns — surfaces as a named field diff
// instead of a single opaque mismatch).
func TestIdempotencyOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	fix := seedTwoTenantIdempotencyFixture(t, db, f)

	// orgA owns two rows (cascaded away).
	for i := 0; i < 2; i++ {
		claimIdem(ctx, t, s, repo,
			idemFixture(fix.orgA.ID, "usr_alpha", "alpha-cascade-key-"+itoaInt(i), "hash-alpha-cascade-"+itoaInt(i)))
	}

	// orgB owns three rows covering the lifecycle spread: pending,
	// completed-with-envelope, and pending-with-future-expiry.
	bravoPending, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_bravo", "bravo-pending-key", "hash-bravo-pending"))

	bravoToComplete, _ := claimIdem(ctx, t, s, repo,
		idemFixture(fix.orgB.ID, "usr_bravo", "bravo-completed-key", "hash-bravo-completed"))
	bravoCompleted := completeIdem(ctx, t, s, repo, bravoToComplete.Ref(), 201,
		[]byte(`{"schema_version":"yalla.output.v1","data":{"id":"proj_bravo_cascade"}}`))

	bravoFutureRec := idemFixture(fix.orgB.ID, "usr_bravo", "bravo-future-key", "hash-bravo-future")
	bravoFutureRec.ExpiresAt = time.Now().UTC().Add(72 * time.Hour)
	bravoFuture, _ := claimIdem(ctx, t, s, repo, bravoFutureRec)

	baselines := []rawIdempotencyRow{
		loadIdempotencyRowByID(ctx, t, db, bravoPending.ID),
		loadIdempotencyRowByID(ctx, t, db, bravoCompleted.ID),
		loadIdempotencyRowByID(ctx, t, db, bravoFuture.ID),
	}

	priorAlphaCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorAlphaCount != 2 {
		t.Fatalf("baseline orgA idempotency_keys count = %d, want 2", priorAlphaCount)
	}
	if priorBravoCount != 3 {
		t.Fatalf("baseline orgB idempotency_keys count = %d, want 3", priorBravoCount)
	}

	// Cascade-delete orgA. The idempotency_keys.organization_id FK
	// CASCADE removes only the rows tagged with orgA.
	if _, err := db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("DELETE orgA: %v", err)
	}

	// orgA's idempotency rows must be gone.
	if got := countIdempotencyRowsForOrg(ctx, t, db, fix.orgA.ID); got != 0 {
		t.Errorf("after orgA cascade: orgA count = %d, want 0 (ON DELETE CASCADE must remove every idempotency row)",
			got)
	}

	// orgB's count must be unchanged.
	if got := countIdempotencyRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after orgA cascade: orgB count = %d, want %d (the cascade crossed the organization_id predicate — worst-case data loss)",
			got, priorBravoCount)
	}

	// Every orgB row must be byte-identical to its baseline.
	for _, baseline := range baselines {
		after := loadIdempotencyRowByID(ctx, t, db, baseline.ID)
		assertIdempotencyRowByteIdentical(t,
			"orgB bystander after orgA cascade",
			baseline, after)
	}

	// Find for every surviving orgB row must still resolve through
	// the repository — the cascade did not silently corrupt the
	// repository read predicate.
	for _, baseline := range baselines {
		ref := store.IdempotencyKeyRef{
			OrganizationID: baseline.OrganizationID,
			PrincipalID:    baseline.PrincipalID,
			Key:            baseline.Key,
		}
		found, ok := findIdem(ctx, t, s, repo, ref)
		if !ok {
			t.Errorf("Find(orgB, %+v) after orgA cascade returned not-found — the cascade silently corrupted orgB's row",
				ref)
			continue
		}
		if found.ID != baseline.ID {
			t.Errorf("Find(orgB, %+v) after orgA cascade returned id %q, want %q",
				ref, found.ID, baseline.ID)
		}
	}
}

// totalIdempotencyRows returns the global idempotency_keys row count.
// It is the global counterpart to countIdempotencyRowsForOrg, used by
// the cross-tenant id-collision test to prove a rolled-back PK
// violation did not land the failing row in some other tenant's slot —
// the per-tenant probe alone cannot prove the absence (the failing
// row's organization_id is unknown to the probe).
func totalIdempotencyRows(ctx context.Context, t *testing.T, db *testutil.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM idempotency_keys`).Scan(&n); err != nil {
		t.Fatalf("count idempotency_keys global: %v", err)
	}
	return n
}
