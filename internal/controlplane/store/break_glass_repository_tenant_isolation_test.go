// Repository-layer tenant-isolation tests for break_glass_sessions (BE-0474).
// The invariants file already pins the single-row CRUD semantics; this file
// deepens the cross-tenant probes with multi-row bystander pools, overlapping
// actor/request shapes, tenant-scoped list limits, and lifecycle spread
// (active + revoked rows).
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type twoTenantBreakGlassFixture struct {
	orgA    testutil.Organization
	orgB    testutil.Organization
	support testutil.Organization
}

func seedTwoTenantBreakGlassFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) twoTenantBreakGlassFixture {
	t.Helper()
	return twoTenantBreakGlassFixture{
		orgA:    seedOrg(t, db, f, "break-glass-tenant-a"),
		orgB:    seedOrg(t, db, f, "break-glass-tenant-b"),
		support: seedOrg(t, db, f, "break-glass-support"),
	}
}

func TestBreakGlassRepositoryAppendOnOrgADoesNotTouchOrgBRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	fix := seedTwoTenantBreakGlassFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	bravoActive := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "shared-actor-active", base, 30*time.Minute))
	bravoRevoked := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "shared-actor-revoked", base.Add(time.Second), 30*time.Minute))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, fix.orgB.ID, bravoRevoked.ID, "usr_support_revoke", "usr", base.Add(2*time.Minute))
		return rErr
	}); err != nil {
		t.Fatalf("seed revoked break-glass session: %v", err)
	}

	baselines := map[string]rawBreakGlassRow{
		bravoActive.ID:  loadBreakGlassRowByID(ctx, t, db, bravoActive.ID),
		bravoRevoked.ID: loadBreakGlassRowByID(ctx, t, db, bravoRevoked.ID),
	}
	priorBCount := countBreakGlassRowsForOrg(ctx, t, db, fix.orgB.ID)

	alpha := breakGlassSessionFixture(fix.orgA, fix.support, "shared-actor-active", base.Add(3*time.Second), 30*time.Minute)
	alpha.ActorID = bravoActive.ActorID
	alpha.RequestID = bravoActive.RequestID
	alpha.CorrelationID = bravoActive.CorrelationID
	alpha.IPAddress = bravoActive.IPAddress
	alpha.UserAgent = bravoActive.UserAgent
	created := seedBreakGlassSession(ctx, t, s, repo, alpha)

	if created.OrganizationID != fix.orgA.ID {
		t.Fatalf("Append returned organization_id %q, want %q", created.OrganizationID, fix.orgA.ID)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgA.ID); got != 1 {
		t.Errorf("orgA break_glass_sessions count = %d, want 1", got)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBCount {
		t.Errorf("orgB break_glass_sessions count = %d, want %d", got, priorBCount)
	}
	for id, baseline := range baselines {
		after := loadBreakGlassRowByID(ctx, t, db, id)
		assertBreakGlassRowByteIdentical(t, "orgB bystander after orgA Append "+id, baseline, after)
	}
}

func TestBreakGlassRepositoryAppendCrossTenantIDCollisionIsConflictAndDoesNotLeak(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	fix := seedTwoTenantBreakGlassFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	bravo := breakGlassSessionFixture(fix.orgB, fix.support, "collision-bravo-secret-shape", base, 30*time.Minute)
	bravo.ID = mintBreakGlassSessionID(t, "collision")
	bravo.Reason = "INCIDENT-BRAVO-DO-NOT-LEAK"
	bravo.ActorID = "usr_bravo_do_not_leak"
	bravo.RequestID = "req_bravo_do_not_leak"
	created := seedBreakGlassSession(ctx, t, s, repo, bravo)
	baseline := loadBreakGlassRowByID(ctx, t, db, created.ID)
	totalBefore := totalBreakGlassRows(ctx, t, db)

	alpha := breakGlassSessionFixture(fix.orgA, fix.support, "collision-alpha", base.Add(time.Second), 30*time.Minute)
	alpha.ID = created.ID
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, alpha)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
	if err != nil {
		testutil.AssertRedacted(t, err.Error(), bravo.Reason, bravo.ActorID, bravo.RequestID)
	}
	if got := totalBreakGlassRows(ctx, t, db); got != totalBefore {
		t.Errorf("total break_glass_sessions rows = %d, want %d", got, totalBefore)
	}
	after := loadBreakGlassRowByID(ctx, t, db, created.ID)
	assertBreakGlassRowByteIdentical(t, "orgB row after cross-tenant id collision", baseline, after)
}

func TestBreakGlassRepositoryListByOrganizationIsTenantScopedWithLifecycleSpread(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	fix := seedTwoTenantBreakGlassFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 5; i++ {
		seedBreakGlassSession(ctx, t, s, repo,
			breakGlassSessionFixture(fix.orgA, fix.support, "alpha-noise-"+itoa(i), base.Add(time.Duration(i)*time.Second), 30*time.Minute))
	}
	bravoOld := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "bravo-old", base.Add(10*time.Second), 30*time.Minute))
	bravoRevoked := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "bravo-revoked", base.Add(11*time.Second), 30*time.Minute))
	bravoNewest := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "bravo-newest", base.Add(12*time.Second), 30*time.Minute))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, fix.orgB.ID, bravoRevoked.ID, "usr_support_revoke", "usr", base.Add(13*time.Second))
		return rErr
	}); err != nil {
		t.Fatalf("seed revoked break-glass session: %v", err)
	}
	baselines := map[string]rawBreakGlassRow{
		bravoNewest.ID:  loadBreakGlassRowByID(ctx, t, db, bravoNewest.ID),
		bravoRevoked.ID: loadBreakGlassRowByID(ctx, t, db, bravoRevoked.ID),
		bravoOld.ID:     loadBreakGlassRowByID(ctx, t, db, bravoOld.ID),
	}

	var rows []store.BreakGlassSession
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		out, lErr := repo.ListByOrganization(ctx, q, fix.orgB.ID, 5000)
		rows = out
		return lErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want exactly orgB's 3 rows", len(rows))
	}
	wantOrder := []string{bravoNewest.ID, bravoRevoked.ID, bravoOld.ID}
	for i, row := range rows {
		if row.OrganizationID != fix.orgB.ID {
			t.Errorf("rows[%d].OrganizationID = %q, want %q", i, row.OrganizationID, fix.orgB.ID)
		}
		if row.ID != wantOrder[i] {
			t.Errorf("rows[%d].ID = %q, want %q", i, row.ID, wantOrder[i])
		}
		assertBreakGlassRowByteIdentical(t, "listed orgB row "+row.ID, baselines[row.ID], loadBreakGlassRowByID(ctx, t, db, row.ID))
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgA.ID); got != 5 {
		t.Errorf("orgA row count after orgB list = %d, want 5", got)
	}
}

func TestBreakGlassRepositoryGetAndMarkRevokedCrossTenantAreSideEffectFree(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	fix := seedTwoTenantBreakGlassFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	bravoActive := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "xt-active", base, 30*time.Minute))
	bravoRevoked := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "xt-revoked", base.Add(time.Second), 30*time.Minute))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, fix.orgB.ID, bravoRevoked.ID, "usr_support_revoke", "usr", base.Add(2*time.Minute))
		return rErr
	}); err != nil {
		t.Fatalf("seed revoked break-glass session: %v", err)
	}
	baselines := map[string]rawBreakGlassRow{
		bravoActive.ID:  loadBreakGlassRowByID(ctx, t, db, bravoActive.ID),
		bravoRevoked.ID: loadBreakGlassRowByID(ctx, t, db, bravoRevoked.ID),
	}
	priorBCount := countBreakGlassRowsForOrg(ctx, t, db, fix.orgB.ID)

	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.Get(ctx, q, fix.orgA.ID, bravoActive.ID)
		return gErr
	})
	wantErrCode(t, getErr, yerr.CodeNotFound)
	revokeErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, fix.orgA.ID, bravoActive.ID, "usr_alpha_attempt", "usr", base.Add(3*time.Minute))
		return rErr
	})
	wantErrCode(t, revokeErr, yerr.CodeNotFound)

	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBCount {
		t.Errorf("orgB row count after cross-tenant read/revoke = %d, want %d", got, priorBCount)
	}
	for id, baseline := range baselines {
		after := loadBreakGlassRowByID(ctx, t, db, id)
		assertBreakGlassRowByteIdentical(t, "orgB bystander after cross-tenant read/revoke "+id, baseline, after)
	}
}

func TestBreakGlassRepositoryOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	fix := seedTwoTenantBreakGlassFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgA, fix.support, "alpha-delete", base, 30*time.Minute))
	bravoActive := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "bravo-active", base.Add(time.Second), 30*time.Minute))
	bravoRevoked := seedBreakGlassSession(ctx, t, s, repo,
		breakGlassSessionFixture(fix.orgB, fix.support, "bravo-revoked", base.Add(2*time.Second), 30*time.Minute))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, fix.orgB.ID, bravoRevoked.ID, "usr_support_revoke", "usr", base.Add(3*time.Second))
		return rErr
	}); err != nil {
		t.Fatalf("seed revoked break-glass session: %v", err)
	}
	baselines := map[string]rawBreakGlassRow{
		bravoActive.ID:  loadBreakGlassRowByID(ctx, t, db, bravoActive.ID),
		bravoRevoked.ID: loadBreakGlassRowByID(ctx, t, db, bravoRevoked.ID),
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgA.ID); got != 0 {
		t.Errorf("orgA break_glass_sessions count after cascade = %d, want 0", got)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, fix.orgB.ID); got != len(baselines) {
		t.Errorf("orgB break_glass_sessions count after orgA cascade = %d, want %d", got, len(baselines))
	}
	for id, baseline := range baselines {
		after := loadBreakGlassRowByID(ctx, t, db, id)
		assertBreakGlassRowByteIdentical(t, "orgB bystander after orgA cascade "+id, baseline, after)
	}
}

func totalBreakGlassRows(ctx context.Context, t *testing.T, db *testutil.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM break_glass_sessions`).Scan(&n); err != nil {
		t.Fatalf("count all break_glass_sessions rows: %v", err)
	}
	return n
}
