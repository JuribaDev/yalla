package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for QuotaRepository — the persistence half of the quota
// checker service. They run against an isolated, freshly migrated Postgres
// database and skip when YALLA_TEST_DATABASE_URL is unset. They prove the
// effective-limit resolution, the FOR UPDATE counter lock, the active-
// reservation sum, and reservation inserts are tenant scoped and behave as the
// checker relies on.

func TestQuotaRepositoryEffectiveLimitPrefersOrgOverride(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedPlanPolicy(t, db, "qp_plan_projects", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects", org.ID, "projects", 10)

	var (
		limit store.QuotaLimit
		found bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		limit, found, rErr = repo.EffectiveLimit(ctx, q, org.ID, "starter", store.QuotaResourceProjects)
		return rErr
	}); err != nil {
		t.Fatalf("EffectiveLimit: %v", err)
	}
	if !found {
		t.Fatal("EffectiveLimit found = false, want the organization override")
	}
	if limit.LimitValue != 10 {
		t.Errorf("EffectiveLimit value = %d, want 10 (organization override wins over plan default)", limit.LimitValue)
	}
	if limit.EnforcementMode != store.EnforcementModeHard {
		t.Errorf("EffectiveLimit mode = %q, want %q", limit.EnforcementMode, store.EnforcementModeHard)
	}
}

func TestQuotaRepositoryEffectiveLimitFallsBackToPlanDefault(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedPlanPolicy(t, db, "qp_plan_services", "starter", "services", 7)

	var (
		limit store.QuotaLimit
		found bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		limit, found, rErr = repo.EffectiveLimit(ctx, q, org.ID, "starter", store.QuotaResourceServices)
		return rErr
	}); err != nil {
		t.Fatalf("EffectiveLimit: %v", err)
	}
	if !found {
		t.Fatal("EffectiveLimit found = false, want the plan default")
	}
	if limit.LimitValue != 7 {
		t.Errorf("EffectiveLimit value = %d, want 7 (plan default)", limit.LimitValue)
	}
}

func TestQuotaRepositoryEffectiveLimitNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	var found bool
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		_, found, rErr = repo.EffectiveLimit(ctx, q, org.ID, "starter", store.QuotaResourceDatabases)
		return rErr
	}); err != nil {
		t.Fatalf("EffectiveLimit: %v", err)
	}
	if found {
		t.Error("EffectiveLimit found = true, want false when no policy is configured at either scope")
	}
}

func TestQuotaRepositoryEffectiveLimitTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	// Only organization A has an override, and there is no plan default.
	seedOrgPolicy(t, db, "qp_org_a_domains", orgA.ID, "domains", 5)

	var found bool
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		_, found, rErr = repo.EffectiveLimit(ctx, q, orgB.ID, "starter", store.QuotaResourceDomains)
		return rErr
	}); err != nil {
		t.Fatalf("EffectiveLimit: %v", err)
	}
	if found {
		t.Error("organization B resolved organization A's override; the lookup is not tenant scoped")
	}
}

func TestQuotaRepositoryLockUsageCreatesAndReturnsCounter(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	var first, second int64
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var lErr error
		first, lErr = repo.LockUsage(ctx, tx, org.ID, store.QuotaResourceProjects)
		return lErr
	}); err != nil {
		t.Fatalf("first LockUsage: %v", err)
	}
	if first != 0 {
		t.Errorf("LockUsage on a fresh tenant = %d, want 0", first)
	}
	// A second call must find the row the first created, not a duplicate.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var lErr error
		second, lErr = repo.LockUsage(ctx, tx, org.ID, store.QuotaResourceProjects)
		return lErr
	}); err != nil {
		t.Fatalf("second LockUsage: %v", err)
	}
	if second != 0 {
		t.Errorf("second LockUsage = %d, want 0", second)
	}

	var rows int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_usage WHERE organization_id = $1 AND resource = 'projects'`,
		org.ID).Scan(&rows); err != nil {
		t.Fatalf("count quota_usage rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("quota_usage rows = %d, want exactly 1 (the counter is upserted, never duplicated)", rows)
	}
}

func TestQuotaRepositorySumActiveReservations(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	now := time.Now()

	// Two live reservations for org A (counted: total 5).
	insertReservationRow(t, db, "qr_a_live_1", orgA.ID, "projects", 2, "active", now.Add(time.Hour))
	insertReservationRow(t, db, "qr_a_live_2", orgA.ID, "projects", 3, "active", now.Add(time.Hour))
	// An expired-but-still-'active' reservation: excluded by the expiry filter.
	insertReservationRow(t, db, "qr_a_expired", orgA.ID, "projects", 9, "active", now.Add(-time.Hour))
	// A settled reservation: excluded by status.
	insertSettledReservationRow(t, db, "qr_a_committed", orgA.ID, "projects", 4, "committed", now.Add(time.Hour))
	// A live reservation for a different resource: excluded by resource.
	insertReservationRow(t, db, "qr_a_services", orgA.ID, "services", 8, "active", now.Add(time.Hour))
	// A live reservation for org B: excluded by tenant.
	insertReservationRow(t, db, "qr_b_live", orgB.ID, "projects", 6, "active", now.Add(time.Hour))

	var sumA, sumB int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		if sumA, rErr = repo.SumActiveReservations(ctx, q, orgA.ID, store.QuotaResourceProjects, now); rErr != nil {
			return rErr
		}
		sumB, rErr = repo.SumActiveReservations(ctx, q, orgB.ID, store.QuotaResourceProjects, now)
		return rErr
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sumA != 5 {
		t.Errorf("org A active projects reservations = %d, want 5", sumA)
	}
	if sumB != 6 {
		t.Errorf("org B active projects reservations = %d, want 6 (tenant scoped)", sumB)
	}
}

func TestQuotaRepositoryInsertReservationMintsIDAndPersists(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	expires := time.Now().Add(30 * time.Minute)

	var created store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var iErr error
		created, iErr = repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      expires,
		})
		return iErr
	}); err != nil {
		t.Fatalf("InsertReservation: %v", err)
	}
	if created.ID == "" {
		t.Error("InsertReservation did not mint an id for a blank-id reservation")
	}
	if created.Status != store.ReservationStatusActive {
		t.Errorf("InsertReservation status = %q, want %q (blank status defaults to active)", created.Status, store.ReservationStatusActive)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("InsertReservation did not return the database-assigned timestamps")
	}

	var persisted int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_reservations WHERE id = $1 AND organization_id = $2 AND status = 'active'`,
		created.ID, org.ID).Scan(&persisted); err != nil {
		t.Fatalf("count reservation row: %v", err)
	}
	if persisted != 1 {
		t.Errorf("persisted reservation rows = %d, want 1", persisted)
	}
}

func TestQuotaRepositoryRejectsNilTransaction(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()
	ctx := context.Background()

	if _, err := repo.LockUsage(ctx, nil, "org_x", store.QuotaResourceProjects); err == nil {
		t.Error("LockUsage(nil tx) error = nil, want an error")
	}
	if _, err := repo.InsertReservation(ctx, nil, store.QuotaReservation{}); err == nil {
		t.Error("InsertReservation(nil tx) error = nil, want an error")
	}
}

// insertReservationRow inserts an active or expired reservation directly and
// fails the test on error. It is used to set up SumActiveReservations cases.
func insertReservationRow(t *testing.T, db *testutil.DB, id, orgID, resource string, amount int64, status string, expiresAt time.Time) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, orgID, resource, amount, status, expiresAt); err != nil {
		t.Fatalf("seed reservation %q: %v", id, err)
	}
}

// insertSettledReservationRow inserts a settled (non-active) reservation, which
// the schema requires to carry settled_at.
func insertSettledReservationRow(t *testing.T, db *testutil.DB, id, orgID, resource string, amount int64, status string, expiresAt time.Time) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at, settled_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())`,
		id, orgID, resource, amount, status, expiresAt); err != nil {
		t.Fatalf("seed settled reservation %q: %v", id, err)
	}
}
