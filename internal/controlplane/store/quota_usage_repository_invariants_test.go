package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-lifecycle invariants for the quota_usage table
// (BE-0453). quota_usage is the per-tenant counter table: one row per
// (organization_id, resource) holding the currently-allocated amount that the
// quota checker reads and locks to make an allocation decision. Its ONLY
// public write surface in the QuotaRepository is LockUsage, which INSERTs the
// counter row with used_value=0 ON CONFLICT (organization_id, resource) DO
// NOTHING, then SELECT ... FOR UPDATE locks the row for the remainder of the
// transaction. There is no per-row Update method, no per-row Delete method,
// no version column, and no service_id pointer — the increment path is owned
// by the quota.Checker (a SQL UPDATE on the locked row) and the
// delete-cascade-on-organization path is owned by the schema's CASCADE.
//
// What this file pins, and what it deliberately delegates:
//
//   - LockUsage row-shape on the INSERT leg: the freshly-minted id carries
//     the qusg_ prefix, used_value defaults to 0, and the database trigger
//     stamps created_at/updated_at within the same wallclock second.
//   - LockUsage idempotency on the ON CONFLICT DO NOTHING leg: a second call
//     for the same (organization, resource) leaves the id, created_at,
//     updated_at, AND used_value byte-equal — the set_updated_at trigger
//     fires BEFORE UPDATE only, and ON CONFLICT DO NOTHING is never a true
//     UPDATE, so updated_at is anchored across the second call too.
//   - Peer-row byte-identity: LockUsage(org, services) does not touch the
//     (org, projects) counter row's id, created_at, updated_at, or
//     used_value. The (organization_id, resource) UNIQUE constraint is the
//     ON CONFLICT target and isolates rows by resource within the same
//     tenant.
//   - LockUsage returns the persisted used_value when the row already exists
//     with a non-zero counter — the SELECT FOR UPDATE leg observes the live
//     value, not the would-be-zero of the discarded INSERT.
//   - Constraint-violation paths surface as typed apierr.Conflict
//     (yerr.CodeConflict) through mapWriteError: unknown organization (FK
//     organizations.id) and unknown quota_resource (DOMAIN quota_resource).
//   - Transaction rollback: a closure that returns an error after a
//     successful LockUsage call must leave quota_usage with no new row for
//     the (organization, resource) — the row never persists because Store.Write
//     rolls back when the closure errors.
//   - nil-tx guard: LockUsage called with a nil *Tx returns a typed
//     apierr.Internal (yerr.CodeInternal), not a nil-pointer panic.
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - The closed-set DOMAIN definition of quota_resource and the UNIQUE
//     (organization_id, resource) index are schema invariants owned by
//     quota_schema_test.go (TestQuotaResourceDomainEnforcesClosedSet,
//     TestQuotaSchemaTablesExist).
//   - The CASCADE delete of quota_usage when organizations is deleted is
//     owned by TestQuotaCascadeDeleteOnOrganization.
//   - The concurrent FOR UPDATE serialisation is owned by
//     TestQuotaReservationConcurrentRowLock (the quota_reservations sibling
//     covers the same primitive via the same SELECT ... FOR UPDATE path).
//   - The ListOrganizationUsage join-with-policies semantics are owned by
//     usage_test.go and the cross-tenant projection by
//     quota_policy_tenant_isolation_test.go.
//   - The CHECK (used_value >= 0) negative-balance guard is a schema
//     invariant on the column; LockUsage never sets used_value directly, so
//     the repository surface has no path that can produce a negative.
//
// Database-backed cases run against an isolated, freshly migrated Postgres
// and skip when YALLA_TEST_DATABASE_URL is unset. The nil-tx guard is a pure
// unit test.

// lockUsageOrFail runs LockUsage inside Store.Write and fatals on error. It
// is the smallest possible happy-path closure and is reused by every test
// that does not need to observe the call's tx in isolation.
func lockUsageOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	organizationID string,
	resource store.QuotaResource,
) int64 {
	t.Helper()
	var used int64
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, lErr := repo.LockUsage(ctx, tx, organizationID, resource)
		if lErr != nil {
			return lErr
		}
		used = got
		return nil
	}); err != nil {
		t.Fatalf("LockUsage(%q, %q): %v", organizationID, resource, err)
	}
	return used
}

// rawQuotaUsageRow is the full quota_usage row, deliberately loaded via raw
// SQL so the test can observe id, created_at, and updated_at — the columns
// the QuotaRepository surface deliberately does not expose. It is the same
// shape rawQuotaPolicyRow uses for quota_policies in BE-0451.
type rawQuotaUsageRow struct {
	ID             string
	OrganizationID string
	Resource       string
	UsedValue      int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// loadQuotaUsageRow reads the raw quota_usage row for (orgID, resource) and
// fatals on error. Two callers exist:
//   - the row-shape tests, which assert against the database-stamped
//     prefix, defaults, and timestamps;
//   - the bystander-byte-identity tests, which snapshot the row before a
//     potentially-touching call and compare field-by-field after.
func loadQuotaUsageRow(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
	resource store.QuotaResource,
) rawQuotaUsageRow {
	t.Helper()
	var row rawQuotaUsageRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, resource, used_value, created_at, updated_at
		   FROM quota_usage
		  WHERE organization_id = $1
		    AND resource = $2`,
		organizationID, string(resource)).Scan(
		&row.ID, &row.OrganizationID, &row.Resource, &row.UsedValue,
		&row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load quota_usage (%q, %q): %v", organizationID, resource, err)
	}
	return row
}

// countQuotaUsageRowsForOrg returns the number of quota_usage counter rows
// owned by organizationID. It is the "did the rollback leave a counter
// behind?" probe.
func countQuotaUsageRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_usage WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count quota_usage rows for %q: %v", organizationID, err)
	}
	return n
}

func TestQuotaRepositoryLockUsageFirstCallMintsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	used := lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceProjects)
	if used != 0 {
		t.Errorf("LockUsage on fresh tenant = %d, want 0", used)
	}

	row := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceProjects)
	if row.OrganizationID != org.ID {
		t.Errorf("organization_id = %q, want %q", row.OrganizationID, org.ID)
	}
	if row.Resource != string(store.QuotaResourceProjects) {
		t.Errorf("resource = %q, want %q", row.Resource, store.QuotaResourceProjects)
	}
	if row.UsedValue != 0 {
		t.Errorf("used_value = %d, want 0 on the fresh INSERT", row.UsedValue)
	}
	if len(row.ID) < len("qusg_") || row.ID[:len("qusg_")] != "qusg_" {
		t.Errorf("id = %q, want qusg_<token> prefix", row.ID)
	}
	if row.CreatedAt.IsZero() || row.UpdatedAt.IsZero() {
		t.Errorf("timestamps zero: created_at=%v updated_at=%v", row.CreatedAt, row.UpdatedAt)
	}
	if delta := row.UpdatedAt.Sub(row.CreatedAt); delta < 0 || delta > time.Second {
		t.Errorf("updated_at - created_at = %v on insert, want within 1s", delta)
	}
}

func TestQuotaRepositoryLockUsageSecondCallPreservesIdAndTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceServices)
	baseline := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceServices)

	// Force a measurable wallclock gap so an accidental UPDATE on the
	// existing row would necessarily move its updated_at forward (the
	// set_updated_at trigger stamps now() BEFORE UPDATE; ON CONFLICT DO
	// NOTHING is not an UPDATE, so the trigger must not fire).
	time.Sleep(time.Millisecond)

	used := lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceServices)
	if used != 0 {
		t.Errorf("second LockUsage = %d, want 0 (counter was never incremented)", used)
	}

	after := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceServices)
	if after.ID != baseline.ID {
		t.Errorf("LockUsage second call mutated id: was %q, now %q (ON CONFLICT DO NOTHING must not replace the row)", baseline.ID, after.ID)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("LockUsage second call moved created_at: was %v, now %v", baseline.CreatedAt, after.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("LockUsage second call moved updated_at: was %v, now %v (set_updated_at trigger fired on a non-UPDATE)", baseline.UpdatedAt, after.UpdatedAt)
	}
	if after.UsedValue != baseline.UsedValue {
		t.Errorf("LockUsage second call mutated used_value: was %d, now %d", baseline.UsedValue, after.UsedValue)
	}
	if after.Resource != baseline.Resource {
		t.Errorf("LockUsage second call mutated resource: was %q, now %q", baseline.Resource, after.Resource)
	}

	if n := countQuotaUsageRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("quota_usage rows for org = %d, want exactly 1 (the counter is upserted, never duplicated)", n)
	}
}

func TestQuotaRepositoryLockUsagePeerCounterRowIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceProjects)
	peerBaseline := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceProjects)

	// Wallclock gap so an accidental cross-row trigger on the peer would
	// necessarily advance its updated_at.
	time.Sleep(time.Millisecond)

	lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceServices)

	peerAfter := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceProjects)
	if peerAfter.ID != peerBaseline.ID {
		t.Errorf("peer (projects) id drifted: was %q, now %q", peerBaseline.ID, peerAfter.ID)
	}
	if !peerAfter.CreatedAt.Equal(peerBaseline.CreatedAt) {
		t.Errorf("peer (projects) created_at drifted: was %v, now %v", peerBaseline.CreatedAt, peerAfter.CreatedAt)
	}
	if !peerAfter.UpdatedAt.Equal(peerBaseline.UpdatedAt) {
		t.Errorf("peer (projects) updated_at drifted: was %v, now %v", peerBaseline.UpdatedAt, peerAfter.UpdatedAt)
	}
	if peerAfter.UsedValue != peerBaseline.UsedValue {
		t.Errorf("peer (projects) used_value drifted: was %d, now %d", peerBaseline.UsedValue, peerAfter.UsedValue)
	}
	if peerAfter.OrganizationID != peerBaseline.OrganizationID {
		t.Errorf("peer (projects) organization_id drifted: was %q, now %q", peerBaseline.OrganizationID, peerAfter.OrganizationID)
	}
	if peerAfter.Resource != peerBaseline.Resource {
		t.Errorf("peer (projects) resource drifted: was %q, now %q", peerBaseline.Resource, peerAfter.Resource)
	}

	// And the new row exists for services with used_value=0 and a distinct id.
	services := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceServices)
	if services.ID == peerBaseline.ID {
		t.Errorf("services row reused projects row id %q — distinct (org, resource) rows must have distinct ids", services.ID)
	}
	if services.UsedValue != 0 {
		t.Errorf("services used_value = %d, want 0 on insert", services.UsedValue)
	}

	if n := countQuotaUsageRowsForOrg(ctx, t, db, org.ID); n != 2 {
		t.Errorf("quota_usage rows for org = %d, want exactly 2 (one per locked resource)", n)
	}
}

func TestQuotaRepositoryLockUsageReflectsPersistedUsedValue(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	// Pre-seed a counter that a quota.Checker UPDATE would have produced. The
	// LockUsage ON CONFLICT DO NOTHING leg must take the conflict branch, and
	// the SELECT FOR UPDATE leg must observe the live used_value — not the
	// would-be-zero of the discarded INSERT.
	seedQuotaUsage(t, db, "qu_seed_projects", org.ID, string(store.QuotaResourceProjects), 17)

	used := lockUsageOrFail(ctx, t, s, repo, org.ID, store.QuotaResourceProjects)
	if used != 17 {
		t.Errorf("LockUsage on pre-seeded counter = %d, want 17", used)
	}

	row := loadQuotaUsageRow(ctx, t, db, org.ID, store.QuotaResourceProjects)
	if row.ID != "qu_seed_projects" {
		t.Errorf("row id mutated: was qu_seed_projects, now %q (ON CONFLICT DO NOTHING must not replace the row's id with the minted qusg_<token>)", row.ID)
	}
	if row.UsedValue != 17 {
		t.Errorf("row used_value = %d, want 17 (LockUsage must not reset to 0)", row.UsedValue)
	}

	if n := countQuotaUsageRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("quota_usage rows for org = %d, want exactly 1 (LockUsage must not duplicate)", n)
	}
}

func TestQuotaRepositoryLockUsageUnknownOrganizationReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, lErr := repo.LockUsage(ctx, tx, "org_does_not_exist", store.QuotaResourceProjects)
		return lErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("LockUsage(unknown org) error = %v, want code %s (FK organizations.id must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryLockUsageInvalidResourceReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	// QuotaResource is `type QuotaResource string`, so a deliberately-cast
	// value bypasses Go's compile-time check on the closed set. The DOMAIN
	// quota_resource is the runtime defense; its CHECK must reject the value
	// and the constraint-violation must map to apierr.Conflict.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, lErr := repo.LockUsage(ctx, tx, org.ID, store.QuotaResource("not-a-resource"))
		return lErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("LockUsage(invalid resource) error = %v, want code %s (DOMAIN quota_resource must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryLockUsageRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	bailout := quotaUsageTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, lErr := repo.LockUsage(ctx, tx, org.ID, store.QuotaResourceProjects); lErr != nil {
			return lErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}
	if !errors.Is(err, bailout) {
		t.Fatalf("Write returned %v, want sentinel %v (closure error must propagate unchanged)", err, bailout)
	}

	// The repository INSERT must not have persisted: no quota_usage row for
	// this org survives the rollback.
	if n := countQuotaUsageRowsForOrg(ctx, t, db, org.ID); n != 0 {
		t.Errorf("quota_usage rows for org after rollback = %d, want 0 (the LockUsage INSERT must roll back with the transaction)", n)
	}
}

// quotaUsageTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback. The type name is intentionally distinct from
// every other rollback sentinel in store_test (every *_test.go file under
// internal/controlplane/store/ shares the same package) — collisions would
// block compilation. Existing siblings include
// quota_policy_repository_invariants_test.go's quotaPolicyTxRollbackSentinel,
// project_repository_invariants_test.go's projectTxRollbackSentinel,
// environment_repository_invariants_test.go's environmentTxRollbackSentinel,
// service_repository_invariants_test.go's serviceTxRollbackSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's apiKeyScopeTxRollbackSentinel,
// project_variable_repository_invariants_test.go's projectVariableTxRollbackSentinel,
// environment_variable_repository_invariants_test.go's environmentVariableTxRollbackSentinel,
// service_variable_repository_invariants_test.go's serviceVariableTxRollbackSentinel,
// and apikey_test.go's apiKeyTxRollbackSentinel.
type quotaUsageTxRollbackSentinel struct{}

func (quotaUsageTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this quota usage transaction"
}

func TestQuotaRepositoryLockUsageWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()

	_, err := repo.LockUsage(context.Background(), nil,
		"org_irrelevant", store.QuotaResourceProjects)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("LockUsage(nil tx) error = %v, want code %s", err, yerr.CodeInternal)
	}
}
