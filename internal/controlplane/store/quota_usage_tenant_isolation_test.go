package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the quota_usage table
// (BE-0454). quota_usage is the per-tenant counter table: one row per
// (organization_id, resource) holding the currently-allocated amount the
// quota checker reads and locks to make an allocation decision. Its ONLY
// public write surface in the QuotaRepository is LockUsage, which is an
// INSERT ... ON CONFLICT (organization_id, resource) DO NOTHING followed by
// SELECT ... FOR UPDATE on the resulting row. There is no per-row Update,
// no per-row Delete, no version column, and no service_id pointer — the
// in-tenant increment path is owned by the quota.Checker (a SQL UPDATE on
// the locked row, exercised elsewhere) and the delete-on-organization path
// is owned by the schema's ON DELETE CASCADE.
//
// What this file pins, and what it deliberately delegates:
//
//   - LockUsage cross-tenant bystander byte-identity: when orgA calls
//     LockUsage(resource), every observable column on every quota_usage
//     row owned by orgB is byte-identical to its baseline (id,
//     organization_id, resource, used_value, created_at, updated_at). The
//     trigger-managed updated_at is the load-bearing anchor: the BEFORE
//     UPDATE quota_usage_set_updated_at trigger refreshes it on any matched
//     UPDATE, so a regression that resolved the ON CONFLICT by (resource,)
//     alone — silently turning orgA's INSERT into an UPDATE on orgB's row —
//     would surface here as updated_at drift on orgB's row even if every
//     other column happened to look right.
//   - LockUsage return value is tenant-scoped: orgA's LockUsage returns
//     orgA's own counter, never orgB's. The SELECT FOR UPDATE leg must
//     match on (organization_id, resource), not on resource alone.
//   - LockUsage on orgA does not create or delete any quota_usage rows for
//     orgB: the per-tenant row count is invariant under another tenant's
//     LockUsage call.
//   - Same-resource LockUsage in two tenants both succeed: the partial
//     unique index quota_usage_org_resource_idx (organization_id, resource)
//     is per-tenant, not global — proving the bystander proofs above
//     cannot trivially pass by virtue of orgB's row never existing.
//   - Cascade-delete tenant isolation: deleting orgA removes ONLY orgA's
//     quota_usage rows; every quota_usage row owned by orgB survives the
//     delete byte-identically. The ON DELETE CASCADE on quota_usage's FK
//     to organizations(id) must be scoped to the deleted tenant.
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - LockUsage CRUD invariants — first-call row shape, second-call
//     idempotency, peer-row byte-identity WITHIN a single tenant,
//     persisted used_value, FK / DOMAIN -> Conflict, transaction rollback,
//     nil-tx -> Internal — all owned by
//     quota_usage_repository_invariants_test.go (BE-0453).
//   - The ON DELETE CASCADE primitive for quota_usage when an organization
//     is deleted is owned by TestQuotaCascadeDeleteOnOrganization
//     (quota_schema_test.go) — that test proves a deleted tenant's rows
//     disappear; this file proves the OTHER tenant's rows survive.
//   - ListOrganizationUsage cross-tenant projection is owned by
//     TestQuotaRepositoryListOrganizationUsageIsTenantScoped and
//     TestQuotaRepositoryListOrganizationUsageIsolatesSharedCounter in
//     quota_policy_tenant_isolation_test.go (BE-0452); the typed
//     OrganizationResourceUsage projection does not expose ids, so a
//     cross-tenant id leak is structurally unrepresentable through that
//     resolver — the cross-tenant id leak surface to defend is LockUsage
//     itself, which this file covers via raw-SQL bystander row loads.
//   - The closed-set DOMAIN definition of quota_resource and the partial
//     UNIQUE (organization_id, resource) index are schema invariants owned
//     by quota_schema_test.go.
//
// Database-backed cases run against an isolated, freshly migrated Postgres
// and skip when YALLA_TEST_DATABASE_URL is unset.

// assertQuotaUsageByteIdentical asserts every observable column on a
// bystander quota_usage row is byte-identical to its baseline. The
// trigger-managed updated_at is the load-bearing anchor: the BEFORE
// UPDATE quota_usage_set_updated_at trigger refreshes it on any matched
// UPDATE, so a missing organization_id predicate in the LockUsage ON
// CONFLICT target would surface here as updated_at drift even when the
// other columns happened to look right.
func assertQuotaUsageByteIdentical(t *testing.T, label string, baseline, after rawQuotaUsageRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.Resource != baseline.Resource {
		t.Errorf("%s: bystander.resource = %q, want %q", label, after.Resource, baseline.Resource)
	}
	if after.UsedValue != baseline.UsedValue {
		t.Errorf("%s: bystander.used_value = %d, want %d",
			label, after.UsedValue, baseline.UsedValue)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v (set_updated_at trigger fired on a cross-tenant UPDATE)",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestQuotaRepositoryLockUsageInsertOnOrgADoesNotTouchOrgB proves the
// load-bearing cross-tenant invariant of LockUsage's INSERT leg: when
// orgB already owns a counter row for the SAME resource (with a
// recognisable non-zero used_value), orgA's first LockUsage call on that
// resource lands as a fresh INSERT for orgA — never as an UPDATE on
// orgB's row. The ON CONFLICT target (organization_id, resource) is
// per-tenant, so orgA's INSERT and orgB's existing row do not conflict.
// A regression that resolved the ON CONFLICT by (resource,) alone — or
// that dropped the organization_id predicate from the SELECT FOR UPDATE
// leg — would surface here in any of three ways: orgB's used_value would
// reset to 0, orgB's id would be replaced by the freshly-minted qusg_
// token, or orgB's updated_at would drift forward via the BEFORE UPDATE
// trigger. We assert all three, plus the orgA-side that the INSERT did
// land as a distinct row.
func TestQuotaRepositoryLockUsageInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// orgB owns the only counter for projects at this point. used_value=42 is
	// a recognisable bystander value — a regression that turned orgA's INSERT
	// into an UPDATE on orgB's row could either reset used_value to 0 (the
	// EXCLUDED.used_value column default) or leave it unchanged while moving
	// updated_at forward, so both are exercised below.
	seedQuotaUsage(t, db, "qu_orgb_projects", orgB.ID, string(store.QuotaResourceProjects), 42)
	baselineB := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)

	// Wallclock gap so an accidental UPDATE on orgB's row would necessarily
	// move its updated_at forward via the set_updated_at trigger — the
	// "row body looks right but updated_at advanced" regression class.
	time.Sleep(time.Millisecond)

	usedA := lockUsageOrFail(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects)
	if usedA != 0 {
		t.Errorf("LockUsage(orgA, projects) = %d, want 0 — orgB's counter (42) leaked into orgA's return value",
			usedA)
	}

	afterB := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	assertQuotaUsageByteIdentical(t, "LockUsage(orgA) bystander orgB(projects)", baselineB, afterB)

	// orgA's INSERT must have landed as a brand-new row, not as a rebound
	// of orgB's id. The qusg_ prefix is the load-bearing anchor.
	rowA := loadQuotaUsageRow(ctx, t, db, orgA.ID, store.QuotaResourceProjects)
	if rowA.OrganizationID != orgA.ID {
		t.Errorf("orgA row.organization_id = %q, want %q", rowA.OrganizationID, orgA.ID)
	}
	if rowA.UsedValue != 0 {
		t.Errorf("orgA row.used_value = %d, want 0 on the fresh INSERT", rowA.UsedValue)
	}
	if rowA.ID == baselineB.ID {
		t.Errorf("orgA row.id = %q, want a fresh qusg_<token> distinct from orgB's id (%q) — id rebound across tenants",
			rowA.ID, baselineB.ID)
	}
	if len(rowA.ID) < len("qusg_") || rowA.ID[:len("qusg_")] != "qusg_" {
		t.Errorf("orgA row.id = %q, want qusg_<token> prefix — the INSERT did not mint a fresh id", rowA.ID)
	}

	// Per-tenant row counts: each tenant owns exactly one row on projects.
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgA.ID); n != 1 {
		t.Errorf("quota_usage rows for orgA = %d, want 1", n)
	}
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgB.ID); n != 1 {
		t.Errorf("quota_usage rows for orgB = %d, want 1 — orgA's LockUsage either deleted or duplicated orgB's row", n)
	}
}

// TestQuotaRepositoryLockUsageReturnValueIsTenantScoped proves the
// SELECT FOR UPDATE leg of LockUsage matches by (organization_id,
// resource), never by resource alone. Each tenant has a pre-seeded
// counter on the SAME resource with a DISTINCT used_value; LockUsage on
// each tenant must observe that tenant's OWN value, not the other's.
// A regression that dropped the organization_id predicate from the
// SELECT would surface here as a swapped (or merged) return value.
func TestQuotaRepositoryLockUsageReturnValueIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Distinct used_value per tenant on the same resource. The chosen
	// values make a swap (return the other tenant's number) or a merge
	// (return their sum) immediately recognisable.
	seedQuotaUsage(t, db, "qu_orga_projects_ts", orgA.ID, string(store.QuotaResourceProjects), 7)
	seedQuotaUsage(t, db, "qu_orgb_projects_ts", orgB.ID, string(store.QuotaResourceProjects), 42)

	usedA := lockUsageOrFail(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects)
	if usedA != 7 {
		t.Errorf("LockUsage(orgA, projects) = %d, want 7 — orgB's counter leaked", usedA)
	}

	usedB := lockUsageOrFail(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects)
	if usedB != 42 {
		t.Errorf("LockUsage(orgB, projects) = %d, want 42 — orgA's counter leaked", usedB)
	}
}

// TestQuotaRepositoryLockUsageOnOrgADoesNotChangeOrgBRowCount proves
// the per-tenant row count is invariant under another tenant's
// LockUsage call. orgB owns counters on three resources before orgA
// makes any call; orgA then LockUsages a different resource that orgB
// has NOT seeded. orgB's count must remain at 3 — neither lower (an
// accidental cross-tenant DELETE) nor higher (an accidental
// cross-tenant INSERT). orgA's count goes from 0 to 1.
func TestQuotaRepositoryLockUsageOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	seedQuotaUsage(t, db, "qu_orgb_projects_rc", orgB.ID, string(store.QuotaResourceProjects), 1)
	seedQuotaUsage(t, db, "qu_orgb_services_rc", orgB.ID, string(store.QuotaResourceServices), 2)
	seedQuotaUsage(t, db, "qu_orgb_databases_rc", orgB.ID, string(store.QuotaResourceDatabases), 3)

	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Fatalf("baseline orgB count = %d, want 3 — test fixture is invalid", n)
	}
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	// orgA LockUsages a resource orgB has NOT seeded — the cleanest
	// signal: an accidental cross-tenant INSERT would either bump orgB's
	// count (if the FK got swapped) or fail entirely.
	lockUsageOrFail(ctx, t, s, repo, orgA.ID, store.QuotaResourceDomains)

	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Errorf("orgB count after LockUsage(orgA, domains) = %d, want 3 — orgA's INSERT touched orgB", n)
	}
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgA.ID); n != 1 {
		t.Errorf("orgA count after LockUsage(orgA, domains) = %d, want 1 — orgA's INSERT did not land", n)
	}
}

// TestQuotaRepositoryLockUsageBystanderRowsAcrossResourcesAreByteIdentical
// proves the cross-tenant bystander invariant generalises across every
// resource orgB owns, not just the resource orgA touches. orgB owns
// counters on three resources at distinct used_value values; orgA
// LockUsages the SAME first resource (projects). All three of orgB's
// rows — including the one whose (resource) value matches orgA's call —
// must be byte-identical to baseline. The cross-resource peers prove
// the schema's partial unique index is keyed on (organization_id,
// resource), not on (organization_id) or (resource) alone; the
// same-resource peer is the load-bearing anchor for the bystander
// invariant.
func TestQuotaRepositoryLockUsageBystanderRowsAcrossResourcesAreByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	seedQuotaUsage(t, db, "qu_orgb_projects_bi", orgB.ID, string(store.QuotaResourceProjects), 5)
	seedQuotaUsage(t, db, "qu_orgb_services_bi", orgB.ID, string(store.QuotaResourceServices), 17)
	seedQuotaUsage(t, db, "qu_orgb_databases_bi", orgB.ID, string(store.QuotaResourceDatabases), 99)

	baselineProjects := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	baselineServices := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)
	baselineDatabases := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceDatabases)

	// Wallclock gap so an accidental cross-tenant UPDATE on any of orgB's
	// rows would advance its updated_at via the BEFORE UPDATE trigger.
	time.Sleep(time.Millisecond)

	// orgA touches the SAME resource as one of orgB's rows. The other two
	// resources prove the bystander invariant generalises beyond the row
	// whose (resource) value matches orgA's call.
	lockUsageOrFail(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects)

	afterProjects := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	assertQuotaUsageByteIdentical(t, "orgB(projects) — same resource as orgA's call",
		baselineProjects, afterProjects)

	afterServices := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)
	assertQuotaUsageByteIdentical(t, "orgB(services) — different resource",
		baselineServices, afterServices)

	afterDatabases := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceDatabases)
	assertQuotaUsageByteIdentical(t, "orgB(databases) — different resource",
		baselineDatabases, afterDatabases)
}

// TestQuotaRepositoryLockUsageSameResourceInTwoTenantsBothSucceed is the
// load-bearing positive-direction pair for the bystander proofs above:
// without it, a regression that resolved the ON CONFLICT by (resource,)
// alone would have prevented orgB's seed INSERT in the first place,
// and every byte-identical assertion would silently pass against a row
// that never existed. The partial unique index
// quota_usage_org_resource_idx (organization_id, resource) is keyed by
// BOTH columns, so two tenants can both own a row on the SAME resource
// without conflicting. We prove this by going through the repository
// surface (LockUsage) on both tenants — not via raw INSERTs — so a
// regression that hard-coded a single organization_id in the INSERT
// itself would surface here too.
func TestQuotaRepositoryLockUsageSameResourceInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	if got := lockUsageOrFail(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects); got != 0 {
		t.Errorf("LockUsage(orgA, projects) = %d, want 0 on the fresh INSERT", got)
	}
	if got := lockUsageOrFail(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects); got != 0 {
		t.Errorf("LockUsage(orgB, projects) = %d, want 0 on the fresh INSERT — the partial unique index conflicted across tenants", got)
	}

	rowA := loadQuotaUsageRow(ctx, t, db, orgA.ID, store.QuotaResourceProjects)
	rowB := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	if rowA.ID == rowB.ID {
		t.Errorf("two tenants share quota_usage.id %q — distinct (organization, resource) rows must have distinct ids", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two rows have the same organization_id %q — fixture is broken", rowA.OrganizationID)
	}
	if rowA.Resource != string(store.QuotaResourceProjects) || rowB.Resource != string(store.QuotaResourceProjects) {
		t.Errorf("resource columns = (%q, %q), want both = projects", rowA.Resource, rowB.Resource)
	}

	// Each tenant owns exactly one row on projects.
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgA.ID); n != 1 {
		t.Errorf("quota_usage rows for orgA = %d, want 1", n)
	}
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgB.ID); n != 1 {
		t.Errorf("quota_usage rows for orgB = %d, want 1", n)
	}
}

// TestQuotaUsageOrganizationDeleteCascadeIsTenantScoped proves the
// schema's ON DELETE CASCADE on quota_usage.organization_id is scoped
// to the deleted tenant: removing orgA removes orgA's quota_usage rows
// and ONLY orgA's. orgB's rows survive byte-identically. The existing
// TestQuotaCascadeDeleteOnOrganization (quota_schema_test.go) proves
// the cascade happens for the targeted tenant; this test proves it
// does NOT bleed into another tenant — a regression that swapped the
// CASCADE clause for `ALL` or dropped the FK predicate would surface
// here as missing or mutated orgB rows.
func TestQuotaUsageOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Two rows for orgA (which will be cascaded away) and three for orgB
	// (which must survive byte-identically). The (orgB, projects) pair is
	// deliberately picked because it shares the resource dimension with
	// (orgA, projects) — a regression that dropped the organization_id
	// predicate in the CASCADE would target rows by resource alone.
	seedQuotaUsage(t, db, "qu_orga_projects_cs", orgA.ID, string(store.QuotaResourceProjects), 4)
	seedQuotaUsage(t, db, "qu_orga_services_cs", orgA.ID, string(store.QuotaResourceServices), 9)
	seedQuotaUsage(t, db, "qu_orgb_projects_cs", orgB.ID, string(store.QuotaResourceProjects), 12)
	seedQuotaUsage(t, db, "qu_orgb_services_cs", orgB.ID, string(store.QuotaResourceServices), 18)
	seedQuotaUsage(t, db, "qu_orgb_databases_cs", orgB.ID, string(store.QuotaResourceDatabases), 27)

	baselineProjects := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	baselineServices := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)
	baselineDatabases := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceDatabases)

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgA.ID); n != 0 {
		t.Errorf("quota_usage rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countQuotaUsageRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Errorf("quota_usage rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	afterProjects := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	assertQuotaUsageByteIdentical(t, "orgB(projects) survives orgA delete",
		baselineProjects, afterProjects)

	afterServices := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)
	assertQuotaUsageByteIdentical(t, "orgB(services) survives orgA delete",
		baselineServices, afterServices)

	afterDatabases := loadQuotaUsageRow(ctx, t, db, orgB.ID, store.QuotaResourceDatabases)
	assertQuotaUsageByteIdentical(t, "orgB(databases) survives orgA delete",
		baselineDatabases, afterDatabases)
}
