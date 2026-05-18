package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the quota_reservations table
// (BE-0456). quota_reservations records amounts claimed by an in-flight unit
// of work BEFORE the resource it would create actually exists. A row that
// belongs to one tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id);
//	(b) the UNIQUE (organization_id, id) composite-FK target so child
//	    rows (usage_events; the provisioning_jobs.organization_id +
//	    quota_reservations.job_id composite FK in the OTHER direction)
//	    cannot cross the boundary; and
//	(c) every QuotaRepository write/read going through the
//	    organization_id predicate.
//
// The QuotaRepository surface for the table is intentionally minimal:
// InsertReservation mints an active row inside a transaction, and
// SumActiveReservations reads the live in-flight total for the headroom
// check. There is no per-row Get/Update/Delete/ListByParent surface — the
// worker-side lifecycle (commit/release/expire) lands later — so the
// cross-tenant surfaces this file must defend are limited to (1) the
// InsertReservation INSERT not touching any other tenant's row, (2)
// SumActiveReservations not folding another tenant's reservations into
// the caller's sum, and (3) ON DELETE CASCADE on organizations not
// bleeding into another tenant's rows.
//
// What this file pins, and what it deliberately delegates:
//
//   - InsertReservation cross-tenant bystander byte-identity: when orgA
//     calls InsertReservation, every observable column on every
//     quota_reservations row owned by orgB is byte-identical to its
//     baseline (id, organization_id, resource, amount, status, job_id,
//     expires_at, settled_at, created_at, updated_at). The
//     trigger-managed updated_at is the load-bearing anchor: the BEFORE
//     UPDATE quota_reservations_set_updated_at trigger refreshes it on
//     any matched UPDATE, so a regression that swept orgB's row through
//     a missing organization_id predicate would surface here as
//     updated_at drift even when the other columns happened to look
//     right.
//   - InsertReservation cross-tenant row-count invariant: an InsertReservation
//     call on orgA changes orgA's row count by exactly +1 and leaves orgB's
//     row count untouched. A regression that targeted the wrong tenant's
//     row would show either as an orgB count change or a missing orgA row.
//   - Same-(resource, amount, expires_at) reservations in two tenants both
//     persist: quota_reservations has NO UNIQUE constraint on
//     (organization_id, resource) — only the PRIMARY KEY (id) and the
//     UNIQUE (organization_id, id) composite-FK target — so two tenants
//     each holding an active reservation for the same resource is the
//     expected concurrent shape. This is the load-bearing positive-direction
//     pair for the bystander byte-identity proofs: without it, a regression
//     that resolved a phantom conflict on (resource,) alone would prevent
//     orgA's INSERT, and every byte-identical assertion above would silently
//     pass against an unmutated row that was never written.
//   - Global PRIMARY KEY collision across tenants surfaces as typed
//     apierr.Conflict (yerr.CodeConflict) through mapWriteError AND leaves
//     the prior owner's row byte-identical. The id column is a global
//     PRIMARY KEY (not scoped per tenant), so an explicit caller-supplied
//     id that collides with an existing row in ANOTHER tenant must reject
//     the request and must NOT silently UPDATE the prior tenant's row.
//   - SumActiveReservations cross-tenant projection: the sum returned for
//     orgA is the sum of orgA's active rows only; orgB's rows contribute
//     zero, even when (resource, amount, expires_at) overlap exactly. A
//     regression that dropped the organization_id predicate would surface
//     as the orthogonal tenant's amounts folded into the caller's total.
//   - SumActiveReservations on an empty tenant returns zero even when
//     other tenants hold rows on the same resource — the COALESCE(SUM,0)
//     coerces the empty-row case, and the organization_id predicate keeps
//     the cross-tenant rows out of the SUM source set.
//   - ON DELETE CASCADE tenant isolation: deleting orgA via raw SQL
//     removes orgA's quota_reservations rows (the CASCADE works) and
//     leaves orgB's rows byte-identical to baseline. The bystander
//     byte-identity check (updated_at anchor) makes a regression that
//     swept rows by resource alone surface immediately.
//
// What this file deliberately delegates:
//
//   - InsertReservation row-shape / id-provenance / round-trip /
//     CHECK and DOMAIN violation / nil-Tx guard / tx-rollback /
//     SumActiveReservations status / time / resource filters are all
//     proved by quota_reservation_repository_invariants_test.go (BE-0455).
//     This file only re-exercises the cross-tenant projection.
//   - The settled_consistent CHECK and the partial active-index schema
//     invariants are owned by quota_schema_test.go
//     (TestQuotaReservationLifecycleConstraints,
//     TestQuotaResourceDomainEnforcesClosedSet).
//   - The composite-FK quota_reservations_job_fk (organization_id, job_id)
//     -> provisioning_jobs (organization_id, id) tenant-scoping is owned
//     by the BE-0461/BE-0462 provisioning_jobs invariants/tenant-isolation
//     stories — this file does not seed a job to exercise it because the
//     reservation surface this file probes does not require a job.
//   - quota_reservations stores NO secret-bearing column — amount/status
//     are non-sensitive — so the BE-0434-style raw-secret_hash probe and
//     the redaction-needle-in-error probe have no analogue here.
//
// Database-backed cases run against an isolated, freshly migrated Postgres
// and skip when YALLA_TEST_DATABASE_URL is unset.

// stringPtrEqualQR and timePtrEqualQR compare nullable columns observed in
// rawQuotaReservationRow (job_id text, settled_at timestamptz). The per-file
// QR suffix is mandatory: every *_test.go file under
// internal/controlplane/store/ shares the same package, and the BE-0440
// project-grant file already exports a stringPtrEqual variant — collisions
// would block compilation. The BE-0451 quota_policy file uses the QP suffix
// for the same reason.
func stringPtrEqualQR(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func timePtrEqualQR(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// fmtStringPtrQR renders a nullable string column for error messages so a
// missing vs empty distinction is obvious.
func fmtStringPtrQR(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// fmtTimePtrQR renders a nullable timestamp column for error messages so a
// missing vs zero distinction is obvious.
func fmtTimePtrQR(p *time.Time) string {
	if p == nil {
		return "<nil>"
	}
	return p.Format(time.RFC3339Nano)
}

// assertQuotaReservationByteIdentical asserts every observable column on a
// bystander quota_reservations row is byte-identical to its baseline. The
// trigger-managed updated_at is the load-bearing anchor: the BEFORE UPDATE
// quota_reservations_set_updated_at trigger refreshes it on every matched
// UPDATE, so a missing organization_id predicate in InsertReservation or
// SumActiveReservations would surface here as updated_at drift even when
// the other columns happened to look right.
func assertQuotaReservationByteIdentical(t *testing.T, label string, baseline, after rawQuotaReservationRow) {
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
	if after.Amount != baseline.Amount {
		t.Errorf("%s: bystander.amount = %d, want %d",
			label, after.Amount, baseline.Amount)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: bystander.status = %q, want %q", label, after.Status, baseline.Status)
	}
	if !stringPtrEqualQR(after.JobID, baseline.JobID) {
		t.Errorf("%s: bystander.job_id = %s, want %s",
			label, fmtStringPtrQR(after.JobID), fmtStringPtrQR(baseline.JobID))
	}
	if !after.ExpiresAt.Equal(baseline.ExpiresAt) {
		t.Errorf("%s: bystander.expires_at = %v, want %v",
			label, after.ExpiresAt, baseline.ExpiresAt)
	}
	if !timePtrEqualQR(after.SettledAt, baseline.SettledAt) {
		t.Errorf("%s: bystander.settled_at = %s, want %s",
			label, fmtTimePtrQR(after.SettledAt), fmtTimePtrQR(baseline.SettledAt))
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE UPDATE quota_reservations_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE silently crossed the organization_id predicate",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestQuotaRepositoryInsertReservationOnOrgADoesNotTouchOrgB proves the
// load-bearing cross-tenant invariant of InsertReservation: when orgB
// already owns active and settled rows for several resources (including
// the SAME resource orgA is about to claim), orgA's InsertReservation
// for that resource lands as a fresh INSERT for orgA — never as an
// UPDATE on any orgB row. The PRIMARY KEY isolates rows by id and the
// partial active-index quota_reservations_active_idx (organization_id,
// resource) WHERE status='active' is per-tenant, so orgA's INSERT and
// orgB's existing rows cannot collide. A regression that swept orgB's
// row through a missing organization_id predicate would surface in any
// of three ways: orgB's amount would change, orgB's updated_at would
// shift (the set_updated_at trigger fires on any matched UPDATE), or
// the bystander row would vanish entirely.
func TestQuotaRepositoryInsertReservationOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	expires := time.Now().Add(time.Hour)

	// orgB owns three quota_reservations rows: an active row on the SAME
	// resource orgA is about to claim (the load-bearing peer), an active
	// row on a different resource (cross-resource peer), and a settled
	// (committed) row on yet another resource (different lifecycle peer).
	// Recognisable amounts make a cross-tenant UPDATE that silently
	// rewrote a column surface immediately.
	insertReservationRow(t, db, "qres_iso_orgb_services_active", orgB.ID, "services", 11,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_orgb_projects_active", orgB.ID, "projects", 22,
		store.ReservationStatusActive, expires)
	insertSettledReservationRow(t, db, "qres_iso_orgb_databases_committed", orgB.ID, "databases", 33,
		store.ReservationStatusCommitted, expires)

	baselineServices := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_services_active")
	baselineProjects := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_projects_active")
	baselineDatabases := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_databases_committed")

	// orgA InsertReservation lands on the SAME resource orgB owns — the
	// load-bearing direction. The lack of UNIQUE (organization_id,
	// resource) means the INSERT must NOT touch orgB's same-resource row.
	created := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: orgA.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         7,
		ExpiresAt:      expires,
	})
	if created.OrganizationID != orgA.ID {
		t.Fatalf("InsertReservation lifted organization_id = %q, want %q (orgA's INSERT was attributed to the wrong tenant)",
			created.OrganizationID, orgA.ID)
	}
	if created.ID == "qres_iso_orgb_services_active" {
		t.Fatalf("InsertReservation returned orgB's reservation id %q — the INSERT silently UPDATEd orgB's row instead of minting a fresh row for orgA", created.ID)
	}

	afterServices := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_services_active")
	assertQuotaReservationByteIdentical(t,
		"orgB(services, active) bystander after orgA InsertReservation(services)",
		baselineServices, afterServices)

	afterProjects := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_projects_active")
	assertQuotaReservationByteIdentical(t,
		"orgB(projects, active) bystander after orgA InsertReservation(services)",
		baselineProjects, afterProjects)

	afterDatabases := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_orgb_databases_committed")
	assertQuotaReservationByteIdentical(t,
		"orgB(databases, committed) bystander after orgA InsertReservation(services)",
		baselineDatabases, afterDatabases)
}

// TestQuotaRepositoryInsertReservationOnOrgADoesNotChangeOrgBRowCount
// proves the per-tenant row count is invariant under another tenant's
// InsertReservation call. orgB owns three reservations before orgA
// makes any call; orgA then inserts an active reservation for a
// resource orgB has NOT seeded. orgB's count must remain at 3 —
// neither lower (an accidental cross-tenant DELETE) nor higher (an
// accidental cross-tenant INSERT). orgA's count goes from 0 to 1.
func TestQuotaRepositoryInsertReservationOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	expires := time.Now().Add(time.Hour)

	insertReservationRow(t, db, "qres_iso_count_orgb_services", orgB.ID, "services", 1,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_count_orgb_projects", orgB.ID, "projects", 2,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_count_orgb_databases", orgB.ID, "databases", 3,
		store.ReservationStatusActive, expires)

	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Fatalf("baseline orgB count = %d, want 3 — test fixture is invalid", n)
	}
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	// orgA InsertReservation on a resource orgB has NOT seeded — the
	// cleanest signal: an accidental cross-tenant INSERT would either
	// bump orgB's count (if the organization_id swapped) or fail
	// entirely (if a phantom UNIQUE on resource alone collided).
	runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: orgA.ID,
		Resource:       store.QuotaResourceDomains,
		Amount:         5,
		ExpiresAt:      expires,
	})

	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Errorf("orgB count after InsertReservation(orgA, domains) = %d, want 3 — orgA's INSERT touched orgB", n)
	}
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgA.ID); n != 1 {
		t.Errorf("orgA count after InsertReservation(orgA, domains) = %d, want 1 — orgA's INSERT did not land", n)
	}
}

// TestQuotaRepositoryInsertReservationSameResourceInTwoTenantsBothPersist
// is the load-bearing positive-direction pair for the bystander
// byte-identity proofs above. quota_reservations has NO UNIQUE
// constraint on (organization_id, resource) — only PRIMARY KEY (id)
// and UNIQUE (organization_id, id) for composite-FK targeting — so two
// tenants each holding an active reservation for the same resource
// (with the same amount and the same expires_at) is the expected
// concurrent shape. Without this test, a regression that resolved a
// phantom conflict on (resource,) alone would prevent orgA's INSERT,
// and every byte-identical assertion in the bystander tests would
// silently pass against an unmutated row that was never written.
func TestQuotaRepositoryInsertReservationSameResourceInTwoTenantsBothPersist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	expires := time.Now().Add(time.Hour)

	rowA := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: orgA.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         4,
		ExpiresAt:      expires,
	})
	rowB := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: orgB.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         4,
		ExpiresAt:      expires,
	})

	if rowA.ID == rowB.ID {
		t.Errorf("two tenants share quota_reservations.id %q — distinct rows must get distinct ids from newQuotaID(\"qres\")", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two reservations have the same organization_id %q — fixture is broken", rowA.OrganizationID)
	}
	if rowA.OrganizationID != orgA.ID {
		t.Errorf("rowA.organization_id = %q, want %q", rowA.OrganizationID, orgA.ID)
	}
	if rowB.OrganizationID != orgB.ID {
		t.Errorf("rowB.organization_id = %q, want %q", rowB.OrganizationID, orgB.ID)
	}
	if rowA.Resource != store.QuotaResourceServices || rowB.Resource != store.QuotaResourceServices {
		t.Errorf("resource columns = (%q, %q), want both = services",
			string(rowA.Resource), string(rowB.Resource))
	}
	if rowA.Amount != 4 || rowB.Amount != 4 {
		t.Errorf("amount columns = (%d, %d), want both = 4 — same-amount cross-tenant rows must each persist their own amount",
			rowA.Amount, rowB.Amount)
	}

	// Each tenant owns exactly one reservation row.
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgA.ID); n != 1 {
		t.Errorf("quota_reservations rows for orgA = %d, want 1", n)
	}
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgB.ID); n != 1 {
		t.Errorf("quota_reservations rows for orgB = %d, want 1", n)
	}
}

// TestQuotaRepositoryInsertReservationGlobalIDCollisionAcrossTenantsIsTypedConflict
// proves a cross-tenant requester cannot UPDATE another tenant's
// reservation row through an explicit-id collision. quota_reservations.id
// is a global PRIMARY KEY, not scoped per tenant, so an orgA request
// that names orgB's existing id must:
//
//	(1) reject the request with typed apierr.Conflict (yerr.CodeConflict),
//	    surfaced through mapWriteError from the PRIMARY KEY unique
//	    violation; and
//	(2) leave orgB's row byte-identical to baseline — the failed INSERT
//	    must NOT silently fall through to an UPDATE of orgB's row.
//
// A regression that resolved the conflict by ON CONFLICT DO UPDATE
// (a copy-paste of the quota_policies upsert pattern, for example)
// would surface either as a nil error or as updated_at drift on orgB's
// row.
func TestQuotaRepositoryInsertReservationGlobalIDCollisionAcrossTenantsIsTypedConflictAndDoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	expires := time.Now().Add(time.Hour)

	// orgB owns the colliding id with a recognisable amount and resource.
	const collisionID = "qres_iso_pk_collision"
	insertReservationRow(t, db, collisionID, orgB.ID, "services", 99,
		store.ReservationStatusActive, expires)

	baseline := loadQuotaReservationRowByID(ctx, t, db, collisionID)

	// orgA tries to InsertReservation with the SAME explicit id. The
	// repository must surface PK uniqueness as typed apierr.Conflict
	// through mapWriteError.
	wErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			ID:             collisionID,
			OrganizationID: orgA.ID,
			Resource:       store.QuotaResourceProjects,
			Amount:         1,
			ExpiresAt:      expires,
		})
		return err
	})
	if wErr == nil {
		t.Fatal("InsertReservation(cross-tenant id collision) returned nil, want typed Conflict — the request silently succeeded which would imply an UPDATE on orgB's row")
	}
	if ye := yerr.From(wErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(cross-tenant id collision) error code = %s, want %s (PRIMARY KEY unique violation must surface as Conflict through mapWriteError)",
			ye.Code, yerr.CodeConflict)
	}

	// orgB's row must be byte-identical — the failed INSERT cannot have
	// fallen through to an UPDATE of orgB's row.
	after := loadQuotaReservationRowByID(ctx, t, db, collisionID)
	assertQuotaReservationByteIdentical(t,
		"orgB row survives cross-tenant id-collision attempt",
		baseline, after)

	// And the failed orgA attempt must not have inserted any orgA-owned row.
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgA.ID); n != 0 {
		t.Errorf("quota_reservations rows for orgA after collision attempt = %d, want 0 — the failed INSERT must not persist", n)
	}
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgB.ID); n != 1 {
		t.Errorf("quota_reservations rows for orgB after collision attempt = %d, want 1 — orgB's row must survive", n)
	}
}

// TestQuotaRepositorySumActiveReservationsIsTenantScoped proves the
// load-bearing cross-tenant invariant of SumActiveReservations: the
// sum returned for orgA includes orgA's active rows only; orgB's
// active rows on the SAME resource contribute zero, even when they
// individually carry larger amounts. A regression that dropped the
// `organization_id = $1` predicate from the SELECT would surface
// here as the orthogonal tenant's amounts folded into the caller's
// total.
func TestQuotaRepositorySumActiveReservationsIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	now := time.Now()
	expires := now.Add(time.Hour)

	// orgA owns three active rows on services summing to 2+3+5 = 10.
	insertReservationRow(t, db, "qres_iso_sum_orga_services_2", orgA.ID, "services", 2,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_sum_orga_services_3", orgA.ID, "services", 3,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_sum_orga_services_5", orgA.ID, "services", 5,
		store.ReservationStatusActive, expires)

	// orgB owns active rows on services summing to 100+200 = 300 — chosen
	// to make a cross-tenant fold immediately recognisable (the orgA sum
	// would jump from 10 to 310).
	insertReservationRow(t, db, "qres_iso_sum_orgb_services_100", orgB.ID, "services", 100,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_sum_orgb_services_200", orgB.ID, "services", 200,
		store.ReservationStatusActive, expires)

	// Cross-resource peer in orgB (projects) must not bleed into the
	// services sum for either tenant — guards the resource predicate at
	// the same time as the tenant predicate.
	insertReservationRow(t, db, "qres_iso_sum_orgb_projects_999", orgB.ID, "projects", 999,
		store.ReservationStatusActive, expires)

	var (
		sumA, sumB int64
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		sumA, rErr = repo.SumActiveReservations(ctx, q, orgA.ID, store.QuotaResourceServices, now)
		if rErr != nil {
			return rErr
		}
		sumB, rErr = repo.SumActiveReservations(ctx, q, orgB.ID, store.QuotaResourceServices, now)
		return rErr
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}

	if sumA != 10 {
		t.Errorf("SumActiveReservations(orgA, services) = %d, want 10 — orgB's reservations leaked into orgA's sum",
			sumA)
	}
	if sumB != 300 {
		t.Errorf("SumActiveReservations(orgB, services) = %d, want 300 — orgA's reservations leaked into orgB's sum",
			sumB)
	}
}

// TestQuotaRepositorySumActiveReservationsOnEmptyTenantReturnsZeroEvenWhenOtherTenantsHaveRows
// is the defensive shape of the tenant predicate: orgB holds many
// active reservations on services, but a sum for orgA (which holds
// none) must still return 0. The COALESCE(SUM(amount), 0) coerces the
// empty-row case, and the organization_id predicate keeps orgB's rows
// out of the SUM source set. A regression that dropped the predicate
// would surface as orgA's sum equalling orgB's total.
func TestQuotaRepositorySumActiveReservationsOnEmptyTenantReturnsZeroEvenWhenOtherTenantsHaveRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	now := time.Now()
	expires := now.Add(time.Hour)

	insertReservationRow(t, db, "qres_iso_empty_orgb_services_50", orgB.ID, "services", 50,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_empty_orgb_services_75", orgB.ID, "services", 75,
		store.ReservationStatusActive, expires)

	var sumA int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, rErr := repo.SumActiveReservations(ctx, q, orgA.ID, store.QuotaResourceServices, now)
		if rErr != nil {
			return rErr
		}
		sumA = got
		return nil
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sumA != 0 {
		t.Errorf("SumActiveReservations(orgA, services) on empty tenant = %d, want 0 — orgB's reservations leaked into orgA's sum",
			sumA)
	}
}

// TestQuotaReservationOrganizationDeleteCascadeIsTenantScoped proves the
// schema's ON DELETE CASCADE on quota_reservations.organization_id is
// scoped to the deleted tenant: removing orgA removes orgA's
// quota_reservations rows and ONLY orgA's. orgB's rows survive
// byte-identically. A regression that swapped the CASCADE FK target
// or dropped the FK predicate would surface here as missing or
// mutated orgB rows. This is the cross-tenant partner of the
// in-tenant cascade probe that lives in quota_schema_test.go
// (TestQuotaCascadeDeleteOnOrganization, which proves the cascade
// happens for the targeted tenant; this test proves it does NOT bleed
// into another tenant).
func TestQuotaReservationOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	expires := time.Now().Add(time.Hour)

	// Two rows for orgA (which will be cascaded away) and three for orgB
	// (which must survive byte-identically). The (orgB, services) pair is
	// deliberately picked because it shares the resource dimension with
	// (orgA, services) — a regression that dropped the organization_id
	// predicate in the CASCADE would target rows by resource alone.
	insertReservationRow(t, db, "qres_iso_cascade_orga_services", orgA.ID, "services", 4,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_cascade_orga_projects", orgA.ID, "projects", 9,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_cascade_orgb_services", orgB.ID, "services", 12,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_iso_cascade_orgb_projects", orgB.ID, "projects", 18,
		store.ReservationStatusActive, expires)
	insertSettledReservationRow(t, db, "qres_iso_cascade_orgb_databases_committed", orgB.ID, "databases", 27,
		store.ReservationStatusCommitted, expires)

	baselineServices := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_services")
	baselineProjects := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_projects")
	baselineDatabases := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_databases_committed")

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgA.ID); n != 0 {
		t.Errorf("quota_reservations rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countQuotaReservationRowsForOrg(ctx, t, db, orgB.ID); n != 3 {
		t.Errorf("quota_reservations rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	afterServices := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_services")
	assertQuotaReservationByteIdentical(t, "orgB(services, active) survives orgA delete",
		baselineServices, afterServices)

	afterProjects := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_projects")
	assertQuotaReservationByteIdentical(t, "orgB(projects, active) survives orgA delete",
		baselineProjects, afterProjects)

	afterDatabases := loadQuotaReservationRowByID(ctx, t, db, "qres_iso_cascade_orgb_databases_committed")
	assertQuotaReservationByteIdentical(t, "orgB(databases, committed) survives orgA delete",
		baselineDatabases, afterDatabases)
}
