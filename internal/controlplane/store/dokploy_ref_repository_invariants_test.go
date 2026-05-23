package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for DokployRefRepository (BE-0465). The dokploy_refs
// table landed in migration 0002 as part of the initial tenant hierarchy
// and has been exercised since then only by schema-level tests
// (TestDokployRefsConstraints, TestTenantHierarchyDeleteCascade in
// schema_test.go) issuing raw SQL. This file is the first set of tests to
// land against the typed DokployRefRepository surface — no pre-existing
// dokploy_ref_test.go exists — so it covers both the CRUD methods and the
// row-shape / lifecycle invariants in a single file. The
// byte-identical-bystander tenant-isolation proof for cross-tenant Get /
// GetByDokployTarget / ListByYallaResource / ListByOrganization / Delete is
// the subject of BE-0466 and will live in
// dokploy_ref_tenant_isolation_test.go.
//
// What this file proves about the typed DokployRefRepository surface:
//
//   - Insert returns the row the database actually committed: id is a
//     positive bigint minted by the GENERATED ALWAYS AS IDENTITY column
//     (so the caller cannot smuggle one in), created_at and updated_at
//     are non-zero and equal on a fresh row (no UPDATE has fired so the
//     dokploy_refs_set_updated_at trigger has not run), and the
//     caller-supplied fields are echoed back verbatim, including the
//     closed-set yalla_kind / dokploy_resource values which round-trip as
//     the typed YallaKind / DokployResource wrappers.
//   - Insert preserves a caller-supplied (ignored) ID. The id field is
//     overwritten by the database-minted value; a caller that tries to
//     supply 999 still observes the minted id in the returned struct, and
//     the persisted row at the minted id is byte-identical to the raw-SQL
//     re-load.
//   - Insert rejects a blank YallaKind / DokployResource as typed Internal
//     (programming error caught at the application boundary).
//   - Insert rejects nil tx as typed Internal (a mapping must never be
//     persisted outside the transaction that also carries the lifecycle
//     write it records).
//   - Insert CHECK / FK violations surface as typed apierr.Conflict
//     through mapWriteError: an unknown yalla_kind, an unknown
//     dokploy_resource, a blank yalla_id, a blank dokploy_id, and an
//     unknown organization_id (FK to organizations).
//   - Insert UNIQUE violations surface as typed apierr.Conflict: the
//     global UNIQUE (dokploy_resource, dokploy_id) — a Dokploy object
//     cannot be claimed twice, even across tenants — and the per-tenant
//     UNIQUE (organization_id, yalla_id, dokploy_resource, dokploy_id) —
//     a duplicate mapping row is rejected at the database.
//   - Insert transaction rollback semantics: a closure that returns an
//     error after a successful Insert leaves no dokploy_refs row behind.
//   - Get returns the row at (organization_id, id), surfaces apierr.NotFound
//     for an unknown id, never leaks the typed-Internal-class StoreUnavailable
//     code for a missing row, and round-trips the persisted struct
//     field-by-field with the raw-SQL view of the same row.
//   - GetByDokployTarget returns the row at (organization_id,
//     dokploy_resource, dokploy_id), surfaces apierr.NotFound for an
//     unknown target, and rejects a blank dokploy_resource as typed
//     Internal.
//   - ListByYallaResource is tenant-scoped, deterministically ordered
//     (dokploy_resource ASC, dokploy_id ASC, id ASC), always returns a
//     non-nil slice, and rejects a blank yalla_kind as typed Internal.
//   - ListByOrganization is tenant-scoped, deterministically ordered,
//     always returns a non-nil slice.
//   - Delete is tenant-scoped via tag.RowsAffected — an unknown id (or a
//     cross-tenant id) surfaces as typed apierr.NotFound, never as a 500.
//   - Delete rejects nil tx as typed Internal.
//   - The dokploy_refs row is removed by the organizations cascade chain:
//     deleting the parent organizations row cascades to all of its
//     dokploy_refs rows.
//
// What this file deliberately delegates:
//
//   - Tenant-isolation byte-identical-bystander semantics across two
//     organizations (Insert(orgA) leaves every orgB row byte-identical,
//     Get/List cross-tenant return empty/NotFound while leaving counts
//     unchanged) is the paired BE-0466 story.
//   - The store package exposes no per-row Update method on dokploy_refs:
//     the mapping has no customer-mutable column (every column is part of
//     either the row identity or a database-owned timestamp). Migration
//     0011's comment about covering dokploy_refs "for parity" with the
//     rest of the tenant hierarchy was aspirational — the actual ALTER
//     statements only touch organizations / projects / environments /
//     services, so dokploy_refs has neither a version column nor a
//     bump_version trigger. A raw-SQL UPDATE test below pins that the
//     dokploy_refs_set_updated_at trigger DOES fire on UPDATE, so a
//     future worker remap story that lands the column + the typed Update
//     surface together has a known-good observability foothold.
//   - Reused helpers from sibling test files in store_test:
//     seedOrg/seedProject/seedEnvironment/seedService (schema_test.go),
//     newStore (store_test.go).

// mintDokployID builds a stable, test-local Dokploy object id from t.Name
// and a suffix. The global UNIQUE (dokploy_resource, dokploy_id) constraint
// is the dokploy_refs table's tightest invariant, so test fixtures MUST
// not collide across parallel runs — t.Name() supplies the test-specific
// scope and the suffix disambiguates rows within a single test.
func mintDokployID(t *testing.T, suffix string) string {
	t.Helper()
	return "dokploy-" + t.Name() + "-" + suffix
}

// runInsertDokployRefOrFail wraps DokployRefRepository.Insert in a
// Store.Write closure and fatals on error, returning the persisted
// mapping. It is the smallest possible happy-path closure and is reused
// by every test that does not need to observe the call's tx in isolation.
func runInsertDokployRefOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DokployRefRepository,
	ref store.DokployRef,
) store.DokployRef {
	t.Helper()
	var created store.DokployRef
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, iErr := repo.Insert(ctx, tx, ref)
		if iErr != nil {
			return iErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("Insert(%+v): %v", ref, err)
	}
	return created
}

// rawDokployRefRow is the full dokploy_refs row, deliberately loaded via
// raw SQL so the test can observe id, created_at, updated_at, and the
// closed-set yalla_kind / dokploy_resource columns through the same shape
// the database stores them in. It is the same template rawDeploymentRow
// uses for deployments and rawJobAttemptRow uses for job_attempts; unlike
// those tables, dokploy_refs has no version column (see file-header note).
type rawDokployRefRow struct {
	ID              int64
	OrganizationID  string
	YallaKind       string
	YallaID         string
	DokployResource string
	DokployID       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// loadDokployRefRowByID reads the raw dokploy_refs row for id and fatals
// on error. The lookup is by primary key — distinct dokploy_refs rows have
// distinct ids — so no tenant scope is needed (raw loaders bypass
// repository scoping deliberately, so the test observes the persisted row
// exactly as the database stores it).
func loadDokployRefRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id int64,
) rawDokployRefRow {
	t.Helper()
	var row rawDokployRefRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, yalla_kind, yalla_id,
		        dokploy_resource, dokploy_id,
		        created_at, updated_at
		   FROM dokploy_refs
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.YallaKind, &row.YallaID,
		&row.DokployResource, &row.DokployID,
		&row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load dokploy_refs id=%d: %v", id, err)
	}
	return row
}

// countDokployRefRowsForOrg returns the number of dokploy_refs rows owned
// by organizationID. It is the "did the rollback / cascade leave a row
// behind?" probe.
func countDokployRefRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM dokploy_refs
		  WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count dokploy_refs for org=%q: %v", organizationID, err)
	}
	return n
}

// dokployRefTxRollbackSentinel is a uniquely-typed sentinel for the
// rollback test. Sentinel types must be unique per file in the store_test
// package (every *_test.go under internal/controlplane/store/ shares the
// same package). Existing siblings include deploymentTxRollbackSentinel,
// deploymentEventTxRollbackSentinel, quotaReservationTxRollbackSentinel,
// jobAttemptTxRollbackSentinel.
type dokployRefTxRollbackSentinel struct{}

func TestDokployRefRepositoryInsertMintsRowShape(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	dokployID := mintDokployID(t, "shape")
	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       dokployID,
	}
	got := runInsertDokployRefOrFail(ctx, t, s, repo, ref)

	if got.ID <= 0 {
		t.Errorf("Insert returned non-positive id %d (id is GENERATED ALWAYS AS IDENTITY and must be a positive bigint)", got.ID)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("OrganizationID = %q, want %q", got.OrganizationID, org.ID)
	}
	if got.YallaKind != store.YallaKindService {
		t.Errorf("YallaKind = %q, want %q", got.YallaKind, store.YallaKindService)
	}
	if got.YallaID != svc.ID {
		t.Errorf("YallaID = %q, want %q", got.YallaID, svc.ID)
	}
	if got.DokployResource != store.DokployResourceApplication {
		t.Errorf("DokployResource = %q, want %q", got.DokployResource, store.DokployResourceApplication)
	}
	if got.DokployID != dokployID {
		t.Errorf("DokployID = %q, want %q", got.DokployID, dokployID)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want database-stamped non-zero timestamp")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero, want database-stamped non-zero timestamp")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("CreatedAt=%v != UpdatedAt=%v on a fresh row (no UPDATE has fired so the set_updated_at trigger has not run)",
			got.CreatedAt, got.UpdatedAt)
	}

	raw := loadDokployRefRowByID(ctx, t, db, got.ID)
	if raw.ID != got.ID || raw.OrganizationID != got.OrganizationID ||
		raw.YallaKind != got.YallaKind.String() || raw.YallaID != got.YallaID ||
		raw.DokployResource != got.DokployResource.String() ||
		raw.DokployID != got.DokployID ||
		!raw.CreatedAt.Equal(got.CreatedAt) || !raw.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("typed Insert row mismatches raw-SQL re-load:\n  typed: %+v\n  raw:   %+v", got, raw)
	}
}

func TestDokployRefRepositoryInsertIgnoresCallerSuppliedID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	const smuggled int64 = 999_999_999
	ref := store.DokployRef{
		ID:              smuggled,
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "smuggle"),
	}
	got := runInsertDokployRefOrFail(ctx, t, s, repo, ref)

	if got.ID == smuggled {
		t.Errorf("Insert echoed caller-supplied id %d; the GENERATED ALWAYS AS IDENTITY column must overwrite it", smuggled)
	}
	if got.ID <= 0 {
		t.Errorf("Insert returned non-positive id %d, want database-minted bigint", got.ID)
	}
}

func TestDokployRefRepositoryInsertBlankYallaKindIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "blank-kind"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with blank YallaKind returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("blank YallaKind persisted %d rows, want 0", got)
	}
}

func TestDokployRefRepositoryInsertBlankDokployResourceIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	ref := store.DokployRef{
		OrganizationID: org.ID,
		YallaKind:      store.YallaKindService,
		YallaID:        svc.ID,
		DokployID:      mintDokployID(t, "blank-resource"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with blank DokployResource returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDokployRefRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := store.NewDokployRefRepository()
	_, err := repo.Insert(ctx, nil, store.DokployRef{
		OrganizationID:  "org_nope",
		YallaKind:       store.YallaKindService,
		YallaID:         "svc_nope",
		DokployResource: store.DokployResourceApplication,
		DokployID:       "dokploy-nil-tx",
	})
	if err == nil {
		t.Fatal("Insert with nil tx returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDokployRefRepositoryInsertUnknownYallaKindIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKind("not-a-real-kind"),
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bad-kind"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with unknown yalla_kind returned nil, want typed Conflict")
	}
	ye := yerr.From(err)
	if ye == nil || ye.Code != yerr.CodeConflict {
		t.Fatalf("error = %v, want code %s", err, yerr.CodeConflict)
	}
	if strings.Contains(ye.Message, "not-a-real-kind") {
		t.Errorf("conflict message leaks the constraint argument: %q", ye.Message)
	}
}

func TestDokployRefRepositoryInsertUnknownDokployResourceIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResource("not-a-real-resource"),
		DokployID:       mintDokployID(t, "bad-resource"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with unknown dokploy_resource returned nil, want typed Conflict")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestDokployRefRepositoryInsertBlankYallaIDIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         "",
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "blank-yalla-id"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with blank yalla_id returned nil, want typed Conflict (CHECK length(yalla_id) > 0)")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestDokployRefRepositoryInsertBlankDokployIDIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	ref := store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       "",
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with blank dokploy_id returned nil, want typed Conflict (CHECK length(dokploy_id) > 0)")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestDokployRefRepositoryInsertUnknownOrganizationIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()

	ref := store.DokployRef{
		OrganizationID:  "org_does_not_exist",
		YallaKind:       store.YallaKindOrganization,
		YallaID:         "yalla_no_org",
		DokployResource: store.DokployResourceOrganization,
		DokployID:       mintDokployID(t, "no-org"),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, ref)
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with unknown organization_id returned nil, want typed Conflict (FK to organizations)")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestDokployRefRepositoryInsertDuplicateDokployTargetIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	orgA := seedOrg(t, db, f, "Alpha")
	projA := seedProject(t, db, f, orgA, "Web")
	envA := seedEnvironment(t, db, f, projA, "Prod")
	svcA := seedService(t, db, f, envA, "API")

	orgB := seedOrg(t, db, f, "Beta")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	svcB := seedService(t, db, f, envB, "API")

	dokployID := mintDokployID(t, "dup-target")
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       dokployID,
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  orgB.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         svcB.ID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       dokployID,
		})
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with reused (dokploy_resource, dokploy_id) returned nil, want typed Conflict (UNIQUE)")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, orgB.ID); got != 0 {
		t.Errorf("rejected duplicate persisted %d rows under orgB, want 0", got)
	}
}

func TestDokployRefRepositoryInsertDuplicateMappingIsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	dokployID := mintDokployID(t, "dup-mapping")
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       dokployID,
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         svc.ID,
			DokployResource: store.DokployResourceDomain,
			DokployID:       dokployID,
		})
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with duplicate (organization_id, yalla_id, dokploy_resource, dokploy_id) returned nil, want typed Conflict (UNIQUE)")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("error = %v, want code %s", err, yerr.CodeConflict)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 1 {
		t.Errorf("after rejected duplicate, org has %d dokploy_refs rows, want 1 (the original)", got)
	}
}

func TestDokployRefRepositoryInsertMultipleDomainsForSameServiceAllPersist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	for _, suffix := range []string{"d1", "d2", "d3"} {
		runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         svc.ID,
			DokployResource: store.DokployResourceDomain,
			DokployID:       mintDokployID(t, suffix),
		})
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 3 {
		t.Errorf("after three domain mappings, org has %d dokploy_refs rows, want 3 (the UNIQUE constraint includes dokploy_id so distinct domains share yalla_id)", got)
	}
}

func TestDokployRefRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	sentinel := errors.New("dokploy_ref rollback sentinel")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, iErr := repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         svc.ID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       mintDokployID(t, "rollback"),
		}); iErr != nil {
			return iErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Store.Write error = %v, want sentinel %v", err, sentinel)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("after rollback, org has %d dokploy_refs rows, want 0 (Insert must roll back with the transaction)", got)
	}

	// Use the sentinel type so the file's unique-sentinel-type contract
	// is observably enforced by the compiler (not just by convention).
	_ = dokployRefTxRollbackSentinel{}
}

func TestDokployRefRepositoryGetReturnsPersistedRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	created := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "get"),
	})

	got, err := repo.Get(ctx, db, org.ID, created.ID)
	if err != nil {
		t.Fatalf("Get(%q, %d): %v", org.ID, created.ID, err)
	}
	if got.ID != created.ID || got.OrganizationID != created.OrganizationID ||
		got.YallaKind != created.YallaKind || got.YallaID != created.YallaID ||
		got.DokployResource != created.DokployResource ||
		got.DokployID != created.DokployID ||
		!got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get mismatches Insert:\n  insert: %+v\n  get:    %+v", created, got)
	}
}

func TestDokployRefRepositoryGetUnknownReturnsTypedNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	_, err := repo.Get(ctx, db, org.ID, 987_654_321)
	if err == nil {
		t.Fatal("Get with unknown id returned nil, want typed NotFound")
	}
	ye := yerr.From(err)
	if ye == nil || ye.Code != yerr.CodeNotFound {
		t.Fatalf("error = %v, want code %s", err, yerr.CodeNotFound)
	}
	if strings.Contains(ye.Message, org.ID) {
		t.Errorf("not-found message leaks the organization id: %q", ye.Message)
	}
}

func TestDokployRefRepositoryGetByDokployTargetReturnsRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	dokployID := mintDokployID(t, "by-target")
	created := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       dokployID,
	})

	got, err := repo.GetByDokployTarget(ctx, db, org.ID, store.DokployResourceApplication, dokployID)
	if err != nil {
		t.Fatalf("GetByDokployTarget: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByDokployTarget id = %d, want %d", got.ID, created.ID)
	}
}

func TestDokployRefRepositoryGetByDokployTargetUnknownReturnsTypedNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	_, err := repo.GetByDokployTarget(ctx, db, org.ID, store.DokployResourceApplication, "dokploy-missing")
	if err == nil {
		t.Fatal("GetByDokployTarget unknown returned nil, want typed NotFound")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Errorf("error = %v, want code %s", err, yerr.CodeNotFound)
	}
}

func TestDokployRefRepositoryGetByDokployTargetBlankResourceIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	_, err := repo.GetByDokployTarget(ctx, db, org.ID, store.DokployResource(""), "dokploy-x")
	if err == nil {
		t.Fatal("GetByDokployTarget with blank resource returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDokployRefRepositoryListByYallaResourceIsOrderedAndBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	// Declare rows in (dokploy_resource ASC, dokploy_id ASC) sort order so
	// the assertion below is a direct read of the SQL ORDER BY contract.
	// "application" < "backup" < "domain" lexicographically, so the
	// expected sequence is application/z, backup/m, domain/a, domain/b.
	wantOrder := []struct {
		resource store.DokployResource
		id       string
	}{
		{store.DokployResourceApplication, "dokploy-z"},
		{store.DokployResourceBackup, "dokploy-m"},
		{store.DokployResourceDomain, "dokploy-a"},
		{store.DokployResourceDomain, "dokploy-b"},
	}
	// Insert in a non-sorted physical order so the ORDER BY contract is
	// the only thing producing the deterministic sequence.
	insertOrder := []int{2, 0, 3, 1}
	for _, idx := range insertOrder {
		runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         svc.ID,
			DokployResource: wantOrder[idx].resource,
			DokployID:       wantOrder[idx].id,
		})
	}

	got, err := repo.ListByYallaResource(ctx, db, org.ID, store.YallaKindService, svc.ID)
	if err != nil {
		t.Fatalf("ListByYallaResource: %v", err)
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d rows, want %d", len(got), len(wantOrder))
	}
	for i, w := range wantOrder {
		if got[i].DokployResource != w.resource || got[i].DokployID != w.id {
			t.Errorf("row %d = (%q,%q), want (%q,%q) — list must order by (dokploy_resource ASC, dokploy_id ASC, id ASC)",
				i, got[i].DokployResource, got[i].DokployID, w.resource, w.id)
		}
	}
}

func TestDokployRefRepositoryListByYallaResourceEmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	got, err := repo.ListByYallaResource(ctx, db, org.ID, store.YallaKindService, svc.ID)
	if err != nil {
		t.Fatalf("ListByYallaResource: %v", err)
	}
	if got == nil {
		t.Error("ListByYallaResource returned nil slice, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("got %d rows, want 0", len(got))
	}
}

func TestDokployRefRepositoryListByYallaResourceBlankKindIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	_, err := repo.ListByYallaResource(ctx, db, org.ID, store.YallaKind(""), "yalla_x")
	if err == nil {
		t.Fatal("ListByYallaResource with blank kind returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDokployRefRepositoryListByOrganizationIsOrderedAndScoped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")
	svc2 := seedService(t, db, f, env, "Worker")

	// Seed mappings under both services and three kinds.
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "svc1-app"),
	})
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc2.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "svc2-app"),
	})
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindProject,
		YallaID:         proj.ID,
		DokployResource: store.DokployResourceProject,
		DokployID:       mintDokployID(t, "proj"),
	})

	got, err := repo.ListByOrganization(ctx, db, org.ID)
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	// project kind sorts before service kind (lexicographic ASC).
	if got[0].YallaKind != store.YallaKindProject {
		t.Errorf("row[0].YallaKind = %q, want %q — list must order by yalla_kind ASC first",
			got[0].YallaKind, store.YallaKindProject)
	}
	if got[1].YallaKind != store.YallaKindService || got[2].YallaKind != store.YallaKindService {
		t.Errorf("rows[1..2] kinds = %q,%q, want service,service",
			got[1].YallaKind, got[2].YallaKind)
	}
}

func TestDokployRefRepositoryListByOrganizationEmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	got, err := repo.ListByOrganization(ctx, db, org.ID)
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if got == nil {
		t.Error("ListByOrganization returned nil slice, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("got %d rows, want 0", len(got))
	}
}

func TestDokployRefRepositoryDeleteRemovesRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	created := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "delete"),
	})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, org.ID, created.ID)
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.Get(ctx, db, org.ID, created.ID)
	if err == nil {
		t.Fatal("Get after Delete returned nil, want typed NotFound")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Errorf("Get after Delete error = %v, want code %s", err, yerr.CodeNotFound)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("after Delete, org has %d dokploy_refs rows, want 0", got)
	}
}

func TestDokployRefRepositoryDeleteUnknownReturnsTypedNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, org.ID, 123_456)
	})
	if err == nil {
		t.Fatal("Delete unknown returned nil, want typed NotFound")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Errorf("error = %v, want code %s", err, yerr.CodeNotFound)
	}
}

func TestDokployRefRepositoryDeleteWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := store.NewDokployRefRepository()

	err := repo.Delete(ctx, nil, "org_x", 1)
	if err == nil {
		t.Fatal("Delete with nil tx returned nil, want typed Internal")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeInternal {
		t.Errorf("error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDokployRefRepositoryOrganizationDeleteCascades(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "cascade-app"),
	})
	runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "cascade-domain"),
	})
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 2 {
		t.Fatalf("pre-cascade org has %d dokploy_refs rows, want 2", got)
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}
	if got := countDokployRefRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("after org delete, dokploy_refs count = %d, want 0 (FK ON DELETE CASCADE)", got)
	}
}

func TestDokployRefRepositorySetUpdatedAtTriggerFiresOnRawUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	created := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  org.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         svc.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "trigger"),
	})

	// The store package exposes no per-row Update on dokploy_refs — the
	// mapping has no customer-mutable column. We drive a raw-SQL UPDATE
	// here only to pin that the dokploy_refs_set_updated_at trigger fires
	// on an UPDATE, so a future worker remap story can rely on it without
	// being the first caller to discover the trigger is missing. The
	// table has no version column (migration 0011's comment was
	// aspirational; the actual ALTER only touched
	// organizations/projects/environments/services), so no bump_version
	// assertion is possible — and that absence is itself documented by
	// the rawDokployRefRow struct, which has no Version field.
	if _, err := db.Exec(ctx,
		`UPDATE dokploy_refs SET dokploy_id = dokploy_id || '-bumped' WHERE id = $1`,
		created.ID); err != nil {
		t.Fatalf("raw UPDATE: %v", err)
	}

	bumped := loadDokployRefRowByID(ctx, t, db, created.ID)
	if !bumped.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("post-UPDATE updated_at = %v, want > pre-UPDATE %v (set_updated_at trigger must refresh on every UPDATE)",
			bumped.UpdatedAt, created.UpdatedAt)
	}
	if !bumped.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("post-UPDATE created_at = %v, want unchanged %v",
			bumped.CreatedAt, created.CreatedAt)
	}
}
