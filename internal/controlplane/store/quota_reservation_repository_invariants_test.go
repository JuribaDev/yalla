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

// Repository-layer CRUD-and-lifecycle invariants for the quota_reservations
// table (BE-0455). quota_reservations holds amounts claimed by an in-flight
// unit of work BEFORE the resource it would create actually exists. An active
// reservation counts against the tenant's effective limit until it is
// committed, released, or expired. The QuotaRepository surface for the table
// is intentionally minimal: InsertReservation mints an active row inside a
// transaction (the same transaction that does the headroom check and the
// desired-state write it guards), and SumActiveReservations reads the live
// in-flight total for the headroom check. There is no per-row Get, Update,
// Commit, Release, or Expire method yet — the worker-side lifecycle lands
// later in the provisioning-jobs PRD and is owned by the future job runner;
// the schema-level lifecycle CHECK (settled_consistent) and the live-row
// concurrent-locking primitive are owned by quota_schema_test.go.
//
// What this file pins, and what it deliberately delegates:
//
//   - InsertReservation row-shape on the first call: a blank-id reservation
//     mints an id carrying the qres_ prefix, a blank Status defaults to
//     'active', JobID/SettledAt stay at the zero value, and the database
//     trigger stamps created_at/updated_at within the same wallclock second.
//     The return value's struct fields are byte-equal to a raw-SQL re-load
//     of the persisted row.
//   - InsertReservation id provenance: an explicit caller-supplied id is
//     preserved verbatim (never replaced by a freshly-minted qres_<token>),
//     and a duplicate-id second call surfaces as typed apierr.Conflict
//     (yerr.CodeConflict) through mapWriteError (the PRIMARY KEY unique
//     violation is the constraint).
//   - InsertReservation JobID round-trip: a non-empty JobID flows through
//     the nullable job_id column and is observable on both the return value
//     and a raw-SQL re-load (a regression that wrote a NULL or a wrong
//     literal would surface on either path).
//   - InsertReservation ExpiresAt round-trip: a caller-chosen expires_at is
//     preserved through the timestamptz column to its microsecond precision
//     (Postgres timestamptz storage). A regression that silently rounded to
//     the second or dropped the timezone would surface here.
//   - Constraint-violation paths surface as typed apierr.Conflict through
//     mapWriteError: unknown organization (FK organizations.id), unknown
//     quota_resource (DOMAIN quota_resource), non-positive amount (CHECK
//     amount > 0), and a deliberately non-'active' status (CHECK
//     quota_reservations_settled_consistent — InsertReservation cannot mint
//     a settled row because it never writes settled_at, so any non-'active'
//     status is structurally inconsistent and the database must reject it).
//   - Peer-row byte-identity: InsertReservation for one (organization,
//     resource) tuple does not touch a sibling reservation row's id,
//     created_at, updated_at, status, amount, or job_id. The schema-level
//     PRIMARY KEY isolates rows by id, and the partial index
//     quota_reservations_active_idx is read-only at INSERT time, so a
//     regression that swept sibling rows would surface here.
//   - Transaction rollback: a closure that returns an error after a
//     successful InsertReservation must leave quota_reservations with no new
//     row for the organization — the INSERT never persists because
//     Store.Write rolls back when the closure errors.
//   - nil-tx guard: InsertReservation called with a nil *Tx returns a typed
//     apierr.Internal (yerr.CodeInternal), not a nil-pointer panic.
//   - SumActiveReservations status filter: rows whose status is anything
//     other than 'active' (committed, released, expired) are excluded from
//     the in-flight sum even when they have not yet passed their expires_at.
//   - SumActiveReservations time filter: rows whose expires_at is at or
//     before the caller-supplied 'now' are excluded — a crashed worker that
//     never reached commit cannot strand quota past its expiry.
//   - SumActiveReservations resource filter: rows for the same tenant but a
//     different resource dimension are excluded — the SQL WHERE clause has
//     BOTH organization_id and resource predicates, and a regression that
//     summed across resources would surface here.
//   - SumActiveReservations empty-tenant: a tenant with no reservation rows
//     for the resource returns 0, not an error (COALESCE(SUM(amount), 0)).
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - The quota_resource DOMAIN closed set, the settled_consistent CHECK as
//     a raw-SQL schema invariant, and the cascade-delete on organizations
//     are owned by quota_schema_test.go (TestQuotaReservationLifecycleConstraints,
//     TestQuotaCascadeDeleteOnOrganization, TestQuotaResourceDomainEnforcesClosedSet).
//   - SumActiveReservations cross-tenant isolation (orgA's reservations
//     invisible to orgB's sum) is the BE-0456 sibling story and lives in
//     quota_reservation_tenant_isolation_test.go.
//   - The concurrent SELECT FOR UPDATE row-lock primitive on a single
//     reservation row is owned by quota_schema_test.go
//     (TestQuotaReservationConcurrentRowLock).
//   - The bare happy-path InsertReservation-mints-id-and-persists scenario
//     is covered by quota_repository_test.go
//     (TestQuotaRepositoryInsertReservationMintsIDAndPersists); this file
//     adds the row-shape, prefix, timestamp-bound, and round-trip
//     invariants the bare scenario does not assert.

// rawQuotaReservationRow is the full quota_reservations row, deliberately
// loaded via raw SQL so the test can observe id, created_at, updated_at, and
// the nullable job_id/settled_at columns through the same shape the database
// stores them in. It is the same template rawQuotaUsageRow uses for
// quota_usage in BE-0453 and rawQuotaPolicyRow uses for quota_policies in
// BE-0451.
type rawQuotaReservationRow struct {
	ID             string
	OrganizationID string
	Resource       string
	Amount         int64
	Status         string
	JobID          *string
	ExpiresAt      time.Time
	SettledAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// loadQuotaReservationRowByID reads the raw quota_reservations row for id and
// fatals on error. The lookup is by primary key — distinct reservation rows
// have distinct ids — so no resource scope is needed.
func loadQuotaReservationRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawQuotaReservationRow {
	t.Helper()
	var row rawQuotaReservationRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, resource, amount, status, job_id, expires_at, settled_at, created_at, updated_at
		   FROM quota_reservations
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.Resource, &row.Amount, &row.Status,
		&row.JobID, &row.ExpiresAt, &row.SettledAt, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load quota_reservations id=%q: %v", id, err)
	}
	return row
}

// countQuotaReservationRowsForOrg returns the number of quota_reservations
// rows owned by organizationID. It is the "did the rollback leave a row
// behind?" probe.
func countQuotaReservationRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_reservations WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count quota_reservations for org %q: %v", organizationID, err)
	}
	return n
}

// runInsertReservationOrFail wraps InsertReservation in a Store.Write closure
// and fatals on error, returning the persisted reservation. It is the
// smallest possible happy-path closure and is reused by every test that does
// not need to observe the call's tx in isolation.
func runInsertReservationOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	res store.QuotaReservation,
) store.QuotaReservation {
	t.Helper()
	var created store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, iErr := repo.InsertReservation(ctx, tx, res)
		if iErr != nil {
			return iErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("InsertReservation(%+v): %v", res, err)
	}
	return created
}

// quotaReservationTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback. The type name is intentionally distinct
// from every other rollback sentinel in store_test (every *_test.go file
// under internal/controlplane/store/ shares the same package) — collisions
// would block compilation. Existing siblings include
// quota_policy_repository_invariants_test.go's quotaPolicyTxRollbackSentinel
// and quota_usage_repository_invariants_test.go's quotaUsageTxRollbackSentinel.
type quotaReservationTxRollbackSentinel struct{}

func (quotaReservationTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this quota reservation transaction"
}

func TestQuotaRepositoryInsertReservationMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	expires := time.Now().Add(30 * time.Minute)

	created := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         3,
		ExpiresAt:      expires,
	})

	if len(created.ID) < len("qres_") || created.ID[:len("qres_")] != "qres_" {
		t.Errorf("created.ID = %q, want qres_<token> prefix (newQuotaID(\"qres\") must own the minted id)", created.ID)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.Resource != store.QuotaResourceServices {
		t.Errorf("created.Resource = %q, want %q", created.Resource, store.QuotaResourceServices)
	}
	if created.Amount != 3 {
		t.Errorf("created.Amount = %d, want 3", created.Amount)
	}
	if created.Status != store.ReservationStatusActive {
		t.Errorf("created.Status = %q, want %q (blank Status must default to active)", created.Status, store.ReservationStatusActive)
	}
	if created.JobID != "" {
		t.Errorf("created.JobID = %q, want empty (no JobID was supplied; the nullable column must scan back as the zero value)", created.JobID)
	}
	if !created.SettledAt.IsZero() {
		t.Errorf("created.SettledAt = %v, want zero (an active reservation must carry NULL settled_at; the nullable column must scan back as the zero time)", created.SettledAt)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps zero on insert: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}
	if delta := created.UpdatedAt.Sub(created.CreatedAt); delta < 0 || delta > time.Second {
		t.Errorf("updated_at - created_at = %v on insert, want within 1s", delta)
	}

	// The returned struct must match a raw-SQL re-load byte-for-byte across
	// every observable column — the only way to prove the RETURNING clause
	// and scanQuotaReservation agree with the persisted row.
	row := loadQuotaReservationRowByID(ctx, t, db, created.ID)
	if row.OrganizationID != created.OrganizationID {
		t.Errorf("row.OrganizationID = %q, want %q", row.OrganizationID, created.OrganizationID)
	}
	if row.Resource != string(created.Resource) {
		t.Errorf("row.Resource = %q, want %q", row.Resource, created.Resource)
	}
	if row.Amount != created.Amount {
		t.Errorf("row.Amount = %d, want %d", row.Amount, created.Amount)
	}
	if row.Status != created.Status {
		t.Errorf("row.Status = %q, want %q", row.Status, created.Status)
	}
	if row.JobID != nil {
		t.Errorf("row.JobID = %q, want NULL (no JobID was supplied)", *row.JobID)
	}
	if row.SettledAt != nil {
		t.Errorf("row.SettledAt = %v, want NULL (an active reservation must carry NULL settled_at)", *row.SettledAt)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v (RETURNING vs re-load disagree)", row.CreatedAt, created.CreatedAt)
	}
	if !row.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("row.UpdatedAt = %v, want %v (RETURNING vs re-load disagree)", row.UpdatedAt, created.UpdatedAt)
	}

	if n := countQuotaReservationRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("quota_reservations rows for org = %d, want exactly 1", n)
	}
}

func TestQuotaRepositoryInsertReservationPreservesExplicitID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	const explicitID = "qres_explicit_test_id"

	created := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		ID:             explicitID,
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         1,
		ExpiresAt:      time.Now().Add(time.Hour),
	})

	if created.ID != explicitID {
		t.Errorf("created.ID = %q, want %q (a non-empty caller id must be preserved, not replaced by newQuotaID)", created.ID, explicitID)
	}

	row := loadQuotaReservationRowByID(ctx, t, db, explicitID)
	if row.ID != explicitID {
		t.Errorf("persisted id = %q, want %q", row.ID, explicitID)
	}
}

func TestQuotaRepositoryInsertReservationDuplicateIDReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	const explicitID = "qres_duplicate_test_id"

	runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		ID:             explicitID,
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         1,
		ExpiresAt:      time.Now().Add(time.Hour),
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			ID:             explicitID,
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(duplicate id) error = %v, want code %s (PRIMARY KEY unique violation must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationRoundtripsJobID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	const jobID = "pjob_provisioning_job_id"

	// Migration 0008 added a composite FK (organization_id, job_id) ->
	// provisioning_jobs (organization_id, id) so a reservation can never name
	// another tenant's job. To test the JobID round-trip through the
	// nullable column we must first seed a real provisioning_jobs row in
	// the same tenant; otherwise the InsertReservation INSERT trips the
	// FK and surfaces as Conflict, not as a JobID-roundtrip pass.
	if _, err := db.Exec(ctx,
		`INSERT INTO provisioning_jobs (id, organization_id, job_type, idempotency_key)
		 VALUES ($1, $2, 'noop', $3)`,
		jobID, org.ID, "idem_"+jobID); err != nil {
		t.Fatalf("seed provisioning_jobs row: %v", err)
	}

	created := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         1,
		JobID:          jobID,
		ExpiresAt:      time.Now().Add(time.Hour),
	})

	if created.JobID != jobID {
		t.Errorf("created.JobID = %q, want %q (a non-empty JobID must round-trip through the nullable job_id column)", created.JobID, jobID)
	}

	row := loadQuotaReservationRowByID(ctx, t, db, created.ID)
	if row.JobID == nil {
		t.Fatal("row.JobID = NULL, want a persisted job id (the nullable column must store the supplied JobID, not NULL)")
	}
	if *row.JobID != jobID {
		t.Errorf("row.JobID = %q, want %q (the persisted column must equal the supplied JobID)", *row.JobID, jobID)
	}
}

func TestQuotaRepositoryInsertReservationRoundtripsExpiresAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	// A non-aligned expires_at with sub-second precision proves the
	// timestamptz column preserves microsecond-resolution timestamps. A
	// regression that rounded to the second or dropped the timezone would
	// surface here. Postgres timestamptz storage is microsecond precision,
	// so any nanoseconds finer than a microsecond are expected to truncate;
	// the test uses microsecond resolution to stay inside that contract.
	expires := time.Date(2099, 1, 2, 3, 4, 5, 678901000, time.UTC)

	created := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         1,
		ExpiresAt:      expires,
	})

	if !created.ExpiresAt.Equal(expires) {
		t.Errorf("created.ExpiresAt = %v, want %v (RETURNING expires_at must match the supplied value)", created.ExpiresAt, expires)
	}

	row := loadQuotaReservationRowByID(ctx, t, db, created.ID)
	if !row.ExpiresAt.Equal(expires) {
		t.Errorf("persisted expires_at = %v, want %v (timestamptz column must preserve microsecond precision)", row.ExpiresAt, expires)
	}
}

func TestQuotaRepositoryInsertReservationUnknownOrganizationReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: "org_does_not_exist",
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(unknown org) error = %v, want code %s (FK organizations.id must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationInvalidResourceReturnsConflict(t *testing.T) {
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
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResource("not-a-resource"),
			Amount:         1,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(invalid resource) error = %v, want code %s (DOMAIN quota_resource must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationZeroAmountReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	// The schema-level CHECK is `amount > 0`; the Go type accepts zero and
	// negative values, so the database is the only line of defense and a
	// CHECK violation must surface as apierr.Conflict through mapWriteError.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         0,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(amount=0) error = %v, want code %s (CHECK amount > 0 must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationNegativeAmountReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         -1,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(amount=-1) error = %v, want code %s (CHECK amount > 0 must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationNonActiveStatusReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	// InsertReservation never writes settled_at — the INSERT column list is
	// (id, organization_id, resource, amount, status, job_id, expires_at).
	// So passing a non-blank, non-'active' status produces an inconsistent
	// row by construction: status<>'active' AND settled_at IS NULL violates
	// quota_reservations_settled_consistent. The CHECK is the database's
	// guarantee that this repository surface can only mint ACTIVE rows; a
	// regression that silently coerced a settled row through it would
	// surface here as a pass instead of a Conflict.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			Status:         store.ReservationStatusCommitted,
			ExpiresAt:      time.Now().Add(time.Hour),
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("InsertReservation(status=committed) error = %v, want code %s (settled_consistent CHECK must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryInsertReservationPeerRowIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	first := runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceProjects,
		Amount:         2,
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	peerBaseline := loadQuotaReservationRowByID(ctx, t, db, first.ID)

	// Wallclock gap so an accidental cross-row trigger on the peer would
	// necessarily advance its updated_at (set_updated_at fires BEFORE
	// UPDATE; INSERT-only paths must not touch a sibling row at all).
	time.Sleep(time.Millisecond)

	runInsertReservationOrFail(ctx, t, s, repo, store.QuotaReservation{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		Amount:         5,
		ExpiresAt:      time.Now().Add(time.Hour),
	})

	peerAfter := loadQuotaReservationRowByID(ctx, t, db, first.ID)
	if peerAfter.ID != peerBaseline.ID {
		t.Errorf("peer id drifted: was %q, now %q", peerBaseline.ID, peerAfter.ID)
	}
	if peerAfter.Resource != peerBaseline.Resource {
		t.Errorf("peer resource drifted: was %q, now %q", peerBaseline.Resource, peerAfter.Resource)
	}
	if peerAfter.Amount != peerBaseline.Amount {
		t.Errorf("peer amount drifted: was %d, now %d", peerBaseline.Amount, peerAfter.Amount)
	}
	if peerAfter.Status != peerBaseline.Status {
		t.Errorf("peer status drifted: was %q, now %q", peerBaseline.Status, peerAfter.Status)
	}
	if !peerAfter.CreatedAt.Equal(peerBaseline.CreatedAt) {
		t.Errorf("peer created_at drifted: was %v, now %v", peerBaseline.CreatedAt, peerAfter.CreatedAt)
	}
	if !peerAfter.UpdatedAt.Equal(peerBaseline.UpdatedAt) {
		t.Errorf("peer updated_at drifted: was %v, now %v (set_updated_at trigger fired on a non-UPDATE)", peerBaseline.UpdatedAt, peerAfter.UpdatedAt)
	}
	if peerAfter.OrganizationID != peerBaseline.OrganizationID {
		t.Errorf("peer organization_id drifted: was %q, now %q", peerBaseline.OrganizationID, peerAfter.OrganizationID)
	}
	if (peerAfter.JobID == nil) != (peerBaseline.JobID == nil) {
		t.Errorf("peer job_id nullness drifted")
	}
	if (peerAfter.SettledAt == nil) != (peerBaseline.SettledAt == nil) {
		t.Errorf("peer settled_at nullness drifted")
	}

	if n := countQuotaReservationRowsForOrg(ctx, t, db, org.ID); n != 2 {
		t.Errorf("quota_reservations rows for org = %d, want exactly 2 (one per InsertReservation call)", n)
	}
}

func TestQuotaRepositoryInsertReservationRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	bailout := quotaReservationTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, iErr := repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      time.Now().Add(time.Hour),
		}); iErr != nil {
			return iErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}
	if !errors.Is(err, bailout) {
		t.Fatalf("Write returned %v, want sentinel %v (closure error must propagate unchanged)", err, bailout)
	}

	// The repository INSERT must not have persisted: no quota_reservations
	// row for this org survives the rollback.
	if n := countQuotaReservationRowsForOrg(ctx, t, db, org.ID); n != 0 {
		t.Errorf("quota_reservations rows for org after rollback = %d, want 0 (the InsertReservation INSERT must roll back with the transaction)", n)
	}
}

func TestQuotaRepositoryInsertReservationWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()

	_, err := repo.InsertReservation(context.Background(), nil, store.QuotaReservation{
		OrganizationID: "org_irrelevant",
		Resource:       store.QuotaResourceServices,
		Amount:         1,
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("InsertReservation(nil tx) error = %v, want code %s (a missing transaction is a wiring error, not a client input error)", err, yerr.CodeInternal)
	}
}

func TestQuotaRepositorySumActiveReservationsReturnsZeroForEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	var sum int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, rErr := repo.SumActiveReservations(ctx, q, org.ID, store.QuotaResourceServices, time.Now())
		if rErr != nil {
			return rErr
		}
		sum = got
		return nil
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sum != 0 {
		t.Errorf("SumActiveReservations on fresh tenant = %d, want 0 (COALESCE(SUM(amount), 0) must coerce the empty-row case to zero, not an error)", sum)
	}
}

func TestQuotaRepositorySumActiveReservationsExcludesNonActiveStatuses(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	expires := time.Now().Add(time.Hour)

	// Seed one active row that the sum MUST count, and three settled rows
	// (committed/released/expired) that the WHERE clause MUST exclude. The
	// schema CHECK quota_reservations_settled_consistent requires the
	// settled rows to carry settled_at, so insertSettledReservationRow stamps
	// it via now().
	insertReservationRow(t, db, "qres_active_only", org.ID, "services", 4,
		store.ReservationStatusActive, expires)
	insertSettledReservationRow(t, db, "qres_committed_skip", org.ID, "services", 100,
		store.ReservationStatusCommitted, expires)
	insertSettledReservationRow(t, db, "qres_released_skip", org.ID, "services", 100,
		store.ReservationStatusReleased, expires)
	insertSettledReservationRow(t, db, "qres_expired_skip", org.ID, "services", 100,
		store.ReservationStatusExpired, expires)

	var sum int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, rErr := repo.SumActiveReservations(ctx, q, org.ID, store.QuotaResourceServices, time.Now())
		if rErr != nil {
			return rErr
		}
		sum = got
		return nil
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sum != 4 {
		t.Errorf("SumActiveReservations = %d, want 4 (only the single active row counts; committed/released/expired must be excluded by the status = 'active' predicate)", sum)
	}
}

func TestQuotaRepositorySumActiveReservationsExcludesExpiredByTime(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	// One row that has not yet expired and MUST be counted; one row whose
	// expires_at is still 'active' in status but already in the past, which
	// the WHERE expires_at > now predicate MUST exclude — a crashed worker
	// that never reached commit cannot strand quota past its expiry.
	now := time.Now()
	insertReservationRow(t, db, "qres_live", org.ID, "services", 7,
		store.ReservationStatusActive, now.Add(time.Hour))
	insertReservationRow(t, db, "qres_expired_by_time", org.ID, "services", 100,
		store.ReservationStatusActive, now.Add(-time.Hour))

	var sum int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, rErr := repo.SumActiveReservations(ctx, q, org.ID, store.QuotaResourceServices, now)
		if rErr != nil {
			return rErr
		}
		sum = got
		return nil
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sum != 7 {
		t.Errorf("SumActiveReservations = %d, want 7 (only the unexpired active row counts; rows where expires_at <= now must be excluded by the expires_at > now predicate)", sum)
	}
}

func TestQuotaRepositorySumActiveReservationsIsResourceScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	expires := time.Now().Add(time.Hour)

	// Two active reservations for the SAME tenant but DIFFERENT resources.
	// SumActiveReservations(org, services, now) must return only the
	// services row's amount; the projects row must be excluded by the
	// resource = $2 predicate. A regression that summed across resources
	// would return 11 instead of 3.
	insertReservationRow(t, db, "qres_services_3", org.ID, "services", 3,
		store.ReservationStatusActive, expires)
	insertReservationRow(t, db, "qres_projects_8", org.ID, "projects", 8,
		store.ReservationStatusActive, expires)

	var (
		sumServices int64
		sumProjects int64
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, rErr := repo.SumActiveReservations(ctx, q, org.ID, store.QuotaResourceServices, time.Now())
		if rErr != nil {
			return rErr
		}
		sumServices = got
		got, rErr = repo.SumActiveReservations(ctx, q, org.ID, store.QuotaResourceProjects, time.Now())
		if rErr != nil {
			return rErr
		}
		sumProjects = got
		return nil
	}); err != nil {
		t.Fatalf("SumActiveReservations: %v", err)
	}
	if sumServices != 3 {
		t.Errorf("SumActiveReservations(services) = %d, want 3 (the resource predicate must exclude the projects row)", sumServices)
	}
	if sumProjects != 8 {
		t.Errorf("SumActiveReservations(projects) = %d, want 8 (the resource predicate must exclude the services row)", sumProjects)
	}
}
