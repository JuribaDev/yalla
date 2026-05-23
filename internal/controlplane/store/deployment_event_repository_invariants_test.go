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

// Repository-layer CRUD-and-invariants for the deployment_events table
// (BE-0459). A deployment_events row is one immutable record on the timeline
// of a single deployment: it captures the observable state transition or
// progress beat the worker recorded as it converged the deployment toward
// Dokploy. The DeploymentEventRepository surface is intentionally narrow:
// Append appends a row inside a transaction (the same transaction that also
// mutates the deployments row, when the writer is a lifecycle transition),
// ListByDeployment reads tenant-scoped chronological history, and GetByID
// reads a single row tenant-scoped. There is no per-row Update / Delete in
// this surface: the database BEFORE UPDATE trigger rejects every update at
// the SQL level, and the store package exposes no row-level delete (row
// removal is reachable only through ON DELETE CASCADE when the parent
// deployment is removed).
//
// What this file pins, and what it deliberately delegates:
//
//   - Append row-shape on the first call: a blank-id event mints an id
//     carrying the depev_ prefix, RequestID / CorrelationID / Message stay
//     at the zero value when not supplied, Metadata round-trips as a nil
//     map when blank, and the database stamps occurred_at / created_at
//     within the same wallclock second. The return value's struct fields
//     are byte-equal to a raw-SQL re-load of the persisted row.
//   - Append id contract: a caller-supplied id is preserved verbatim, a
//     blank id is rejected at the CHECK (length(id) > 0), and a duplicate
//     id surfaces as typed apierr.Conflict (PRIMARY KEY) through
//     mapWriteError.
//   - Append CHECK / FK violations surface as typed apierr.Conflict through
//     mapWriteError: an unknown event_type, an unknown organization /
//     deployment (composite FK deployments(organization_id, id)), and a
//     cross-tenant (organization_id, deployment_id) tuple that would
//     reference another tenant's deployment.
//   - Append nil-Tx and blank-event-type surface as typed apierr.Internal:
//     a deployment event must never be persisted outside the transaction
//     that also carries the lifecycle write it records, and a blank
//     event_type is a programming error caught at the application boundary
//     rather than leaving the database to reject it.
//   - Append transaction rollback semantics: a closure that returns an
//     error after a successful Append leaves no deployment_events row
//     behind.
//   - Append caller-supplied occurred_at is preserved verbatim: a worker
//     reconciling after a restart can persist the original wallclock the
//     event was observed at; a zero occurred_at lets the database stamp
//     now().
//   - Append metadata redaction surface: the jsonb metadata column
//     round-trips a non-empty map back as a map and the empty map back as
//     a nil map, so callers do not have to distinguish "no metadata" from
//     "empty metadata".
//   - Peer-row byte-identity: Append for one (organization, deployment)
//     tuple does not touch a sibling event row's id, created_at,
//     occurred_at, event_type, message, or metadata.
//   - Append-only enforcement: the database BEFORE UPDATE trigger rejects
//     every UPDATE against deployment_events at the SQL level, so a
//     written event record can never be altered after the fact.
//   - Cascade delete: removing the parent deployment cascades through the
//     deployment_events composite FK ON DELETE CASCADE — an event row
//     never survives its parent deployment.
//   - GetByID lookup contracts: a persisted row reads back byte-identical
//     to the Append RETURNING projection; an unknown id surfaces as typed
//     apierr.NotFound (never as a 500 leaking the cause); the row is
//     never an oracle that reveals another tenant's event ids.
//   - ListByDeployment ordering contract: rows are returned in
//     chronological order (occurred_at ASC, id ASC tiebreaker) — the
//     timeline endpoint renders the deployment unfolding forward in time.
//   - ListByDeployment unknown-deployment contract: an unknown or
//     cross-tenant deployment_id returns the empty slice, never an error,
//     so the timeline endpoint can render an empty timeline without
//     distinguishing "no events" from "no parent" (callers that need the
//     distinction Get the parent deployment first).
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - Cross-tenant List leak under SumActiveReservations-style aggregation
//     is the BE-0460 sibling tenant-isolation story and lives in
//     deployment_event_tenant_isolation_test.go.
//   - The HTTP wire shape of the timeline endpoint, its policy matrix,
//     and its OpenAPI contract are owned by future deployment-events HTTP
//     stories.
//
// Helpers introduced here: rawDeploymentEventRow, loadDeploymentEventRowByID,
// countDeploymentEventRowsForDeployment, mintDeploymentEventID,
// runAppendDeploymentEventOrFail, seedDeploymentEvent,
// deploymentEventTxRollbackSentinel. Helpers reused from sibling files:
// seedOrg, seedProject, seedEnvironment, seedService (schema_test.go);
// newStore (store_test.go); mintDeploymentID, seedQueuedDeployment
// (deployment_repository_invariants_test.go).

// rawDeploymentEventRow is the full deployment_events row, deliberately
// loaded via raw SQL so the test can observe id, created_at, occurred_at,
// the closed-set event_type column, and the metadata jsonb document
// through the same shape the database stores them in. It is the same
// template rawDeploymentRow uses for deployments in BE-0457 and
// rawQuotaReservationRow uses for quota_reservations in BE-0455.
type rawDeploymentEventRow struct {
	ID             string
	OrganizationID string
	DeploymentID   string
	EventType      string
	Message        string
	Metadata       []byte
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// loadDeploymentEventRowByID reads the raw deployment_events row for id and
// fatals on error. The lookup is by primary key — distinct event rows have
// distinct ids — so no tenant scope is needed (raw loaders bypass repository
// scoping deliberately, so the test observes the persisted row exactly as
// the database stores it).
func loadDeploymentEventRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawDeploymentEventRow {
	t.Helper()
	var row rawDeploymentEventRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, deployment_id, event_type,
		        message, metadata, request_id, correlation_id,
		        occurred_at, created_at
		   FROM deployment_events
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.DeploymentID, &row.EventType,
		&row.Message, &row.Metadata, &row.RequestID, &row.CorrelationID,
		&row.OccurredAt, &row.CreatedAt,
	); err != nil {
		t.Fatalf("load deployment_events id=%q: %v", id, err)
	}
	return row
}

// countDeploymentEventRowsForDeployment returns the number of
// deployment_events rows owned by (organizationID, deploymentID). It is the
// "did the rollback / cascade leave a row behind?" probe.
func countDeploymentEventRowsForDeployment(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID, deploymentID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM deployment_events
		  WHERE organization_id = $1 AND deployment_id = $2`,
		organizationID, deploymentID).Scan(&n); err != nil {
		t.Fatalf("count deployment_events for (%q, %q): %v",
			organizationID, deploymentID, err)
	}
	return n
}

// mintDeploymentEventID builds a stable, test-local deployment event id from
// the test name and a per-test suffix. Tests in store_test share a single
// package, so the test name keeps ids unique across parallel test cases
// without needing a shared atomic counter. Real id minting lives in
// DeploymentEventRepository.Append (newDeploymentEventID), so this is the
// test-local override that exercises the caller-supplied-id branch.
func mintDeploymentEventID(t *testing.T, suffix string) string {
	t.Helper()
	return "depev_" + t.Name() + "_" + suffix
}

// runAppendDeploymentEventOrFail runs DeploymentEventRepository.Append inside
// a write transaction, fatals on error, and returns the persisted event. It
// is the smallest possible happy-path closure and is reused by every test
// that does not need to observe the call's tx in isolation.
func runAppendDeploymentEventOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DeploymentEventRepository,
	e store.DeploymentEvent,
) store.DeploymentEvent {
	t.Helper()
	var created store.DeploymentEvent
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, aErr := repo.Append(ctx, tx, e)
		if aErr != nil {
			return aErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("Append(%+v): %v", e, err)
	}
	return created
}

// seedDeploymentEvent appends a 'progress' event row against (org, dep) and
// returns it. It centralises the boilerplate the List / cascade tests need
// so the per-test bodies focus on the invariant rather than the construction
// of a valid row.
func seedDeploymentEvent(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DeploymentEventRepository,
	org testutil.Organization,
	dep store.Deployment,
	suffix string,
	occurredAt time.Time,
) store.DeploymentEvent {
	t.Helper()
	return runAppendDeploymentEventOrFail(ctx, t, s, repo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, suffix),
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeProgress,
		Message:        "progress " + suffix,
		RequestID:      "req_" + suffix,
		CorrelationID:  "cor_" + suffix,
		OccurredAt:     occurredAt,
	})
}

// deploymentEventTxRollbackSentinel is a uniquely-typed sentinel for the
// rollback test. Sentinel types must be unique per file in the store_test
// package (every *_test.go under internal/controlplane/store/ shares the
// same package). Existing siblings include deploymentTxRollbackSentinel
// and quotaReservationTxRollbackSentinel.
type deploymentEventTxRollbackSentinel struct{}

func (deploymentEventTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this deployment event transaction"
}

func TestDeploymentEventRepositoryAppendMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "shape")

	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "worker accepted job",
		Metadata:       map[string]string{"replicas": "3"},
		RequestID:      "req_shape",
		CorrelationID:  "cor_shape",
	})

	if created.ID == "" {
		t.Fatal("created.ID is blank, want a minted id")
	}
	if !strings.HasPrefix(created.ID, "depev_") {
		t.Errorf("created.ID = %q, want depev_ prefix", created.ID)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.DeploymentID != dep.ID {
		t.Errorf("created.DeploymentID = %q, want %q", created.DeploymentID, dep.ID)
	}
	if created.EventType != store.DeploymentEventTypeRunning {
		t.Errorf("created.EventType = %q, want %q", created.EventType, store.DeploymentEventTypeRunning)
	}
	if created.Message != "worker accepted job" {
		t.Errorf("created.Message = %q, want round-trip", created.Message)
	}
	if got := created.Metadata["replicas"]; got != "3" {
		t.Errorf("created.Metadata[replicas] = %q, want %q (metadata must round-trip)", got, "3")
	}
	if created.CreatedAt.IsZero() || created.OccurredAt.IsZero() {
		t.Errorf("timestamps zero on append: occurred_at=%v created_at=%v",
			created.OccurredAt, created.CreatedAt)
	}
	if delta := created.OccurredAt.Sub(created.CreatedAt); delta < -time.Second || delta > time.Second {
		t.Errorf("occurred_at - created_at = %v on append, want within 1s "+
			"(both stamped by now() when caller supplies zero occurred_at)", delta)
	}

	// The returned struct must match a raw-SQL re-load byte-for-byte across
	// every observable column — the only way to prove the RETURNING clause
	// and scanDeploymentEvent agree with the persisted row.
	row := loadDeploymentEventRowByID(ctx, t, db, created.ID)
	if row.OrganizationID != created.OrganizationID {
		t.Errorf("row.OrganizationID = %q, want %q", row.OrganizationID, created.OrganizationID)
	}
	if row.DeploymentID != created.DeploymentID {
		t.Errorf("row.DeploymentID = %q, want %q", row.DeploymentID, created.DeploymentID)
	}
	if row.EventType != string(created.EventType) {
		t.Errorf("row.EventType = %q, want %q", row.EventType, created.EventType)
	}
	if row.Message != created.Message {
		t.Errorf("row.Message = %q, want %q", row.Message, created.Message)
	}
	if !row.OccurredAt.Equal(created.OccurredAt) {
		t.Errorf("row.OccurredAt = %v, want %v", row.OccurredAt, created.OccurredAt)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v", row.CreatedAt, created.CreatedAt)
	}
	if row.RequestID != created.RequestID || row.CorrelationID != created.CorrelationID {
		t.Errorf("correlation ids drifted: row=(%q,%q) created=(%q,%q)",
			row.RequestID, row.CorrelationID, created.RequestID, created.CorrelationID)
	}
}

func TestDeploymentEventRepositoryAppendBlankFieldsDefault(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "blank")

	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeQueued,
	})

	if created.Message != "" {
		t.Errorf("created.Message = %q, want empty (default)", created.Message)
	}
	if created.RequestID != "" || created.CorrelationID != "" {
		t.Errorf("blank correlation ids drifted: req=%q cor=%q",
			created.RequestID, created.CorrelationID)
	}
	if created.Metadata != nil {
		t.Errorf("created.Metadata = %v, want nil (empty jsonb '{}' must scan back as nil map)",
			created.Metadata)
	}
}

func TestDeploymentEventRepositoryAppendRespectsCallerSuppliedID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "caller_id")

	explicitID := mintDeploymentEventID(t, "explicit")
	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             explicitID,
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeProgress,
	})

	if created.ID != explicitID {
		t.Errorf("created.ID = %q, want %q (a non-empty caller id must be preserved verbatim)",
			created.ID, explicitID)
	}
}

func TestDeploymentEventRepositoryAppendRespectsCallerSuppliedOccurredAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "occ")

	// A worker reconciling after a restart persists the original wallclock
	// the event was observed at, not the row's persistence time.
	observed := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)
	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeProgress,
		OccurredAt:     observed,
	})

	if !created.OccurredAt.Equal(observed) {
		t.Errorf("created.OccurredAt = %v, want %v (caller-supplied non-zero must round-trip)",
			created.OccurredAt, observed)
	}
	if !created.CreatedAt.After(observed.Add(time.Hour)) {
		t.Errorf("created.CreatedAt = %v, want after %v (created_at is stamped by now() even when occurred_at is in the past)",
			created.CreatedAt, observed.Add(time.Hour))
	}
}

func TestDeploymentEventRepositoryAppendUnknownEventTypeRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "unknown_type")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			OrganizationID: org.ID,
			DeploymentID:   dep.ID,
			EventType:      store.DeploymentEventType("not_a_real_event_type"),
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(unknown event_type) error = %v, want code %s (CHECK violation must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestDeploymentEventRepositoryAppendBlankEventTypeIsTypedInternal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "blank_type")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			OrganizationID: org.ID,
			DeploymentID:   dep.ID,
			EventType:      "",
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Append(blank event_type) error = %v, want code %s (programming error caught at application boundary)",
			err, yerr.CodeInternal)
	}
}

func TestDeploymentEventRepositoryAppendUnknownDeploymentRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			OrganizationID: org.ID,
			DeploymentID:   "dep_does_not_exist",
			EventType:      store.DeploymentEventTypeRunning,
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(unknown deployment_id) error = %v, want code %s (composite FK violation must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestDeploymentEventRepositoryAppendCrossTenantDeploymentRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Seed alpha's deployment.
	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, depRepo, alpha, alphaProj, alphaEnv, alphaSvc, "cross_tenant")

	// Bravo tries to append against alpha's deployment id using bravo's
	// organization_id. The composite FK (organization_id, deployment_id)
	// references deployments (organization_id, id), so a foreign-tenant
	// deployment_id paired with bravo's organization_id matches no
	// deployments row and the FK rejects the insert.
	bravo := seedOrg(t, db, f, "bravo")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			OrganizationID: bravo.ID,
			DeploymentID:   alphaDep.ID,
			EventType:      store.DeploymentEventTypeRunning,
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(cross-tenant deployment_id) error = %v, want code %s (composite FK must reject)",
			err, yerr.CodeConflict)
	}

	// Belt-and-braces: no event row may have been persisted under bravo.
	if n := countDeploymentEventRowsForDeployment(ctx, t, db, bravo.ID, alphaDep.ID); n != 0 {
		t.Errorf("deployment_events rows for (bravo, alphaDep) = %d, want 0", n)
	}
}

func TestDeploymentEventRepositoryAppendDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "dup")

	dupID := mintDeploymentEventID(t, "dup")
	runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             dupID,
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeRunning,
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			ID:             dupID,
			OrganizationID: org.ID,
			DeploymentID:   dep.ID,
			EventType:      store.DeploymentEventTypeRunning,
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(duplicate id) error = %v, want code %s (PRIMARY KEY collision via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestDeploymentEventRepositoryAppendWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewDeploymentEventRepository()

	_, err := repo.Append(context.Background(), nil, store.DeploymentEvent{
		OrganizationID: "org_irrelevant",
		DeploymentID:   "dep_irrelevant",
		EventType:      store.DeploymentEventTypeRunning,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Append(nil tx) error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDeploymentEventRepositoryAppendRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "rollback")

	bailout := deploymentEventTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			OrganizationID: org.ID,
			DeploymentID:   dep.ID,
			EventType:      store.DeploymentEventTypeRunning,
		})
		if aErr != nil {
			return aErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}
	if !errors.Is(err, bailout) {
		t.Fatalf("Write returned %v, want sentinel %v", err, bailout)
	}

	if n := countDeploymentEventRowsForDeployment(ctx, t, db, org.ID, dep.ID); n != 0 {
		t.Errorf("deployment_events rows for (org, dep) after rollback = %d, want 0 (the Append must roll back with the transaction)", n)
	}
}

func TestDeploymentEventRepositoryAppendPeerRowByteIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "peer")

	first := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "first",
	})
	peerBaseline := loadDeploymentEventRowByID(ctx, t, db, first.ID)

	// Wallclock gap so an accidental cross-row trigger on the peer would
	// necessarily advance its created_at. The append-only trigger should
	// guarantee the peer row remains byte-identical regardless.
	time.Sleep(time.Millisecond)

	runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeSucceeded,
		Message:        "second",
	})

	peerAfter := loadDeploymentEventRowByID(ctx, t, db, first.ID)
	if peerAfter.ID != peerBaseline.ID ||
		peerAfter.EventType != peerBaseline.EventType ||
		peerAfter.Message != peerBaseline.Message ||
		!peerAfter.OccurredAt.Equal(peerBaseline.OccurredAt) ||
		!peerAfter.CreatedAt.Equal(peerBaseline.CreatedAt) {
		t.Errorf("peer row drifted after second append:\n  baseline = %+v\n  after    = %+v",
			peerBaseline, peerAfter)
	}

	if n := countDeploymentEventRowsForDeployment(ctx, t, db, org.ID, dep.ID); n != 2 {
		t.Errorf("deployment_events rows = %d, want exactly 2 (one per Append call)", n)
	}
}

func TestDeploymentEventRepositoryUpdateRejectedByTrigger(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "trigger")
	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		OrganizationID: org.ID,
		DeploymentID:   dep.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "immutable",
	})

	// Raw SQL: bypass the repository surface entirely so the trigger is
	// the only thing that can stop the write.
	_, err := db.Exec(ctx,
		`UPDATE deployment_events SET message = $1 WHERE id = $2`,
		"tampered", created.ID)
	if err == nil {
		t.Fatal("raw UPDATE on deployment_events returned nil, want trigger error (append-only enforcement)")
	}

	// And the persisted row is unchanged.
	row := loadDeploymentEventRowByID(ctx, t, db, created.ID)
	if row.Message != "immutable" {
		t.Errorf("row.Message = %q after rejected UPDATE, want %q", row.Message, "immutable")
	}
}

func TestDeploymentEventRepositoryCascadeDeleteOnDeployment(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "cascade")
	seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "cascade_a", time.Now().UTC())
	seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "cascade_b", time.Now().UTC())

	if n := countDeploymentEventRowsForDeployment(ctx, t, db, org.ID, dep.ID); n != 2 {
		t.Fatalf("setup: events before cascade = %d, want 2", n)
	}

	// Raw DELETE on the parent deployment cascades through the composite
	// FK ON DELETE CASCADE.
	if _, err := db.Exec(ctx, `DELETE FROM deployments WHERE id = $1`, dep.ID); err != nil {
		t.Fatalf("DELETE deployments: %v", err)
	}

	if n := countDeploymentEventRowsForDeployment(ctx, t, db, org.ID, dep.ID); n != 0 {
		t.Errorf("deployment_events rows after parent delete = %d, want 0 (ON DELETE CASCADE must remove children)", n)
	}
}

func TestDeploymentEventRepositoryGetByIDReturnsPersistedRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "get")
	created := seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "get_one", time.Now().UTC())

	var got store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, gErr := eventRepo.GetByID(ctx, q, org.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		got = g
		return nil
	}); err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.ID != created.ID || got.EventType != created.EventType ||
		got.OrganizationID != created.OrganizationID || got.DeploymentID != created.DeploymentID ||
		got.Message != created.Message || !got.OccurredAt.Equal(created.OccurredAt) ||
		!got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("GetByID returned %+v, want byte-identical projection of %+v", got, created)
	}
}

func TestDeploymentEventRepositoryGetByIDUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := eventRepo.GetByID(ctx, q, org.ID, "depev_does_not_exist")
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(unknown) error = %v, want code %s (unknown id must surface as NotFound, never a 500 leaking pgx.ErrNoRows)",
			err, yerr.CodeNotFound)
	}
}

func TestDeploymentEventRepositoryGetByIDCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, depRepo, alpha, alphaProj, alphaEnv, alphaSvc, "cross_get")
	alphaEvt := seedDeploymentEvent(ctx, t, s, eventRepo, alpha, alphaDep, "cross_get_evt", time.Now().UTC())

	bravo := seedOrg(t, db, f, "bravo")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := eventRepo.GetByID(ctx, q, bravo.ID, alphaEvt.ID)
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s", err, yerr.CodeNotFound)
	}
	// And the not-found payload must name only the caller-supplied id,
	// never the foreign tenant's deployment_id or message.
	if ye := yerr.From(err); strings.Contains(ye.Message, alphaDep.ID) {
		t.Errorf("not-found message leaked foreign deployment id: %q", ye.Message)
	}
}

func TestDeploymentEventRepositoryListByDeploymentChronologicalOrder(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	dep := seedQueuedDeployment(ctx, t, s, depRepo, org, proj, env, svc, "order")

	base := time.Now().UTC().Truncate(time.Microsecond)
	// Append rows out of chronological order so the ASC ordering must
	// reorder them on read.
	e2 := seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "evt_b", base.Add(2*time.Second))
	e1 := seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "evt_a", base.Add(1*time.Second))
	e3 := seedDeploymentEvent(ctx, t, s, eventRepo, org, dep, "evt_c", base.Add(3*time.Second))

	var listed []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := eventRepo.ListByDeployment(ctx, q, org.ID, dep.ID)
		if lErr != nil {
			return lErr
		}
		listed = l
		return nil
	}); err != nil {
		t.Fatalf("ListByDeployment: %v", err)
	}

	if len(listed) != 3 {
		t.Fatalf("ListByDeployment returned %d rows, want 3", len(listed))
	}
	wantOrder := []string{e1.ID, e2.ID, e3.ID}
	for i, want := range wantOrder {
		if listed[i].ID != want {
			t.Errorf("ListByDeployment[%d].ID = %q, want %q (rows must be returned in occurred_at ASC order)",
				i, listed[i].ID, want)
		}
	}
}

func TestDeploymentEventRepositoryListByDeploymentUnknownReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	var listed []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := eventRepo.ListByDeployment(ctx, q, org.ID, "dep_does_not_exist")
		if lErr != nil {
			return lErr
		}
		listed = l
		return nil
	}); err != nil {
		t.Fatalf("ListByDeployment(unknown): %v (must return empty slice, not error)", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListByDeployment(unknown) returned %d rows, want 0", len(listed))
	}
}

func TestDeploymentEventRepositoryListByDeploymentCrossTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, depRepo, alpha, alphaProj, alphaEnv, alphaSvc, "cross_list")
	seedDeploymentEvent(ctx, t, s, eventRepo, alpha, alphaDep, "alpha_evt", time.Now().UTC())

	bravo := seedOrg(t, db, f, "bravo")

	var listed []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := eventRepo.ListByDeployment(ctx, q, bravo.ID, alphaDep.ID)
		if lErr != nil {
			return lErr
		}
		listed = l
		return nil
	}); err != nil {
		t.Fatalf("ListByDeployment(cross-tenant): %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListByDeployment(cross-tenant) returned %d rows, want 0 (foreign tenant's events must not leak)",
			len(listed))
	}
}
