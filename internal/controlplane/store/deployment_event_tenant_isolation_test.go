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

// Repository-layer tenant-isolation tests for the deployment_events table
// (BE-0460). deployment_events is an APPEND-ONLY timeline: a single row is
// one immutable record of the worker-observed lifecycle transition or
// progress beat that produced a deployment's current converged status.
// The row's tenant anchor is two-deep:
//
//	(a) the organization_id column itself (persisted directly so every
//	    customer-facing read can be tenant-scoped by a simple WHERE
//	    organization_id = $1 predicate); and
//	(b) the composite foreign key (organization_id, deployment_id)
//	    references deployments(organization_id, id) ON DELETE CASCADE,
//	    so an event row can never sit under a foreign tenant's
//	    deployment AND a deployment teardown cascades through its
//	    event history.
//
// The DeploymentEventRepository surface is intentionally narrow:
// Append appends a row inside a *Tx, GetByID reads a single row
// tenant-scoped, and ListByDeployment reads the chronological history
// of one parent deployment tenant-scoped. There is no per-row Update /
// Delete: the database BEFORE UPDATE trigger rejects every UPDATE at
// the SQL level (so Append is the ONLY mutation surface), and the
// store package exposes no row-level delete (row removal is reachable
// only through ON DELETE CASCADE when the parent deployment — or
// transitively the organization — is removed).
//
// This file pins the cross-tenant invariants of every one of those
// surfaces and of the two cascade depths (parent deployment, parent
// organization):
//
//   - Append(orgA, alphaDep) cross-tenant bystander byte-identity:
//     when orgB already owns several deployment_events rows under
//     orgB's deployment (deliberately overlapping-looking — same
//     event_types, same message/metadata/request_id/correlation_id
//     shapes), an Append on orgA's deployment lands as a fresh row
//     owned by orgA and leaves every observable column on every orgB
//     event row byte-identical to its baseline. The append-only BEFORE
//     UPDATE trigger is a load-bearing anchor: a regression that
//     widened the predicate by deployment_id alone (or by event_type
//     alone) and swept an orgB row through a phantom UPDATE would be
//     rejected at the database, NOT silently applied — so the
//     bystander byte-identity assertion here is really proving that
//     Append never even attempts a write outside the supplied
//     (organization_id, deployment_id) tuple.
//   - Append(orgA, alphaDep) row-count invariant: orgB's per-tenant
//     event count is unchanged and orgA's per-deployment event count
//     grows by exactly +1.
//   - Append cross-tenant parent-deployment rejection AND bystander
//     byte-identity: when orgA tries to Append an event whose
//     deployment_id belongs to orgB (a forged cross-tenant write),
//     the composite FK rejects the INSERT as typed apierr.Conflict
//     AND leaves every orgB event row byte-identical AND inserts no
//     row under orgA. The reverse direction (orgB tries to Append
//     against alphaDep.ID) is symmetrically rejected. This is the
//     load-bearing positive-direction pair for the cross-tenant
//     foreign-key guard: without it, a regression that derived
//     organization_id from the deployment row at write time (instead
//     of trusting the caller-supplied organization_id leg) could
//     mint an event under the WRONG tenant and the bystander
//     byte-identity test would not catch it because the new row
//     would be a fresh INSERT, not a sweep-update.
//   - GetByID(orgB, alphaEvent.ID) cross-tenant: returns typed
//     apierr.NotFound AND the not-found payload echoes ONLY the
//     supplied event id — never the foreign tenant's
//     message / metadata / request_id / correlation_id / event_type
//     / deployment_id. The apierr.NotFound("deployment_event",
//     eventID) call site is the chokepoint.
//   - ListByDeployment(orgB, alphaDep.ID) cross-tenant: returns the
//     empty slice AND the per-tenant event count for orgB is
//     unchanged AND the per-deployment event count for alphaDep is
//     unchanged. The acceptance criterion "List queries return stable
//     pagination without leaking total counts from other tenants"
//     requires asserting BOTH the empty slice AND that the foreign
//     tenant's row counts do not move — a read must not leak into a
//     write.
//   - ListByDeployment(orgA, bravoDep.ID) — same-tenant org with a
//     foreign-tenant deployment_id — returns empty: the composite
//     predicate (organization_id, deployment_id) matches no row
//     even when the caller supplies its own org. A regression that
//     resolved by deployment_id alone would surface here.
//   - Parent-deployment delete cascade is tenant-scoped: deleting
//     alphaDep cascades through its event history (alpha events
//     gone) AND leaves every bravo event row byte-identical. The
//     deployment_events composite FK ON DELETE CASCADE is the
//     anchor; a regression that wired the FK to ON DELETE NO ACTION
//     and let a manual cleanup path widen the predicate would
//     surface here as either an orgB row vanishing or a column
//     drifting.
//   - Organization delete cascade is tenant-scoped: deleting orgA
//     cascades the full hierarchy (organizations -> deployments ->
//     deployment_events) and leaves every orgB event row
//     byte-identical. This proves the transitive cascade does not
//     bleed across the organization_id leg.
//
// What this file deliberately delegates:
//
//   - The single-tenant Append CRUD/invariants (mints id with
//     depev_ prefix, blank-EventType -> typed Internal, unknown
//     event_type -> Conflict, append-only trigger, GetByID
//     not-found shape, ListByDeployment chronological order) are
//     covered by deployment_event_repository_invariants_test.go
//     (BE-0459) and are not re-asserted here.
//   - Soft-deleted rows are intentionally not covered: the
//     deployment_events table has no soft-delete column and no
//     Delete repository surface (rows leave the table only through
//     CASCADE when their parent deployment / organization is
//     removed). The acceptance-criteria phrase "soft-deleted rows
//     where applicable" therefore narrows to "where applicable",
//     and the cascade variants below are the analogous proof.
//   - The HTTP wire shape of the deployment timeline endpoint, its
//     policy matrix, and its OpenAPI contract are owned by future
//     deployment-events HTTP stories.
//
// Helpers introduced here: assertDeploymentEventByteIdentical,
// twoTenantDeploymentEventFixture, seedTwoTenantDeploymentEventFixture,
// countDeploymentEventRowsForOrg. Helpers reused from BE-0459:
// rawDeploymentEventRow, loadDeploymentEventRowByID,
// countDeploymentEventRowsForDeployment, mintDeploymentEventID,
// runAppendDeploymentEventOrFail, seedDeploymentEvent; from BE-0458:
// seedTwoTenantDeploymentFixture; from BE-0457: seedQueuedDeployment;
// from store_test helpers package-wide: seedOrg, seedProject,
// seedEnvironment, seedService, containsValue, newStore.

// assertDeploymentEventByteIdentical fails the test if any observable
// column on after diverges from baseline. The metadata column is jsonb
// stored as []byte; bytes.Equal is the exact-comparison primitive
// (json.RawMessage normalization would mask a regression that stripped
// or reordered keys at write time).
func assertDeploymentEventByteIdentical(t *testing.T, label string, baseline, after rawDeploymentEventRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.DeploymentID != baseline.DeploymentID {
		t.Errorf("%s: bystander.deployment_id = %q, want %q",
			label, after.DeploymentID, baseline.DeploymentID)
	}
	if after.EventType != baseline.EventType {
		t.Errorf("%s: bystander.event_type = %q, want %q",
			label, after.EventType, baseline.EventType)
	}
	if after.Message != baseline.Message {
		t.Errorf("%s: bystander.message = %q, want %q",
			label, after.Message, baseline.Message)
	}
	if !bytes.Equal(after.Metadata, baseline.Metadata) {
		t.Errorf("%s: bystander.metadata = %s, want %s",
			label, string(after.Metadata), string(baseline.Metadata))
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: bystander.request_id = %q, want %q",
			label, after.RequestID, baseline.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: bystander.correlation_id = %q, want %q",
			label, after.CorrelationID, baseline.CorrelationID)
	}
	if !after.OccurredAt.Equal(baseline.OccurredAt) {
		t.Errorf("%s: bystander.occurred_at = %v, want %v",
			label, after.OccurredAt, baseline.OccurredAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v — a written event was either re-inserted or silently rewritten",
			label, after.CreatedAt, baseline.CreatedAt)
	}
}

// twoTenantDeploymentEventFixture extends seedTwoTenantDeploymentFixture
// with one parent deployment per tenant, so the per-test bodies can focus
// on the event-level invariant rather than the boilerplate of minting two
// full hierarchies + deployments. depA is owned by (orgA, projA, envA,
// svcA); depB by (orgB, projB, envB, svcB).
type twoTenantDeploymentEventFixture struct {
	base twoTenantDeploymentFixture
	depA store.Deployment
	depB store.Deployment
}

// seedTwoTenantDeploymentEventFixture builds the fixture above. The
// deployments are seeded as 'queued' (the cheapest valid lifecycle
// state); the BE-0460 invariants do not care about the parent
// deployment's status, only that it exists as a tenant-scoped FK
// target.
func seedTwoTenantDeploymentEventFixture(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
	s *store.Store,
	depRepo *store.DeploymentRepository,
) twoTenantDeploymentEventFixture {
	t.Helper()
	base := seedTwoTenantDeploymentFixture(t, db, f)
	depA := seedQueuedDeployment(ctx, t, s, depRepo, base.orgA, base.projA, base.envA, base.svcA, "parent_alpha")
	depB := seedQueuedDeployment(ctx, t, s, depRepo, base.orgB, base.projB, base.envB, base.svcB, "parent_bravo")
	return twoTenantDeploymentEventFixture{base: base, depA: depA, depB: depB}
}

// countDeploymentEventRowsForOrg returns the number of deployment_events
// rows owned by organizationID across every deployment under that
// tenant. It is the cascade-scoped variant of
// countDeploymentEventRowsForDeployment: cascade tests need to assert
// the foreign tenant's WHOLE event surface is unchanged after a delete,
// not just one deployment's worth.
func countDeploymentEventRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM deployment_events WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count deployment_events for org %q: %v", organizationID, err)
	}
	return n
}

// TestDeploymentEventRepositoryAppendOnOrgADoesNotTouchOrgBEvents proves
// the load-bearing cross-tenant invariant of Append: when orgB owns
// several deployment_events rows under bravoDep — a 'queued', a 'running',
// and a 'progress' row with deliberately overlapping-looking message /
// metadata / request_id / correlation_id shapes — an Append on alphaDep
// lands as a fresh row owned by orgA and leaves every observable column
// on every orgB event row byte-identical to its baseline. The
// append-only BEFORE UPDATE trigger guarantees the database would
// reject any phantom cross-row UPDATE; this test is therefore really
// proving that Append's INSERT statement never even attempts a write
// outside the supplied (organization_id, deployment_id) tuple.
func TestDeploymentEventRepositoryAppendOnOrgADoesNotTouchOrgBEvents(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	// orgB owns three overlapping-looking peer events under bravoDep.
	// Distinct event_types (queued, running, progress) cover every
	// non-terminal taxon a cross-row regression could widen by;
	// per-event suffixes ("peer_queued", "peer_running",
	// "peer_progress") make a column rewrite immediately visible.
	bravoOccurred := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	bravoQueued := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "peer_queued"),
		OrganizationID: fix.base.orgB.ID,
		DeploymentID:   fix.depB.ID,
		EventType:      store.DeploymentEventTypeQueued,
		Message:        "queued by worker peer_queued",
		Metadata:       map[string]string{"slot": "peer_queued"},
		RequestID:      "req_peer_queued",
		CorrelationID:  "cor_peer_queued",
		OccurredAt:     bravoOccurred,
	})
	bravoRunning := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "peer_running"),
		OrganizationID: fix.base.orgB.ID,
		DeploymentID:   fix.depB.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "running peer_running",
		Metadata:       map[string]string{"slot": "peer_running"},
		RequestID:      "req_peer_running",
		CorrelationID:  "cor_peer_running",
		OccurredAt:     bravoOccurred.Add(time.Second),
	})
	bravoProgress := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "peer_progress"),
		OrganizationID: fix.base.orgB.ID,
		DeploymentID:   fix.depB.ID,
		EventType:      store.DeploymentEventTypeProgress,
		Message:        "progress peer_progress",
		Metadata:       map[string]string{"slot": "peer_progress"},
		RequestID:      "req_peer_progress",
		CorrelationID:  "cor_peer_progress",
		OccurredAt:     bravoOccurred.Add(2 * time.Second),
	})

	baselineQueued := loadDeploymentEventRowByID(ctx, t, db, bravoQueued.ID)
	baselineRunning := loadDeploymentEventRowByID(ctx, t, db, bravoRunning.ID)
	baselineProgress := loadDeploymentEventRowByID(ctx, t, db, bravoProgress.ID)

	// Wallclock gap so an accidental cross-row write would advance
	// the bystander's created_at. The append-only trigger should keep
	// every bystander byte-identical regardless.
	time.Sleep(time.Millisecond)

	created := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "alpha"),
		OrganizationID: fix.base.orgA.ID,
		DeploymentID:   fix.depA.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "running peer_running", // deliberately same message body as bravoRunning
		Metadata:       map[string]string{"slot": "peer_running"},
		RequestID:      "req_peer_running",
		CorrelationID:  "cor_peer_running",
	})
	if created.OrganizationID != fix.base.orgA.ID {
		t.Fatalf("Append lifted organization_id = %q, want %q (orgA's Append was attributed to the wrong tenant)",
			created.OrganizationID, fix.base.orgA.ID)
	}
	if created.DeploymentID != fix.depA.ID {
		t.Fatalf("Append lifted deployment_id = %q, want %q (orgA's Append was attributed to orgB's deployment)",
			created.DeploymentID, fix.depA.ID)
	}
	if created.ID == bravoQueued.ID || created.ID == bravoRunning.ID || created.ID == bravoProgress.ID {
		t.Fatalf("Append returned an orgB event id %q — INSERT collided with an existing row instead of minting a fresh row for orgA", created.ID)
	}

	afterQueued := loadDeploymentEventRowByID(ctx, t, db, bravoQueued.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB queued event bystander after orgA Append",
		baselineQueued, afterQueued)

	afterRunning := loadDeploymentEventRowByID(ctx, t, db, bravoRunning.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB running event bystander after orgA Append",
		baselineRunning, afterRunning)

	afterProgress := loadDeploymentEventRowByID(ctx, t, db, bravoProgress.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB progress event bystander after orgA Append",
		baselineProgress, afterProgress)
}

// TestDeploymentEventRepositoryAppendOnOrgADoesNotChangeOrgBRowCount
// proves the per-tenant event count is invariant under another tenant's
// Append. orgB owns two event rows before orgA makes any call; orgA
// then Appends one row under its own deployment. orgB's count must
// remain at 2 — neither lower (an accidental cross-tenant DELETE) nor
// higher (an accidental cross-tenant INSERT). orgA's per-deployment
// count goes from 0 to 1. This complements the byte-identity bystander
// proof above: a regression that silently dropped one orgB row and
// minted a new one with the same content would defeat the byte-identity
// test but trip here.
func TestDeploymentEventRepositoryAppendOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "count_a",
		time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "count_b",
		time.Date(2025, 1, 1, 12, 0, 1, 0, time.UTC))

	baselineCountB := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID)
	if baselineCountB != 2 {
		t.Fatalf("baseline orgB event count = %d, want 2 — test fixture is invalid", baselineCountB)
	}
	baselineCountA := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID)
	if baselineCountA != 0 {
		t.Fatalf("baseline orgA event count = %d, want 0 — test fixture is invalid", baselineCountA)
	}

	runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "alpha"),
		OrganizationID: fix.base.orgA.ID,
		DeploymentID:   fix.depA.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "running",
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
	})

	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID); n != baselineCountB {
		t.Errorf("orgB event count after orgA Append = %d, want %d (orgA's Append leaked into orgB's count)",
			n, baselineCountB)
	}
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID); n != 1 {
		t.Errorf("orgA event count after Append = %d, want 1", n)
	}
	if n := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgB.ID, fix.depB.ID); n != 2 {
		t.Errorf("orgB depB event count = %d, want 2", n)
	}
	if n := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgA.ID, fix.depA.ID); n != 1 {
		t.Errorf("orgA depA event count = %d, want 1", n)
	}
}

// TestDeploymentEventRepositoryAppendForeignParentDeploymentRejectedAndLeavesBystanders
// proves the cross-tenant Append guard: when a caller tries to Append
// an event whose (organization_id, deployment_id) tuple points at a
// deployment owned by another tenant, the composite FK
// deployment_events_organization_id_deployment_id_fkey rejects the
// INSERT as typed apierr.Conflict AND no row is inserted under either
// tenant AND every existing orgB event row is left byte-identical.
// This is the load-bearing positive-direction pair for the FK guard:
// without it, a regression that derived organization_id from the
// deployment row at write time (instead of trusting the
// caller-supplied organization_id leg) could mint an event under the
// WRONG tenant — and a pure bystander-byte-identity test would not
// catch a fresh INSERT into a foreign tenant.
func TestDeploymentEventRepositoryAppendForeignParentDeploymentRejectedAndLeavesBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	// Seed two orgB events as the load-bearing bystanders. A
	// regression that resolved by deployment_id alone could either
	// touch one of these rows (sweep-update) OR mint a fresh row
	// for orgB owned by orgA's caller (sweep-insert); the byte-identity
	// + count assertions below catch both.
	bravoBaselineOccurred := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	bravoFirst := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "guard_first", bravoBaselineOccurred)
	bravoSecond := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "guard_second", bravoBaselineOccurred.Add(time.Second))

	baselineFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	baselineSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)
	baselineOrgBCount := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID)
	baselineOrgACount := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID)

	// Direction 1: orgA's caller forges a write at orgA's deployment
	// id but using orgB's caller hand: (organization_id=orgA,
	// deployment_id=bravoDep) — the (orgA, bravoDep) tuple is not in
	// deployments (bravoDep is owned by orgB), so the composite FK
	// must reject. The forged id is recognisable so the test can prove
	// no row was inserted.
	forgedAlphaID := mintDeploymentEventID(t, "forged_alpha_to_bravo")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			ID:             forgedAlphaID,
			OrganizationID: fix.base.orgA.ID,
			DeploymentID:   fix.depB.ID,
			EventType:      store.DeploymentEventTypeRunning,
			Message:        "forged",
			RequestID:      "req_forged",
			CorrelationID:  "cor_forged",
		})
		return aErr
	})
	if err == nil {
		t.Fatal("Append(orgA, bravoDep) returned nil error, want apierr.Conflict (the composite FK must reject a cross-tenant parent deployment)")
	}
	ye := yerr.From(err)
	if ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(orgA, bravoDep) code = %s, want %s (cross-tenant parent FK violation must surface as Conflict)",
			ye.Code, yerr.CodeConflict)
	}

	// Direction 2: orgB's caller forges a write at orgB's
	// organization_id but with alphaDep's deployment_id — symmetrical
	// rejection. The forged id is again recognisable.
	forgedBravoID := mintDeploymentEventID(t, "forged_bravo_to_alpha")
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := eventRepo.Append(ctx, tx, store.DeploymentEvent{
			ID:             forgedBravoID,
			OrganizationID: fix.base.orgB.ID,
			DeploymentID:   fix.depA.ID,
			EventType:      store.DeploymentEventTypeRunning,
			Message:        "forged",
			RequestID:      "req_forged",
			CorrelationID:  "cor_forged",
		})
		return aErr
	})
	if err == nil {
		t.Fatal("Append(orgB, alphaDep) returned nil error, want apierr.Conflict (the composite FK must reject a cross-tenant parent deployment)")
	}
	ye = yerr.From(err)
	if ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(orgB, alphaDep) code = %s, want %s (cross-tenant parent FK violation must surface as Conflict)",
			ye.Code, yerr.CodeConflict)
	}

	// Neither forged row may exist anywhere in deployment_events.
	for _, id := range []string{forgedAlphaID, forgedBravoID} {
		var seen int
		if qErr := db.QueryRow(ctx,
			`SELECT count(*) FROM deployment_events WHERE id = $1`, id).Scan(&seen); qErr != nil {
			t.Fatalf("count by id %q: %v", id, qErr)
		}
		if seen != 0 {
			t.Errorf("forged event id %q persisted %d row(s), want 0 — the FK rejection did not prevent the INSERT", id, seen)
		}
	}

	// Bystander byte-identity AND row-count invariants.
	afterFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB first event after cross-tenant Append rejection",
		baselineFirst, afterFirst)
	afterSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB second event after cross-tenant Append rejection",
		baselineSecond, afterSecond)
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID); n != baselineOrgBCount {
		t.Errorf("orgB event count after cross-tenant Append rejection = %d, want %d", n, baselineOrgBCount)
	}
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID); n != baselineOrgACount {
		t.Errorf("orgA event count after cross-tenant Append rejection = %d, want %d", n, baselineOrgACount)
	}
}

// TestDeploymentEventRepositoryGetByIDCrossTenantReturnsNotFoundAndDoesNotEcho
// proves GetByID(orgB, alphaEvent.ID) surfaces typed apierr.NotFound
// AND the not-found payload echoes ONLY the supplied event id — never
// the foreign tenant's message, metadata key/value, request_id,
// correlation_id, event_type, or deployment_id. The
// apierr.NotFound("deployment_event", eventID) call site is the
// chokepoint; any echo of a foreign-tenant column in a not-found
// payload would be a confused-deputy oracle.
func TestDeploymentEventRepositoryGetByIDCrossTenantReturnsNotFoundAndDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	// alpha owns one event with deliberately distinctive
	// message / metadata / request_id / correlation_id suffixes. If a
	// regression echoed any of them into the not-found payload, the
	// substring checks below would trip.
	alphaEvent := runAppendDeploymentEventOrFail(ctx, t, s, eventRepo, store.DeploymentEvent{
		ID:             mintDeploymentEventID(t, "alpha"),
		OrganizationID: fix.base.orgA.ID,
		DeploymentID:   fix.depA.ID,
		EventType:      store.DeploymentEventTypeRunning,
		Message:        "no_echo_distinctive_alpha_message_payload",
		Metadata:       map[string]string{"no_echo_distinctive_alpha_metakey": "no_echo_distinctive_alpha_metaval"},
		RequestID:      "req_no_echo_distinctive_alpha",
		CorrelationID:  "cor_no_echo_distinctive_alpha",
	})

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := eventRepo.GetByID(ctx, q, fix.base.orgB.ID, alphaEvent.ID)
		return gErr
	})
	ye := yerr.From(err)
	if ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s (a cross-tenant event id must surface as NotFound, never a successful read of another tenant's row)",
			err, yerr.CodeNotFound)
	}

	msg := err.Error()
	for _, leak := range []string{
		"no_echo_distinctive_alpha_message_payload",
		"no_echo_distinctive_alpha_metakey",
		"no_echo_distinctive_alpha_metaval",
		"req_no_echo_distinctive_alpha",
		"cor_no_echo_distinctive_alpha",
		fix.depA.ID,
		string(store.DeploymentEventTypeRunning),
	} {
		if containsValue(msg, leak) {
			t.Errorf("GetByID(cross-tenant) error message %q echoed foreign-tenant value %q — the not-found payload must name only the supplied event_id",
				msg, leak)
		}
	}
}

// TestDeploymentEventRepositoryListByDeploymentCrossTenantReturnsEmptyAndDoesNotLeakTotal
// proves ListByDeployment(orgB, alphaDep.ID) returns the empty slice
// AND that the read does not side-effect either tenant's event count.
// The acceptance criterion "List queries return stable pagination
// without leaking total counts from other tenants" requires asserting
// BOTH the empty slice AND that the foreign tenant's per-org and
// per-deployment counts are unchanged — a read must not leak into a
// write.
func TestDeploymentEventRepositoryListByDeploymentCrossTenantReturnsEmptyAndDoesNotLeakTotal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	alphaOccurred := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "list_a_first", alphaOccurred)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "list_a_second", alphaOccurred.Add(time.Second))
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "list_a_third", alphaOccurred.Add(2*time.Second))

	baselineAlphaCount := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID)
	if baselineAlphaCount != 3 {
		t.Fatalf("baseline orgA event count = %d, want 3 — test fixture is invalid", baselineAlphaCount)
	}
	baselineBravoCount := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID)
	if baselineBravoCount != 0 {
		t.Fatalf("baseline orgB event count = %d, want 0 — test fixture is invalid", baselineBravoCount)
	}
	baselineAlphaPerDep := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgA.ID, fix.depA.ID)
	if baselineAlphaPerDep != 3 {
		t.Fatalf("baseline orgA depA event count = %d, want 3 — test fixture is invalid", baselineAlphaPerDep)
	}

	var list []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := eventRepo.ListByDeployment(ctx, q, fix.base.orgB.ID, fix.depA.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByDeployment(orgB, alphaDep) error = %v, want nil (a cross-tenant tuple must match no rows, never error)", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByDeployment(orgB, alphaDep) returned %d rows, want 0 (alpha's events leaked through bravo's predicate)", len(list))
	}

	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID); n != baselineAlphaCount {
		t.Errorf("orgA event count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineAlphaCount)
	}
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID); n != baselineBravoCount {
		t.Errorf("orgB event count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineBravoCount)
	}
	if n := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgA.ID, fix.depA.ID); n != baselineAlphaPerDep {
		t.Errorf("orgA depA event count after cross-tenant List = %d, want %d (per-deployment count drifted)", n, baselineAlphaPerDep)
	}
}

// TestDeploymentEventRepositoryListByDeploymentForeignDeploymentIDOfSameTenantReturnsEmpty
// proves ListByDeployment is scoped by the COMPOSITE (organization_id,
// deployment_id) — passing a deployment_id that exists in another
// tenant MUST NOT return that tenant's events even though the
// organization_id supplied is the caller's own. A regression that
// resolved by deployment_id alone would surface here.
func TestDeploymentEventRepositoryListByDeploymentForeignDeploymentIDOfSameTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	// Seed events under each tenant's OWN deployment.
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "self_alpha",
		time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "self_bravo",
		time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))

	// orgA passes its own organization_id but bravoDep's deployment_id
	// — the composite predicate matches no rows, so the response must
	// be empty.
	var list []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := eventRepo.ListByDeployment(ctx, q, fix.base.orgA.ID, fix.depB.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByDeployment(orgA, bravoDep): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByDeployment(orgA, bravoDep) returned %d rows, want 0 (a foreign-tenant deployment_id must not surface its events via the caller's own org)",
			len(list))
	}
}

// TestDeploymentEventDeploymentDeleteCascadeOnOrgAIsTenantScoped
// proves that deleting alphaDep cascades through alphaDep's event
// history (alpha events gone) AND leaves every bravo event row
// byte-identical. The deployment_events composite FK ON DELETE CASCADE
// confines the cleanup to the deleted deployment's events; a
// regression that wired the FK to ON DELETE NO ACTION and let a
// manual cleanup path widen the predicate would surface here as
// either an orgB row vanishing or a column drifting.
func TestDeploymentEventDeploymentDeleteCascadeOnOrgAIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	// alpha owns two events to be cascaded away. bravo owns three
	// events with overlapping-looking shapes that must survive
	// byte-identically.
	occurred := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "cascade_alpha_first", occurred)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "cascade_alpha_second", occurred.Add(time.Second))

	bravoFirst := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "cascade_bravo_first", occurred)
	bravoSecond := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "cascade_bravo_second", occurred.Add(time.Second))
	bravoThird := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "cascade_bravo_third", occurred.Add(2*time.Second))

	baselineFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	baselineSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)
	baselineThird := loadDeploymentEventRowByID(ctx, t, db, bravoThird.ID)

	// Deleting alphaDep cascades through its deployment_events via
	// the composite FK ON DELETE CASCADE; bravoDep's events are
	// anchored by a different (organization_id, deployment_id) tuple
	// and must remain untouched.
	if _, err := db.Exec(ctx,
		`DELETE FROM deployments WHERE organization_id = $1 AND id = $2`,
		fix.base.orgA.ID, fix.depA.ID); err != nil {
		t.Fatalf("delete alphaDep: %v", err)
	}

	if n := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgA.ID, fix.depA.ID); n != 0 {
		t.Errorf("deployment_events for alphaDep after delete = %d, want 0 (cascade must remove the deleted deployment's events)", n)
	}
	if n := countDeploymentEventRowsForDeployment(ctx, t, db, fix.base.orgB.ID, fix.depB.ID); n != 3 {
		t.Errorf("deployment_events for bravoDep after alphaDep delete = %d, want 3 — the cascade bled into another tenant", n)
	}
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID); n != 3 {
		t.Errorf("orgB total event count after alphaDep delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	afterFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB first event bystander survives alphaDep delete",
		baselineFirst, afterFirst)
	afterSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB second event bystander survives alphaDep delete",
		baselineSecond, afterSecond)
	afterThird := loadDeploymentEventRowByID(ctx, t, db, bravoThird.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB third event bystander survives alphaDep delete",
		baselineThird, afterThird)
}

// TestDeploymentEventOrganizationDeleteCascadeIsTenantScoped proves
// orgA's deletion cascades the transitive hierarchy (organizations ->
// deployments -> deployment_events) and leaves every orgB event row
// byte-identical. The deployments_organization_id_fkey CASCADE on
// organizations(id) plus the deployment_events composite FK CASCADE
// confine the cleanup to the deleted tenant; a regression that
// dropped the organization_id leg of either FK would surface here as
// either an orgB row vanishing or a column drifting.
func TestDeploymentEventOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	depRepo := store.NewDeploymentRepository()
	eventRepo := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentEventFixture(ctx, t, db, f, s, depRepo)

	occurred := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "org_cascade_alpha_first", occurred)
	seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgA, fix.depA, "org_cascade_alpha_second", occurred.Add(time.Second))

	bravoFirst := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "org_cascade_bravo_first", occurred)
	bravoSecond := seedDeploymentEvent(ctx, t, s, eventRepo, fix.base.orgB, fix.depB, "org_cascade_bravo_second", occurred.Add(time.Second))

	baselineFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	baselineSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)

	// Deleting orgA cascades through the full hierarchy: projects,
	// environments, services, deployments and deployment_events are
	// all anchored by composite FKs descending from organizations(id).
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.base.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgA.ID); n != 0 {
		t.Errorf("deployment_events for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's events)", n)
	}
	if n := countDeploymentEventRowsForOrg(ctx, t, db, fix.base.orgB.ID); n != 2 {
		t.Errorf("deployment_events for orgB after orgA delete = %d, want 2 — the cascade bled into another tenant", n)
	}

	afterFirst := loadDeploymentEventRowByID(ctx, t, db, bravoFirst.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB first event bystander survives orgA delete",
		baselineFirst, afterFirst)
	afterSecond := loadDeploymentEventRowByID(ctx, t, db, bravoSecond.ID)
	assertDeploymentEventByteIdentical(t,
		"orgB second event bystander survives orgA delete",
		baselineSecond, afterSecond)
}
