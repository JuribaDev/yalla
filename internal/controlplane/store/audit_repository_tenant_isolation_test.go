package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the audit_events table
// (BE-0468). audit_events is Yalla's immutable authorization-decision log.
// A row that belongs to one tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id) — the only parent FK
//	    audit_events carries;
//	(b) every AuditRepository write/read going through the
//	    organization_id column: Append is tenant-attributed by the input
//	    AuditEvent.OrganizationID; ListByOrganization filters rows by
//	    the organization_id predicate before any ordering or limit
//	    clause runs.
//
// The AuditRepository surface this file exercises against the
// cross-tenant boundary is deliberately the NARROWEST in the store
// package — Append (write) and ListByOrganization (read). There is no
// GetByID, no Update, and no Delete on audit_events (see the
// AuditRepository file header and audit_repository_invariants_test.go
// file header — the append-only lifecycle is a load-bearing public
// contract, enforced both at the application layer via the missing
// methods AND at the database layer via the BEFORE UPDATE trigger that
// rejects every UPDATE). Row removal is reachable only through
// organizations ON DELETE CASCADE on tenant teardown, which is the
// final cross-tenant cascade probe in this file.
//
// This file pins the cross-tenant gap-fill probes the audit_events
// invariants test file (audit_repository_invariants_test.go) explicitly
// delegates here:
//
//   - Append(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns several audit_events rows (across both decision
//     verdicts, with and without an actor, varying actions and
//     resources) an Append on orgA mints a fresh row owned by orgA and
//     leaves every observable column on every orgB row byte-identical
//     to its baseline. A foreign-tenant UPDATE that snuck past the
//     organization_id predicate (or a phantom mutation that bypassed
//     the database BEFORE UPDATE trigger) would surface here as a
//     column rewrite or an occurred_at/created_at drift on any
//     bystander. The corollary per-tenant count probe is in the
//     immediate sibling test.
//   - Append(orgA) per-tenant row-count invariant: orgB's per-org count
//     and orgA's per-org count change as expected (+1 for the writer,
//     unchanged for the bystander) — neither lower (an accidental
//     cross-tenant DELETE — impossible on this table by surface but
//     still pinned because a future regression could add one) nor
//     higher (an accidental cross-tenant INSERT routed under the wrong
//     organization_id) on the bystander.
//   - Append(orgB, id already owned by orgA) is the cross-tenant mirror
//     of the PRIMARY KEY Conflict pinned in
//     audit_repository_invariants_test.go's
//     TestAuditRepositoryAppendDuplicateIDIsConflict: a typed
//     apierr.Conflict surfaces, orgA's pre-existing row is
//     byte-identical after the rejection, and the per-tenant count for
//     orgB stays at 0 while the per-tenant count for orgA stays at 1.
//     The audit_events PRIMARY KEY (id) is global (there is no
//     UNIQUE(organization_id, id) — id is sufficient by itself because
//     newAuditID mints a 128-bit-entropy opaque token), so the
//     cross-tenant id collision is the worst-case probe for a
//     regression that widened the conflict resolution by
//     organization_id (which would silently allow orgB to clobber or
//     mirror orgA's id, breaking the global uniqueness invariant a
//     future correlation system relies on). The Conflict payload must
//     echo only the supplied id (which orgB already has) and never any
//     foreign column from orgA's row (action, resource_kind,
//     resource_id, reason, request_id, correlation_id, ip_address,
//     user_agent, or metadata values).
//   - ListByOrganization(orgB) cross-tenant: returns only orgB's rows
//     even when orgA owns several entries, AND every returned row is
//     byte-identical to its baseline snapshot AND orgA's per-tenant
//     count is unaffected by orgB's read (the read is side-effect-free
//     against the audit_events table). A regression that dropped the
//     organization_id predicate from ListByOrganization would surface
//     here as a leak of orgA's rows into orgB's result set, the
//     worst-case audit-log data-leak shape.
//   - ListByOrganization limit clamping is tenant-scoped: a regression
//     that returned ALL rows clamped to auditEventListMaxLimit (i.e.
//     ignoring the organization_id predicate but honouring the LIMIT
//     clause) would surface here. orgA seeds rows ABOVE the cap
//     (auditEventListMaxLimit + extras), orgB seeds a small fixed
//     count, and orgB's ListByOrganization with an above-cap limit
//     request resolves to exactly orgB's count, NOT the cap — proving
//     the cap clamps the orgB row pool, not a globally-merged pool.
//   - ListByOrganization unknown-org cross-tenant: a fresh,
//     never-persisted org-id returns the empty slice AND every existing
//     tenant's per-org COUNT(*) is unchanged after the read. The
//     unknown-org-returns-empty branch is also pinned by the
//     invariants file with a single-tenant fixture; this file pins the
//     cross-tenant variant where multiple tenants exist and the read
//     of a phantom tenant must not leak a hint of either tenant's
//     existence through a row-count side-effect.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's audit_events rows. orgB's rows must remain
//     byte-identical to their baselines, including the immutable
//     business columns and the database-assigned occurred_at /
//     created_at timestamps. The single-bystander variant of this
//     cascade is already pinned by audit_repository_invariants_test.go's
//     TestAuditRepositoryAppendCascadesFromOrganizationDelete (which
//     seeds one orgB row); the BE-0468 variant deepens it with a
//     three-row orgB pool covering the decision / metadata spread, a
//     post-cascade ListByOrganization side-effect-free probe, and a
//     byte-identity assertion through assertAuditRowByteIdentical on
//     every bystander row (so a column drift on any persisted shape
//     surfaces as a named field diff instead of a single opaque
//     mismatch).
//
// Helpers introduced here: assertAuditRowByteIdentical (the raw-row
// snapshot comparator — assertAuditEventByteIdentical in audit_test.go
// compares the application-level store.AuditEvent struct, but the
// tenant-isolation tests must compare the persisted rawAuditRow shape
// to catch a metadata jsonb byte drift or a created_at sub-second
// rewrite that the application-level struct would silently round-trip),
// seedTwoTenantAuditFixture (two-organization fixture, narrower than
// the dokploy_refs equivalent because audit_events has no
// project/environment/service parent chain).
//
// Helpers reused from sibling files: seedOrg (schema_test.go); newStore
// (store_test.go); auditEventFixture, appendAudit (audit_test.go);
// rawAuditRow, loadAuditRowByID, countAuditRowsForOrg, mintAuditID
// (audit_repository_invariants_test.go); containsValue
// (organization_variable_tenant_isolation_test.go).

// assertAuditRowByteIdentical compares every column of a rawAuditRow
// pair (the persisted shape, including the metadata jsonb document and
// the database-assigned occurred_at / created_at timestamps) and emits
// a single diagnostic per drift. It is the byte-level snapshot probe
// used after every cross-tenant operation — if any orgB row's
// observable persisted shape drifts after an orgA Append, an orgA
// rejected Append, an orgB read, or an unknown-org read, this helper
// surfaces it as a named field diff.
//
// Every business column is compared individually so a rewrite of any
// one would surface as a named field diff in the failure message,
// rather than a single opaque "row mismatch" diagnostic.
func assertAuditRowByteIdentical(t *testing.T, label string, baseline, after rawAuditRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.ActorID != baseline.ActorID {
		t.Errorf("%s: bystander.actor_id = %q, want %q",
			label, after.ActorID, baseline.ActorID)
	}
	if after.ActorKind != baseline.ActorKind {
		t.Errorf("%s: bystander.actor_kind = %q, want %q",
			label, after.ActorKind, baseline.ActorKind)
	}
	if after.Action != baseline.Action {
		t.Errorf("%s: bystander.action = %q, want %q",
			label, after.Action, baseline.Action)
	}
	if after.ResourceKind != baseline.ResourceKind {
		t.Errorf("%s: bystander.resource_kind = %q, want %q",
			label, after.ResourceKind, baseline.ResourceKind)
	}
	if after.ResourceID != baseline.ResourceID {
		t.Errorf("%s: bystander.resource_id = %q, want %q",
			label, after.ResourceID, baseline.ResourceID)
	}
	if after.Decision != baseline.Decision {
		t.Errorf("%s: bystander.decision = %q, want %q",
			label, after.Decision, baseline.Decision)
	}
	if after.Reason != baseline.Reason {
		t.Errorf("%s: bystander.reason = %q, want %q",
			label, after.Reason, baseline.Reason)
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: bystander.request_id = %q, want %q",
			label, after.RequestID, baseline.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: bystander.correlation_id = %q, want %q",
			label, after.CorrelationID, baseline.CorrelationID)
	}
	if after.IPAddress != baseline.IPAddress {
		t.Errorf("%s: bystander.ip_address = %q, want %q",
			label, after.IPAddress, baseline.IPAddress)
	}
	if after.UserAgent != baseline.UserAgent {
		t.Errorf("%s: bystander.user_agent = %q, want %q",
			label, after.UserAgent, baseline.UserAgent)
	}
	if string(after.Metadata) != string(baseline.Metadata) {
		t.Errorf("%s: bystander.metadata = %q, want %q",
			label, string(after.Metadata), string(baseline.Metadata))
	}
	if !after.OccurredAt.Equal(baseline.OccurredAt) {
		t.Errorf("%s: bystander.occurred_at = %s, want %s",
			label, after.OccurredAt, baseline.OccurredAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %s, want %s",
			label, after.CreatedAt, baseline.CreatedAt)
	}
}

// twoTenantAuditFixture is the two-organization shape every test in
// this file seeds before the cross-tenant probe runs. audit_events has
// no project/environment/service parent chain (its only parent FK is
// organizations), so the fixture is deliberately narrower than the
// dokploy_refs equivalent.
type twoTenantAuditFixture struct {
	orgA testutil.Organization
	orgB testutil.Organization
}

// seedTwoTenantAuditFixture creates two organizations the cross-tenant
// tests can use as orgA (writer / target) and orgB (bystander).
func seedTwoTenantAuditFixture(
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
) twoTenantAuditFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "audit-tenant-a")
	orgB := seedOrg(t, db, f, "audit-tenant-b")
	return twoTenantAuditFixture{orgA: orgA, orgB: orgB}
}

// TestAuditRepositoryAppendOnOrgADoesNotTouchOrgBRows proves the
// load-bearing bystander invariant: an Append on orgA mints exactly
// one new row owned by orgA, and every column of every orgB row is
// byte-identical to its baseline snapshot afterwards. The bystander
// pool deliberately spans (a) both decision verdicts, (b) presence /
// absence of an actor pair, (c) a non-empty redacted metadata document,
// (d) the empty-metadata document — so a regression that rewrote any
// of those legs on a foreign-tenant row would surface as a named field
// diff via assertAuditRowByteIdentical.
//
// A regression that dropped the organization_id leg from the Append
// INSERT (e.g. INSERT ... RETURNING * ON CONFLICT DO UPDATE with no
// tenant predicate) would surface here either as an orgB row column
// rewrite OR as orgA's RETURNING row carrying orgB's id. The strict
// equality on the post-Append rawAuditRow set is the chokepoint.
func TestAuditRepositoryAppendOnOrgADoesNotTouchOrgBRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	// orgB seeds four rows covering the audit_events shape spread:
	// allowed + actor + metadata, denied + no-actor + empty-metadata,
	// allowed + actor + empty-metadata, denied + actor + metadata. A
	// regression that touched any one of these legs would surface as a
	// named field diff in the assertion loop.
	bravoAllowedWithMeta := auditEventFixture(fix.orgB.ID)
	bravoAllowedWithMeta.Reason = "bravo_allowed_with_meta"
	bravoAllowedWithMeta.Action = "project.update"
	bravoAllowedStored := appendAudit(ctx, t, s, repo, bravoAllowedWithMeta)

	bravoDeniedNoActor := auditEventFixture(fix.orgB.ID)
	bravoDeniedNoActor.Decision = store.AuditDecisionDenied
	bravoDeniedNoActor.Reason = "bravo_denied_no_principal"
	bravoDeniedNoActor.ActorID = ""
	bravoDeniedNoActor.ActorKind = ""
	bravoDeniedNoActor.Metadata = nil
	bravoDeniedStored := appendAudit(ctx, t, s, repo, bravoDeniedNoActor)

	bravoAllowedEmptyMeta := auditEventFixture(fix.orgB.ID)
	bravoAllowedEmptyMeta.Reason = "bravo_allowed_empty_meta"
	bravoAllowedEmptyMeta.Metadata = nil
	bravoEmptyMetaStored := appendAudit(ctx, t, s, repo, bravoAllowedEmptyMeta)

	bravoDeniedWithMeta := auditEventFixture(fix.orgB.ID)
	bravoDeniedWithMeta.Decision = store.AuditDecisionDenied
	bravoDeniedWithMeta.Reason = "bravo_denied_with_meta"
	bravoDeniedStoredWithMeta := appendAudit(ctx, t, s, repo, bravoDeniedWithMeta)

	baselines := []rawAuditRow{
		loadAuditRowByID(ctx, t, db, bravoAllowedStored.ID),
		loadAuditRowByID(ctx, t, db, bravoDeniedStored.ID),
		loadAuditRowByID(ctx, t, db, bravoEmptyMetaStored.ID),
		loadAuditRowByID(ctx, t, db, bravoDeniedStoredWithMeta.ID),
	}

	// orgA writes a single audit row. This is the operation whose
	// side-effects on the orgB bystander pool we pin.
	alpha := auditEventFixture(fix.orgA.ID)
	alpha.Reason = "alpha_writer_event"
	alpha.Action = "service.deploy"
	alphaStored := appendAudit(ctx, t, s, repo, alpha)

	if alphaStored.OrganizationID != fix.orgA.ID {
		t.Fatalf("orgA Append returned organization_id %q, want %q — the writer's RETURNING row must echo the writer's tenant",
			alphaStored.OrganizationID, fix.orgA.ID)
	}

	// Every orgB row must remain byte-identical to its baseline. A
	// regression that mutated any column on any bystander row would
	// surface here as a named field diff.
	for i, baseline := range baselines {
		after := loadAuditRowByID(ctx, t, db, baseline.ID)
		assertAuditRowByteIdentical(t,
			"orgB bystander row after orgA Append",
			baseline, after)
		_ = i
	}
}

// TestAuditRepositoryAppendOnOrgADoesNotChangeOrgBRowCount is the
// corollary count probe. It exists separately from the byte-identity
// probe because a regression that rewrote one bystander column on one
// row would surface in the byte-identity test but a regression that
// added a phantom orgB row (e.g. a misrouted Append that inserted
// under the wrong organization_id) would surface only here — the
// per-tenant COUNT(*) is the side-effect probe the byte-identity loop
// cannot catch (it iterates over baseline ids, so a stray new row is
// invisible to it).
func TestAuditRepositoryAppendOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	for i := 0; i < 3; i++ {
		e := auditEventFixture(fix.orgB.ID)
		e.Reason = "bravo_baseline"
		appendAudit(ctx, t, s, repo, e)
	}

	priorAlphaCount := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorAlphaCount != 0 {
		t.Fatalf("baseline orgA audit_events count = %d, want 0", priorAlphaCount)
	}
	if priorBravoCount != 3 {
		t.Fatalf("baseline orgB audit_events count = %d, want 3", priorBravoCount)
	}

	alpha := auditEventFixture(fix.orgA.ID)
	alpha.Reason = "alpha_writer"
	appendAudit(ctx, t, s, repo, alpha)

	afterAlphaCount := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID)
	afterBravoCount := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID)

	if afterAlphaCount != priorAlphaCount+1 {
		t.Errorf("after orgA Append: orgA count = %d, want %d (writer's row must persist exactly once under the writer's tenant)",
			afterAlphaCount, priorAlphaCount+1)
	}
	if afterBravoCount != priorBravoCount {
		t.Errorf("after orgA Append: orgB count = %d, want %d (bystander tenant's count must be unchanged)",
			afterBravoCount, priorBravoCount)
	}
}

// TestAuditRepositoryAppendCrossTenantIDCollisionIsConflictAndBystanderByteIdentical
// is the cross-tenant mirror of the PRIMARY KEY conflict pinned in
// TestAuditRepositoryAppendDuplicateIDIsConflict: the audit_events
// PRIMARY KEY (id) is global (no UNIQUE on (organization_id, id) — id
// alone is sufficient because newAuditID mints a 128-bit-entropy opaque
// token). A regression that widened the conflict resolution by
// organization_id (e.g. a phantom UNIQUE on (organization_id, id) or
// an ON CONFLICT (organization_id, id) clause) would silently allow
// orgB to mint a row carrying orgA's id under its own tenant — the
// worst-case audit-log correlation-corruption shape.
//
// The Conflict payload must echo only the supplied id (orgB already
// has it in hand) and never any foreign column from orgA's row. The
// not-foreign-substring assertions are the second-line defence behind
// the apierr.Conflict code probe.
func TestAuditRepositoryAppendCrossTenantIDCollisionIsConflictAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	sharedID := mintAuditID(t, "cross-tenant-collision")

	// orgA writes a row carrying distinctive business columns so the
	// no-leak assertions on orgB's conflict payload can prove the
	// Conflict echoes only the supplied id (which orgB has) and never
	// any column from orgA's row.
	alpha := auditEventFixture(fix.orgA.ID)
	alpha.ID = sharedID
	alpha.Action = "alpha_distinctive_action"
	alpha.ResourceKind = "alpha_distinctive_resource"
	alpha.ResourceID = "alpha_distinctive_resource_id"
	alpha.Reason = "alpha_distinctive_reason"
	alpha.RequestID = "alpha_distinctive_request"
	alpha.CorrelationID = "alpha_distinctive_correlation"
	alpha.IPAddress = "198.51.100.7"
	alpha.UserAgent = "alpha-distinctive-agent/9.9"
	alpha.Metadata = map[string]string{"alpha_distinctive_meta_key": "alpha_distinctive_meta_val"}
	appendAudit(ctx, t, s, repo, alpha)

	baseline := loadAuditRowByID(ctx, t, db, sharedID)

	// orgB attempts to mint a row with the SAME id under its own
	// tenant. The global PRIMARY KEY on (id) means this is a Conflict
	// regardless of organization_id, and orgA's bystander row must
	// survive byte-identical.
	bravo := auditEventFixture(fix.orgB.ID)
	bravo.ID = sharedID
	bravo.Action = "bravo_writer_action"
	bravo.Reason = "bravo_writer_reason"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, appendErr := repo.Append(ctx, tx, bravo)
		return appendErr
	})
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(cross-tenant id collision) error = %v, want code %s — a duplicate id under a foreign tenant must surface as the same typed Conflict as same-tenant duplicate id",
			err, yerr.CodeConflict)
	}

	msg := err.Error()
	// The Conflict payload must NOT echo any column from orgA's
	// distinctive row. The id leg is intentionally not asserted
	// out — orgB supplied that id, so it is permitted to appear.
	leaks := []string{
		"alpha_distinctive_action",
		"alpha_distinctive_resource",
		"alpha_distinctive_resource_id",
		"alpha_distinctive_reason",
		"alpha_distinctive_request",
		"alpha_distinctive_correlation",
		"198.51.100.7",
		"alpha-distinctive-agent/9.9",
		"alpha_distinctive_meta_key",
		"alpha_distinctive_meta_val",
		fix.orgA.ID,
	}
	for _, leak := range leaks {
		if containsValue(msg, leak) {
			t.Errorf("Append(cross-tenant id collision) error message %q echoed orgA's foreign column %q — the conflict payload must echo only the supplied id and never a foreign tenant's column",
				msg, leak)
		}
	}

	// orgA's bystander row must be byte-identical to its baseline.
	// A regression that turned the conflict into an UPDATE (e.g.
	// ON CONFLICT (id) DO UPDATE bleeding orgB's payload through)
	// would surface here as a column rewrite.
	after := loadAuditRowByID(ctx, t, db, sharedID)
	assertAuditRowByteIdentical(t,
		"orgA bystander after orgB's cross-tenant id-collision Append",
		baseline, after)

	if got := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID); got != 1 {
		t.Errorf("after cross-tenant id collision: orgA count = %d, want 1 (the original row must persist exactly once)", got)
	}
	if got := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID); got != 0 {
		t.Errorf("after cross-tenant id collision: orgB count = %d, want 0 (the rejected Append must leave no row behind)", got)
	}
}

// TestAuditRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows
// is the read-side cross-tenant proof: even when orgA owns many
// audit_events rows of varying shape, ListByOrganization(orgB.ID)
// returns exactly orgB's row count, every returned row is owned by
// orgB, every returned row is byte-identical to its baseline, and
// orgA's per-tenant COUNT(*) is unchanged afterwards (the read is
// side-effect-free).
//
// A regression that dropped the organization_id predicate from the
// ListByOrganization query (e.g. SELECT ... FROM audit_events ORDER BY
// ... LIMIT $2 — i.e. ignoring $1) would surface here as a leak of
// orgA's rows into orgB's result set, the worst-case audit-log
// data-leak shape. This is the gap-fill probe sibling to
// TestAuditRepositoryListTenantIsolation in audit_test.go, with the
// added byte-identity bystander assertion on every returned row.
func TestAuditRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	// orgA seeds 5 rows across the decision / metadata spread. A
	// regression that leaked orgA rows into orgB's list would surface
	// as either an unexpected row count OR a row carrying orgA's
	// organization_id in the result set.
	for i := 0; i < 5; i++ {
		alpha := auditEventFixture(fix.orgA.ID)
		alpha.Reason = "alpha_seed"
		alpha.Action = "alpha_seed_action"
		if i%2 == 1 {
			alpha.Decision = store.AuditDecisionDenied
			alpha.Reason = "alpha_seed_denied"
		}
		appendAudit(ctx, t, s, repo, alpha)
	}

	bravoStored := make([]store.AuditEvent, 0, 3)
	for i := 0; i < 3; i++ {
		bravo := auditEventFixture(fix.orgB.ID)
		bravo.Reason = "bravo_seed"
		bravo.Action = "bravo_seed_action"
		if i == 1 {
			bravo.Decision = store.AuditDecisionDenied
			bravo.Reason = "bravo_seed_denied"
			bravo.ActorID = ""
			bravo.ActorKind = ""
			bravo.Metadata = nil
		}
		bravoStored = append(bravoStored, appendAudit(ctx, t, s, repo, bravo))
	}

	bravoBaselines := make(map[string]rawAuditRow, len(bravoStored))
	for _, e := range bravoStored {
		bravoBaselines[e.ID] = loadAuditRowByID(ctx, t, db, e.ID)
	}

	priorAlphaCount := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID)

	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 100)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}

	if len(listed) != len(bravoStored) {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want %d — a different count means the orgA pool leaked into orgB's result set (or a row was lost)",
			len(listed), len(bravoStored))
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a row owned by org %q — the organization_id predicate must filter cross-tenant rows out",
				e.OrganizationID)
		}
		baseline, ok := bravoBaselines[e.ID]
		if !ok {
			t.Errorf("ListByOrganization(orgB) returned an unexpected id %q (not in the bravo baseline set) — a regression must have either minted a phantom row or returned an orgA row",
				e.ID)
			continue
		}
		after := loadAuditRowByID(ctx, t, db, e.ID)
		assertAuditRowByteIdentical(t,
			"orgB returned row after cross-tenant List",
			baseline, after)
	}

	// The read must have no side effect on orgA's per-tenant count.
	afterAlphaCount := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID)
	if afterAlphaCount != priorAlphaCount {
		t.Errorf("after orgB ListByOrganization: orgA count = %d, want %d (the read must not have any side effect on the bystander tenant's row count)",
			afterAlphaCount, priorAlphaCount)
	}
}

// TestAuditRepositoryListByOrganizationLimitClampingIsTenantScoped
// pins that auditEventListMaxLimit clamps the orgB row pool, NOT a
// globally-merged pool. A regression that dropped the organization_id
// predicate but still honoured the LIMIT clause would surface here:
// orgA seeds rows ABOVE the cap and orgB seeds a small fixed count, so
// the malformed query would return min(orgA_count + orgB_count, cap)
// rows — a number well above orgB's actual count.
//
// orgA seeds auditEventListMaxLimit + 5 rows (slightly above the cap
// so the leak shape is observable but the seed time is bounded) and
// orgB seeds 4 rows. orgB's ListByOrganization with an above-cap limit
// (limit = auditEventListMaxLimit + 10) must resolve to exactly 4 rows
// — not the cap (which would prove the leak), not auditEventListMaxLimit
// + 9 (the merged pool clamped), not auditEventListMaxLimit + 4 (the
// cap drift). Exact equality on len(listed) is the chokepoint.
func TestAuditRepositoryListByOrganizationLimitClampingIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	// Seed orgA's row pool ABOVE the repository-level cap so the
	// "ignored the predicate, honoured the LIMIT" regression shape is
	// observable: a merged pool would surface as a returned-row count
	// well above orgB's seeded count. Use raw SQL to keep the seed
	// fast (a 205-row Append-loop through the store would multiply the
	// transaction setup cost). The INSERT mirrors the auditEventColumns
	// shape minus occurred_at/created_at (which DEFAULT now() — same
	// pattern as seedAuditRowsRawSQL in the invariants file).
	alphaSeedCount := 205 // above auditEventListMaxLimit (200)
	for i := 0; i < alphaSeedCount; i++ {
		id := mintAuditID(t, "alpha-cap-leak-probe-")
		// Per-row uniqueness via the loop index since mintAuditID
		// only uses the test name + the literal suffix.
		_, err := db.Exec(ctx,
			`INSERT INTO audit_events
			   (id, organization_id, actor_id, actor_kind, action,
			    resource_kind, resource_id, decision, reason,
			    request_id, correlation_id, ip_address, user_agent,
			    metadata)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			id+"_"+itoa(i), fix.orgA.ID, "usr_alpha", "usr",
			"alpha.seed", "proj", "proj_alpha_seed",
			string(store.AuditDecisionAllowed), "alpha_seed",
			"req-alpha-seed", "corr-alpha-seed", "203.0.113.7",
			"yalla-test/1.0", []byte(`{}`))
		if err != nil {
			t.Fatalf("seed orgA row %d: %v", i, err)
		}
	}

	bravoSeedCount := 4
	for i := 0; i < bravoSeedCount; i++ {
		bravo := auditEventFixture(fix.orgB.ID)
		bravo.Reason = "bravo_cap_seed"
		appendAudit(ctx, t, s, repo, bravo)
	}

	// Above-cap limit request: with a tenant-scoped predicate this
	// resolves to exactly orgB's row count. Without the predicate it
	// would resolve to min(alphaSeedCount + bravoSeedCount,
	// auditEventListMaxLimit) — i.e. 200 (the cap), well above
	// bravoSeedCount.
	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 1000)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB, above-cap limit): %v", err)
	}

	if len(listed) != bravoSeedCount {
		t.Fatalf("ListByOrganization(orgB, above-cap limit) returned %d rows, want %d — a count matching the repository cap (or any number above bravoSeedCount) proves the orgA pool leaked through the limit clause",
			len(listed), bravoSeedCount)
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB, above-cap limit) returned a row owned by org %q — every returned row must be tenant-owned",
				e.OrganizationID)
		}
	}

	// orgA's per-tenant count is unchanged after orgB's read.
	if got := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID); got != alphaSeedCount {
		t.Errorf("after orgB above-cap List: orgA count = %d, want %d (the read must be side-effect-free)",
			got, alphaSeedCount)
	}
}

// TestAuditRepositoryListByOrganizationUnknownTenantReturnsEmptyAndPreservesCounts
// pins the cross-tenant variant of the unknown-org-returns-empty
// branch. The invariants file's TestAuditRepositoryListByOrganizationUnknownOrgReturnsEmpty
// seeds a single tenant; this test seeds two and proves the
// phantom-tenant read leaks no hint of either real tenant's existence
// through a per-tenant row-count side-effect (the COUNT(*) probe is
// the side-effect probe; the empty-slice probe is the surface contract).
func TestAuditRepositoryListByOrganizationUnknownTenantReturnsEmptyAndPreservesCounts(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	for i := 0; i < 2; i++ {
		appendAudit(ctx, t, s, repo, auditEventFixture(fix.orgA.ID))
	}
	for i := 0; i < 5; i++ {
		appendAudit(ctx, t, s, repo, auditEventFixture(fix.orgB.ID))
	}

	priorAlphaCount := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID)

	// A plausibly-shaped but never-persisted org id. The slug-shape
	// matches Factory.Organization to keep the test resilient against a
	// future tightening of the input validation that might short-circuit
	// obviously-malformed ids.
	phantomID := "org_phantom_tenant_does_not_exist"

	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, phantomID, 50)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(phantom): %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListByOrganization(phantom) returned %d rows, want 0 — an unknown org id must resolve to the empty slice and never leak rows from any real tenant",
			len(listed))
	}

	if got := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID); got != priorAlphaCount {
		t.Errorf("after phantom-tenant read: orgA count = %d, want %d (the read must be side-effect-free)",
			got, priorAlphaCount)
	}
	if got := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after phantom-tenant read: orgB count = %d, want %d (the read must be side-effect-free)",
			got, priorBravoCount)
	}
}

// TestAuditOrganizationDeleteCascadeIsTenantScoped proves orgA's
// deletion cascades only to orgA's audit_events. orgB's rows must
// remain byte-identical to their baselines. The audit_events
// organization_id FK CASCADE on organizations(id) is the cascade
// chain; a regression that dropped the organization_id leg of the FK
// (or scoped the cascade too widely) would surface here as either an
// orgB row vanishing or its columns drifting.
//
// The single-bystander variant of this cascade is already pinned by
// audit_repository_invariants_test.go's
// TestAuditRepositoryAppendCascadesFromOrganizationDelete (which seeds
// one orgB row and asserts a handful of column equalities inline); the
// BE-0468 variant deepens it with a three-row orgB pool covering the
// decision / metadata spread, a post-cascade ListByOrganization
// side-effect-free probe, and a byte-identity assertion through
// assertAuditRowByteIdentical on every bystander row (so a column
// drift on any persisted shape surfaces as a named field diff).
func TestAuditOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantAuditFixture(t, db, f)

	// orgA owns two rows (cascaded away). orgB owns three rows
	// covering the decision / metadata spread (survive byte-identically
	// so the bystander assertion is anchored against a representative
	// spread of the audit_events shape).
	for i := 0; i < 2; i++ {
		alpha := auditEventFixture(fix.orgA.ID)
		alpha.Reason = "alpha_cascade_target"
		appendAudit(ctx, t, s, repo, alpha)
	}

	bravoAllowed := auditEventFixture(fix.orgB.ID)
	bravoAllowed.Reason = "bravo_cascade_allowed"
	bravoAllowedStored := appendAudit(ctx, t, s, repo, bravoAllowed)

	bravoDenied := auditEventFixture(fix.orgB.ID)
	bravoDenied.Decision = store.AuditDecisionDenied
	bravoDenied.Reason = "bravo_cascade_denied"
	bravoDenied.ActorID = ""
	bravoDenied.ActorKind = ""
	bravoDenied.Metadata = nil
	bravoDeniedStored := appendAudit(ctx, t, s, repo, bravoDenied)

	bravoEmptyMeta := auditEventFixture(fix.orgB.ID)
	bravoEmptyMeta.Reason = "bravo_cascade_empty_meta"
	bravoEmptyMeta.Metadata = nil
	bravoEmptyMetaStored := appendAudit(ctx, t, s, repo, bravoEmptyMeta)

	bravoBaselines := []rawAuditRow{
		loadAuditRowByID(ctx, t, db, bravoAllowedStored.ID),
		loadAuditRowByID(ctx, t, db, bravoDeniedStored.ID),
		loadAuditRowByID(ctx, t, db, bravoEmptyMetaStored.ID),
	}

	priorBravoCount := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorBravoCount != 3 {
		t.Fatalf("baseline orgB audit_events count = %d, want 3", priorBravoCount)
	}

	// Cascade-delete orgA. The audit_events.organization_id FK CASCADE
	// removes only the rows tagged with orgA.
	if _, err := db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("DELETE orgA: %v", err)
	}

	// orgA's audit rows must be gone.
	if got := countAuditRowsForOrg(ctx, t, db, fix.orgA.ID); got != 0 {
		t.Errorf("after orgA cascade: orgA count = %d, want 0", got)
	}

	// orgB's count must be unchanged.
	if got := countAuditRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after orgA cascade: orgB count = %d, want %d (the cascade crossed the organization_id predicate — worst-case data loss)",
			got, priorBravoCount)
	}

	// Every orgB row must be byte-identical to its baseline.
	for _, baseline := range bravoBaselines {
		after := loadAuditRowByID(ctx, t, db, baseline.ID)
		assertAuditRowByteIdentical(t,
			"orgB bystander after orgA cascade",
			baseline, after)
	}

	// ListByOrganization(orgB) after the cascade must still return
	// exactly orgB's row set — the cascade did not silently corrupt the
	// repository read predicate.
	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 100)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB) after orgA cascade: %v", err)
	}
	if len(listed) != priorBravoCount {
		t.Errorf("ListByOrganization(orgB) after orgA cascade returned %d rows, want %d",
			len(listed), priorBravoCount)
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB) after orgA cascade returned a row owned by org %q",
				e.OrganizationID)
		}
	}
}

// itoa is a tiny local integer-to-string helper used by the raw-SQL
// seed loop in TestAuditRepositoryListByOrganizationLimitClampingIsTenantScoped.
// It exists so the seed loop does not have to import strconv only for
// one call site; the loop runs O(205) times so the allocation cost is
// negligible.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
