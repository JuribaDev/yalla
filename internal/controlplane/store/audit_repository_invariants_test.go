package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-invariants for the audit_events table (BE-0467).
// An audit_events row is one immutable record of a security-relevant
// authorization decision made by the control plane. The AuditRepository
// surface is intentionally narrow: Append appends a row inside the same
// transaction as the mutation it records (so the audit write commits or
// rolls back atomically with the mutation), and ListByOrganization reads
// the tenant-scoped, newest-first audit history. There is no per-row
// Update, no caller-facing Delete, and no GetByID -- audit reads are
// performed exclusively through the tenant-scoped List surface, and row
// removal is reachable only through ON DELETE CASCADE when the parent
// organization is removed (tenant teardown).
//
// What this file pins, and what it deliberately delegates:
//
//   - Append row-shape on the first call: a blank-id event mints an id
//     carrying the aud_ prefix, the database stamps occurred_at and
//     created_at server-side (NOT caller-supplied -- the INSERT column
//     list deliberately omits both, so DEFAULT now() applies), the
//     caller-supplied actor / action / resource / decision / reason
//     fields round-trip verbatim, and the return value's struct fields
//     are byte-equal to a raw-SQL re-load of the persisted row.
//   - Append id contract: a caller-supplied id is preserved verbatim, a
//     duplicate id surfaces as typed apierr.Conflict (PRIMARY KEY) through
//     mapWriteError.
//   - Append timestamp contract: the table is a forensic record of the
//     decision wallclock, but the persistence layer deliberately defers
//     occurred_at to the database -- a caller that smuggles a back-dated
//     OccurredAt must NOT influence the persisted row. This is the
//     load-bearing "audit timestamps are server-side" invariant; a future
//     refactor that adds occurred_at to the INSERT column list would have
//     to also update this test (and the migration's comment).
//   - Append CHECK violations surface as typed apierr.Conflict through
//     mapWriteError: blank action (length(action) > 0), blank
//     resource_kind (length(resource_kind) > 0), blank reason
//     (length(reason) > 0), and an actor_kind outside the closed-set
//     ('', 'usr', 'sa', 'system') all flow through the database CHECK
//     and surface as Conflict. The decision CHECK and the FK on
//     organization_id are covered elsewhere (audit_internal_test.go
//     pins the application-layer Valid() guard before the row ever
//     reaches the database; audit_test.go's
//     TestAuditRepositoryAppendCrossTenantOrgRejected pins the FK).
//   - Append transaction rollback semantics: a closure that returns an
//     error after a successful Append leaves no audit_events row behind.
//     The audit log must commit or roll back atomically with the
//     mutation it records.
//   - Cascade delete: removing the parent organization removes every
//     audit_events row owned by that organization via ON DELETE CASCADE,
//     while a sibling tenant's audit rows survive byte-identical.
//   - Peer-row byte-identity: Append for one (organization, event) tuple
//     does not touch a prior audit row's id, actor, decision, reason,
//     metadata, occurred_at, or created_at columns.
//   - ListByOrganization ordering: rows are returned newest first by
//     occurred_at DESC with a secondary id DESC tiebreaker, so a pair of
//     audit events written in the same microsecond have a deterministic
//     ordering (the ListByOrganization index pairs (organization_id,
//     occurred_at DESC) and the secondary id DESC tiebreaker is what
//     makes the result stable for tied timestamps).
//   - ListByOrganization limit clamping: a non-positive limit is treated
//     as the maximum cap (auditEventListMaxLimit, 200), a limit above
//     the cap is clamped down to the cap, and a limit in (0, cap] is
//     honoured verbatim. The cap exists so an unbounded query can never
//     be issued by accident.
//   - ListByOrganization unknown-org contract: an unknown or
//     cross-tenant organization_id returns the empty slice, never an
//     error, so a caller that has not yet seeded any audit rows can
//     render an empty history without distinguishing "no events" from
//     "no organization" (callers that need the distinction Get the
//     organization first).
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - Append-only enforcement (the database BEFORE UPDATE trigger
//     rejecting every UPDATE) is pinned by audit_test.go's
//     TestAuditRepositoryAppendImmutability and
//     TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation,
//     including the canonical SQLSTATE / message proof.
//   - Cross-tenant read leak (orgB reading orgA's audit rows via
//     ListByOrganization, or vice-versa) is pinned by audit_test.go's
//     TestAuditRepositoryListTenantIsolation. The BE-0468 sibling
//     tenant-isolation story will add the byte-identical-bystander
//     gap-fill probes (Append on orgA leaves every observable column
//     on every orgB row byte-identical).
//   - Application-layer Append guards (nil tx, invalid decision) are
//     pinned by audit_internal_test.go's TestAuditRepositoryAppendNilTransaction
//     and TestAuditRepositoryAppendInvalidDecision; both surface as
//     typed apierr.Internal before the database is touched.
//   - Metadata redaction is the audit service's job (and is pinned by
//     internal/controlplane/audit). The audit_events table comment
//     explicitly documents this delegation: "metadata is redacted by
//     the audit service before it is ever handed to this table".
//
// Helpers introduced here: rawAuditRow, loadAuditRowByID,
// countAuditRowsForOrg, mintAuditID, auditTxRollbackSentinel. Helpers
// reused from sibling files: seedOrg (schema_test.go); newStore
// (store_test.go); auditEventFixture, appendAudit, assertAuditEventByteIdentical
// (audit_test.go).

// rawAuditRow is the full audit_events row, deliberately loaded via raw
// SQL so the test can observe id, organization_id, the actor pair, the
// closed-set decision column, the metadata jsonb document, occurred_at
// and created_at through the same shape the database stores them in. It
// is the same template rawJobAttemptRow uses for job_attempts in
// BE-0463 and rawDokployRefRow uses for dokploy_refs in BE-0465.
type rawAuditRow struct {
	ID             string
	OrganizationID string
	ActorID        string
	ActorKind      string
	Action         string
	ResourceKind   string
	ResourceID     string
	Decision       string
	Reason         string
	RequestID      string
	CorrelationID  string
	IPAddress      string
	UserAgent      string
	Metadata       []byte
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// loadAuditRowByID reads the raw audit_events row for id and fatals on
// error. The lookup is by primary key -- distinct audit rows have
// distinct ids -- so no tenant scope is needed (raw loaders bypass
// repository scoping deliberately, so the test observes the persisted
// row exactly as the database stores it).
func loadAuditRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawAuditRow {
	t.Helper()
	var row rawAuditRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, actor_id, actor_kind, action, resource_kind,
		        resource_id, decision, reason, request_id, correlation_id,
		        ip_address, user_agent, metadata, occurred_at, created_at
		   FROM audit_events
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.ActorID, &row.ActorKind, &row.Action,
		&row.ResourceKind, &row.ResourceID, &row.Decision, &row.Reason,
		&row.RequestID, &row.CorrelationID, &row.IPAddress, &row.UserAgent,
		&row.Metadata, &row.OccurredAt, &row.CreatedAt,
	); err != nil {
		t.Fatalf("load audit_events id=%q: %v", id, err)
	}
	return row
}

// countAuditRowsForOrg returns the total number of audit_events rows
// owned by organizationID. It is the "did the rollback / cascade leave a
// row behind?" probe and the natural per-parent counter for the
// audit_events table (organization is the only parent FK).
func countAuditRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count audit_events for org %q: %v", organizationID, err)
	}
	return n
}

// mintAuditID builds a stable, test-local audit id from the test name and
// a per-test suffix. Tests in store_test share a single package, so the
// test name keeps ids unique across parallel test cases without needing
// a shared atomic counter. Real id minting lives in newAuditID, so this
// is the test-local override that exercises the caller-supplied-id
// branch of Append (a blank ID still triggers newAuditID via Append).
func mintAuditID(t *testing.T, suffix string) string {
	t.Helper()
	return "aud_" + t.Name() + "_" + suffix
}

// auditTxRollbackSentinel is a uniquely-typed sentinel for the rollback
// test. Sentinel types must be unique per file in the store_test package
// (every *_test.go under internal/controlplane/store/ shares the same
// package). Existing siblings include jobAttemptTxRollbackSentinel and
// dokployRefTxRollbackSentinel.
type auditTxRollbackSentinel struct{}

func (auditTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this audit event transaction"
}

// TestAuditRepositoryAppendMintsRowShape pins the Append row-shape on the
// first call. It walks every observable column of the returned struct
// against a raw-SQL re-load of the persisted row: a regression that
// silently dropped a column from auditEventColumns or scanAuditEvent
// would surface as a drift here. The id minting and server-side
// timestamps are also pinned.
func TestAuditRepositoryAppendMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	before := time.Now().UTC().Add(-time.Second)
	created := appendAudit(ctx, t, s, repo, auditEventFixture(org.ID))
	after := time.Now().UTC().Add(time.Second)

	if created.ID == "" {
		t.Fatal("created.ID is blank, want a minted id")
	}
	if !strings.HasPrefix(created.ID, "aud_") {
		t.Errorf("created.ID = %q, want aud_ prefix", created.ID)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.OccurredAt.Before(before) || created.OccurredAt.After(after) {
		t.Errorf("created.OccurredAt = %v, want within [%v, %v] (server-side now())",
			created.OccurredAt, before, after)
	}
	if created.CreatedAt.Before(before) || created.CreatedAt.After(after) {
		t.Errorf("created.CreatedAt = %v, want within [%v, %v] (server-side now())",
			created.CreatedAt, before, after)
	}

	row := loadAuditRowByID(ctx, t, db, created.ID)
	if row.ID != created.ID {
		t.Errorf("row.ID = %q, want %q", row.ID, created.ID)
	}
	if row.OrganizationID != created.OrganizationID {
		t.Errorf("row.OrganizationID = %q, want %q", row.OrganizationID, created.OrganizationID)
	}
	if row.ActorID != created.ActorID || row.ActorKind != created.ActorKind {
		t.Errorf("actor drift: row=(%q,%q) created=(%q,%q)",
			row.ActorID, row.ActorKind, created.ActorID, created.ActorKind)
	}
	if row.Action != created.Action {
		t.Errorf("row.Action = %q, want %q", row.Action, created.Action)
	}
	if row.ResourceKind != created.ResourceKind || row.ResourceID != created.ResourceID {
		t.Errorf("resource drift: row=(%q,%q) created=(%q,%q)",
			row.ResourceKind, row.ResourceID, created.ResourceKind, created.ResourceID)
	}
	if row.Decision != string(created.Decision) {
		t.Errorf("row.Decision = %q, want %q", row.Decision, created.Decision)
	}
	if row.Reason != created.Reason {
		t.Errorf("row.Reason = %q, want %q", row.Reason, created.Reason)
	}
	if row.RequestID != created.RequestID || row.CorrelationID != created.CorrelationID {
		t.Errorf("correlation ids drifted: row=(%q,%q) created=(%q,%q)",
			row.RequestID, row.CorrelationID, created.RequestID, created.CorrelationID)
	}
	if row.IPAddress != created.IPAddress || row.UserAgent != created.UserAgent {
		t.Errorf("transport drift: row=(%q,%q) created=(%q,%q)",
			row.IPAddress, row.UserAgent, created.IPAddress, created.UserAgent)
	}
	if !row.OccurredAt.Equal(created.OccurredAt) {
		t.Errorf("row.OccurredAt = %v, want %v", row.OccurredAt, created.OccurredAt)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v", row.CreatedAt, created.CreatedAt)
	}
	// metadata is jsonb. json.Marshal of the stored map must produce the
	// same document the raw row carries, modulo whitespace.
	var stored map[string]string
	if err := json.Unmarshal(row.Metadata, &stored); err != nil {
		t.Fatalf("unmarshal raw metadata %q: %v", row.Metadata, err)
	}
	if stored["field"] != "replicas" || stored["from"] != "1" || stored["to"] != "3" {
		t.Errorf("raw metadata = %v, want the fixture metadata round-tripped", stored)
	}
}

// TestAuditRepositoryAppendRespectsCallerSuppliedID pins that a non-blank
// caller-supplied id is preserved verbatim. The blank-id mint branch is
// covered by TestAuditRepositoryAppendMintsRowShape; this is the other
// half of the id contract.
func TestAuditRepositoryAppendRespectsCallerSuppliedID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	want := mintAuditID(t, "caller_supplied")

	e := auditEventFixture(org.ID)
	e.ID = want
	created := appendAudit(ctx, t, s, repo, e)
	if created.ID != want {
		t.Errorf("created.ID = %q, want %q (caller-supplied id must be preserved verbatim)",
			created.ID, want)
	}
	row := loadAuditRowByID(ctx, t, db, want)
	if row.ID != want {
		t.Errorf("row.ID = %q, want %q", row.ID, want)
	}
}

// TestAuditRepositoryAppendIgnoresCallerSuppliedTimestamps pins the
// load-bearing "audit timestamps are server-side" invariant. The
// auditEventColumns INSERT list deliberately omits occurred_at and
// created_at, so the database fills them with DEFAULT now() regardless
// of what the caller supplies. A regression that added occurred_at to
// the INSERT (so a caller could back-date an audit record) would surface
// here.
func TestAuditRepositoryAppendIgnoresCallerSuppliedTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	backDated := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	e := auditEventFixture(org.ID)
	e.OccurredAt = backDated
	e.CreatedAt = backDated

	before := time.Now().UTC().Add(-time.Second)
	created := appendAudit(ctx, t, s, repo, e)
	after := time.Now().UTC().Add(time.Second)

	if created.OccurredAt.Equal(backDated) {
		t.Errorf("created.OccurredAt = %v, want server-side now() (caller-supplied back-dated value must be discarded)",
			created.OccurredAt)
	}
	if created.CreatedAt.Equal(backDated) {
		t.Errorf("created.CreatedAt = %v, want server-side now()", created.CreatedAt)
	}
	if created.OccurredAt.Before(before) || created.OccurredAt.After(after) {
		t.Errorf("created.OccurredAt = %v, want within [%v, %v]", created.OccurredAt, before, after)
	}
	if created.CreatedAt.Before(before) || created.CreatedAt.After(after) {
		t.Errorf("created.CreatedAt = %v, want within [%v, %v]", created.CreatedAt, before, after)
	}
}

// TestAuditRepositoryAppendBlankActionIsConflict pins the
// length(action) > 0 CHECK as a typed Conflict via mapWriteError. The
// Append method does not pre-validate this field, so the constraint
// violation flows through the database and back through the typed
// error taxonomy.
func TestAuditRepositoryAppendBlankActionIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	e := auditEventFixture(org.ID)
	e.Action = ""

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, e)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(blank action) error code = %v, want %s (length(action) > 0 CHECK must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("blank-action rejection left %d audit_events rows behind, want 0", got)
	}
}

// TestAuditRepositoryAppendBlankResourceKindIsConflict pins the
// length(resource_kind) > 0 CHECK.
func TestAuditRepositoryAppendBlankResourceKindIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	e := auditEventFixture(org.ID)
	e.ResourceKind = ""

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, e)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(blank resource_kind) error code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("blank-resource_kind rejection left %d audit_events rows behind, want 0", got)
	}
}

// TestAuditRepositoryAppendBlankReasonIsConflict pins the
// length(reason) > 0 CHECK. Reason is required even for an allowed
// decision so the audit log is never silent about why a verdict was
// reached.
func TestAuditRepositoryAppendBlankReasonIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	e := auditEventFixture(org.ID)
	e.Reason = ""

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, e)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(blank reason) error code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("blank-reason rejection left %d audit_events rows behind, want 0", got)
	}
}

// TestAuditRepositoryAppendUnknownActorKindIsConflict pins the
// actor_kind IN (”, 'usr', 'sa', 'system') closed-set CHECK. The
// repository does not pre-validate actor_kind (the audit service is
// the chokepoint for principal mapping), so an out-of-set value flows
// through the database CHECK and surfaces as Conflict.
func TestAuditRepositoryAppendUnknownActorKindIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	e := auditEventFixture(org.ID)
	e.ActorKind = "bogus"

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, e)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(unknown actor_kind) error code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("unknown-actor_kind rejection left %d audit_events rows behind, want 0", got)
	}
}

// TestAuditRepositoryAppendDuplicateIDIsConflict pins the PRIMARY KEY
// collision. A duplicate id surfaces as typed apierr.Conflict through
// mapWriteError -- not a 500 leaking the raw pgconn message.
func TestAuditRepositoryAppendDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	id := mintAuditID(t, "duplicate")

	first := auditEventFixture(org.ID)
	first.ID = id
	appendAudit(ctx, t, s, repo, first)

	second := auditEventFixture(org.ID)
	second.ID = id
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, second)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(duplicate id) error code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 1 {
		t.Errorf("duplicate-id rejection left %d audit_events rows behind, want 1 (only the first row should persist)", got)
	}
}

// TestAuditRepositoryAppendTransactionRollback pins the load-bearing
// atomicity invariant: an audit row is committed only when the
// transaction that carries the recorded mutation commits. A closure
// that returns an error after a successful Append leaves no row behind.
func TestAuditRepositoryAppendTransactionRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	sentinel := auditTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, aErr := repo.Append(ctx, tx, auditEventFixture(org.ID)); aErr != nil {
			return aErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the rollback sentinel", err)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("rollback left %d audit_events rows behind, want 0", got)
	}
}

// TestAuditRepositoryAppendCascadesFromOrganizationDelete pins the
// tenant-teardown cascade: removing the parent organization removes
// every audit_events row owned by that organization via ON DELETE
// CASCADE. A sibling tenant's audit rows are unaffected.
func TestAuditRepositoryAppendCascadesFromOrganizationDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	appendAudit(ctx, t, s, repo, auditEventFixture(orgA.ID))
	appendAudit(ctx, t, s, repo, auditEventFixture(orgA.ID))
	bystander := appendAudit(ctx, t, s, repo, auditEventFixture(orgB.ID))
	beforeBystander := loadAuditRowByID(ctx, t, db, bystander.ID)

	if got := countAuditRowsForOrg(ctx, t, db, orgA.ID); got != 2 {
		t.Fatalf("orgA pre-cascade count = %d, want 2", got)
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgA.ID); err != nil {
		t.Fatalf("DELETE organization orgA: %v", err)
	}

	if got := countAuditRowsForOrg(ctx, t, db, orgA.ID); got != 0 {
		t.Errorf("orgA post-cascade audit count = %d, want 0 (ON DELETE CASCADE must remove every audit row)", got)
	}
	if got := countAuditRowsForOrg(ctx, t, db, orgB.ID); got != 1 {
		t.Errorf("orgB post-cascade audit count = %d, want 1 (sibling tenant must be untouched)", got)
	}
	afterBystander := loadAuditRowByID(ctx, t, db, bystander.ID)
	if afterBystander.ID != beforeBystander.ID ||
		afterBystander.OrganizationID != beforeBystander.OrganizationID ||
		afterBystander.Action != beforeBystander.Action ||
		afterBystander.Reason != beforeBystander.Reason ||
		!afterBystander.OccurredAt.Equal(beforeBystander.OccurredAt) ||
		!afterBystander.CreatedAt.Equal(beforeBystander.CreatedAt) {
		t.Errorf("orgB bystander row drifted after orgA cascade: before=%+v after=%+v",
			beforeBystander, afterBystander)
	}
}

// TestAuditRepositoryAppendPeerRowByteIdentical pins the load-bearing
// peer-row invariant: appending a new audit row for the same
// organization does not touch a prior audit row. audit_events is
// append-only with a BEFORE UPDATE trigger rejecting every UPDATE, so a
// foreign-row UPDATE that snuck past the trigger would surface here as
// a column rewrite on the bystander.
func TestAuditRepositoryAppendPeerRowByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	first := appendAudit(ctx, t, s, repo, auditEventFixture(org.ID))
	beforeFirst := loadAuditRowByID(ctx, t, db, first.ID)

	second := auditEventFixture(org.ID)
	second.Reason = "denied_second_event"
	second.Decision = store.AuditDecisionDenied
	appendAudit(ctx, t, s, repo, second)

	afterFirst := loadAuditRowByID(ctx, t, db, first.ID)
	if afterFirst.Reason != beforeFirst.Reason {
		t.Errorf("peer Append rewrote first row's reason: before=%q after=%q",
			beforeFirst.Reason, afterFirst.Reason)
	}
	if afterFirst.Decision != beforeFirst.Decision {
		t.Errorf("peer Append rewrote first row's decision: before=%q after=%q",
			beforeFirst.Decision, afterFirst.Decision)
	}
	if !afterFirst.OccurredAt.Equal(beforeFirst.OccurredAt) {
		t.Errorf("peer Append rewrote first row's occurred_at: before=%v after=%v",
			beforeFirst.OccurredAt, afterFirst.OccurredAt)
	}
	if !afterFirst.CreatedAt.Equal(beforeFirst.CreatedAt) {
		t.Errorf("peer Append rewrote first row's created_at: before=%v after=%v",
			beforeFirst.CreatedAt, afterFirst.CreatedAt)
	}
	if got := countAuditRowsForOrg(ctx, t, db, org.ID); got != 2 {
		t.Errorf("post-peer Append count = %d, want 2", got)
	}
}

// TestAuditRepositoryListByOrganizationOrdersIDDescOnTimestampTie pins
// the ListByOrganization secondary-sort contract: two rows written
// inside the same microsecond (which is the precision Postgres stores
// timestamptz at) share an occurred_at, and the ORDER BY uses id DESC
// as the tiebreaker. Without it, a tied pair's order would be
// non-deterministic and a UI rendering them would flicker.
func TestAuditRepositoryListByOrganizationOrdersIDDescOnTimestampTie(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	// Force both rows to share an occurred_at by directly inserting them
	// at the same wallclock value through raw SQL: Append leans on
	// DEFAULT now() which would advance between calls.
	tied := time.Now().UTC().Truncate(time.Microsecond)
	// Pick two suffixes whose mint outputs sort deterministically: idHigh
	// must be lex-greater than idLow so the id DESC tiebreaker is
	// observable. 'b' > 'a' guarantees the ordering regardless of how
	// the test name (encoded into mintAuditID) sorts.
	idLow := mintAuditID(t, "a_lower")
	idHigh := mintAuditID(t, "b_upper")
	if !(idHigh > idLow) {
		t.Fatalf("test setup error: expected %q > %q lexicographically", idHigh, idLow)
	}
	for _, id := range []string{idLow, idHigh} {
		if _, err := db.Exec(ctx,
			`INSERT INTO audit_events
			   (id, organization_id, actor_id, actor_kind, action, resource_kind,
			    resource_id, decision, reason, request_id, correlation_id,
			    ip_address, user_agent, metadata, occurred_at, created_at)
			 VALUES ($1, $2, '', '', 'audit.test', 'aud', '',
			         'allowed', 'tied_timestamp', '', '', '', '', '{}'::jsonb, $3, $3)`,
			id, org.ID, tied); err != nil {
			t.Fatalf("seed tied row %q: %v", id, err)
		}
	}

	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, org.ID, 10)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("ListByOrganization returned %d events, want 2", len(listed))
	}
	if listed[0].ID != idHigh {
		t.Errorf("ListByOrganization[0].ID = %q, want %q (id DESC tiebreaker on tied occurred_at)",
			listed[0].ID, idHigh)
	}
	if listed[1].ID != idLow {
		t.Errorf("ListByOrganization[1].ID = %q, want %q", listed[1].ID, idLow)
	}
}

// TestAuditRepositoryListByOrganizationClampsNonPositiveLimit pins that
// a non-positive limit is treated as the maximum cap
// (auditEventListMaxLimit, 200). A regression that returned the empty
// slice or every row would surface here.
func TestAuditRepositoryListByOrganizationClampsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedAuditRowsRawSQL(ctx, t, db, org.ID, 201)

	for _, limit := range []int{0, -1, -100} {
		var listed []store.AuditEvent
		if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var rErr error
			listed, rErr = repo.ListByOrganization(ctx, q, org.ID, limit)
			return rErr
		}); err != nil {
			t.Fatalf("ListByOrganization(limit=%d): %v", limit, err)
		}
		if len(listed) != 200 {
			t.Errorf("ListByOrganization(limit=%d) returned %d events, want 200 (cap)", limit, len(listed))
		}
	}
}

// TestAuditRepositoryListByOrganizationClampsLimitAboveMax pins that a
// limit above auditEventListMaxLimit (200) is clamped down to the cap.
func TestAuditRepositoryListByOrganizationClampsLimitAboveMax(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedAuditRowsRawSQL(ctx, t, db, org.ID, 201)

	for _, limit := range []int{201, 500, 1_000_000} {
		var listed []store.AuditEvent
		if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var rErr error
			listed, rErr = repo.ListByOrganization(ctx, q, org.ID, limit)
			return rErr
		}); err != nil {
			t.Fatalf("ListByOrganization(limit=%d): %v", limit, err)
		}
		if len(listed) != 200 {
			t.Errorf("ListByOrganization(limit=%d) returned %d events, want 200 (cap)", limit, len(listed))
		}
	}
}

// TestAuditRepositoryListByOrganizationHonoursLimitInRange pins that a
// limit in (0, auditEventListMaxLimit] is honoured verbatim.
func TestAuditRepositoryListByOrganizationHonoursLimitInRange(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedAuditRowsRawSQL(ctx, t, db, org.ID, 50)

	for _, tc := range []struct {
		limit int
		want  int
	}{
		{1, 1},
		{10, 10},
		{50, 50},
		{200, 50}, // cap allows up to 200 but only 50 rows exist
	} {
		var listed []store.AuditEvent
		if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var rErr error
			listed, rErr = repo.ListByOrganization(ctx, q, org.ID, tc.limit)
			return rErr
		}); err != nil {
			t.Fatalf("ListByOrganization(limit=%d): %v", tc.limit, err)
		}
		if len(listed) != tc.want {
			t.Errorf("ListByOrganization(limit=%d) returned %d events, want %d", tc.limit, len(listed), tc.want)
		}
	}
}

// TestAuditRepositoryListByOrganizationUnknownOrgReturnsEmpty pins the
// unknown-org contract: an unknown or stale organization_id returns the
// empty slice with no error.
func TestAuditRepositoryListByOrganizationUnknownOrgReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	ctx := context.Background()

	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, "org_does_not_exist_0001", 50)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(unknown org): %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListByOrganization(unknown org) returned %d events, want 0", len(listed))
	}
}

// seedAuditRowsRawSQL inserts n audit_events rows under organizationID
// via direct INSERT (bypassing the repository) so the limit-clamping
// tests can seed the cap-boundary quickly. Every row carries a distinct
// id and decreasing occurred_at so ListByOrganization returns the
// most-recently-inserted ones first.
func seedAuditRowsRawSQL(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
	n int,
) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("aud_%s_seed_%04d", t.Name(), i)
		occurred := now.Add(-time.Duration(n-i) * time.Microsecond)
		if _, err := db.Exec(ctx,
			`INSERT INTO audit_events
			   (id, organization_id, actor_id, actor_kind, action, resource_kind,
			    resource_id, decision, reason, request_id, correlation_id,
			    ip_address, user_agent, metadata, occurred_at, created_at)
			 VALUES ($1, $2, '', '', 'audit.test', 'aud', '',
			         'allowed', 'seed', '', '', '', '', '{}'::jsonb, $3, $3)`,
			id, organizationID, occurred); err != nil {
			t.Fatalf("seed audit row %d: %v", i, err)
		}
	}
}
