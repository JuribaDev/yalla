package store_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-invariants for the break_glass_sessions table
// (BE-0473). A break_glass_sessions row is the durable record of one
// internal-support session in which an admin uses their support capability
// to reach into another tenant. The BreakGlassRepository surface is
// intentionally narrow: Append writes a session inside a transaction, Get
// and ListByOrganization read tenant-scoped, and MarkRevoked is the only
// mutation -- a session's only legal state-transition is to be revoked
// early; otherwise it expires of its own accord. There is no per-row
// Delete: row removal is reachable only through ON DELETE CASCADE when
// the target tenant is deleted.
//
// What this file pins, and what it deliberately delegates:
//
//   - Append row-shape on the first call: a blank-id session mints an id
//     carrying the bgs_ prefix, the database stamps created_at /
//     updated_at within the same wallclock second of the call, version
//     starts at 1, RevokedAt / RevokedByID / RevokedByKind stay at the
//     zero values, the caller-supplied started_at / expires_at /
//     request_id / correlation_id / ip_address / user_agent round-trip
//     verbatim, and the return value's struct fields are byte-equal to a
//     raw-SQL re-load of the persisted row.
//   - Append id contract: a caller-supplied id is preserved verbatim, a
//     duplicate id surfaces as typed apierr.Conflict (PRIMARY KEY)
//     through mapWriteError.
//   - Append CHECK / FK violations surface as typed apierr.Conflict
//     through mapWriteError: an unknown organization (FK), a blank
//     actor_kind (CHECK actor_kind IN ('usr','sa')), a blank reason
//     (CHECK length(reason) > 0), and an expires_at not strictly after
//     started_at (CHECK expires_at > started_at).
//   - Append nil-Tx surfaces as typed apierr.Internal: a session row
//     must never be persisted outside the transaction that also carries
//     the sibling audit record.
//   - Append default StartedAt: a zero StartedAt is filled by the
//     repository to now() before insert, so the database CHECK on
//     expires_at > started_at is satisfied even for a caller that did
//     not pre-stamp started_at.
//   - Append transaction rollback semantics: a closure that returns an
//     error after a successful Append leaves no break_glass_sessions
//     row behind.
//   - Peer-row byte-identity: Append for one (organization, session)
//     tuple does not touch a sibling session row's id, organization_id,
//     actor_id, actor_kind, reason, started_at, expires_at, revoked_at,
//     revoked_by_id, revoked_by_kind, request_id, correlation_id,
//     ip_address, user_agent, version, created_at, or updated_at.
//   - Get lookup contracts: a persisted row reads back byte-identical
//     to the Append RETURNING projection; an unknown id surfaces as
//     typed apierr.NotFound (never as a 500 leaking the cause); a
//     cross-tenant (organization_id, id) tuple surfaces as typed
//     apierr.NotFound (the row is never an oracle that reveals
//     another tenant's session ids).
//   - Get returns expired-as-is: a session whose expires_at has elapsed
//     is still returned by Get -- expiration is observed by the caller
//     via session.Active(t), not by Get dropping the row.
//   - ListByOrganization ordering contract: rows are returned newest
//     first (started_at DESC, id DESC on tie).
//   - ListByOrganization limit clamping: a non-positive or above-cap
//     limit is silently clamped to breakGlassSessionListMaxLimit; an
//     in-range limit is honored verbatim.
//   - ListByOrganization unknown-org contract: a missing or
//     cross-tenant organizationID returns the empty (non-nil) slice,
//     never an error.
//   - MarkRevoked happy path: revoked_at / revoked_by_id /
//     revoked_by_kind move together inside the same tx, the
//     bump_version trigger increments version, the set_updated_at
//     trigger refreshes updated_at, and the row reads back
//     byte-identical to the RETURNING projection.
//   - MarkRevoked already-revoked: a second MarkRevoked against the
//     same id surfaces as typed apierr.Conflict and does not move
//     revoked_at / revoked_by_id / revoked_by_kind from their first
//     values.
//   - MarkRevoked cross-tenant / missing: a missing or cross-tenant
//     (organization_id, id) tuple surfaces as typed apierr.NotFound,
//     never an oracle that reveals another tenant's session ids.
//   - MarkRevoked nil-Tx surfaces as typed apierr.Internal.
//   - MarkRevoked peer-row byte-identity: revoking one session does
//     not touch a sibling session row.
//   - Append-mostly trigger enforcement: a raw-SQL UPDATE that rewrites
//     any column other than the revocation columns (id,
//     organization_id, actor_id, actor_kind, reason, started_at,
//     expires_at, request_id, correlation_id) is rejected by the
//     break_glass_sessions_reject_rewrite trigger with the
//     append-mostly restrict_violation. The blank-reason rewrite
//     is rejected by the same trigger's leading guard.
//   - Cascade delete: removing the target organization cascades
//     through break_glass_sessions (organization_id) ON DELETE CASCADE
//     -- a session row never survives its target tenant.
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - The pure validator (buildSessionToCreate) covers actor / reason /
//     TTL / actor_kind rejection at the service layer; it lives in
//     break_glass_internal_test.go and break_glass_canonical_test.go.
//   - The StartSession + Revoke service flows that join the session
//     row to its sibling audit record are pinned in break_glass_test.go.
//   - The HTTP wire shape of /v1/admin/break-glass and its policy
//     matrix are owned by httpapi/break_glass.go and the
//     admin_break_glass_*_policy_test files in internal/controlplane/policy.
//
// Helpers introduced here: rawBreakGlassRow, loadBreakGlassRowByID,
// countBreakGlassRowsForOrg, mintBreakGlassSessionID,
// breakGlassSessionFixture, seedBreakGlassSession,
// assertBreakGlassRowByteIdentical, breakGlassTxRollbackSentinel,
// sanitizeTestNameForBreakGlassID. Helpers reused from sibling files:
// seedOrg (schema_test.go); newStore (store_test.go); wantErrCode
// (idempotency_test.go).

// rawBreakGlassRow is the full break_glass_sessions row, deliberately
// loaded via raw SQL so the test can observe id, version, created_at,
// updated_at, the actor / target / revocation tuples, and the
// nullable revoked_at through the same shape the database stores them
// in.
type rawBreakGlassRow struct {
	ID                  string
	OrganizationID      string
	ActorID             string
	ActorKind           string
	ActorOrganizationID string
	Reason              string
	Status              store.BreakGlassSessionStatus
	StartedAt           time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
	RevokedByID         string
	RevokedByKind       string
	RequestID           string
	CorrelationID       string
	IPAddress           string
	UserAgent           string
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// loadBreakGlassRowByID reads the raw break_glass_sessions row for id
// and fatals on error. The lookup is by primary key, so no tenant scope
// is needed (raw loaders bypass repository scoping deliberately, so the
// test observes the persisted row exactly as the database stores it).
func loadBreakGlassRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawBreakGlassRow {
	t.Helper()
	var row rawBreakGlassRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, actor_id, actor_kind, actor_organization_id,
		        reason, status, started_at, expires_at, revoked_at, revoked_by_id, revoked_by_kind,
		        request_id, correlation_id, ip_address, user_agent,
		        version, created_at, updated_at
		   FROM break_glass_sessions
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.ActorID, &row.ActorKind, &row.ActorOrganizationID,
		&row.Reason, &row.Status, &row.StartedAt, &row.ExpiresAt, &row.RevokedAt, &row.RevokedByID, &row.RevokedByKind,
		&row.RequestID, &row.CorrelationID, &row.IPAddress, &row.UserAgent,
		&row.Version, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load break_glass_sessions id=%q: %v", id, err)
	}
	row.StartedAt = row.StartedAt.UTC()
	row.ExpiresAt = row.ExpiresAt.UTC()
	if row.RevokedAt != nil {
		t := row.RevokedAt.UTC()
		row.RevokedAt = &t
	}
	row.CreatedAt = row.CreatedAt.UTC()
	row.UpdatedAt = row.UpdatedAt.UTC()
	return row
}

// countBreakGlassRowsForOrg returns the number of break_glass_sessions
// rows owned by organizationID. It is the "did the rollback / cascade
// leave a row behind?" probe.
func countBreakGlassRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM break_glass_sessions WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count break_glass_sessions for org=%q: %v", organizationID, err)
	}
	return n
}

// mintBreakGlassSessionID builds a stable, test-local break-glass
// session id from the test name and a per-test suffix. Tests in
// store_test share a single package, so the test name keeps ids unique
// across parallel test cases without needing a shared atomic counter.
// Real id minting lives in BreakGlassRepository.Append (newBreakGlassID),
// so this is the test-local override that exercises the
// caller-supplied-id branch.
func mintBreakGlassSessionID(t *testing.T, suffix string) string {
	t.Helper()
	return "bgs_" + sanitizeTestNameForBreakGlassID(t.Name()) + "_" + suffix
}

// sanitizeTestNameForBreakGlassID strips slashes from a test name so an
// id derived from t.Name() in a nested subtest stays a single token.
// Subtest names contain '/' which would otherwise produce a multi-slash
// id and confuse debugging output. The drift_finding test file uses an
// identically-shaped helper (sanitizeTestNameForDriftID); naming them
// per-file keeps the store_test package free of collisions.
func sanitizeTestNameForBreakGlassID(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '/' {
			out = append(out, '_')
			continue
		}
		out = append(out, b)
	}
	return string(out)
}

// breakGlassTxRollbackSentinel is the sentinel error a closure returns
// to trigger Store.Write's rollback path. It is a uniquely-typed
// sentinel for this file -- every *_test.go under
// internal/controlplane/store/ shares the same store_test package, so
// each file's rollback sentinel needs a unique type to avoid a name
// collision with siblings (driftFindingTxRollbackSentinel,
// jobAttemptTxRollbackSentinel, idempotencyTxRollbackSentinel, ...).
type breakGlassTxRollbackSentinel struct{}

func (breakGlassTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this break-glass session transaction"
}

// breakGlassSessionFixture returns a known-good BreakGlassSession
// targeting target with actorOrg as the support principal's home
// organization. Callers override individual fields as needed. The
// fixture is large because the table carries many forensic columns
// (request_id, correlation_id, ip_address, user_agent) that every
// real write populates, and tests need a single source of truth for
// the baseline shape.
func breakGlassSessionFixture(
	target testutil.Organization,
	actorOrg testutil.Organization,
	suffix string,
	startedAt time.Time,
	ttl time.Duration,
) store.BreakGlassSession {
	return store.BreakGlassSession{
		OrganizationID:      target.ID,
		ActorID:             "usr_admin_" + suffix,
		ActorKind:           "usr",
		ActorOrganizationID: actorOrg.ID,
		Reason:              "INCIDENT-" + suffix + ": fixture justification",
		StartedAt:           startedAt,
		ExpiresAt:           startedAt.Add(ttl),
		RequestID:           "req_bg_" + suffix,
		CorrelationID:       "cor_bg_" + suffix,
		IPAddress:           "10.0.0.42",
		UserAgent:           "yalla-admin-cli/1.0",
	}
}

// seedBreakGlassSession appends s through the repository's Append and
// fatals on error. It is the smallest happy-path closure and is reused
// by every test that does not need to observe the call's tx in
// isolation.
func seedBreakGlassSession(
	ctx context.Context,
	t *testing.T,
	st *store.Store,
	repo *store.BreakGlassRepository,
	s store.BreakGlassSession,
) store.BreakGlassSession {
	t.Helper()
	var created store.BreakGlassSession
	if err := st.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, aErr := repo.Append(ctx, tx, s)
		if aErr != nil {
			return aErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("seed break-glass session: %v", err)
	}
	return created
}

// assertBreakGlassRowByteIdentical asserts every column of after equals
// the corresponding column of baseline. The nullable revoked_at column
// is switched on pointer nil-ness first so a regression that flipped a
// NULL to a zero-value timestamp (or vice versa) is caught explicitly
// rather than silently round-tripping.
func assertBreakGlassRowByteIdentical(t *testing.T, label string, baseline, after rawBreakGlassRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: id drift baseline=%q after=%q", label, baseline.ID, after.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: organization_id drift baseline=%q after=%q", label, baseline.OrganizationID, after.OrganizationID)
	}
	if after.ActorID != baseline.ActorID {
		t.Errorf("%s: actor_id drift baseline=%q after=%q", label, baseline.ActorID, after.ActorID)
	}
	if after.ActorKind != baseline.ActorKind {
		t.Errorf("%s: actor_kind drift baseline=%q after=%q", label, baseline.ActorKind, after.ActorKind)
	}
	if after.ActorOrganizationID != baseline.ActorOrganizationID {
		t.Errorf("%s: actor_organization_id drift baseline=%q after=%q", label, baseline.ActorOrganizationID, after.ActorOrganizationID)
	}
	if after.Reason != baseline.Reason {
		t.Errorf("%s: reason drift baseline=%q after=%q", label, baseline.Reason, after.Reason)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: status drift baseline=%q after=%q", label, baseline.Status, after.Status)
	}
	if !after.StartedAt.Equal(baseline.StartedAt) {
		t.Errorf("%s: started_at drift baseline=%s after=%s", label, baseline.StartedAt, after.StartedAt)
	}
	if !after.ExpiresAt.Equal(baseline.ExpiresAt) {
		t.Errorf("%s: expires_at drift baseline=%s after=%s", label, baseline.ExpiresAt, after.ExpiresAt)
	}
	assertTimePtrEqual(t, label+".revoked_at", baseline.RevokedAt, after.RevokedAt)
	if after.RevokedByID != baseline.RevokedByID {
		t.Errorf("%s: revoked_by_id drift baseline=%q after=%q", label, baseline.RevokedByID, after.RevokedByID)
	}
	if after.RevokedByKind != baseline.RevokedByKind {
		t.Errorf("%s: revoked_by_kind drift baseline=%q after=%q", label, baseline.RevokedByKind, after.RevokedByKind)
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: request_id drift baseline=%q after=%q", label, baseline.RequestID, after.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: correlation_id drift baseline=%q after=%q", label, baseline.CorrelationID, after.CorrelationID)
	}
	if after.IPAddress != baseline.IPAddress {
		t.Errorf("%s: ip_address drift baseline=%q after=%q", label, baseline.IPAddress, after.IPAddress)
	}
	if after.UserAgent != baseline.UserAgent {
		t.Errorf("%s: user_agent drift baseline=%q after=%q", label, baseline.UserAgent, after.UserAgent)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: version drift baseline=%d after=%d", label, baseline.Version, after.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: created_at drift baseline=%s after=%s", label, baseline.CreatedAt, after.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: updated_at drift baseline=%s after=%s", label, baseline.UpdatedAt, after.UpdatedAt)
	}
}

// twoOrgs returns one target org and one actor org for break-glass
// fixtures. A break-glass row points at one tenant (the target) and the
// actor lives in a different tenant (a Yalla support principal), so
// every test that touches a session row needs at least two
// organizations seeded.
func twoOrgs(t *testing.T, db *testutil.DB, f *testutil.Factory, label string) (testutil.Organization, testutil.Organization) {
	t.Helper()
	return seedOrg(t, db, f, label+"Target"), seedOrg(t, db, f, label+"Support")
}

// ---------------------------------------------------------------------------
// Append: row-shape and id contract
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryAppendMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGShape")

	// Wallclock window is bounded by ±2s margins to absorb clock skew
	// between the test runner and the Postgres container (the database
	// stamps created_at via now() inside the INSERT).
	before := time.Now().UTC().Add(-2 * time.Second)
	started := before.Add(-time.Minute)
	fixture := breakGlassSessionFixture(target, actor, "shape", started, 15*time.Minute)
	fixture.ID = "" // force the repo to mint an id

	created := seedBreakGlassSession(ctx, t, s, repo, fixture)
	after := time.Now().UTC().Add(2 * time.Second)

	if !strings.HasPrefix(created.ID, "bgs_") {
		t.Errorf("ID = %q, want bgs_ prefix", created.ID)
	}
	if got := len(created.ID); got <= len("bgs_") {
		t.Errorf("ID length = %d, want > %d (random suffix)", got, len("bgs_"))
	}
	if created.OrganizationID != target.ID {
		t.Errorf("OrganizationID = %q, want %q", created.OrganizationID, target.ID)
	}
	if created.ActorID != fixture.ActorID {
		t.Errorf("ActorID = %q, want %q", created.ActorID, fixture.ActorID)
	}
	if created.ActorKind != "usr" {
		t.Errorf("ActorKind = %q, want %q", created.ActorKind, "usr")
	}
	if created.ActorOrganizationID != actor.ID {
		t.Errorf("ActorOrganizationID = %q, want %q", created.ActorOrganizationID, actor.ID)
	}
	if created.Reason != fixture.Reason {
		t.Errorf("Reason = %q, want %q", created.Reason, fixture.Reason)
	}
	if !created.StartedAt.Equal(started) {
		t.Errorf("StartedAt = %s, want %s", created.StartedAt, started)
	}
	if !created.ExpiresAt.Equal(fixture.ExpiresAt) {
		t.Errorf("ExpiresAt = %s, want %s", created.ExpiresAt, fixture.ExpiresAt)
	}
	if created.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil for a fresh session", created.RevokedAt)
	}
	if created.RevokedByID != "" {
		t.Errorf("RevokedByID = %q, want empty for a fresh session", created.RevokedByID)
	}
	if created.RevokedByKind != "" {
		t.Errorf("RevokedByKind = %q, want empty for a fresh session", created.RevokedByKind)
	}
	if created.RequestID != fixture.RequestID {
		t.Errorf("RequestID = %q, want %q", created.RequestID, fixture.RequestID)
	}
	if created.CorrelationID != fixture.CorrelationID {
		t.Errorf("CorrelationID = %q, want %q", created.CorrelationID, fixture.CorrelationID)
	}
	if created.IPAddress != fixture.IPAddress {
		t.Errorf("IPAddress = %q, want %q", created.IPAddress, fixture.IPAddress)
	}
	if created.UserAgent != fixture.UserAgent {
		t.Errorf("UserAgent = %q, want %q", created.UserAgent, fixture.UserAgent)
	}
	if created.Version != 1 {
		t.Errorf("Version = %d, want 1 on insert", created.Version)
	}
	if created.CreatedAt.Before(before) || created.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %s, want within [%s, %s]", created.CreatedAt, before, after)
	}
	if !created.UpdatedAt.Equal(created.CreatedAt) {
		t.Errorf("UpdatedAt = %s, want = CreatedAt = %s on insert", created.UpdatedAt, created.CreatedAt)
	}

	// Raw-SQL re-load should be byte-equal to the RETURNING projection.
	rawAfter := loadBreakGlassRowByID(ctx, t, db, created.ID)
	baseline := rawBreakGlassRow{
		ID:                  created.ID,
		OrganizationID:      created.OrganizationID,
		ActorID:             created.ActorID,
		ActorKind:           created.ActorKind,
		ActorOrganizationID: created.ActorOrganizationID,
		Reason:              created.Reason,
		Status:              created.Status,
		StartedAt:           created.StartedAt,
		ExpiresAt:           created.ExpiresAt,
		RevokedAt:           nil,
		RevokedByID:         created.RevokedByID,
		RevokedByKind:       created.RevokedByKind,
		RequestID:           created.RequestID,
		CorrelationID:       created.CorrelationID,
		IPAddress:           created.IPAddress,
		UserAgent:           created.UserAgent,
		Version:             created.Version,
		CreatedAt:           created.CreatedAt,
		UpdatedAt:           created.UpdatedAt,
	}
	assertBreakGlassRowByteIdentical(t, "Append RETURNING vs raw SQL re-load", baseline, rawAfter)
}

func TestBreakGlassRepositoryAppendCallerSuppliedIDIsPreserved(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGSuppliedID")

	id := mintBreakGlassSessionID(t, "supplied")
	started := time.Now().UTC().Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(target, actor, "supplied", started, 10*time.Minute)
	fixture.ID = id

	created := seedBreakGlassSession(ctx, t, s, repo, fixture)
	if created.ID != id {
		t.Errorf("ID = %q, want %q (caller-supplied id must be preserved verbatim)", created.ID, id)
	}
}

func TestBreakGlassRepositoryAppendDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGDupID")

	id := mintBreakGlassSessionID(t, "dup")
	started := time.Now().UTC().Truncate(time.Microsecond)
	first := breakGlassSessionFixture(target, actor, "dup1", started, 10*time.Minute)
	first.ID = id
	_ = seedBreakGlassSession(ctx, t, s, repo, first)

	second := breakGlassSessionFixture(target, actor, "dup2", started.Add(time.Second), 10*time.Minute)
	second.ID = id

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, second)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestBreakGlassRepositoryAppendStartedAtDefaultsToNow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGDefaultStart")

	// Caller leaves StartedAt zero. Repository must fill it with now()
	// so the CHECK expires_at > started_at is satisfied. expires_at is
	// set to a far-future time so the CHECK does not depend on the
	// repo's exact fill value.
	fixture := breakGlassSessionFixture(target, actor, "now", time.Time{}, 0)
	fixture.StartedAt = time.Time{}
	fixture.ExpiresAt = time.Now().UTC().Add(time.Hour)

	// Wallclock window is bounded by ±2s margins to absorb clock skew
	// between the test runner and the Postgres container (the
	// repository fills StartedAt with time.Now().UTC() before insert).
	before := time.Now().UTC().Add(-2 * time.Second)
	created := seedBreakGlassSession(ctx, t, s, repo, fixture)
	after := time.Now().UTC().Add(2 * time.Second)

	if created.StartedAt.IsZero() {
		t.Fatal("StartedAt is zero, want repository to fill it with now()")
	}
	if created.StartedAt.Before(before) || created.StartedAt.After(after) {
		t.Errorf("StartedAt = %s, want within [%s, %s]", created.StartedAt, before, after)
	}
}

// ---------------------------------------------------------------------------
// Append: error contracts (FK, CHECK, nil-Tx, rollback)
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryAppendUnknownOrganizationIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	_, actor := twoOrgs(t, db, f, "BGUnknownOrg")
	ghost := testutil.Organization{ID: "org_does_not_exist", Slug: "ghost"}
	started := time.Now().UTC().Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(ghost, actor, "ghost", started, 5*time.Minute)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, fixture)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestBreakGlassRepositoryAppendBlankActorKindIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGBlankKind")
	started := time.Now().UTC().Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(target, actor, "blankkind", started, 5*time.Minute)
	fixture.ActorKind = "" // CHECK actor_kind IN ('usr','sa')

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, fixture)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestBreakGlassRepositoryAppendUnknownActorKindIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGUnknownKind")
	started := time.Now().UTC().Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(target, actor, "unknownkind", started, 5*time.Minute)
	fixture.ActorKind = "robot" // not in {usr, sa}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, fixture)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestBreakGlassRepositoryAppendBlankReasonIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGBlankReason")
	started := time.Now().UTC().Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(target, actor, "blankreason", started, 5*time.Minute)
	fixture.Reason = "" // CHECK length(reason) > 0

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, fixture)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestBreakGlassRepositoryAppendExpiresAtNotAfterStartedAtIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGExpiresEq")

	started := time.Now().UTC().Truncate(time.Microsecond)
	cases := []struct {
		name      string
		expiresAt time.Time
	}{
		{"expires_at equals started_at", started},
		{"expires_at predates started_at", started.Add(-time.Minute)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := breakGlassSessionFixture(target, actor, "expiresEq", started, 0)
			fixture.StartedAt = started
			fixture.ExpiresAt = tc.expiresAt

			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, aErr := repo.Append(ctx, tx, fixture)
				return aErr
			})
			wantErrCode(t, err, yerr.CodeConflict)
		})
	}
}

func TestBreakGlassRepositoryAppendNilTxIsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewBreakGlassRepository()
	started := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repo.Append(context.Background(), nil, store.BreakGlassSession{
		OrganizationID:      "org_x",
		ActorID:             "usr_a",
		ActorKind:           "usr",
		ActorOrganizationID: "org_actor",
		Reason:              "x",
		StartedAt:           started,
		ExpiresAt:           started.Add(time.Minute),
	})
	wantErrCode(t, err, yerr.CodeInternal)
}

func TestBreakGlassRepositoryAppendTransactionRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGRollback")

	sentinel := breakGlassTxRollbackSentinel{}
	started := time.Now().UTC().Truncate(time.Microsecond)
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, breakGlassSessionFixture(target, actor, "rollback", started, 5*time.Minute))
		if aErr != nil {
			return aErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the rollback sentinel", err)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, target.ID); got != 0 {
		t.Errorf("rollback left %d break_glass_sessions rows behind, want 0", got)
	}
}

func TestBreakGlassRepositoryAppendPeerRowByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGPeerAppend")

	started := time.Now().UTC().Truncate(time.Microsecond)
	peer := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "peer", started, 10*time.Minute))
	peerBaseline := loadBreakGlassRowByID(ctx, t, db, peer.ID)

	_ = seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "second", started.Add(time.Second), 10*time.Minute))

	peerAfter := loadBreakGlassRowByID(ctx, t, db, peer.ID)
	assertBreakGlassRowByteIdentical(t, "peer-row after sibling Append", peerBaseline, peerAfter)
}

// ---------------------------------------------------------------------------
// Get: round-trip, not-found, cross-tenant, expired-as-is
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryGetReadsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGGet")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "get", started, 10*time.Minute))

	var got store.BreakGlassSession
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row, gErr := repo.Get(ctx, q, target.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %q, want %q", got.ID, created.ID)
	}
	if !got.StartedAt.Equal(created.StartedAt) {
		t.Errorf("StartedAt drift Get=%s Append=%s", got.StartedAt, created.StartedAt)
	}
	if !got.ExpiresAt.Equal(created.ExpiresAt) {
		t.Errorf("ExpiresAt drift Get=%s Append=%s", got.ExpiresAt, created.ExpiresAt)
	}
	if got.Version != created.Version {
		t.Errorf("Version drift Get=%d Append=%d", got.Version, created.Version)
	}
}

func TestBreakGlassRepositoryGetUnknownIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, _ := twoOrgs(t, db, f, "BGGetUnknown")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.Get(ctx, q, target.ID, "bgs_does_not_exist")
		return gErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestBreakGlassRepositoryGetCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGGetXTenant")
	other := seedOrg(t, db, f, "BGGetXTenantOther")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "xt", started, 10*time.Minute))

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.Get(ctx, q, other.ID, created.ID)
		return gErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestBreakGlassRepositoryGetExpiredReturnsRowAsIs(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGGetExpired")

	// Schedule a 1-second session that has elapsed by the time Get runs.
	started := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	fixture := breakGlassSessionFixture(target, actor, "expired", started, time.Minute)
	created := seedBreakGlassSession(ctx, t, s, repo, fixture)

	var got store.BreakGlassSession
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row, gErr := repo.Get(ctx, q, target.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("Get on expired session returned error %v, want the row as-is", err)
	}
	if got.ID != created.ID {
		t.Errorf("expired Get ID = %q, want %q", got.ID, created.ID)
	}
	if got.Active(time.Now().UTC()) {
		t.Errorf("expired session Active(now)=true, want false (expires_at was %s, started_at was %s)",
			got.ExpiresAt, got.StartedAt)
	}
}

// ---------------------------------------------------------------------------
// ListByOrganization: ordering, limit clamping, unknown-org
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryListByOrganizationOrdersNewestFirst(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGList")

	base := time.Now().UTC().Truncate(time.Microsecond)
	first := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "a", base, 10*time.Minute))
	second := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "b", base.Add(2*time.Second), 10*time.Minute))
	third := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "c", base.Add(1*time.Second), 10*time.Minute))

	var rows []store.BreakGlassSession
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		out, lErr := repo.ListByOrganization(ctx, q, target.ID, 10)
		if lErr != nil {
			return lErr
		}
		rows = out
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	// Expected order: second (latest), third, first.
	want := []string{second.ID, third.ID, first.ID}
	for i, id := range want {
		if rows[i].ID != id {
			t.Errorf("rows[%d].ID = %q, want %q", i, rows[i].ID, id)
		}
	}
}

func TestBreakGlassRepositoryListByOrganizationClampsLimit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGListClamp")

	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		_ = seedBreakGlassSession(ctx, t, s, repo,
			breakGlassSessionFixture(target, actor, "c"+strconv.Itoa(i), base.Add(time.Duration(i)*time.Second), 10*time.Minute))
	}

	cases := []struct {
		name  string
		limit int
		want  int
	}{
		{"non-positive clamped to cap", 0, 3},
		{"negative clamped to cap", -10, 3},
		{"above cap clamped to cap returns all", 5000, 3},
		{"explicit small limit honored", 2, 2},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var rows []store.BreakGlassSession
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				out, lErr := repo.ListByOrganization(ctx, q, target.ID, tc.limit)
				if lErr != nil {
					return lErr
				}
				rows = out
				return nil
			}); err != nil {
				t.Fatalf("ListByOrganization: %v", err)
			}
			if len(rows) != tc.want {
				t.Errorf("len(rows) = %d, want %d (limit=%d)", len(rows), tc.want, tc.limit)
			}
		})
	}
}

func TestBreakGlassRepositoryListByOrganizationUnknownOrgIsEmptySlice(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	ctx := context.Background()

	var rows []store.BreakGlassSession
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		out, lErr := repo.ListByOrganization(ctx, q, "org_does_not_exist", 50)
		if lErr != nil {
			return lErr
		}
		rows = out
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if rows == nil {
		t.Fatalf("rows is nil, want non-nil empty slice")
	}
	if len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}

// ---------------------------------------------------------------------------
// MarkRevoked: happy path, conflict, not-found, nil-tx, peer-row
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryMarkRevokedHappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGRevoke")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "revoke", started, 30*time.Minute))
	baseline := loadBreakGlassRowByID(ctx, t, db, created.ID)

	revokedAt := started.Add(5 * time.Minute)
	var revoked store.BreakGlassSession
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, rErr := repo.MarkRevoked(ctx, tx, target.ID, created.ID, "usr_revoker", "usr", revokedAt)
		if rErr != nil {
			return rErr
		}
		revoked = row
		return nil
	}); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}

	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %s", revoked.RevokedAt, revokedAt)
	}
	if revoked.RevokedByID != "usr_revoker" {
		t.Errorf("RevokedByID = %q, want usr_revoker", revoked.RevokedByID)
	}
	if revoked.RevokedByKind != "usr" {
		t.Errorf("RevokedByKind = %q, want usr", revoked.RevokedByKind)
	}
	if revoked.Version != baseline.Version+1 {
		t.Errorf("Version = %d, want %d (bump_version trigger should advance by 1)",
			revoked.Version, baseline.Version+1)
	}
	if !revoked.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("UpdatedAt = %s, want strictly after baseline %s (set_updated_at trigger)",
			revoked.UpdatedAt, baseline.UpdatedAt)
	}

	// Raw-SQL re-load must match the RETURNING projection byte for byte
	// on every column.
	rawAfter := loadBreakGlassRowByID(ctx, t, db, created.ID)
	rawRevokedAt := revokedAt
	wantBaseline := rawBreakGlassRow{
		ID:                  revoked.ID,
		OrganizationID:      revoked.OrganizationID,
		ActorID:             revoked.ActorID,
		ActorKind:           revoked.ActorKind,
		ActorOrganizationID: revoked.ActorOrganizationID,
		Reason:              revoked.Reason,
		Status:              revoked.Status,
		StartedAt:           revoked.StartedAt,
		ExpiresAt:           revoked.ExpiresAt,
		RevokedAt:           &rawRevokedAt,
		RevokedByID:         revoked.RevokedByID,
		RevokedByKind:       revoked.RevokedByKind,
		RequestID:           revoked.RequestID,
		CorrelationID:       revoked.CorrelationID,
		IPAddress:           revoked.IPAddress,
		UserAgent:           revoked.UserAgent,
		Version:             revoked.Version,
		CreatedAt:           revoked.CreatedAt,
		UpdatedAt:           revoked.UpdatedAt,
	}
	assertBreakGlassRowByteIdentical(t, "MarkRevoked RETURNING vs raw SQL re-load", wantBaseline, rawAfter)
}

func TestBreakGlassRepositoryMarkRevokedAlreadyRevokedIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGRevokeTwice")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "twice", started, 30*time.Minute))

	revokedAt := started.Add(5 * time.Minute)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, target.ID, created.ID, "usr_first", "usr", revokedAt)
		return rErr
	}); err != nil {
		t.Fatalf("first MarkRevoked: %v", err)
	}
	firstRaw := loadBreakGlassRowByID(ctx, t, db, created.ID)

	// Second MarkRevoked must surface as a typed Conflict and must NOT
	// move revoked_at / revoked_by_* from their first values.
	secondErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, target.ID, created.ID, "usr_second", "usr", revokedAt.Add(time.Minute))
		return rErr
	})
	wantErrCode(t, secondErr, yerr.CodeConflict)

	secondRaw := loadBreakGlassRowByID(ctx, t, db, created.ID)
	assertBreakGlassRowByteIdentical(t, "row after rejected second MarkRevoked", firstRaw, secondRaw)
}

func TestBreakGlassRepositoryMarkRevokedUnknownIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, _ := twoOrgs(t, db, f, "BGRevokeUnknown")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, target.ID, "bgs_does_not_exist", "usr_revoker", "usr", time.Now().UTC())
		return rErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestBreakGlassRepositoryMarkRevokedCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGRevokeXTenant")
	other := seedOrg(t, db, f, "BGRevokeXTenantOther")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "xtenant", started, 30*time.Minute))
	baseline := loadBreakGlassRowByID(ctx, t, db, created.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, other.ID, created.ID, "usr_revoker", "usr", started.Add(time.Minute))
		return rErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	// The cross-tenant attempt must not have touched the row.
	after := loadBreakGlassRowByID(ctx, t, db, created.ID)
	assertBreakGlassRowByteIdentical(t, "row after cross-tenant MarkRevoked NotFound", baseline, after)
}

func TestBreakGlassRepositoryMarkRevokedNilTxIsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewBreakGlassRepository()
	_, err := repo.MarkRevoked(context.Background(), nil, "org_x", "bgs_x", "usr_a", "usr", time.Now().UTC())
	wantErrCode(t, err, yerr.CodeInternal)
}

func TestBreakGlassRepositoryMarkRevokedPeerRowIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGRevokePeer")

	base := time.Now().UTC().Truncate(time.Microsecond)
	subject := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "subject", base, 30*time.Minute))
	peer := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "peer", base.Add(time.Second), 30*time.Minute))
	peerBaseline := loadBreakGlassRowByID(ctx, t, db, peer.ID)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkRevoked(ctx, tx, target.ID, subject.ID, "usr_revoker", "usr", base.Add(5*time.Minute))
		return rErr
	}); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}

	peerAfter := loadBreakGlassRowByID(ctx, t, db, peer.ID)
	assertBreakGlassRowByteIdentical(t, "peer-row after sibling MarkRevoked", peerBaseline, peerAfter)
}

// ---------------------------------------------------------------------------
// Append-mostly trigger: only revocation columns are mutable
// ---------------------------------------------------------------------------

// TestBreakGlassRepositoryAppendMostlyTriggerRejectsColumnRewrites walks
// every column the break_glass_sessions_reject_rewrite trigger names in
// its predicate (id, organization_id, actor_id, actor_kind, reason,
// started_at, expires_at, request_id, correlation_id) and asserts a raw
// SQL UPDATE rewriting that column is rejected with the append-mostly
// restrict_violation. A regression that demoted the trigger to any one
// column would surface as a per-case failure here, even if the existing
// TestBreakGlassSchemaRejectsUpdateToImmutableColumns test (which only
// covers reason) continued to pass.
func TestBreakGlassRepositoryAppendMostlyTriggerRejectsColumnRewrites(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGImmut")
	other := seedOrg(t, db, f, "BGImmutOther")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "immut", started, 30*time.Minute))
	baseline := loadBreakGlassRowByID(ctx, t, db, created.ID)

	cases := []struct {
		name     string
		sql      string
		argument any
	}{
		{"id rewrite", `UPDATE break_glass_sessions SET id = $2 WHERE id = $1`, "bgs_rewritten"},
		{"organization_id rewrite", `UPDATE break_glass_sessions SET organization_id = $2 WHERE id = $1`, other.ID},
		{"actor_id rewrite", `UPDATE break_glass_sessions SET actor_id = $2 WHERE id = $1`, "usr_someone_else"},
		{"actor_kind rewrite", `UPDATE break_glass_sessions SET actor_kind = $2 WHERE id = $1`, "sa"},
		{"reason rewrite", `UPDATE break_glass_sessions SET reason = $2 WHERE id = $1`, "rewritten reason"},
		{"started_at rewrite", `UPDATE break_glass_sessions SET started_at = $2 WHERE id = $1`, started.Add(time.Hour)},
		{"expires_at rewrite", `UPDATE break_glass_sessions SET expires_at = $2 WHERE id = $1`, started.Add(7 * 24 * time.Hour)},
		{"request_id rewrite", `UPDATE break_glass_sessions SET request_id = $2 WHERE id = $1`, "req_rewritten"},
		{"correlation_id rewrite", `UPDATE break_glass_sessions SET correlation_id = $2 WHERE id = $1`, "cor_rewritten"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(ctx, tc.sql, created.ID, tc.argument); err == nil {
				t.Fatalf("UPDATE (%s) succeeded, want rejected by the append-mostly trigger", tc.name)
			} else if !strings.Contains(err.Error(), "append-mostly") {
				t.Fatalf("UPDATE (%s) error = %v, want message mentioning append-mostly", tc.name, err)
			}
			after := loadBreakGlassRowByID(ctx, t, db, created.ID)
			assertBreakGlassRowByteIdentical(t, "row after rejected "+tc.name, baseline, after)
		})
	}
}

// TestBreakGlassRepositoryAppendMostlyTriggerRejectsBlankReason pins the
// trigger's leading guard: a raw UPDATE that blanks reason is rejected
// even though it does not rewrite any other immutable column.
func TestBreakGlassRepositoryAppendMostlyTriggerRejectsBlankReason(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGBlankReasonImmut")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "blank", started, 30*time.Minute))
	baseline := loadBreakGlassRowByID(ctx, t, db, created.ID)

	_, err := db.Exec(ctx, `UPDATE break_glass_sessions SET reason = '' WHERE id = $1`, created.ID)
	if err == nil {
		t.Fatal("UPDATE blanking reason succeeded, want rejected by the trigger")
	}
	if !strings.Contains(err.Error(), "must remain set") {
		t.Fatalf("UPDATE blanking reason error = %v, want message mentioning 'must remain set'", err)
	}

	after := loadBreakGlassRowByID(ctx, t, db, created.ID)
	assertBreakGlassRowByteIdentical(t, "row after rejected blank-reason UPDATE", baseline, after)
}

// ---------------------------------------------------------------------------
// Cascade delete from organization
// ---------------------------------------------------------------------------

func TestBreakGlassRepositoryCascadeDeleteOnOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewBreakGlassRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actor := twoOrgs(t, db, f, "BGCascade")

	started := time.Now().UTC().Truncate(time.Microsecond)
	_ = seedBreakGlassSession(ctx, t, s, repo, breakGlassSessionFixture(target, actor, "cascade", started, 30*time.Minute))
	if got := countBreakGlassRowsForOrg(ctx, t, db, target.ID); got != 1 {
		t.Fatalf("pre-delete count = %d, want 1", got)
	}
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, target.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}
	if got := countBreakGlassRowsForOrg(ctx, t, db, target.ID); got != 0 {
		t.Errorf("post-delete count = %d, want 0 (cascade)", got)
	}
}
