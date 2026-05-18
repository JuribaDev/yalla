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

// Repository-layer CRUD-and-invariants for the drift_findings table
// (BE-0471). A drift_findings row is one detected divergence between
// Yalla's desired state and Dokploy's actual state, recorded for
// operator triage. The DriftFindingRepository surface is intentionally
// narrow: Append writes a finding inside a transaction, GetByID and
// ListByOrganization read tenant-scoped, and MarkResolved is the one
// mutation -- a finding's only legal state-transition is to be
// resolved. There is no per-row Delete in this surface: row removal is
// reachable only through ON DELETE CASCADE when the parent
// organization (or any scoped parent) is removed.
//
// What this file pins, and what it deliberately delegates:
//
//   - Append row-shape on the first call: a blank-id finding mints an id
//     carrying the drft_ prefix, optional resource legs stay at the zero
//     string when not supplied (the column is SQL NULL on disk, the Go
//     struct surfaces "" because the read projects NULL onto the zero
//     value), the database stamps created_at / updated_at within the
//     same wallclock second of the call, the caller-supplied
//     detected_at round-trips verbatim, and ResolvedAt / ResolvedByActor
//     stay at the zero value because an open finding is the only legal
//     lifecycle entry point. The return value's struct fields are
//     byte-equal to a raw-SQL re-load of the persisted row.
//   - Append id contract: a caller-supplied id is preserved verbatim, a
//     duplicate id surfaces as typed apierr.Conflict (PRIMARY KEY)
//     through mapWriteError.
//   - Append CHECK / FK violations surface as typed apierr.Conflict
//     through mapWriteError: an unknown organization, an unknown /
//     cross-tenant project_id / environment_id / service_id /
//     service_domain_id (each composite FK pins the leg to the
//     organization).
//   - Append application-layer validation: missing organization_id /
//     kind / reason / level, an unknown taxonomy value, a zero
//     detected_at, a non-nil resolved_at at append time, and a
//     non-empty resolved_by_actor_id at append time all surface as
//     typed apierr.InvalidInput before the database is touched.
//   - Append nil-Tx surfaces as typed apierr.Internal: a finding must
//     never be persisted outside the transaction that may also carry
//     its sibling audit record.
//   - Append transaction rollback semantics: a closure that returns an
//     error after a successful Append leaves no drift_findings row
//     behind.
//   - Peer-row byte-identity: Append for one (organization, finding)
//     tuple does not touch a sibling finding row's id, detected_at,
//     created_at, updated_at, resolved_at, resolved_by_actor_id, kind,
//     reason, level, env_var_key, dokploy_resource_id, or
//     parent_dokploy_id.
//   - GetByID lookup contracts: a persisted row reads back byte-identical
//     to the Append RETURNING projection; an unknown id surfaces as
//     typed apierr.NotFound (never as a 500 leaking the cause); the row
//     is never an oracle that reveals another tenant's finding ids.
//   - ListByOrganization ordering contract: rows are returned newest
//     first (detected_at DESC, id DESC on tie).
//   - ListByOrganization limit clamping: a non-positive or above-cap
//     limit is silently clamped to driftFindingListMaxLimit; an
//     in-range limit is honored verbatim.
//   - ListByOrganization unknown-org contract: a missing or
//     cross-tenant organizationID returns the empty slice, never an
//     error.
//   - MarkResolved happy path: the resolved_at / resolved_by_actor_id
//     columns move together inside the same tx, updated_at is
//     refreshed by the trigger, and the row reads back byte-identical
//     to the RETURNING projection.
//   - MarkResolved already-resolved: a second MarkResolved against the
//     same id surfaces as typed apierr.Conflict and does not move
//     resolved_at / resolved_by_actor_id from their first values.
//   - MarkResolved cross-tenant / missing: a missing or cross-tenant
//     (organization_id, id) tuple surfaces as typed apierr.NotFound,
//     never an oracle that reveals another tenant's finding ids.
//   - MarkResolved validation: blank organization_id / id /
//     resolved_by_actor_id and a zero resolved_at surface as typed
//     apierr.InvalidInput before any database work.
//   - MarkResolved peer-row byte-identity: resolving one finding does
//     not touch a sibling finding row.
//   - Cascade delete: removing the parent organization cascades through
//     drift_findings (organization_id) ON DELETE CASCADE -- a finding
//     row never survives its parent tenant. Removing a parent project /
//     environment / service / service_domain cascades through the
//     respective composite FK.
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - Cross-tenant List leak under cross-organization read scenarios is
//     the BE-0472 sibling tenant-isolation story and lives in the future
//     drift_finding_repository_tenant_isolation_test.go.
//   - The HTTP wire shape of the future GET /v1/admin/dokploy/drift
//     endpoint, its policy matrix, and its OpenAPI contract are owned
//     by future drift-findings HTTP stories.
//
// Helpers introduced here: rawDriftFindingRow, loadDriftFindingRowByID,
// countDriftFindingRowsForOrg, mintDriftFindingID, seedDriftFinding,
// driftFindingTxRollbackSentinel, driftFindingFixture,
// assertDriftFindingByteIdentical. Helpers reused from sibling files:
// seedOrg, seedProject, seedEnvironment, seedService (schema_test.go);
// newStore (store_test.go); wantErrCode (idempotency_test.go).

// rawDriftFindingRow is the full drift_findings row, deliberately loaded
// via raw SQL so the test can observe id, created_at, updated_at, the
// closed-set kind / reason / level columns, the nullable optional
// resource legs, and the resolution columns through the same shape the
// database stores them in.
type rawDriftFindingRow struct {
	ID                string
	OrganizationID    string
	Kind              string
	Reason            string
	Level             string
	ProjectID         *string
	EnvironmentID     *string
	ServiceID         *string
	ServiceDomainID   *string
	EnvVarKey         string
	DokployResourceID string
	ParentDokployID   string
	RequestID         string
	CorrelationID     string
	DetectedAt        time.Time
	ResolvedAt        *time.Time
	ResolvedByActorID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// loadDriftFindingRowByID reads the raw drift_findings row for id and
// fatals on error. The lookup is by primary key, so no tenant scope is
// needed (raw loaders bypass repository scoping deliberately, so the
// test observes the persisted row exactly as the database stores it).
func loadDriftFindingRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawDriftFindingRow {
	t.Helper()
	var row rawDriftFindingRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, kind, reason, level,
		        project_id, environment_id, service_id, service_domain_id,
		        env_var_key, dokploy_resource_id, parent_dokploy_id,
		        request_id, correlation_id,
		        detected_at, resolved_at, resolved_by_actor_id,
		        created_at, updated_at
		   FROM drift_findings
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.Kind, &row.Reason, &row.Level,
		&row.ProjectID, &row.EnvironmentID, &row.ServiceID, &row.ServiceDomainID,
		&row.EnvVarKey, &row.DokployResourceID, &row.ParentDokployID,
		&row.RequestID, &row.CorrelationID,
		&row.DetectedAt, &row.ResolvedAt, &row.ResolvedByActorID,
		&row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load drift_findings id=%q: %v", id, err)
	}
	return row
}

// countDriftFindingRowsForOrg returns the number of drift_findings rows
// owned by organizationID. It is the "did the rollback / cascade leave a
// row behind?" probe.
func countDriftFindingRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM drift_findings WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count drift_findings for org=%q: %v", organizationID, err)
	}
	return n
}

// mintDriftFindingID builds a stable, test-local drift finding id from
// the test name and a per-test suffix. Tests in store_test share a
// single package, so the test name keeps ids unique across parallel
// test cases without needing a shared atomic counter. Real id minting
// lives in DriftFindingRepository.Append (newDriftFindingID), so this
// is the test-local override that exercises the caller-supplied-id
// branch.
func mintDriftFindingID(t *testing.T, suffix string) string {
	t.Helper()
	return "drft_" + sanitizeTestNameForDriftID(t.Name()) + "_" + suffix
}

// sanitizeTestNameForDriftID strips slashes from a test name so an
// id derived from t.Name() in a nested subtest stays a single token.
// Subtest names contain '/' which would otherwise produce a multi-slash
// id and confuse debugging output.
func sanitizeTestNameForDriftID(name string) string {
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

// driftFindingTxRollbackSentinel is the sentinel error a closure returns
// to trigger Store.Write's rollback path. It is a typed struct{} rather
// than a package var so callers cannot accidentally rely on identity
// equality across test files; rollback semantics are independent of the
// backend error taxonomy. The type name is intentionally distinct from
// sibling per-file sentinels (apiKeyTxRollbackSentinel,
// membershipTxRollbackSentinel, etc.) to avoid a store_test collision.
type driftFindingTxRollbackSentinel struct{}

func (driftFindingTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this drift finding transaction"
}

// driftFindingFixture returns a known-good DriftFinding for org / svc.
// Callers override individual fields as needed.
func driftFindingFixture(org testutil.Organization, svc testutil.Service, detectedAt time.Time) store.DriftFinding {
	return store.DriftFinding{
		OrganizationID: org.ID,
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonEnvVarChanged,
		Level:          store.DriftLevelService,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		EnvVarKey:      "DATABASE_URL",
		RequestID:      "req_drft_fixture",
		CorrelationID:  "cor_drft_fixture",
		DetectedAt:     detectedAt,
	}
}

// seedDriftFinding inserts f through the repository's Append and fatals
// on error. It is the smallest happy-path closure and is reused by every
// test that does not need to observe the call's tx in isolation.
func seedDriftFinding(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DriftFindingRepository,
	f store.DriftFinding,
) store.DriftFinding {
	t.Helper()
	var created store.DriftFinding
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, aErr := repo.Append(ctx, tx, f)
		if aErr != nil {
			return aErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("seed drift finding: %v", err)
	}
	return created
}

// assertDriftFindingByteIdentical asserts every column of after equals
// the corresponding column of baseline. The comparator switches on
// pointer nil-ness first for every nullable column so a regression that
// flipped a NULL leg to a zero-value scalar is caught explicitly rather
// than silently round-tripping.
func assertDriftFindingByteIdentical(t *testing.T, label string, baseline, after rawDriftFindingRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: id drift baseline=%q after=%q", label, baseline.ID, after.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: organization_id drift baseline=%q after=%q", label, baseline.OrganizationID, after.OrganizationID)
	}
	if after.Kind != baseline.Kind {
		t.Errorf("%s: kind drift baseline=%q after=%q", label, baseline.Kind, after.Kind)
	}
	if after.Reason != baseline.Reason {
		t.Errorf("%s: reason drift baseline=%q after=%q", label, baseline.Reason, after.Reason)
	}
	if after.Level != baseline.Level {
		t.Errorf("%s: level drift baseline=%q after=%q", label, baseline.Level, after.Level)
	}
	assertStringPtrEqual(t, label+".project_id", baseline.ProjectID, after.ProjectID)
	assertStringPtrEqual(t, label+".environment_id", baseline.EnvironmentID, after.EnvironmentID)
	assertStringPtrEqual(t, label+".service_id", baseline.ServiceID, after.ServiceID)
	assertStringPtrEqual(t, label+".service_domain_id", baseline.ServiceDomainID, after.ServiceDomainID)
	if after.EnvVarKey != baseline.EnvVarKey {
		t.Errorf("%s: env_var_key drift baseline=%q after=%q", label, baseline.EnvVarKey, after.EnvVarKey)
	}
	if after.DokployResourceID != baseline.DokployResourceID {
		t.Errorf("%s: dokploy_resource_id drift baseline=%q after=%q", label, baseline.DokployResourceID, after.DokployResourceID)
	}
	if after.ParentDokployID != baseline.ParentDokployID {
		t.Errorf("%s: parent_dokploy_id drift baseline=%q after=%q", label, baseline.ParentDokployID, after.ParentDokployID)
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: request_id drift baseline=%q after=%q", label, baseline.RequestID, after.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: correlation_id drift baseline=%q after=%q", label, baseline.CorrelationID, after.CorrelationID)
	}
	if !after.DetectedAt.Equal(baseline.DetectedAt) {
		t.Errorf("%s: detected_at drift baseline=%s after=%s", label, baseline.DetectedAt, after.DetectedAt)
	}
	assertTimePtrEqual(t, label+".resolved_at", baseline.ResolvedAt, after.ResolvedAt)
	if after.ResolvedByActorID != baseline.ResolvedByActorID {
		t.Errorf("%s: resolved_by_actor_id drift baseline=%q after=%q", label, baseline.ResolvedByActorID, after.ResolvedByActorID)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: created_at drift baseline=%s after=%s", label, baseline.CreatedAt, after.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: updated_at drift baseline=%s after=%s", label, baseline.UpdatedAt, after.UpdatedAt)
	}
}

func assertStringPtrEqual(t *testing.T, label string, baseline, after *string) {
	t.Helper()
	switch {
	case baseline == nil && after == nil:
		return
	case baseline == nil && after != nil:
		t.Errorf("%s: nil-ness drift baseline=<nil> after=%q", label, *after)
	case baseline != nil && after == nil:
		t.Errorf("%s: nil-ness drift baseline=%q after=<nil>", label, *baseline)
	default:
		if *baseline != *after {
			t.Errorf("%s: value drift baseline=%q after=%q", label, *baseline, *after)
		}
	}
}

func assertTimePtrEqual(t *testing.T, label string, baseline, after *time.Time) {
	t.Helper()
	switch {
	case baseline == nil && after == nil:
		return
	case baseline == nil && after != nil:
		t.Errorf("%s: nil-ness drift baseline=<nil> after=%s", label, after.String())
	case baseline != nil && after == nil:
		t.Errorf("%s: nil-ness drift baseline=%s after=<nil>", label, baseline.String())
	default:
		if !baseline.Equal(*after) {
			t.Errorf("%s: value drift baseline=%s after=%s", label, baseline.String(), after.String())
		}
	}
}

func TestDriftFindingAppendPersistsRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	detected := time.Now().UTC().Truncate(time.Microsecond)
	fixture := driftFindingFixture(org, svc, detected)

	before := time.Now().UTC()
	created := seedDriftFinding(ctx, t, s, repo, fixture)
	after := time.Now().UTC()

	if created.ID == "" {
		t.Fatalf("created.ID is empty")
	}
	if got := created.ID[:5]; got != "drft_" {
		t.Errorf("id prefix = %q, want drft_", got)
	}
	if created.OrganizationID != fixture.OrganizationID {
		t.Errorf("organization_id = %q, want %q", created.OrganizationID, fixture.OrganizationID)
	}
	if created.Kind != fixture.Kind {
		t.Errorf("kind = %q, want %q", created.Kind, fixture.Kind)
	}
	if created.ResolvedAt != nil {
		t.Errorf("resolved_at = %v, want nil for a new finding", created.ResolvedAt)
	}
	if created.ResolvedByActorID != "" {
		t.Errorf("resolved_by_actor_id = %q, want empty for a new finding", created.ResolvedByActorID)
	}
	if created.CreatedAt.Before(before.Add(-time.Second)) || created.CreatedAt.After(after.Add(time.Second)) {
		t.Errorf("created_at = %s, want within (%s, %s)", created.CreatedAt, before, after)
	}
	if !created.DetectedAt.Equal(detected) {
		t.Errorf("detected_at = %s, want %s", created.DetectedAt, detected)
	}

	raw := loadDriftFindingRowByID(ctx, t, db, created.ID)
	if raw.OrganizationID != created.OrganizationID {
		t.Errorf("raw.organization_id = %q, want %q", raw.OrganizationID, created.OrganizationID)
	}
	if raw.Kind != string(created.Kind) {
		t.Errorf("raw.kind = %q, want %q", raw.Kind, created.Kind)
	}
	if raw.ProjectID == nil || *raw.ProjectID != svc.ProjectID {
		t.Errorf("raw.project_id = %v, want %q", raw.ProjectID, svc.ProjectID)
	}
	if raw.ServiceID == nil || *raw.ServiceID != svc.ID {
		t.Errorf("raw.service_id = %v, want %q", raw.ServiceID, svc.ID)
	}
	if raw.ResolvedAt != nil {
		t.Errorf("raw.resolved_at = %v, want nil", raw.ResolvedAt)
	}
}

func TestDriftFindingAppendOrganizationLevelLegsAreNull(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")

	finding := store.DriftFinding{
		OrganizationID:    org.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelOrganization,
		DokployResourceID: "dokploy-org-stray-1",
		DetectedAt:        time.Now().UTC().Truncate(time.Microsecond),
	}
	created := seedDriftFinding(ctx, t, s, repo, finding)

	raw := loadDriftFindingRowByID(ctx, t, db, created.ID)
	if raw.ProjectID != nil {
		t.Errorf("project_id = %v, want NULL for organization-level finding", raw.ProjectID)
	}
	if raw.EnvironmentID != nil {
		t.Errorf("environment_id = %v, want NULL", raw.EnvironmentID)
	}
	if raw.ServiceID != nil {
		t.Errorf("service_id = %v, want NULL", raw.ServiceID)
	}
	if raw.ServiceDomainID != nil {
		t.Errorf("service_domain_id = %v, want NULL", raw.ServiceDomainID)
	}
	if created.ProjectID != "" {
		t.Errorf("repo.project_id = %q, want empty string projection of NULL", created.ProjectID)
	}
}

func TestDriftFindingAppendCallerSuppliedIDIsPreserved(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	id := mintDriftFindingID(t, "supplied")
	fixture := driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond))
	fixture.ID = id

	created := seedDriftFinding(ctx, t, s, repo, fixture)
	if created.ID != id {
		t.Errorf("created.ID = %q, want %q", created.ID, id)
	}
}

func TestDriftFindingAppendDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	id := mintDriftFindingID(t, "dup")
	fixture := driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond))
	fixture.ID = id
	_ = seedDriftFinding(ctx, t, s, repo, fixture)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, fixture)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestDriftFindingAppendValidationRejectsBadInput(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	now := time.Now().UTC().Truncate(time.Microsecond)
	resolved := now

	cases := []struct {
		name   string
		mutate func(f *store.DriftFinding)
	}{
		{"missing organization_id", func(f *store.DriftFinding) { f.OrganizationID = "" }},
		{"missing kind", func(f *store.DriftFinding) { f.Kind = "" }},
		{"unknown kind", func(f *store.DriftFinding) { f.Kind = store.DriftKind("rogue") }},
		{"missing reason", func(f *store.DriftFinding) { f.Reason = "" }},
		{"unknown reason", func(f *store.DriftFinding) { f.Reason = store.DriftReason("rogue") }},
		{"missing level", func(f *store.DriftFinding) { f.Level = "" }},
		{"unknown level", func(f *store.DriftFinding) { f.Level = store.DriftLevel("rogue") }},
		{"zero detected_at", func(f *store.DriftFinding) { f.DetectedAt = time.Time{} }},
		{"resolved_at set on new finding", func(f *store.DriftFinding) { f.ResolvedAt = &resolved }},
		{"resolved_by_actor_id set on new finding", func(f *store.DriftFinding) { f.ResolvedByActorID = "usr_rogue" }},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := driftFindingFixture(org, svc, now)
			tc.mutate(&fixture)
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, aErr := repo.Append(ctx, tx, fixture)
				return aErr
			})
			wantErrCode(t, err, yerr.CodeValidation)
		})
	}
}

func TestDriftFindingAppendNilTxIsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewDriftFindingRepository()

	_, err := repo.Append(context.Background(), nil, store.DriftFinding{
		OrganizationID: "org_x",
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonEnvVarChanged,
		Level:          store.DriftLevelService,
		DetectedAt:     time.Now().UTC(),
	})
	wantErrCode(t, err, yerr.CodeInternal)
}

func TestDriftFindingAppendUnknownOrganizationIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()
	_ = f

	finding := store.DriftFinding{
		OrganizationID: "org_does_not_exist",
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonEnvVarChanged,
		Level:          store.DriftLevelOrganization,
		DetectedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, finding)
		return aErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestDriftFindingAppendCrossTenantParentIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	orgA := seedOrg(t, db, f, "A")
	orgB := seedOrg(t, db, f, "B")
	projB := seedProject(t, db, f, orgB, "B-project")
	envB := seedEnvironment(t, db, f, projB, "B-env")
	svcB := seedService(t, db, f, envB, "B-svc")

	now := time.Now().UTC().Truncate(time.Microsecond)

	// orgA tries to point a finding at orgB's project / env / service.
	cases := []struct {
		name string
		f    store.DriftFinding
	}{
		{"foreign project", store.DriftFinding{
			OrganizationID: orgA.ID, Kind: store.DriftKindSafe,
			Reason: store.DriftReasonEnvVarChanged, Level: store.DriftLevelProject,
			ProjectID: projB.ID, DetectedAt: now,
		}},
		{"foreign environment", store.DriftFinding{
			OrganizationID: orgA.ID, Kind: store.DriftKindSafe,
			Reason: store.DriftReasonEnvVarChanged, Level: store.DriftLevelEnvironment,
			EnvironmentID: envB.ID, DetectedAt: now,
		}},
		{"foreign service", store.DriftFinding{
			OrganizationID: orgA.ID, Kind: store.DriftKindSafe,
			Reason: store.DriftReasonEnvVarChanged, Level: store.DriftLevelService,
			ServiceID: svcB.ID, DetectedAt: now,
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, aErr := repo.Append(ctx, tx, tc.f)
				return aErr
			})
			wantErrCode(t, err, yerr.CodeConflict)
		})
	}
}

func TestDriftFindingAppendRollbackRemovesRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	fixture := driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond))

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, aErr := repo.Append(ctx, tx, fixture); aErr != nil {
			return aErr
		}
		return driftFindingTxRollbackSentinel{}
	})
	var sentinel driftFindingTxRollbackSentinel
	if !errors.As(err, &sentinel) {
		t.Fatalf("Write returned err=%v, want rollback sentinel", err)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("drift_findings rows after rollback = %d, want 0", got)
	}
}

func TestDriftFindingAppendPeerRowIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	now := time.Now().UTC().Truncate(time.Microsecond)
	first := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, now))
	baseline := loadDriftFindingRowByID(ctx, t, db, first.ID)

	// Append a second, unrelated finding for the same tenant. The first
	// row must be byte-identical afterwards.
	_ = seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, now.Add(time.Second)))
	after := loadDriftFindingRowByID(ctx, t, db, first.ID)
	assertDriftFindingByteIdentical(t, "peer-row after sibling Append", baseline, after)
}

func TestDriftFindingGetByIDRoundTrip(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	created := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))

	var got store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		out, gErr := repo.GetByID(ctx, q, org.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		got = out
		return nil
	}); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("got.ID = %q, want %q", got.ID, created.ID)
	}
	if got.Kind != created.Kind {
		t.Errorf("got.Kind = %q, want %q", got.Kind, created.Kind)
	}
	if !got.DetectedAt.Equal(created.DetectedAt) {
		t.Errorf("got.DetectedAt = %s, want %s", got.DetectedAt, created.DetectedAt)
	}
}

func TestDriftFindingGetByIDUnknownIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, org.ID, "drft_does_not_exist")
		return gErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestDriftFindingGetByIDCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	orgA := seedOrg(t, db, f, "A")
	orgB := seedOrg(t, db, f, "B")
	projB := seedProject(t, db, f, orgB, "B-project")
	envB := seedEnvironment(t, db, f, projB, "B-env")
	svcB := seedService(t, db, f, envB, "B-svc")

	createdB := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(orgB, svcB, time.Now().UTC().Truncate(time.Microsecond)))

	// orgA tries to read orgB's finding by id.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, orgA.ID, createdB.ID)
		return gErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestDriftFindingListByOrganizationOrdersNewestFirst(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	base := time.Now().UTC().Truncate(time.Microsecond)
	older := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, base))
	newer := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, base.Add(2*time.Second)))

	var rows []store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		out, lErr := repo.ListByOrganization(ctx, q, org.ID, 100)
		if lErr != nil {
			return lErr
		}
		rows = out
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].ID != newer.ID {
		t.Errorf("rows[0].ID = %q, want newest %q", rows[0].ID, newer.ID)
	}
	if rows[1].ID != older.ID {
		t.Errorf("rows[1].ID = %q, want oldest %q", rows[1].ID, older.ID)
	}
}

func TestDriftFindingListByOrganizationClampsLimit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		_ = seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, base.Add(time.Duration(i)*time.Second)))
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
			var rows []store.DriftFinding
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				out, lErr := repo.ListByOrganization(ctx, q, org.ID, tc.limit)
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

func TestDriftFindingListByOrganizationUnknownOrgIsEmptySlice(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	var rows []store.DriftFinding
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

func TestDriftFindingMarkResolvedHappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	created := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))

	resolvedAt := time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Minute)
	actor := "usr_drft_resolver"

	var resolved store.DriftFinding
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		out, rErr := repo.MarkResolved(ctx, tx, org.ID, created.ID, actor, resolvedAt)
		if rErr != nil {
			return rErr
		}
		resolved = out
		return nil
	}); err != nil {
		t.Fatalf("MarkResolved: %v", err)
	}
	if resolved.ResolvedAt == nil || !resolved.ResolvedAt.Equal(resolvedAt) {
		t.Errorf("ResolvedAt = %v, want %s", resolved.ResolvedAt, resolvedAt)
	}
	if resolved.ResolvedByActorID != actor {
		t.Errorf("ResolvedByActorID = %q, want %q", resolved.ResolvedByActorID, actor)
	}
	if !resolved.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("UpdatedAt = %s, want after %s", resolved.UpdatedAt, created.UpdatedAt)
	}

	raw := loadDriftFindingRowByID(ctx, t, db, created.ID)
	if raw.ResolvedAt == nil || !raw.ResolvedAt.Equal(resolvedAt) {
		t.Errorf("raw.resolved_at = %v, want %s", raw.ResolvedAt, resolvedAt)
	}
	if raw.ResolvedByActorID != actor {
		t.Errorf("raw.resolved_by_actor_id = %q, want %q", raw.ResolvedByActorID, actor)
	}
}

func TestDriftFindingMarkResolvedAlreadyResolvedIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	created := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))

	firstResolvedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkResolved(ctx, tx, org.ID, created.ID, "usr_first", firstResolvedAt)
		return rErr
	}); err != nil {
		t.Fatalf("first MarkResolved: %v", err)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkResolved(ctx, tx, org.ID, created.ID, "usr_second", firstResolvedAt.Add(time.Minute))
		return rErr
	})
	wantErrCode(t, err, yerr.CodeConflict)

	raw := loadDriftFindingRowByID(ctx, t, db, created.ID)
	if raw.ResolvedAt == nil || !raw.ResolvedAt.Equal(firstResolvedAt) {
		t.Errorf("resolved_at moved on second MarkResolved: got=%v, want=%s", raw.ResolvedAt, firstResolvedAt)
	}
	if raw.ResolvedByActorID != "usr_first" {
		t.Errorf("resolved_by_actor_id moved on second MarkResolved: got=%q, want=usr_first", raw.ResolvedByActorID)
	}
}

func TestDriftFindingMarkResolvedUnknownIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkResolved(ctx, tx, org.ID, "drft_missing", "usr_x", time.Now().UTC())
		return rErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestDriftFindingMarkResolvedCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	orgA := seedOrg(t, db, f, "A")
	orgB := seedOrg(t, db, f, "B")
	projB := seedProject(t, db, f, orgB, "B-project")
	envB := seedEnvironment(t, db, f, projB, "B-env")
	svcB := seedService(t, db, f, envB, "B-svc")

	createdB := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(orgB, svcB, time.Now().UTC().Truncate(time.Microsecond)))
	baseline := loadDriftFindingRowByID(ctx, t, db, createdB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkResolved(ctx, tx, orgA.ID, createdB.ID, "usr_a_attacker", time.Now().UTC())
		return rErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	after := loadDriftFindingRowByID(ctx, t, db, createdB.ID)
	assertDriftFindingByteIdentical(t, "cross-tenant resolve does not touch peer", baseline, after)
}

func TestDriftFindingMarkResolvedValidationRejectsBadInput(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	now := time.Now().UTC()
	cases := []struct {
		name  string
		org   string
		id    string
		actor string
		stamp time.Time
	}{
		{"missing organization_id", "", "drft_x", "usr_a", now},
		{"missing id", "org_a", "", "usr_a", now},
		{"missing resolver actor", "org_a", "drft_x", "", now},
		{"zero resolved_at", "org_a", "drft_x", "usr_a", time.Time{}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, rErr := repo.MarkResolved(ctx, tx, tc.org, tc.id, tc.actor, tc.stamp)
				return rErr
			})
			wantErrCode(t, err, yerr.CodeValidation)
		})
	}
}

func TestDriftFindingMarkResolvedNilTxIsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewDriftFindingRepository()
	_, err := repo.MarkResolved(context.Background(), nil, "org_x", "drft_x", "usr_a", time.Now().UTC())
	wantErrCode(t, err, yerr.CodeInternal)
}

func TestDriftFindingMarkResolvedPeerRowIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	now := time.Now().UTC().Truncate(time.Microsecond)
	target := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, now))
	peer := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, now.Add(time.Second)))
	peerBaseline := loadDriftFindingRowByID(ctx, t, db, peer.ID)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, rErr := repo.MarkResolved(ctx, tx, org.ID, target.ID, "usr_resolver", now.Add(5*time.Minute))
		return rErr
	}); err != nil {
		t.Fatalf("MarkResolved: %v", err)
	}

	peerAfter := loadDriftFindingRowByID(ctx, t, db, peer.ID)
	assertDriftFindingByteIdentical(t, "peer-row after sibling MarkResolved", peerBaseline, peerAfter)
}

func TestDriftFindingCascadeDeleteOnOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	_ = seedDriftFinding(ctx, t, s, repo, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))
	if got := countDriftFindingRowsForOrg(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("pre-delete count = %d, want 1", got)
	}
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, org.ID); got != 0 {
		t.Errorf("post-delete count = %d, want 0 (cascade)", got)
	}
}
