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

// Integration and unit tests for QuotaRepository's quota_policies write
// surface and the ListEffectiveLimits resolver (BE-0451). This file pins
// the row-shape, timestamp, CHECK/FK, enforcement-mode, scope-resolution,
// and transaction-rollback invariants the existing
// quota_repository_test.go (EffectiveLimit + reservation flows) does not
// already cover:
//
//   - UpsertOrganizationPolicy is the only write surface. It mints a fresh
//     id on insert, leaves the id and created_at byte-equal on update,
//     refreshes updated_at via the set_updated_at trigger, and never
//     touches plan-default rows. A foreign-key, CHECK, or DOMAIN violation
//     surfaces as typed apierr.Conflict through mapWriteError; the nil-tx
//     guard renders apierr.Internal.
//   - ListEffectiveLimits resolves every resource that has a policy at
//     either scope in deterministic resource order. The query is tenant
//     scoped at both legs (only the named plan's defaults and the requested
//     org's overrides enter the result) — so it never leaks another
//     tenant's overrides or another plan's defaults.
//
// The per-resource EffectiveLimit semantics (override-beats-default,
// plan-fallback, not-found, tenant-scoping) are owned by
// quota_repository_test.go. The schema-level uniqueness, scope-consistency,
// and cascade invariants are owned by quota_schema_test.go. quota_policies
// has no version column, so optimistic-versioning checks are not
// applicable.
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset. The nil-tx
// guard is a pure unit test.

// upsertOrganizationPolicy runs UpsertOrganizationPolicy inside Store.Write
// and fatals on error. It is the smallest possible happy-path closure and
// is reused by every test that does not need to observe the upsert's tx in
// isolation.
func upsertOrganizationPolicy(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	organizationID string,
	resource store.QuotaResource,
	limitValue int64,
	mode store.EnforcementMode,
) {
	t.Helper()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.UpsertOrganizationPolicy(ctx, tx, organizationID, resource, limitValue, mode)
	}); err != nil {
		t.Fatalf("UpsertOrganizationPolicy(%q, %q, %d, %q): %v",
			organizationID, resource, limitValue, mode, err)
	}
}

// effectiveLimitOrFail runs EffectiveLimit inside Store.Read and fatals on
// error. It is reused by every test that needs to observe the post-condition
// of an upsert.
func effectiveLimitOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	organizationID, plan string,
	resource store.QuotaResource,
) (store.QuotaLimit, bool) {
	t.Helper()
	var (
		limit store.QuotaLimit
		ok    bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, found, lerr := repo.EffectiveLimit(ctx, q, organizationID, plan, resource)
		if lerr != nil {
			return lerr
		}
		limit = got
		ok = found
		return nil
	}); err != nil {
		t.Fatalf("EffectiveLimit(%q, %q, %q): %v", organizationID, plan, resource, err)
	}
	return limit, ok
}

// listEffectiveLimitsOrFail runs ListEffectiveLimits inside Store.Read and
// fatals on error.
func listEffectiveLimitsOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	organizationID, plan string,
) []store.EffectiveQuotaLimit {
	t.Helper()
	var out []store.EffectiveQuotaLimit
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListEffectiveLimits(ctx, q, organizationID, plan)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListEffectiveLimits(%q, %q): %v", organizationID, plan, err)
	}
	return out
}

// loadQuotaPolicyRow reads the raw quota_policies row for (orgID, resource)
// and fatals on error. It bypasses the repository so the test can observe
// the id, scope_kind, plan, created_at, and updated_at columns the repo's
// reader projections deliberately do not expose.
type rawQuotaPolicyRow struct {
	ID              string
	ScopeKind       string
	Plan            *string
	OrganizationID  *string
	Resource        string
	LimitValue      int64
	EnforcementMode string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func loadOrganizationPolicyRow(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
	resource store.QuotaResource,
) rawQuotaPolicyRow {
	t.Helper()
	var row rawQuotaPolicyRow
	if err := db.QueryRow(ctx,
		`SELECT id, scope_kind, plan, organization_id, resource,
		        limit_value, enforcement_mode, created_at, updated_at
		   FROM quota_policies
		  WHERE scope_kind = 'organization'
		    AND organization_id = $1
		    AND resource = $2`,
		organizationID, string(resource)).Scan(
		&row.ID, &row.ScopeKind, &row.Plan, &row.OrganizationID, &row.Resource,
		&row.LimitValue, &row.EnforcementMode, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load organization quota policy (%q, %q): %v", organizationID, resource, err)
	}
	return row
}

func loadPlanPolicyRow(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	plan, resource string,
) rawQuotaPolicyRow {
	t.Helper()
	var row rawQuotaPolicyRow
	if err := db.QueryRow(ctx,
		`SELECT id, scope_kind, plan, organization_id, resource,
		        limit_value, enforcement_mode, created_at, updated_at
		   FROM quota_policies
		  WHERE scope_kind = 'plan_default'
		    AND plan = $1
		    AND resource = $2`,
		plan, resource).Scan(
		&row.ID, &row.ScopeKind, &row.Plan, &row.OrganizationID, &row.Resource,
		&row.LimitValue, &row.EnforcementMode, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		t.Fatalf("load plan-default quota policy (%q, %q): %v", plan, resource, err)
	}
	return row
}

func TestQuotaRepositoryUpsertOrganizationPolicyInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	upsertOrganizationPolicy(ctx, t, s, repo, org.ID, store.QuotaResourceProjects, 25, store.EnforcementModeHard)

	row := loadOrganizationPolicyRow(ctx, t, db, org.ID, store.QuotaResourceProjects)
	if row.ScopeKind != "organization" {
		t.Errorf("scope_kind = %q, want %q", row.ScopeKind, "organization")
	}
	if row.Plan != nil {
		t.Errorf("plan = %q, want NULL on organization override", *row.Plan)
	}
	if row.OrganizationID == nil || *row.OrganizationID != org.ID {
		t.Errorf("organization_id = %v, want %q", row.OrganizationID, org.ID)
	}
	if row.LimitValue != 25 {
		t.Errorf("limit_value = %d, want 25", row.LimitValue)
	}
	if row.EnforcementMode != string(store.EnforcementModeHard) {
		t.Errorf("enforcement_mode = %q, want %q", row.EnforcementMode, store.EnforcementModeHard)
	}
	if len(row.ID) < len("qpol_") || row.ID[:len("qpol_")] != "qpol_" {
		t.Errorf("id = %q, want qpol_<token> prefix", row.ID)
	}
	if row.CreatedAt.IsZero() || row.UpdatedAt.IsZero() {
		t.Errorf("timestamps zero: created_at=%v updated_at=%v", row.CreatedAt, row.UpdatedAt)
	}
	if delta := row.UpdatedAt.Sub(row.CreatedAt); delta < 0 || delta > time.Second {
		t.Errorf("updated_at - created_at = %v on insert, want within 1s", delta)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyUpdatePreservesIdAndCreatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	upsertOrganizationPolicy(ctx, t, s, repo, org.ID, store.QuotaResourceServices, 50, store.EnforcementModeHard)
	baseline := loadOrganizationPolicyRow(ctx, t, db, org.ID, store.QuotaResourceServices)

	time.Sleep(time.Millisecond)

	upsertOrganizationPolicy(ctx, t, s, repo, org.ID, store.QuotaResourceServices, 120, store.EnforcementModeSoft)

	updated := loadOrganizationPolicyRow(ctx, t, db, org.ID, store.QuotaResourceServices)

	if updated.ID != baseline.ID {
		t.Errorf("Upsert UPDATE mutated id: was %q, now %q", baseline.ID, updated.ID)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Upsert UPDATE mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("Upsert UPDATE did not refresh updated_at: was %v, now %v", baseline.UpdatedAt, updated.UpdatedAt)
	}
	if updated.LimitValue != 120 {
		t.Errorf("limit_value not updated: got %d, want 120", updated.LimitValue)
	}
	if updated.EnforcementMode != string(store.EnforcementModeSoft) {
		t.Errorf("enforcement_mode not updated: got %q, want %q", updated.EnforcementMode, store.EnforcementModeSoft)
	}
	if updated.ScopeKind != "organization" || updated.Plan != nil {
		t.Errorf("scope drift after UPDATE: scope_kind=%q plan=%v, want (organization, nil)",
			updated.ScopeKind, updated.Plan)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyDoesNotTouchPlanDefault(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	seedPlanPolicy(t, db, "qp_starter_projects", "starter", string(store.QuotaResourceProjects), 5)
	planBaseline := loadPlanPolicyRow(ctx, t, db, "starter", string(store.QuotaResourceProjects))

	// Force a measurable wallclock gap so an accidental UPDATE of the
	// plan-default row would necessarily move its updated_at forward.
	time.Sleep(time.Millisecond)

	upsertOrganizationPolicy(ctx, t, s, repo, org.ID, store.QuotaResourceProjects, 25, store.EnforcementModeHard)

	planAfter := loadPlanPolicyRow(ctx, t, db, "starter", string(store.QuotaResourceProjects))
	if planAfter.ID != planBaseline.ID {
		t.Errorf("plan_default id drifted: was %q, now %q", planBaseline.ID, planAfter.ID)
	}
	if planAfter.LimitValue != planBaseline.LimitValue {
		t.Errorf("plan_default limit drifted: was %d, now %d", planBaseline.LimitValue, planAfter.LimitValue)
	}
	if planAfter.EnforcementMode != planBaseline.EnforcementMode {
		t.Errorf("plan_default enforcement_mode drifted: was %q, now %q",
			planBaseline.EnforcementMode, planAfter.EnforcementMode)
	}
	if !planAfter.CreatedAt.Equal(planBaseline.CreatedAt) {
		t.Errorf("plan_default created_at drifted: was %v, now %v", planBaseline.CreatedAt, planAfter.CreatedAt)
	}
	if !planAfter.UpdatedAt.Equal(planBaseline.UpdatedAt) {
		t.Errorf("plan_default updated_at drifted: was %v, now %v", planBaseline.UpdatedAt, planAfter.UpdatedAt)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyUnknownOrganizationReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.UpsertOrganizationPolicy(ctx, tx,
			"org_does_not_exist", store.QuotaResourceProjects, 10, store.EnforcementModeHard)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown org) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyNegativeLimitReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.UpsertOrganizationPolicy(ctx, tx,
			org.ID, store.QuotaResourceProjects, -1, store.EnforcementModeHard)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(negative limit) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyUnknownEnforcementModeReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.UpsertOrganizationPolicy(ctx, tx,
			org.ID, store.QuotaResourceProjects, 5, store.EnforcementMode("not-a-mode"))
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown enforcement_mode) error = %v, want code %s",
			err, yerr.CodeConflict)
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyEachEnforcementModeRoundTrips(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	cases := []struct {
		resource store.QuotaResource
		mode     store.EnforcementMode
	}{
		{store.QuotaResourceProjects, store.EnforcementModeHard},
		{store.QuotaResourceServices, store.EnforcementModeSoft},
		{store.QuotaResourceStorageGB, store.EnforcementModeMetered},
		{store.QuotaResourceDomains, store.EnforcementModeDisabled},
	}
	for _, tc := range cases {
		upsertOrganizationPolicy(ctx, t, s, repo, org.ID, tc.resource, 7, tc.mode)
		row := loadOrganizationPolicyRow(ctx, t, db, org.ID, tc.resource)
		if row.EnforcementMode != string(tc.mode) {
			t.Errorf("resource %q: enforcement_mode = %q, want %q",
				tc.resource, row.EnforcementMode, tc.mode)
		}
	}
}

func TestQuotaRepositoryListEffectiveLimitsResolvesAcrossScopesInDeterministicOrder(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	// Plan defaults: members=3, projects=5, services=10.
	seedPlanPolicy(t, db, "qp_starter_members", "starter", string(store.QuotaResourceMembers), 3)
	seedPlanPolicy(t, db, "qp_starter_projects", "starter", string(store.QuotaResourceProjects), 5)
	seedPlanPolicy(t, db, "qp_starter_services", "starter", string(store.QuotaResourceServices), 10)
	// A plan default on a different plan must not bleed into the result.
	seedPlanPolicy(t, db, "qp_pro_databases", "pro", string(store.QuotaResourceDatabases), 99)
	// Organization override of projects beats the plan default; members and
	// services fall back to plan defaults.
	upsertOrganizationPolicy(ctx, t, s, repo, org.ID, store.QuotaResourceProjects, 25, store.EnforcementModeSoft)

	limits := listEffectiveLimitsOrFail(ctx, t, s, repo, org.ID, "starter")
	want := []store.EffectiveQuotaLimit{
		{Resource: store.QuotaResourceMembers, LimitValue: 3, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopePlanDefault},
		{Resource: store.QuotaResourceProjects, LimitValue: 25, EnforcementMode: store.EnforcementModeSoft, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceServices, LimitValue: 10, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopePlanDefault},
	}
	if len(limits) != len(want) {
		t.Fatalf("ListEffectiveLimits returned %d rows, want %d (rows = %+v)", len(limits), len(want), limits)
	}
	for i, w := range want {
		if limits[i] != w {
			t.Errorf("row %d = %+v, want %+v", i, limits[i], w)
		}
	}
}

func TestQuotaRepositoryListEffectiveLimitsIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	seedPlanPolicy(t, db, "qp_starter_projects", "starter", string(store.QuotaResourceProjects), 5)
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceServices, 42, store.EnforcementModeMetered)

	limits := listEffectiveLimitsOrFail(ctx, t, s, repo, orgB.ID, "starter")
	if len(limits) != 1 {
		t.Fatalf("ListEffectiveLimits for orgB returned %d rows, want 1 (only the plan default); rows = %+v",
			len(limits), limits)
	}
	got := limits[0]
	if got.Resource != store.QuotaResourceProjects || got.LimitValue != 5 ||
		got.EnforcementMode != store.EnforcementModeHard || got.Scope != store.QuotaScopePlanDefault {
		t.Errorf("orgB plan-default projection = %+v, want plan_default(projects, 5, hard); orgA's override leaked",
			got)
	}
}

func TestQuotaRepositoryListEffectiveLimitsReturnsEmptyWhenUnconfigured(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	limits := listEffectiveLimitsOrFail(ctx, t, s, repo, org.ID, "starter")
	if len(limits) != 0 {
		t.Errorf("ListEffectiveLimits with no policies returned %d rows, want 0", len(limits))
	}
}

func TestQuotaRepositoryUpsertOrganizationPolicyRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	bailout := quotaPolicyTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if upErr := repo.UpsertOrganizationPolicy(ctx, tx,
			org.ID, store.QuotaResourceProjects, 99, store.EnforcementModeHard); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}
	if !errors.Is(err, bailout) {
		t.Fatalf("Write returned %v, want sentinel %v (closure error must propagate unchanged)", err, bailout)
	}

	// The repository read must report the dimension as unconfigured: the
	// rolled-back row never made it past the rollback point.
	if _, ok := effectiveLimitOrFail(ctx, t, s, repo, org.ID, "starter", store.QuotaResourceProjects); ok {
		t.Error("EffectiveLimit reports a configured policy after a rolled-back upsert; the transaction did NOT roll back")
	}
}

// quotaPolicyTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback. The type name is intentionally distinct from
// every other rollback sentinel in store_test (every *_test.go file under
// internal/controlplane/store/ shares the same package) — collisions would
// block compilation.
type quotaPolicyTxRollbackSentinel struct{}

func (quotaPolicyTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this quota policy transaction"
}

func TestQuotaRepositoryUpsertOrganizationPolicyWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()

	err := repo.UpsertOrganizationPolicy(context.Background(), nil,
		"org_irrelevant", store.QuotaResourceProjects, 1, store.EnforcementModeHard)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpsertOrganizationPolicy(nil tx) error = %v, want code %s", err, yerr.CodeInternal)
	}
}
