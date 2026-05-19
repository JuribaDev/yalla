package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the quota_policies table
// (BE-0452). quota_policies is a dual-scope table: a 'plan_default' row
// is keyed by (plan, resource) and carries NULL organization_id; an
// 'organization' override row is keyed by (organization_id, resource).
// A row that belongs to one tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations, AND
//	(b) the partial unique index
//	    quota_policies_org_resource_idx (organization_id, resource)
//	    WHERE scope_kind = 'organization' — the ON CONFLICT target the
//	    only mutation surface (UpsertOrganizationPolicy) names, so an
//	    upsert from one tenant can never accidentally land on another
//	    tenant's row even when the resource and limit_value match.
//
// The QuotaRepository surface for quota_policies has NO per-id Get,
// NO per-id Update, and NO Delete — the row body is only observable
// through the typed resolvers (EffectiveLimit per-resource,
// ListEffectiveLimits across resources, ListOrganizationUsage joined
// with quota_usage), and the only mutation is UpsertOrganizationPolicy.
// The cross-tenant guarantee at this layer is therefore the projection
// invariant on every resolver leg AND the byte-identical-bystander
// invariant on the upsert.
//
// quota_policies has no version column (unlike api_key_scopes /
// projects), so the load-bearing trigger-managed anchor on every
// byte-identical-bystander projection is updated_at alone — refreshed
// by the BEFORE UPDATE quota_policies_set_updated_at trigger on every
// matched UPDATE. The bystander assertion covers ALL nine observable
// columns (id, scope_kind, plan, organization_id, resource,
// limit_value, enforcement_mode, created_at, updated_at) so a
// regression that wrote correct-looking column values onto the peer's
// row still surfaces through updated_at drift.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - The UpsertOrganizationPolicy row-shape / Insert vs UPDATE
//     id-and-created-at preservation / does-not-touch-plan-default /
//     CHECK and DOMAIN violation / nil-Tx guard / tx-rollback
//     invariants are proved by quota_policy_repository_invariants_test.go
//     (BE-0451). This file only re-exercises the cross-tenant
//     projection.
//   - The (organization_id, id) composite-FK pattern other tenant-
//     scoped tables rely on is NOT applicable here: quota_policies has
//     no child rows pointing at it, so it does not expose
//     UNIQUE (organization_id, id) and there is no composite-FK
//     cross-tenant probe to add.
//   - quota_policies has NO soft-delete column (no
//     deletion_scheduled_at). The acceptance-criteria mention of
//     "soft-deleted rows where applicable" therefore has no surface
//     here; documenting the deliberate absence keeps a future reader
//     from looking for a missing test (mirrors api_key_scope's no-
//     soft-delete note).
//   - The HTTP-layer "another tenant's override is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//   - quota_policies stores NO secret-bearing column — limit_value is
//     a bigint and enforcement_mode is a closed-set domain string —
//     so the BE-0434 raw-secret_hash probe and the
//     redaction-needle-in-error probe have no analogue here.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// listOrganizationUsageOrFail runs ListOrganizationUsage inside Store.Read
// and fatals on error. The helper is distinct from every other
// list-or-fail wrapper in store_test (every *_test.go file under
// internal/controlplane/store/ shares the same package), and is the only
// list-or-fail wrapper that anchors on (orgID, plan) instead of a single
// scope id.
func listOrganizationUsageOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.QuotaRepository,
	organizationID, plan string,
) []store.OrganizationResourceUsage {
	t.Helper()
	var out []store.OrganizationResourceUsage
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListOrganizationUsage(ctx, q, organizationID, plan)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListOrganizationUsage(%q, %q): %v", organizationID, plan, err)
	}
	return out
}

// assertQuotaPolicyByteIdentical asserts every observable column on a
// bystander quota_policies row is byte-identical to its baseline. The
// trigger-managed updated_at is the load-bearing anchor: the BEFORE
// UPDATE quota_policies_set_updated_at trigger refreshes it on every
// matched UPDATE, so a missing tenant predicate in UpsertOrganizationPolicy
// would surface through updated_at drift even when the column writes
// themselves happened to look correct.
func assertQuotaPolicyByteIdentical(t *testing.T, label string, baseline, after rawQuotaPolicyRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.ScopeKind != baseline.ScopeKind {
		t.Errorf("%s: bystander.scope_kind = %q, want %q",
			label, after.ScopeKind, baseline.ScopeKind)
	}
	if !stringPtrEqualQP(after.Plan, baseline.Plan) {
		t.Errorf("%s: bystander.plan = %s, want %s",
			label, fmtStringPtrQP(after.Plan), fmtStringPtrQP(baseline.Plan))
	}
	if !stringPtrEqualQP(after.OrganizationID, baseline.OrganizationID) {
		t.Errorf("%s: bystander.organization_id = %s, want %s",
			label, fmtStringPtrQP(after.OrganizationID), fmtStringPtrQP(baseline.OrganizationID))
	}
	if after.Resource != baseline.Resource {
		t.Errorf("%s: bystander.resource = %q, want %q", label, after.Resource, baseline.Resource)
	}
	if after.LimitValue != baseline.LimitValue {
		t.Errorf("%s: bystander.limit_value = %d, want %d",
			label, after.LimitValue, baseline.LimitValue)
	}
	if after.EnforcementMode != baseline.EnforcementMode {
		t.Errorf("%s: bystander.enforcement_mode = %q, want %q",
			label, after.EnforcementMode, baseline.EnforcementMode)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE UPDATE quota_policies_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// stringPtrEqualQP / fmtStringPtrQP are nullable-column helpers local to
// this file. The suffix avoids collisions with same-named helpers in
// other *_test.go files in store_test.
func stringPtrEqualQP(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func fmtStringPtrQP(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return `"` + *p + `"`
}

// TestQuotaRepositoryEffectiveLimitIsTenantScoped proves the per-resource
// lookup is keyed strictly by organization_id: orgB owns an organization
// override for a resource orgA has not configured, and EffectiveLimit
// for orgA on that resource must NOT pick up orgB's override.
//
// The plan column is deliberately distinct between the two tenants so
// the plan_default leg of the WHERE clause cannot accidentally
// "rescue" the assertion — orgA's plan has no default, so the
// expected outcome is (zero, false, nil). A regression that dropped
// the organization_id predicate from the WHERE clause would surface
// orgB's override here.
func TestQuotaRepositoryEffectiveLimitIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	// orgB has an organization override on projects=99. No plan default
	// is seeded for orgA's plan, so the only possible source of a match
	// for EffectiveLimit(orgA, "starter", projects) is a regression.
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)

	limit, ok := effectiveLimitOrFail(ctx, t, s, repo, orgA.ID, "starter", store.QuotaResourceProjects)
	if ok {
		t.Fatalf("EffectiveLimit(orgA, starter, projects) found = %+v, want unconfigured — orgB's override leaked across the tenant boundary",
			limit)
	}

	// orgB's own lookup must STILL resolve to orgB's override — the
	// positive-direction pair guarantees the test cannot trivially pass
	// by virtue of the override row not existing in the table at all.
	gotB, okB := effectiveLimitOrFail(ctx, t, s, repo, orgB.ID, "starter", store.QuotaResourceProjects)
	if !okB {
		t.Fatal("EffectiveLimit(orgB, starter, projects) reported unconfigured; orgB's own override is missing from the table — test fixture is invalid")
	}
	if gotB.Resource != store.QuotaResourceProjects || gotB.LimitValue != 99 || gotB.EnforcementMode != store.EnforcementModeSoft {
		t.Errorf("EffectiveLimit(orgB) = %+v, want projects/99/soft", gotB)
	}
}

// TestQuotaRepositoryListEffectiveLimitsCountsAreIsolated proves the
// rendered length of ListEffectiveLimits is local to the queried
// tenant — never the global count, never a sum across tenants. orgA
// owns one override on (services). orgB owns three: projects,
// services, databases. The two tenants are on the SAME plan, and that
// plan has no defaults, so the expected counts are exactly one row
// for orgA and exactly three rows for orgB. A regression that
// dropped the organization_id leg of the WHERE clause would have
// returned four rows for both calls.
func TestQuotaRepositoryListEffectiveLimitsCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceServices, 7, store.EnforcementModeHard)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 11, store.EnforcementModeSoft)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceServices, 22, store.EnforcementModeMetered)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceDatabases, 33, store.EnforcementModeDisabled)

	gotA := listEffectiveLimitsOrFail(ctx, t, s, repo, orgA.ID, "starter")
	if len(gotA) != 1 {
		t.Fatalf("ListEffectiveLimits(orgA) returned %d rows, want 1 — orgB overrides leaked (rows = %+v)", len(gotA), gotA)
	}
	if gotA[0].Resource != store.QuotaResourceServices || gotA[0].LimitValue != 7 || gotA[0].Scope != store.QuotaScopeOrganization {
		t.Errorf("ListEffectiveLimits(orgA)[0] = %+v, want services/7/organization", gotA[0])
	}

	gotB := listEffectiveLimitsOrFail(ctx, t, s, repo, orgB.ID, "starter")
	if len(gotB) != 3 {
		t.Fatalf("ListEffectiveLimits(orgB) returned %d rows, want 3 — orgA's override leaked or orgB's rows went missing (rows = %+v)", len(gotB), gotB)
	}
	// The result is ORDER BY resource so the projection is deterministic:
	// databases (33/disabled), projects (11/soft), services (22/metered).
	wantB := []store.EffectiveQuotaLimit{
		{Resource: store.QuotaResourceDatabases, LimitValue: 33, EnforcementMode: store.EnforcementModeDisabled, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceProjects, LimitValue: 11, EnforcementMode: store.EnforcementModeSoft, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceServices, LimitValue: 22, EnforcementMode: store.EnforcementModeMetered, Scope: store.QuotaScopeOrganization},
	}
	for i, w := range wantB {
		if gotB[i].Resource != w.Resource || gotB[i].LimitValue != w.LimitValue || gotB[i].EnforcementMode != w.EnforcementMode || gotB[i].Scope != w.Scope {
			t.Errorf("ListEffectiveLimits(orgB)[%d] = %+v, want %+v", i, gotB[i], w)
		}
	}

	// The two projections must not overlap on (resource, LimitValue): if
	// the same (resource, limit) pair appeared in both lists the
	// organization_id leg of the WHERE clause is the only thing keeping
	// them apart, and the only way for both calls to share a row is a
	// missing tenant predicate. orgA owns services=7; orgB owns
	// services=22 — the LimitValue divergence is what makes the test
	// load-bearing.
	for _, a := range gotA {
		for _, b := range gotB {
			if a.Resource == b.Resource && a.LimitValue == b.LimitValue {
				t.Errorf("resource %q with limit %d appears in BOTH List(orgA) and List(orgB) — tenant predicate is missing or weak",
					a.Resource, a.LimitValue)
			}
		}
	}
}

// TestQuotaRepositoryListEffectiveLimitsIsolatesSharedResource proves
// the partial unique index on (organization_id, resource) lets two
// tenants legitimately each have an override on the SAME resource,
// and each ListEffectiveLimits call renders only THIS tenant's row —
// never the other's, never a duplicate. The shared-row safety net
// analogous to the shared-scope-name test for api_key_scopes: a
// regression that resolved the WHERE filter by resource alone would
// surface here as a leak even when both tenants had legitimately
// configured the same dimension.
func TestQuotaRepositoryListEffectiveLimitsIsolatesSharedResource(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Both tenants override the same resource, with DISTINCT limit and
	// enforcement values so a swap or merge surfaces in the projection.
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 25, store.EnforcementModeHard)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)

	gotA := listEffectiveLimitsOrFail(ctx, t, s, repo, orgA.ID, "starter")
	if len(gotA) != 1 {
		t.Fatalf("ListEffectiveLimits(orgA) returned %d rows, want exactly 1 — orgB's projects override leaked or duplicated", len(gotA))
	}
	if gotA[0].Resource != store.QuotaResourceProjects || gotA[0].LimitValue != 25 || gotA[0].EnforcementMode != store.EnforcementModeHard {
		t.Errorf("ListEffectiveLimits(orgA)[0] = %+v, want projects/25/hard", gotA[0])
	}

	gotB := listEffectiveLimitsOrFail(ctx, t, s, repo, orgB.ID, "starter")
	if len(gotB) != 1 {
		t.Fatalf("ListEffectiveLimits(orgB) returned %d rows, want exactly 1 — orgA's projects override leaked or duplicated", len(gotB))
	}
	if gotB[0].Resource != store.QuotaResourceProjects || gotB[0].LimitValue != 99 || gotB[0].EnforcementMode != store.EnforcementModeSoft {
		t.Errorf("ListEffectiveLimits(orgB)[0] = %+v, want projects/99/soft", gotB[0])
	}
}

// TestQuotaRepositoryListEffectiveLimitsIsolatesAcrossPlans proves the
// plan_default leg of the WHERE clause is tenant-scoped by the plan
// argument: orgA on "starter" must not see "pro" plan defaults, even
// though both rows live in the same table with NULL organization_id.
// A regression that dropped the plan leg of the WHERE clause would
// have surfaced orgB's plan's defaults in orgA's projection.
func TestQuotaRepositoryListEffectiveLimitsIsolatesAcrossPlans(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// orgA's plan defines projects=5. orgB's plan defines a wholly
	// disjoint dimension (databases=99) that would surface in the
	// orgA-on-starter projection if the plan leg of the WHERE clause
	// were missing.
	seedPlanPolicy(t, db, "qp_starter_projects", "starter", string(store.QuotaResourceProjects), 5)
	seedPlanPolicy(t, db, "qp_pro_databases", "pro", string(store.QuotaResourceDatabases), 99)
	// Sanity: orgA has no org override, so its projection is
	// exclusively the plan_default leg.
	_ = orgB

	gotA := listEffectiveLimitsOrFail(ctx, t, s, repo, orgA.ID, "starter")
	if len(gotA) != 1 {
		t.Fatalf("ListEffectiveLimits(orgA, starter) returned %d rows, want 1 — the 'pro' plan default leaked into 'starter' (rows = %+v)", len(gotA), gotA)
	}
	if gotA[0].Resource != store.QuotaResourceProjects || gotA[0].LimitValue != 5 || gotA[0].Scope != store.QuotaScopePlanDefault {
		t.Errorf("ListEffectiveLimits(orgA, starter)[0] = %+v, want projects/5/plan_default", gotA[0])
	}

	// orgA on "pro" sees the pro plan default — the same row that would
	// have leaked in the orgA-on-starter call if the plan predicate
	// were dropped. The positive-direction pair guarantees the test
	// cannot trivially pass by virtue of the pro plan default not
	// existing in the table at all.
	gotAOnPro := listEffectiveLimitsOrFail(ctx, t, s, repo, orgA.ID, "pro")
	if len(gotAOnPro) != 1 {
		t.Fatalf("ListEffectiveLimits(orgA, pro) returned %d rows, want 1 — the 'pro' plan default is missing from the table or the 'starter' default leaked",
			len(gotAOnPro))
	}
	if gotAOnPro[0].Resource != store.QuotaResourceDatabases || gotAOnPro[0].LimitValue != 99 || gotAOnPro[0].Scope != store.QuotaScopePlanDefault {
		t.Errorf("ListEffectiveLimits(orgA, pro)[0] = %+v, want databases/99/plan_default", gotAOnPro[0])
	}
}

// TestQuotaRepositoryListOrganizationUsageIsTenantScoped proves the
// JOIN-based usage projection is tenant scoped at BOTH legs: only the
// queried tenant's overrides flow through the policies CTE, and only
// the queried tenant's counter rows flow through the usage CTE. A
// regression that dropped the organization_id predicate in EITHER CTE
// would surface a peer tenant's policy or counter in the projection.
//
// orgA has a counter on projects=4 and an override on projects=10.
// orgB has overrides on projects=99 AND databases=77, plus a counter
// on databases=5 and a counter on projects=88. The projection for
// orgA must report ONLY (projects, used=4, limit=10, override) — no
// orgB databases, no orgB projects counter merged in.
func TestQuotaRepositoryListOrganizationUsageIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// orgA's tenant: one override + one counter on the same resource.
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 10, store.EnforcementModeHard)
	seedQuotaUsage(t, db, "qusg_a_projects", orgA.ID, string(store.QuotaResourceProjects), 4)
	// orgB's tenant: two overrides + two counters on overlapping
	// dimensions. ANY of these surfacing in the orgA projection is a
	// leak.
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceDatabases, 77, store.EnforcementModeMetered)
	seedQuotaUsage(t, db, "qusg_b_projects", orgB.ID, string(store.QuotaResourceProjects), 88)
	seedQuotaUsage(t, db, "qusg_b_databases", orgB.ID, string(store.QuotaResourceDatabases), 5)

	gotA := listOrganizationUsageOrFail(ctx, t, s, repo, orgA.ID, "starter")
	if len(gotA) != 1 {
		t.Fatalf("ListOrganizationUsage(orgA) returned %d rows, want 1 — orgB rows leaked through one of the two CTE legs (rows = %+v)",
			len(gotA), gotA)
	}
	row := gotA[0]
	if row.Resource != store.QuotaResourceProjects {
		t.Errorf("ListOrganizationUsage(orgA)[0].Resource = %q, want %q", row.Resource, store.QuotaResourceProjects)
	}
	if row.UsedValue != 4 {
		t.Errorf("ListOrganizationUsage(orgA)[0].UsedValue = %d, want 4 — orgB's counter (88) merged in", row.UsedValue)
	}
	if row.LimitValue == nil || *row.LimitValue != 10 {
		t.Errorf("ListOrganizationUsage(orgA)[0].LimitValue = %v, want 10 — orgB's override (99) leaked or orgA's override is missing", row.LimitValue)
	}
	if row.EnforcementMode == nil || *row.EnforcementMode != store.EnforcementModeHard {
		t.Errorf("ListOrganizationUsage(orgA)[0].EnforcementMode = %v, want hard", row.EnforcementMode)
	}
	if row.Scope == nil || *row.Scope != store.QuotaScopeOrganization {
		t.Errorf("ListOrganizationUsage(orgA)[0].Scope = %v, want organization", row.Scope)
	}
}

// TestQuotaRepositoryListOrganizationUsageIsolatesSharedCounter proves
// the usage CTE is tenant scoped at the counter row level: when both
// tenants have a counter row for the SAME resource with DISTINCT
// used_value values, each ListOrganizationUsage call renders only THIS
// tenant's counter — never the other's, never a sum. A regression
// that dropped the organization_id leg of the usage CTE would surface
// here as a counter merge or swap.
func TestQuotaRepositoryListOrganizationUsageIsolatesSharedCounter(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	seedQuotaUsage(t, db, "qusg_a_projects", orgA.ID, string(store.QuotaResourceProjects), 3)
	seedQuotaUsage(t, db, "qusg_b_projects", orgB.ID, string(store.QuotaResourceProjects), 17)

	gotA := listOrganizationUsageOrFail(ctx, t, s, repo, orgA.ID, "starter")
	if len(gotA) != 1 {
		t.Fatalf("ListOrganizationUsage(orgA) returned %d rows, want 1 (rows = %+v)", len(gotA), gotA)
	}
	if gotA[0].UsedValue != 3 {
		t.Errorf("ListOrganizationUsage(orgA)[0].UsedValue = %d, want 3 — orgB's counter (17) leaked", gotA[0].UsedValue)
	}

	gotB := listOrganizationUsageOrFail(ctx, t, s, repo, orgB.ID, "starter")
	if len(gotB) != 1 {
		t.Fatalf("ListOrganizationUsage(orgB) returned %d rows, want 1 (rows = %+v)", len(gotB), gotB)
	}
	if gotB[0].UsedValue != 17 {
		t.Errorf("ListOrganizationUsage(orgB)[0].UsedValue = %d, want 17 — orgA's counter (3) leaked", gotB[0].UsedValue)
	}
}

// TestQuotaRepositoryUpsertOrganizationPolicyInsertOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the Insert branch of
// UpsertOrganizationPolicy. orgB has an existing override on
// (services); orgA inserts a brand-new override on (services) — the
// SAME resource so the ON CONFLICT predicate is exercised — and orgB's
// row must be byte-identical to its baseline across every observable
// column. The trigger-managed updated_at is the load-bearing anchor:
// the BEFORE UPDATE trigger refreshes it on every matched UPDATE, so a
// regression that resolved the ON CONFLICT branch by (resource,) alone
// — dropping the organization_id leg of the partial unique index
// target — would fire the UPDATE on orgB's row and surface here.
func TestQuotaRepositoryUpsertOrganizationPolicyInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	// orgB owns its own (services) override; orgA has none yet.
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceServices, 50, store.EnforcementModeHard)
	baselineB := loadOrganizationPolicyRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)

	// orgA inserts a fresh override on the SAME resource. The Insert
	// branch must mint a new row owned by orgA — never UPDATE orgB's
	// row.
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceServices, 7, store.EnforcementModeSoft)

	// orgA's row exists, owns the right organization and the right
	// values — a no-op repository cannot silently pass the
	// byte-identical-orgB check below.
	insertedA := loadOrganizationPolicyRow(ctx, t, db, orgA.ID, store.QuotaResourceServices)
	if insertedA.OrganizationID == nil || *insertedA.OrganizationID != orgA.ID || insertedA.LimitValue != 7 || insertedA.EnforcementMode != string(store.EnforcementModeSoft) {
		t.Errorf("Upsert Insert on orgA produced %+v, want orgA/services/7/soft", insertedA)
	}
	// orgA's new row must NOT collide with orgB's id.
	if insertedA.ID == baselineB.ID {
		t.Fatalf("Upsert minted orgA's id %q identical to orgB's existing id — id collision invalidates the byte-identical check below",
			insertedA.ID)
	}

	afterB := loadOrganizationPolicyRow(ctx, t, db, orgB.ID, store.QuotaResourceServices)
	assertQuotaPolicyByteIdentical(t, "Upsert Insert(orgA) bystander orgB", baselineB, afterB)
}

// TestQuotaRepositoryUpsertOrganizationPolicyUpdateOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the UPDATE branch of
// UpsertOrganizationPolicy. Both tenants own an existing override on
// the SAME resource — the maximally adversarial fixture for the ON
// CONFLICT path. orgA UPDATEs its own row; orgB's row must be
// byte-identical to its baseline across every observable column. A
// regression that dropped the organization_id leg of the partial
// unique index target would route the UPDATE onto whichever row the
// planner picked first — and the trigger-managed updated_at would
// surface that drift even when the column writes happened to land on
// the wrong row by chance.
func TestQuotaRepositoryUpsertOrganizationPolicyUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Both tenants seed an override on the SAME resource — the
	// shared-conflict-tuple fixture is what makes the byte-identical
	// proof load-bearing.
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 25, store.EnforcementModeHard)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)
	baselineB := loadOrganizationPolicyRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)

	// orgA mutates its own row to a new (limit, mode) pair — the
	// EXCLUDED.* clauses fire the UPDATE on whichever row the ON
	// CONFLICT branch matches. The partial unique index target
	// (organization_id, resource) WHERE scope_kind='organization' makes
	// that orgA's row.
	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 50, store.EnforcementModeMetered)

	// orgA's row reflects the UPDATE — the test cannot trivially pass
	// by virtue of the UPDATE never having matched any row at all.
	updatedA := loadOrganizationPolicyRow(ctx, t, db, orgA.ID, store.QuotaResourceProjects)
	if updatedA.LimitValue != 50 || updatedA.EnforcementMode != string(store.EnforcementModeMetered) {
		t.Errorf("Upsert UPDATE on orgA produced %+v, want limit=50 mode=metered", updatedA)
	}

	afterB := loadOrganizationPolicyRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)
	assertQuotaPolicyByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestQuotaRepositoryUpsertOrganizationPolicySameResourceInTwoTenantsBothSucceed
// proves the partial unique index quota_policies_org_resource_idx is
// per-tenant, not global: two tenants can legitimately each have an
// organization override on the SAME resource, and neither Upsert
// collides with the other. The flip side is the load-bearing reason
// every bystander assertion above is the byte-identical projection —
// if the partial index were global (organization_id ignored), the two
// Upserts could not coexist, and the WHERE filter on every read leg
// would be redundant.
func TestQuotaRepositoryUpsertOrganizationPolicySameResourceInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	upsertOrganizationPolicy(ctx, t, s, repo, orgA.ID, store.QuotaResourceProjects, 25, store.EnforcementModeHard)
	upsertOrganizationPolicy(ctx, t, s, repo, orgB.ID, store.QuotaResourceProjects, 99, store.EnforcementModeSoft)

	rowA := loadOrganizationPolicyRow(ctx, t, db, orgA.ID, store.QuotaResourceProjects)
	rowB := loadOrganizationPolicyRow(ctx, t, db, orgB.ID, store.QuotaResourceProjects)

	if rowA.ID == rowB.ID {
		t.Fatalf("two tenants minted the same quota_policies id %q — the id generator collided, the byte-identical-bystander tests above are invalid",
			rowA.ID)
	}
	if rowA.OrganizationID == nil || rowB.OrganizationID == nil {
		t.Fatalf("organization_id is NULL on at least one row: orgA=%v orgB=%v — scope_consistent CHECK is broken",
			rowA.OrganizationID, rowB.OrganizationID)
	}
	if *rowA.OrganizationID == *rowB.OrganizationID {
		t.Errorf("two override rows landed under the SAME organization_id %q — the partial unique index merged the two upserts", *rowA.OrganizationID)
	}
	if rowA.Resource != rowB.Resource {
		t.Errorf("resource drifted between the two upserts: orgA=%q orgB=%q, want both %q", rowA.Resource, rowB.Resource, store.QuotaResourceProjects)
	}
	if rowA.LimitValue == rowB.LimitValue {
		t.Errorf("limit_value collapsed onto the same value: orgA=%d orgB=%d — the EXCLUDED.* clauses fired across the tenant boundary", rowA.LimitValue, rowB.LimitValue)
	}
}
