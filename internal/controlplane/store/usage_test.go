package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for UsageReader and QuotaRepository.ListOrganizationUsage —
// the persistence half of GET /v1/organizations/{org_id}/usage (BE-0100).
// They run against an isolated, freshly migrated Postgres database and skip
// when YALLA_TEST_DATABASE_URL is unset. They prove the join over the
// effective-limit resolution and the quota_usage counter is correct
// (organization overrides beat plan defaults; usage without a configured
// limit is reported as unconstrained; configured limits without usage report
// used_value=0), the result is in deterministic resource order, and the
// read is tenant scoped at both legs of the join.

// seedQuotaUsage inserts a counter row for (orgID, resource) at used_value.
func seedQuotaUsage(t *testing.T, db *testutil.DB, id, orgID, resource string, used int64) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, $4)`,
		id, orgID, resource, used); err != nil {
		t.Fatalf("seed quota_usage %q: %v", id, err)
	}
}

// TestQuotaRepositoryListOrganizationUsageJoinsPolicyAndCounter proves the
// happy path: every resource that has either a configured limit at the
// tenant's scope or a quota_usage counter row appears in the result, the
// effective-limit resolution (organization override beats plan default) is
// the same lookup the quota checker uses, used_value defaults to 0 when no
// counter exists yet, and a resource with usage but no policy is reported
// as unconstrained.
func TestQuotaRepositoryListOrganizationUsageJoinsPolicyAndCounter(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	// projects: plan default 3, organization override 10, current usage 4
	// -> override wins, scope=organization, used=4.
	seedPlanPolicy(t, db, "qp_plan_projects_u", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects_u", org.ID, "projects", 10)
	seedQuotaUsage(t, db, "qu_projects_u", org.ID, "projects", 4)
	// services: plan default only, no usage row yet -> plan default,
	// scope=plan_default, used=0.
	seedPlanPolicy(t, db, "qp_plan_services_u", "starter", "services", 25)
	// domains: usage but no policy at either scope -> unconstrained, used=7.
	seedQuotaUsage(t, db, "qu_domains_u", org.ID, "domains", 7)

	var got []store.OrganizationResourceUsage
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListOrganizationUsage(ctx, q, org.ID, "starter")
		return err
	}); err != nil {
		t.Fatalf("ListOrganizationUsage: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3; got = %+v", len(got), got)
	}
	// The full outer join's COALESCE(p.resource, u.resource) + ORDER BY resource
	// yields deterministic alphabetical order: domains, projects, services.
	if got[0].Resource != store.QuotaResourceDomains || got[0].UsedValue != 7 || got[0].LimitValue != nil {
		t.Errorf("[0] = %+v, want domains used=7 limit=nil", got[0])
	}
	if got[0].EnforcementMode != nil || got[0].Scope != nil {
		t.Errorf("[0] mode/scope = %v/%v, want nil/nil for an unconstrained resource", got[0].EnforcementMode, got[0].Scope)
	}
	if got[1].Resource != store.QuotaResourceProjects || got[1].UsedValue != 4 {
		t.Errorf("[1] = %+v, want projects used=4", got[1])
	}
	if got[1].LimitValue == nil || *got[1].LimitValue != 10 {
		t.Errorf("[1].LimitValue = %v, want 10 (organization override)", got[1].LimitValue)
	}
	if got[1].Scope == nil || *got[1].Scope != store.QuotaScopeOrganization {
		t.Errorf("[1].Scope = %v, want organization", got[1].Scope)
	}
	if got[1].EnforcementMode == nil || *got[1].EnforcementMode != store.EnforcementModeHard {
		t.Errorf("[1].EnforcementMode = %v, want hard", got[1].EnforcementMode)
	}
	if got[2].Resource != store.QuotaResourceServices || got[2].UsedValue != 0 {
		t.Errorf("[2] = %+v, want services used=0", got[2])
	}
	if got[2].LimitValue == nil || *got[2].LimitValue != 25 {
		t.Errorf("[2].LimitValue = %v, want 25 (plan default)", got[2].LimitValue)
	}
	if got[2].Scope == nil || *got[2].Scope != store.QuotaScopePlanDefault {
		t.Errorf("[2].Scope = %v, want plan_default", got[2].Scope)
	}
}

// TestQuotaRepositoryListOrganizationUsageEmpty proves an organization with
// no quota_usage rows and no configured policies at either scope yields an
// empty slice rather than a nil — exactly the same shape the wire-empty
// case must serve.
func TestQuotaRepositoryListOrganizationUsageEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Empty")

	var got []store.OrganizationResourceUsage
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListOrganizationUsage(ctx, q, org.ID, "starter")
		return err
	}); err != nil {
		t.Fatalf("ListOrganizationUsage: %v", err)
	}
	if got == nil {
		t.Errorf("got = nil, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0; got = %+v", len(got), got)
	}
}

// TestQuotaRepositoryListOrganizationUsageTenantScoped proves the read is
// tenant scoped at every leg of the join: neither another organization's
// override nor another organization's counter rows leak into the result,
// even when both organizations share the same plan and resource.
func TestQuotaRepositoryListOrganizationUsageTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "AcmeA")
	orgB := seedOrg(t, db, f, "AcmeB")
	// Org A has an override and a counter for projects, plus a counter for
	// domains; both organizations inherit the plan default for projects.
	seedPlanPolicy(t, db, "qp_plan_projects_ts", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects_ts_a", orgA.ID, "projects", 50)
	seedQuotaUsage(t, db, "qu_projects_ts_a", orgA.ID, "projects", 12)
	seedQuotaUsage(t, db, "qu_domains_ts_a", orgA.ID, "domains", 1)

	var (
		gotA []store.OrganizationResourceUsage
		gotB []store.OrganizationResourceUsage
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		a, err := repo.ListOrganizationUsage(ctx, q, orgA.ID, "starter")
		if err != nil {
			return err
		}
		gotA = a
		b, err := repo.ListOrganizationUsage(ctx, q, orgB.ID, "starter")
		if err != nil {
			return err
		}
		gotB = b
		return nil
	}); err != nil {
		t.Fatalf("ListOrganizationUsage: %v", err)
	}

	// orgA sees both resources with its own values.
	if len(gotA) != 2 {
		t.Fatalf("orgA len = %d, want 2; got = %+v", len(gotA), gotA)
	}
	// orgB sees only the projects plan default, with no usage; org A's
	// override of 50 must not leak, and org A's domains counter must not
	// leak either.
	if len(gotB) != 1 {
		t.Fatalf("orgB len = %d, want 1 (just the plan default for projects); got = %+v", len(gotB), gotB)
	}
	if gotB[0].Resource != store.QuotaResourceProjects {
		t.Errorf("orgB[0].Resource = %q, want projects", gotB[0].Resource)
	}
	if gotB[0].LimitValue == nil || *gotB[0].LimitValue != 3 {
		t.Errorf("orgB[0].LimitValue = %v, want 3 (plan default; org A's override of 50 must not leak)", gotB[0].LimitValue)
	}
	if gotB[0].UsedValue != 0 {
		t.Errorf("orgB[0].UsedValue = %d, want 0 (org A's counter of 12 must not leak)", gotB[0].UsedValue)
	}
}

// TestUsageReaderListOrganizationUsage proves the UsageReader adapter wires
// the repository through Store.Read and the configured PlanLookup —
// passing nil falls back to DefaultPlan, so the lookup observes the same
// plan name the deployment seeded with.
func TestUsageReaderListOrganizationUsage(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderAcme")
	// Plan default on the DefaultPlan placeholder, organization override
	// for services, and a usage counter for projects.
	seedPlanPolicy(t, db, "qp_plan_projects_ur", store.DefaultPlan, "projects", 5)
	seedOrgPolicy(t, db, "qp_org_services_ur", org.ID, "services", 99)
	seedQuotaUsage(t, db, "qu_projects_ur", org.ID, "projects", 2)

	reader, err := store.NewUsageReader(s, nil)
	if err != nil {
		t.Fatalf("NewUsageReader: %v", err)
	}
	got, err := reader.ListOrganizationUsage(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrganizationUsage: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2; got = %+v", len(got), got)
	}
	// Alphabetical order: projects, services.
	if got[0].Resource != store.QuotaResourceProjects || got[0].UsedValue != 2 {
		t.Errorf("[0] = %+v, want projects used=2", got[0])
	}
	if got[0].LimitValue == nil || *got[0].LimitValue != 5 || got[0].Scope == nil || *got[0].Scope != store.QuotaScopePlanDefault {
		t.Errorf("[0] limit projection = %+v, want plan default of 5", got[0])
	}
	if got[1].Resource != store.QuotaResourceServices || got[1].UsedValue != 0 {
		t.Errorf("[1] = %+v, want services used=0", got[1])
	}
	if got[1].LimitValue == nil || *got[1].LimitValue != 99 || got[1].Scope == nil || *got[1].Scope != store.QuotaScopeOrganization {
		t.Errorf("[1] limit projection = %+v, want organization override of 99", got[1])
	}
}

// TestUsageReaderRespectsCustomPlanLookup proves the constructor wires the
// PlanLookup function: the lookup is called inside the same read
// transaction the join runs in, so plan/usage pairs are always coherent.
func TestUsageReaderRespectsCustomPlanLookup(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderPlanU")
	// Seed plan defaults for two named plans; the custom lookup must pick
	// the right one, and the deployment's quota_usage counter must always
	// be observed regardless of which plan applies.
	seedPlanPolicy(t, db, "qp_plan_starter_pu", "starter", "projects", 5)
	seedPlanPolicy(t, db, "qp_plan_pro_pu", "pro", "projects", 50)
	seedQuotaUsage(t, db, "qu_projects_pu", org.ID, "projects", 3)

	reader, err := store.NewUsageReader(s, func(_ context.Context, _ store.Querier, _ string) (string, error) {
		return "pro", nil
	})
	if err != nil {
		t.Fatalf("NewUsageReader: %v", err)
	}
	got, err := reader.ListOrganizationUsage(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrganizationUsage: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1; got = %+v", len(got), got)
	}
	if got[0].LimitValue == nil || *got[0].LimitValue != 50 {
		t.Errorf("LimitValue = %v, want 50 (the lookup chose plan \"pro\")", got[0].LimitValue)
	}
	if got[0].UsedValue != 3 {
		t.Errorf("UsedValue = %d, want 3", got[0].UsedValue)
	}
}

// TestNewUsageReaderRejectsNilStore proves a misconfigured reader fails at
// construction rather than on its first request.
func TestNewUsageReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewUsageReader(nil, nil); err == nil {
		t.Error("NewUsageReader(nil, nil) returned no error; want a nil-store error")
	}
}
