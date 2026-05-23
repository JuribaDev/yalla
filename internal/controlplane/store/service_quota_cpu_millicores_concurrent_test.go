package store_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/quota"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// TestServiceServiceCreateRejectsParallelOversubscriptionForCPUMillicoresQuota
// is the integration test for BE-0331 (quota dimension: cpu_millicores) —
// the "concurrent integration tests prove parallel requests cannot
// oversubscribe the quota" acceptance criterion. Unlike the per-subtype
// count dimensions (applications / compose_stacks / databases /
// preview_environments / domains), cpu_millicores is the FIRST dimensional
// magnitude dimension: every service create consumes a per-Kind baseline
// of CPU millicores against the tenant's cpu_millicores ceiling, and the
// rejection's ExceededDetail.Requested is the per-Kind magnitude — not a
// constant 1. The test wires a real *store.ServiceService against a real
// *quota.Checker, a real *store.QuotaRepository, and a real
// *store.AuditRepository — the only fakes are the Authorizer and
// JobEnqueuer dependencies (covered by their own dedicated stories),
// which are recording fakes that always succeed.
//
// Twenty goroutines race to create a fresh application-kind service
// inside the same environment against a hard-enforced cpu_millicores
// limit of 1000 — exactly four times the per-application baseline of
// 250 millicores. Every other dimension (services, applications) is
// seeded LOOSE so it cannot be the boundary that bites. The test
// asserts that exactly four Create calls return successfully and that
// the remaining sixteen are rejected with the typed CodeQuotaExceeded
// code, that each rejection carries a recoverable quota.ExceededDetail
// whose Resource is "cpu_millicores" (proving the rejection came from
// the new dimensional dimension and not from any of the count
// dimensions), whose Requested is the per-Kind amount 250 (proving the
// magnitude-axis plumbing reached the Checker and the wire), whose
// Limit is 1000, whose Reserved is the cumulative-after-winners 1000,
// and whose Current is 0 (no usage was committed during the race).
// The test then asserts that exactly four service rows are visible in
// the database, that exactly four active reservations exist on the
// cpu_millicores dimension (one per winner, each carrying Amount=250),
// and that the sum of active cpu_millicores reservations equals
// successes * per-Kind-amount = 1000. Together these assertions prove
// the quota_usage row lock (SELECT FOR UPDATE inside ReserveAmount)
// serialises concurrent transactions against the cpu_millicores
// counter row so the dimensional limit can never be over-allocated.
//
// This test is the BE-0331 dimensional clone of the BE-0326..0330
// per-subtype count-dimension references (documented in
// ralph/progress.txt). The differences are:
// (1) the policy is seeded with a LIMIT that is a multiple of the
//
//	per-Kind magnitude rather than the attempt count, so the
//	successes count is limit/amount rather than equal to limit;
//
// (2) ExceededDetail.Requested is the per-Kind magnitude (250 for
//
//	ServiceKindApplication, sourced from
//	serviceCPUMillicoresByKind in serviceservice.go), not 1;
//
// (3) the active-reservations SUM (via SumActiveReservations) is the
//
//	authoritative check — a raw COUNT(*) merely confirms there are
//	successes-many reservation rows, while SumActiveReservations
//	proves their Amount column carries the per-Kind magnitude;
//
// (4) the leaky-input redaction check still pins that the rejection
//
//	diagnostic never carries caller-supplied content, since the
//	dimensional path uses the same quotaExceeded() formatter as
//	the count path.
func TestServiceServiceCreateRejectsParallelOversubscriptionForCPUMillicoresQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan = "starter"
		// Per-application CPU baseline. Mirrors
		// serviceCPUMillicoresByKind[ServiceKindApplication] in
		// serviceservice.go; the value is stable contract and a
		// future change must update both sides together.
		appCPUMillicores = int64(250)
		// CPU ceiling is exactly four application-sized allocations.
		// The successes count is therefore cpuLimit/appCPUMillicores = 4,
		// which is materially smaller than attempts so the rejections
		// can only come from the cpu_millicores dimension row lock.
		cpuLimit          = int64(1000)
		expectedSuccesses = cpuLimit / appCPUMillicores
		// Loose bounds for every count dimension every application
		// create also touches: services and applications. They are
		// large enough that the count-dimension row locks cannot be
		// the limit that bites, so every rejection's
		// detail.Resource can only be "cpu_millicores".
		servicesLimit     = int64(100)
		applicationsLimit = int64(100)
		attempts          = 20
	)

	orgID := domain.MustNewID(domain.KindOrganization).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	projectID := domain.MustNewID(domain.KindProject).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		projectID, orgID, "prj-"+projectID[len(projectID)-12:], "Test Project"); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	environmentID := domain.MustNewID(domain.KindEnvironment).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
		 VALUES ($1, $2, $3, $4, $5)`,
		environmentID, orgID, projectID,
		"env-"+environmentID[len(environmentID)-12:], "Test Environment"); err != nil {
		t.Fatalf("seed environment: %v", err)
	}

	// Pre-seed every quota_usage counter row touched by an application
	// create: cpu_millicores (the tight bound the test exercises) plus
	// services and applications (loose bounds — every application
	// create also reserves +1 of each). LockUsage acquires the row
	// without inserting mid-race so the concurrent serialisation is
	// purely about the SELECT FOR UPDATE step on rows that already
	// exist.
	for _, seed := range []struct {
		id  string
		res store.QuotaResource
	}{
		{"qu_cpu_concurrent_cpu", store.QuotaResourceCPUMillicores},
		{"qu_cpu_concurrent_svc", store.QuotaResourceServices},
		{"qu_cpu_concurrent_app", store.QuotaResourceApplications},
	} {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_usage (id, organization_id, resource, used_value)
			 VALUES ($1, $2, $3, 0)`,
			seed.id, orgID, string(seed.res)); err != nil {
			t.Fatalf("seed %s quota_usage: %v", seed.res, err)
		}
	}

	// Plan-default policies for every touched dimension. CPU is the
	// TIGHT bound at exactly four application-sized allocations — this
	// is the dimension the test proves serialises under concurrent
	// load. Services and applications are LOOSE — large enough that
	// neither row lock can be the limit that bites, so a rejection's
	// detail.Resource can only be "cpu_millicores". No organization
	// override is seeded, so the Checker's plan-default fallback path
	// is the one exercised.
	for _, seed := range []struct {
		id    string
		res   store.QuotaResource
		limit int64
	}{
		{"qp_cpu_concurrent_cpu", store.QuotaResourceCPUMillicores, cpuLimit},
		{"qp_cpu_concurrent_svc", store.QuotaResourceServices, servicesLimit},
		{"qp_cpu_concurrent_app", store.QuotaResourceApplications, applicationsLimit},
	} {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
			 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
			seed.id, plan, string(seed.res), seed.limit); err != nil {
			t.Fatalf("seed %s plan policy: %v", seed.res, err)
		}
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewServiceService(
		s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		store.NewServiceRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceService: %v", err)
	}

	type outcome struct {
		index     int
		serviceID string
		slug      string
		err       error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateServiceInput{
				OrganizationID: orgID,
				EnvironmentID:  environmentID,
				ServiceID:      domain.MustNewID(domain.KindService).String(),
				Slug:           fmt.Sprintf("cpu-%02d", i),
				DisplayName:    fmt.Sprintf("CPU %02d", i),
				// Kind is pinned to the application taxonomy member so
				// every goroutine consumes the same per-Kind magnitude
				// (appCPUMillicores). A mixed-Kind race would make the
				// successes-count derivation cpu_limit/per_kind_amount
				// non-trivial; pinning the kind keeps the boundary the
				// test exercises clean.
				Kind:          store.ServiceKindApplication,
				ActorID:       "usr_cpu_concurrent",
				ActorKind:     "usr",
				ActorOrgID:    orgID,
				RequestID:     fmt.Sprintf("req_cpu_%02d", i),
				CorrelationID: fmt.Sprintf("corr_cpu_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{
				index:     i,
				serviceID: in.ServiceID,
				slug:      in.Slug,
				err:       createErr,
			}
		}(i)
	}
	wg.Wait()

	var successes, rejections int
	var successIDs []string
	for _, r := range results {
		if r.err == nil {
			successes++
			successIDs = append(successIDs, r.serviceID)
			continue
		}
		ye := yerr.From(r.err)
		if ye.Code != yerr.CodeQuotaExceeded {
			t.Errorf("attempt %d returned error code %s, want %s (err=%v)",
				r.index, ye.Code, yerr.CodeQuotaExceeded, r.err)
			continue
		}
		rejections++

		detail, ok := quota.DetailOf(r.err)
		if !ok {
			t.Errorf("attempt %d quota error did not carry a recoverable ExceededDetail (err=%v)",
				r.index, r.err)
			continue
		}
		// The rejection MUST name the cpu_millicores dimension. If it
		// ever names "services" or "applications" instead, then either
		// (a) Service.Create is no longer calling ReserveAmount for the
		// cpu_millicores dimension, or (b) one of the count-dimension
		// upper bounds is too tight to keep the dimensional boundary
		// the one that bites. Either is a defect this test surfaces.
		if detail.Resource != string(store.QuotaResourceCPUMillicores) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceCPUMillicores)
		}
		if detail.Limit != cpuLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, cpuLimit)
		}
		// Requested is the per-Kind magnitude — NOT 1. A regression
		// that hard-coded the dimensional path back to amount=1 would
		// surface here as detail.Requested=1.
		if detail.Requested != appCPUMillicores {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want %d (per-Kind magnitude)",
				r.index, detail.Requested, appCPUMillicores)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal
		// successes * per-Kind magnitude = cpuLimit (since
		// expectedSuccesses == cpuLimit/appCPUMillicores). Anything
		// less would mean the lock did not serialise concurrent
		// reservers, or the per-Kind magnitude did not reach the
		// reservation row.
		if detail.Reserved != expectedSuccesses*appCPUMillicores {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, expectedSuccesses*appCPUMillicores)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, slug, display name, correlation id, or service id — so a
		// future logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("cpu-%02d", r.index),
			fmt.Sprintf("CPU %02d", r.index),
			fmt.Sprintf("req_cpu_%02d", r.index),
			fmt.Sprintf("corr_cpu_%02d", r.index),
			r.serviceID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if int64(successes) != expectedSuccesses {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, expectedSuccesses)
	}
	if int64(rejections) != attempts-expectedSuccesses {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-expectedSuccesses)
	}

	// The winners are unique — no two goroutines can have shared a
	// service id since each generated its own canonical id.
	seen := make(map[string]struct{}, len(successIDs))
	for _, id := range successIDs {
		if _, dup := seen[id]; dup {
			t.Errorf("two winners reported the same service id %q", id)
		}
		seen[id] = struct{}{}
	}

	// The desired-state row count must match the success count exactly —
	// proves no rejected transaction left behind a half-written service,
	// and no committed transaction failed to persist its service row.
	var serviceRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM services WHERE organization_id = $1 AND environment_id = $2`,
		orgID, environmentID).Scan(&serviceRows); err != nil {
		t.Fatalf("count services: %v", err)
	}
	if serviceRows != expectedSuccesses {
		t.Errorf("services rows for (org, env) = %d, want %d", serviceRows, expectedSuccesses)
	}

	// Each winning Create commits exactly ONE cpu_millicores reservation
	// row whose Amount carries the per-Kind magnitude. Counting rows
	// proves the row count; summing Amount proves the magnitude reached
	// the table — the dimensional contract this story introduces.
	var activeCPUReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceCPUMillicores)).Scan(&activeCPUReservations); err != nil {
		t.Fatalf("count active cpu_millicores reservations: %v", err)
	}
	if activeCPUReservations != expectedSuccesses {
		t.Errorf("active cpu_millicores reservations = %d, want %d",
			activeCPUReservations, expectedSuccesses)
	}
	var summedCPUAmount int64
	if err := db.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount), 0) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceCPUMillicores)).Scan(&summedCPUAmount); err != nil {
		t.Fatalf("sum active cpu_millicores reservation amounts: %v", err)
	}
	if summedCPUAmount != expectedSuccesses*appCPUMillicores {
		t.Errorf("SUM(amount) on active cpu_millicores reservations = %d, want %d (per-Kind magnitude not persisted)",
			summedCPUAmount, expectedSuccesses*appCPUMillicores)
	}

	// SumActiveReservations is the surface the Checker consults to
	// decide future requests. It must agree with the raw SUM above —
	// the wire that gates the next allocation cannot disagree with the
	// table itself.
	var summedCPU int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceCPUMillicores, time.Now().UTC())
		if err != nil {
			return err
		}
		summedCPU = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedCPU != expectedSuccesses*appCPUMillicores {
		t.Errorf("SumActiveReservations(cpu_millicores) = %d, want %d",
			summedCPU, expectedSuccesses*appCPUMillicores)
	}

	// Both fakes were called exactly once per Create attempt — except
	// for the JobEnqueuer, which is never reached by a rejected
	// transaction because quota fails first. Authorization runs before
	// quota, so the rejected attempts increment authz but not jobs.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
	if got := jobs.calls.Load(); got != expectedSuccesses {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			got, expectedSuccesses)
	}
}

// TestServiceServiceCreateCPUMillicoresAmountVariesByKind pins the
// dimensional contract this story introduces: the cpu_millicores
// reservation amount reflects the SERVICE KIND, not a constant
// per-resource value. A regression that hard-coded the dimensional
// path back to amount=1 — or that swapped the per-Kind map for a flat
// baseline — would let the wrong amount reach the reservation row,
// and the next caller's Reserved sum would lie about real CPU
// pressure. This test proves end-to-end that:
//
//   - an application-kind service reserves 250 cpu_millicores;
//   - a compose-kind service reserves 500 cpu_millicores;
//   - a database-kind service reserves 500 cpu_millicores;
//   - the rejection's ExceededDetail.Requested matches the per-Kind
//     magnitude of the request that overflowed, not a constant.
//
// The cpu_millicores ceiling is set to 1000 — exactly large enough to
// fit one application (250) + one database (500) + one more
// application (250) = 1000 millicores, leaving no headroom. A
// subsequent compose-kind request (would-reserve 500) is rejected
// with Requested=500; a subsequent application-kind request
// (would-reserve 250) is rejected with Requested=250. The count
// dimensions (services, applications, compose_stacks, databases) are
// seeded LOOSE so they cannot be the limit that bites — every
// rejection must name cpu_millicores.
func TestServiceServiceCreateCPUMillicoresAmountVariesByKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan                 = "starter"
		appCPUMillicores     = int64(250)
		composeCPUMillicores = int64(500)
		dbCPUMillicores      = int64(500)
		// 250 + 500 + 250 = 1000 — exactly full.
		cpuLimit        = int64(1000)
		looseCountLimit = int64(50)
	)

	orgID := domain.MustNewID(domain.KindOrganization).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	projectID := domain.MustNewID(domain.KindProject).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		projectID, orgID, "prj-"+projectID[len(projectID)-12:], "Test Project"); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	environmentID := domain.MustNewID(domain.KindEnvironment).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
		 VALUES ($1, $2, $3, $4, $5)`,
		environmentID, orgID, projectID,
		"env-"+environmentID[len(environmentID)-12:], "Test Environment"); err != nil {
		t.Fatalf("seed environment: %v", err)
	}

	for _, seed := range []struct {
		id  string
		res store.QuotaResource
	}{
		{"qu_cpukind_cpu", store.QuotaResourceCPUMillicores},
		{"qu_cpukind_svc", store.QuotaResourceServices},
		{"qu_cpukind_app", store.QuotaResourceApplications},
		{"qu_cpukind_cmp", store.QuotaResourceComposeStacks},
		{"qu_cpukind_db", store.QuotaResourceDatabases},
	} {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_usage (id, organization_id, resource, used_value)
			 VALUES ($1, $2, $3, 0)`,
			seed.id, orgID, string(seed.res)); err != nil {
			t.Fatalf("seed %s quota_usage: %v", seed.res, err)
		}
	}

	for _, seed := range []struct {
		id    string
		res   store.QuotaResource
		limit int64
	}{
		{"qp_cpukind_cpu", store.QuotaResourceCPUMillicores, cpuLimit},
		{"qp_cpukind_svc", store.QuotaResourceServices, looseCountLimit},
		{"qp_cpukind_app", store.QuotaResourceApplications, looseCountLimit},
		{"qp_cpukind_cmp", store.QuotaResourceComposeStacks, looseCountLimit},
		{"qp_cpukind_db", store.QuotaResourceDatabases, looseCountLimit},
	} {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
			 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
			seed.id, plan, string(seed.res), seed.limit); err != nil {
			t.Fatalf("seed %s plan policy: %v", seed.res, err)
		}
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}
	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewServiceService(
		s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		store.NewServiceRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceService: %v", err)
	}

	create := func(t *testing.T, kind, slug, requestSuffix string) error {
		t.Helper()
		in := store.CreateServiceInput{
			OrganizationID: orgID,
			EnvironmentID:  environmentID,
			ServiceID:      domain.MustNewID(domain.KindService).String(),
			Slug:           slug,
			DisplayName:    slug,
			Kind:           kind,
			ActorID:        "usr_cpukind",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      "req_cpukind_" + requestSuffix,
			CorrelationID:  "corr_cpukind_" + requestSuffix,
		}
		_, createErr := svc.Create(ctx, in)
		return createErr
	}

	// Step 1: an application reserves 250. Running total: 250/1000.
	if err := create(t, store.ServiceKindApplication, "app-1", "app1"); err != nil {
		t.Fatalf("application create 1: %v", err)
	}
	// Step 2: a database reserves 500. Running total: 750/1000.
	if err := create(t, store.ServiceKindDatabase, "db-1", "db1"); err != nil {
		t.Fatalf("database create 1: %v", err)
	}
	// Step 3: another application reserves 250. Running total: 1000/1000.
	if err := create(t, store.ServiceKindApplication, "app-2", "app2"); err != nil {
		t.Fatalf("application create 2: %v", err)
	}

	// Step 4: a compose service would reserve 500 but only 0 headroom
	// remains — rejection must carry Requested=500 (compose magnitude),
	// proving the per-Kind amount reached the Checker.
	composeErr := create(t, store.ServiceKindCompose, "cmp-overflow", "cmp_overflow")
	if composeErr == nil {
		t.Fatalf("compose overflow: expected cpu_millicores rejection, got success")
	}
	if ye := yerr.From(composeErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("compose overflow code = %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	}
	composeDetail, ok := quota.DetailOf(composeErr)
	if !ok {
		t.Fatalf("compose overflow: no ExceededDetail (err=%v)", composeErr)
	}
	if composeDetail.Resource != string(store.QuotaResourceCPUMillicores) {
		t.Errorf("compose overflow detail.Resource = %q, want %q",
			composeDetail.Resource, store.QuotaResourceCPUMillicores)
	}
	if composeDetail.Requested != composeCPUMillicores {
		t.Errorf("compose overflow detail.Requested = %d, want %d (per-Kind magnitude not reaching Checker)",
			composeDetail.Requested, composeCPUMillicores)
	}
	if composeDetail.Limit != cpuLimit {
		t.Errorf("compose overflow detail.Limit = %d, want %d",
			composeDetail.Limit, cpuLimit)
	}
	if composeDetail.Reserved != cpuLimit {
		t.Errorf("compose overflow detail.Reserved = %d, want %d (sum of two apps + one database)",
			composeDetail.Reserved, cpuLimit)
	}

	// Step 5: another application would reserve 250 but still no
	// headroom — rejection must carry Requested=250 (app magnitude),
	// distinct from the compose rejection above.
	appErr := create(t, store.ServiceKindApplication, "app-overflow", "app_overflow")
	if appErr == nil {
		t.Fatalf("application overflow: expected cpu_millicores rejection, got success")
	}
	if ye := yerr.From(appErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("application overflow code = %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	}
	appDetail, ok := quota.DetailOf(appErr)
	if !ok {
		t.Fatalf("application overflow: no ExceededDetail (err=%v)", appErr)
	}
	if appDetail.Requested != appCPUMillicores {
		t.Errorf("application overflow detail.Requested = %d, want %d",
			appDetail.Requested, appCPUMillicores)
	}
	// The two rejections must report DIFFERENT Requested values — the
	// strongest assertion that the per-Kind magnitude actually varies.
	if composeDetail.Requested == appDetail.Requested {
		t.Errorf("compose and application overflow Requested are equal (%d) — per-Kind magnitudes did not vary",
			composeDetail.Requested)
	}

	// Final state: the cpu_millicores active reservations sum equals
	// exactly cpuLimit — two applications at 250 each + one database at
	// 500 = 1000. The COUNT(*) is three reservation rows.
	var cpuRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceCPUMillicores)).Scan(&cpuRows); err != nil {
		t.Fatalf("count cpu_millicores reservations: %v", err)
	}
	if cpuRows != 3 {
		t.Errorf("cpu_millicores reservation rows = %d, want 3 (one per successful Create)", cpuRows)
	}
	var cpuSum int64
	if err := db.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount), 0) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceCPUMillicores)).Scan(&cpuSum); err != nil {
		t.Fatalf("sum cpu_millicores reservation amounts: %v", err)
	}
	if cpuSum != cpuLimit {
		t.Errorf("SUM(amount) on cpu_millicores reservations = %d, want %d (per-Kind magnitudes not persisted)",
			cpuSum, cpuLimit)
	}

	// The two committed application reservations must each carry
	// amount=appCPUMillicores, and the database reservation must carry
	// amount=dbCPUMillicores. A SQL group-by surfaces the distribution
	// without leaning on test-only ordering.
	rows, err := db.Query(ctx,
		`SELECT amount, COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'
		 GROUP BY amount ORDER BY amount`,
		orgID, string(store.QuotaResourceCPUMillicores))
	if err != nil {
		t.Fatalf("group cpu_millicores reservations by amount: %v", err)
	}
	defer rows.Close()
	type amountRow struct {
		amount int64
		count  int64
	}
	var distribution []amountRow
	for rows.Next() {
		var ar amountRow
		if err := rows.Scan(&ar.amount, &ar.count); err != nil {
			t.Fatalf("scan amount row: %v", err)
		}
		distribution = append(distribution, ar)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate amount rows: %v", err)
	}
	wantDistribution := []amountRow{
		{amount: appCPUMillicores, count: 2},
		{amount: dbCPUMillicores, count: 1},
	}
	if len(distribution) != len(wantDistribution) {
		t.Fatalf("cpu_millicores amount distribution = %+v, want %+v",
			distribution, wantDistribution)
	}
	for i := range wantDistribution {
		if distribution[i] != wantDistribution[i] {
			t.Errorf("cpu_millicores amount[%d] = %+v, want %+v",
				i, distribution[i], wantDistribution[i])
		}
	}
}
