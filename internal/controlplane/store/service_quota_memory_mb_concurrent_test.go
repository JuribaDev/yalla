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

// TestServiceServiceCreateRejectsParallelOversubscriptionForMemoryMBQuota
// is the integration test for BE-0332 (quota dimension: memory_mb) —
// the "concurrent integration tests prove parallel requests cannot
// oversubscribe the quota" acceptance criterion. Like cpu_millicores
// (BE-0331), memory_mb is a magnitude-axis dimension: every service
// create consumes a per-Kind baseline of memory megabytes against the
// tenant's memory_mb ceiling, and the rejection's
// ExceededDetail.Requested is the per-Kind magnitude — not a constant
// 1. The test wires a real *store.ServiceService against a real
// *quota.Checker, a real *store.QuotaRepository, and a real
// *store.AuditRepository — the only fakes are the Authorizer and
// JobEnqueuer dependencies (covered by their own dedicated stories),
// which are recording fakes that always succeed.
//
// Twenty goroutines race to create a fresh application-kind service
// inside the same environment against a hard-enforced memory_mb
// limit of 2048 — exactly four times the per-application baseline of
// 512 megabytes. Every other dimension (services, applications, and
// cpu_millicores) is seeded LOOSE so it cannot be the boundary that
// bites. The test asserts that exactly four Create calls return
// successfully and that the remaining sixteen are rejected with the
// typed CodeQuotaExceeded code, that each rejection carries a
// recoverable quota.ExceededDetail whose Resource is "memory_mb"
// (proving the rejection came from the new dimensional dimension and
// not from any of the count dimensions or cpu_millicores), whose
// Requested is the per-Kind amount 512 (proving the magnitude-axis
// plumbing reached the Checker and the wire), whose Limit is 2048,
// whose Reserved is the cumulative-after-winners 2048, and whose
// Current is 0 (no usage was committed during the race). The test
// then asserts that exactly four service rows are visible in the
// database, that exactly four active reservations exist on the
// memory_mb dimension (one per winner, each carrying Amount=512),
// and that the sum of active memory_mb reservations equals
// successes * per-Kind-amount = 2048. Together these assertions
// prove the quota_usage row lock (SELECT FOR UPDATE inside
// ReserveAmount) serialises concurrent transactions against the
// memory_mb counter row so the dimensional limit can never be
// over-allocated.
//
// This test is the BE-0332 dimensional clone of the BE-0331
// cpu_millicores reference. Memory and CPU share the magnitude-axis
// shape; the only structural difference is that memory_mb runs LAST
// in the reservation order inside ServiceService.Create, so when
// cpu_millicores and memory_mb would both exhaust on the same
// Create, memory_mb is the one whose ExceededDetail.Resource
// surfaces. This test pins that boundary by seeding cpu_millicores
// LOOSE — a regression that reorders the reservations would surface
// here as detail.Resource = "cpu_millicores" instead of "memory_mb".
func TestServiceServiceCreateRejectsParallelOversubscriptionForMemoryMBQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan = "starter"
		// Per-application memory baseline. Mirrors
		// serviceMemoryMBByKind[ServiceKindApplication] in
		// serviceservice.go; the value is stable contract and a
		// future change must update both sides together.
		appMemoryMB = int64(512)
		// Memory ceiling is exactly four application-sized
		// allocations. The successes count is therefore
		// memoryLimit/appMemoryMB = 4, which is materially smaller
		// than attempts so the rejections can only come from the
		// memory_mb dimension row lock.
		memoryLimit       = int64(2048)
		expectedSuccesses = memoryLimit / appMemoryMB
		// Loose bounds for every other dimension every application
		// create also touches: services, applications, and
		// cpu_millicores. They are large enough that none of those
		// row locks can be the limit that bites, so every
		// rejection's detail.Resource can only be "memory_mb". The
		// cpu_millicores loose bound is critical because the
		// cpu_millicores reservation runs BEFORE memory_mb in
		// ServiceService.Create — if cpu were tight, it would
		// surface as the rejection instead, and this test would not
		// prove the memory_mb path.
		cpuLimit          = int64(50000)
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
	// create: memory_mb (the tight bound the test exercises) plus
	// cpu_millicores, services, and applications (loose bounds — every
	// application create also reserves against each). LockUsage acquires
	// the row without inserting mid-race so the concurrent
	// serialisation is purely about the SELECT FOR UPDATE step on rows
	// that already exist.
	for _, seed := range []struct {
		id  string
		res store.QuotaResource
	}{
		{"qu_mem_concurrent_mem", store.QuotaResourceMemoryMB},
		{"qu_mem_concurrent_cpu", store.QuotaResourceCPUMillicores},
		{"qu_mem_concurrent_svc", store.QuotaResourceServices},
		{"qu_mem_concurrent_app", store.QuotaResourceApplications},
	} {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_usage (id, organization_id, resource, used_value)
			 VALUES ($1, $2, $3, 0)`,
			seed.id, orgID, string(seed.res)); err != nil {
			t.Fatalf("seed %s quota_usage: %v", seed.res, err)
		}
	}

	// Plan-default policies for every touched dimension. Memory is the
	// TIGHT bound at exactly four application-sized allocations — this
	// is the dimension the test proves serialises under concurrent
	// load. cpu_millicores, services, and applications are LOOSE —
	// large enough that none can be the limit that bites, so a
	// rejection's detail.Resource can only be "memory_mb". No
	// organization override is seeded, so the Checker's plan-default
	// fallback path is the one exercised.
	for _, seed := range []struct {
		id    string
		res   store.QuotaResource
		limit int64
	}{
		{"qp_mem_concurrent_mem", store.QuotaResourceMemoryMB, memoryLimit},
		{"qp_mem_concurrent_cpu", store.QuotaResourceCPUMillicores, cpuLimit},
		{"qp_mem_concurrent_svc", store.QuotaResourceServices, servicesLimit},
		{"qp_mem_concurrent_app", store.QuotaResourceApplications, applicationsLimit},
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
				Slug:           fmt.Sprintf("mem-%02d", i),
				DisplayName:    fmt.Sprintf("MEM %02d", i),
				// Kind is pinned to the application taxonomy member so
				// every goroutine consumes the same per-Kind magnitude
				// (appMemoryMB). A mixed-Kind race would make the
				// successes-count derivation memory_limit/per_kind_amount
				// non-trivial; pinning the kind keeps the boundary the
				// test exercises clean.
				Kind:          store.ServiceKindApplication,
				ActorID:       "usr_mem_concurrent",
				ActorKind:     "usr",
				ActorOrgID:    orgID,
				RequestID:     fmt.Sprintf("req_mem_%02d", i),
				CorrelationID: fmt.Sprintf("corr_mem_%02d", i),
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
		// The rejection MUST name the memory_mb dimension. If it ever
		// names "services", "applications", or "cpu_millicores"
		// instead, then either (a) Service.Create is no longer
		// calling ReserveAmount for the memory_mb dimension, (b) one
		// of the other upper bounds is too tight to keep the memory
		// boundary the one that bites, or (c) the reservation order
		// was changed so memory_mb no longer runs last. Each is a
		// defect this test surfaces.
		if detail.Resource != string(store.QuotaResourceMemoryMB) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceMemoryMB)
		}
		if detail.Limit != memoryLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, memoryLimit)
		}
		// Requested is the per-Kind magnitude — NOT 1. A regression
		// that hard-coded the dimensional path back to amount=1 would
		// surface here as detail.Requested=1.
		if detail.Requested != appMemoryMB {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want %d (per-Kind magnitude)",
				r.index, detail.Requested, appMemoryMB)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal
		// successes * per-Kind magnitude = memoryLimit (since
		// expectedSuccesses == memoryLimit/appMemoryMB). Anything
		// less would mean the lock did not serialise concurrent
		// reservers, or the per-Kind magnitude did not reach the
		// reservation row.
		if detail.Reserved != expectedSuccesses*appMemoryMB {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, expectedSuccesses*appMemoryMB)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, slug, display name, correlation id, or service id — so
		// a future logging path cannot turn it into a content
		// channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("mem-%02d", r.index),
			fmt.Sprintf("MEM %02d", r.index),
			fmt.Sprintf("req_mem_%02d", r.index),
			fmt.Sprintf("corr_mem_%02d", r.index),
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

	// The desired-state row count must match the success count
	// exactly — proves no rejected transaction left behind a
	// half-written service, and no committed transaction failed to
	// persist its service row.
	var serviceRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM services WHERE organization_id = $1 AND environment_id = $2`,
		orgID, environmentID).Scan(&serviceRows); err != nil {
		t.Fatalf("count services: %v", err)
	}
	if serviceRows != expectedSuccesses {
		t.Errorf("services rows for (org, env) = %d, want %d", serviceRows, expectedSuccesses)
	}

	// Each winning Create commits exactly ONE memory_mb reservation
	// row whose Amount carries the per-Kind magnitude. Counting rows
	// proves the row count; summing Amount proves the magnitude
	// reached the table — the dimensional contract this story
	// introduces.
	var activeMemoryReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMemoryMB)).Scan(&activeMemoryReservations); err != nil {
		t.Fatalf("count active memory_mb reservations: %v", err)
	}
	if activeMemoryReservations != expectedSuccesses {
		t.Errorf("active memory_mb reservations = %d, want %d",
			activeMemoryReservations, expectedSuccesses)
	}
	var summedMemoryAmount int64
	if err := db.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount), 0) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMemoryMB)).Scan(&summedMemoryAmount); err != nil {
		t.Fatalf("sum active memory_mb reservation amounts: %v", err)
	}
	if summedMemoryAmount != expectedSuccesses*appMemoryMB {
		t.Errorf("SUM(amount) on active memory_mb reservations = %d, want %d (per-Kind magnitude not persisted)",
			summedMemoryAmount, expectedSuccesses*appMemoryMB)
	}

	// SumActiveReservations is the surface the Checker consults to
	// decide future requests. It must agree with the raw SUM above —
	// the wire that gates the next allocation cannot disagree with
	// the table itself.
	var summedMemory int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceMemoryMB, time.Now().UTC())
		if err != nil {
			return err
		}
		summedMemory = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedMemory != expectedSuccesses*appMemoryMB {
		t.Errorf("SumActiveReservations(memory_mb) = %d, want %d",
			summedMemory, expectedSuccesses*appMemoryMB)
	}

	// Both fakes were called exactly once per Create attempt — except
	// for the JobEnqueuer, which is never reached by a rejected
	// transaction because quota fails first. Authorization runs
	// before quota, so the rejected attempts increment authz but not
	// jobs.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
	if got := jobs.calls.Load(); got != expectedSuccesses {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			got, expectedSuccesses)
	}
}

// TestServiceServiceCreateMemoryMBAmountVariesByKind pins the
// dimensional contract this story introduces: the memory_mb
// reservation amount reflects the SERVICE KIND, not a constant
// per-resource value. A regression that hard-coded the dimensional
// path back to amount=1 — or that swapped the per-Kind map for a flat
// baseline — would let the wrong amount reach the reservation row,
// and the next caller's Reserved sum would lie about real memory
// pressure. This test proves end-to-end that:
//
//   - an application-kind service reserves 512 memory_mb;
//   - a compose-kind service reserves 1024 memory_mb;
//   - a database-kind service reserves 1024 memory_mb;
//   - the rejection's ExceededDetail.Requested matches the per-Kind
//     magnitude of the request that overflowed, not a constant.
//
// The memory_mb ceiling is set to 2048 — exactly large enough to fit
// one application (512) + one database (1024) + one more application
// (512) = 2048 megabytes, leaving no headroom. A subsequent
// compose-kind request (would-reserve 1024) is rejected with
// Requested=1024; a subsequent application-kind request
// (would-reserve 512) is rejected with Requested=512. The other
// dimensions (services, applications, compose_stacks, databases,
// cpu_millicores) are seeded LOOSE so they cannot be the limit that
// bites — every rejection must name memory_mb.
func TestServiceServiceCreateMemoryMBAmountVariesByKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan            = "starter"
		appMemoryMB     = int64(512)
		composeMemoryMB = int64(1024)
		dbMemoryMB      = int64(1024)
		// 512 + 1024 + 512 = 2048 — exactly full.
		memoryLimit     = int64(2048)
		looseCountLimit = int64(50)
		// cpu_millicores must be loose enough to never be the
		// boundary that bites across this whole scenario. Worst case
		// is 5 attempts touching the database value of 500 each =
		// 2500 millicores — well below 50000.
		looseCPULimit = int64(50000)
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
		{"qu_memkind_mem", store.QuotaResourceMemoryMB},
		{"qu_memkind_cpu", store.QuotaResourceCPUMillicores},
		{"qu_memkind_svc", store.QuotaResourceServices},
		{"qu_memkind_app", store.QuotaResourceApplications},
		{"qu_memkind_cmp", store.QuotaResourceComposeStacks},
		{"qu_memkind_db", store.QuotaResourceDatabases},
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
		{"qp_memkind_mem", store.QuotaResourceMemoryMB, memoryLimit},
		{"qp_memkind_cpu", store.QuotaResourceCPUMillicores, looseCPULimit},
		{"qp_memkind_svc", store.QuotaResourceServices, looseCountLimit},
		{"qp_memkind_app", store.QuotaResourceApplications, looseCountLimit},
		{"qp_memkind_cmp", store.QuotaResourceComposeStacks, looseCountLimit},
		{"qp_memkind_db", store.QuotaResourceDatabases, looseCountLimit},
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
			ActorID:        "usr_memkind",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      "req_memkind_" + requestSuffix,
			CorrelationID:  "corr_memkind_" + requestSuffix,
		}
		_, createErr := svc.Create(ctx, in)
		return createErr
	}

	// Step 1: an application reserves 512. Running total: 512/2048.
	if err := create(t, store.ServiceKindApplication, "app-1", "app1"); err != nil {
		t.Fatalf("application create 1: %v", err)
	}
	// Step 2: a database reserves 1024. Running total: 1536/2048.
	if err := create(t, store.ServiceKindDatabase, "db-1", "db1"); err != nil {
		t.Fatalf("database create 1: %v", err)
	}
	// Step 3: another application reserves 512. Running total: 2048/2048.
	if err := create(t, store.ServiceKindApplication, "app-2", "app2"); err != nil {
		t.Fatalf("application create 2: %v", err)
	}

	// Step 4: a compose service would reserve 1024 but only 0
	// headroom remains — rejection must carry Requested=1024 (compose
	// magnitude), proving the per-Kind amount reached the Checker.
	composeErr := create(t, store.ServiceKindCompose, "cmp-overflow", "cmp_overflow")
	if composeErr == nil {
		t.Fatalf("compose overflow: expected memory_mb rejection, got success")
	}
	if ye := yerr.From(composeErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("compose overflow code = %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	}
	composeDetail, ok := quota.DetailOf(composeErr)
	if !ok {
		t.Fatalf("compose overflow: no ExceededDetail (err=%v)", composeErr)
	}
	if composeDetail.Resource != string(store.QuotaResourceMemoryMB) {
		t.Errorf("compose overflow detail.Resource = %q, want %q",
			composeDetail.Resource, store.QuotaResourceMemoryMB)
	}
	if composeDetail.Requested != composeMemoryMB {
		t.Errorf("compose overflow detail.Requested = %d, want %d (per-Kind magnitude not reaching Checker)",
			composeDetail.Requested, composeMemoryMB)
	}
	if composeDetail.Limit != memoryLimit {
		t.Errorf("compose overflow detail.Limit = %d, want %d",
			composeDetail.Limit, memoryLimit)
	}
	if composeDetail.Reserved != memoryLimit {
		t.Errorf("compose overflow detail.Reserved = %d, want %d (sum of two apps + one database)",
			composeDetail.Reserved, memoryLimit)
	}

	// Step 5: another application would reserve 512 but still no
	// headroom — rejection must carry Requested=512 (app magnitude),
	// distinct from the compose rejection above.
	appErr := create(t, store.ServiceKindApplication, "app-overflow", "app_overflow")
	if appErr == nil {
		t.Fatalf("application overflow: expected memory_mb rejection, got success")
	}
	if ye := yerr.From(appErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("application overflow code = %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	}
	appDetail, ok := quota.DetailOf(appErr)
	if !ok {
		t.Fatalf("application overflow: no ExceededDetail (err=%v)", appErr)
	}
	if appDetail.Requested != appMemoryMB {
		t.Errorf("application overflow detail.Requested = %d, want %d",
			appDetail.Requested, appMemoryMB)
	}
	// The two rejections must report DIFFERENT Requested values — the
	// strongest assertion that the per-Kind magnitude actually varies.
	if composeDetail.Requested == appDetail.Requested {
		t.Errorf("compose and application overflow Requested are equal (%d) — per-Kind magnitudes did not vary",
			composeDetail.Requested)
	}

	// Final state: the memory_mb active reservations sum equals
	// exactly memoryLimit — two applications at 512 each + one
	// database at 1024 = 2048. The COUNT(*) is three reservation
	// rows.
	var memoryRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMemoryMB)).Scan(&memoryRows); err != nil {
		t.Fatalf("count memory_mb reservations: %v", err)
	}
	if memoryRows != 3 {
		t.Errorf("memory_mb reservation rows = %d, want 3 (one per successful Create)", memoryRows)
	}
	var memorySum int64
	if err := db.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount), 0) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMemoryMB)).Scan(&memorySum); err != nil {
		t.Fatalf("sum memory_mb reservation amounts: %v", err)
	}
	if memorySum != memoryLimit {
		t.Errorf("SUM(amount) on memory_mb reservations = %d, want %d (per-Kind magnitudes not persisted)",
			memorySum, memoryLimit)
	}

	// The two committed application reservations must each carry
	// amount=appMemoryMB, and the database reservation must carry
	// amount=dbMemoryMB. A SQL group-by surfaces the distribution
	// without leaning on test-only ordering.
	rows, err := db.Query(ctx,
		`SELECT amount, COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'
		 GROUP BY amount ORDER BY amount`,
		orgID, string(store.QuotaResourceMemoryMB))
	if err != nil {
		t.Fatalf("group memory_mb reservations by amount: %v", err)
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
		{amount: appMemoryMB, count: 2},
		{amount: dbMemoryMB, count: 1},
	}
	if len(distribution) != len(wantDistribution) {
		t.Fatalf("memory_mb amount distribution = %+v, want %+v",
			distribution, wantDistribution)
	}
	for i := range wantDistribution {
		if distribution[i] != wantDistribution[i] {
			t.Errorf("memory_mb amount[%d] = %+v, want %+v",
				i, distribution[i], wantDistribution[i])
		}
	}
}
