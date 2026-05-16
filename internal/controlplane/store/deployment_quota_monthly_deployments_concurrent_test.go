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

// TestDeploymentServiceCreateRejectsParallelOversubscriptionForMonthlyDeploymentsQuota
// is the integration test for BE-0335 (quota dimension:
// monthly_deployments) — the "concurrent integration tests prove
// parallel requests cannot oversubscribe the quota" acceptance
// criterion. The test wires a real *store.DeploymentService against
// a real *quota.Checker, a real *store.QuotaRepository, and a real
// *store.AuditRepository — the only fakes are the Authorizer and
// JobEnqueuer dependencies (covered by their own dedicated
// stories), which are recording fakes that always succeed. Twenty
// goroutines race to create a fresh deployment row against a
// hard-enforced "monthly_deployments" limit of five; the test
// asserts that exactly five Create calls return successfully and
// that the remaining fifteen are rejected with the typed
// CodeQuotaExceeded code, that the rejection error carries a
// recoverable quota.ExceededDetail whose Resource is
// "monthly_deployments" (proving the rejection came from the new
// dimension and not from concurrent_deployments, which is reserved
// FIRST in the same unit of work but has no policy seeded so the
// Checker allows it), that exactly five deployment rows are
// visible in the database, and that exactly five active
// quota_reservations rows exist for the "monthly_deployments"
// dimension. Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises
// concurrent transactions against the monthly_deployments counter
// row so the limit can never be over-allocated.
//
// The test is the BE-0335 clone of the BE-0334 backup_schedules
// reference (documented in ralph/progress.txt). The differences
// are: (1) the boundary under test is DeploymentService.Create
// rather than ServiceBackupService.Create; (2) every deployment is
// given a unique idempotency key so no two goroutines short-circuit
// on the same persisted row; (3) the manual deployment source is
// used because its ref validator accepts an empty string and a
// short label — keeping the per-attempt payload minimal and not
// dependent on a git branch / image ref taxonomy that is unrelated
// to the quota boundary under test; (4) the JobEnqueuer port is
// exercised through atomicJobs so a regression that re-ordered the
// reservation past the enqueue would surface in the call count.
func TestDeploymentServiceCreateRejectsParallelOversubscriptionForMonthlyDeploymentsQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan                    = "starter"
		monthlyDeploymentsLimit = int64(5)
		attempts                = 20
	)

	// Seed the parent organization, project, environment, and service
	// with canonical domain IDs. Raw SQL with domain.MustNewID(...)
	// mirrors the BE-0323..BE-0334 seed pattern and keeps the
	// unit-of-work boundary under test — not the test fixture — the
	// only thing the validator can reject.
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
	serviceID := domain.MustNewID(domain.KindService).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		serviceID, orgID, projectID, environmentID,
		"svc-"+serviceID[len(serviceID)-12:], "Test Service",
		string(store.ServiceKindApplication)); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage
	// can acquire it without inserting a new row mid-race. The row
	// already exists so the concurrent serialisation is purely about
	// the SELECT FOR UPDATE step on a row that already exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_mdep_concurrent", orgID, string(store.QuotaResourceMonthlyDeployments)); err != nil {
		t.Fatalf("seed monthly_deployments quota_usage: %v", err)
	}

	// Plan-default policy for the monthly_deployments dimension at
	// the TIGHT bound of five — this is the dimension the test
	// proves serialises under concurrent load. No organization
	// override is seeded, so the Checker's plan-default fallback
	// path is the one exercised. The concurrent_deployments
	// dimension is INTENTIONALLY left unpoliced so the Checker's
	// "no policy => allow without recording a reservation" branch
	// fires for it — that way every rejection observed below MUST
	// have come from monthly_deployments, never concurrent_
	// deployments, even though concurrent_deployments is reserved
	// first in the unit of work.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_mdep_concurrent", plan, string(store.QuotaResourceMonthlyDeployments), monthlyDeploymentsLimit); err != nil {
		t.Fatalf("seed monthly_deployments plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewDeploymentService(
		s,
		store.NewServiceRepository(),
		store.NewDeploymentRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewDeploymentService: %v", err)
	}

	type outcome struct {
		index          int
		idempotencyKey string
		err            error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateDeploymentInput{
				OrganizationID: orgID,
				ServiceID:      serviceID,
				Source:         store.DeploymentSourceManual,
				SourceRef:      fmt.Sprintf("manual-%02d", i),
				IdempotencyKey: fmt.Sprintf("idem-mdep-%02d", i),
				ActorID:        "usr_mdep_concurrent",
				ActorKind:      "usr",
				ActorOrgID:     orgID,
				RequestID:      fmt.Sprintf("req_mdep_%02d", i),
				CorrelationID:  fmt.Sprintf("corr_mdep_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{
				index:          i,
				idempotencyKey: in.IdempotencyKey,
				err:            createErr,
			}
		}(i)
	}
	wg.Wait()

	var successes, rejections int
	for _, r := range results {
		if r.err == nil {
			successes++
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
		// The rejection MUST name the monthly_deployments dimension.
		// If it ever names a different resource (e.g. concurrent_
		// deployments because the seed accidentally configured a
		// policy for it), the create unit of work has drifted off
		// the dimension the story enforces and this test must
		// surface it.
		if detail.Resource != string(store.QuotaResourceMonthlyDeployments) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceMonthlyDeployments)
		}
		if detail.Limit != monthlyDeploymentsLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, monthlyDeploymentsLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal
		// the limit — anything less would mean the lock did not
		// serialise transactions against the counter row.
		if detail.Reserved != monthlyDeploymentsLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, monthlyDeploymentsLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, idempotency key, correlation id, or source ref — so a
		// future logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("manual-%02d", r.index),
			fmt.Sprintf("idem-mdep-%02d", r.index),
			fmt.Sprintf("req_mdep_%02d", r.index),
			fmt.Sprintf("corr_mdep_%02d", r.index),
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(monthlyDeploymentsLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, monthlyDeploymentsLimit)
	}
	if rejections != attempts-int(monthlyDeploymentsLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(monthlyDeploymentsLimit))
	}

	// The desired-state row count must match the success count
	// exactly — proves no rejected transaction left behind a
	// half-written deployment row, and no committed transaction
	// failed to persist its row. The scope is (organization_id,
	// service_id) — the tightest tenant scope a deployments row
	// carries that the create unit of work writes against.
	var deploymentRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM deployments WHERE organization_id = $1 AND service_id = $2`,
		orgID, serviceID).Scan(&deploymentRows); err != nil {
		t.Fatalf("count deployments: %v", err)
	}
	if deploymentRows != monthlyDeploymentsLimit {
		t.Errorf("deployment rows for (org, service) = %d, want %d", deploymentRows, monthlyDeploymentsLimit)
	}

	// Each winning Create commits one active reservation on the
	// "monthly_deployments" dimension. Rejected Creates rolled their
	// reservation back with the rest of the unit of work. So the
	// active reservation count for the dimension must equal the
	// number of successes.
	var activeMonthlyReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMonthlyDeployments)).Scan(&activeMonthlyReservations); err != nil {
		t.Fatalf("count active monthly_deployments reservations: %v", err)
	}
	if activeMonthlyReservations != monthlyDeploymentsLimit {
		t.Errorf("active monthly_deployments reservations = %d, want %d",
			activeMonthlyReservations, monthlyDeploymentsLimit)
	}

	// The concurrent_deployments dimension was reserved FIRST in the
	// unit of work but has no policy configured, so the Checker's
	// "no policy => allow without recording" branch fires for it and
	// no reservation row is ever inserted. A regression that
	// accidentally inserted a reservation despite the absence of a
	// policy would surface here.
	var activeConcurrentReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceConcurrentDeployments)).Scan(&activeConcurrentReservations); err != nil {
		t.Fatalf("count active concurrent_deployments reservations: %v", err)
	}
	if activeConcurrentReservations != 0 {
		t.Errorf("active concurrent_deployments reservations = %d, want 0 (no policy configured for this dimension)",
			activeConcurrentReservations)
	}

	// The repository's SumActiveReservations agrees with the raw
	// count on the monthly_deployments dimension — the surface the
	// Checker consults to decide future requests cannot disagree
	// with the table itself.
	var summedMonthly int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceMonthlyDeployments, time.Now().UTC())
		if err != nil {
			return err
		}
		summedMonthly = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedMonthly != monthlyDeploymentsLimit {
		t.Errorf("SumActiveReservations(monthly_deployments) = %d, want %d",
			summedMonthly, monthlyDeploymentsLimit)
	}

	// Authorization runs before quota inside the unit of work, so
	// every attempt — successful or rejected — increments the
	// authorizer fake.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}

	// JobEnqueuer runs AFTER the quota reservation and the desired-
	// state insert, so only winning transactions reach it. The job
	// enqueue count must match the success count exactly: a
	// regression that re-ordered the Reserve past the Enqueue would
	// surface here as the job count exceeding the success count.
	if got := jobs.calls.Load(); got != int64(successes) {
		t.Errorf("jobs.calls = %d, want %d", got, successes)
	}
}

// TestDeploymentServiceCreateAppliesMonthlyDeploymentsQuotaIndependentlyOfConcurrentDeployments
// pins that the monthly_deployments dimension is INDEPENDENT of the
// concurrent_deployments dimension: a deployment Create reserves
// BOTH dimensions, but a rejection on monthly_deployments must
// surface on the monthly_deployments dimension specifically — never
// disguised as a concurrent_deployments rejection. The negative
// complement of the concurrent oversub test.
//
// The test exhausts the monthly_deployments dimension by creating
// five deployments against a hard-enforced limit of five, then
// proves a SIXTH Create fails with E_QUOTA_EXCEEDED whose
// ExceededDetail.Resource is "monthly_deployments" — never
// "concurrent_deployments" (no policy configured for that
// dimension) and never another dimension. A future regression that
// either dropped the Reserve(monthly_deployments) call or
// accidentally chose another resource string would surface here.
func TestDeploymentServiceCreateAppliesMonthlyDeploymentsQuotaIndependentlyOfConcurrentDeployments(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan                    = "starter"
		monthlyDeploymentsLimit = int64(5)
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
	serviceID := domain.MustNewID(domain.KindService).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		serviceID, orgID, projectID, environmentID,
		"svc-"+serviceID[len(serviceID)-12:], "Test Service",
		string(store.ServiceKindApplication)); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_mdep_only", plan, string(store.QuotaResourceMonthlyDeployments), monthlyDeploymentsLimit); err != nil {
		t.Fatalf("seed monthly_deployments plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewDeploymentService(
		s,
		store.NewServiceRepository(),
		store.NewDeploymentRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewDeploymentService: %v", err)
	}

	// Exhaust the monthly_deployments dimension by creating exactly
	// limit deployment rows. Each Create succeeds and consumes one
	// monthly_deployments reservation.
	for i := int64(0); i < monthlyDeploymentsLimit; i++ {
		in := store.CreateDeploymentInput{
			OrganizationID: orgID,
			ServiceID:      serviceID,
			Source:         store.DeploymentSourceManual,
			SourceRef:      fmt.Sprintf("fill-%02d", i),
			IdempotencyKey: fmt.Sprintf("idem-mdep-fill-%02d", i),
			ActorID:        "usr_mdep_only",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_mdep_only_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_mdep_only_%02d", i),
		}
		if _, err := svc.Create(ctx, in); err != nil {
			t.Fatalf("seed deployment %d: %v", i, err)
		}
	}

	// One more Create must now fail on the monthly_deployments
	// dimension — guards against a regression where the Reserve
	// call gets silently dropped or its resource string is changed.
	exhausted := store.CreateDeploymentInput{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		Source:         store.DeploymentSourceManual,
		SourceRef:      "extra",
		IdempotencyKey: "idem-mdep-extra",
		ActorID:        "usr_mdep_only",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_mdep_only_extra",
		CorrelationID:  "corr_mdep_only_extra",
	}
	if _, err := svc.Create(ctx, exhausted); err == nil {
		t.Fatalf("expected monthly_deployments-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("deployment overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceMonthlyDeployments) {
		t.Fatalf("deployment overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceMonthlyDeployments)
	}

	// The concurrent_deployments dimension was reserved FIRST in
	// the unit of work but has no policy configured, so no
	// reservation row exists for it. A regression that accidentally
	// inserted a concurrent_deployments reservation despite the
	// absence of a policy would surface here.
	var concurrentReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceConcurrentDeployments)).Scan(&concurrentReservations); err != nil {
		t.Fatalf("count active concurrent_deployments reservations: %v", err)
	}
	if concurrentReservations != 0 {
		t.Errorf("active concurrent_deployments reservations = %d, want 0 (no policy configured for this dimension)",
			concurrentReservations)
	}

	// Symmetrically, the services dimension was never touched by a
	// deployment Create, so no services reservation row exists for
	// this tenant either. Pins that the deployment unit of work
	// does not accidentally consume an unrelated dimension's quota.
	var servicesReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&servicesReservations); err != nil {
		t.Fatalf("count active services reservations: %v", err)
	}
	if servicesReservations != 0 {
		t.Errorf("active services reservations = %d, want 0 (deployment Create must not reserve on the services dimension)",
			servicesReservations)
	}
}
