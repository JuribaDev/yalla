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

// TestServiceServiceCreateRejectsParallelOversubscriptionForServicesQuota is
// the integration test for BE-0325 (quota dimension: services) — the
// "concurrent integration tests prove parallel requests cannot oversubscribe
// the quota" acceptance criterion. The end-to-end path under test wires a
// real *store.ServiceService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository — the only fakes
// are the Authorizer and JobEnqueuer dependencies (covered by their own
// dedicated stories), which are recording fakes that always succeed. Twenty
// goroutines race to create a fresh service inside the same environment
// against a hard-enforced "services" limit of five; the test asserts that
// exactly five Create calls return successfully and that the remaining
// fifteen are rejected with the typed CodeQuotaExceeded code, that the
// rejection error carries a recoverable quota.ExceededDetail with the
// expected counts, that exactly five service rows are visible in the
// database, and that exactly five active quota reservations exist for the
// "services" dimension. Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises concurrent
// transactions so the limit can never be over-allocated.
//
// This test is the BE-0325 clone of the structural template documented in
// ralph/progress.txt (BE-0323 reference for projects, BE-0324 reference for
// environments). The same authorize -> reserve quota -> write desired state
// -> enqueue job unit of work runs inside ServiceService.Create, so the same
// concurrency invariants apply. The differences from the BE-0324 reference
// are: (1) an environment parent is seeded in addition to the organization
// and project, because services are child rows of environments; (2)
// QuotaResourceServices replaces QuotaResourceEnvironments in the seeded
// counter row, the seeded plan policy, the rejection detail.Resource
// assertion, the active-reservations count, and the SumActiveReservations
// call; (3) the asserted desired-state row count is taken from the services
// table, scoped by (organization_id, environment_id) — the tightest tenant
// scope the service row carries; (4) the leaky-input candidates added to
// the diagnostic-string check use the service's slug, display name,
// request_id, correlation_id, and id patterns so a rejection that leaked
// any of them would still be caught; (5) the CreateServiceInput carries a
// Kind field — services have a closed Dokploy taxonomy
// (application / database / compose) — pinned to ServiceKindApplication so
// the validator never fails on kind and the test stays focused on the quota
// boundary.
func TestServiceServiceCreateRejectsParallelOversubscriptionForServicesQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan           = "starter"
		limit    int64 = 5
		attempts       = 20
	)

	// Seed the parent organization, project, and environment with
	// canonical domain IDs. The testutil.Factory's id prefixes are not
	// the canonical Kind strings (the factory writes "prj_..." while
	// domain.KindProject is "proj", and "svc_..." vs "svc" /
	// "env_..." vs "env"), so CreateServiceInput.EnvironmentID would
	// not pass domain.ParseID inside validateCreateServiceInput if it
	// came from f.Environment(...). Raw SQL with domain.MustNewID(...)
	// mirrors the BE-0323 / BE-0324 seed pattern and keeps the
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

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage can
	// acquire it without inserting a new row mid-race. LockUsage inserts
	// on first read; pre-seeding makes the concurrent serialisation
	// purely about the SELECT FOR UPDATE step on a row that already
	// exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_svc_concurrent", orgID, string(store.QuotaResourceServices)); err != nil {
		t.Fatalf("seed quota_usage: %v", err)
	}

	// Plan-default policy: hard-enforced "services" limit at five. No
	// organization override is seeded, so the Checker's plan-default
	// fallback path is the one exercised. The org-override path has its
	// own dedicated repository test
	// (TestQuotaRepositoryEffectiveLimitPrefersOrgOverride).
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_svc_concurrent", plan, string(store.QuotaResourceServices), limit); err != nil {
		t.Fatalf("seed plan policy: %v", err)
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
				Slug:           fmt.Sprintf("svc-%02d", i),
				DisplayName:    fmt.Sprintf("Service %02d", i),
				// Kind is pinned to the application taxonomy member so
				// the validator never fails on kind — services have a
				// closed Dokploy taxonomy (application/database/compose)
				// and only application keeps this test focused on the
				// quota boundary instead of, e.g., compose-only fields.
				Kind:          store.ServiceKindApplication,
				ActorID:       "usr_concurrent",
				ActorKind:     "usr",
				ActorOrgID:    orgID,
				RequestID:     fmt.Sprintf("req_svc_%02d", i),
				CorrelationID: fmt.Sprintf("corr_svc_%02d", i),
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
		if detail.Resource != string(store.QuotaResourceServices) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceServices)
		}
		if detail.Limit != limit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, limit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal the
		// limit — anything less would mean the lock did not serialise
		// transactions against the counter row.
		if detail.Reserved != limit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, limit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the resource
		// name and the counts — never the caller's request id, slug,
		// display name, correlation id, or service id — so a future
		// logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("svc-%02d", r.index),
			fmt.Sprintf("Service %02d", r.index),
			fmt.Sprintf("req_svc_%02d", r.index),
			fmt.Sprintf("corr_svc_%02d", r.index),
			r.serviceID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(limit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, limit)
	}
	if rejections != attempts-int(limit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(limit))
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
	// The scope is (organization_id, environment_id) — the tightest
	// tenant scope a service row carries, and the only one the create
	// unit of work writes against.
	var serviceRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM services WHERE organization_id = $1 AND environment_id = $2`,
		orgID, environmentID).Scan(&serviceRows); err != nil {
		t.Fatalf("count services: %v", err)
	}
	if serviceRows != limit {
		t.Errorf("services rows for (org, env) = %d, want %d", serviceRows, limit)
	}

	// Each winning Create commits one active reservation; rejected
	// Creates rolled their reservation back with the rest of the unit of
	// work. So the active reservation count for the services dimension
	// must equal the number of successes.
	var activeReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&activeReservations); err != nil {
		t.Fatalf("count active reservations: %v", err)
	}
	if activeReservations != limit {
		t.Errorf("active services reservations = %d, want %d", activeReservations, limit)
	}

	// The repository's SumActiveReservations agrees with the raw count —
	// the surface the Checker consults to decide future requests cannot
	// disagree with the table itself.
	var summed int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceServices, time.Now().UTC())
		if err != nil {
			return err
		}
		summed = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summed != limit {
		t.Errorf("SumActiveReservations = %d, want %d", summed, limit)
	}

	// Both fakes were called exactly once per Create attempt — except for
	// the JobEnqueuer, which is never reached by a rejected transaction
	// because quota fails first. Authorization runs before quota, so the
	// rejected attempts increment authz but not jobs.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
	if got := jobs.calls.Load(); got != limit {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			got, limit)
	}
}
