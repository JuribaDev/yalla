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

// TestServiceServiceCreateRejectsParallelOversubscriptionForComposeStacksQuota
// is the integration test for BE-0327 (quota dimension: compose_stacks) — the
// "concurrent integration tests prove parallel requests cannot oversubscribe
// the quota" acceptance criterion. Unlike the services dimension, the
// compose_stacks dimension is per-subtype: it counts ONLY service rows whose
// Kind is ServiceKindCompose, so an application or database service in the
// same environment does not consume a compose_stacks reservation. The test
// wires a real *store.ServiceService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository — the only
// fakes are the Authorizer and JobEnqueuer dependencies (covered by their
// own dedicated stories), which are recording fakes that always succeed.
// Twenty goroutines race to create a fresh compose-kind service inside
// the same environment against a hard-enforced "compose_stacks" limit of
// five (the services-dimension limit is seeded HIGHER than the attempt
// count so it cannot be the boundary that bites); the test asserts that
// exactly five Create calls return successfully and that the remaining
// fifteen are rejected with the typed CodeQuotaExceeded code, that the
// rejection error carries a recoverable quota.ExceededDetail whose
// Resource is "compose_stacks" (proving the rejection came from the new
// per-subtype dimension and not from the services dimension), that
// exactly five service rows are visible in the database, and that exactly
// five active quota reservations exist for the "compose_stacks" dimension
// (with another five for "services", since every compose Create
// reserves both). Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises concurrent
// transactions against the new compose_stacks counter row so the
// per-subtype limit can never be over-allocated.
//
// This test is the BE-0327 clone of the BE-0326 applications-dimension
// reference (documented in ralph/progress.txt). The differences are:
// (1) two quota_usage counter rows and two quota_policies rows are seeded
// — one for each dimension — because Service.Create now calls
// quota.Reserve twice for a compose-kind service; (2) the
// compose_stacks policy is the TIGHT bound (limit=5, hard-enforced) while
// the services policy is the LOOSE bound (limit=attempts*2, hard-enforced)
// so a rejection can only be attributed to the new compose_stacks-dimension
// row lock; (3) detail.Resource is asserted to equal
// QuotaResourceComposeStacks so the test fails closed if Service.Create
// ever stopped calling Reserve(compose_stacks) and the rejections drifted
// back onto the services dimension; (4) both reservation tables are
// counted at the end — compose_stacks must equal the success count, and
// services must also equal the success count since every winning Create
// reserved one of each, while losers rolled both reservations back.
func TestServiceServiceCreateRejectsParallelOversubscriptionForComposeStacksQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan               = "starter"
		composeStacksLimit = int64(5)
		servicesLimit      = int64(40)
		attempts           = 20
	)

	// Seed the parent organization, project, and environment with
	// canonical domain IDs. The testutil.Factory's id prefixes are not
	// the canonical Kind strings, so raw SQL with domain.MustNewID(...)
	// mirrors the BE-0323 / BE-0324 / BE-0325 / BE-0326 seed pattern and
	// keeps the unit-of-work boundary under test — not the test fixture —
	// the only thing the validator can reject.
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

	// Pre-seed both quota_usage counter rows so quota.Checker.LockUsage
	// can acquire them without inserting new rows mid-race. The
	// compose_stacks row is the one the per-subtype reservation locks;
	// the services row is the one the existing services-dimension
	// reservation locks. Both already exist so the concurrent
	// serialisation is purely about the SELECT FOR UPDATE step on rows
	// that already exist.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_cmp_concurrent", orgID, string(store.QuotaResourceComposeStacks)); err != nil {
		t.Fatalf("seed compose_stacks quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_cmp_svc_concurrent", orgID, string(store.QuotaResourceServices)); err != nil {
		t.Fatalf("seed services quota_usage: %v", err)
	}

	// Plan-default policies for both dimensions. ComposeStacks is the
	// TIGHT bound at five — this is the dimension the test proves
	// serialises under concurrent load. Services is the LOOSE bound at
	// attempts*2 — large enough that the services row lock cannot be
	// the limit that bites, so a rejection's detail.Resource can only
	// be "compose_stacks". No organization override is seeded, so the
	// Checker's plan-default fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_cmp_concurrent", plan, string(store.QuotaResourceComposeStacks), composeStacksLimit); err != nil {
		t.Fatalf("seed compose_stacks plan policy: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_cmp_svc_concurrent", plan, string(store.QuotaResourceServices), servicesLimit); err != nil {
		t.Fatalf("seed services plan policy: %v", err)
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
				Slug:           fmt.Sprintf("cmp-%02d", i),
				DisplayName:    fmt.Sprintf("Compose %02d", i),
				// Kind is pinned to the compose taxonomy member because
				// the compose_stacks quota dimension only counts compose-
				// kind services. An application- or database-kind service
				// would not consume a compose_stacks reservation, so the
				// per-subtype boundary the test exercises would not bite —
				// the test would fall back to the services dimension and
				// prove the wrong thing.
				Kind:          store.ServiceKindCompose,
				ActorID:       "usr_cmp_concurrent",
				ActorKind:     "usr",
				ActorOrgID:    orgID,
				RequestID:     fmt.Sprintf("req_cmp_%02d", i),
				CorrelationID: fmt.Sprintf("corr_cmp_%02d", i),
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
		// The rejection MUST name the compose_stacks dimension. If it
		// ever names "services" instead, then either (a) Service.Create
		// is no longer calling Reserve(compose_stacks) for the compose
		// kind, or (b) the test's services-dimension upper bound is
		// too tight to keep the per-subtype boundary the one that
		// bites. Either is a defect this test must surface.
		if detail.Resource != string(store.QuotaResourceComposeStacks) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceComposeStacks)
		}
		if detail.Limit != composeStacksLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, composeStacksLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal the
		// limit — anything less would mean the lock did not serialise
		// transactions against the counter row.
		if detail.Reserved != composeStacksLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, composeStacksLimit)
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
			fmt.Sprintf("cmp-%02d", r.index),
			fmt.Sprintf("Compose %02d", r.index),
			fmt.Sprintf("req_cmp_%02d", r.index),
			fmt.Sprintf("corr_cmp_%02d", r.index),
			r.serviceID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(composeStacksLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, composeStacksLimit)
	}
	if rejections != attempts-int(composeStacksLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(composeStacksLimit))
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
	if serviceRows != composeStacksLimit {
		t.Errorf("services rows for (org, env) = %d, want %d", serviceRows, composeStacksLimit)
	}

	// Each winning Create commits ONE active reservation per dimension:
	// one for "compose_stacks" (the new per-subtype dimension this story
	// adds) and one for "services" (the pre-existing dimension every
	// service create already touched). Rejected Creates rolled both
	// reservations back with the rest of the unit of work. So the
	// active reservation count for each dimension must equal the
	// number of successes.
	var activeComposeReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceComposeStacks)).Scan(&activeComposeReservations); err != nil {
		t.Fatalf("count active compose_stacks reservations: %v", err)
	}
	if activeComposeReservations != composeStacksLimit {
		t.Errorf("active compose_stacks reservations = %d, want %d",
			activeComposeReservations, composeStacksLimit)
	}
	var activeServicesReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&activeServicesReservations); err != nil {
		t.Fatalf("count active services reservations: %v", err)
	}
	if activeServicesReservations != composeStacksLimit {
		t.Errorf("active services reservations = %d, want %d (every compose create reserves both)",
			activeServicesReservations, composeStacksLimit)
	}

	// The repository's SumActiveReservations agrees with the raw count
	// on the compose_stacks dimension — the surface the Checker consults
	// to decide future requests cannot disagree with the table itself.
	var summedCompose int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceComposeStacks, time.Now().UTC())
		if err != nil {
			return err
		}
		summedCompose = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedCompose != composeStacksLimit {
		t.Errorf("SumActiveReservations(compose_stacks) = %d, want %d",
			summedCompose, composeStacksLimit)
	}

	// Both fakes were called exactly once per Create attempt — except for
	// the JobEnqueuer, which is never reached by a rejected transaction
	// because quota fails first. Authorization runs before quota, so the
	// rejected attempts increment authz but not jobs.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
	if got := jobs.calls.Load(); got != composeStacksLimit {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			got, composeStacksLimit)
	}
}

// TestServiceServiceCreateAppliesComposeStacksQuotaOnlyToComposeKind pins
// the per-subtype boundary the new compose_stacks dimension introduces: an
// application or database service in the same organization must NOT consume
// a compose_stacks reservation, even when the compose_stacks dimension is
// exhausted. This is the negative complement of the concurrent oversub
// test — together they prove the dimension is per-subtype AND row-locked.
//
// The test exhausts the compose_stacks dimension by creating five
// compose services against a hard-enforced limit of five, then proves
// that a SIXTH service whose Kind is ServiceKindApplication still
// succeeds, and likewise for ServiceKindDatabase. A future regression
// that dropped the Kind guard in ServiceService.Create would let the
// sixth (application or database) service reserve a compose_stacks row
// and fail with E_QUOTA_EXCEEDED for the compose_stacks dimension — this
// test would surface that as a defect.
func TestServiceServiceCreateAppliesComposeStacksQuotaOnlyToComposeKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan               = "starter"
		composeStacksLimit = int64(5)
		servicesLimit      = int64(20)
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

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value) VALUES ($1, $2, $3, 0)`,
		"qu_cmpkind_cmp", orgID, string(store.QuotaResourceComposeStacks)); err != nil {
		t.Fatalf("seed compose_stacks quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value) VALUES ($1, $2, $3, 0)`,
		"qu_cmpkind_svc", orgID, string(store.QuotaResourceServices)); err != nil {
		t.Fatalf("seed services quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_cmpkind_cmp", plan, string(store.QuotaResourceComposeStacks), composeStacksLimit); err != nil {
		t.Fatalf("seed compose_stacks plan policy: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_cmpkind_svc", plan, string(store.QuotaResourceServices), servicesLimit); err != nil {
		t.Fatalf("seed services plan policy: %v", err)
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

	// Exhaust the compose_stacks dimension by creating exactly limit
	// compose services. These all succeed — the services dimension is
	// loose, the compose_stacks dimension has room for exactly five,
	// and each create reserves one of each.
	for i := int64(0); i < composeStacksLimit; i++ {
		in := store.CreateServiceInput{
			OrganizationID: orgID,
			EnvironmentID:  environmentID,
			ServiceID:      domain.MustNewID(domain.KindService).String(),
			Slug:           fmt.Sprintf("cmp-fill-%02d", i),
			DisplayName:    fmt.Sprintf("Compose Fill %02d", i),
			Kind:           store.ServiceKindCompose,
			ActorID:        "usr_cmpkind",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_cmpkind_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_cmpkind_%02d", i),
		}
		if _, err := svc.Create(ctx, in); err != nil {
			t.Fatalf("seed compose %d: %v", i, err)
		}
	}

	// One more compose-kind service must now fail with the
	// compose_stacks-dimension code — guards against a regression where
	// the per-subtype Reserve call gets silently dropped.
	exhausted := store.CreateServiceInput{
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		ServiceID:      domain.MustNewID(domain.KindService).String(),
		Slug:           "cmp-extra",
		DisplayName:    "Compose Extra",
		Kind:           store.ServiceKindCompose,
		ActorID:        "usr_cmpkind",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_cmpkind_extra",
		CorrelationID:  "corr_cmpkind_extra",
	}
	if _, err := svc.Create(ctx, exhausted); err == nil {
		t.Fatalf("expected compose_stacks-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("compose overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceComposeStacks) {
		t.Fatalf("compose overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceComposeStacks)
	}

	// An application-kind service does NOT consume the compose_stacks
	// dimension and must succeed even though compose_stacks is full.
	// This is the per-subtype boundary the story introduces.
	application := store.CreateServiceInput{
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		ServiceID:      domain.MustNewID(domain.KindService).String(),
		Slug:           "app-after-fill",
		DisplayName:    "App After Fill",
		Kind:           store.ServiceKindApplication,
		ActorID:        "usr_cmpkind",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_cmpkind_app",
		CorrelationID:  "corr_cmpkind_app",
	}
	if _, err := svc.Create(ctx, application); err != nil {
		t.Fatalf("application create after compose_stacks exhaustion: unexpected error %v "+
			"(per-subtype boundary regressed — application now consuming compose_stacks quota)", err)
	}

	// A database-kind service is the other non-compose member of the
	// Dokploy taxonomy. It must also be unaffected by an exhausted
	// compose_stacks dimension.
	dbService := store.CreateServiceInput{
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		ServiceID:      domain.MustNewID(domain.KindService).String(),
		Slug:           "db-after-fill",
		DisplayName:    "DB After Fill",
		Kind:           store.ServiceKindDatabase,
		ActorID:        "usr_cmpkind",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_cmpkind_db",
		CorrelationID:  "corr_cmpkind_db",
	}
	if _, err := svc.Create(ctx, dbService); err != nil {
		t.Fatalf("database create after compose_stacks exhaustion: unexpected error %v "+
			"(per-subtype boundary regressed — database now consuming compose_stacks quota)", err)
	}

	// Final state: the compose_stacks counter has exactly five active
	// reservations (no more, no less). The services counter has seven —
	// the five compose plus the application plus the database — proving
	// the services dimension still counts every kind while the
	// compose_stacks dimension counts only compose-kind services.
	var cmpActive, svcActive int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceComposeStacks)).Scan(&cmpActive); err != nil {
		t.Fatalf("count compose_stacks reservations: %v", err)
	}
	if cmpActive != composeStacksLimit {
		t.Errorf("compose_stacks reservations = %d, want %d (non-compose kinds must not reserve)",
			cmpActive, composeStacksLimit)
	}
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&svcActive); err != nil {
		t.Fatalf("count services reservations: %v", err)
	}
	if svcActive != composeStacksLimit+2 {
		t.Errorf("services reservations = %d, want %d (every service kind reserves the services dimension)",
			svcActive, composeStacksLimit+2)
	}
}
