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

// TestServiceDomainServiceCreateRejectsParallelOversubscriptionForDomainsQuota
// is the integration test for BE-0329 (quota dimension: domains) — the
// "concurrent integration tests prove parallel requests cannot oversubscribe
// the quota" acceptance criterion. The test wires a real
// *store.ServiceDomainService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository — the only
// fake is the Authorizer (covered by its own dedicated story), a
// recording fake that always succeeds. Twenty goroutines race to create
// a fresh service-scoped domain row against a hard-enforced "domains"
// limit of five; the test asserts that exactly five Create calls return
// successfully and that the remaining fifteen are rejected with the
// typed CodeQuotaExceeded code, that the rejection error carries a
// recoverable quota.ExceededDetail whose Resource is "domains" (proving
// the rejection came from the new dimension), that exactly five
// service_domains rows are visible in the database, and that exactly
// five active quota_reservations rows exist for the "domains"
// dimension. Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises concurrent
// transactions against the domains counter row so the limit can never
// be over-allocated.
//
// The test is the BE-0329 clone of the BE-0327 / BE-0328 service-
// quota reference (documented in ralph/progress.txt). The differences
// are: (1) the boundary under test is ServiceDomainService.Create
// rather than ServiceService.Create; (2) every domain is given a
// unique hostname (the (hostname, path) UNIQUE constraint forbids
// duplicates across the cluster, so two goroutines cannot race on the
// same hostname); (3) only the "domains" reservation table is counted
// at the end because the create unit of work touches a single quota
// dimension; (4) the JobEnqueuer port is not part of the service-
// domain orchestrator yet, so no equivalent assertion is needed.
func TestServiceDomainServiceCreateRejectsParallelOversubscriptionForDomainsQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		domainsLimit = int64(5)
		attempts     = 20
	)

	// Seed the parent organization, project, environment, and service
	// with canonical domain IDs. Raw SQL with domain.MustNewID(...)
	// mirrors the BE-0323..BE-0328 seed pattern and keeps the unit-of-
	// work boundary under test — not the test fixture — the only thing
	// the validator can reject.
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
		"qu_dom_concurrent", orgID, string(store.QuotaResourceDomains)); err != nil {
		t.Fatalf("seed domains quota_usage: %v", err)
	}

	// Plan-default policy for the domains dimension at the TIGHT bound
	// of five — this is the dimension the test proves serialises under
	// concurrent load. No organization override is seeded, so the
	// Checker's plan-default fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_dom_concurrent", plan, string(store.QuotaResourceDomains), domainsLimit); err != nil {
		t.Fatalf("seed domains plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	svc, err := store.NewServiceDomainService(
		s,
		store.NewServiceRepository(),
		store.NewServiceDomainRepository(),
		authz,
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceDomainService: %v", err)
	}

	type outcome struct {
		index    int
		domainID string
		hostname string
		err      error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateServiceDomainInput{
				OrganizationID: orgID,
				ServiceID:      serviceID,
				DomainID:       domain.MustNewID(domain.KindServiceDomain).String(),
				// Every goroutine uses a unique hostname so the
				// (hostname, path) UNIQUE constraint at the database
				// cannot be what makes any one attempt fail — the
				// only boundary that can reject a request is the
				// quota row lock under test.
				Hostname:        fmt.Sprintf("dom-%02d.example.com", i),
				Path:            "/",
				Port:            8080,
				HTTPS:           true,
				CertificateType: store.ServiceDomainCertificateLetsEncrypt,
				ActorID:         "usr_dom_concurrent",
				ActorKind:       "usr",
				ActorOrgID:      orgID,
				RequestID:       fmt.Sprintf("req_dom_%02d", i),
				CorrelationID:   fmt.Sprintf("corr_dom_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{
				index:    i,
				domainID: in.DomainID,
				hostname: in.Hostname,
				err:      createErr,
			}
		}(i)
	}
	wg.Wait()

	var successes, rejections int
	var successIDs []string
	for _, r := range results {
		if r.err == nil {
			successes++
			successIDs = append(successIDs, r.domainID)
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
		// The rejection MUST name the domains dimension. If it ever
		// names a different resource, the create unit of work has
		// drifted off the dimension the story enforces and this test
		// must surface it.
		if detail.Resource != string(store.QuotaResourceDomains) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceDomains)
		}
		if detail.Limit != domainsLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, domainsLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal
		// the limit — anything less would mean the lock did not
		// serialise transactions against the counter row.
		if detail.Reserved != domainsLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, domainsLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, hostname, correlation id, or domain id — so a future
		// logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("dom-%02d.example.com", r.index),
			fmt.Sprintf("req_dom_%02d", r.index),
			fmt.Sprintf("corr_dom_%02d", r.index),
			r.domainID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(domainsLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, domainsLimit)
	}
	if rejections != attempts-int(domainsLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(domainsLimit))
	}

	// The winners are unique — no two goroutines can have shared a
	// domain id since each generated its own canonical id.
	seen := make(map[string]struct{}, len(successIDs))
	for _, id := range successIDs {
		if _, dup := seen[id]; dup {
			t.Errorf("two winners reported the same domain id %q", id)
		}
		seen[id] = struct{}{}
	}

	// The desired-state row count must match the success count
	// exactly — proves no rejected transaction left behind a half-
	// written domain row, and no committed transaction failed to
	// persist its row. The scope is (organization_id, service_id) —
	// the tightest tenant scope a service_domains row carries, and
	// the only one the create unit of work writes against.
	var domainRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM service_domains WHERE organization_id = $1 AND service_id = $2`,
		orgID, serviceID).Scan(&domainRows); err != nil {
		t.Fatalf("count service_domains: %v", err)
	}
	if domainRows != domainsLimit {
		t.Errorf("service_domains rows for (org, service) = %d, want %d", domainRows, domainsLimit)
	}

	// Each winning Create commits one active reservation on the
	// "domains" dimension. Rejected Creates rolled their reservation
	// back with the rest of the unit of work. So the active
	// reservation count for the dimension must equal the number of
	// successes.
	var activeDomainsReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceDomains)).Scan(&activeDomainsReservations); err != nil {
		t.Fatalf("count active domains reservations: %v", err)
	}
	if activeDomainsReservations != domainsLimit {
		t.Errorf("active domains reservations = %d, want %d",
			activeDomainsReservations, domainsLimit)
	}

	// The repository's SumActiveReservations agrees with the raw
	// count on the domains dimension — the surface the Checker
	// consults to decide future requests cannot disagree with the
	// table itself.
	var summedDomains int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceDomains, time.Now().UTC())
		if err != nil {
			return err
		}
		summedDomains = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedDomains != domainsLimit {
		t.Errorf("SumActiveReservations(domains) = %d, want %d",
			summedDomains, domainsLimit)
	}

	// Authorization runs before quota inside the unit of work, so
	// every attempt — successful or rejected — increments the
	// authorizer fake.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
}

// TestServiceDomainServiceCreateAppliesDomainsQuotaIndependentlyOfServicesQuota
// pins that the domains dimension is INDEPENDENT of the services
// dimension: a service-domain Create reserves only the domains row,
// never the services row, so a tenant that exhausted services should
// still be able to create a domain on an existing service, and a
// tenant that exhausted domains should still observe the rejection on
// the domains dimension even when there is plenty of services
// headroom. The negative complement of the concurrent oversub test.
//
// The test exhausts the domains dimension by creating five domain
// rows against a hard-enforced limit of five, then proves a SIXTH
// Create fails with E_QUOTA_EXCEEDED whose ExceededDetail.Resource is
// "domains" — never another dimension. A future regression that
// either dropped the Reserve(domains) call or accidentally chose
// another resource string would surface here.
func TestServiceDomainServiceCreateAppliesDomainsQuotaIndependentlyOfServicesQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		domainsLimit = int64(5)
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
		"qp_dom_only", plan, string(store.QuotaResourceDomains), domainsLimit); err != nil {
		t.Fatalf("seed domains plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	svc, err := store.NewServiceDomainService(
		s,
		store.NewServiceRepository(),
		store.NewServiceDomainRepository(),
		authz,
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceDomainService: %v", err)
	}

	// Exhaust the domains dimension by creating exactly limit
	// domain rows. Each Create succeeds and consumes one domains
	// reservation.
	for i := int64(0); i < domainsLimit; i++ {
		in := store.CreateServiceDomainInput{
			OrganizationID:  orgID,
			ServiceID:       serviceID,
			DomainID:        domain.MustNewID(domain.KindServiceDomain).String(),
			Hostname:        fmt.Sprintf("fill-%02d.example.com", i),
			Path:            "/",
			Port:            8080,
			HTTPS:           true,
			CertificateType: store.ServiceDomainCertificateLetsEncrypt,
			ActorID:         "usr_dom_only",
			ActorKind:       "usr",
			ActorOrgID:      orgID,
			RequestID:       fmt.Sprintf("req_dom_only_%02d", i),
			CorrelationID:   fmt.Sprintf("corr_dom_only_%02d", i),
		}
		if _, err := svc.Create(ctx, in); err != nil {
			t.Fatalf("seed domain %d: %v", i, err)
		}
	}

	// One more Create must now fail on the domains dimension —
	// guards against a regression where the Reserve call gets
	// silently dropped or its resource string is changed.
	exhausted := store.CreateServiceDomainInput{
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		DomainID:        domain.MustNewID(domain.KindServiceDomain).String(),
		Hostname:        "extra.example.com",
		Path:            "/",
		Port:            8080,
		HTTPS:           true,
		CertificateType: store.ServiceDomainCertificateLetsEncrypt,
		ActorID:         "usr_dom_only",
		ActorKind:       "usr",
		ActorOrgID:      orgID,
		RequestID:       "req_dom_only_extra",
		CorrelationID:   "corr_dom_only_extra",
	}
	if _, err := svc.Create(ctx, exhausted); err == nil {
		t.Fatalf("expected domains-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("domain overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceDomains) {
		t.Fatalf("domain overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceDomains)
	}

	// Services dimension was never touched, so no services
	// reservation row exists for this tenant.
	var servicesReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&servicesReservations); err != nil {
		t.Fatalf("count active services reservations: %v", err)
	}
	if servicesReservations != 0 {
		t.Errorf("active services reservations = %d, want 0 (domain Create must not reserve on the services dimension)",
			servicesReservations)
	}
}
