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

// TestServiceBackupServiceCreateRejectsParallelOversubscriptionForBackupSchedulesQuota
// is the integration test for BE-0334 (quota dimension:
// backup_schedules) — the "concurrent integration tests prove
// parallel requests cannot oversubscribe the quota" acceptance
// criterion. The test wires a real *store.ServiceBackupService
// against a real *quota.Checker, a real *store.QuotaRepository, and
// a real *store.AuditRepository — the only fake is the Authorizer
// (covered by its own dedicated story), a recording fake that
// always succeeds. Twenty goroutines race to create a fresh
// service-scoped backup-policy row against a hard-enforced
// "backup_schedules" limit of five; the test asserts that exactly
// five Create calls return successfully and that the remaining
// fifteen are rejected with the typed CodeQuotaExceeded code, that
// the rejection error carries a recoverable quota.ExceededDetail
// whose Resource is "backup_schedules" (proving the rejection came
// from the new dimension), that exactly five service_backups rows
// are visible in the database, and that exactly five active
// quota_reservations rows exist for the "backup_schedules"
// dimension. Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises
// concurrent transactions against the backup_schedules counter row
// so the limit can never be over-allocated.
//
// The test is the BE-0334 clone of the BE-0329 service-domain
// reference (documented in ralph/progress.txt). The differences
// are: (1) the boundary under test is ServiceBackupService.Create
// rather than ServiceDomainService.Create; (2) every backup is
// given a unique backup id and display name so no two goroutines
// can race on the same row; (3) only the "backup_schedules"
// reservation table is counted at the end because the create unit
// of work touches a single quota dimension; (4) the JobEnqueuer
// port is not part of the service-backup orchestrator yet, so no
// equivalent assertion is needed.
func TestServiceBackupServiceCreateRejectsParallelOversubscriptionForBackupSchedulesQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan                 = "starter"
		backupSchedulesLimit = int64(5)
		attempts             = 20
	)

	// Seed the parent organization, project, environment, and service
	// with canonical domain IDs. Raw SQL with domain.MustNewID(...)
	// mirrors the BE-0323..BE-0329 seed pattern and keeps the
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
		string(store.ServiceKindDatabase)); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage
	// can acquire it without inserting a new row mid-race. The row
	// already exists so the concurrent serialisation is purely about
	// the SELECT FOR UPDATE step on a row that already exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_bks_concurrent", orgID, string(store.QuotaResourceBackupSchedules)); err != nil {
		t.Fatalf("seed backup_schedules quota_usage: %v", err)
	}

	// Plan-default policy for the backup_schedules dimension at the
	// TIGHT bound of five — this is the dimension the test proves
	// serialises under concurrent load. No organization override is
	// seeded, so the Checker's plan-default fallback path is the one
	// exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_bks_concurrent", plan, string(store.QuotaResourceBackupSchedules), backupSchedulesLimit); err != nil {
		t.Fatalf("seed backup_schedules plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	svc, err := store.NewServiceBackupService(
		s,
		store.NewServiceRepository(),
		store.NewServiceBackupRepository(),
		authz,
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceBackupService: %v", err)
	}

	type outcome struct {
		index    int
		backupID string
		err      error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateServiceBackupInput{
				OrganizationID: orgID,
				ServiceID:      serviceID,
				BackupID:       domain.MustNewID(domain.KindServiceBackup).String(),
				DisplayName:    fmt.Sprintf("nightly-%02d", i),
				Schedule:       "0 2 * * *",
				RetentionCount: 7,
				Enabled:        true,
				ActorID:        "usr_bks_concurrent",
				ActorKind:      "usr",
				ActorOrgID:     orgID,
				RequestID:      fmt.Sprintf("req_bks_%02d", i),
				CorrelationID:  fmt.Sprintf("corr_bks_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{
				index:    i,
				backupID: in.BackupID,
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
			successIDs = append(successIDs, r.backupID)
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
		// The rejection MUST name the backup_schedules dimension. If
		// it ever names a different resource, the create unit of work
		// has drifted off the dimension the story enforces and this
		// test must surface it.
		if detail.Resource != string(store.QuotaResourceBackupSchedules) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceBackupSchedules)
		}
		if detail.Limit != backupSchedulesLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, backupSchedulesLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal
		// the limit — anything less would mean the lock did not
		// serialise transactions against the counter row.
		if detail.Reserved != backupSchedulesLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, backupSchedulesLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, backup id, correlation id, or display name — so a
		// future logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("nightly-%02d", r.index),
			fmt.Sprintf("req_bks_%02d", r.index),
			fmt.Sprintf("corr_bks_%02d", r.index),
			r.backupID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(backupSchedulesLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, backupSchedulesLimit)
	}
	if rejections != attempts-int(backupSchedulesLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(backupSchedulesLimit))
	}

	// The winners are unique — no two goroutines can have shared a
	// backup id since each generated its own canonical id.
	seen := make(map[string]struct{}, len(successIDs))
	for _, id := range successIDs {
		if _, dup := seen[id]; dup {
			t.Errorf("two winners reported the same backup id %q", id)
		}
		seen[id] = struct{}{}
	}

	// The desired-state row count must match the success count
	// exactly — proves no rejected transaction left behind a
	// half-written backup row, and no committed transaction failed to
	// persist its row. The scope is (organization_id, service_id) —
	// the tightest tenant scope a service_backups row carries, and
	// the only one the create unit of work writes against.
	var backupRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM service_backups WHERE organization_id = $1 AND service_id = $2`,
		orgID, serviceID).Scan(&backupRows); err != nil {
		t.Fatalf("count service_backups: %v", err)
	}
	if backupRows != backupSchedulesLimit {
		t.Errorf("service_backups rows for (org, service) = %d, want %d", backupRows, backupSchedulesLimit)
	}

	// Each winning Create commits one active reservation on the
	// "backup_schedules" dimension. Rejected Creates rolled their
	// reservation back with the rest of the unit of work. So the
	// active reservation count for the dimension must equal the
	// number of successes.
	var activeBackupScheduleReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceBackupSchedules)).Scan(&activeBackupScheduleReservations); err != nil {
		t.Fatalf("count active backup_schedules reservations: %v", err)
	}
	if activeBackupScheduleReservations != backupSchedulesLimit {
		t.Errorf("active backup_schedules reservations = %d, want %d",
			activeBackupScheduleReservations, backupSchedulesLimit)
	}

	// The repository's SumActiveReservations agrees with the raw
	// count on the backup_schedules dimension — the surface the
	// Checker consults to decide future requests cannot disagree with
	// the table itself.
	var summedBackupSchedules int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceBackupSchedules, time.Now().UTC())
		if err != nil {
			return err
		}
		summedBackupSchedules = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedBackupSchedules != backupSchedulesLimit {
		t.Errorf("SumActiveReservations(backup_schedules) = %d, want %d",
			summedBackupSchedules, backupSchedulesLimit)
	}

	// Authorization runs before quota inside the unit of work, so
	// every attempt — successful or rejected — increments the
	// authorizer fake.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
}

// TestServiceBackupServiceCreateAppliesBackupSchedulesQuotaIndependentlyOfServicesQuota
// pins that the backup_schedules dimension is INDEPENDENT of the
// services dimension: a service-backup Create reserves only the
// backup_schedules row, never the services row, so a tenant that
// exhausted services should still be able to create a backup policy
// on an existing service, and a tenant that exhausted
// backup_schedules should still observe the rejection on the
// backup_schedules dimension even when there is plenty of services
// headroom. The negative complement of the concurrent oversub test.
//
// The test exhausts the backup_schedules dimension by creating five
// backup rows against a hard-enforced limit of five, then proves a
// SIXTH Create fails with E_QUOTA_EXCEEDED whose
// ExceededDetail.Resource is "backup_schedules" — never another
// dimension. A future regression that either dropped the
// Reserve(backup_schedules) call or accidentally chose another
// resource string would surface here.
func TestServiceBackupServiceCreateAppliesBackupSchedulesQuotaIndependentlyOfServicesQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan                 = "starter"
		backupSchedulesLimit = int64(5)
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
		string(store.ServiceKindDatabase)); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_bks_only", plan, string(store.QuotaResourceBackupSchedules), backupSchedulesLimit); err != nil {
		t.Fatalf("seed backup_schedules plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	svc, err := store.NewServiceBackupService(
		s,
		store.NewServiceRepository(),
		store.NewServiceBackupRepository(),
		authz,
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceBackupService: %v", err)
	}

	// Exhaust the backup_schedules dimension by creating exactly
	// limit backup rows. Each Create succeeds and consumes one
	// backup_schedules reservation.
	for i := int64(0); i < backupSchedulesLimit; i++ {
		in := store.CreateServiceBackupInput{
			OrganizationID: orgID,
			ServiceID:      serviceID,
			BackupID:       domain.MustNewID(domain.KindServiceBackup).String(),
			DisplayName:    fmt.Sprintf("fill-%02d", i),
			Schedule:       "0 2 * * *",
			RetentionCount: 7,
			Enabled:        true,
			ActorID:        "usr_bks_only",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_bks_only_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_bks_only_%02d", i),
		}
		if _, err := svc.Create(ctx, in); err != nil {
			t.Fatalf("seed backup %d: %v", i, err)
		}
	}

	// One more Create must now fail on the backup_schedules
	// dimension — guards against a regression where the Reserve call
	// gets silently dropped or its resource string is changed.
	exhausted := store.CreateServiceBackupInput{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		BackupID:       domain.MustNewID(domain.KindServiceBackup).String(),
		DisplayName:    "extra",
		Schedule:       "0 2 * * *",
		RetentionCount: 7,
		Enabled:        true,
		ActorID:        "usr_bks_only",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_bks_only_extra",
		CorrelationID:  "corr_bks_only_extra",
	}
	if _, err := svc.Create(ctx, exhausted); err == nil {
		t.Fatalf("expected backup_schedules-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("backup overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceBackupSchedules) {
		t.Fatalf("backup overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceBackupSchedules)
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
		t.Errorf("active services reservations = %d, want 0 (backup Create must not reserve on the services dimension)",
			servicesReservations)
	}
}
