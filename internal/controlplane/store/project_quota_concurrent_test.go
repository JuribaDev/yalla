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

// TestProjectServiceCreateRejectsParallelOversubscriptionForProjectsQuota is
// the integration test for BE-0323 (quota dimension: projects) — the
// "concurrent integration tests prove parallel requests cannot oversubscribe
// the quota" acceptance criterion. The end-to-end path under test wires a
// real *store.ProjectService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository — the only fakes
// are the Authorizer and JobEnqueuer dependencies (covered by their own
// dedicated stories), which are recording fakes that always succeed. Twenty
// goroutines race to create a fresh project inside the same organization
// against a hard-enforced "projects" limit of five; the test asserts that
// exactly five Create calls return successfully and that the remaining
// fifteen are rejected with the typed CodeQuotaExceeded code, that the
// rejection error carries a recoverable quota.ExceededDetail with the
// expected counts, that exactly five project rows are visible in the
// database, and that exactly five active quota reservations exist for the
// "projects" dimension. Together these assertions prove the quota row lock
// (quota_usage SELECT FOR UPDATE inside Reserve) serialises concurrent
// transactions so the limit can never be over-allocated.
func TestProjectServiceCreateRejectsParallelOversubscriptionForProjectsQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan           = "starter"
		limit    int64 = 5
		attempts       = 20
	)

	orgID := seedDomainOrg(t, db)

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage can
	// acquire it without inserting a new row mid-race. LockUsage inserts
	// on first read; pre-seeding makes the concurrent serialisation
	// purely about the SELECT FOR UPDATE step on a row that already
	// exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_proj_concurrent", orgID, string(store.QuotaResourceProjects)); err != nil {
		t.Fatalf("seed quota_usage: %v", err)
	}

	// Plan-default policy: hard-enforced "projects" limit at five. No
	// organization override is seeded, so the Checker's plan-default
	// fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_proj_concurrent", plan, string(store.QuotaResourceProjects), limit); err != nil {
		t.Fatalf("seed plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	projRepo := store.NewProjectRepository()
	authz := &recordingAuthorizer{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, projRepo, authz, checker, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	type outcome struct {
		index     int
		projectID string
		err       error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateProjectInput{
				OrganizationID: orgID,
				ProjectID:      domain.MustNewID(domain.KindProject).String(),
				Slug:           fmt.Sprintf("p-%02d", i),
				DisplayName:    fmt.Sprintf("Project %02d", i),
				ActorID:        "usr_concurrent",
				ActorKind:      "usr",
				ActorOrgID:     orgID,
				RequestID:      fmt.Sprintf("req_p_%02d", i),
				CorrelationID:  fmt.Sprintf("corr_p_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{index: i, projectID: in.ProjectID, err: createErr}
		}(i)
	}
	wg.Wait()

	var successes, rejections int
	var successIDs []string
	for _, r := range results {
		if r.err == nil {
			successes++
			successIDs = append(successIDs, r.projectID)
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
		if detail.Resource != string(store.QuotaResourceProjects) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceProjects)
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
		// name and the counts — never the caller's request id, slug, or
		// any other input field — so a future logging path cannot turn
		// it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("p-%02d", r.index),
			fmt.Sprintf("Project %02d", r.index),
			fmt.Sprintf("req_p_%02d", r.index),
			fmt.Sprintf("corr_p_%02d", r.index),
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

	// The winners are unique — no two goroutines can have shared a project
	// id since each generated its own canonical id.
	seen := make(map[string]struct{}, len(successIDs))
	for _, id := range successIDs {
		if _, dup := seen[id]; dup {
			t.Errorf("two winners reported the same project id %q", id)
		}
		seen[id] = struct{}{}
	}

	// The desired-state row count must match the success count exactly —
	// proves no rejected transaction left behind a half-written project,
	// and no committed transaction failed to persist its project row.
	var projectRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM projects WHERE organization_id = $1`,
		orgID).Scan(&projectRows); err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if projectRows != limit {
		t.Errorf("projects rows for org = %d, want %d", projectRows, limit)
	}

	// Each winning Create commits one active reservation; rejected Creates
	// rolled their reservation back with the rest of the unit of work. So
	// the active reservation count for the projects dimension must equal
	// the number of successes.
	var activeReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceProjects)).Scan(&activeReservations); err != nil {
		t.Fatalf("count active reservations: %v", err)
	}
	if activeReservations != limit {
		t.Errorf("active projects reservations = %d, want %d", activeReservations, limit)
	}

	// The repository's SumActiveReservations agrees with the raw count —
	// the surface the Checker consults to decide future requests cannot
	// disagree with the table itself.
	var summed int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceProjects, time.Now().UTC())
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
	if authz.calls != attempts {
		t.Errorf("authorizer.calls = %d, want %d", authz.calls, attempts)
	}
	if jobs.calls != int(limit) {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			jobs.calls, limit)
	}
}
