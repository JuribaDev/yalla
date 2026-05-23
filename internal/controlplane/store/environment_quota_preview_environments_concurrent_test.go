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

// TestEnvironmentServiceCreateRejectsParallelOversubscriptionForPreviewEnvironmentsQuota
// is the integration test for BE-0330 (quota dimension:
// preview_environments) — the "concurrent integration tests prove
// parallel requests cannot oversubscribe the quota" acceptance
// criterion. Unlike the environments dimension, the
// preview_environments dimension is per-subtype: it counts ONLY
// environment rows whose Kind is EnvironmentKindPreview, so a
// standard-kind environment in the same project does not consume a
// preview_environments reservation. The test wires a real
// *store.EnvironmentService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository — the only
// fakes are the Authorizer and JobEnqueuer dependencies (covered by
// their own dedicated stories), which are recording fakes that always
// succeed. Twenty goroutines race to create a fresh preview-kind
// environment inside the same project against a hard-enforced
// "preview_environments" limit of five (the environments-dimension
// limit is seeded HIGHER than the attempt count so it cannot be the
// boundary that bites); the test asserts that exactly five Create calls
// return successfully and that the remaining fifteen are rejected with
// the typed CodeQuotaExceeded code, that the rejection error carries a
// recoverable quota.ExceededDetail whose Resource is
// "preview_environments" (proving the rejection came from the new
// per-subtype dimension and not from the environments dimension), that
// exactly five environment rows are visible in the database, and that
// exactly five active quota reservations exist for the
// "preview_environments" dimension (with another five for
// "environments", since every preview Create reserves both). Together
// these assertions prove the quota row lock (quota_usage SELECT FOR
// UPDATE inside Reserve) serialises concurrent transactions against the
// new preview_environments counter row so the per-subtype limit can
// never be over-allocated.
//
// This test is the BE-0330 clone of the BE-0328 databases-dimension
// reference (documented in ralph/progress.txt). The differences are:
// (1) the resource under test is the environment, so the test wires
// EnvironmentService instead of ServiceService and seeds only the
// organization+project parents (environments are the third hierarchy
// layer, so a parent environment is not needed); (2) the environment
// Kind is pinned to EnvironmentKindPreview, because the
// preview_environments dimension only counts preview-kind
// environments; (3) detail.Resource is asserted to equal
// QuotaResourcePreviewEnvironments so the test fails closed if
// Environment.Create ever stopped calling Reserve(preview_environments)
// for the preview kind and the rejections drifted back onto the
// environments dimension; (4) both reservation tables are counted at
// the end — preview_environments must equal the success count, and
// environments must also equal the success count since every winning
// Create reserved one of each, while losers rolled both reservations
// back.
func TestEnvironmentServiceCreateRejectsParallelOversubscriptionForPreviewEnvironmentsQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan              = "starter"
		previewLimit      = int64(5)
		environmentsLimit = int64(40)
		attempts          = 20
	)

	// Seed the parent organization and project with canonical domain IDs.
	// The testutil.Factory's id prefixes are not the canonical Kind
	// strings, so raw SQL with domain.MustNewID(...) mirrors the
	// BE-0323..BE-0329 seed pattern and keeps the unit-of-work boundary
	// under test — not the test fixture — the only thing the validator
	// can reject.
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

	// Pre-seed both quota_usage counter rows so quota.Checker.LockUsage
	// can acquire them without inserting new rows mid-race. The
	// preview_environments row is the one the per-subtype reservation
	// locks; the environments row is the one the existing
	// environments-dimension reservation locks. Both already exist so
	// the concurrent serialisation is purely about the SELECT FOR
	// UPDATE step on rows that already exist.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_pe_concurrent", orgID, string(store.QuotaResourcePreviewEnvironments)); err != nil {
		t.Fatalf("seed preview_environments quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_pe_env_concurrent", orgID, string(store.QuotaResourceEnvironments)); err != nil {
		t.Fatalf("seed environments quota_usage: %v", err)
	}

	// Plan-default policies for both dimensions. preview_environments
	// is the TIGHT bound at five — this is the dimension the test
	// proves serialises under concurrent load. environments is the
	// LOOSE bound at attempts*2 — large enough that the environments
	// row lock cannot be the limit that bites, so a rejection's
	// detail.Resource can only be "preview_environments". No
	// organization override is seeded, so the Checker's plan-default
	// fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_pe_concurrent", plan, string(store.QuotaResourcePreviewEnvironments), previewLimit); err != nil {
		t.Fatalf("seed preview_environments plan policy: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_pe_env_concurrent", plan, string(store.QuotaResourceEnvironments), environmentsLimit); err != nil {
		t.Fatalf("seed environments plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewEnvironmentService(
		s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	type outcome struct {
		index         int
		environmentID string
		slug          string
		err           error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.CreateEnvironmentInput{
				OrganizationID: orgID,
				ProjectID:      projectID,
				EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
				Slug:           fmt.Sprintf("pe-%02d", i),
				DisplayName:    fmt.Sprintf("Preview %02d", i),
				// Kind is pinned to the preview taxonomy member because
				// the preview_environments quota dimension only counts
				// preview-kind environments. A standard-kind environment
				// would not consume a preview_environments reservation,
				// so the per-subtype boundary the test exercises would
				// not bite — the test would fall back to the
				// environments dimension and prove the wrong thing.
				Kind:          store.EnvironmentKindPreview,
				ActorID:       "usr_pe_concurrent",
				ActorKind:     "usr",
				ActorOrgID:    orgID,
				RequestID:     fmt.Sprintf("req_pe_%02d", i),
				CorrelationID: fmt.Sprintf("corr_pe_%02d", i),
			}
			_, createErr := svc.Create(ctx, in)
			results[i] = outcome{
				index:         i,
				environmentID: in.EnvironmentID,
				slug:          in.Slug,
				err:           createErr,
			}
		}(i)
	}
	wg.Wait()

	var successes, rejections int
	var successIDs []string
	for _, r := range results {
		if r.err == nil {
			successes++
			successIDs = append(successIDs, r.environmentID)
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
		// The rejection MUST name the preview_environments dimension. If
		// it ever names "environments" instead, then either (a)
		// Environment.Create is no longer calling
		// Reserve(preview_environments) for the preview kind, or (b) the
		// test's environments-dimension upper bound is too tight to keep
		// the per-subtype boundary the one that bites. Either is a defect
		// this test must surface.
		if detail.Resource != string(store.QuotaResourcePreviewEnvironments) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourcePreviewEnvironments)
		}
		if detail.Limit != previewLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, previewLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal the
		// limit — anything less would mean the lock did not serialise
		// transactions against the counter row.
		if detail.Reserved != previewLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, previewLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the resource
		// name and the counts — never the caller's request id, slug,
		// display name, correlation id, or environment id — so a future
		// logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("pe-%02d", r.index),
			fmt.Sprintf("Preview %02d", r.index),
			fmt.Sprintf("req_pe_%02d", r.index),
			fmt.Sprintf("corr_pe_%02d", r.index),
			r.environmentID,
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(previewLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, previewLimit)
	}
	if rejections != attempts-int(previewLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(previewLimit))
	}

	// The winners are unique — no two goroutines can have shared an
	// environment id since each generated its own canonical id.
	seen := make(map[string]struct{}, len(successIDs))
	for _, id := range successIDs {
		if _, dup := seen[id]; dup {
			t.Errorf("two winners reported the same environment id %q", id)
		}
		seen[id] = struct{}{}
	}

	// The desired-state row count must match the success count exactly —
	// proves no rejected transaction left behind a half-written
	// environment, and no committed transaction failed to persist its
	// environment row. The scope is (organization_id, project_id, kind)
	// because the test only writes preview-kind environments under one
	// project and other tests could write standard environments
	// elsewhere in the same shared database.
	var previewRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM environments WHERE organization_id = $1 AND project_id = $2 AND kind = $3`,
		orgID, projectID, store.EnvironmentKindPreview).Scan(&previewRows); err != nil {
		t.Fatalf("count preview environments: %v", err)
	}
	if previewRows != previewLimit {
		t.Errorf("preview environment rows for (org, project) = %d, want %d", previewRows, previewLimit)
	}

	// Each winning Create commits ONE active reservation per dimension:
	// one for "preview_environments" (the new per-subtype dimension
	// this story adds) and one for "environments" (the pre-existing
	// dimension every environment create already touched). Rejected
	// Creates rolled both reservations back with the rest of the unit
	// of work. So the active reservation count for each dimension must
	// equal the number of successes.
	var activePreviewReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourcePreviewEnvironments)).Scan(&activePreviewReservations); err != nil {
		t.Fatalf("count active preview_environments reservations: %v", err)
	}
	if activePreviewReservations != previewLimit {
		t.Errorf("active preview_environments reservations = %d, want %d",
			activePreviewReservations, previewLimit)
	}
	var activeEnvironmentsReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceEnvironments)).Scan(&activeEnvironmentsReservations); err != nil {
		t.Fatalf("count active environments reservations: %v", err)
	}
	if activeEnvironmentsReservations != previewLimit {
		t.Errorf("active environments reservations = %d, want %d (every preview create reserves both)",
			activeEnvironmentsReservations, previewLimit)
	}

	// The repository's SumActiveReservations agrees with the raw count
	// on the preview_environments dimension — the surface the Checker
	// consults to decide future requests cannot disagree with the table
	// itself.
	var summedPreview int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourcePreviewEnvironments, time.Now().UTC())
		if err != nil {
			return err
		}
		summedPreview = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedPreview != previewLimit {
		t.Errorf("SumActiveReservations(preview_environments) = %d, want %d",
			summedPreview, previewLimit)
	}

	// Both fakes were called exactly once per Create attempt — except
	// for the JobEnqueuer, which is never reached by a rejected
	// transaction because quota fails first. Authorization runs before
	// quota, so the rejected attempts increment authz but not jobs.
	if got := authz.calls.Load(); got != int64(attempts) {
		t.Errorf("authorizer.calls = %d, want %d", got, attempts)
	}
	if got := jobs.calls.Load(); got != previewLimit {
		t.Errorf("jobs.calls = %d, want %d (rejected attempts must not enqueue)",
			got, previewLimit)
	}
}

// TestEnvironmentServiceCreateAppliesPreviewEnvironmentsQuotaOnlyToPreviewKind
// pins the per-subtype boundary the new preview_environments dimension
// introduces: a standard environment in the same organization must NOT
// consume a preview_environments reservation, even when the
// preview_environments dimension is exhausted. This is the negative
// complement of the concurrent oversub test — together they prove the
// dimension is per-subtype AND row-locked.
//
// The test exhausts the preview_environments dimension by creating
// five preview environments against a hard-enforced limit of five,
// then proves that a SIXTH environment whose Kind is
// EnvironmentKindStandard still succeeds. A future regression that
// dropped the Kind guard in EnvironmentService.Create would let the
// sixth (standard) environment reserve a preview_environments row and
// fail with E_QUOTA_EXCEEDED for the preview_environments dimension —
// this test would surface that as a defect.
func TestEnvironmentServiceCreateAppliesPreviewEnvironmentsQuotaOnlyToPreviewKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan              = "starter"
		previewLimit      = int64(5)
		environmentsLimit = int64(20)
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

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value) VALUES ($1, $2, $3, 0)`,
		"qu_pekind_pe", orgID, string(store.QuotaResourcePreviewEnvironments)); err != nil {
		t.Fatalf("seed preview_environments quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value) VALUES ($1, $2, $3, 0)`,
		"qu_pekind_env", orgID, string(store.QuotaResourceEnvironments)); err != nil {
		t.Fatalf("seed environments quota_usage: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_pekind_pe", plan, string(store.QuotaResourcePreviewEnvironments), previewLimit); err != nil {
		t.Fatalf("seed preview_environments plan policy: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_pekind_env", plan, string(store.QuotaResourceEnvironments), environmentsLimit); err != nil {
		t.Fatalf("seed environments plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}
	authz := &atomicAuthorizer{}
	jobs := &atomicJobs{}
	svc, err := store.NewEnvironmentService(
		s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		authz,
		checker,
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	// Exhaust the preview_environments dimension by creating exactly
	// limit preview environments. These all succeed — the environments
	// dimension is loose, the preview_environments dimension has room
	// for exactly five, and each create reserves one of each.
	for i := int64(0); i < previewLimit; i++ {
		in := store.CreateEnvironmentInput{
			OrganizationID: orgID,
			ProjectID:      projectID,
			EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
			Slug:           fmt.Sprintf("pe-fill-%02d", i),
			DisplayName:    fmt.Sprintf("Preview Fill %02d", i),
			Kind:           store.EnvironmentKindPreview,
			ActorID:        "usr_pekind",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_pekind_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_pekind_%02d", i),
		}
		if _, err := svc.Create(ctx, in); err != nil {
			t.Fatalf("seed preview %d: %v", i, err)
		}
	}

	// One more preview-kind environment must now fail with the
	// preview_environments-dimension code — guards against a regression
	// where the per-subtype Reserve call gets silently dropped.
	exhausted := store.CreateEnvironmentInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "pe-extra",
		DisplayName:    "Preview Extra",
		Kind:           store.EnvironmentKindPreview,
		ActorID:        "usr_pekind",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_pekind_extra",
		CorrelationID:  "corr_pekind_extra",
	}
	if _, err := svc.Create(ctx, exhausted); err == nil {
		t.Fatalf("expected preview_environments-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("preview overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourcePreviewEnvironments) {
		t.Fatalf("preview overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourcePreviewEnvironments)
	}

	// A standard-kind environment does NOT consume the
	// preview_environments dimension and must succeed even though
	// preview_environments is full. This is the per-subtype boundary
	// the story introduces.
	standard := store.CreateEnvironmentInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "std-after-fill",
		DisplayName:    "Standard After Fill",
		Kind:           store.EnvironmentKindStandard,
		ActorID:        "usr_pekind",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_pekind_std",
		CorrelationID:  "corr_pekind_std",
	}
	if _, err := svc.Create(ctx, standard); err != nil {
		t.Fatalf("standard create after preview_environments exhaustion: unexpected error %v "+
			"(per-subtype boundary regressed — standard now consuming preview_environments quota)", err)
	}

	// A blank-Kind environment normalises to EnvironmentKindStandard
	// (the validateEnvironmentKind default-on-blank contract) so it
	// must also be unaffected by an exhausted preview_environments
	// dimension. This is the legacy-caller path that predates BE-0330:
	// callers that never carried the field still produce standard
	// environments and still skip the preview_environments quota.
	legacy := store.CreateEnvironmentInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "lgc-after-fill",
		DisplayName:    "Legacy After Fill",
		// Kind intentionally left blank.
		ActorID:       "usr_pekind",
		ActorKind:     "usr",
		ActorOrgID:    orgID,
		RequestID:     "req_pekind_lgc",
		CorrelationID: "corr_pekind_lgc",
	}
	if _, err := svc.Create(ctx, legacy); err != nil {
		t.Fatalf("legacy (blank-Kind) create after preview_environments exhaustion: unexpected error %v "+
			"(blank-Kind must normalise to standard and skip the preview_environments dimension)", err)
	}

	// Final state: the preview_environments counter has exactly five
	// active reservations (no more, no less). The environments counter
	// has seven — the five preview plus the standard plus the legacy
	// (blank-Kind, which normalises to standard) — proving the
	// environments dimension still counts every kind while the
	// preview_environments dimension counts only preview-kind
	// environments.
	var previewActive, envActive int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourcePreviewEnvironments)).Scan(&previewActive); err != nil {
		t.Fatalf("count preview_environments reservations: %v", err)
	}
	if previewActive != previewLimit {
		t.Errorf("preview_environments reservations = %d, want %d (non-preview kinds must not reserve)",
			previewActive, previewLimit)
	}
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceEnvironments)).Scan(&envActive); err != nil {
		t.Fatalf("count environments reservations: %v", err)
	}
	if envActive != previewLimit+2 {
		t.Errorf("environments reservations = %d, want %d (every environment kind reserves the environments dimension)",
			envActive, previewLimit+2)
	}
}
