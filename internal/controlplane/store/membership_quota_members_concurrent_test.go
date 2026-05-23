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

// TestMembershipServiceAddRejectsParallelOversubscriptionForMembersQuota is
// the integration test for BE-0338 (quota dimension: members) — the
// "concurrent integration tests prove parallel requests cannot
// oversubscribe the quota" acceptance criterion. The test wires a real
// *store.MembershipService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository. Twenty
// goroutines race to add a fresh user to the same organization against a
// hard-enforced "members" limit of five; the test asserts that exactly
// five Add calls return successfully and that the remaining fifteen are
// rejected with the typed CodeQuotaExceeded code, that the rejection
// error carries a recoverable quota.ExceededDetail whose Resource is
// "members", that exactly five memberships rows are visible in the
// database, and that exactly five active quota_reservations rows exist
// for the "members" dimension. Together these assertions prove the
// quota row lock (quota_usage SELECT FOR UPDATE inside Reserve)
// serialises concurrent transactions against the members counter row
// so the limit can never be over-allocated.
//
// The test is the BE-0338 sibling of the BE-0337 api_keys reference. The
// structural differences from the BE-0337 test are: (1) the unit of work
// under test is MembershipService.Add, which has no in-tx Authorizer and
// no JobEnqueuer — membership is pure Yalla source of truth with no
// Dokploy object to mirror — so this test wires no recording authorizer
// or jobs fakes; (2) each Add needs a fresh, distinct user row to add
// (the (organization_id, user_id) UNIQUE constraint forbids two adds of
// the same user), so the test pre-seeds twenty user rows up-front and
// each goroutine adds its own user; (3) no parent project / environment /
// service is seeded — memberships live directly under organizations,
// pairing one organization row with one user row per goroutine.
func TestMembershipServiceAddRejectsParallelOversubscriptionForMembersQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		membersLimit = int64(5)
		attempts     = 20
	)

	// Seed the parent organization with a canonical domain id. Raw SQL with
	// domain.MustNewID(...) mirrors the BE-0323..BE-0337 seed pattern and
	// keeps the unit-of-work boundary under test — not the test fixture —
	// the only thing the validator can reject.
	orgID := domain.MustNewID(domain.KindOrganization).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	// Pre-seed every user row up-front so the concurrent race is purely
	// about MembershipService.Add — not about INSERTing users mid-race.
	// Each goroutine adds a distinct user id to the same organization;
	// the (organization_id, user_id) UNIQUE constraint never fires
	// because every goroutine sees a different user_id.
	userIDs := make([]string, attempts)
	for i := 0; i < attempts; i++ {
		userID := domain.MustNewID(domain.KindUser).String()
		email := fmt.Sprintf("members-concurrent-%02d-%s@example.test", i, userID[len(userID)-8:])
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
			userID, email, fmt.Sprintf("member-%02d", i)); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
		userIDs[i] = userID
	}

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage can
	// acquire it without inserting a new row mid-race. The row already
	// exists so the concurrent serialisation is purely about the
	// SELECT FOR UPDATE step on a row that already exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_members_concurrent", orgID, string(store.QuotaResourceMembers)); err != nil {
		t.Fatalf("seed members quota_usage: %v", err)
	}

	// Plan-default policy for the members dimension at the TIGHT bound of
	// five — this is the dimension the test proves serialises under
	// concurrent load. No organization override is seeded, so the
	// Checker's plan-default fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_members_concurrent", plan, string(store.QuotaResourceMembers), membersLimit); err != nil {
		t.Fatalf("seed members plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	svc, err := store.NewMembershipService(
		s,
		store.NewOrganizationRepository(),
		store.NewMembershipRepository(),
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewMembershipService: %v", err)
	}

	type outcome struct {
		index  int
		userID string
		err    error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			in := store.AddMembershipInput{
				OrganizationID: orgID,
				UserID:         userIDs[i],
				Role:           "member",
				ActorID:        "usr_members_concurrent",
				ActorKind:      "usr",
				ActorOrgID:     orgID,
				RequestID:      fmt.Sprintf("req_members_%02d", i),
				CorrelationID:  fmt.Sprintf("corr_members_%02d", i),
			}
			_, addErr := svc.Add(ctx, in)
			results[i] = outcome{
				index:  i,
				userID: in.UserID,
				err:    addErr,
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
		// The rejection MUST name the members dimension. A regression
		// that dropped the Reserve call or accidentally changed the
		// resource string to a different dimension would surface here.
		if detail.Resource != string(store.QuotaResourceMembers) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceMembers)
		}
		if detail.Limit != membersLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, membersLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal the
		// limit — anything less would mean the lock did not serialise
		// transactions against the counter row.
		if detail.Reserved != membersLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, membersLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, correlation id, user id, or any other free-text input —
		// so a future logging path cannot turn it into a content
		// channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			r.userID,
			fmt.Sprintf("req_members_%02d", r.index),
			fmt.Sprintf("corr_members_%02d", r.index),
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(membersLimit) {
		t.Fatalf("concurrent Add successes = %d, want %d", successes, membersLimit)
	}
	if rejections != attempts-int(membersLimit) {
		t.Fatalf("concurrent Add rejections = %d, want %d", rejections, attempts-int(membersLimit))
	}

	// The desired-state row count must match the success count exactly —
	// proves no rejected transaction left behind a half-written
	// memberships row, and no committed transaction failed to persist its
	// row. The scope is (organization_id) — the tenant scope a
	// memberships row carries that the add unit of work writes against.
	var memberRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM memberships WHERE organization_id = $1`,
		orgID).Scan(&memberRows); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberRows != membersLimit {
		t.Errorf("memberships rows for org = %d, want %d", memberRows, membersLimit)
	}

	// Each winning Add commits one active reservation on the "members"
	// dimension. Rejected Adds rolled their reservation back with the
	// rest of the unit of work. So the active reservation count for the
	// dimension must equal the number of successes.
	var activeMemberReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceMembers)).Scan(&activeMemberReservations); err != nil {
		t.Fatalf("count active members reservations: %v", err)
	}
	if activeMemberReservations != membersLimit {
		t.Errorf("active members reservations = %d, want %d",
			activeMemberReservations, membersLimit)
	}

	// The repository's SumActiveReservations agrees with the raw count on
	// the members dimension — the surface the Checker consults to decide
	// future requests cannot disagree with the table itself.
	var summedMembers int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceMembers, time.Now().UTC())
		if err != nil {
			return err
		}
		summedMembers = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedMembers != membersLimit {
		t.Errorf("SumActiveReservations(members) = %d, want %d",
			summedMembers, membersLimit)
	}
}

// TestMembershipServiceAddAppliesMembersQuotaIndependentlyOfOtherDimensions
// pins that the members dimension is INDEPENDENT of every other quota
// dimension: a membership Add reserves the members dimension and no
// other, and a rejection on members must surface on the members
// dimension specifically — never disguised as another dimension's
// rejection. The negative complement of the concurrent oversub test
// above.
//
// The test exhausts the members dimension by adding five users against
// a hard-enforced limit of five (the in-flight reservations remain
// active for the 15-minute DefaultReservationTTL, so they are NOT
// released between calls within a single test run), then proves a
// SIXTH Add fails with E_QUOTA_EXCEEDED whose ExceededDetail.Resource
// is "members" — never another dimension. A future regression that
// either dropped the Reserve(members) call or accidentally chose
// another resource string would surface here. The test also pins that
// no quota_reservations row exists for unrelated dimensions
// (api_keys / projects) — the membership Add must not accidentally
// consume an unrelated dimension's quota.
func TestMembershipServiceAddAppliesMembersQuotaIndependentlyOfOtherDimensions(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		membersLimit = int64(5)
	)

	orgID := domain.MustNewID(domain.KindOrganization).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_members_only", plan, string(store.QuotaResourceMembers), membersLimit); err != nil {
		t.Fatalf("seed members plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	svc, err := store.NewMembershipService(
		s,
		store.NewOrganizationRepository(),
		store.NewMembershipRepository(),
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewMembershipService: %v", err)
	}

	// Exhaust the members dimension by adding exactly limit users. Each
	// Add succeeds and consumes one members reservation that stays active
	// for the duration of the test (DefaultReservationTTL is 15 minutes,
	// far longer than any test run).
	for i := int64(0); i < membersLimit; i++ {
		userID := domain.MustNewID(domain.KindUser).String()
		email := fmt.Sprintf("members-only-%02d-%s@example.test", i, userID[len(userID)-8:])
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
			userID, email, fmt.Sprintf("seed-member-%02d", i)); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
		in := store.AddMembershipInput{
			OrganizationID: orgID,
			UserID:         userID,
			Role:           "member",
			ActorID:        "usr_members_only",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_members_only_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_members_only_%02d", i),
		}
		if _, err := svc.Add(ctx, in); err != nil {
			t.Fatalf("seed member %d: %v", i, err)
		}
	}

	// One more Add must now fail on the members dimension — guards
	// against a regression where the Reserve call gets silently dropped
	// or its resource string is changed.
	overflowUserID := domain.MustNewID(domain.KindUser).String()
	overflowEmail := fmt.Sprintf("members-only-extra-%s@example.test", overflowUserID[len(overflowUserID)-8:])
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		overflowUserID, overflowEmail, "overflow-member"); err != nil {
		t.Fatalf("seed overflow user: %v", err)
	}
	exhausted := store.AddMembershipInput{
		OrganizationID: orgID,
		UserID:         overflowUserID,
		Role:           "member",
		ActorID:        "usr_members_only",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_members_only_extra",
		CorrelationID:  "corr_members_only_extra",
	}
	if _, err := svc.Add(ctx, exhausted); err == nil {
		t.Fatalf("expected members-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("members overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceMembers) {
		t.Fatalf("members overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceMembers)
	}

	// The api_keys dimension was never touched by a membership Add, so no
	// api_keys reservation row exists for this tenant. Pins that the
	// membership Add unit of work does not accidentally consume an
	// unrelated dimension's quota.
	var apiKeyReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceAPIKeys)).Scan(&apiKeyReservations); err != nil {
		t.Fatalf("count active api_keys reservations: %v", err)
	}
	if apiKeyReservations != 0 {
		t.Errorf("active api_keys reservations = %d, want 0 (membership Add must not reserve on the api_keys dimension)",
			apiKeyReservations)
	}

	// Symmetrically, the projects dimension was never touched either.
	var projectsReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceProjects)).Scan(&projectsReservations); err != nil {
		t.Fatalf("count active projects reservations: %v", err)
	}
	if projectsReservations != 0 {
		t.Errorf("active projects reservations = %d, want 0 (membership Add must not reserve on the projects dimension)",
			projectsReservations)
	}
}
