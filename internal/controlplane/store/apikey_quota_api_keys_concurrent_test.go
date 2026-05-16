package store_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/quota"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// TestAPIKeyServiceCreateRejectsParallelOversubscriptionForAPIKeysQuota is
// the integration test for BE-0337 (quota dimension: api_keys) — the
// "concurrent integration tests prove parallel requests cannot
// oversubscribe the quota" acceptance criterion. The test wires a real
// *store.APIKeyService against a real *quota.Checker, a real
// *store.QuotaRepository, and a real *store.AuditRepository. Twenty
// goroutines race to mint a fresh api_keys row in the same organization
// against a hard-enforced "api_keys" limit of five; the test asserts that
// exactly five Create calls return successfully and that the remaining
// fifteen are rejected with the typed CodeQuotaExceeded code, that the
// rejection error carries a recoverable quota.ExceededDetail whose
// Resource is "api_keys", that exactly five api_keys rows are visible in
// the database, and that exactly five active quota_reservations rows
// exist for the "api_keys" dimension. Together these assertions prove
// the quota row lock (quota_usage SELECT FOR UPDATE inside Reserve)
// serialises concurrent transactions against the api_keys counter row
// so the limit can never be over-allocated.
//
// The test is the BE-0337 sibling of the BE-0336 concurrent_deployments
// reference. The structural differences from the BE-0336 test are:
// (1) the unit of work under test is APIKeyService.Create, which has no
// in-tx Authorizer and no JobEnqueuer to fake — APIKeyService is pure
// Yalla identity with no Dokploy object to mirror — so this test seeds
// no recording-authorizer / recording-jobs fakes and instead relies on
// the recordingQuota stub from projectservice_test.go for fakes that
// might still be needed via the constructor (none, in this case);
// (2) each Create needs a fresh, unique (prefix, secret_hash) pair, so
// every goroutine calls auth.Generate() independently inside its
// goroutine and never shares the credential primitives; (3) no parent
// project / environment / service is seeded — api_keys live directly
// under organizations.
func TestAPIKeyServiceCreateRejectsParallelOversubscriptionForAPIKeysQuota(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		apiKeysLimit = int64(5)
		attempts     = 20
	)

	// Seed the parent organization with a canonical domain id. Raw SQL with
	// domain.MustNewID(...) mirrors the BE-0323..BE-0336 seed pattern and
	// keeps the unit-of-work boundary under test — not the test fixture —
	// the only thing the validator can reject.
	orgID := domain.MustNewID(domain.KindOrganization).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	// Pre-seed the quota_usage counter row so quota.Checker.LockUsage can
	// acquire it without inserting a new row mid-race. The row already
	// exists so the concurrent serialisation is purely about the
	// SELECT FOR UPDATE step on a row that already exists.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ($1, $2, $3, 0)`,
		"qu_apikeys_concurrent", orgID, string(store.QuotaResourceAPIKeys)); err != nil {
		t.Fatalf("seed api_keys quota_usage: %v", err)
	}

	// Plan-default policy for the api_keys dimension at the TIGHT bound of
	// five — this is the dimension the test proves serialises under
	// concurrent load. No organization override is seeded, so the
	// Checker's plan-default fallback path is the one exercised.
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'plan_default', $2, $3, $4, 'hard')`,
		"qp_apikeys_concurrent", plan, string(store.QuotaResourceAPIKeys), apiKeysLimit); err != nil {
		t.Fatalf("seed api_keys plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	svc, err := store.NewAPIKeyService(
		s,
		store.NewOrganizationRepository(),
		store.NewServiceAccountRepository(),
		store.NewAPIKeyRepository(),
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewAPIKeyService: %v", err)
	}

	type outcome struct {
		index int
		name  string
		err   error
	}
	results := make([]outcome, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			// Each goroutine mints its own credential primitives — the
			// auth-layer mint is independent per call so a (prefix,
			// secret_hash) collision is astronomically unlikely.
			gen, genErr := auth.Generate()
			if genErr != nil {
				results[i] = outcome{index: i, err: fmt.Errorf("auth.Generate: %w", genErr)}
				return
			}
			in := store.CreateAPIKeyInput{
				OrganizationID: orgID,
				Name:           fmt.Sprintf("key-%02d", i),
				Scopes:         []string{"projects:read"},
				Prefix:         gen.Prefix,
				SecretHash:     gen.SecretHash,
				ActorID:        "usr_apikeys_concurrent",
				ActorKind:      "usr",
				ActorOrgID:     orgID,
				RequestID:      fmt.Sprintf("req_apikeys_%02d", i),
				CorrelationID:  fmt.Sprintf("corr_apikeys_%02d", i),
			}
			_, createErr := svc.Create(ctx, in, time.Now())
			results[i] = outcome{
				index: i,
				name:  in.Name,
				err:   createErr,
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
		// The rejection MUST name the api_keys dimension. A regression
		// that dropped the Reserve call or accidentally changed the
		// resource string to a different dimension would surface here.
		if detail.Resource != string(store.QuotaResourceAPIKeys) {
			t.Errorf("attempt %d ExceededDetail.Resource = %q, want %q",
				r.index, detail.Resource, store.QuotaResourceAPIKeys)
		}
		if detail.Limit != apiKeysLimit {
			t.Errorf("attempt %d ExceededDetail.Limit = %d, want %d",
				r.index, detail.Limit, apiKeysLimit)
		}
		if detail.Requested != 1 {
			t.Errorf("attempt %d ExceededDetail.Requested = %d, want 1",
				r.index, detail.Requested)
		}
		// At the moment a rejection observes the lock, every winning
		// reservation is already committed, so Reserved must equal the
		// limit — anything less would mean the lock did not serialise
		// transactions against the counter row.
		if detail.Reserved != apiKeysLimit {
			t.Errorf("attempt %d ExceededDetail.Reserved = %d, want %d (lock did not serialise concurrent reservers)",
				r.index, detail.Reserved, apiKeysLimit)
		}
		if detail.Current != 0 {
			t.Errorf("attempt %d ExceededDetail.Current = %d, want 0 (no usage was committed during the race)",
				r.index, detail.Current)
		}

		// The rejection's diagnostic string must carry only the
		// resource name and the counts — never the caller's request
		// id, correlation id, name, or any other free-text input — so
		// a future logging path cannot turn it into a content channel.
		msg := r.err.Error()
		for _, leaky := range []string{
			fmt.Sprintf("key-%02d", r.index),
			fmt.Sprintf("req_apikeys_%02d", r.index),
			fmt.Sprintf("corr_apikeys_%02d", r.index),
		} {
			if strings.Contains(msg, leaky) {
				t.Errorf("attempt %d quota error leaks caller input %q in message %q",
					r.index, leaky, msg)
			}
		}
	}

	if successes != int(apiKeysLimit) {
		t.Fatalf("concurrent Create successes = %d, want %d", successes, apiKeysLimit)
	}
	if rejections != attempts-int(apiKeysLimit) {
		t.Fatalf("concurrent Create rejections = %d, want %d", rejections, attempts-int(apiKeysLimit))
	}

	// The desired-state row count must match the success count exactly —
	// proves no rejected transaction left behind a half-written api_keys
	// row, and no committed transaction failed to persist its row. The
	// scope is (organization_id) — the tenant scope an api_keys row
	// carries that the create unit of work writes against.
	var apiKeyRows int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE organization_id = $1`,
		orgID).Scan(&apiKeyRows); err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if apiKeyRows != apiKeysLimit {
		t.Errorf("api_keys rows for org = %d, want %d", apiKeyRows, apiKeysLimit)
	}

	// Each winning Create commits one active reservation on the "api_keys"
	// dimension. Rejected Creates rolled their reservation back with the
	// rest of the unit of work. So the active reservation count for the
	// dimension must equal the number of successes.
	var activeAPIKeyReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceAPIKeys)).Scan(&activeAPIKeyReservations); err != nil {
		t.Fatalf("count active api_keys reservations: %v", err)
	}
	if activeAPIKeyReservations != apiKeysLimit {
		t.Errorf("active api_keys reservations = %d, want %d",
			activeAPIKeyReservations, apiKeysLimit)
	}

	// The repository's SumActiveReservations agrees with the raw count on
	// the api_keys dimension — the surface the Checker consults to decide
	// future requests cannot disagree with the table itself.
	var summedAPIKeys int64
	readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		sum, err := quotaRepo.SumActiveReservations(ctx, q, orgID, store.QuotaResourceAPIKeys, time.Now().UTC())
		if err != nil {
			return err
		}
		summedAPIKeys = sum
		return nil
	})
	if readErr != nil {
		t.Fatalf("SumActiveReservations: %v", readErr)
	}
	if summedAPIKeys != apiKeysLimit {
		t.Errorf("SumActiveReservations(api_keys) = %d, want %d",
			summedAPIKeys, apiKeysLimit)
	}
}

// TestAPIKeyServiceCreateAppliesAPIKeysQuotaIndependentlyOfOtherDimensions
// pins that the api_keys dimension is INDEPENDENT of every other quota
// dimension: an api-key Create reserves the api_keys dimension and no
// other, and a rejection on api_keys must surface on the api_keys
// dimension specifically — never disguised as another dimension's
// rejection. The negative complement of the concurrent oversub test
// above.
//
// The test exhausts the api_keys dimension by minting five keys against
// a hard-enforced limit of five (the in-flight reservations remain active
// for the 15-minute DefaultReservationTTL, so they are NOT released
// between calls within a single test run), then proves a SIXTH Create
// fails with E_QUOTA_EXCEEDED whose ExceededDetail.Resource is
// "api_keys" — never another dimension. A future regression that either
// dropped the Reserve(api_keys) call or accidentally chose another
// resource string would surface here. The test also pins that no
// quota_reservations row exists for unrelated dimensions
// (services / projects) — the api-key Create must not accidentally
// consume an unrelated dimension's quota.
func TestAPIKeyServiceCreateAppliesAPIKeysQuotaIndependentlyOfOtherDimensions(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	const (
		plan         = "starter"
		apiKeysLimit = int64(5)
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
		"qp_apikeys_only", plan, string(store.QuotaResourceAPIKeys), apiKeysLimit); err != nil {
		t.Fatalf("seed api_keys plan policy: %v", err)
	}

	quotaRepo := store.NewQuotaRepository()
	checker, err := quota.NewChecker(quotaRepo, quota.StaticPlanResolver(plan))
	if err != nil {
		t.Fatalf("quota.NewChecker: %v", err)
	}

	svc, err := store.NewAPIKeyService(
		s,
		store.NewOrganizationRepository(),
		store.NewServiceAccountRepository(),
		store.NewAPIKeyRepository(),
		checker,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewAPIKeyService: %v", err)
	}

	// Exhaust the api_keys dimension by minting exactly limit keys. Each
	// Create succeeds and consumes one api_keys reservation that stays
	// active for the duration of the test (DefaultReservationTTL is
	// 15 minutes, far longer than any test run).
	for i := int64(0); i < apiKeysLimit; i++ {
		gen, genErr := auth.Generate()
		if genErr != nil {
			t.Fatalf("auth.Generate for seed %d: %v", i, genErr)
		}
		in := store.CreateAPIKeyInput{
			OrganizationID: orgID,
			Name:           fmt.Sprintf("fill-%02d", i),
			Scopes:         []string{"projects:read"},
			Prefix:         gen.Prefix,
			SecretHash:     gen.SecretHash,
			ActorID:        "usr_apikeys_only",
			ActorKind:      "usr",
			ActorOrgID:     orgID,
			RequestID:      fmt.Sprintf("req_apikeys_only_%02d", i),
			CorrelationID:  fmt.Sprintf("corr_apikeys_only_%02d", i),
		}
		if _, err := svc.Create(ctx, in, time.Now()); err != nil {
			t.Fatalf("seed api key %d: %v", i, err)
		}
	}

	// One more Create must now fail on the api_keys dimension — guards
	// against a regression where the Reserve call gets silently dropped
	// or its resource string is changed.
	gen, genErr := auth.Generate()
	if genErr != nil {
		t.Fatalf("auth.Generate for overflow: %v", genErr)
	}
	exhausted := store.CreateAPIKeyInput{
		OrganizationID: orgID,
		Name:           "extra",
		Scopes:         []string{"projects:read"},
		Prefix:         gen.Prefix,
		SecretHash:     gen.SecretHash,
		ActorID:        "usr_apikeys_only",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_apikeys_only_extra",
		CorrelationID:  "corr_apikeys_only_extra",
	}
	if _, err := svc.Create(ctx, exhausted, time.Now()); err == nil {
		t.Fatalf("expected api_keys-dimension rejection, got success")
	} else if ye := yerr.From(err); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("api_keys overflow returned code %s, want %s", ye.Code, yerr.CodeQuotaExceeded)
	} else if detail, ok := quota.DetailOf(err); !ok || detail.Resource != string(store.QuotaResourceAPIKeys) {
		t.Fatalf("api_keys overflow detail = %+v ok=%v, want resource %q",
			detail, ok, store.QuotaResourceAPIKeys)
	}

	// The services dimension was never touched by an api-key Create, so
	// no services reservation row exists for this tenant. Pins that the
	// api-key Create unit of work does not accidentally consume an
	// unrelated dimension's quota.
	var servicesReservations int64
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM quota_reservations
		 WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, string(store.QuotaResourceServices)).Scan(&servicesReservations); err != nil {
		t.Fatalf("count active services reservations: %v", err)
	}
	if servicesReservations != 0 {
		t.Errorf("active services reservations = %d, want 0 (api-key Create must not reserve on the services dimension)",
			servicesReservations)
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
		t.Errorf("active projects reservations = %d, want 0 (api-key Create must not reserve on the projects dimension)",
			projectsReservations)
	}
}
