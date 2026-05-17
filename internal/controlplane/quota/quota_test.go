package quota_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/quota"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Tests for the quota checker service. The pure construction-guard, validation,
// and error-detail behaviour is unit tested without a database; the headroom
// decision, the FOR UPDATE serialisation, and tenant isolation are integration
// tested against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

// --- Unit tests (no database) ---

func TestNewCheckerRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()

	if _, err := quota.NewChecker(nil, quota.StaticPlanResolver(quota.DefaultPlan)); err == nil {
		t.Error("NewChecker(nil repo) error = nil, want an error")
	}
	if _, err := quota.NewChecker(repo, nil); err == nil {
		t.Error("NewChecker(nil plan resolver) error = nil, want an error")
	}
}

func TestNewCheckerRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	repo := store.NewQuotaRepository()
	plans := quota.StaticPlanResolver(quota.DefaultPlan)

	if _, err := quota.NewChecker(repo, plans, quota.WithReservationTTL(0)); err == nil {
		t.Error("NewChecker(WithReservationTTL(0)) error = nil, want an error")
	}
	if _, err := quota.NewChecker(repo, plans, quota.WithReservationTTL(-time.Minute)); err == nil {
		t.Error("NewChecker(WithReservationTTL(negative)) error = nil, want an error")
	}
	if _, err := quota.NewChecker(repo, plans, quota.WithClock(nil)); err == nil {
		t.Error("NewChecker(WithClock(nil)) error = nil, want an error")
	}
}

func TestCheckerReserveRejectsNilTransaction(t *testing.T) {
	t.Parallel()
	checker := mustChecker(t)

	err := checker.Reserve(context.Background(), nil, "org_x", "projects")
	if err == nil {
		t.Fatal("Reserve(nil tx) error = nil, want an error")
	}
	if yerr.From(err).Code != yerr.CodeInternal {
		t.Errorf("Reserve(nil tx) code = %v, want %s", yerr.From(err).Code, yerr.CodeInternal)
	}
}

func TestCheckerReserveValidationFailure(t *testing.T) {
	t.Parallel()
	checker := mustChecker(t)
	ctx := context.Background()

	cases := []struct {
		name     string
		orgID    string
		resource string
		field    string
	}{
		{"empty organization", "  ", "projects", "organization_id"},
		{"unknown resource", "org_x", "not-a-dimension", "resource"},
		{"empty resource", "org_x", "", "resource"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Validation runs before the transaction is ever touched, so a
			// zero-value *store.Tx is sufficient — it is never dereferenced.
			err := checker.Reserve(ctx, &store.Tx{}, tc.orgID, tc.resource)
			if err == nil {
				t.Fatal("Reserve error = nil, want a validation failure")
			}
			if yerr.From(err).Code != yerr.CodeInvalidInput {
				t.Fatalf("Reserve code = %v, want %s", yerr.From(err).Code, yerr.CodeInvalidInput)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok || len(violations) == 0 {
				t.Fatalf("Reserve carried no field violations: ok=%v", ok)
			}
			if violations[0].Field != tc.field {
				t.Errorf("violation field = %q, want %q", violations[0].Field, tc.field)
			}
		})
	}
}

func TestExceededDetailRoundTrips(t *testing.T) {
	t.Parallel()

	want := quota.ExceededDetail{Resource: "projects", Current: 1, Reserved: 2, Requested: 1, Limit: 3}
	wrapped := apierr.QuotaExceeded("projects", 3).Wrap(want)

	got, ok := quota.DetailOf(wrapped)
	if !ok {
		t.Fatal("DetailOf returned ok = false, want the wrapped detail")
	}
	if got != want {
		t.Errorf("DetailOf = %+v, want %+v", got, want)
	}
	if _, ok := quota.DetailOf(errors.New("unrelated")); ok {
		t.Error("DetailOf(unrelated error) ok = true, want false")
	}
	if _, ok := quota.DetailOf(nil); ok {
		t.Error("DetailOf(nil) ok = true, want false")
	}
}

// --- Integration tests (Postgres) ---

func TestCheckerReserveRecordsReservationWithHeadroom(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	seedOrgQuotaPolicy(t, db, orgID, "projects", 3, "hard")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgID, "projects")
	}); err != nil {
		t.Fatalf("Reserve with headroom: %v", err)
	}
	if got := activeReservationCount(t, db, orgID, "projects"); got != 1 {
		t.Errorf("active reservations = %d, want 1", got)
	}
}

func TestCheckerReserveRejectsWhenLimitExhausted(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	seedOrgQuotaPolicy(t, db, orgID, "projects", 1, "hard")

	// The first reservation consumes the only unit.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgID, "projects")
	}); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}

	// The second must be rejected, and the rejection must roll back cleanly.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgID, "projects")
	})
	if err == nil {
		t.Fatal("second Reserve error = nil, want a quota rejection")
	}
	if yerr.From(err).Code != yerr.CodeQuotaExceeded {
		t.Fatalf("second Reserve code = %v, want %s", yerr.From(err).Code, yerr.CodeQuotaExceeded)
	}
	detail, ok := quota.DetailOf(err)
	if !ok {
		t.Fatal("quota rejection carried no recoverable ExceededDetail")
	}
	want := quota.ExceededDetail{Resource: "projects", Current: 0, Reserved: 1, Requested: 1, Limit: 1}
	if detail != want {
		t.Errorf("ExceededDetail = %+v, want %+v", detail, want)
	}
	if got := activeReservationCount(t, db, orgID, "projects"); got != 1 {
		t.Errorf("active reservations after a rejected Reserve = %d, want 1 (the rejection rolled back)", got)
	}
}

func TestCheckerReserveAllowsWhenNoPolicyConfigured(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	// No policy seeded for this dimension at either scope.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgID, "databases")
	}); err != nil {
		t.Fatalf("Reserve with no policy: %v", err)
	}
	if got := activeReservationCount(t, db, orgID, "databases"); got != 0 {
		t.Errorf("active reservations = %d, want 0 (an unconstrained resource records nothing)", got)
	}
}

func TestCheckerReserveAllowsWhenEnforcementDisabled(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	seedOrgQuotaPolicy(t, db, orgID, "domains", 0, "disabled")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgID, "domains")
	}); err != nil {
		t.Fatalf("Reserve with disabled enforcement: %v", err)
	}
	if got := activeReservationCount(t, db, orgID, "domains"); got != 0 {
		t.Errorf("active reservations = %d, want 0 (disabled enforcement records nothing)", got)
	}
}

func TestCheckerReserveSoftLimitNeverRejects(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	seedOrgQuotaPolicy(t, db, orgID, "services", 1, "soft")

	// Two reservations against a soft limit of one: both are recorded.
	for i := 0; i < 2; i++ {
		if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			return checker.Reserve(ctx, tx, orgID, "services")
		}); err != nil {
			t.Fatalf("soft Reserve %d: %v", i, err)
		}
	}
	if got := activeReservationCount(t, db, orgID, "services"); got != 2 {
		t.Errorf("active reservations under a soft limit = %d, want 2", got)
	}
}

// TestCheckerReserveConcurrentRespectsLimit is the core concurrency test:
// parallel reservations against the same organization, with a hard limit below
// the number of attempts. Exactly limit reservations must succeed, the rest
// must be rejected, and the database must agree — the FOR UPDATE lock on the
// usage counter makes it impossible for two units of work to both decide they
// have headroom.
func TestCheckerReserveConcurrentRespectsLimit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	const limit = 3
	const attempts = 9
	seedOrgQuotaPolicy(t, db, orgID, "projects", limit, "hard")

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		rejected  int
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				return checker.Reserve(ctx, tx, orgID, "projects")
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case yerr.From(err).Code == yerr.CodeQuotaExceeded:
				rejected++
			default:
				t.Errorf("unexpected Reserve error: %v", err)
			}
		}()
	}
	wg.Wait()

	if succeeded != limit {
		t.Errorf("succeeded reservations = %d, want %d", succeeded, limit)
	}
	if rejected != attempts-limit {
		t.Errorf("rejected reservations = %d, want %d", rejected, attempts-limit)
	}
	if got := activeReservationCount(t, db, orgID, "projects"); got != limit {
		t.Errorf("active reservations in the database = %d, want %d", got, limit)
	}
}

// TestQuotaConcurrencyHardLimitNeverOverallocates is the canonical
// hard-limit concurrency invariant: parallel reservations against the same
// organization, with a hard limit below the number of attempts, must result
// in exactly limit successes and the rest rejected with
// yerr.CodeQuotaExceeded. The FOR UPDATE lock on the usage counter row is
// what makes "two units of work both decide they have headroom" impossible;
// a regression that drops the lock would silently let two concurrent
// reservations exceed the limit without firing any other gate.
//
// The function name is deliberately prefixed `TestQuotaConcurrency` so the
// PRD's `go test -run TestQuotaConcurrency ./...` filter (pinned by
// `internal/release/verification_suite_quota_concurrency_static_test.go`)
// binds to it. Renaming this function to a name that does not match the
// prefix silently de-gates the concurrency suite for any caller relying
// on the filter — the static test fails loudly if this happens.
//
// Actionable failures: every diagnostic surfaces the organization ID and
// the resource so an operator reading the CI log can map the failure to
// the exact tenant and dimension without re-running the suite locally.
func TestQuotaConcurrencyHardLimitNeverOverallocates(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgID := seedQuotaOrg(t, db)
	const limit = 3
	const attempts = 12
	seedOrgQuotaPolicy(t, db, orgID, "projects", limit, "hard")

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		rejected  int
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				return checker.Reserve(ctx, tx, orgID, "projects")
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case yerr.From(err).Code == yerr.CodeQuotaExceeded:
				rejected++
			default:
				t.Errorf("organization %q resource %q unexpected Reserve error: %v", orgID, "projects", err)
			}
		}()
	}
	wg.Wait()

	if succeeded != limit {
		t.Errorf("organization %q resource %q succeeded reservations = %d, want %d", orgID, "projects", succeeded, limit)
	}
	if rejected != attempts-limit {
		t.Errorf("organization %q resource %q rejected reservations = %d, want %d", orgID, "projects", rejected, attempts-limit)
	}
	if got := activeReservationCount(t, db, orgID, "projects"); got != limit {
		t.Errorf("organization %q resource %q active reservations in the database = %d, want %d", orgID, "projects", got, limit)
	}
}

// TestQuotaConcurrencyTenantIsolation is the canonical cross-tenant
// concurrency invariant: parallel reservations against two organizations,
// each with its own hard limit, must each respect its own organization's
// limit and must never have one tenant's usage leak into the other. A
// regression that scoped the FOR UPDATE lock to the resource dimension
// alone (instead of the organization-and-resource pair) would silently
// serialise unrelated tenants behind one another and could over-count
// usage across organizations; a regression that dropped the
// organization predicate from the usage-counter or reservation-sum
// queries would silently flatten cross-tenant counts into one bucket
// and reject one tenant on another tenant's traffic.
//
// The function name is deliberately prefixed `TestQuotaConcurrency` so
// the PRD's `go test -run TestQuotaConcurrency ./...` filter (pinned by
// `internal/release/verification_suite_quota_concurrency_static_test.go`)
// binds to it. The pair (this test + the hard-limit twin above) captures
// the two load-bearing concurrency invariants the checker MUST keep.
//
// Actionable failures: every diagnostic names both organization IDs so
// an operator reading the CI log can map the failure to the exact pair
// without re-running the suite locally.
func TestQuotaConcurrencyTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgA := seedQuotaOrg(t, db)
	orgB := seedQuotaOrg(t, db)
	const limitA = 2
	const limitB = 4
	const attemptsPerOrg = 8
	seedOrgQuotaPolicy(t, db, orgA, "projects", limitA, "hard")
	seedOrgQuotaPolicy(t, db, orgB, "projects", limitB, "hard")

	type tally struct {
		mu                  sync.Mutex
		succeeded, rejected int
	}
	results := map[string]*tally{orgA: {}, orgB: {}}

	var wg sync.WaitGroup
	for _, orgID := range []string{orgA, orgB} {
		orgID := orgID
		bucket := results[orgID]
		for i := 0; i < attemptsPerOrg; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
					return checker.Reserve(ctx, tx, orgID, "projects")
				})
				bucket.mu.Lock()
				defer bucket.mu.Unlock()
				switch {
				case err == nil:
					bucket.succeeded++
				case yerr.From(err).Code == yerr.CodeQuotaExceeded:
					bucket.rejected++
				default:
					t.Errorf("organization %q unexpected Reserve error: %v", orgID, err)
				}
			}()
		}
	}
	wg.Wait()

	for orgID, want := range map[string]int{orgA: limitA, orgB: limitB} {
		got := results[orgID]
		if got.succeeded != want {
			t.Errorf("organization %q (limit %d) succeeded reservations = %d, want %d (concurrent reserves under another tenant must not leak into this tenant's count)", orgID, want, got.succeeded, want)
		}
		if got.rejected != attemptsPerOrg-want {
			t.Errorf("organization %q (limit %d) rejected reservations = %d, want %d", orgID, want, got.rejected, attemptsPerOrg-want)
		}
		if active := activeReservationCount(t, db, orgID, "projects"); active != want {
			t.Errorf("organization %q (limit %d) active reservations in the database = %d, want %d", orgID, want, active, want)
		}
	}

	// Defence-in-depth: the two tenants' active reservations MUST sum to
	// the two limits. A regression that flattened cross-tenant counts
	// into one bucket (e.g. dropping the organization predicate from the
	// usage-counter query) would let each per-organization
	// activeReservationCount above still pass while the total silently
	// dropped below limitA+limitB.
	totalA := activeReservationCount(t, db, orgA, "projects")
	totalB := activeReservationCount(t, db, orgB, "projects")
	if totalA+totalB != limitA+limitB {
		t.Errorf("tenant-isolation total active reservations across organizations %q and %q = %d, want %d (the two tenants' counts must sum to the two limits, never collapse into one bucket)", orgA, orgB, totalA+totalB, limitA+limitB)
	}
}

func TestCheckerReserveTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQuotaStore(t, db)
	checker := mustChecker(t)
	ctx := context.Background()

	orgA := seedQuotaOrg(t, db)
	orgB := seedQuotaOrg(t, db)
	seedOrgQuotaPolicy(t, db, orgA, "projects", 1, "hard")
	seedOrgQuotaPolicy(t, db, orgB, "projects", 1, "hard")

	// Organization A exhausts its limit.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgA, "projects")
	}); err != nil {
		t.Fatalf("org A first Reserve: %v", err)
	}
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgA, "projects")
	}); yerr.From(err).Code != yerr.CodeQuotaExceeded {
		t.Fatalf("org A second Reserve code = %v, want %s", yerr.From(err).Code, yerr.CodeQuotaExceeded)
	}

	// Organization B's limit is untouched: its own first reservation succeeds.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return checker.Reserve(ctx, tx, orgB, "projects")
	}); err != nil {
		t.Fatalf("org B Reserve must succeed — A's usage must not leak into B: %v", err)
	}
	if got := activeReservationCount(t, db, orgB, "projects"); got != 1 {
		t.Errorf("org B active reservations = %d, want 1", got)
	}
}

// --- test helpers ---

// mustChecker builds a Checker over a fresh QuotaRepository and the static
// default plan resolver, failing the test on a construction error.
func mustChecker(t *testing.T) *quota.Checker {
	t.Helper()
	checker, err := quota.NewChecker(store.NewQuotaRepository(), quota.StaticPlanResolver(quota.DefaultPlan))
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return checker
}

// newQuotaStore builds a Store over the test database's pool.
func newQuotaStore(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

// seedQuotaOrg inserts an organization with a canonical domain id and returns
// the id.
func seedQuotaOrg(t *testing.T, db *testutil.DB) string {
	t.Helper()
	id := domain.MustNewID(domain.KindOrganization).String()
	slug := "org-" + id[len(id)-12:]
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		id, slug, "Quota Test Organization"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	return id
}

// seedOrgQuotaPolicy inserts an organization-override quota policy with an
// explicit enforcement mode and fails the test on error.
func seedOrgQuotaPolicy(t *testing.T, db *testutil.DB, orgID, resource string, limit int64, mode string) {
	t.Helper()
	id := "qp_" + resource + "_" + orgID[len(orgID)-10:]
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_policies (id, scope_kind, organization_id, resource, limit_value, enforcement_mode)
		 VALUES ($1, 'organization', $2, $3, $4, $5)`,
		id, orgID, resource, limit, mode); err != nil {
		t.Fatalf("seed org quota policy %q: %v", id, err)
	}
}

// activeReservationCount returns the number of active reservations for the
// organization and resource.
func activeReservationCount(t *testing.T, db *testutil.DB, orgID, resource string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(),
		`SELECT count(*) FROM quota_reservations
		  WHERE organization_id = $1 AND resource = $2 AND status = 'active'`,
		orgID, resource).Scan(&n); err != nil {
		t.Fatalf("count active reservations: %v", err)
	}
	return n
}
