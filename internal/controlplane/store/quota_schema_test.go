package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/jackc/pgx/v5/pgconn"
)

// The quota policy schema (migration 0006) is exercised here as an integration
// test: it runs against an isolated, freshly migrated Postgres database and
// skips when YALLA_TEST_DATABASE_URL is unset. The tests prove the database —
// not just the application — enforces the closed set of quota dimensions, the
// plan-default / organization-override scoping of quota_policies, the
// reservation lifecycle, tenant scoping, and cascade behaviour.

// isPgErrorCode reports whether err is a Postgres server error with the given
// five-character SQLSTATE.
func isPgErrorCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == code
}

// seedPlanPolicy inserts a plan-default quota policy and fails the test on error.
func seedPlanPolicy(t *testing.T, db *testutil.DB, id, plan, resource string, limit int64) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value)
		 VALUES ($1, 'plan_default', $2, $3, $4)`,
		id, plan, resource, limit); err != nil {
		t.Fatalf("seed plan policy %q: %v", id, err)
	}
}

// seedOrgPolicy inserts an organization-override quota policy and fails the test on error.
func seedOrgPolicy(t *testing.T, db *testutil.DB, id, orgID, resource string, limit int64) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_policies (id, scope_kind, organization_id, resource, limit_value)
		 VALUES ($1, 'organization', $2, $3, $4)`,
		id, orgID, resource, limit); err != nil {
		t.Fatalf("seed org policy %q: %v", id, err)
	}
}

// seedReservation inserts an active reservation expiring an hour out and fails the test on error.
func seedReservation(t *testing.T, db *testutil.DB, id, orgID, resource string, amount int64) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO quota_reservations (id, organization_id, resource, amount, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, orgID, resource, amount, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("seed reservation %q: %v", id, err)
	}
}

func TestQuotaSchemaTablesExist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	want := []string{"quota_policies", "quota_usage", "quota_reservations", "usage_events"}
	for _, table := range want {
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM information_schema.tables
			   WHERE table_schema = 'public' AND table_name = $1
			 )`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %q: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q does not exist after migration", table)
		}
	}

	// The shared quota dimension and enforcement-mode domains exist too.
	for _, domain := range []string{"quota_resource", "quota_enforcement_mode"} {
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM information_schema.domains
			   WHERE domain_schema = 'public' AND domain_name = $1
			 )`, domain).Scan(&exists); err != nil {
			t.Fatalf("check domain %q: %v", domain, err)
		}
		if !exists {
			t.Errorf("domain %q does not exist after migration", domain)
		}
	}
}

func TestQuotaResourceDomainEnforcesClosedSet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	// Every dimension named by the acceptance criteria is accepted.
	dimensions := []string{
		"projects", "environments", "services", "applications", "compose_stacks",
		"databases", "domains", "preview_environments", "cpu_millicores",
		"memory_mb", "storage_gb", "backups", "backup_schedules", "api_keys",
		"members", "concurrent_deployments", "monthly_deployments", "deployments",
		"failed_deployments", "build_minutes", "http_requests", "http_response_bytes", "http_request_bytes",
		"http_bandwidth_total", "http_rps_peak_1m", "http_5xx_count", "latency_p95_ms", "container_cpu_millicore_seconds", "container_memory_mb_hours",
		"storage_gb_month", "backup_storage_gb_month",
	}
	for i, dim := range dimensions {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_usage (id, organization_id, resource, used_value)
			 VALUES ($1, $2, $3, 0)`,
			"quota_usage_"+dim, org.ID, dim); err != nil {
			t.Errorf("dimension %q (#%d) rejected by quota_resource domain: %v", dim, i, err)
		}
	}

	// An unknown dimension is rejected by the database.
	_, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ('quota_usage_bogus', $1, 'not_a_real_dimension', 0)`, org.ID)
	if err == nil {
		t.Fatal("unknown quota dimension was accepted, want domain check violation")
	}
	if !isConstraintViolation(err) {
		t.Fatalf("unknown quota dimension: err = %v, want constraint violation", err)
	}
}

func TestQuotaPolicyScopeConsistency(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	t.Run("plan default with only a plan is accepted", func(t *testing.T) {
		seedPlanPolicy(t, db, "qp_plan_ok", "starter", "projects", 3)
	})

	t.Run("organization override with only an organization is accepted", func(t *testing.T) {
		seedOrgPolicy(t, db, "qp_org_ok", org.ID, "projects", 10)
	})

	t.Run("plan default carrying an organization_id is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, plan, organization_id, resource, limit_value)
			 VALUES ('qp_bad_1', 'plan_default', 'starter', $1, 'services', 5)`, org.ID)
		if !isConstraintViolation(err) {
			t.Fatalf("plan default with organization_id: err = %v, want constraint violation", err)
		}
	})

	t.Run("organization override carrying a plan is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, plan, organization_id, resource, limit_value)
			 VALUES ('qp_bad_2', 'organization', 'starter', $1, 'services', 5)`, org.ID)
		if !isConstraintViolation(err) {
			t.Fatalf("organization override with plan: err = %v, want constraint violation", err)
		}
	})

	t.Run("plan default with neither identifier is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, resource, limit_value)
			 VALUES ('qp_bad_3', 'plan_default', 'services', 5)`)
		if !isConstraintViolation(err) {
			t.Fatalf("plan default with no plan: err = %v, want constraint violation", err)
		}
	})

	t.Run("a negative limit is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value)
			 VALUES ('qp_bad_4', 'plan_default', 'pro', 'services', -1)`)
		if !isConstraintViolation(err) {
			t.Fatalf("negative limit: err = %v, want constraint violation", err)
		}
	})
}

func TestQuotaPolicyUniquePerScope(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	// A plan default and an organization override for the same resource
	// coexist: the two scopes are independent.
	seedPlanPolicy(t, db, "qp_plan_projects", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects", org.ID, "projects", 25)

	// A second plan default for the same (plan, resource) is rejected.
	_, err := db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, plan, resource, limit_value)
		 VALUES ('qp_plan_projects_dup', 'plan_default', 'starter', 'projects', 9)`)
	if !isConstraintViolation(err) {
		t.Fatalf("duplicate plan default: err = %v, want constraint violation", err)
	}

	// A second organization override for the same (organization, resource) is rejected.
	_, err = db.Exec(ctx,
		`INSERT INTO quota_policies (id, scope_kind, organization_id, resource, limit_value)
		 VALUES ('qp_org_projects_dup', 'organization', $1, 'projects', 99)`, org.ID)
	if !isConstraintViolation(err) {
		t.Fatalf("duplicate organization override: err = %v, want constraint violation", err)
	}

	// The same plan name may set a default for a different resource.
	seedPlanPolicy(t, db, "qp_plan_services", "starter", "services", 5)
}

func TestQuotaReservationLifecycleConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	t.Run("an active reservation without settled_at is accepted", func(t *testing.T) {
		seedReservation(t, db, "qr_active", org.ID, "services", 1)
	})

	t.Run("a settled reservation with settled_at is accepted", func(t *testing.T) {
		if _, err := db.Exec(ctx,
			`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at, settled_at)
			 VALUES ('qr_committed', $1, 'services', 1, 'committed', $2, now())`,
			org.ID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("committed reservation with settled_at: %v", err)
		}
	})

	t.Run("an active reservation carrying settled_at is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at, settled_at)
			 VALUES ('qr_bad_1', $1, 'services', 1, 'active', $2, now())`,
			org.ID, time.Now().Add(time.Hour))
		if !isConstraintViolation(err) {
			t.Fatalf("active reservation with settled_at: err = %v, want constraint violation", err)
		}
	})

	t.Run("a settled reservation missing settled_at is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at)
			 VALUES ('qr_bad_2', $1, 'services', 1, 'released', $2)`,
			org.ID, time.Now().Add(time.Hour))
		if !isConstraintViolation(err) {
			t.Fatalf("released reservation without settled_at: err = %v, want constraint violation", err)
		}
	})

	t.Run("a non-positive reservation amount is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_reservations (id, organization_id, resource, amount, expires_at)
			 VALUES ('qr_bad_3', $1, 'services', 0, $2)`,
			org.ID, time.Now().Add(time.Hour))
		if !isConstraintViolation(err) {
			t.Fatalf("zero reservation amount: err = %v, want constraint violation", err)
		}
	})

	t.Run("an unknown reservation status is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, expires_at, settled_at)
			 VALUES ('qr_bad_4', $1, 'services', 1, 'cancelled', $2, now())`,
			org.ID, time.Now().Add(time.Hour))
		if !isConstraintViolation(err) {
			t.Fatalf("unknown reservation status: err = %v, want constraint violation", err)
		}
	})
}

func TestUsageEventsReservationLinkIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	seedReservation(t, db, "qr_a", orgA.ID, "services", 1)

	// An event in the same organization may reference that organization's reservation.
	if _, err := db.Exec(ctx,
		`INSERT INTO usage_events (id, organization_id, resource, event_type, delta, reservation_id)
		 VALUES ('ue_ok', $1, 'services', 'reserved', 1, 'qr_a')`, orgA.ID); err != nil {
		t.Fatalf("same-tenant reservation reference: %v", err)
	}

	// An event with no reservation link is accepted (the composite FK is MATCH SIMPLE).
	if _, err := db.Exec(ctx,
		`INSERT INTO usage_events (id, organization_id, resource, event_type, delta)
		 VALUES ('ue_no_link', $1, 'services', 'consumed', 1)`, orgA.ID); err != nil {
		t.Fatalf("event without reservation link: %v", err)
	}

	// Organization B cannot reference organization A's reservation.
	_, err := db.Exec(ctx,
		`INSERT INTO usage_events (id, organization_id, resource, event_type, delta, reservation_id)
		 VALUES ('ue_cross', $1, 'services', 'reserved', 1, 'qr_a')`, orgB.ID)
	if !isConstraintViolation(err) {
		t.Fatalf("cross-tenant reservation reference: err = %v, want constraint violation", err)
	}

	// usage_events has no updated_at column — it is append-only.
	var hasUpdatedAt bool
	if err := db.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM information_schema.columns
		   WHERE table_schema = 'public' AND table_name = 'usage_events' AND column_name = 'updated_at'
		 )`).Scan(&hasUpdatedAt); err != nil {
		t.Fatalf("inspect usage_events columns: %v", err)
	}
	if hasUpdatedAt {
		t.Error("usage_events has an updated_at column; it must be append-only")
	}
}

func TestQuotaCascadeDeleteOnOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	// A plan default is not owned by any organization and must survive.
	seedPlanPolicy(t, db, "qp_plan_survivor", "starter", "projects", 3)
	// Org-scoped rows across every quota table.
	seedOrgPolicy(t, db, "qp_org_doomed", org.ID, "projects", 10)
	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ('qu_doomed', $1, 'projects', 2)`, org.ID); err != nil {
		t.Fatalf("seed quota_usage: %v", err)
	}
	seedReservation(t, db, "qr_doomed", org.ID, "projects", 1)
	if _, err := db.Exec(ctx,
		`INSERT INTO usage_events (id, organization_id, resource, event_type, delta, reservation_id)
		 VALUES ('ue_doomed', $1, 'projects', 'reserved', 1, 'qr_doomed')`, org.ID); err != nil {
		t.Fatalf("seed usage_events: %v", err)
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	for _, table := range []string{"quota_policies", "quota_usage", "quota_reservations", "usage_events"} {
		var count int
		if err := db.QueryRow(ctx,
			`SELECT count(*) FROM `+table+` WHERE organization_id = $1`, org.ID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s rows after org delete = %d, want 0", table, count)
		}
	}

	var planPolicies int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_policies WHERE scope_kind = 'plan_default'`).Scan(&planPolicies); err != nil {
		t.Fatalf("count plan policies: %v", err)
	}
	if planPolicies != 1 {
		t.Errorf("plan-default policies after org delete = %d, want 1 (plan defaults are org-independent)", planPolicies)
	}
}

func TestQuotaTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	seedReservation(t, db, "qr_a1", orgA.ID, "services", 1)
	seedReservation(t, db, "qr_a2", orgA.ID, "databases", 1)
	seedReservation(t, db, "qr_b1", orgB.ID, "services", 1)

	var countA, countB int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_reservations WHERE organization_id = $1`, orgA.ID).Scan(&countA); err != nil {
		t.Fatalf("count org A reservations: %v", err)
	}
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_reservations WHERE organization_id = $1`, orgB.ID).Scan(&countB); err != nil {
		t.Fatalf("count org B reservations: %v", err)
	}
	if countA != 2 {
		t.Errorf("org A reservations = %d, want 2", countA)
	}
	if countB != 1 {
		t.Errorf("org B reservations = %d, want 1", countB)
	}
}

// TestQuotaReservationConcurrentRowLock proves the row-level locking primitive
// the quota checker relies on: a transaction that holds SELECT ... FOR UPDATE
// on a tenant's usage counter blocks a concurrent transaction from locking the
// same row, so two units of work can never both decide they have headroom and
// over-allocate. The losing transaction sees SQLSTATE 55P03 (lock_not_available)
// when it asks with NOWAIT, and succeeds once the holder commits.
func TestQuotaReservationConcurrentRowLock(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")

	if _, err := db.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource, used_value)
		 VALUES ('qu_lock', $1, 'concurrent_deployments', 0)`, org.ID); err != nil {
		t.Fatalf("seed quota_usage: %v", err)
	}

	// Transaction 1 claims the counter row.
	tx1, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()

	var locked int64
	if err := tx1.QueryRow(ctx,
		`SELECT used_value FROM quota_usage
		 WHERE organization_id = $1 AND resource = 'concurrent_deployments'
		 FOR UPDATE`, org.ID).Scan(&locked); err != nil {
		t.Fatalf("tx1 lock row: %v", err)
	}

	// Transaction 2 cannot lock the same row while tx1 holds it.
	tx2, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()

	_, lockErr := tx2.Exec(ctx,
		`SELECT used_value FROM quota_usage
		 WHERE organization_id = $1 AND resource = 'concurrent_deployments'
		 FOR UPDATE NOWAIT`, org.ID)
	if lockErr == nil {
		t.Fatal("tx2 acquired a row lock tx1 already holds, want lock_not_available")
	}
	if !isPgErrorCode(lockErr, "55P03") {
		t.Fatalf("tx2 lock error = %v, want SQLSTATE 55P03 (lock_not_available)", lockErr)
	}
	if err := tx2.Rollback(ctx); err != nil {
		t.Fatalf("rollback tx2: %v", err)
	}

	// Once tx1 commits its update, a fresh transaction can lock and read it.
	if _, err := tx1.Exec(ctx,
		`UPDATE quota_usage SET used_value = used_value + 1
		 WHERE organization_id = $1 AND resource = 'concurrent_deployments'`, org.ID); err != nil {
		t.Fatalf("tx1 update row: %v", err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}

	tx3, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx3: %v", err)
	}
	defer func() { _ = tx3.Rollback(ctx) }()

	var got int64
	if err := tx3.QueryRow(ctx,
		`SELECT used_value FROM quota_usage
		 WHERE organization_id = $1 AND resource = 'concurrent_deployments'
		 FOR UPDATE NOWAIT`, org.ID).Scan(&got); err != nil {
		t.Fatalf("tx3 lock row after tx1 commit: %v", err)
	}
	if got != 1 {
		t.Errorf("used_value after committed increment = %d, want 1", got)
	}
}
