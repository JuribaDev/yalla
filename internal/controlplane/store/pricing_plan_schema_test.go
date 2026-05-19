package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestPricingPlanSchemaSeedsDefaultPackages(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	want := []struct {
		slug         string
		name         string
		displayOrder int
	}{
		{"starter", "Starter", 10},
		{"pro", "Pro", 20},
		{"business", "Business", 30},
		{"enterprise", "Enterprise", 40},
	}
	for _, row := range want {
		var (
			name         string
			status       string
			period       string
			displayOrder int
			version      int
		)
		if err := db.QueryRow(ctx,
			`SELECT name, status, billing_period, display_order, version
			   FROM plans
			  WHERE slug = $1`,
			row.slug,
		).Scan(&name, &status, &period, &displayOrder, &version); err != nil {
			t.Fatalf("seeded plan %q: %v", row.slug, err)
		}
		if name != row.name || status != "active" || period != "monthly" || displayOrder != row.displayOrder || version != 1 {
			t.Errorf("plan %q = {name:%q status:%q period:%q order:%d version:%d}, want {%q active monthly %d 1}",
				row.slug, name, status, period, displayOrder, version, row.name, row.displayOrder)
		}
	}

	var modes []string
	rows, err := db.Query(ctx,
		`SELECT DISTINCT enforcement_mode
		   FROM plan_entitlements
		  ORDER BY enforcement_mode`,
	)
	if err != nil {
		t.Fatalf("read seeded entitlement modes: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mode string
		if err := rows.Scan(&mode); err != nil {
			t.Fatalf("scan entitlement mode: %v", err)
		}
		modes = append(modes, mode)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("entitlement modes rows: %v", err)
	}
	got := map[string]bool{}
	for _, mode := range modes {
		got[mode] = true
	}
	for _, mode := range []string{"hard", "soft", "metered", "disabled"} {
		if !got[mode] {
			t.Errorf("seeded plan_entitlements missing enforcement_mode %q; got %v", mode, modes)
		}
	}
}

func TestPricingPlanSchemaConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	_, err := db.Exec(ctx,
		`INSERT INTO plans (id, slug, name, status, billing_period, display_order, version)
		 VALUES ('plan_bad_status', 'badstatus', 'Bad Status', 'launched', 'monthly', 1, 1)`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid plan status err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO plans (id, slug, name, status, billing_period, display_order, version)
		 VALUES ('plan_bad_period', 'badperiod', 'Bad Period', 'active', 'weekly', 1, 1)`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid billing period err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO plan_entitlements (id, plan_id, entitlement_key, limit_value, enforcement_mode)
		 VALUES ('pent_bad_mode', 'plan_starter_monthly_v1', 'bad_mode', 1, 'sometimes')`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid entitlement enforcement mode err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO plans (id, slug, name, status, billing_period, display_order, version)
		 VALUES ('plan_starter_monthly_v2_duplicate_active', 'starter', 'Starter Again', 'active', 'monthly', 11, 2)`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("second active starter monthly err = %v, want constraint violation", err)
	}
}
