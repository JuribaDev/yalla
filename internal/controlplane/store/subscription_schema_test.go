package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestSubscriptionSchemaConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "subscription-schema")
	otherOrg := seedOrg(t, db, f, "subscription-schema-other")
	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)

	if _, err := db.Exec(ctx,
		`INSERT INTO subscriptions
		    (id, organization_id, plan_id, status, current_period_start, current_period_end)
		 VALUES ('sub_schema_active', $1, 'plan_starter_monthly_v1', 'active', $2, $3)`,
		org.ID, now.Add(-time.Hour), now.Add(time.Hour),
	); err != nil {
		t.Fatalf("seed active subscription: %v", err)
	}

	_, err := db.Exec(ctx,
		`INSERT INTO subscriptions
		    (id, organization_id, plan_id, status, current_period_start, current_period_end)
		 VALUES ('sub_schema_second_active', $1, 'plan_pro_monthly_v1', 'active', $2, $3)`,
		org.ID, now.Add(-time.Hour), now.Add(time.Hour),
	)
	if !isConstraintViolation(err) {
		t.Fatalf("second current subscription err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO subscriptions
		    (id, organization_id, plan_id, status, current_period_start, current_period_end)
		 VALUES ('sub_schema_bad_status', $1, 'plan_pro_monthly_v1', 'paused', $2, $3)`,
		otherOrg.ID, now.Add(-time.Hour), now.Add(time.Hour),
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid subscription status err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO subscription_entitlements
		    (id, organization_id, subscription_id, source, entitlement_key, limit_value, enforcement_mode,
		     reason, actor_id, actor_kind, request_id, correlation_id, effective_from)
		 VALUES ('sent_schema_bad_source', $1, NULL, 'subscription_override', 'projects', 10, 'hard',
		         'reason', 'usr_test', 'user', 'req_test', 'corr_test', $2)`,
		org.ID, now,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("subscription override without subscription err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO subscription_entitlements
		    (id, organization_id, subscription_id, source, entitlement_key, limit_value, enforcement_mode,
		     reason, actor_id, actor_kind, request_id, correlation_id, effective_from)
		 VALUES ('sent_schema_cross_tenant', $1, 'sub_schema_active', 'subscription_override', 'projects', 10, 'hard',
		         'reason', 'usr_test', 'user', 'req_test', 'corr_test', $2)`,
		otherOrg.ID, now,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("cross-tenant subscription entitlement err = %v, want constraint violation", err)
	}
}
