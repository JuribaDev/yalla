package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminConfigSchemaCreatesSetsAndVersions(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	effectiveAt := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	if _, err := db.Exec(ctx,
		`INSERT INTO admin_config_sets (id, slug, domain, name)
		 VALUES ('cfg_test_pricing', 'pricing-runtime', 'pricing', 'Pricing Runtime')`,
	); err != nil {
		t.Fatalf("insert admin_config_sets: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO admin_config_versions
		    (id, config_set_id, version, status, payload, effective_at, published_at, published_by)
		 VALUES
		    ('cfgver_test_pricing_v1', 'cfg_test_pricing', 1, 'published', '{"plans": []}'::jsonb, $1, $1, 'usr_admin')`,
		effectiveAt,
	); err != nil {
		t.Fatalf("insert admin_config_versions: %v", err)
	}

	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*)
		   FROM admin_config_versions
		  WHERE config_set_id = 'cfg_test_pricing'
		    AND status = 'published'
		    AND effective_at = $1`,
		effectiveAt,
	).Scan(&count); err != nil {
		t.Fatalf("read inserted published version: %v", err)
	}
	if count != 1 {
		t.Fatalf("published version count = %d, want 1", count)
	}
}

func TestAdminConfigSchemaConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	_, err := db.Exec(ctx,
		`INSERT INTO admin_config_sets (id, slug, domain, name)
		 VALUES ('cfg_bad_domain', 'bad-domain', 'unknown', 'Bad Domain')`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid admin_config_sets.domain err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO admin_config_sets (id, slug, domain, name)
		 VALUES ('cfg_test_features', 'features-runtime', 'features', 'Features Runtime')`,
	)
	if err != nil {
		t.Fatalf("insert admin config set: %v", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO admin_config_versions (id, config_set_id, version, status, payload)
		 VALUES ('cfgver_bad_status', 'cfg_test_features', 1, 'enabled', '{}'::jsonb)`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("invalid admin_config_versions.status err = %v, want constraint violation", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO admin_config_versions
		    (id, config_set_id, version, status, payload, published_at, published_by)
		 VALUES ('cfgver_bad_publish', 'cfg_test_features', 1, 'published', '{}'::jsonb, now(), 'usr_admin')`,
	)
	if !isConstraintViolation(err) {
		t.Fatalf("published version without effective_at err = %v, want constraint violation", err)
	}
}
