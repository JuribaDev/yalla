package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/jackc/pgx/v5/pgconn"
)

// The optimistic-concurrency schema (migration 0011) is exercised here as an
// integration test: it runs against an isolated, freshly migrated Postgres
// database and skips when YALLA_TEST_DATABASE_URL is unset. The tests prove
// every mutable customer-data table carries the version column the API layer
// requires for If-Match preconditions, that the column starts at 1 on INSERT,
// is bumped by the bump_version trigger on every UPDATE (even a no-op data
// change), and that the schema CHECK refuses a non-positive version so a "0"
// sentinel can never accidentally match a real row.

// TestOptimisticVersionColumnExistsAndDefaultsToOne proves every mutable
// customer-data table carries a version column with a default of 1, so a
// freshly inserted row is immediately addressable via If-Match without an
// extra read.
func TestOptimisticVersionColumnExistsAndDefaultsToOne(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "acme-co")
	proj := seedProject(t, db, f, org, "billing")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	cases := []struct {
		table string
		query string
		args  []any
	}{
		{"organizations", `SELECT version FROM organizations WHERE id = $1`, []any{org.ID}},
		{"projects", `SELECT version FROM projects WHERE id = $1`, []any{proj.ID}},
		{"environments", `SELECT version FROM environments WHERE id = $1`, []any{env.ID}},
		{"services", `SELECT version FROM services WHERE id = $1`, []any{svc.ID}},
	}
	for _, tc := range cases {
		var v int64
		if err := db.QueryRow(ctx, tc.query, tc.args...).Scan(&v); err != nil {
			t.Fatalf("read %s.version: %v", tc.table, err)
		}
		if v != 1 {
			t.Errorf("%s.version after INSERT = %d, want 1", tc.table, v)
		}
	}
}

// TestOptimisticVersionTriggerBumpsOnEveryUpdate proves the bump_version
// trigger fires on every UPDATE — including a no-op data UPDATE that
// rewrites a column to its current value. A no-op UPDATE in the same
// transaction as a real one would otherwise advance the row's observable
// state without advancing the version, defeating the precondition check.
func TestOptimisticVersionTriggerBumpsOnEveryUpdate(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "acme-co")

	if _, err := db.Exec(ctx,
		`UPDATE organizations SET display_name = $2 WHERE id = $1`,
		org.ID, "Acme Worldwide"); err != nil {
		t.Fatalf("first UPDATE: %v", err)
	}
	var v1 int64
	if err := db.QueryRow(ctx,
		`SELECT version FROM organizations WHERE id = $1`, org.ID).Scan(&v1); err != nil {
		t.Fatalf("read version after first UPDATE: %v", err)
	}
	if v1 != 2 {
		t.Errorf("version after first UPDATE = %d, want 2", v1)
	}

	// Re-writing the same value still bumps the version: the trigger fires
	// per-statement, regardless of whether NEW differs from OLD.
	if _, err := db.Exec(ctx,
		`UPDATE organizations SET display_name = display_name WHERE id = $1`,
		org.ID); err != nil {
		t.Fatalf("no-op UPDATE: %v", err)
	}
	var v2 int64
	if err := db.QueryRow(ctx,
		`SELECT version FROM organizations WHERE id = $1`, org.ID).Scan(&v2); err != nil {
		t.Fatalf("read version after no-op UPDATE: %v", err)
	}
	if v2 != 3 {
		t.Errorf("version after no-op UPDATE = %d, want 3", v2)
	}
}

// TestOptimisticVersionRejectsNonPositiveInsert proves the schema CHECK
// refuses a non-positive version on INSERT — a manual fixture or a
// bypassed-repository code path cannot create a row at "version 0" that
// would silently match every If-Match header. (UPDATEs cannot violate the
// CHECK because the bump_version trigger overrides NEW.version with
// OLD.version+1, so an UPDATE attempting `SET version = 0` ends up at a
// strictly-positive value before the constraint is evaluated.)
func TestOptimisticVersionRejectsNonPositiveInsert(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := f.Organization("acme-co")
	_, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, version) VALUES ($1, $2, $3, 0)`,
		org.ID, org.Slug, org.Name)
	if !isCheckViolation(err) {
		t.Fatalf("INSERT version=0: err = %v, want a check_violation", err)
	}
}

// TestOptimisticVersionTriggerOverridesCallerSuppliedVersion proves the
// bump_version trigger ignores any caller-supplied version on UPDATE: the
// new value is always OLD.version+1, regardless of what the SET clause
// names. This guarantees an application that forgets — or maliciously
// rewrites — the version cannot freeze the row's monotonic sequence.
func TestOptimisticVersionTriggerOverridesCallerSuppliedVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "acme-co")

	if _, err := db.Exec(ctx,
		`UPDATE organizations SET version = 999 WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("UPDATE version=999: %v", err)
	}
	var v int64
	if err := db.QueryRow(ctx,
		`SELECT version FROM organizations WHERE id = $1`, org.ID).Scan(&v); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if v != 2 {
		t.Errorf("version after UPDATE SET version=999 = %d, want 2 (the trigger must override caller-supplied values)", v)
	}
}

// TestOptimisticVersionStoreOrganizationRoundTrip proves the store layer
// scans the new version column and exposes it on the returned row, so the
// HTTP layer can mirror it into ETag/If-Match without a second query.
func TestOptimisticVersionStoreOrganizationRoundTrip(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	org := seedOrg(t, db, f, "acme-co")

	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	got, err := reader.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("GetOrganization Version = %d, want 1 for a freshly inserted row", got.Version)
	}
}

// isCheckViolation reports whether err is a Postgres check_violation.
func isCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	// 23514 — check_violation (Class 23, Integrity Constraint Violation).
	return pgErr.Code == "23514"
}
