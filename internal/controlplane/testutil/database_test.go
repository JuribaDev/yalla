package testutil_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These are integration tests: they provision a real Postgres database via
// testutil.RequireDB and skip cleanly when YALLA_TEST_DATABASE_URL is unset, so
// `go test ./...` stays green without Postgres.

func TestRequireDBProvidesIsolatedDatabases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	db1 := testutil.RequireDB(t)
	db2 := testutil.RequireDB(t)

	if db1.Name == db2.Name {
		t.Fatalf("two RequireDB calls returned the same database %q", db1.Name)
	}

	// A table created in db1 must be invisible from db2 — separate databases.
	if _, err := db1.Exec(ctx, `CREATE TABLE only_in_db1 (id int PRIMARY KEY)`); err != nil {
		t.Fatalf("create table in db1: %v", err)
	}
	var visibleInDB2 bool
	if err := db2.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables WHERE table_name = 'only_in_db1'
		)`).Scan(&visibleInDB2); err != nil {
		t.Fatalf("inspect db2: %v", err)
	}
	if visibleInDB2 {
		t.Fatal("db2 can observe a table created in db1 — databases are not isolated")
	}
}

func TestRequireDBIsParallelSafe(t *testing.T) {
	t.Parallel()

	// Every worker creates an identically-named table and inserts the same row.
	// That is only safe because each worker has its own isolated database.
	for i := 0; i < 8; i++ {
		t.Run(fmt.Sprintf("worker-%d", i), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := testutil.RequireDB(t)
			if _, err := db.Exec(ctx, `CREATE TABLE shared_name (id int PRIMARY KEY)`); err != nil {
				t.Fatalf("create table: %v", err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO shared_name (id) VALUES (1)`); err != nil {
				t.Fatalf("insert row: %v", err)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM shared_name`).Scan(&count); err != nil {
				t.Fatalf("count rows: %v", err)
			}
			if count != 1 {
				t.Fatalf("row count = %d, want 1 (cross-test contamination?)", count)
			}
		})
	}
}

func TestRequireDBDropsDatabaseOnCleanup(t *testing.T) {
	t.Parallel()

	adminDSN := strings.TrimSpace(os.Getenv(testutil.EnvDatabaseURL))
	if adminDSN == "" {
		t.Skip(testutil.SkipReason)
	}

	var dbName string
	// The inner subtest's cleanups run before t.Run returns (it is not
	// parallel), so by the time we inspect, the database must already be gone.
	t.Run("provision-then-clean-up", func(t *testing.T) {
		db := testutil.RequireDB(t)
		dbName = db.Name
	})
	if dbName == "" {
		t.Fatal("inner subtest did not provision a database")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	defer admin.Close()

	var stillExists bool
	if err := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).
		Scan(&stillExists); err != nil {
		t.Fatalf("inspect pg_database: %v", err)
	}
	if stillExists {
		t.Fatalf("database %q was not dropped on test cleanup", dbName)
	}
}

func TestRequireMigratedDBAppliesMigrations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	db := testutil.RequireMigratedDB(t)

	// The schema_migrations ledger records at least the baseline migration,
	// cleanly applied.
	var current int64
	if err := db.QueryRow(ctx,
		`SELECT coalesce(max(version), 0) FROM schema_migrations WHERE NOT dirty`).
		Scan(&current); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if current < 1 {
		t.Fatalf("current migration version = %d, want >= 1", current)
	}

	// The baseline migration installs the pgcrypto extension; its presence
	// proves RequireMigratedDB actually ran the embedded migrations.
	var hasPgcrypto bool
	if err := db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto')`).
		Scan(&hasPgcrypto); err != nil {
		t.Fatalf("check pgcrypto extension: %v", err)
	}
	if !hasPgcrypto {
		t.Fatal("RequireMigratedDB did not apply the baseline migration (pgcrypto missing)")
	}
}

func TestRequireMigratedDBIsIsolatedPerTest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	a := testutil.RequireMigratedDB(t)
	b := testutil.RequireMigratedDB(t)
	if a.Name == b.Name {
		t.Fatalf("two RequireMigratedDB calls shared database %q", a.Name)
	}

	// Seed a domain-shaped table in one database; the other must not see it.
	if _, err := a.Exec(ctx, `CREATE TABLE seeded_in_a (id int PRIMARY KEY)`); err != nil {
		t.Fatalf("seed database a: %v", err)
	}
	var leaked bool
	if err := b.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables WHERE table_name = 'seeded_in_a'
		)`).Scan(&leaked); err != nil {
		t.Fatalf("inspect database b: %v", err)
	}
	if leaked {
		t.Fatal("a migrated database observed another test's seeded table")
	}
}
