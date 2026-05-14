package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// --- pure unit tests: migration loading and validation (no database) ---

func TestLoadMigrationsParsesEmbedded(t *testing.T) {
	t.Parallel()

	migrations, err := LoadMigrations(embeddedMigrations)
	if err != nil {
		t.Fatalf("LoadMigrations(embedded): %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("expected at least one embedded migration")
	}

	// versions must be strictly ascending and unique.
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			t.Fatalf("migrations not strictly ascending at index %d: %d <= %d",
				i, migrations[i].Version, migrations[i-1].Version)
		}
	}

	first := migrations[0]
	if first.Version != 1 || first.Name != "baseline" {
		t.Fatalf("first migration = {%d %q}, want {1 baseline}", first.Version, first.Name)
	}
	if strings.TrimSpace(first.UpSQL) == "" {
		t.Fatal("baseline up SQL is empty")
	}
	if !first.Reversible() {
		t.Fatal("baseline should ship a down script")
	}
	if len(first.Checksum) != 64 {
		t.Fatalf("checksum = %q, want 64 hex chars", first.Checksum)
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	t.Parallel()

	good := "CREATE TABLE t (id int);"

	cases := []struct {
		name  string
		files map[string]string
	}{
		{
			name:  "malformed filename",
			files: map[string]string{"migrations/baseline.sql": good},
		},
		{
			name: "two ups claim the same version",
			files: map[string]string{
				"migrations/0001_a.up.sql": good,
				"migrations/0001_b.up.sql": good,
			},
		},
		{
			name: "down without up",
			files: map[string]string{
				"migrations/0001_a.down.sql": good,
			},
		},
		{
			name: "empty up sql",
			files: map[string]string{
				"migrations/0001_a.up.sql": "   \n\t  ",
			},
		},
		{
			name: "conflicting names for one version",
			files: map[string]string{
				"migrations/0001_a.up.sql":   good,
				"migrations/0001_b.down.sql": good,
			},
		},
		{
			name:  "no migrations at all",
			files: map[string]string{"migrations/.keep": ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fsys := fstest.MapFS{}
			for name, body := range tc.files {
				fsys[name] = &fstest.MapFile{Data: []byte(body)}
			}
			if _, err := LoadMigrations(fsys); err == nil {
				t.Fatalf("LoadMigrations(%s): expected error, got nil", tc.name)
			}
		})
	}
}

func TestLoadMigrationsSuccessFromFixtureFS(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"migrations/0002_second.up.sql":  {Data: []byte("SELECT 2;")},
		"migrations/0001_first.up.sql":   {Data: []byte("SELECT 1;")},
		"migrations/0001_first.down.sql": {Data: []byte("SELECT 10;")},
	}
	migrations, err := LoadMigrations(fsys)
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(migrations) != 2 {
		t.Fatalf("got %d migrations, want 2", len(migrations))
	}
	if migrations[0].Version != 1 || migrations[1].Version != 2 {
		t.Fatalf("migrations not sorted: %d, %d", migrations[0].Version, migrations[1].Version)
	}
	if !migrations[0].Reversible() {
		t.Fatal("version 1 should be reversible")
	}
	if migrations[1].Reversible() {
		t.Fatal("version 2 should not be reversible")
	}
}

func TestNewWithFSRejectsNilPool(t *testing.T) {
	t.Parallel()
	if _, err := NewWithFS(nil, embeddedMigrations, nil); err == nil {
		t.Fatal("NewWithFS(nil pool): expected error")
	}
}

// --- integration tests: run against an isolated Postgres database ---

// testPool provisions a throwaway Postgres database for one test and returns a
// pool connected to it. It skips the test when YALLA_TEST_DATABASE_URL is unset
// so the suite stays green on machines without Postgres. Each test gets its own
// database, so the suite is parallel- and isolation-safe; the database is
// dropped on cleanup.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	adminDSN := strings.TrimSpace(os.Getenv("YALLA_TEST_DATABASE_URL"))
	if adminDSN == "" {
		t.Skip("YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	t.Cleanup(admin.Close)

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("random db name: %v", err)
	}
	dbName := "yalla_migtest_" + hex.EncodeToString(buf[:])
	quoted := pgx.Identifier{dbName}.Sanitize()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)")
	})

	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestMigrationsUpFromEmptyDatabase(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// the ledger records version 1, clean, with the embedded checksum.
	var (
		version  int64
		name     string
		checksum string
		dirty    bool
	)
	row := pool.QueryRow(ctx,
		`SELECT version, name, checksum, dirty FROM schema_migrations ORDER BY version`)
	if err := row.Scan(&version, &name, &checksum, &dirty); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if version != 1 || name != "baseline" || dirty {
		t.Fatalf("ledger row = {%d %q dirty=%v}, want {1 baseline dirty=false}", version, name, dirty)
	}
	if checksum != m.Migrations()[0].Checksum {
		t.Fatalf("recorded checksum %q != embedded checksum %q", checksum, m.Migrations()[0].Checksum)
	}

	// schema_migrations is constrained: version is the primary key.
	var pkCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.table_constraints
		WHERE table_name = 'schema_migrations' AND constraint_type = 'PRIMARY KEY'`).
		Scan(&pkCount); err != nil {
		t.Fatalf("inspect schema_migrations constraints: %v", err)
	}
	if pkCount != 1 {
		t.Fatalf("schema_migrations primary-key constraints = %d, want 1", pkCount)
	}

	// the baseline migration installed its objects: extensions and the trigger.
	assertExtension(t, ctx, pool, "pgcrypto", true)
	assertExtension(t, ctx, pool, "citext", true)
	assertFunction(t, ctx, pool, "set_updated_at", true)
}

func TestMigrationsUpIsIdempotent(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("first Up: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("second Up: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != len(m.Migrations()) {
		t.Fatalf("schema_migrations rows = %d, want %d", count, len(m.Migrations()))
	}

	st, err := m.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Pending) != 0 {
		t.Fatalf("pending = %d, want 0", len(st.Pending))
	}
	wantCurrent := m.Migrations()[len(m.Migrations())-1].Version
	if st.Current != wantCurrent || st.Dirty {
		t.Fatalf("status = {current:%d dirty:%v}, want {current:%d dirty:false}", st.Current, st.Dirty, wantCurrent)
	}
}

func TestMigrationsRefusesDirtyDatabase(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET dirty = true WHERE version = 1`); err != nil {
		t.Fatalf("mark dirty: %v", err)
	}

	err = m.Up(ctx)
	if !errors.Is(err, ErrDirtyDatabase) {
		t.Fatalf("Up against dirty db: err = %v, want ErrDirtyDatabase", err)
	}
}

func TestMigrationsRefusesUnknownVersion(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, dirty) VALUES (999999, 'from_the_future', 'deadbeef', false)`); err != nil {
		t.Fatalf("insert unknown version: %v", err)
	}

	err = m.Up(ctx)
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("Up against unknown version: err = %v, want ErrUnknownVersion", err)
	}
}

func TestMigrationsRefusesChecksumMismatch(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatalf("tamper checksum: %v", err)
	}

	err = m.Up(ctx)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Up against tampered checksum: err = %v, want ErrChecksumMismatch", err)
	}
}

func TestMigrationsDownIsReversible(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(ctx, 0); err != nil {
		t.Fatalf("Down to 0: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 0 {
		t.Fatalf("schema_migrations rows after Down = %d, want 0", count)
	}
	assertFunction(t, ctx, pool, "set_updated_at", false)

	// the database is migratable again after a full rollback.
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	assertFunction(t, ctx, pool, "set_updated_at", true)
}

func TestMigrationsFailedMigrationRollsBackCleanly(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	// a fixture FS whose only migration contains invalid SQL.
	fsys := fstest.MapFS{
		"migrations/0001_broken.up.sql": {Data: []byte("CREATE TABLE bad (;")},
	}
	m, err := NewWithFS(pool, fsys, nil)
	if err != nil {
		t.Fatalf("NewWithFS: %v", err)
	}

	if err := m.Up(ctx); err == nil {
		t.Fatal("Up with broken migration: expected error, got nil")
	}

	// the failed migration left no ledger row — not even a dirty one — because
	// the whole transaction rolled back.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 0 {
		t.Fatalf("schema_migrations rows after failed Up = %d, want 0", count)
	}
}

func TestStatusReportsPendingMigrations(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st, err := m.Status(ctx)
	if err != nil {
		t.Fatalf("Status before Up: %v", err)
	}
	if len(st.Pending) != len(m.Migrations()) {
		t.Fatalf("pending before Up = %d, want %d", len(st.Pending), len(m.Migrations()))
	}
	if st.Current != 0 || len(st.Applied) != 0 {
		t.Fatalf("status before Up = {current:%d applied:%d}, want {0 0}", st.Current, len(st.Applied))
	}

	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	st, err = m.Status(ctx)
	if err != nil {
		t.Fatalf("Status after Up: %v", err)
	}
	if len(st.Pending) != 0 {
		t.Fatalf("pending after Up = %d, want 0", len(st.Pending))
	}
	if len(st.Applied) != len(m.Migrations()) {
		t.Fatalf("applied after Up = %d, want %d", len(st.Applied), len(m.Migrations()))
	}
	if st.Applied[0].AppliedAt.IsZero() || st.Applied[0].AppliedAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("applied_at looks wrong: %v", st.Applied[0].AppliedAt)
	}
}

// --- integration test helpers ---

func assertExtension(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("check extension %q: %v", name, err)
	}
	if exists != want {
		t.Fatalf("extension %q exists = %v, want %v", name, exists, want)
	}
}

func assertFunction(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("check function %q: %v", name, err)
	}
	if exists != want {
		t.Fatalf("function %q exists = %v, want %v", name, exists, want)
	}
}
