package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
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

// --- BE-0389 canonical pair: migration tests from empty DB ---
//
// These two tests are the canonical pair the PRD's
// `go test -run TestMigrationsEmptyDB ./...` filter binds to. They pin the
// two load-bearing invariants the migration runner owes any operator who
// boots a fresh Yalla control-plane database:
//
//  1. TestMigrationsEmptyDBContractCoversAllNumberedFiles — the closed-set
//     coverage invariant. Every numbered `NNNN_*.up.sql` file in the
//     embedded migrations directory MUST surface as a loaded Migration with
//     a strictly ascending, gap-free version starting at 1 and a non-empty
//     checksum. A new migration file added without re-running the loader
//     (or a `0NNN_baseline.up.sql` accidentally renamed to a non-numbered
//     form) trips this gate at the package-internal API with no Postgres
//     dependency, so the regression surfaces on every developer machine.
//  2. TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase —
//     the empty-DB applies-cleanly invariant. A throwaway database (created
//     by `testPool` when `YALLA_TEST_DATABASE_URL` is set; skipped
//     otherwise) MUST accept every embedded migration in order, leave the
//     schema_migrations ledger with one clean row per migration, the
//     correct embedded checksum, dirty=false on every row, and an
//     idempotent second `Up` that adds nothing. A real regression — a
//     migration that fails on an empty database, leaks a partial row, or
//     skips ahead — surfaces with the offending migration version AND
//     resource identifier (`schema_migrations` row reference) so the
//     operator can map the failure to the exact migration without
//     re-running the suite locally.

// migrationFilenamePattern mirrors the loader's filename grammar (see
// LoadMigrations in migrate.go). The canonical-coverage test reads the
// embedded FS through this pattern so a future filename-grammar change in
// the loader is mirrored here in the same edit.
var migrationFilenamePattern = regexp.MustCompile(`^(\d{4,})_([a-z0-9_]+)\.(up|down)\.sql$`)

// TestMigrationsEmptyDBContractCoversAllNumberedFiles pins the closed-set
// coverage invariant: every `NNNN_*.up.sql` file embedded in the binary
// MUST surface as a loaded Migration, the versions MUST be strictly
// ascending and gap-free starting at 1, and every loaded migration MUST
// carry a non-empty up SQL body and a 64-character sha256 hex checksum.
//
// No live Postgres is required: this is a deterministic, sandbox-only
// invariant that runs on every developer machine and on every CI runner.
func TestMigrationsEmptyDBContractCoversAllNumberedFiles(t *testing.T) {
	t.Parallel()

	entries, err := fs.ReadDir(embeddedMigrations, migrationsDir)
	if err != nil {
		t.Fatalf("read embedded migrations dir %q: %v", migrationsDir, err)
	}

	// fileVersions collects the version numbers parsed from every
	// well-formed `NNNN_*.up.sql` filename in the embedded directory.
	// We assert below that this set matches the loaded migration set
	// exactly — any drift (a file added without re-running the loader,
	// a numbered file accidentally renamed to a non-numbered form, a
	// duplicate version across two filenames) is a closed-set coverage
	// regression and trips this gate with the offending filename
	// reported as the failure context.
	type fileRef struct {
		version  int64
		name     string
		filename string
	}
	var ups []fileRef
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		matches := migrationFilenamePattern.FindStringSubmatch(e.Name())
		if matches == nil {
			// The loader is the authority on filename grammar; any file
			// that does not match the pattern would trip
			// LoadMigrations validation. We mirror the loader here so a
			// future grammar change (e.g. a permissive `.sql` form)
			// reaches both sides in the same edit.
			t.Errorf("embedded migrations contain non-conforming file %q; the loader's filename grammar is `NNNN_name.{up,down}.sql` — re-run the loader fixtures if this is intentional",
				e.Name())
			continue
		}
		if matches[3] != "up" {
			continue
		}
		v, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			t.Errorf("embedded migration %q has unparseable version %q: %v",
				e.Name(), matches[1], err)
			continue
		}
		ups = append(ups, fileRef{version: v, name: matches[2], filename: e.Name()})
	}
	if len(ups) == 0 {
		t.Fatal("embedded migrations directory contains no `NNNN_*.up.sql` files; the closed-set coverage gate has nothing to bind to — the embed glob in migrate.go has drifted")
	}

	sort.Slice(ups, func(i, j int) bool { return ups[i].version < ups[j].version })

	// Strictly ascending, gap-free, starting at 1. A gap is a deployment
	// hazard — the ledger uses version as the primary key and an
	// operator inspecting the ladder must be able to assume contiguous
	// versions.
	for i, ref := range ups {
		want := int64(i + 1)
		if ref.version != want {
			t.Errorf("embedded migrations contain a version gap at index %d: file %q has version %d, want %d (strictly ascending, gap-free, starting at 1)",
				i, ref.filename, ref.version, want)
		}
	}

	loaded, err := LoadMigrations(embeddedMigrations)
	if err != nil {
		t.Fatalf("LoadMigrations(embedded): %v", err)
	}
	if len(loaded) != len(ups) {
		t.Fatalf("loaded migrations = %d, want %d (every `NNNN_*.up.sql` file MUST become a loaded Migration; mismatch indicates a loader or embed-glob regression)",
			len(loaded), len(ups))
	}
	for i, m := range loaded {
		ref := ups[i]
		if m.Version != ref.version {
			t.Errorf("loaded[%d].Version = %d, want %d (file %q); resource_id schema_migrations.version=%d",
				i, m.Version, ref.version, ref.filename, ref.version)
		}
		if m.Name != ref.name {
			t.Errorf("loaded[%d].Name = %q, want %q (file %q)",
				i, m.Name, ref.name, ref.filename)
		}
		if strings.TrimSpace(m.UpSQL) == "" {
			t.Errorf("loaded[%d] (file %q) has empty up SQL; an empty migration is a closed-set coverage regression — operators booting from empty would silently skip this version",
				i, ref.filename)
		}
		if len(m.Checksum) != 64 {
			t.Errorf("loaded[%d] (file %q) checksum = %q, want 64 hex chars",
				i, ref.filename, m.Checksum)
		}
	}
}

// TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase pins
// the empty-DB applies-cleanly invariant: the embedded migration ladder
// MUST apply to an empty Postgres database from version 0 through to the
// last embedded version, leaving the schema_migrations ledger with one
// clean row per migration, the correct embedded checksum, dirty=false on
// every row, and an idempotent second `Up` that adds nothing.
//
// Failures surface with the offending migration version AND the
// resource_id (schema_migrations row reference) so the operator can map
// the failure to the exact migration without re-running the suite
// locally. The test skips when `YALLA_TEST_DATABASE_URL` is unset so the
// suite stays green on machines without Postgres; CI sets the env var.
func TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := m.Migrations()
	if len(want) == 0 {
		t.Fatal("no embedded migrations; the empty-DB applies-cleanly gate has nothing to bind to")
	}

	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up(empty-db): %v", err)
	}

	// Read the ledger back in version-ascending order and assert the
	// closed-set match: same length, same versions in order, same
	// checksums, dirty=false on every row, and a non-zero applied_at
	// that is not in the future.
	rows, err := pool.Query(ctx,
		`SELECT version, name, checksum, applied_at, dirty FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	defer rows.Close()

	type ledgerRow struct {
		version   int64
		name      string
		checksum  string
		appliedAt time.Time
		dirty     bool
	}
	var got []ledgerRow
	for rows.Next() {
		var r ledgerRow
		if err := rows.Scan(&r.version, &r.name, &r.checksum, &r.appliedAt, &r.dirty); err != nil {
			t.Fatalf("scan schema_migrations row: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("schema_migrations rows = %d, want %d (every embedded migration MUST land in the ledger after a clean empty-DB Up)",
			len(got), len(want))
	}
	soon := time.Now().Add(time.Minute)
	for i, r := range got {
		w := want[i]
		// resource_id: schema_migrations.version is the row identifier
		// an operator can grep the failure for.
		resourceID := "schema_migrations.version=" + strconv.FormatInt(r.version, 10)
		if r.version != w.Version {
			t.Errorf("ledger row %d: version = %d, want %d (resource_id %s)", i, r.version, w.Version, resourceID)
		}
		if r.name != w.Name {
			t.Errorf("ledger row %d: name = %q, want %q (resource_id %s)", i, r.name, w.Name, resourceID)
		}
		if r.checksum != w.Checksum {
			t.Errorf("ledger row %d: checksum = %q, want %q (resource_id %s) — a checksum mismatch on an empty-DB Up indicates the loader or embed glob drifted from the on-disk migration file",
				i, r.checksum, w.Checksum, resourceID)
		}
		if r.dirty {
			t.Errorf("ledger row %d: dirty = true, want false (resource_id %s) — a dirty row after an empty-DB Up means a migration started but did not finish; the transaction-per-migration contract was broken",
				i, resourceID)
		}
		if r.appliedAt.IsZero() || r.appliedAt.After(soon) {
			t.Errorf("ledger row %d: applied_at = %v, want a recent past timestamp (resource_id %s)",
				i, r.appliedAt, resourceID)
		}
	}

	// Second Up is a no-op (idempotency) — the ledger row count MUST
	// stay equal to the embedded migration count.
	if err := m.Up(ctx); err != nil {
		t.Fatalf("second Up after empty-DB ladder: %v", err)
	}
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rowCount); err != nil {
		t.Fatalf("count schema_migrations after second Up: %v", err)
	}
	if rowCount != len(want) {
		t.Fatalf("schema_migrations rows after second Up = %d, want %d (Up MUST be idempotent on a fully-applied empty-DB ladder)",
			rowCount, len(want))
	}

	// Status reports zero pending, current = last embedded version,
	// dirty = false.
	st, err := m.Status(ctx)
	if err != nil {
		t.Fatalf("Status after empty-DB Up: %v", err)
	}
	if len(st.Pending) != 0 {
		t.Errorf("Status.Pending = %d, want 0", len(st.Pending))
	}
	if st.Dirty {
		t.Errorf("Status.Dirty = true, want false")
	}
	wantCurrent := want[len(want)-1].Version
	if st.Current != wantCurrent {
		t.Errorf("Status.Current = %d, want %d (resource_id schema_migrations.version=%d)", st.Current, wantCurrent, wantCurrent)
	}
}

// --- BE-0390 canonical pair: migration downgrade safety ---
//
// These two tests are the canonical pair the PRD's
// `go test -run TestMigrationsDowngradeSafety ./...` filter binds to.
// They pin the two load-bearing invariants the migration runner owes any
// operator who must roll a control-plane database back to recover from a
// botched deploy:
//
//  1. TestMigrationsDowngradeSafetyContractCoversAllDownFiles — the
//     closed-set reversibility invariant. Every numbered
//     `NNNN_*.up.sql` file in the embedded migrations directory MUST
//     ship with a matching `NNNN_*.down.sql` file with the same
//     version+name, a non-empty body, and no orphan `.down.sql` files
//     for a version that has no `.up.sql`. A new migration committed
//     without a down script — or a down script accidentally renamed,
//     deleted, or version-mismatched — trips this gate at the
//     package-internal API with no Postgres dependency, so the
//     regression surfaces on every developer machine. Without this
//     invariant `Migrator.Down(ctx, 0)` returns ErrIrreversible mid-way
//     through a rollback, leaving the ledger in an indeterminate state.
//  2. TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder —
//     the empty-DB round-trip invariant. A throwaway database (created
//     by `testPool` when `YALLA_TEST_DATABASE_URL` is set; skipped
//     otherwise) MUST accept the full embedded ladder, then accept a
//     Down to version 0 (the ledger MUST become empty), then accept Up
//     a second time and end up in the same fully-applied state with
//     identical checksums. Failures surface with the offending
//     migration version AND resource_id (`schema_migrations.version=N`)
//     so an operator can map the failure to the exact migration
//     without re-running the suite locally. The test skips when
//     `YALLA_TEST_DATABASE_URL` is unset so the suite stays green on
//     machines without Postgres; CI sets the env var.

// TestMigrationsDowngradeSafetyContractCoversAllDownFiles pins the
// closed-set reversibility invariant: every `NNNN_*.up.sql` file
// embedded in the binary MUST ship with a matching
// `NNNN_*.down.sql` file (same version, same name slug), every
// embedded `.down.sql` MUST correspond to an existing `.up.sql`, and
// every loaded Migration with a recorded version MUST carry a
// non-empty DownSQL body. The matcher walks the embedded directory
// through the same filename grammar the loader uses and cross-checks
// the parsed set against LoadMigrations so a drift between filename
// presence and loader-recognised reversibility is caught in the same
// edit.
//
// No live Postgres is required: this is a deterministic, sandbox-only
// invariant that runs on every developer machine and on every CI
// runner.
func TestMigrationsDowngradeSafetyContractCoversAllDownFiles(t *testing.T) {
	t.Parallel()

	entries, err := fs.ReadDir(embeddedMigrations, migrationsDir)
	if err != nil {
		t.Fatalf("read embedded migrations dir %q: %v", migrationsDir, err)
	}

	type fileRef struct {
		version  int64
		name     string
		filename string
		body     string
	}
	ups := map[int64]fileRef{}
	downs := map[int64]fileRef{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		matches := migrationFilenamePattern.FindStringSubmatch(e.Name())
		if matches == nil {
			t.Errorf("embedded migrations contain non-conforming file %q; the loader's filename grammar is `NNNN_name.{up,down}.sql` — re-run the loader fixtures if this is intentional",
				e.Name())
			continue
		}
		v, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			t.Errorf("embedded migration %q has unparseable version %q: %v",
				e.Name(), matches[1], err)
			continue
		}
		body, err := fs.ReadFile(embeddedMigrations, migrationsDir+"/"+e.Name())
		if err != nil {
			t.Errorf("read embedded migration %q: %v", e.Name(), err)
			continue
		}
		ref := fileRef{version: v, name: matches[2], filename: e.Name(), body: string(body)}
		switch matches[3] {
		case "up":
			ups[v] = ref
		case "down":
			downs[v] = ref
		}
	}
	if len(ups) == 0 {
		t.Fatal("embedded migrations directory contains no `NNNN_*.up.sql` files; the downgrade-safety gate has nothing to bind to — the embed glob in migrate.go has drifted")
	}

	// Every up MUST have a matching down with the same name slug and a
	// non-empty body. A migration without a down script is a recovery
	// hazard — `Migrator.Down(ctx, 0)` returns ErrIrreversible when it
	// reaches an up-only version, leaving the ledger in an
	// indeterminate state.
	for version, up := range ups {
		resourceID := "schema_migrations.version=" + strconv.FormatInt(version, 10)
		down, ok := downs[version]
		if !ok {
			t.Errorf("embedded migration %q (resource_id %s) has no matching `%04d_%s.down.sql`; every reversible migration MUST ship a down script so `Migrator.Down(ctx, 0)` can roll the ledger back without ErrIrreversible",
				up.filename, resourceID, version, up.name)
			continue
		}
		if down.name != up.name {
			t.Errorf("embedded down migration %q (resource_id %s) has name slug %q, want %q to match `%s`; the loader pairs up/down by both version and name, so a mismatch is a closed-set reversibility regression",
				down.filename, resourceID, down.name, up.name, up.filename)
		}
		if strings.TrimSpace(down.body) == "" {
			t.Errorf("embedded down migration %q (resource_id %s) is empty; an empty down script silently no-ops on rollback and leaves the corresponding up-side schema in place, which the round-trip test would observe as a stale object",
				down.filename, resourceID)
		}
	}

	// Every down MUST have a corresponding up. An orphan down is a
	// closed-set regression: the loader will reject the FS with
	// `version N has a down migration but no up migration`, so we
	// mirror that invariant here for a faster failure with the
	// offending filename surfaced.
	for version, down := range downs {
		if _, ok := ups[version]; !ok {
			t.Errorf("embedded down migration %q (resource_id schema_migrations.version=%d) has no matching `NNNN_*.up.sql`; every down script MUST pair with an up script — `LoadMigrations` would reject this FS with `version %d has a down migration but no up migration`",
				down.filename, version, version)
		}
	}

	// Cross-check: LoadMigrations sees every up-side migration as
	// reversible (DownSQL non-empty) iff a matching down file exists.
	// This pins the loader's behaviour against the embed FS we just
	// inspected so a future loader change that drops DownSQL parsing
	// silently fails ONE test, not zero.
	loaded, err := LoadMigrations(embeddedMigrations)
	if err != nil {
		t.Fatalf("LoadMigrations(embedded): %v", err)
	}
	for _, m := range loaded {
		resourceID := "schema_migrations.version=" + strconv.FormatInt(m.Version, 10)
		_, hasDownFile := downs[m.Version]
		hasDownSQL := strings.TrimSpace(m.DownSQL) != ""
		if hasDownFile != hasDownSQL {
			t.Errorf("loaded migration version=%d name=%q (resource_id %s): DownSQL-non-empty=%v but down file present=%v; LoadMigrations must surface every embedded `NNNN_*.down.sql` as a non-empty DownSQL — a drift here means the loader will refuse to roll back versions that have a down file on disk",
				m.Version, m.Name, resourceID, hasDownSQL, hasDownFile)
		}
	}
}

// TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder pins
// the empty-DB round-trip invariant: a throwaway database MUST accept
// the full embedded ladder, then accept a Down to version 0 (the
// ledger MUST become empty), then accept Up a second time and end up
// in the same fully-applied state with identical checksums. Failures
// surface with the offending migration version AND the resource_id
// (`schema_migrations.version=N`) so the operator can map the failure
// to the exact migration without re-running the suite locally. The
// test skips when `YALLA_TEST_DATABASE_URL` is unset so the suite
// stays green on machines without Postgres; CI sets the env var.
func TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder(t *testing.T) {
	t.Parallel()
	pool := testPool(t)
	ctx := context.Background()

	m, err := New(pool, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := m.Migrations()
	if len(want) == 0 {
		t.Fatal("no embedded migrations; the downgrade-safety round-trip gate has nothing to bind to")
	}

	// Phase 1: Up applies the full ladder cleanly.
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up(empty-db): %v", err)
	}
	beforeDown, err := pool.Query(ctx,
		`SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations before Down: %v", err)
	}
	type ledgerRow struct {
		version  int64
		checksum string
	}
	var firstUp []ledgerRow
	for beforeDown.Next() {
		var r ledgerRow
		if err := beforeDown.Scan(&r.version, &r.checksum); err != nil {
			beforeDown.Close()
			t.Fatalf("scan schema_migrations before Down: %v", err)
		}
		firstUp = append(firstUp, r)
	}
	beforeDown.Close()
	if err := beforeDown.Err(); err != nil {
		t.Fatalf("iterate schema_migrations before Down: %v", err)
	}
	if len(firstUp) != len(want) {
		t.Fatalf("schema_migrations rows after first Up = %d, want %d (every embedded migration MUST land in the ledger before the round-trip can begin)",
			len(firstUp), len(want))
	}

	// Phase 2: Down to version 0 rolls every migration back. The
	// ledger MUST be empty; an ErrIrreversible at this point would
	// mean an up-only migration slipped past the closed-set
	// reversibility gate above.
	if err := m.Down(ctx, 0); err != nil {
		// Surface the offending version when the runner identifies
		// one. errors.Is(ErrIrreversible) ties this back to the
		// closed-set reversibility gate above; the down-file
		// coverage matcher would have caught the missing file
		// deterministically without needing Postgres.
		if errors.Is(err, ErrIrreversible) {
			t.Fatalf("Down(0) returned ErrIrreversible: %v — an embedded migration ships no down script; the closed-set reversibility gate (TestMigrationsDowngradeSafetyContractCoversAllDownFiles) should have caught this before Postgres ran",
				err)
		}
		t.Fatalf("Down(0) on a fully-applied empty-DB ladder: %v", err)
	}

	// The ledger MUST be empty after a full rollback.
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rowCount); err != nil {
		t.Fatalf("count schema_migrations after Down(0): %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("schema_migrations rows after Down(0) = %d, want 0 — a non-empty ledger after a full rollback means a down script silently no-opped its delete or a partial rollback left a row behind",
			rowCount)
	}

	// Status reports zero applied, all pending, current=0, dirty=false.
	st, err := m.Status(ctx)
	if err != nil {
		t.Fatalf("Status after Down(0): %v", err)
	}
	if st.Current != 0 || len(st.Applied) != 0 || st.Dirty {
		t.Errorf("Status after Down(0) = {current:%d applied:%d dirty:%v}, want {0 0 false}",
			st.Current, len(st.Applied), st.Dirty)
	}
	if len(st.Pending) != len(want) {
		t.Errorf("Status.Pending after Down(0) = %d, want %d (every embedded migration MUST be re-pending after a full rollback)",
			len(st.Pending), len(want))
	}

	// Phase 3: Up a second time after the rollback. The runner MUST
	// re-apply the full ladder cleanly and end up at the same set of
	// versions with the same checksums it had before the Down. A
	// drift here would indicate a down script that destroyed
	// idempotency (e.g. dropped a table the next up assumes exists,
	// or left state the next up cannot tolerate).
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up after Down(0): %v — a clean down script MUST leave the database in a state the next Up can re-apply", err)
	}
	afterUp, err := pool.Query(ctx,
		`SELECT version, checksum, dirty FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations after second Up: %v", err)
	}
	defer afterUp.Close()
	var roundTrip []ledgerRow
	for afterUp.Next() {
		var r ledgerRow
		var dirty bool
		if err := afterUp.Scan(&r.version, &r.checksum, &dirty); err != nil {
			t.Fatalf("scan schema_migrations after second Up: %v", err)
		}
		if dirty {
			t.Errorf("ledger row version=%d (resource_id schema_migrations.version=%d) is dirty=true after round-trip Up — a dirty row after a clean down+up cycle means the transaction-per-migration contract was broken",
				r.version, r.version)
		}
		roundTrip = append(roundTrip, r)
	}
	if err := afterUp.Err(); err != nil {
		t.Fatalf("iterate schema_migrations after second Up: %v", err)
	}
	if len(roundTrip) != len(firstUp) {
		t.Fatalf("schema_migrations rows after round-trip = %d, want %d — the ladder is not idempotent across a Down(0)+Up cycle",
			len(roundTrip), len(firstUp))
	}
	for i, r := range roundTrip {
		f := firstUp[i]
		resourceID := "schema_migrations.version=" + strconv.FormatInt(r.version, 10)
		if r.version != f.version {
			t.Errorf("round-trip ledger row %d: version = %d, want %d (resource_id %s)",
				i, r.version, f.version, resourceID)
		}
		if r.checksum != f.checksum {
			t.Errorf("round-trip ledger row %d: checksum = %q, want %q (resource_id %s) — a checksum drift after a Down(0)+Up cycle indicates the loader read different up SQL between the two phases",
				i, r.checksum, f.checksum, resourceID)
		}
	}
}
