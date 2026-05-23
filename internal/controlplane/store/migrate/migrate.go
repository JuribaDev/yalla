// Package migrate runs ordered, checksummed SQL migrations against the
// control-plane Postgres database.
//
// Migrations are plain .sql files embedded in the binary at build time, named
// NNNN_name.up.sql (required) and NNNN_name.down.sql (optional, present only
// when the migration is safely reversible). The runner records every applied
// migration in a schema_migrations table together with the sha256 checksum of
// the file it ran, and refuses to proceed when it finds:
//
//   - a dirty migration — a previous run failed part-way (ErrDirtyDatabase);
//   - an applied version not present in the embedded set — the database is
//     ahead of, or has diverged from, this binary (ErrUnknownVersion); or
//   - an applied version whose checksum no longer matches the embedded file —
//     a migration's contents changed after it was applied (ErrChecksumMismatch).
//
// Each migration runs inside its own transaction, so a failed migration leaves
// no partial schema and no migration row behind. A Postgres advisory lock
// serialises concurrent runners so two processes starting at once cannot race.
//
// migrate is a persistence-layer package: it returns descriptive, sentinel-
// wrapped errors. Mapping those onto the HTTP error taxonomy (apierr) is the
// job of whatever startup or admin path invokes it.
package migrate

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// migrationsDir is the path within a migration filesystem that holds the .sql
// files. It is the same for the embedded FS and for test filesystems.
const migrationsDir = "migrations"

// advisoryLockKey serialises concurrent migration runners through a Postgres
// session-level advisory lock. The value is arbitrary but must stay stable
// across builds; it spells "yalla" in ASCII.
const advisoryLockKey int64 = 0x79616C6C61

// createSchemaMigrationsTable bootstraps the ledger the runner uses to track
// applied migrations. The runner owns this table directly rather than shipping
// it as migration 0001, so that there is always somewhere to record the first
// real migration. version is the primary key; dirty marks a migration that
// started but did not finish.
const createSchemaMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    bigint      PRIMARY KEY,
    name       text        NOT NULL,
    checksum   text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    dirty      boolean     NOT NULL DEFAULT false
)`

// Sentinel errors. Callers and tests match these with errors.Is; the wrapping
// error carries the offending version for operators.
var (
	// ErrDirtyDatabase means a previous migration run failed part-way and left
	// the database in an unknown state. An operator must resolve it before
	// migrations can run again.
	ErrDirtyDatabase = errors.New("migrate: database is dirty")

	// ErrUnknownVersion means the database has an applied migration version
	// that this binary does not know about — the database is ahead of, or has
	// diverged from, this build.
	ErrUnknownVersion = errors.New("migrate: database has an unknown applied migration version")

	// ErrChecksumMismatch means an applied migration's recorded checksum does
	// not match the embedded file: a migration's contents changed after it was
	// applied, which is never safe.
	ErrChecksumMismatch = errors.New("migrate: applied migration checksum does not match embedded file")

	// ErrIrreversible means a Down was requested across a migration that ships
	// no .down.sql file.
	ErrIrreversible = errors.New("migrate: migration is not reversible")
)

// Migration is a single ordered schema change loaded from the migration
// filesystem.
type Migration struct {
	Version  int64  // monotonically increasing, parsed from the filename
	Name     string // human-readable slug, parsed from the filename
	UpSQL    string // forward migration SQL; always present
	DownSQL  string // reverse migration SQL; empty when not reversible
	Checksum string // sha256 hex digest of UpSQL
}

// Reversible reports whether the migration ships a down script.
func (m Migration) Reversible() bool { return m.DownSQL != "" }

// AppliedMigration is one row recorded in the schema_migrations ledger.
type AppliedMigration struct {
	Version   int64
	Name      string
	Checksum  string
	AppliedAt time.Time
	Dirty     bool
}

// Status is a point-in-time snapshot of migration state.
type Status struct {
	Applied []AppliedMigration // every recorded row, ascending by version
	Pending []Migration        // embedded migrations not yet applied, ascending
	Current int64              // highest cleanly-applied version, 0 when none
	Dirty   bool               // true when any applied row is dirty
}

// migrationFileRE matches NNNN_name.(up|down).sql. The version must be at least
// four digits (zero-padded) and the name lower-case alphanumeric with
// underscores, so files sort lexically in version order.
var migrationFileRE = regexp.MustCompile(`^([0-9]{4,})_([a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql$`)

// LoadMigrations parses and validates every migration file in fsys (expected
// under the "migrations" directory) and returns them sorted ascending by
// version. It fails when a filename is malformed, when a version is missing
// its up script, when a version has an empty up script, or when two files
// claim the same version with conflicting names.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("migrate: read migrations dir: %w", err)
	}

	type pair struct {
		name    string
		up      string
		down    string
		hasUp   bool
		hasDown bool
	}
	byVersion := make(map[int64]*pair)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		groups := migrationFileRE.FindStringSubmatch(e.Name())
		if groups == nil {
			return nil, fmt.Errorf("migrate: malformed migration filename %q (want NNNN_name.up.sql or NNNN_name.down.sql)", e.Name())
		}
		version, err := strconv.ParseInt(groups[1], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migrate: invalid migration version in %q", e.Name())
		}
		name, direction := groups[2], groups[3]

		body, err := fs.ReadFile(fsys, migrationsDir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("migrate: read %q: %w", e.Name(), err)
		}

		p := byVersion[version]
		if p == nil {
			p = &pair{name: name}
			byVersion[version] = p
		}
		if p.name != name {
			return nil, fmt.Errorf("migrate: version %d has conflicting names %q and %q", version, p.name, name)
		}

		switch direction {
		case "up":
			if p.hasUp {
				return nil, fmt.Errorf("migrate: duplicate up migration for version %d", version)
			}
			if strings.TrimSpace(string(body)) == "" {
				return nil, fmt.Errorf("migrate: up migration for version %d is empty", version)
			}
			p.up = string(body)
			p.hasUp = true
		case "down":
			if p.hasDown {
				return nil, fmt.Errorf("migrate: duplicate down migration for version %d", version)
			}
			p.down = string(body)
			p.hasDown = true
		}
	}

	if len(byVersion) == 0 {
		return nil, errors.New("migrate: no migrations found")
	}

	out := make([]Migration, 0, len(byVersion))
	for version, p := range byVersion {
		if !p.hasUp {
			return nil, fmt.Errorf("migrate: version %d has a down migration but no up migration", version)
		}
		sum := sha256.Sum256([]byte(p.up))
		out = append(out, Migration{
			Version:  version,
			Name:     p.name,
			UpSQL:    p.up,
			DownSQL:  p.down,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrator applies a fixed set of migrations to a Postgres database.
type Migrator struct {
	pool       *pgxpool.Pool
	migrations []Migration
	logger     *slog.Logger
}

// New builds a Migrator from the migrations embedded in this package. It is the
// constructor production code uses.
func New(pool *pgxpool.Pool, logger *slog.Logger) (*Migrator, error) {
	return NewWithFS(pool, embeddedMigrations, logger)
}

// NewWithFS builds a Migrator from an arbitrary migration filesystem. It exists
// so tests can exercise the runner against fixture migrations; production code
// uses New.
func NewWithFS(pool *pgxpool.Pool, fsys fs.FS, logger *slog.Logger) (*Migrator, error) {
	if pool == nil {
		return nil, errors.New("migrate: nil pool")
	}
	migrations, err := LoadMigrations(fsys)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Migrator{pool: pool, migrations: migrations, logger: logger}, nil
}

// Migrations returns a copy of the loaded migration set, ascending by version.
func (m *Migrator) Migrations() []Migration {
	out := make([]Migration, len(m.migrations))
	copy(out, m.migrations)
	return out
}

// Up applies every embedded migration that has not yet been recorded, in
// ascending version order. It is idempotent: a fully migrated database is a
// no-op. It refuses to run against a dirty, unknown, or checksum-mismatched
// database (see the package sentinel errors).
func (m *Migrator) Up(ctx context.Context) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	unlock, err := lock(ctx, conn)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := conn.Exec(ctx, createSchemaMigrationsTable); err != nil {
		return fmt.Errorf("migrate: ensure schema_migrations table: %w", err)
	}

	applied, err := queryApplied(ctx, conn)
	if err != nil {
		return err
	}
	if err := m.verify(applied); err != nil {
		return err
	}

	appliedSet := make(map[int64]bool, len(applied))
	for _, a := range applied {
		appliedSet[a.Version] = true
	}

	for _, mig := range m.migrations {
		if appliedSet[mig.Version] {
			continue
		}
		if err := applyUp(ctx, conn, mig); err != nil {
			return err
		}
		m.logger.InfoContext(ctx, "applied migration",
			slog.Int64("version", mig.Version),
			slog.String("name", mig.Name))
	}
	return nil
}

// Down rolls the database back to targetVersion by applying the down script of
// every cleanly-applied migration with a higher version, newest-first. A
// targetVersion of 0 rolls every migration back. It refuses a dirty, unknown,
// or checksum-mismatched database, and fails with ErrIrreversible if any
// migration in range ships no down script.
func (m *Migrator) Down(ctx context.Context, targetVersion int64) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	unlock, err := lock(ctx, conn)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := conn.Exec(ctx, createSchemaMigrationsTable); err != nil {
		return fmt.Errorf("migrate: ensure schema_migrations table: %w", err)
	}

	applied, err := queryApplied(ctx, conn)
	if err != nil {
		return err
	}
	if err := m.verify(applied); err != nil {
		return err
	}

	known := make(map[int64]Migration, len(m.migrations))
	for _, mig := range m.migrations {
		known[mig.Version] = mig
	}

	// applied is ascending by version; roll back newest-first.
	for i := len(applied) - 1; i >= 0; i-- {
		a := applied[i]
		if a.Version <= targetVersion {
			break
		}
		mig := known[a.Version] // verify guaranteed this exists
		if !mig.Reversible() {
			return fmt.Errorf("%w: version %d (%s)", ErrIrreversible, mig.Version, mig.Name)
		}
		if err := applyDown(ctx, conn, mig); err != nil {
			return err
		}
		m.logger.InfoContext(ctx, "reverted migration",
			slog.Int64("version", mig.Version),
			slog.String("name", mig.Name))
	}
	return nil
}

// Status returns a snapshot of applied and pending migrations. It creates the
// schema_migrations ledger if it does not exist but applies nothing.
func (m *Migrator) Status(ctx context.Context) (Status, error) {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, createSchemaMigrationsTable); err != nil {
		return Status{}, fmt.Errorf("migrate: ensure schema_migrations table: %w", err)
	}

	applied, err := queryApplied(ctx, conn)
	if err != nil {
		return Status{}, err
	}

	st := Status{Applied: applied}
	appliedSet := make(map[int64]bool, len(applied))
	for _, a := range applied {
		appliedSet[a.Version] = true
		if a.Dirty {
			st.Dirty = true
			continue
		}
		if a.Version > st.Current {
			st.Current = a.Version
		}
	}
	for _, mig := range m.migrations {
		if !appliedSet[mig.Version] {
			st.Pending = append(st.Pending, mig)
		}
	}
	return st, nil
}

// verify rejects an applied set that the runner must not touch: a dirty row, a
// version this binary does not ship, or a checksum that no longer matches.
func (m *Migrator) verify(applied []AppliedMigration) error {
	known := make(map[int64]Migration, len(m.migrations))
	for _, mig := range m.migrations {
		known[mig.Version] = mig
	}
	for _, a := range applied {
		if a.Dirty {
			return fmt.Errorf("%w: version %d (%s)", ErrDirtyDatabase, a.Version, a.Name)
		}
		mig, ok := known[a.Version]
		if !ok {
			return fmt.Errorf("%w: version %d (%s)", ErrUnknownVersion, a.Version, a.Name)
		}
		if mig.Checksum != a.Checksum {
			return fmt.Errorf("%w: version %d (%s)", ErrChecksumMismatch, a.Version, a.Name)
		}
	}
	return nil
}

// lock acquires the migration advisory lock on conn and returns a release
// function. The release uses a cancellation-detached context so the lock is
// always returned even when the caller's context is already cancelled.
func lock(ctx context.Context, conn *pgxpool.Conn) (func(), error) {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return nil, fmt.Errorf("migrate: acquire advisory lock: %w", err)
	}
	return func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", advisoryLockKey)
	}, nil
}

// applyUp records and runs a single migration inside one transaction. The row
// is inserted dirty, the migration SQL runs, then the row is marked clean — so
// a crash between insert and finalise is observable as ErrDirtyDatabase, while
// a SQL failure rolls the whole transaction back and leaves no row at all.
func applyUp(ctx context.Context, conn *pgxpool.Conn, mig Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: begin tx for version %d: %w", mig.Version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, dirty) VALUES ($1, $2, $3, true)`,
		mig.Version, mig.Name, mig.Checksum); err != nil {
		return fmt.Errorf("migrate: record version %d: %w", mig.Version, err)
	}
	if _, err := tx.Exec(ctx, mig.UpSQL); err != nil {
		return fmt.Errorf("migrate: apply version %d (%s): %w", mig.Version, mig.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE schema_migrations SET dirty = false, applied_at = now() WHERE version = $1`,
		mig.Version); err != nil {
		return fmt.Errorf("migrate: finalize version %d: %w", mig.Version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate: commit version %d: %w", mig.Version, err)
	}
	return nil
}

// applyDown runs a single migration's down script and deletes its ledger row,
// both inside one transaction.
func applyDown(ctx context.Context, conn *pgxpool.Conn, mig Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: begin tx for down version %d: %w", mig.Version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, mig.DownSQL); err != nil {
		return fmt.Errorf("migrate: revert version %d (%s): %w", mig.Version, mig.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version = $1`, mig.Version); err != nil {
		return fmt.Errorf("migrate: remove ledger row for version %d: %w", mig.Version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate: commit down version %d: %w", mig.Version, err)
	}
	return nil
}

// queryApplied reads the schema_migrations ledger ascending by version.
func queryApplied(ctx context.Context, conn *pgxpool.Conn) ([]AppliedMigration, error) {
	rows, err := conn.Query(ctx,
		`SELECT version, name, checksum, applied_at, dirty FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read schema_migrations: %w", err)
	}
	defer rows.Close()

	var out []AppliedMigration
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt, &a.Dirty); err != nil {
			return nil, fmt.Errorf("migrate: scan schema_migrations row: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: iterate schema_migrations: %w", err)
	}
	return out, nil
}
