// Package testutil provides reusable backend test helpers shared by every
// control-plane package: isolated Postgres databases for persistence
// integration tests, deterministic data fixtures, and redaction assertions.
//
// The persistence helpers (RequireDB, RequireMigratedDB) provision a freshly
// created, throwaway Postgres database per test. Each test therefore gets its
// own isolated data and can never observe another test's tenant, which makes
// the suite safe to run with t.Parallel(). The database is dropped on test
// cleanup. When YALLA_TEST_DATABASE_URL is unset the helpers skip the test
// instead of failing, so `go test ./...` stays green on machines and CI lanes
// without Postgres — this is the only external dependency CI may skip, and the
// skip carries an explicit documented reason (SkipReason).
//
// The fixture helpers (Factory) build deterministically-shaped, globally-unique
// in-memory fixture values for the organization -> project -> environment ->
// service hierarchy plus users and API keys. They are the shared shape every
// persistence test seeds from; persisting them is the job of the repository
// layer.
//
// The redaction helpers (AssertRedacted, AssertRedactedValue) guard the
// "secrets must never reach logs, errors, audit metadata, or test output"
// invariant.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvDatabaseURL is the environment variable holding an admin Postgres DSN with
// CREATE DATABASE / DROP DATABASE privileges. The persistence helpers use it to
// provision an isolated throwaway database per test. When it is unset the
// helpers skip the test rather than fail.
const EnvDatabaseURL = "YALLA_TEST_DATABASE_URL"

// SkipReason is the explicit, documented reason the persistence helpers skip a
// test. The local Docker Postgres stack (see docker-compose.yml) is the only
// external dependency CI is permitted to skip; it must do so with this reason
// so a skipped persistence suite is never silent.
const SkipReason = EnvDatabaseURL + " not set; skipping Postgres integration test " +
	"(the local Docker Postgres stack is the only external dependency CI may skip)"

// DB is an isolated, throwaway Postgres database scoped to a single test. It
// embeds *pgxpool.Pool, so the pool API is available directly on the value.
// Every RequireDB / RequireMigratedDB call provisions a freshly created
// database with a crypto-random name; the database is dropped on test cleanup.
type DB struct {
	*pgxpool.Pool
	// Name is the generated database name. It is unique per call, so two
	// helpers in the same or different tests never share a database.
	Name string
}

// RequireDB provisions an empty, isolated Postgres database for t and returns a
// pool connected to it. It skips t when EnvDatabaseURL is unset. The database
// is dropped on test cleanup; cleanup is deterministic and safe under
// t.Parallel() because every call gets its own uniquely named database.
func RequireDB(t testing.TB) *DB {
	t.Helper()

	adminDSN, ok := lookupAdminDSN(os.Getenv)
	if !ok {
		t.Skip(SkipReason)
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("testutil: connect admin database: %v", err)
	}
	// Registered first so it runs last: the admin pool must stay open until
	// after the DROP DATABASE cleanup has run.
	t.Cleanup(admin.Close)

	name := uniqueDBName(t)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("testutil: create test database: %v", err)
	}
	t.Cleanup(func() {
		// context.Background: the test's own context may already be cancelled
		// by the time cleanup runs. WITH (FORCE) evicts any straggler sessions.
		if _, err := admin.Exec(context.Background(),
			"DROP DATABASE IF EXISTS "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("testutil: drop test database %s: %v", name, err)
		}
	})

	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("testutil: parse admin DSN: %v", err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("testutil: connect test database: %v", err)
	}
	// Registered last so it runs first: the test pool is closed before the
	// database it points at is dropped.
	t.Cleanup(pool.Close)

	return &DB{Pool: pool, Name: name}
}

// RequireMigratedDB provisions an isolated Postgres database like RequireDB and
// then applies every embedded migration to it, so the test starts from the
// real control-plane schema. It skips t when EnvDatabaseURL is unset.
func RequireMigratedDB(t testing.TB) *DB {
	t.Helper()

	db := RequireDB(t)
	m, err := migrate.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("testutil: build migrator: %v", err)
	}
	if err := m.Up(context.Background()); err != nil {
		t.Fatalf("testutil: apply migrations: %v", err)
	}
	return db
}

// lookupAdminDSN resolves the admin DSN from the environment. It is split out
// from RequireDB so the skip decision is unit-testable without a database.
func lookupAdminDSN(getenv func(string) string) (string, bool) {
	dsn := strings.TrimSpace(getenv(EnvDatabaseURL))
	return dsn, dsn != ""
}

// uniqueDBName returns a crypto-random, valid Postgres database name. The
// random suffix guarantees two parallel tests never collide on a database.
func uniqueDBName(t testing.TB) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("testutil: generate database name: %v", err)
	}
	return "yalla_test_" + hex.EncodeToString(buf[:])
}
