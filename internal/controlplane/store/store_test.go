package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// These are integration tests for the Store transaction runner: Read, Write,
// commit, rollback-on-error, and rollback-on-panic. They run against an
// isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset, so `go test ./...` stays green without
// Postgres.

// newStore builds a Store over the test database's pool. A nil logger keeps
// rollback diagnostics out of test output; the behaviour under test does not
// depend on logging.
func newStore(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

// insertOrg writes an organization row through tx. It is the smallest mutation
// available against the migrated schema, so the transaction tests use it to
// prove commit and rollback semantics.
func insertOrg(ctx context.Context, tx *store.Tx, org testutil.Organization) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		org.ID, org.Slug, org.Name)
	return err
}

// orgExists reports whether an organization row with id is visible through q.
func orgExists(ctx context.Context, t *testing.T, q store.Querier, id string) bool {
	t.Helper()
	var n int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM organizations WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count organizations: %v", err)
	}
	return n > 0
}

func TestWriteCommitsOnSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	org := testutil.NewFactory(t).Organization("acme")
	ctx := context.Background()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return insertOrg(ctx, tx, org)
	}); err != nil {
		t.Fatalf("Write returned %v, want nil", err)
	}

	if !orgExists(ctx, t, db.Pool, org.ID) {
		t.Error("organization row was not committed")
	}
}

func TestWriteRollsBackOnError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	org := testutil.NewFactory(t).Organization("acme")
	ctx := context.Background()

	sentinel := errors.New("unit of work failed after the write")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if e := insertOrg(ctx, tx, org); e != nil {
			return e
		}
		// The row exists inside the transaction...
		if !orgExists(ctx, t, tx, org.ID) {
			t.Error("row not visible inside its own transaction")
		}
		// ...but a later step of the unit of work fails.
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write error = %v, want the sentinel returned by fn", err)
	}

	if orgExists(ctx, t, db.Pool, org.ID) {
		t.Error("organization row survived a rolled-back transaction")
	}
}

func TestWriteRollsBackOnPanic(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	org := testutil.NewFactory(t).Organization("acme")
	ctx := context.Background()

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected the panic to propagate out of Write")
			}
			if r != "unit of work panicked" {
				t.Errorf("recovered %v, want the original panic value", r)
			}
		}()
		_ = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			if e := insertOrg(ctx, tx, org); e != nil {
				t.Errorf("insert inside panicking tx: %v", e)
			}
			panic("unit of work panicked")
		})
	}()

	if orgExists(ctx, t, db.Pool, org.ID) {
		t.Error("organization row survived a panicked, rolled-back transaction")
	}
}

func TestReadSeesCommittedData(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "acme")
	ctx := context.Background()

	var seen bool
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		seen = orgExists(ctx, t, q, org.ID)
		return nil
	}); err != nil {
		t.Fatalf("Read returned %v, want nil", err)
	}
	if !seen {
		t.Error("Read did not see a committed organization row")
	}
}

func TestReadRejectsWrites(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	org := testutil.NewFactory(t).Organization("acme")
	ctx := context.Background()

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
			org.ID, org.Slug, org.Name)
		return execErr
	})
	if err == nil {
		t.Fatal("Read allowed a write; a read-only transaction must reject it")
	}

	if orgExists(ctx, t, db.Pool, org.ID) {
		t.Error("a write smuggled through Read was persisted")
	}
}

func TestReadPropagatesTypedErrors(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	want := yerr.New(yerr.CodeNotFound, "nothing here")
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("Read error = %v, want the typed error returned by fn unchanged", err)
	}
}
