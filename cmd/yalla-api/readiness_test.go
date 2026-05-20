package main

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestRunStartupChecksPassesMigratedDatabaseAndSetsMigrationVersion(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	meta := runtime.NewMeta()

	results := runStartupChecks(context.Background(), db.Pool, meta, nil)
	assertNoStartupError(t, results, "database")
	assertNoStartupError(t, results, "migrations")
	assertNoStartupError(t, results, "queue")
	if got := meta.MigrationVersion(); got == runtime.MigrationVersionUnknown || got == "0000" {
		t.Fatalf("migration version = %q, want applied version", got)
	}
}

func TestRunStartupChecksReportsPendingMigrations(t *testing.T) {
	t.Parallel()

	db := testutil.RequireDB(t)
	meta := runtime.NewMeta()

	results := runStartupChecks(context.Background(), db.Pool, meta, nil)
	assertNoStartupError(t, results, "database")
	assertStartupErrorCode(t, results, "migrations", yerr.CodeMigrationRequired)
	assertStartupErrorCode(t, results, "queue", yerr.CodeUnavailable)
	if got := meta.MigrationVersion(); got != "0000" {
		t.Fatalf("migration version = %q, want 0000 for empty schema", got)
	}
}

func TestRunStartupChecksReportsDirtyMigrations(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	if _, err := db.Exec(context.Background(),
		`UPDATE schema_migrations SET dirty = true WHERE version = (SELECT max(version) FROM schema_migrations)`); err != nil {
		t.Fatalf("mark schema dirty: %v", err)
	}
	meta := runtime.NewMeta()

	results := runStartupChecks(context.Background(), db.Pool, meta, nil)
	assertNoStartupError(t, results, "database")
	assertStartupErrorCode(t, results, "migrations", yerr.CodeMigrationRequired)
	assertNoStartupError(t, results, "queue")
	if got := meta.MigrationVersion(); got == runtime.MigrationVersionUnknown {
		t.Fatal("migration version was not populated for dirty schema")
	}
}

func TestRunStartupChecksRunsOptionalDokployChecker(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	meta := runtime.NewMeta()
	want := errors.New("dokploy health check failed")
	called := false

	results := runStartupChecks(context.Background(), db.Pool, meta, func(context.Context) error {
		called = true
		return want
	})
	if !called {
		t.Fatal("dokploy checker was not called")
	}
	assertNoStartupError(t, results, "database")
	assertNoStartupError(t, results, "migrations")
	assertNoStartupError(t, results, "queue")
	if !errors.Is(results["dokploy"], want) {
		t.Fatalf("dokploy error = %v, want %v", results["dokploy"], want)
	}
}

func TestMarkStartupReadinessMarksOnlyPassingGates(t *testing.T) {
	t.Parallel()

	readiness := runtime.NewReadiness("database", "migrations", "queue", "dokploy")
	markStartupReadiness(readiness, []string{"database", "migrations", "queue", "dokploy"}, map[string]error{
		"queue": errors.New("queue unavailable"),
	})

	snapshot := readiness.Snapshot()
	for _, gate := range []string{"database", "migrations", "dokploy"} {
		if !snapshot[gate] {
			t.Fatalf("gate %q = false, want true", gate)
		}
	}
	if snapshot["queue"] {
		t.Fatal("queue gate = true, want false while queue check fails")
	}
	if readiness.Ready() {
		t.Fatal("readiness.Ready() = true, want false while queue check fails")
	}
}

func assertNoStartupError(t *testing.T, results map[string]error, gate string) {
	t.Helper()
	if err := results[gate]; err != nil {
		t.Fatalf("%s startup check error = %v, want nil", gate, err)
	}
}

func assertStartupErrorCode(t *testing.T, results map[string]error, gate string, want yerr.Code) {
	t.Helper()
	err := results[gate]
	if err == nil {
		t.Fatalf("%s startup check error = nil, want %s", gate, want)
	}
	if got := yerr.From(err).Code; got != want {
		t.Fatalf("%s startup check error code = %s, want %s", gate, got, want)
	}
}
