package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const databaseMigrationAuthoringPath = "docs/development/database-migration-authoring.md"

func TestDatabaseMigrationAuthoringArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, databaseMigrationAuthoringPath))

	for _, want := range []string{
		"Create a migration",
		"internal/controlplane/store/migrate/migrations",
		"NNNN_description.up.sql",
		"NNNN_description.down.sql",
		"schema_migrations",
		"docker compose up -d postgres",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"go test -run TestMigrations ./...",
		"go test -run TestMigrationsEmptyDB ./...",
		"go test -run TestMigrationsDowngradeSafety ./...",
		"go test ./internal/controlplane/store/...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", databaseMigrationAuthoringPath, want)
		}
	}
}

func TestDatabaseMigrationAuthoringArtifactDocumentsContractsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, databaseMigrationAuthoringPath))

	for _, want := range []string{
		"expected output",
		"ok",
		"no rows in result set",
		"dirty migration",
		"Failure recovery",
		"go clean -testcache",
		"docker compose logs postgres",
		"docker compose down",
		"docker volume rm yalla_yalla_pgdata",
		"restore from backup",
		"Postgres source of truth",
		"private Dokploy API",
		"stable JSON envelopes",
		"schema_version yalla.output.v1",
		"schema_version yalla.error.v1",
		"request_id",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", databaseMigrationAuthoringPath, want)
		}
	}
}

func TestDatabaseMigrationAuthoringArtifactContainsNoSecrets(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, databaseMigrationAuthoringPath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer ",
		"api-key-",
		"dokploy-service-token",
		"cookie:",
		"password:",
		"YALLA_DOKPLOY_TOKEN=",
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", databaseMigrationAuthoringPath, forbidden)
		}
	}
}

func TestDatabaseMigrationAuthoringArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Database migration authoring artifact static tests",
				"go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Database Migration Authoring Artifact",
				databaseMigrationAuthoringPath,
				"go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact",
			},
		},
	} {
		body := readTextFile(t, filepath.Join(root, tc.path))
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q", tc.path, want)
			}
		}
	}
}
