package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const repositoryConventionsPath = "docs/development/repository-conventions.md"

func TestRepositoryConventionsArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, repositoryConventionsPath))

	for _, want := range []string{
		"Add or change a repository",
		"internal/controlplane/store",
		"internal/controlplane/store/migrate/migrations",
		"testutil.RequireMigratedDB",
		"Store.Read",
		"Store.Write",
		"apierr",
		"organization_id",
		"tenant isolation",
		"optimistic concurrency",
		"rollback",
		"go test ./internal/controlplane/store/...",
		"go test -run TestMigrations ./...",
		"go test -run TestTenantIsolation ./...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", repositoryConventionsPath, want)
		}
	}
}

func TestRepositoryConventionsArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, repositoryConventionsPath))

	for _, want := range []string{
		"required environment variables",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>",
		"expected output",
		"ok",
		"YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"Failure recovery",
		"docker compose up -d postgres",
		"docker compose logs postgres",
		"docker compose down",
		"go clean -testcache",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", repositoryConventionsPath, want)
		}
	}
}

func TestRepositoryConventionsArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, repositoryConventionsPath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Every customer-data query must be tenant-scoped",
		"Do not expose raw Dokploy operations",
		"Do not print SQL bind values",
		"Do not log DSNs",
		"fake Dokploy",
		"composite foreign keys",
		"cross-tenant IDs",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", repositoryConventionsPath, want)
		}
	}
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", repositoryConventionsPath, forbidden)
		}
	}
}

func TestRepositoryConventionsArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestRepositoryConventionsArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Repository conventions artifact static tests",
				"go test ./internal/release/... -run TestRepositoryConventionsArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Repository Conventions Artifact",
				repositoryConventionsPath,
				"go test ./internal/release/... -run TestRepositoryConventionsArtifact",
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
