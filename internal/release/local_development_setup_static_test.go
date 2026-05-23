package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const localDevelopmentSetupPath = "docs/development/local-development.md"

func TestLocalDevelopmentSetupArtifactDocumentsRequiredWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, localDevelopmentSetupPath))

	for _, want := range []string{
		"docker compose up -d postgres",
		"docker compose --profile control-plane up --build",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>",
		"export YALLA_SIGNING_KEYS=<redacted:signing-keys>",
		"export YALLA_SECRET_KEYS=<redacted:secret-keys>",
		"export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example",
		"export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", localDevelopmentSetupPath, want)
		}
	}
}

func TestLocalDevelopmentSetupArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, localDevelopmentSetupPath))

	for _, want := range []string{
		"expected output",
		"STATUS",
		"healthy",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"database",
		"migrations",
		"queue",
		"Dokploy",
		"Failure recovery",
		"docker compose logs postgres",
		"docker compose down",
		"docker volume rm yalla_yalla_pgdata",
		"go clean -testcache",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", localDevelopmentSetupPath, want)
		}
	}
}

func TestLocalDevelopmentSetupArtifactDocumentsSafetyAndBackendContract(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, localDevelopmentSetupPath))

	for _, want := range []string{
		"Customer / Agent / CI",
		"Postgres source of truth",
		"private Dokploy API",
		"Customers must never receive Dokploy API tokens",
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"structured JSON",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", localDevelopmentSetupPath, want)
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
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", localDevelopmentSetupPath, forbidden)
		}
	}
}

func TestLocalDevelopmentSetupArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Local development setup artifact static tests",
				"go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Local Development Setup Artifact",
				localDevelopmentSetupPath,
				"go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact",
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
