package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const fakeDokployUsagePath = "docs/development/fake-dokploy-usage.md"

func TestFakeDokployUsageArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, fakeDokployUsagePath))

	for _, want := range []string{
		"Use fake Dokploy",
		"internal/controlplane/dokploy/dokployfake",
		"dokployfake.New",
		"internal/controlplane/dokploy",
		"internal/controlplane/worker",
		"internal/controlplane/httpapi",
		"Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API",
		"go test -run TestFakeDokploy ./...",
		"go test ./internal/controlplane/dokploy/...",
		"go test ./internal/controlplane/worker/...",
		"go test ./internal/controlplane/httpapi/...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", fakeDokployUsagePath, want)
		}
	}
}

func TestFakeDokployUsageArtifactDocumentsEnvironmentOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, fakeDokployUsagePath))

	for _, want := range []string{
		"required environment variables",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example",
		"export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
		"expected output",
		"ok",
		"YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test",
		"schema_version yalla.output.v1",
		"schema_version yalla.error.v1",
		"request_id",
		"Failure recovery",
		"go clean -testcache",
		"docker compose up -d postgres",
		"docker compose logs postgres",
		"docker compose down",
		"TestFakeDokployContractDeterministicHierarchyIDs",
		"TestFakeDokployContractRecordedRequestsRedactCredentials",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", fakeDokployUsagePath, want)
		}
	}
}

func TestFakeDokployUsageArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, fakeDokployUsagePath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not call Dokploy from handlers",
		"tenant isolation",
		"idempotency",
		"audit",
		"quota",
		"dokploy_refs",
		"Authorization",
		"output.Sentinel",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", fakeDokployUsagePath, want)
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
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", fakeDokployUsagePath, forbidden)
		}
	}
}

func TestFakeDokployUsageArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestFakeDokployUsageArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Fake Dokploy usage artifact static tests",
				"go test ./internal/release/... -run TestFakeDokployUsageArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Fake Dokploy Usage Artifact",
				fakeDokployUsagePath,
				"go test ./internal/release/... -run TestFakeDokployUsageArtifact",
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
