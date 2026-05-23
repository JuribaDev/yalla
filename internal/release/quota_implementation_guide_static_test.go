package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const quotaImplementationGuidePath = "docs/development/quota-implementation-guide.md"

func TestQuotaImplementationGuideArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, quotaImplementationGuidePath))

	for _, want := range []string{
		"Quota Implementation Guide",
		"internal/controlplane/quota",
		"internal/controlplane/store",
		"Store.Write",
		"quota.Checker",
		"quota.ExceededDetail",
		"quota.DetailOf",
		"ReserveAmount",
		"store.QuotaResource",
		"store.QuotaRepository",
		"store.QuotaReserver",
		"policy.Action",
		"apierr.QuotaExceeded",
		"telemetry.QuotaUsageMetrics",
		"quota_reservations",
		"usage_counters",
		"organization_id",
		"tenant isolation",
		"Yalla API -> Postgres source of truth -> worker -> private Dokploy API",
		"go test ./internal/controlplane/quota/...",
		"go test ./internal/controlplane/store/...",
		"go test -run TestQuotaConcurrency ./...",
		"go test -run TestPolicyMatrix ./...",
		"go test -run TestTenantIsolation ./...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", quotaImplementationGuidePath, want)
		}
	}
}

func TestQuotaImplementationGuideArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, quotaImplementationGuidePath))

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
		"E_QUOTA_EXCEEDED",
		"Failure recovery",
		"docker compose up -d postgres",
		"docker compose logs postgres",
		"docker compose down",
		"go clean -testcache",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", quotaImplementationGuidePath, want)
		}
	}
}

func TestQuotaImplementationGuideArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, quotaImplementationGuidePath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not call Dokploy from quota code",
		"Every customer-data query must be tenant-scoped",
		"Quota reservations happen in the same transaction",
		"fake Dokploy",
		"idempotency",
		"audit",
		"soft-limit warnings",
		"hard-limit rejection",
		"cross-tenant IDs",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", quotaImplementationGuidePath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", quotaImplementationGuidePath, forbidden)
		}
	}
}

func TestQuotaImplementationGuideArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestQuotaImplementationGuideArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Quota implementation guide artifact static tests",
				"go test ./internal/release/... -run TestQuotaImplementationGuideArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Quota Implementation Guide Artifact",
				quotaImplementationGuidePath,
				"go test ./internal/release/... -run TestQuotaImplementationGuideArtifact",
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
