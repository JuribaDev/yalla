package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const pricingAndUsageTrackingArchitecturePath = "docs/operations/pricing-and-usage-tracking-architecture.md"

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsReviewScope(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"Pricing and Usage Tracking Architecture",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"Dokploy",
		"PostgreSQL",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsWhyNotDokploy(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"Why Dokploy monitoring is not the billing source of truth",
		"billing source of truth",
		"append-only",
		"usage_events",
		"usage_counters",
		"Tenant isolation",
		"Deterministic replay",
		"Auditable corrections",
		"Provider neutrality",
		"Defense in depth",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsDiagrams(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"Traefik metric label",
		"dokploy_refs",
		"yalla_kind=service",
		"service_id -> environment_id -> project_id -> org_id",
		"org-scoped usage counter",
		"Customer traffic -> Traefik -> Dokploy service",
		"Prometheus metrics",
		"Yalla metering source adapters",
		"Attribution layer",
		"Append-only usage_events",
		"Billing export snapshots",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsUsageKeys(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"Hard-limit keys",
		"Soft-limit keys",
		"Metered keys",
		"Observability-only keys",
		"active_services",
		"active_databases",
		"active_domains",
		"http_rps_peak_1m",
		"http_requests",
		"http_response_bytes",
		"http_request_bytes",
		"http_bandwidth_total",
		"container_cpu_millicore_seconds",
		"container_memory_mb_hours",
		"storage_gb_month",
		"backup_storage_gb_month",
		"build_minutes",
		"deployments",
		"http_5xx_count",
		"latency_p95_ms",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsRequiredVariables(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"YALLA_TEST_DATABASE_URL",
		"YALLA_POSTGRES_PASSWORD",
		"YALLA_EXTERNAL_DOKPLOY",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsVerificationCommands(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"go test ./internal/controlplane/metering/...",
		"go test ./internal/controlplane/billing/...",
		"go test ./internal/controlplane/entitlements/...",
		"go test ./internal/controlplane/quota/...",
		"go test ./internal/controlplane/store/...",
		"go test -run TestQuotaConcurrency ./...",
		"go test -run TestTenantIsolation ./...",
		"go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"<redacted:postgres-password>",
		"<redacted:postgres-dsn>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"must not print database URLs",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
		"redacted",
		"Failure recovery",
		"Normal verification gates must never require a live Dokploy server",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", pricingAndUsageTrackingArchitecturePath, forbidden)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, pricingAndUsageTrackingArchitecturePath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not call Dokploy from quota code",
		"Every customer-data query must be tenant-scoped",
		"fake Dokploy",
		"idempotency",
		"audit",
		"cross-tenant IDs",
		"internal/controlplane/entitlements",
		"internal/controlplane/metering",
		"internal/controlplane/billing",
		"quota.Checker",
		"entitlements.Resolver",
		"billing.ExportBatch",
		"UsageCounterRepository.AggregateUsageEvents",
		"dokploy_refs",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", pricingAndUsageTrackingArchitecturePath, want)
		}
	}
}

func TestPricingAndUsageTrackingArchitectureArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Pricing and usage tracking architecture artifact static tests",
				"go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Pricing and Usage Tracking Architecture Artifact",
				pricingAndUsageTrackingArchitecturePath,
				"go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact",
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
