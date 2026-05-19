package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const observabilityDashboardGuidePath = "docs/development/observability-dashboard-guide.md"

func TestObservabilityDashboardGuideArtifactDocumentsReviewScope(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"Observability Dashboard Guide",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"Dokploy",
		"PostgreSQL",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
		}
	}
}

func TestObservabilityDashboardGuideArtifactDocumentsMetricSources(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"HTTP request metrics",
		"Trace spans",
		"Dokploy dependencies",
		"Quota usage",
		"Policy decisions",
		"Audit events",
		"Worker queue",
		"Reconciliation drift",
		"Dead-letter alerts",
		"SLO burn-rate",
		"Secret-redaction canaries",
		"Readiness degradation",
		"Slow queries",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
		}
	}
}

func TestObservabilityDashboardGuideArtifactDocumentsRequiredVariables(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"YALLA_DATABASE_URL",
		"YALLA_DOKPLOY_BASE_URL",
		"YALLA_DOKPLOY_TOKEN",
		"YALLA_LOG_LEVEL",
		"YALLA_FEATURE_FLAGS",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
		}
	}
}

func TestObservabilityDashboardGuideArtifactDocumentsVerificationCommands(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"go test ./internal/controlplane/telemetry/...",
		"go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact",
		"scripts/verify.sh",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
		}
	}
}

func TestObservabilityDashboardGuideArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"correlation_id",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
		}
	}
}

func TestObservabilityDashboardGuideArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, observabilityDashboardGuidePath))

	for _, want := range []string{
		"must not print database URLs",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
		"redacted",
		"failure recovery",
		"Normal verification gates must never require a live Dokploy server",
		"must never run against production",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", observabilityDashboardGuidePath, want)
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
		if strings.Contains(strings.ToLower(guide), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", observabilityDashboardGuidePath, forbidden)
		}
	}
}

func TestObservabilityDashboardGuideArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Observability dashboard guide artifact static tests",
				"go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Observability Dashboard Guide Artifact",
				observabilityDashboardGuidePath,
				"go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact",
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
