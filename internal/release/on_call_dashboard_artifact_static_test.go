package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const onCallDashboardArtifactPath = "docs/operations/on-call-dashboard.md"

func TestOnCallDashboardArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	dashboard := readTextFile(t, filepath.Join(root, onCallDashboardArtifactPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"private Dokploy API",
		"GET /dashboards/control-plane.json",
		"GET /metrics",
		"yalla.dashboard.v1",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"correlation_id",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("%s missing %q", onCallDashboardArtifactPath, want)
		}
	}
}

func TestOnCallDashboardArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	dashboard := readTextFile(t, filepath.Join(root, onCallDashboardArtifactPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"operator-managed",
		"Customers must never receive Dokploy API tokens",
		"least-privilege",
		"read-only",
		"must not print database URLs",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
		"redacted",
		"support.manage",
		"break-glass",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("%s missing %q", onCallDashboardArtifactPath, want)
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
		if strings.Contains(strings.ToLower(dashboard), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", onCallDashboardArtifactPath, forbidden)
		}
	}
}

func TestOnCallDashboardArtifactDocumentsPanelsAndIncidentFlows(t *testing.T) {
	root := projectRoot(t)
	dashboard := readTextFile(t, filepath.Join(root, onCallDashboardArtifactPath))

	for _, want := range []string{
		"API availability",
		"Readiness degradation",
		"HTTP error budget",
		"Provisioning worker",
		"Dead-letter alerts",
		"Reconciliation drift",
		"Dokploy dependency",
		"Policy decisions",
		"Audit events",
		"Secret-redaction canaries",
		"SLO burn-rate",
		"Slow queries",
		"Trace spans",
		"Customer-impacting API incident",
		"Provisioning worker incident",
		"Secret exposure incident",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("%s missing %q", onCallDashboardArtifactPath, want)
		}
	}
}

func TestOnCallDashboardArtifactDocumentsHealthReadinessAndLogs(t *testing.T) {
	root := projectRoot(t)
	dashboard := readTextFile(t, filepath.Join(root, onCallDashboardArtifactPath))

	for _, want := range []string{
		"/healthz",
		"/readyz",
		"/version",
		"database",
		"migrations",
		"queue",
		"Dokploy",
		"structured JSON",
		"journalctl -u yalla-api -u yalla-worker -o json",
		"kubectl logs deploy/yalla-api",
		"kubectl logs deploy/yalla-worker",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("%s missing %q", onCallDashboardArtifactPath, want)
		}
	}
}

func TestOnCallDashboardArtifactDocumentsVerification(t *testing.T) {
	root := projectRoot(t)
	dashboard := readTextFile(t, filepath.Join(root, onCallDashboardArtifactPath))

	for _, want := range []string{
		"curl -fsS http://127.0.0.1:8080/healthz",
		"curl -fsS http://127.0.0.1:8080/readyz",
		"curl -fsS http://127.0.0.1:8080/version",
		"curl -fsS http://127.0.0.1:8080/dashboards/control-plane.json",
		"curl -fsS http://127.0.0.1:8080/metrics",
		"go test ./internal/release/... -run TestOnCallDashboardArtifact",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("%s missing %q", onCallDashboardArtifactPath, want)
		}
	}
}

func TestOnCallDashboardArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestOnCallDashboardArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"On-call dashboard artifact static tests",
				"go test ./internal/release/... -run TestOnCallDashboardArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## On-Call Dashboard Artifact",
				onCallDashboardArtifactPath,
				"go test ./internal/release/... -run TestOnCallDashboardArtifact",
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
