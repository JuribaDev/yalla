package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const sloDocumentArtifactPath = "docs/operations/slo.md"

func TestSLODocumentArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, sloDocumentArtifactPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"private Dokploy API",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"correlation_id",
		"GET /metrics",
		"data.slo_burn_rates",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", sloDocumentArtifactPath, want)
		}
	}
}

func TestSLODocumentArtifactDocumentsObjectivesAndEscalation(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, sloDocumentArtifactPath))

	for _, want := range []string{
		"API availability",
		"API latency",
		"Provisioning job completion",
		"Backup freshness",
		"Audit durability",
		"Error budget policy",
		"1h",
		"6h",
		"24h",
		"page",
		"ticket",
		"freeze non-urgent releases",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", sloDocumentArtifactPath, want)
		}
	}
}

func TestSLODocumentArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, sloDocumentArtifactPath))

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
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", sloDocumentArtifactPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", sloDocumentArtifactPath, forbidden)
		}
	}
}

func TestSLODocumentArtifactDocumentsHealthReadinessAndLogs(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, sloDocumentArtifactPath))

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
		"dead-letter alerts",
		"readiness degradation",
		"policy decision",
		"audit event",
		"secret-redaction canaries",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", sloDocumentArtifactPath, want)
		}
	}
}

func TestSLODocumentArtifactDocumentsVerification(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, sloDocumentArtifactPath))

	for _, want := range []string{
		"curl -fsS http://127.0.0.1:8080/healthz",
		"curl -fsS http://127.0.0.1:8080/readyz",
		"curl -fsS http://127.0.0.1:8080/version",
		"curl -fsS http://127.0.0.1:8080/metrics",
		"go test ./internal/release/... -run TestSLODocumentArtifact",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", sloDocumentArtifactPath, want)
		}
	}
}

func TestSLODocumentArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestSLODocumentArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"SLO document artifact static tests",
				"go test ./internal/release/... -run TestSLODocumentArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## SLO Document Artifact",
				sloDocumentArtifactPath,
				"go test ./internal/release/... -run TestSLODocumentArtifact",
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
