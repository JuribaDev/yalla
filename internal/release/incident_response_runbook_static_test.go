package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const incidentResponseRunbookPath = "docs/operations/incident-response.md"

func TestIncidentResponseRunbookArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, incidentResponseRunbookPath))

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
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", incidentResponseRunbookPath, want)
		}
	}
}

func TestIncidentResponseRunbookArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, incidentResponseRunbookPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"operator-managed",
		"Customers must never receive Dokploy API tokens",
		"must not print database URLs",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
		"redacted",
		"support.manage",
		"break-glass",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", incidentResponseRunbookPath, want)
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
		if strings.Contains(strings.ToLower(runbook), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", incidentResponseRunbookPath, forbidden)
		}
	}
}

func TestIncidentResponseRunbookArtifactDocumentsHealthReadinessAndLogs(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, incidentResponseRunbookPath))

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
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", incidentResponseRunbookPath, want)
		}
	}
}

func TestIncidentResponseRunbookArtifactDocumentsTriageAndRecovery(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, incidentResponseRunbookPath))

	for _, want := range []string{
		"Incident severity",
		"Initial containment",
		"Customer-impacting API incident",
		"Provisioning worker incident",
		"Postgres incident",
		"Dokploy dependency incident",
		"Secret exposure incident",
		"restore rehearsal",
		"post-incident review",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", incidentResponseRunbookPath, want)
		}
	}
}

func TestIncidentResponseRunbookArtifactDocumentsVerification(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, incidentResponseRunbookPath))

	for _, want := range []string{
		"curl -fsS http://127.0.0.1:8080/healthz",
		"curl -fsS http://127.0.0.1:8080/readyz",
		"curl -fsS http://127.0.0.1:8080/version",
		"go test ./internal/release/... -run TestIncidentResponseRunbookArtifact",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", incidentResponseRunbookPath, want)
		}
	}
}

func TestIncidentResponseRunbookArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestIncidentResponseRunbookArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Incident response runbook artifact static tests",
				"go test ./internal/release/... -run TestIncidentResponseRunbookArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Incident Response Runbook Artifact",
				incidentResponseRunbookPath,
				"go test ./internal/release/... -run TestIncidentResponseRunbookArtifact",
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
