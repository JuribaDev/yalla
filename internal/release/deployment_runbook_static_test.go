package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const deploymentRunbookPath = "docs/operations/deployment.md"

func TestDeploymentRunbookArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, deploymentRunbookPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"deploy/config/control-plane.env.example",
		"/etc/yalla/control-plane.env",
		"root:yalla",
		"0640",
		"yalla-control-plane-secrets",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"private Dokploy API",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", deploymentRunbookPath, want)
		}
	}
}

func TestDeploymentRunbookArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, deploymentRunbookPath))

	for _, want := range []string{
		"Customers must never receive Dokploy API tokens",
		"secret outside the repository",
		"redacted `YALLA_*` variable",
		"must not print database URLs",
		"must never contain database URLs",
		"request bodies",
		"response bodies",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", deploymentRunbookPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", deploymentRunbookPath, forbidden)
		}
	}
}

func TestDeploymentRunbookArtifactDocumentsHealthReadinessAndLogs(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, deploymentRunbookPath))

	for _, want := range []string{
		"/healthz",
		"/readyz",
		"/version",
		"database",
		"migrations",
		"queue",
		"Dokploy",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"structured JSON",
		"journalctl -u yalla-api -u yalla-worker -o json",
		"kubectl logs deploy/yalla-api",
		"kubectl logs deploy/yalla-worker",
		"dead-letter alerts",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", deploymentRunbookPath, want)
		}
	}
}

func TestDeploymentRunbookArtifactDocumentsVerification(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, deploymentRunbookPath))

	for _, want := range []string{
		"kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml",
		"kubectl kustomize deploy/kubernetes",
		"systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service",
		"deploy/operations/migrate-database.sh --dry-run",
		"deploy/operations/migrate-database.sh --apply",
		"/usr/local/bin/yalla-api --migrate-only",
		"go test ./internal/release/... -run TestDeploymentRunbookArtifact",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", deploymentRunbookPath, want)
		}
	}
}

func TestDeploymentRunbookArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestDeploymentRunbookArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Deployment runbook artifact static tests",
				"go test ./internal/release/... -run TestDeploymentRunbookArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Deployment Runbook Artifact",
				deploymentRunbookPath,
				"go test ./internal/release/... -run TestDeploymentRunbookArtifact",
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
