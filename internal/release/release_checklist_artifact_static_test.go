package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const releaseChecklistPath = "docs/operations/release-checklist.md"

func TestReleaseChecklistArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"correlation_id",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", releaseChecklistPath, want)
		}
	}
}

func TestReleaseChecklistArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"operator-managed",
		"least-privilege",
		"Customers must never receive Dokploy API tokens",
		"redacted `YALLA_*` variable",
		"must never contain",
		"tokens, API keys, cookies, database URLs, Dokploy tokens",
		"request bodies",
		"response bodies",
		"<redacted:YALLA_DATABASE_URL>",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", releaseChecklistPath, want)
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
		if strings.Contains(strings.ToLower(checklist), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", releaseChecklistPath, forbidden)
		}
	}
}

func TestReleaseChecklistArtifactDocumentsReleaseGates(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"scripts/verify.sh --release",
		"go test ./internal/release/... -run TestReleaseChecklistArtifact",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", releaseChecklistPath, want)
		}
	}
}

func TestReleaseChecklistArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"## Expected outputs",
		"PASS",
		"ok  github.com/juribadev/yalla",
		"service=yalla-api",
		"service=yalla-worker",
		"schema_version\":\"yalla.output.v1",
		"schema_version\":\"yalla.error.v1",
		"\"ok\":true",
		"\"request_id\":\"req_",
		"\"api_schema_version\"",
		"\"migration_version\"",
		"\"checks\"",
		"Never copy the full rendered output into release notes",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing expected-output guidance %q", releaseChecklistPath, want)
		}
	}
}

func TestReleaseChecklistArtifactDocumentsHealthReadinessLogsAndMigration(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"kubectl kustomize deploy/kubernetes",
		"kubectl apply --dry-run=server -f deploy/kubernetes/yalla-control-plane.yaml",
		"systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service",
		"deploy/operations/migrate-database.sh --dry-run",
		"deploy/operations/migrate-database.sh --apply",
		"/usr/local/bin/yalla-api --migrate-only",
		"/healthz",
		"/readyz",
		"/version",
		"/metrics",
		"database",
		"migrations",
		"queue",
		"Dokploy",
		"structured JSON",
		"journalctl -u yalla-api -u yalla-worker -o json",
		"kubectl logs deploy/yalla-api",
		"kubectl logs deploy/yalla-worker",
		"dead-letter alerts",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", releaseChecklistPath, want)
		}
	}
}

func TestReleaseChecklistArtifactDocumentsExternalSmokeGuard(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, releaseChecklistPath))

	for _, want := range []string{
		"Normal release gates must never require a live Dokploy server",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", releaseChecklistPath, want)
		}
	}
}

func TestReleaseChecklistArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestReleaseChecklistArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Release checklist artifact static tests",
				"go test ./internal/release/... -run TestReleaseChecklistArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Release Checklist Artifact",
				releaseChecklistPath,
				"go test ./internal/release/... -run TestReleaseChecklistArtifact",
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
