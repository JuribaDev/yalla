package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const rollbackChecklistPath = "docs/operations/rollback-checklist.md"

func TestRollbackChecklistArtifactDocumentsRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

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
			t.Fatalf("%s missing %q", rollbackChecklistPath, want)
		}
	}
}

func TestRollbackChecklistArtifactDocumentsLeastPrivilegeAndSecrets(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"YALLA_BACKUP_STATUS_FILE=<redacted:YALLA_BACKUP_STATUS_FILE>",
		"YALLA_REHEARSAL_DATABASE_URL=<redacted:YALLA_REHEARSAL_DATABASE_URL>",
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
			t.Fatalf("%s missing %q", rollbackChecklistPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", rollbackChecklistPath, forbidden)
		}
	}
}

func TestRollbackChecklistArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

	for _, want := range []string{
		"## Expected outputs",
		"PASS",
		"ok  github.com/juribadev/yalla",
		"active",
		"service=yalla-api",
		"service=yalla-worker",
		"schema_version\":\"yalla.output.v1",
		"schema_version\":\"yalla.error.v1",
		"\"ok\":true",
		"\"request_id\":\"req_",
		"\"api_schema_version\"",
		"\"migration_version\"",
		"\"checks\"",
		"Never copy the full rendered output into rollback notes",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing expected-output guidance %q", rollbackChecklistPath, want)
		}
	}
}

func TestRollbackChecklistArtifactDocumentsRollbackSafety(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

	for _, want := range []string{
		"deploy/operations/backup-database.sh --dry-run",
		"deploy/operations/restore-rehearsal.sh --dry-run",
		"deploy/operations/migrate-database.sh --dry-run",
		"/usr/local/bin/yalla-api --migrate-only",
		"fresh encrypted backup",
		"restore rehearsal",
		"reversible",
		"do not run ad hoc SQL snippets",
		"pause `yalla-worker`",
		"durable job state",
		"dead-letter alerts",
		"fix forward",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", rollbackChecklistPath, want)
		}
	}
}

func TestRollbackChecklistArtifactDocumentsHealthReadinessAndLogs(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

	for _, want := range []string{
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
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", rollbackChecklistPath, want)
		}
	}
}

func TestRollbackChecklistArtifactDocumentsVerification(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, rollbackChecklistPath))

	for _, want := range []string{
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"go test ./internal/release/... -run TestRollbackChecklistArtifact",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", rollbackChecklistPath, want)
		}
	}
}

func TestRollbackChecklistArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestRollbackChecklistArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Rollback checklist artifact static tests",
				"go test ./internal/release/... -run TestRollbackChecklistArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Rollback Checklist Artifact",
				rollbackChecklistPath,
				"go test ./internal/release/... -run TestRollbackChecklistArtifact",
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
