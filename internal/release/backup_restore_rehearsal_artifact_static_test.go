package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const backupRestoreRehearsalArtifactPath = "docs/operations/backup-restore.md"

func TestBackupRestoreRehearsalArtifactDocumentsRehearsalScope(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, backupRestoreRehearsalArtifactPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"RTO",
		"RPO",
		"every quarter",
		"rehearsal",
		"throwaway",
		"YALLA_REHEARSAL_DATABASE_URL",
		"pg_restore",
		"--migrate-only",
		"canary",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", backupRestoreRehearsalArtifactPath, want)
		}
	}
}

func TestBackupRestoreRehearsalArtifactDocumentsCommandsEnvironmentAndOutputs(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, backupRestoreRehearsalArtifactPath))

	for _, want := range []string{
		"pg_restore --clean --if-exists",
		"yalla-api --migrate-only",
		"scripts/canary.sh",
		"deploy/operations/restore-rehearsal.sh --apply --snapshot",
		"YALLA_REHEARSAL_DATABASE_URL",
		"YALLA_PROFILE",
		"YALLA_BACKUP_STATUS_FILE",
		"YALLA_BACKUP_MAX_AGE",
		"GET /healthz/backup",
		"\"schema_version\": \"yalla.output.v1\"",
		"\"schema_version\": \"yalla.error.v1\"",
		"\"request_id\": \"req_",
		"configured",
		"fresh",
		"last_success_at",
		"age_seconds",
		"max_age_seconds",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", backupRestoreRehearsalArtifactPath, want)
		}
	}
}

func TestBackupRestoreRehearsalArtifactDocumentsFailureRecoveryAndRedaction(t *testing.T) {
	root := projectRoot(t)
	runbook := readTextFile(t, filepath.Join(root, backupRestoreRehearsalArtifactPath))

	for _, want := range []string{
		"Open an incident",
		"Freeze writes",
		"Provision a fresh database",
		"Restore the snapshot",
		"Replay WAL",
		"Apply migrations",
		"Smoke-test",
		"Switch traffic",
		"Resume workers",
		"Emit audit event",
		"Close the incident",
		"redacted",
		"**never** write secrets",
		"Postgres DSN, signing keys, Dokploy token",
		"rendered",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("%s missing %q", backupRestoreRehearsalArtifactPath, want)
		}
	}
	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer yk_",
		"api-key-",
		"dokploy-service-token",
		"cookie:",
		"password:",
	} {
		if strings.Contains(strings.ToLower(runbook), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", backupRestoreRehearsalArtifactPath, forbidden)
		}
	}
}

func TestBackupRestoreRehearsalArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestBackupRestoreRehearsalArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Backup restore rehearsal artifact static tests",
				"go test ./internal/release/... -run TestBackupRestoreRehearsalArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Backup Restore Rehearsal Artifact",
				backupRestoreRehearsalArtifactPath,
				"go test ./internal/release/... -run TestBackupRestoreRehearsalArtifact",
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
