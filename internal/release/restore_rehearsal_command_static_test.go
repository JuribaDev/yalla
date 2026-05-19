package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const restoreRehearsalCommandPath = "deploy/operations/restore-rehearsal.sh"

func TestRestoreRehearsalCommandArtifactDefinesSafeOperatorCommand(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, restoreRehearsalCommandPath))

	for _, want := range []string{
		"set -euo pipefail",
		`ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"`,
		`API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"`,
		`WORKER_BIN="${YALLA_WORKER_BIN:-/usr/local/bin/yalla-worker}"`,
		`PG_RESTORE_BIN="${YALLA_PG_RESTORE_BIN:-pg_restore}"`,
		`REHEARSAL_DATABASE_URL="${YALLA_REHEARSAL_DATABASE_URL:-}"`,
		`REPORT_DIR="${YALLA_RESTORE_REHEARSAL_REPORT_DIR:-/var/log/yalla/restore-rehearsals}"`,
		"--clean",
		"--if-exists",
		"--no-owner",
		"--no-acl",
		"--jobs",
		"--migrate-only",
		"flock",
		"mktemp",
		"mv",
		"/healthz",
		"/readyz",
		"/healthz/backup",
		"structured JSON",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing %q", restoreRehearsalCommandPath, want)
		}
	}
	if strings.Contains(script, "yk_") || strings.Contains(script, "Bearer ") {
		t.Fatalf("%s must not bake API keys or bearer tokens", restoreRehearsalCommandPath)
	}
}

func TestRestoreRehearsalCommandKeepsSecretsRuntimeOnly(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, restoreRehearsalCommandPath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"YALLA_DOKPLOY_TOKEN=",
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
		"YALLA_DATABASE_URL=",
		"YALLA_REHEARSAL_DATABASE_URL=",
		"YALLA_BACKUP_BUCKET_KEY=",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("%s must not contain rendered secret-shaped value or assignment %q", restoreRehearsalCommandPath, forbidden)
		}
	}
	for _, want := range []string{
		"YALLA_REHEARSAL_DATABASE_URL",
		"YALLA_RESTORE_SNAPSHOT",
		"YALLA_RESTORE_REHEARSAL_REPORT_DIR",
		"<redacted>",
		"env | sed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing secret-safe handling marker %q", restoreRehearsalCommandPath, want)
		}
	}
}

func TestRestoreRehearsalCommandDocumentationAndGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "deploy/operations/README.md",
			want: []string{
				"deploy/operations/restore-rehearsal.sh --dry-run --snapshot",
				"sudo deploy/operations/restore-rehearsal.sh --apply --snapshot",
				"pg_restore --clean --if-exists --no-owner --no-acl --jobs",
				"/usr/local/bin/yalla-api --migrate-only",
				"/usr/local/bin/yalla-worker",
				"/healthz",
				"/readyz",
				"/healthz/backup",
				"yalla.output.v1",
				"yalla.error.v1",
				"structured JSON",
			},
		},
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestRestoreRehearsalCommand",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Restore rehearsal command artifact static tests",
				"go test ./internal/release/... -run TestRestoreRehearsalCommand",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Restore Rehearsal Command Artifact",
				"deploy/operations/restore-rehearsal.sh",
				"go test ./internal/release/... -run TestRestoreRehearsalCommand",
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
