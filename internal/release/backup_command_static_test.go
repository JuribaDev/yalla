package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const backupCommandPath = "deploy/operations/backup-database.sh"

func TestBackupCommandArtifactDefinesSafeOperatorCommand(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, backupCommandPath))

	for _, want := range []string{
		"set -euo pipefail",
		`ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"`,
		`API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"`,
		`WORKER_BIN="${YALLA_WORKER_BIN:-/usr/local/bin/yalla-worker}"`,
		`PG_DUMP_BIN="${YALLA_PG_DUMP_BIN:-pg_dump}"`,
		`STATUS_FILE="${YALLA_BACKUP_STATUS_FILE:-}"`,
		`BACKUP_DIR="${YALLA_BACKUP_DIR:-/var/backups/yalla-control-plane}"`,
		"--format=custom",
		"--no-acl",
		"--no-owner",
		"--compress=9",
		"flock",
		"mktemp",
		"mv",
		"/healthz",
		"/readyz",
		"/healthz/backup",
		"structured JSON",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing %q", backupCommandPath, want)
		}
	}
	if strings.Contains(script, "yk_") || strings.Contains(script, "Bearer ") {
		t.Fatalf("%s must not bake API keys or bearer tokens", backupCommandPath)
	}
}

func TestBackupCommandKeepsSecretsRuntimeOnly(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, backupCommandPath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"YALLA_DOKPLOY_TOKEN=",
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
		"YALLA_DATABASE_URL=",
		"YALLA_BACKUP_BUCKET_KEY=",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("%s must not contain rendered secret-shaped value or assignment %q", backupCommandPath, forbidden)
		}
	}
	for _, want := range []string{
		"YALLA_DATABASE_URL",
		"YALLA_BACKUP_STATUS_FILE",
		"YALLA_BACKUP_DIR",
		"<redacted>",
		"env | sed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing secret-safe handling marker %q", backupCommandPath, want)
		}
	}
}

func TestBackupCommandDocumentationAndGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "deploy/operations/README.md",
			want: []string{
				"deploy/operations/backup-database.sh --dry-run",
				"sudo deploy/operations/backup-database.sh --apply",
				"pg_dump --format=custom --no-acl --no-owner --compress=9",
				"/usr/local/bin/yalla-api",
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
				"go test ./internal/release/... -run TestBackupCommand",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Backup command artifact static tests",
				"go test ./internal/release/... -run TestBackupCommand",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Backup Command Artifact",
				"deploy/operations/backup-database.sh",
				"go test ./internal/release/... -run TestBackupCommand",
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
