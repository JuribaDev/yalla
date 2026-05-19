package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const databaseMigrationCommandPath = "deploy/operations/migrate-database.sh"

func TestDatabaseMigrationCommandArtifactDefinesSafeOperatorCommand(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, databaseMigrationCommandPath))

	for _, want := range []string{
		"set -euo pipefail",
		`ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"`,
		`API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"`,
		`WORKER_SERVICE="${YALLA_WORKER_SERVICE:-yalla-worker}"`,
		"--migrate-only",
		"systemctl stop",
		"systemctl start",
		"/healthz",
		"/readyz",
		"structured JSON",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing %q", databaseMigrationCommandPath, want)
		}
	}
	if strings.Contains(script, "/usr/local/bin/yalla-worker --migrate") {
		t.Fatalf("%s must not run migrations through the worker binary", databaseMigrationCommandPath)
	}
}

func TestDatabaseMigrationCommandKeepsSecretsRuntimeOnly(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, databaseMigrationCommandPath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer ",
		"YALLA_DOKPLOY_TOKEN=",
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("%s must not contain rendered secret-shaped value or assignment %q", databaseMigrationCommandPath, forbidden)
		}
	}
	for _, want := range []string{
		"YALLA_DATABASE_URL",
		"<redacted>",
		"env | sed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing secret-safe handling marker %q", databaseMigrationCommandPath, want)
		}
	}
}

func TestDatabaseMigrationCommandDocumentationAndGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "deploy/operations/README.md",
			want: []string{
				"deploy/operations/migrate-database.sh --dry-run",
				"deploy/operations/migrate-database.sh --apply",
				"/usr/local/bin/yalla-api --migrate-only",
				"sudo systemctl stop yalla-worker",
				"/healthz",
				"/readyz",
				"yalla.output.v1",
				"yalla.error.v1",
				"structured JSON",
			},
		},
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestDatabaseMigrationCommand",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Database migration command artifact static tests",
				"go test ./internal/release/... -run TestDatabaseMigrationCommand",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Database Migration Command Artifact",
				"deploy/operations/migrate-database.sh",
				"go test ./internal/release/... -run TestDatabaseMigrationCommand",
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

func TestDatabaseMigrationCommandBinarySupportsMigrateOnly(t *testing.T) {
	root := projectRoot(t)
	main := readTextFile(t, filepath.Join(root, "cmd/yalla-api/main.go"))
	for _, want := range []string{
		`BoolVar(&opts.migrateOnly, "migrate-only"`,
		`migrate.New(pool, logger)`,
		`migrator.Up(ctx)`,
		`migration command completed`,
	} {
		if !strings.Contains(main, want) {
			t.Fatalf("cmd/yalla-api/main.go missing %q", want)
		}
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
