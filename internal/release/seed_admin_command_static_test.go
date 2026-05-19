package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const seedAdminCommandPath = "deploy/operations/seed-admin.sh"

func TestSeedAdminCommandArtifactDefinesSafeOperatorCommand(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, seedAdminCommandPath))

	for _, want := range []string{
		"set -euo pipefail",
		`ENV_FILE="${YALLA_CONTROL_PLANE_ENV_FILE:-/etc/yalla/control-plane.env}"`,
		`API_BIN="${YALLA_API_BIN:-/usr/local/bin/yalla-api}"`,
		`API_SERVICE="${YALLA_API_SERVICE:-yalla-api}"`,
		`WORKER_SERVICE="${YALLA_WORKER_SERVICE:-yalla-worker}"`,
		"--seed-admin",
		"--seed-admin-email",
		"--seed-admin-organization",
		"--seed-admin-role",
		"systemctl is-active",
		"/healthz",
		"/readyz",
		"structured JSON",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing %q", seedAdminCommandPath, want)
		}
	}
	if strings.Contains(script, "yk_") || strings.Contains(script, "Bearer ") {
		t.Fatalf("%s must not bake API keys or bearer tokens", seedAdminCommandPath)
	}
}

func TestSeedAdminCommandKeepsSecretsRuntimeOnly(t *testing.T) {
	root := projectRoot(t)
	script := readTextFile(t, filepath.Join(root, seedAdminCommandPath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"YALLA_DOKPLOY_TOKEN=",
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
		"YALLA_SEED_ADMIN_PASSWORD=",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("%s must not contain rendered secret-shaped value or assignment %q", seedAdminCommandPath, forbidden)
		}
	}
	for _, want := range []string{
		"YALLA_DATABASE_URL",
		"YALLA_SEED_ADMIN_EMAIL",
		"YALLA_SEED_ADMIN_ORGANIZATION",
		"<redacted>",
		"env | sed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing secret-safe handling marker %q", seedAdminCommandPath, want)
		}
	}
}

func TestSeedAdminCommandDocumentationAndGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "deploy/operations/README.md",
			want: []string{
				"deploy/operations/seed-admin.sh --dry-run",
				"sudo deploy/operations/seed-admin.sh --apply",
				"/usr/local/bin/yalla-api --seed-admin",
				"sudo systemctl is-active yalla-api",
				"sudo systemctl is-active yalla-worker",
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
				"go test ./internal/release/... -run TestSeedAdminCommand",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Seed admin command artifact static tests",
				"go test ./internal/release/... -run TestSeedAdminCommand",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Seed Admin Command Artifact",
				"deploy/operations/seed-admin.sh",
				"go test ./internal/release/... -run TestSeedAdminCommand",
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

func TestSeedAdminCommandBinarySupportsSeedAdmin(t *testing.T) {
	root := projectRoot(t)
	main := readTextFile(t, filepath.Join(root, "cmd/yalla-api/main.go"))
	for _, want := range []string{
		`BoolVar(&opts.seedAdmin, "seed-admin"`,
		`StringVar(&opts.seedAdminEmail, "seed-admin-email"`,
		`StringVar(&opts.seedAdminOrganization, "seed-admin-organization"`,
		`StringVar(&opts.seedAdminRole, "seed-admin-role"`,
		`runSeedAdminCommand(ctx, dataStore, logger, opts)`,
		`seed admin command completed`,
	} {
		if !strings.Contains(main, want) {
			t.Fatalf("cmd/yalla-api/main.go missing %q", want)
		}
	}
}
