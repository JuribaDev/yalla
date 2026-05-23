package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const configExamplePath = "deploy/config/control-plane.env.example"

func TestConfigExamplesArtifactDefinesProductionRuntimeContract(t *testing.T) {
	root := projectRoot(t)
	envExample := readTextFile(t, filepath.Join(root, configExamplePath))

	for _, want := range []string{
		"YALLA_PROFILE=production",
		"YALLA_API_ADDR=127.0.0.1:8080",
		"YALLA_PUBLIC_URL=https://api.example.com",
		"YALLA_DATABASE_URL=<redacted:postgres-dsn>",
		"YALLA_SIGNING_KEYS=<redacted:signing-keys>",
		"YALLA_SECRET_KEYS=<redacted:secret-keys>",
		"YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example.com",
		"YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"YALLA_INTERNAL_WORKER_TOKEN=<redacted:internal-worker-token>",
		"YALLA_BACKUP_STATUS_FILE=/var/lib/yalla/backup.status",
		"YALLA_BACKUP_MAX_AGE=26h",
		"YALLA_LOG_LEVEL=info",
		"YALLA_SHUTDOWN_TIMEOUT=30s",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"/healthz",
		"/readyz",
		"structured JSON",
	} {
		if !strings.Contains(envExample, want) {
			t.Fatalf("%s missing %q", configExamplePath, want)
		}
	}
}

func TestConfigExamplesArtifactKeepsSecretsAsPlaceholders(t *testing.T) {
	root := projectRoot(t)
	envExample := readTextFile(t, filepath.Join(root, configExamplePath))

	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer ",
		"api-key-",
		"cookie:",
		"password:",
		"dokploy-service-token",
	} {
		if strings.Contains(strings.ToLower(envExample), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", configExamplePath, forbidden)
		}
	}
	for _, assignment := range strings.Split(envExample, "\n") {
		assignment = strings.TrimSpace(assignment)
		if assignment == "" || strings.HasPrefix(assignment, "#") {
			continue
		}
		key, value, ok := strings.Cut(assignment, "=")
		if !ok {
			t.Fatalf("%s has malformed assignment %q", configExamplePath, assignment)
		}
		if isSecretShapedEnvName(key) && !strings.HasPrefix(value, "<redacted:") {
			t.Fatalf("%s assigns secret-shaped %s without a redacted placeholder", configExamplePath, key)
		}
	}
}

func TestConfigExamplesArtifactDocumentationAndGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "deploy/config/README.md",
			want: []string{
				"deploy/config/control-plane.env.example",
				"/etc/yalla/control-plane.env",
				"root:yalla",
				"0640",
				"/usr/local/bin/yalla-api",
				"/usr/local/bin/yalla-worker",
				"/healthz",
				"/readyz",
				"yalla.output.v1",
				"yalla.error.v1",
				"structured JSON",
				"go test ./internal/release/... -run TestConfigExamplesArtifact",
			},
		},
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestConfigExamplesArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Config example artifact static tests",
				"go test ./internal/release/... -run TestConfigExamplesArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Config Example Files Artifact",
				"deploy/config/control-plane.env.example",
				"go test ./internal/release/... -run TestConfigExamplesArtifact",
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
