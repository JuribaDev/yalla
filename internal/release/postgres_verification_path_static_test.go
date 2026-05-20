package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresVerificationPathArtifactDocumentsScriptMode(t *testing.T) {
	root := projectRoot(t)
	verify := readTextFile(t, filepath.Join(root, "scripts/verify.sh"))

	for _, want := range []string{
		"--with-postgres",
		"YALLA_TEST_DATABASE_URL is required for --with-postgres",
		"YALLA_TEST_REDIS_URL is required for --with-postgres",
		"YALLA_POSTGRES_TEST_PARALLELISM",
		"YALLA_POSTGRES_TEST_TIMEOUT",
		"go test ./...",
		"go test -timeout \"$postgres_test_timeout\" -p \"$postgres_test_parallelism\" -parallel \"$postgres_test_parallelism\" ./...",
		"go test -timeout \"$postgres_test_timeout\" -p \"$postgres_test_parallelism\" -parallel \"$postgres_test_parallelism\" -race ./internal/controlplane/...",
		"go test -timeout \"$postgres_test_timeout\" -p \"$postgres_test_parallelism\" -parallel \"$postgres_test_parallelism\" -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...",
		"go test ./internal/controlplane/ratelimit/... -run TestRedisLimiter -count=1",
		"go vet ./...",
	} {
		if !strings.Contains(verify, want) {
			t.Fatalf("scripts/verify.sh missing %q", want)
		}
	}
}

func TestPostgresVerificationPathArtifactDocumentsRunbook(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "ralph/VERIFICATION.md",
			want: []string{
				"Database-backed loop",
				"docker compose up -d postgres",
				"YALLA_TEST_DATABASE_URL",
				"YALLA_TEST_REDIS_URL",
				"./scripts/verify.sh --with-postgres",
			},
		},
		{
			path: "deploy/operations/README.md",
			want: []string{
				"Production Verification Path",
				"docker compose up -d postgres",
				"YALLA_TEST_DATABASE_URL",
				"YALLA_TEST_REDIS_URL",
				"./scripts/verify.sh --with-postgres",
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
