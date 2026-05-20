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
		"go test ./...",
		"go test -race ./internal/controlplane/...",
		"go test -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...",
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
				"./scripts/verify.sh --with-postgres",
			},
		},
		{
			path: "deploy/operations/README.md",
			want: []string{
				"Production Verification Path",
				"docker compose up -d postgres",
				"YALLA_TEST_DATABASE_URL",
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
