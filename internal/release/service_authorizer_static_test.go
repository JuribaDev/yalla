package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIDoesNotWireAlwaysAllowAuthorizer(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "cmd", "yalla-api", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(data), "alwaysAllowAuthorizer") {
		t.Fatal("cmd/yalla-api must not wire alwaysAllowAuthorizer in production")
	}
}
