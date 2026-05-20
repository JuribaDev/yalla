package release_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestContainerGoVersionsMatchModuleToolchain(t *testing.T) {
	t.Parallel()

	root := projectRoot(t)
	want := goToolchainVersion(t, filepath.Join(root, "go.mod"))
	for _, file := range []string{"Dockerfile", "Dockerfile.worker"} {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		re := regexp.MustCompile(`(?m)^ARG\s+GO_VERSION=([^\s]+)\s*$`)
		match := re.FindStringSubmatch(string(data))
		if len(match) != 2 {
			t.Fatalf("%s must declare ARG GO_VERSION with a pinned default", file)
		}
		if match[1] != want {
			t.Fatalf("%s GO_VERSION = %q, want %q from go.mod toolchain", file, match[1], want)
		}
	}
}

func goToolchainVersion(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "toolchain" {
			return strings.TrimPrefix(fields[1], "go")
		}
	}
	t.Fatal("go.mod must declare a toolchain line")
	return ""
}
