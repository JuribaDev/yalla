package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDependencyReviewWorkflowIsBlocking(t *testing.T) {
	t.Parallel()

	src := readWorkflowSource(t, ".github/workflows/dependency-review.yml")
	if strings.Contains(src, "continue-on-error") {
		t.Fatal("dependency review workflow must be blocking; remove continue-on-error from the dependency-review step")
	}
}

func TestReleaseWorkflowHasProductionPreflightAndContainerGates(t *testing.T) {
	t.Parallel()

	src := readWorkflowSource(t, ".github/workflows/release.yml")
	required := []string{
		"preflight:",
		"name: Release preflight",
		"go mod tidy",
		"git diff --exit-code -- go.mod go.sum",
		"test -z \"$(gofmt -l .)\"",
		"go vet ./...",
		"go test ./...",
		"go test -race ./...",
		"govulncheck ./...",
		"staticcheck ./...",
		"golangci/golangci-lint-action@v7",
		"npm test",
		"npm audit --omit=dev",
		"containers:",
		"name: Build and sign containers",
		"docker/build-push-action@v6",
		"file: Dockerfile",
		"file: Dockerfile.worker",
		"provenance: true",
		"sbom: true",
		"sigstore/cosign-installer@v3",
		"cosign sign --yes",
		"needs:\n      - preflight\n      - containers",
		"Render Kubernetes manifest",
		"dist/yalla-control-plane-${GITHUB_REF_NAME}.yaml",
		"--include \"yalla-control-plane-*.yaml\"",
	}
	for _, want := range required {
		if !strings.Contains(src, want) {
			t.Errorf("release workflow missing %q", want)
		}
	}
}

func readWorkflowSource(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(projectRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}
