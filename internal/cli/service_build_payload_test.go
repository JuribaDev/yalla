package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceBuildPayloadValidatesStaticOutputDir(t *testing.T) {
	_, err := buildConfigPayload(serviceBuildFlags{BuildType: "static", Repo: "https://github.com/example/web"})
	if err == nil {
		t.Fatal("expected missing output-dir validation error")
	}
}

func TestServiceBuildPayloadImage(t *testing.T) {
	got, err := buildConfigPayload(serviceBuildFlags{BuildType: "image", Image: "ghcr.io/example/web:latest", Port: 8080})
	if err != nil {
		t.Fatalf("buildConfigPayload: %v", err)
	}
	if got["build_type"] != "image" || got["source_type"] != "image" {
		t.Fatalf("bad payload: %+v", got)
	}
}

func TestServiceBuildPayloadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.yaml")
	err := os.WriteFile(path, []byte(`
build_config:
  build_type: dockerfile
  source_type: git
  source:
    repo: https://github.com/example/api
  config:
    context: .
    dockerfile: Dockerfile
`), 0o600)
	if err != nil {
		t.Fatalf("write spec: %v", err)
	}

	got, err := buildConfigPayload(serviceBuildFlags{FromFile: path})
	if err != nil {
		t.Fatalf("buildConfigPayload: %v", err)
	}
	if got["build_type"] != "dockerfile" || got["source_type"] != "git" {
		t.Fatalf("bad payload: %+v", got)
	}
}
