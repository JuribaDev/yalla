package cli

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestServiceCreate_PostsBackendBuildConfig(t *testing.T) {
	var body map[string]any
	var seenPath string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"service":{"id":"svc_web"}}}`))
	})

	_, stderr, err := runRootArgs(t, "--json", "service", "create",
		"--environment-id", "env_test",
		"--service-id", "svc_web",
		"--name", "web",
		"--kind", "application",
		"--build-type", "static",
		"--repo", "https://github.com/example/web",
		"--branch", "main",
		"--output-dir", "dist")
	if err != nil {
		t.Fatalf("Execute: %v stderr=%s", err, stderr)
	}
	if seenPath != "/v1/environments/env_test/services" {
		t.Fatalf("path = %q", seenPath)
	}
	build, ok := body["build_config"].(map[string]any)
	if !ok {
		t.Fatalf("missing build_config in body: %+v", body)
	}
	if build["build_type"] != "static" || build["source_type"] != "git" {
		t.Fatalf("bad build config: %+v", build)
	}
}

func TestServiceDeploy_PostsBackendDeployment(t *testing.T) {
	var body map[string]string
	var seenPath string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"deployment":{"id":"dep_1"}}}`))
	})

	_, stderr, err := runRootArgs(t, "--json", "service", "deploy", "--service-id", "svc_web", "--idempotency-key", "test-key")
	if err != nil {
		t.Fatalf("Execute: %v stderr=%s", err, stderr)
	}
	if seenPath != "/v1/services/svc_web/deployments" {
		t.Fatalf("path = %q", seenPath)
	}
	if body["idempotency_key"] != "test-key" || body["source"] != "manual" {
		t.Fatalf("bad body: %+v", body)
	}
}
