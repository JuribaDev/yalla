package cli

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestEnvironmentCreate_PostsBackendProjectEnvironment(t *testing.T) {
	var body map[string]string
	var seenPath string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"environment":{"id":"env_test"}}}`))
	})

	_, stderr, err := runRootArgs(t, "--json", "environment", "create", "--project-id", "proj_test", "--environment-id", "env_test", "--name", "production")
	if err != nil {
		t.Fatalf("Execute: %v stderr=%s", err, stderr)
	}
	if seenPath != "/v1/projects/proj_test/environments" {
		t.Fatalf("path = %q", seenPath)
	}
	if body["environment_id"] != "env_test" || body["slug"] != "production" || body["kind"] != "standard" {
		t.Fatalf("bad body: %+v", body)
	}
}
