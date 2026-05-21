package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
)

func TestProjectCreate_PostsBackendProject(t *testing.T) {
	var body map[string]string
	var seenPath, seenAuth, seenAPIKey string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"project":{"id":"proj_test"}}}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "project", "create", "--project-id", "proj_test", "--name", "test")
	if err != nil {
		t.Fatalf("Execute: %v stderr=%s", err, stderr)
	}
	if seenPath != "/v1/projects" || seenAuth != "Bearer test-yalla-token" || seenAPIKey != "" {
		t.Fatalf("bad request path/auth path=%q auth=%q api_key=%q", seenPath, seenAuth, seenAPIKey)
	}
	if body["project_id"] != "proj_test" || body["slug"] != "test" || body["display_name"] != "test" {
		t.Fatalf("bad body: %+v", body)
	}
	if !strings.Contains(stdout, `"proj_test"`) {
		t.Fatalf("stdout missing project: %s", stdout)
	}
}
