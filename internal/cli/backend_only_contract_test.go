package cli

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
)

const backendOpenAPIFixture = `{
  "openapi": "3.1.0",
  "info": {"title": "Yalla Control Plane API", "version": "0.0.0-test"},
  "servers": [{"url": "/"}],
  "components": {
    "securitySchemes": {"ApiKeyAuth": {"type": "http", "scheme": "bearer"}}
  },
  "security": [{"ApiKeyAuth": []}],
  "paths": {
    "/v1/me": {
      "get": {
        "operationId": "getMe",
        "tags": ["identity"],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/v1/services/{service_id}/deployments": {
      "post": {
        "operationId": "createServiceDeployment",
        "tags": ["deployments"],
        "parameters": [{"name":"service_id","in":"path","required":true,"schema":{"type":"string"}}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type":"object"}}}},
        "responses": {"202": {"description": "accepted"}}
      }
    }
  }
}`

func setupBackendServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(config.EnvBaseURL, srv.URL)
	t.Setenv(config.EnvToken, "test-yalla-token")
	return srv
}

func TestAPICall_RawDokployExecutorUnsupported(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://api.yalla.example")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-create", "--data", `{"name":"x"}`)
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	if stdout != "" {
		t.Fatalf("stdout should be empty on error, got %q", stdout)
	}
	if !strings.Contains(stderr, "E_UNSUPPORTED") {
		t.Fatalf("stderr missing E_UNSUPPORTED: %s", stderr)
	}
	if strings.Contains(stderr, "secret-token-value") {
		t.Fatalf("token leaked: %s", stderr)
	}
}

func TestAPIOperations_FetchesBackendOpenAPI(t *testing.T) {
	var seenAuth, seenAPIKey string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		if r.URL.Path != "/openapi.json" {
			t.Fatalf("path = %s, want /openapi.json", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(backendOpenAPIFixture))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "operations")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if seenAuth != "Bearer test-yalla-token" {
		t.Fatalf("Authorization = %q, want bearer token", seenAuth)
	}
	if seenAPIKey != "" {
		t.Fatalf("x-api-key must not be sent, got %q", seenAPIKey)
	}
	var env struct {
		Data apiOperationsDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.SpecTitle != "Yalla Control Plane API" || env.Data.Total != 2 {
		t.Fatalf("unexpected operations payload: %+v", env.Data)
	}
}

func TestSchemaGet_UsesBackendOpenAPI(t *testing.T) {
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(backendOpenAPIFixture))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "schema", "get", "createServiceDeployment")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if !strings.Contains(stdout, `"operation_id":"createServiceDeployment"`) {
		t.Fatalf("schema output did not include backend operation: %s", stdout)
	}
}

func TestDeployCompose_PostsBackendDeployment(t *testing.T) {
	var seenBody map[string]string
	var seenPath, seenAuth, seenAPIKey string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"deployment":{"id":"dep_1","status":"queued"},"job_id":"job_1"}}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "deploy", "compose", "--service-id", "svc_1", "--source", "git", "--source-ref", "main", "--idempotency-key", "idem_1")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if seenPath != "/v1/services/svc_1/deployments" {
		t.Fatalf("path = %q", seenPath)
	}
	if seenAuth != "Bearer test-yalla-token" || seenAPIKey != "" {
		t.Fatalf("bad auth headers: authorization=%q x-api-key=%q", seenAuth, seenAPIKey)
	}
	if seenBody["source"] != "git" || seenBody["source_ref"] != "main" || seenBody["idempotency_key"] != "idem_1" {
		t.Fatalf("bad request body: %+v", seenBody)
	}
	if !strings.Contains(stdout, `"dep_1"`) {
		t.Fatalf("stdout missing backend deployment: %s", stdout)
	}
}

func TestTeardownProject_DeletesBackendProject(t *testing.T) {
	var seenPath, seenMethod, seenAPIKey string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"project":{"id":"prj_1","status":"deleting"},"job_id":"job_1"}}`))
	})

	_, stderr, err := runRootArgs(t, "--json", "teardown", "project", "--project-id", "prj_1")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if seenMethod != http.MethodDelete || seenPath != "/v1/projects/prj_1" {
		t.Fatalf("request = %s %s", seenMethod, seenPath)
	}
	if seenAPIKey != "" {
		t.Fatalf("x-api-key must not be sent, got %q", seenAPIKey)
	}
}

func TestWaitJob_PollsBackendJob(t *testing.T) {
	attempts := 0
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		status := "running"
		if attempts == 2 {
			status = "succeeded"
		}
		_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"job":{"id":"job_1","status":"` + status + `"}}}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "wait", "job", "--job-id", "job_1", "--status", "succeeded", "--interval", "1ms", "--timeout", "1s")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if !strings.Contains(stdout, `"succeeded"`) {
		t.Fatalf("stdout missing final status: %s", stdout)
	}
}

func TestDatabaseCommandsUseBackendRoutes(t *testing.T) {
	var seen []string
	var seenAuth, seenAPIKey string
	setupBackendServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		seenAuth = r.Header.Get(api.HeaderAuthorization)
		seenAPIKey = r.Header.Get(api.DefaultAPIKeyHeader)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/environments/env_1/services":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create service: %v", err)
			}
			if body["service_id"] != "svc_db" || body["slug"] != "postgres" || body["kind"] != "database" {
				t.Fatalf("bad create body: %+v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"service":{"id":"svc_db","kind":"database","slug":"postgres"}}}`))
		case "POST /v1/services/svc_db/deployments":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"deployment":{"id":"dep_db","status":"queued"}}}`))
		case "GET /v1/environments/env_1/services":
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"services":[{"id":"svc_db","kind":"database"},{"id":"svc_app","kind":"application"}]}}`))
		case "POST /v1/services/svc_db/backups":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"backup":{"id":"sbkp_1","service_id":"svc_db","status":"pending"}}}`))
		case "POST /v1/services/svc_db/backups/sbkp_1/run":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"backup":{"id":"sbkp_1","service_id":"svc_db","status":"pending"},"job_id":"job_run"}}`))
		case "POST /v1/services/svc_db/backups/sbkp_1/restore":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"backup":{"id":"sbkp_1","service_id":"svc_db","status":"succeeded"},"job_id":"job_restore"}}`))
		case "GET /v1/jobs/job_run", "GET /v1/jobs/job_restore":
			_, _ = w.Write([]byte(`{"schema_version":"yalla.output.v1","data":{"job":{"id":"` + r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] + `","status":"succeeded"}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	commands := [][]string{
		{"--json", "database", "create", "--environment-id", "env_1", "--service-id", "svc_db", "--name", "postgres", "--deploy"},
		{"--json", "database", "list", "--environment-id", "env_1"},
		{"--json", "database", "backup", "create", "--service-id", "svc_db", "--backup-id", "sbkp_1", "--display-name", "nightly", "--schedule", "0 2 * * *"},
		{"--json", "database", "backup", "run", "--service-id", "svc_db", "--backup-id", "sbkp_1", "--wait", "--poll-interval", "1ms"},
		{"--json", "database", "backup", "restore", "--service-id", "svc_db", "--backup-id", "sbkp_1", "--wait", "--poll-interval", "1ms"},
	}
	for _, args := range commands {
		stdout, stderr, err := runRootArgs(t, args...)
		if err != nil {
			t.Fatalf("%v failed: %v stderr=%s", args, err, stderr)
		}
		if stdout == "" {
			t.Fatalf("%v wrote empty stdout", args)
		}
	}
	if seenAuth != "Bearer test-yalla-token" || seenAPIKey != "" {
		t.Fatalf("bad auth headers: authorization=%q x-api-key=%q", seenAuth, seenAPIKey)
	}
	want := []string{
		"POST /v1/environments/env_1/services",
		"POST /v1/services/svc_db/deployments",
		"GET /v1/environments/env_1/services",
		"POST /v1/services/svc_db/backups",
		"POST /v1/services/svc_db/backups/sbkp_1/run",
		"GET /v1/jobs/job_run",
		"POST /v1/services/svc_db/backups/sbkp_1/restore",
		"GET /v1/jobs/job_restore",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %#v, want %#v", seen, want)
	}
}

func TestRescueIsUnsupportedNotDirectDokploy(t *testing.T) {
	for _, args := range [][]string{{"--json", "rescue", "orphans"}} {
		stdout, stderr, err := runRootArgs(t, args...)
		if err == nil {
			t.Fatalf("%v unexpectedly succeeded", args)
		}
		if stdout != "" {
			t.Fatalf("%v wrote stdout on error: %q", args, stdout)
		}
		if !strings.Contains(stderr, "E_UNSUPPORTED") {
			t.Fatalf("%v stderr missing E_UNSUPPORTED: %s", args, stderr)
		}
	}
}

func TestNormalCLIHasNoDirectDokployImports(t *testing.T) {
	root, err := os.OpenRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	}()
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := root.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), `internal/dokploy`) {
			t.Fatalf("%s imports internal/dokploy", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
