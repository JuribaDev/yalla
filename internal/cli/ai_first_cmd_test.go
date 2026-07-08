package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestAPICall_DataAutoWrapsBody(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-create", "--data", `{"name":"smoke"}`, "--dry-run")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	var env struct {
		Data apiCallDryRunDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if got := string(env.Data.Body); !strings.Contains(got, `"name":"smoke"`) {
		t.Fatalf("body = %s, want auto-wrapped project body", got)
	}
}

func TestAPICall_InputAndDataConflict(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "project-create", "--input", "in.json", "--data", `{}`)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Fatalf("stderr = %q, want E_INVALID_INPUT", stderr)
	}
}

func TestAPICall_KnownComposeStopBugMapsToUpstreamBug(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"spawn /bin/sh ENOENT"}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "compose-stop", "--data", `{"composeId":"cmp_1"}`)
	if err == nil {
		t.Fatal("expected known issue error")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeUpstreamBug)) {
		t.Fatalf("stderr = %q, want E_UPSTREAM_BUG", stderr)
	}
}

func TestAPICall_ComposeCreateAppNameWarningAndStrictMode(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmp_1","name":"web","appName":"web-mutated"}`))
	})

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "compose-create", "--data", `{"name":"web","environmentId":"env_1","appName":"web"}`)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if !strings.Contains(stdout, "APPNAME_MUTATED") {
		t.Fatalf("stdout = %q, want mutation warning", stdout)
	}

	stdout, stderr, err = runRootArgs(t, "--json", "api", "call", "compose-create", "--data", `{"name":"web","environmentId":"env_1","appName":"web"}`, "--strict-appname")
	if err == nil {
		t.Fatal("expected strict appName failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Fatalf("stderr = %q, want E_INVALID_INPUT", stderr)
	}
}

func TestCompositeCommandsRegisteredInManifest(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	for _, want := range []string{"deploy", "teardown", "rescue", "wait", "audit"} {
		if !strings.Contains(stdout, `"path":"yalla `+want+`"`) {
			t.Fatalf("manifest missing %q: %s", want, stdout)
		}
	}
}
