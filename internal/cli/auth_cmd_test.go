package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestAuthStatus_JSONReportsReadyWhenConfigured(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	var env struct {
		SchemaVersion string        `json:"schema_version"`
		Data          authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if !env.Data.Ready {
		t.Errorf("ready = false; want true (token + base_url both set)")
	}
	if !env.Data.Token.Set {
		t.Error("token.set = false; want true")
	}
	if env.Data.Token.Value != "" {
		t.Errorf("token value leaked into JSON: %q", env.Data.Token.Value)
	}
	if env.Data.Token.Source != config.SourceEnv {
		t.Errorf("token.source = %q, want %q", env.Data.Token.Source, config.SourceEnv)
	}
	if env.Data.BaseURL.Value != "https://dokploy.example.com" {
		t.Errorf("base_url value = %q", env.Data.BaseURL.Value)
	}
	if env.Data.Reason != "" {
		t.Errorf("reason = %q, want empty when ready", env.Data.Reason)
	}
}

func TestAuthStatus_JSONReportsNotReadyWhenTokenMissing(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")

	stdout, stderr, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Ready {
		t.Error("ready = true; want false (token missing)")
	}
	if env.Data.Token.Set {
		t.Error("token.set = true; want false")
	}
	if !strings.Contains(env.Data.Reason, "E_AUTH") {
		t.Errorf("reason = %q, want to mention E_AUTH", env.Data.Reason)
	}
}

func TestAuthStatus_JSONReportsNotReadyWhenBaseURLMissing(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, _, err := runRootArgs(t, "--json", "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data authStatusDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Ready {
		t.Error("ready = true; want false (base_url missing)")
	}
	if !strings.Contains(env.Data.Reason, "E_CONFIG") {
		t.Errorf("reason = %q, want to mention E_CONFIG", env.Data.Reason)
	}
}

func TestAuthStatus_HumanNeverEchoesToken(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "supersecret-token-value")

	stdout, stderr, err := runRootArgs(t, "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, "supersecret-token-value") {
		t.Errorf("token leaked: %q", combined)
	}
	if !strings.Contains(stdout, "configured") {
		t.Errorf("expected token line to read 'configured'; got %q", stdout)
	}
	if !strings.Contains(stdout, "ready: yes") {
		t.Errorf("expected ready line; got %q", stdout)
	}
}

func TestAuthStatus_HumanWithoutTokenSaysNotReady(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")

	stdout, _, err := runRootArgs(t, "auth", "status")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout, "ready: no") {
		t.Errorf("expected 'ready: no'; got %q", stdout)
	}
	if !strings.Contains(stdout, "not set") {
		t.Errorf("expected 'not set' for missing token; got %q", stdout)
	}
}

func TestAuthStatus_NoInputDoesNotPrompt(t *testing.T) {
	withTempConfig(t, "")
	streams, stdout, _ := testStreams()
	streams.In = blockingReader{}
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--no-input", "--json", "auth", "status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("expected JSON output on stdout")
	}
}
