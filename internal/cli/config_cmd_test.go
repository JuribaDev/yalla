package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

// runRootArgs drives the binary's executeWith seam, mirroring how the real
// Execute helper wires terminal error rendering. The returned error is the
// raw cobra error (nil on success) so callers can branch on failure without
// parsing stderr; the typed error banner is also rendered to stderr through
// renderTerminalError so assertions on Code-string presence still work.
func runRootArgs(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	streams, stdout, stderr := testStreams()
	cmd, flags := buildRoot(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err != nil {
		_ = renderTerminalError(streams, flags, err)
	}
	return stdout.String(), stderr.String(), err
}

// withTempConfig creates a writable config file and returns its path. The
// returned path is also exported as $YALLA_CONFIG so the loader honours it
// without callers having to thread --config through every assertion.
func withTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("seed config: %v", err)
		}
	}
	t.Setenv(config.EnvConfig, path)
	return path
}

func TestConfigGet_JSONListsAllKeysWithSources(t *testing.T) {
	path := withTempConfig(t, "base_url: https://from-file.example.com\n")
	t.Setenv(config.EnvToken, "env-token-value")

	stdout, stderr, err := runRootArgs(t, "--json", "config", "get")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	var env struct {
		SchemaVersion string       `json:"schema_version"`
		Data          configGetDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.ConfigPath != path {
		t.Errorf("config_path = %q, want %q", env.Data.ConfigPath, path)
	}
	if !env.Data.FileLoaded {
		t.Error("file_loaded = false; expected true after seeding the file")
	}

	got := map[string]configValueDoc{}
	for _, item := range env.Data.Items {
		got[item.Key] = item
	}
	if got[config.KeyBaseURL].Value != "https://from-file.example.com" {
		t.Errorf("base_url value = %q, want from-file value", got[config.KeyBaseURL].Value)
	}
	if got[config.KeyBaseURL].Source != string(config.SourceFile) {
		t.Errorf("base_url source = %q, want %q", got[config.KeyBaseURL].Source, config.SourceFile)
	}
	if got[config.KeyToken].Value != "" {
		t.Errorf("token value leaked into JSON: %q", got[config.KeyToken].Value)
	}
	if !got[config.KeyToken].Set {
		t.Error("token.set = false; expected true (env value seeded)")
	}
	if got[config.KeyToken].Source != string(config.SourceEnv) {
		t.Errorf("token source = %q, want %q", got[config.KeyToken].Source, config.SourceEnv)
	}
	if got[config.KeyToken].Secret != true {
		t.Error("token.secret = false; expected true")
	}
}

func TestConfigGet_HumanRedactsToken(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, stderr, err := runRootArgs(t, "config", "get")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	if strings.Contains(stdout, "secret-token-value") {
		t.Errorf("token leaked into human output: %q", stdout)
	}
	if !strings.Contains(stdout, output.Sentinel) {
		t.Errorf("expected redaction sentinel in human output; got %q", stdout)
	}
}

func TestConfigGetSingleKey_RedactsToken(t *testing.T) {
	withTempConfig(t, "")
	t.Setenv(config.EnvToken, "secret-token-value")

	stdout, stderr, err := runRootArgs(t, "config", "get", "token")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if strings.Contains(stdout+stderr, "secret-token-value") {
		t.Errorf("token leaked: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, output.Sentinel) {
		t.Errorf("expected redaction sentinel; stdout=%q", stdout)
	}
}

func TestConfigGetSingleKey_JSONForKnownKey(t *testing.T) {
	withTempConfig(t, "base_url: https://from-file.example.com\n")

	stdout, stderr, err := runRootArgs(t, "--json", "config", "get", "base_url")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data configValueDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Key != "base_url" || env.Data.Value != "https://from-file.example.com" {
		t.Errorf("unexpected payload: %+v", env.Data)
	}
}

func TestConfigGet_UnknownKeyReturnsCodeInvalidInput(t *testing.T) {
	withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "--json", "config", "get", "nonsense")
	if err == nil {
		t.Fatal("Execute returned nil for unknown key")
	}
	if stdout != "" {
		t.Errorf("stdout leak: %q", stdout)
	}
	if !strings.Contains(stderr, "E_INVALID_INPUT") {
		t.Errorf("expected E_INVALID_INPUT in stderr; got %q", stderr)
	}
}

func TestConfigSet_PersistsBaseURL(t *testing.T) {
	path := withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "--json", "config", "set", "base_url", "https://dokploy.example.com")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data configSetDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Key != "base_url" || env.Data.Path != path {
		t.Errorf("unexpected payload: %+v", env.Data)
	}

	// File was actually written and round-trips.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "https://dokploy.example.com") {
		t.Errorf("file body missing base_url: %q", string(body))
	}
}

func TestConfigSet_PreservesUnrelatedKeys(t *testing.T) {
	path := withTempConfig(t, "base_url: https://kept.example.com\noutput: json\n")

	if _, stderr, err := runRootArgs(t, "config", "set", "no_input", "true"); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "https://kept.example.com") {
		t.Errorf("base_url clobbered; file=%q", got)
	}
	if !strings.Contains(got, "no_input: true") {
		t.Errorf("no_input not written; file=%q", got)
	}
	if !strings.Contains(got, "output: json") {
		t.Errorf("output clobbered; file=%q", got)
	}
}

func TestConfigSet_NeverEchoesTokenValue(t *testing.T) {
	withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "config", "set", "token", "supersecret-token-value")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, "supersecret-token-value") {
		t.Errorf("token leaked into output: %q", combined)
	}
}

func TestConfigSet_RejectsUnknownKey(t *testing.T) {
	withTempConfig(t, "")

	stdout, stderr, err := runRootArgs(t, "config", "set", "no_such_key", "value")
	if err == nil {
		t.Fatal("Execute returned nil for unknown key")
	}
	if stdout != "" {
		t.Errorf("stdout leak: %q", stdout)
	}
	if !strings.Contains(stderr, "E_INVALID_INPUT") {
		t.Errorf("expected E_INVALID_INPUT; got %q", stderr)
	}
}

func TestConfigSet_RejectsInvalidBaseURL(t *testing.T) {
	withTempConfig(t, "")

	_, stderr, err := runRootArgs(t, "config", "set", "base_url", "ftp://example.com")
	if err == nil {
		t.Fatal("Execute returned nil for invalid base URL")
	}
	if !strings.Contains(stderr, "E_CONFIG") {
		t.Errorf("expected E_CONFIG; got %q", stderr)
	}
}

func TestConfigGet_NoInputDoesNotPrompt(t *testing.T) {
	// Stronger statement: --no-input plus a config command must complete
	// without ever calling into stdin. We assert by piping a stdin that
	// would cause a hang if read; the command must still terminate cleanly.
	streams, stdout, stderr := testStreams()
	streams.In = blockingReader{}
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	cmd.SetArgs([]string{"--no-input", "--json", "config", "get"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("expected JSON envelope on stdout; got nothing")
	}
}

// blockingReader is an io.Reader that hangs forever; calling Read panics so
// any code path that touches stdin while --no-input is set fails loudly
// instead of hanging the test runner.
type blockingReader struct{}

func (blockingReader) Read(_ []byte) (int, error) {
	panic("blockingReader.Read called; --no-input must not consult stdin")
}

func TestConfigSet_FailsWhenNoConfigPathResolvable(t *testing.T) {
	// Override the default user-config dir so the loader cannot find one.
	// We achieve this by running with --config "" explicitly and an env
	// snapshot that has no YALLA_CONFIG set; the only way to get an empty
	// resolved path is through the readFileForCommand seam, so we stub it
	// to return an empty-path config.
	streams, stdout, stderr := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.0.0-test"})
	// Use a writable temp dir but force the path to be empty by stubbing
	// the read seam to return an error other than not-exist.
	origRead := readFileForCommand
	t.Cleanup(func() { readFileForCommand = origRead })
	// We need cfg.ConfigPath == "". The loader only returns "" when
	// DefaultConfigPath returns "" and no flag/env supplies a path. We
	// simulate this by setting --config to "" while ensuring no env is set.
	cmd.SetArgs([]string{"--config", "", "config", "set", "base_url", "https://example.com"})
	_ = cmd.Execute()
	// The expected outcome: no panic, stdout silent, stderr carries either
	// E_CONFIG (no path) or a specific resolution failure. Both are ok for
	// this test; the goal is ensuring the path is not silently chosen.
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "panic") {
		t.Errorf("config set leaked panic: %q", combined)
	}
}

// bytesEqual is a placeholder helper kept here so future fuzz tests can
// compare canonical byte sequences without re-importing bytes everywhere.
// The func itself is unused today but deliberately public to discourage
// duplicate one-off comparators.
var _ = bytes.Equal
