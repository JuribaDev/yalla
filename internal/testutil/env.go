package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JuribaDev/yalla/internal/config"
)

// allYallaEnvVars is the canonical set of env vars the yalla loader honours.
// Adding or renaming one is a public-API change; reflect it here so the
// harness scrubs the host environment from every test that uses it.
var allYallaEnvVars = []string{
	config.EnvBaseURL,
	config.EnvToken,
	config.EnvConfig,
	config.EnvOutput,
	config.EnvNoInput,
}

// IsolateEnv unsets every YALLA_* env var for the duration of the test. It
// is the foundation of every test that reads env vars: a developer with
// YALLA_TOKEN exported in their shell would otherwise see flaky JSON
// envelopes and, occasionally, a real token leaking into a buffer.
//
// IsolateEnv uses t.Setenv with an empty value followed by os.Unsetenv via
// t.Cleanup so the env is restored even if the test panics. Tests that mix
// this with t.Parallel must understand that t.Setenv forbids parallelism.
func IsolateEnv(t testing.TB) {
	t.Helper()
	tt, ok := t.(interface {
		Setenv(key, value string)
	})
	if !ok {
		t.Fatalf("IsolateEnv requires a *testing.T or *testing.B")
	}
	for _, key := range allYallaEnvVars {
		// t.Setenv forbids t.Parallel — that is documented in the
		// AGENTS.md and surfaces here as a clear stack on misuse.
		tt.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}

// SetEnv applies the provided key/value pairs via t.Setenv, restoring the
// previous values automatically when the test ends. Empty values are
// translated to os.Unsetenv so callers can clear a single variable cleanly.
func SetEnv(t testing.TB, kv map[string]string) {
	t.Helper()
	tt, ok := t.(interface {
		Setenv(key, value string)
	})
	if !ok {
		t.Fatalf("SetEnv requires a *testing.T or *testing.B")
	}
	for k, v := range kv {
		tt.Setenv(k, v)
		if v == "" {
			_ = os.Unsetenv(k)
		}
	}
}

// WriteTempConfig creates a YAML config file inside a temp directory and
// exports its path as $YALLA_CONFIG so the loader picks it up without the
// caller having to thread `--config` through every assertion. The returned
// path is also useful for direct file assertions.
//
// An empty contents string is allowed and skips the write — the file path is
// still populated so the loader treats it as "missing on disk", which is
// the documented "works out of the box" behaviour.
func WriteTempConfig(t testing.TB, contents string) string {
	t.Helper()
	tt, ok := t.(interface {
		TempDir() string
		Setenv(key, value string)
	})
	if !ok {
		t.Fatalf("WriteTempConfig requires a *testing.T or *testing.B")
	}
	dir := tt.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("seed config: %v", err)
		}
	}
	tt.Setenv(config.EnvConfig, path)
	return path
}
