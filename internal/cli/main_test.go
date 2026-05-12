package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/JuribaDev/yalla/internal/config"
)

// TestMain isolates the package's tests from the real process environment.
// Two side effects matter:
//
//  1. The config loader is environment-aware (YALLA_BASE_URL, YALLA_TOKEN,
//     YALLA_CONFIG, YALLA_OUTPUT, YALLA_NO_INPUT). A developer with any of
//     those set in their shell would otherwise see flaky test output,
//     unexpected reads from their real config file, and occasionally a real
//     token leaking into a test buffer.
//
//  2. The terminal error renderer also consults YALLA_OUTPUT and YALLA_TOKEN
//     via envSnapshotForRenderer to honour JSON mode and redaction at
//     parse-time. Pinning that snapshot to empty defaults keeps every test
//     deterministic regardless of how the test host is configured.
//
// Individual tests opt back into env-driven behaviour via t.Setenv plus a
// scoped override of envSnapshotForRenderer.
func TestMain(m *testing.M) {
	configDir, err := os.MkdirTemp("", "yalla-cli-test-*")
	for _, key := range []string{
		config.EnvBaseURL,
		config.EnvToken,
		config.EnvConfig,
		config.EnvOutput,
		config.EnvNoInput,
	} {
		_ = os.Unsetenv(key)
	}
	if err == nil {
		_ = os.Setenv(config.EnvConfig, filepath.Join(configDir, "config.yaml"))
	}
	envSnapshotForRenderer = func() config.EnvSnapshot {
		return config.EnvSnapshot{Output: config.OutputHuman}
	}
	keyring.MockInit()
	code := m.Run()
	if configDir != "" {
		_ = os.RemoveAll(configDir)
	}
	os.Exit(code)
}
