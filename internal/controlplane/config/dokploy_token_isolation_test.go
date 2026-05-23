package config_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/output"
)

// BE-0361: Security verification — Dokploy token isolation.
//
// Runtime evidence half of the BE-0344 two-test pattern. The static
// half is internal/release/dokploy_token_isolation_static_test.go and
// pins the structural seams: the bare `c.DokployToken` selector cannot
// reach `Redacted()` or `LogValue()`, no customer-facing handler can
// reference the token-bearing dokploy.Client, and `Client.token`
// remains unexported. The runtime tests here close the loop by
// proving the operator-visible projections — Redacted() JSON marshal,
// LogValue() under a slog JSON handler, and the String() debug
// projection — never carry the bearer token's bytes for ANY of the
// three input shapes a regression would surface (the canonical
// short-token shape, a long token, and a token whose prefix collides
// with one of Yalla's other redacted fields).
//
// The marker pattern is intentional: the test installs a globally
// unique fixed prefix (`BE0361DOKPLOYTOKENMARKERXYZ`) on every token
// value. The leak detector asserts the marker never appears in the
// projection output, independent of the token's bytes. Asserting on
// the token bytes alone would false-positive whenever the token
// happens to equal a substring of the stable projection text (e.g.
// the field-name `dokploy_token` would mask a leak whose value
// contained the substring `token`). The marker is what makes the leak
// detector load-bearing under fuzzed inputs.

// dokployTokenMarker is the fixed prefix every token-bearing fixture
// inherits. It is alphanumeric, long enough to exceed
// `internal/output.Redactor`'s `minRedactableLen`, and contains the
// substring "MARKER" so its presence in any projection output
// unambiguously identifies a leak even if the surrounding bytes
// happen to look like a real token.
const dokployTokenMarker = "BE0361DOKPLOYTOKENMARKERXYZ"

// dokployTokenIsolationFixtures enumerates the three input shapes the
// runtime gate asserts on. Each fixture's `name` flows into a
// subtest name so a regression diagnostic identifies the exact shape
// that leaked; each fixture's `token` is the value bound to
// `Config.DokployToken`. The fixture set is intentionally small —
// the static gate carries the structural load — but every shape was
// chosen to surface a different class of regression:
//
//   - "short-token" exercises the canonical happy path,
//   - "long-token" exercises a token longer than the redactor's
//     sentinel and longer than any reasonable line-buffered slog
//     handler chunk, so a partial-flush leak would still surface,
//   - "collision-prefix" exercises a token whose first bytes match
//     the field name `dokploy_token` (a regression that wrote a
//     bare selector but happened to truncate at the field name would
//     still trip the marker check).
var dokployTokenIsolationFixtures = []struct {
	name  string
	token string
}{
	{
		name:  "short-token",
		token: dokployTokenMarker + "-short",
	},
	{
		name:  "long-token",
		token: dokployTokenMarker + "-" + strings.Repeat("zZ9", 64),
	},
	{
		name:  "collision-prefix",
		token: "dokploy_token-" + dokployTokenMarker + "-collide",
	},
}

// newDokployTokenIsolationConfig builds a minimal-but-valid Config
// suitable for exercising every operator-visible projection. The
// non-token fields are filled with deterministic placeholders so a
// regression that leaked the token via a sibling field (e.g. baking
// it into PublicURL) would still be caught by the marker check.
func newDokployTokenIsolationConfig(token string) *config.Config {
	return &config.Config{
		Profile:          config.ProfileProduction,
		APIAddr:          ":0",
		PublicURL:        "https://api.yalla.invalid",
		DatabaseURL:      "postgres://app:pw@db.invalid:5432/yalla",
		SigningKeys:      []string{strings.Repeat("0", 64), strings.Repeat("1", 64)},
		SecretKeys:       []string{strings.Repeat("a", 64)},
		DokployBaseURL:   "https://dokploy.invalid",
		DokployToken:     token,
		ShutdownTimeout:  10 * time.Second,
		BackupStatusFile: "/var/lib/yalla/backup.status",
		BackupMaxAge:     24 * time.Hour,
		LogLevel:         slog.LevelInfo,
		FeatureFlags:     map[string]bool{"experimental": false},
	}
}

// TestRuntimeConfigDokployTokenRedactionNeverLeaks proves the
// `(*Config).Redacted()` projection's `DokployToken` field equals the
// redaction sentinel exactly (bytes-equal, not just "does not
// contain"), and that a JSON encoding of the entire RedactedConfig
// carries neither the marker nor the raw token bytes. The
// bytes-equal assertion is strictly stronger than substring redaction
// checks: a regression that returned `"redacted-" + c.DokployToken`
// would still satisfy a "does not equal raw" check, but would fail
// the bytes-equal-to-sentinel check.
func TestRuntimeConfigDokployTokenRedactionNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, fx := range dokployTokenIsolationFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			cfg := newDokployTokenIsolationConfig(fx.token)
			r := cfg.Redacted()

			if r.DokployToken != output.Sentinel {
				t.Errorf("Redacted().DokployToken = %q; want exactly %q (bytes-equal). "+
					"A regression that returned `redacted-` + c.DokployToken would still satisfy a contains check; the bytes-equal assertion is the load-bearing one.",
					r.DokployToken, output.Sentinel)
			}

			payload, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("json.Marshal(Redacted): %v", err)
			}
			if bytes.Contains(payload, []byte(dokployTokenMarker)) {
				t.Errorf("Redacted JSON projection leaked the BE-0361 marker for fixture %q. "+
					"Projection bytes:\n  %s", fx.name, string(payload))
			}
			if bytes.Contains(payload, []byte(fx.token)) {
				t.Errorf("Redacted JSON projection leaked the raw DokployToken for fixture %q. "+
					"Projection bytes:\n  %s", fx.name, string(payload))
			}
		})
	}
}

// TestRuntimeConfigLogValueDokployTokenRedactionNeverLeaks proves an
// accidental `slog.Any("config", c)` capture cannot surface the
// Dokploy bearer token. The test routes a Config through the
// canonical slog JSON handler — the production wire format —
// asserting the marker and the raw token are both absent and the
// sentinel is present. A regression that emitted a bare
// `c.DokployToken` from `(*Config).LogValue()` would land the bytes
// in the structured log stream where operators expect redacted
// records.
func TestRuntimeConfigLogValueDokployTokenRedactionNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, fx := range dokployTokenIsolationFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			cfg := newDokployTokenIsolationConfig(fx.token)
			var buf bytes.Buffer
			// LevelDebug catches every future debug-level log line a
			// regression might add; a fixed handler avoids depending on
			// global slog state.
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
			slog.New(handler).Info("config snapshot", slog.Any("config", cfg))

			out := buf.Bytes()
			if bytes.Contains(out, []byte(dokployTokenMarker)) {
				t.Errorf("slog.Any(config, c) leaked the BE-0361 marker for fixture %q. "+
					"Slog output bytes:\n  %s", fx.name, string(out))
			}
			if bytes.Contains(out, []byte(fx.token)) {
				t.Errorf("slog.Any(config, c) leaked the raw DokployToken for fixture %q. "+
					"Slog output bytes:\n  %s", fx.name, string(out))
			}
			if !bytes.Contains(out, []byte(output.Sentinel)) {
				t.Errorf("slog.Any(config, c) produced no sentinel for fixture %q; "+
					"the redaction seam appears bypassed. Slog output bytes:\n  %s", fx.name, string(out))
			}
		})
	}
}

// TestRuntimeConfigStringDokployTokenRedactionNeverLeaks proves the
// `(*Config).String()` debug projection — used by `fmt.Sprintf`,
// `fmt.Errorf("config: %s", cfg)`, and any other Stringer consumer
// — never carries the bearer token's bytes. The static gate cannot
// inspect format verbs; the runtime test closes the gap by invoking
// the Stringer directly (which is the same code path
// `fmt.Sprintf("%s", cfg)` would call) and asserting the marker is
// absent.
func TestRuntimeConfigStringDokployTokenRedactionNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, fx := range dokployTokenIsolationFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			cfg := newDokployTokenIsolationConfig(fx.token)
			rendered := cfg.String()
			if strings.Contains(rendered, dokployTokenMarker) {
				t.Errorf("Config.String() leaked the BE-0361 marker for fixture %q. "+
					"String projection:\n  %s", fx.name, rendered)
			}
			if strings.Contains(rendered, fx.token) {
				t.Errorf("Config.String() leaked the raw DokployToken for fixture %q. "+
					"String projection:\n  %s", fx.name, rendered)
			}
		})
	}
}
