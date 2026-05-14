package config

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// strictEnv is a fully-populated environment that satisfies the staging and
// production profiles. Tests clone and mutate it to exercise individual
// failure paths.
func strictEnv() map[string]string {
	return map[string]string{
		EnvProfile:        "production",
		EnvAPIAddr:        ":9090",
		EnvPublicURL:      "https://api.yalla.example",
		EnvDatabaseURL:    "postgres://yalla:s3cr3t@db.internal:5432/yalla",
		EnvSigningKeys:    "primary-signing-key-aaaa,rotated-signing-key-bb",
		EnvDokployBaseURL: "https://dokploy.internal",
		EnvDokployToken:   "dokploy-service-token-zzzz",
		EnvLogLevel:       "info",
		EnvFeatureFlags:   "billing,preview=false",
	}
}

func TestLoadSuccessProduction(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Profile != ProfileProduction {
		t.Errorf("profile = %q, want production", cfg.Profile)
	}
	if cfg.APIAddr != ":9090" {
		t.Errorf("api addr = %q, want :9090", cfg.APIAddr)
	}
	if cfg.PublicURL != "https://api.yalla.example" {
		t.Errorf("public url = %q", cfg.PublicURL)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("log level = %v, want info", cfg.LogLevel)
	}
	if got := cfg.ActiveSigningKey(); got != "primary-signing-key-aaaa" {
		t.Errorf("active signing key = %q", got)
	}
	if len(cfg.SigningKeys) != 2 {
		t.Errorf("signing keys = %d, want 2", len(cfg.SigningKeys))
	}
	if !cfg.FeatureEnabled("billing") {
		t.Errorf("billing flag should be enabled")
	}
	if cfg.FeatureEnabled("preview") {
		t.Errorf("preview flag should be disabled")
	}
	if cfg.FeatureEnabled("unknown") {
		t.Errorf("unknown flag should default to disabled")
	}
}

func TestLoadDefaultsToLocalProfile(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(map[string]string{
		EnvDatabaseURL: "postgresql://localhost:5432/yalla_dev",
	}))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Profile != ProfileLocal {
		t.Errorf("profile = %q, want local", cfg.Profile)
	}
	if cfg.APIAddr != ":8080" {
		t.Errorf("api addr = %q, want :8080 default", cfg.APIAddr)
	}
	if cfg.PublicURL != "http://localhost:8080" {
		t.Errorf("public url = %q, want local default", cfg.PublicURL)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("log level = %v, want debug default for local", cfg.LogLevel)
	}
}

func TestLoadLocalAndTestAllowMissingSecrets(t *testing.T) {
	t.Parallel()

	for _, profile := range []string{"local", "test"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{EnvProfile: profile}
			if profile == "local" {
				// local still needs a database; test does not.
				env[EnvDatabaseURL] = "postgres://localhost:5432/yalla"
			}
			cfg, err := Load(MapLookup(env))
			if err != nil {
				t.Fatalf("Load(%s) returned error: %v", profile, err)
			}
			if cfg.DokployToken != "" {
				t.Errorf("expected empty dokploy token in %s profile", profile)
			}
		})
	}
}

func TestLoadValidationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantSub string
	}{
		{
			name:    "invalid profile",
			mutate:  func(e map[string]string) { e[EnvProfile] = "prod" },
			wantSub: "invalid " + EnvProfile,
		},
		{
			name:    "invalid log level",
			mutate:  func(e map[string]string) { e[EnvLogLevel] = "trace" },
			wantSub: "invalid " + EnvLogLevel,
		},
		{
			name:    "invalid listen addr",
			mutate:  func(e map[string]string) { e[EnvAPIAddr] = "not-an-addr:::" },
			wantSub: EnvAPIAddr,
		},
		{
			name:    "invalid public url",
			mutate:  func(e map[string]string) { e[EnvPublicURL] = "ftp://bad" },
			wantSub: EnvPublicURL,
		},
		{
			name:    "invalid dokploy url",
			mutate:  func(e map[string]string) { e[EnvDokployBaseURL] = "://broken" },
			wantSub: EnvDokployBaseURL,
		},
		{
			name:    "invalid database scheme",
			mutate:  func(e map[string]string) { e[EnvDatabaseURL] = "mysql://db:3306/yalla" },
			wantSub: "scheme must be postgres",
		},
		{
			name:    "short signing key",
			mutate:  func(e map[string]string) { e[EnvSigningKeys] = "tooshort" },
			wantSub: "too short",
		},
		{
			name:    "bad feature flag value",
			mutate:  func(e map[string]string) { e[EnvFeatureFlags] = "billing=maybe" },
			wantSub: EnvFeatureFlags,
		},
		{
			name:    "empty feature flag name",
			mutate:  func(e map[string]string) { e[EnvFeatureFlags] = "=true" },
			wantSub: EnvFeatureFlags,
		},
		{
			name:    "invalid shutdown timeout",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "soon" },
			wantSub: EnvShutdownTimeout,
		},
		{
			name:    "shutdown timeout too small",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "0s" },
			wantSub: "out of range",
		},
		{
			name:    "shutdown timeout too large",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "10m" },
			wantSub: "out of range",
		},
		{
			name: "strict profile missing fields",
			mutate: func(e map[string]string) {
				delete(e, EnvDatabaseURL)
				delete(e, EnvDokployToken)
			},
			wantSub: "requires",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := strictEnv()
			tt.mutate(env)

			_, err := Load(MapLookup(env))
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", tt.wantSub)
			}
			var typed *yerr.Error
			if !stderrors.As(err, &typed) {
				t.Fatalf("error is not *yerr.Error: %T", err)
			}
			if typed.Code != yerr.CodeConfig {
				t.Errorf("error code = %q, want %q", typed.Code, yerr.CodeConfig)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestValidationErrorsNeverEchoSecrets is the redaction guarantee: a
// validation failure on a secret-bearing field must not include the secret
// value in the error string.
func TestValidationErrorsNeverEchoSecrets(t *testing.T) {
	t.Parallel()

	const secretDSN = "postgres://user:SUPERSECRETPW@db/yalla?sslmode=require"
	env := strictEnv()
	env[EnvDatabaseURL] = "redis://" + "SUPERSECRETPW" + "@db" // invalid scheme, carries the secret
	_, err := Load(MapLookup(env))
	if err == nil {
		t.Fatal("expected validation error for bad database scheme")
	}
	if strings.Contains(err.Error(), "SUPERSECRETPW") {
		t.Errorf("validation error leaked secret: %q", err.Error())
	}
	_ = secretDSN
}

func TestRedactedHidesSecrets(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	r := cfg.Redacted()
	if r.DatabaseURL == cfg.DatabaseURL {
		t.Errorf("redacted database url equals raw value")
	}
	if strings.Contains(r.DatabaseURL, "s3cr3t") {
		t.Errorf("redacted database url leaked secret: %q", r.DatabaseURL)
	}
	if strings.Contains(r.DokployToken, "dokploy-service-token") {
		t.Errorf("redacted dokploy token leaked secret: %q", r.DokployToken)
	}
	if r.SigningKeysConfigured != 2 {
		t.Errorf("signing keys configured = %d, want 2", r.SigningKeysConfigured)
	}

	// JSON serialisation of the redacted view must not contain any secret.
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal redacted config: %v", err)
	}
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "rotated-signing-key", "dokploy-service-token"} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("redacted JSON leaked %q: %s", secret, blob)
		}
	}
}

// TestLogValueRedactsSecrets proves an accidental slog.Any("config", cfg)
// emits a scrubbed record.
func TestLogValueRedactsSecrets(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("startup", slog.Any("config", cfg))

	out := buf.String()
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "rotated-signing-key", "dokploy-service-token"} {
		if strings.Contains(out, secret) {
			t.Errorf("slog output leaked %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "production") {
		t.Errorf("slog output missing non-secret profile field: %s", out)
	}
}

// TestStringRedactsSecrets proves fmt.Sprintf("%v", cfg) is safe.
func TestStringRedactsSecrets(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	s := cfg.String()
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "dokploy-service-token"} {
		if strings.Contains(s, secret) {
			t.Errorf("String() leaked %q: %s", secret, s)
		}
	}
}

func TestShutdownTimeoutResolution(t *testing.T) {
	t.Parallel()

	// Default applies when the variable is unset.
	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ShutdownTimeout != 25*time.Second {
		t.Errorf("default shutdown timeout = %s, want 25s", cfg.ShutdownTimeout)
	}

	// An explicit value overrides the profile default.
	env := strictEnv()
	env[EnvShutdownTimeout] = "45s"
	cfg, err = Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ShutdownTimeout != 45*time.Second {
		t.Errorf("override shutdown timeout = %s, want 45s", cfg.ShutdownTimeout)
	}

	// The local profile has its own default.
	cfg, err = Load(MapLookup(map[string]string{
		EnvDatabaseURL: "postgres://localhost:5432/yalla",
	}))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("local default shutdown timeout = %s, want 15s", cfg.ShutdownTimeout)
	}
}

func TestProfileHelpers(t *testing.T) {
	t.Parallel()

	if !ProfileProduction.IsStrict() || !ProfileStaging.IsStrict() {
		t.Errorf("staging and production must be strict")
	}
	if ProfileLocal.IsStrict() || ProfileTest.IsStrict() {
		t.Errorf("local and test must not be strict")
	}
	if Profile("nonsense").Valid() {
		t.Errorf("unknown profile must be invalid")
	}
}

func TestNilConfigSafety(t *testing.T) {
	t.Parallel()

	var c *Config
	if c.ActiveSigningKey() != "" {
		t.Errorf("nil config ActiveSigningKey should be empty")
	}
	if c.FeatureEnabled("x") {
		t.Errorf("nil config FeatureEnabled should be false")
	}
	if c.String() != "config<nil>" {
		t.Errorf("nil config String = %q", c.String())
	}
	if err := c.Validate(); err == nil {
		t.Errorf("nil config Validate should error")
	}
}
