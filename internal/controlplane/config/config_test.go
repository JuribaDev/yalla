package config

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"path/filepath"
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
		EnvProfile:             "production",
		EnvAPIAddr:             ":9090",
		EnvPublicURL:           "https://api.yalla.example",
		EnvDatabaseURL:         "postgres://yalla:s3cr3t@db.internal:5432/yalla",
		EnvSigningKeys:         "primary-signing-key-aaaa,rotated-signing-key-bb",
		EnvSecretKeys:          "0011223344556677889900112233445566778899001122334455667788990011,aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa",
		EnvDokployBaseURL:      "https://dokploy.internal",
		EnvDokployToken:        "dokploy-service-token-zzzz",
		EnvInternalWorkerToken: "internal-worker-token-0123456789abcdef",
		EnvRateLimitRedisURL:   "redis://redis.internal:6379/0",
		EnvLogLevel:            "info",
		EnvFeatureFlags:        "billing,preview=false",
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
	if cfg.InternalWorkerToken != "internal-worker-token-0123456789abcdef" {
		t.Errorf("internal worker token = %q, want configured fixture", cfg.InternalWorkerToken)
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
			if cfg.InternalWorkerToken != "" {
				t.Errorf("expected empty internal worker token in %s profile", profile)
			}
		})
	}
}

func TestHTTPTimeoutDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load strict env: %v", err)
	}
	if cfg.HTTPReadTimeout != 15*time.Second {
		t.Errorf("HTTPReadTimeout = %s, want 15s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout != 60*time.Second {
		t.Errorf("HTTPWriteTimeout = %s, want 60s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout != 120*time.Second {
		t.Errorf("HTTPIdleTimeout = %s, want 120s", cfg.HTTPIdleTimeout)
	}

	env := strictEnv()
	env[EnvHTTPReadTimeout] = "20s"
	env[EnvHTTPWriteTimeout] = "90s"
	env[EnvHTTPIdleTimeout] = "3m"
	cfg, err = Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load overridden env: %v", err)
	}
	if cfg.HTTPReadTimeout != 20*time.Second || cfg.HTTPWriteTimeout != 90*time.Second || cfg.HTTPIdleTimeout != 3*time.Minute {
		t.Fatalf("HTTP timeouts = %s/%s/%s, want 20s/90s/3m", cfg.HTTPReadTimeout, cfg.HTTPWriteTimeout, cfg.HTTPIdleTimeout)
	}
}

func TestTrustedProxyCIDRsDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load strict env: %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Fatalf("TrustedProxyCIDRs = %v, want empty default", cfg.TrustedProxyCIDRs)
	}

	env := strictEnv()
	env[EnvTrustedProxyCIDRs] = "10.42.0.0/16, 2001:db8::/32"
	cfg, err = Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load overridden env: %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("TrustedProxyCIDRs length = %d, want 2", len(cfg.TrustedProxyCIDRs))
	}
	if got := cfg.TrustedProxyCIDRs[0].String(); got != "10.42.0.0/16" {
		t.Errorf("TrustedProxyCIDRs[0] = %q, want 10.42.0.0/16", got)
	}
	if got := cfg.TrustedProxyCIDRs[1].String(); got != "2001:db8::/32" {
		t.Errorf("TrustedProxyCIDRs[1] = %q, want 2001:db8::/32", got)
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
			name:    "short internal worker token",
			mutate:  func(e map[string]string) { e[EnvInternalWorkerToken] = "tooshort" },
			wantSub: EnvInternalWorkerToken,
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
				delete(e, EnvInternalWorkerToken)
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
	if strings.Contains(r.InternalWorkerToken, "internal-worker-token") {
		t.Errorf("redacted internal worker token leaked secret: %q", r.InternalWorkerToken)
	}
	if r.SigningKeysConfigured != 2 {
		t.Errorf("signing keys configured = %d, want 2", r.SigningKeysConfigured)
	}

	// JSON serialisation of the redacted view must not contain any secret.
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal redacted config: %v", err)
	}
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "rotated-signing-key", "dokploy-service-token", "internal-worker-token"} {
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
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "rotated-signing-key", "dokploy-service-token", "internal-worker-token"} {
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
	for _, secret := range []string{"s3cr3t", "primary-signing-key", "dokploy-service-token", "internal-worker-token"} {
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

// TestRateLimitProfileDefaults pins the per-profile baseline: production
// and staging ship non-trivial limits; local is permissive; test disables
// the limiter so contract tests cannot trip it.
func TestRateLimitProfileDefaults(t *testing.T) {
	t.Parallel()

	cases := []struct {
		profile     string
		wantEnabled bool
	}{
		{"local", true},
		{"test", false},
		{"staging", true},
		{"production", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.profile, func(t *testing.T) {
			t.Parallel()
			env := strictEnv()
			env[EnvProfile] = tc.profile
			cfg, err := Load(MapLookup(env))
			if err != nil {
				t.Fatalf("Load %s: %v", tc.profile, err)
			}
			if got := cfg.RateLimit.AnyEnabled(); got != tc.wantEnabled {
				t.Errorf("%s RateLimit.AnyEnabled = %t, want %t", tc.profile, got, tc.wantEnabled)
			}
		})
	}
}

func TestRateLimitBackendDefaults(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	delete(env, EnvRateLimitRedisURL)
	_, err := Load(MapLookup(env))
	if err == nil {
		t.Fatal("production rate limiting without Redis URL succeeded, want config error")
	}
	if !strings.Contains(err.Error(), EnvRateLimitRedisURL) {
		t.Fatalf("error %q does not mention %s", err.Error(), EnvRateLimitRedisURL)
	}

	env[EnvRateLimitRedisURL] = "redis://redis.internal:6379/0"
	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load with Redis URL: %v", err)
	}
	if cfg.RateLimit.Backend != RateLimitBackendRedis {
		t.Fatalf("backend = %q, want %q", cfg.RateLimit.Backend, RateLimitBackendRedis)
	}
	if cfg.RateLimit.RedisURL != "redis://redis.internal:6379/0" {
		t.Fatalf("RedisURL = %q, want configured URL", cfg.RateLimit.RedisURL)
	}
	if cfg.RateLimit.RedisPrefix == "" {
		t.Fatal("RedisPrefix is empty")
	}
	if cfg.RateLimit.RedisTimeout <= 0 {
		t.Fatalf("RedisTimeout = %s, want positive duration", cfg.RateLimit.RedisTimeout)
	}

	local, err := Load(MapLookup(map[string]string{
		EnvProfile:     string(ProfileLocal),
		EnvDatabaseURL: "postgres://localhost:5432/yalla",
	}))
	if err != nil {
		t.Fatalf("Load local profile: %v", err)
	}
	if local.RateLimit.Backend != RateLimitBackendMemory {
		t.Fatalf("local backend = %q, want %q", local.RateLimit.Backend, RateLimitBackendMemory)
	}

	testCfg, err := Load(MapLookup(map[string]string{EnvProfile: string(ProfileTest)}))
	if err != nil {
		t.Fatalf("Load test profile: %v", err)
	}
	if testCfg.RateLimit.AnyEnabled() {
		t.Fatal("test profile rate limit should be disabled")
	}
}

// TestRateLimitEnvOverridesLayer proves a YALLA_RATE_LIMIT_* override
// replaces only the field it names; the rest of the profile baseline
// continues to apply.
func TestRateLimitEnvOverridesLayer(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	env[EnvRateLimitOrgReadRPS] = "5"
	env[EnvRateLimitOrgReadBurst] = "10"
	env[EnvRateLimitIdleTTL] = "30s"
	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.OrgReadRPS != 5 {
		t.Errorf("OrgReadRPS = %v, want 5", cfg.RateLimit.OrgReadRPS)
	}
	if cfg.RateLimit.OrgReadBurst != 10 {
		t.Errorf("OrgReadBurst = %d, want 10", cfg.RateLimit.OrgReadBurst)
	}
	if cfg.RateLimit.IdleTTL != 30*time.Second {
		t.Errorf("IdleTTL = %s, want 30s", cfg.RateLimit.IdleTTL)
	}
	// Unset knobs keep the production baseline (Org write spec stays set).
	if cfg.RateLimit.OrgWriteRPS == 0 {
		t.Error("OrgWriteRPS = 0, want profile baseline to remain set")
	}
}

// TestRateLimitDisableFlagTurnsLimiterOff proves the master disable
// switch overrides every spec, even when the per-dimension values are
// non-zero.
func TestRateLimitDisableFlagTurnsLimiterOff(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	env[EnvRateLimitDisabled] = "true"
	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.AnyEnabled() {
		t.Errorf("AnyEnabled = true with disable flag set")
	}
	if !cfg.RateLimit.Disabled {
		t.Errorf("Disabled = false, want true")
	}
}

// TestRateLimitInvalidValuesAreRejected proves the validator catches
// negative rates, oversized bursts, malformed durations, and a
// nonsense boolean — each surfaces a stable CodeConfig error.
func TestRateLimitInvalidValuesAreRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		key     string
		value   string
		wantSub string
	}{
		{"negative org RPS", EnvRateLimitOrgReadRPS, "-1", EnvRateLimitOrgReadRPS},
		{"oversized burst", EnvRateLimitKeyReadBurst, "5000000", EnvRateLimitKeyReadBurst},
		{"malformed duration", EnvRateLimitIdleTTL, "not-a-duration", EnvRateLimitIdleTTL},
		{"too-short ttl", EnvRateLimitIdleTTL, "1ms", EnvRateLimitIdleTTL},
		{"too-long ttl", EnvRateLimitIdleTTL, "2h", EnvRateLimitIdleTTL},
		{"malformed disable", EnvRateLimitDisabled, "maybe", EnvRateLimitDisabled},
		{"malformed int", EnvRateLimitIPReadBurst, "ten", EnvRateLimitIPReadBurst},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := strictEnv()
			env[tc.key] = tc.value
			_, err := Load(MapLookup(env))
			if err == nil {
				t.Fatalf("Load accepted invalid %s=%q", tc.key, tc.value)
			}
			var ye *yerr.Error
			if !stderrors.As(err, &ye) || ye.Code != yerr.CodeConfig {
				t.Errorf("error = %v, want CodeConfig", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestBackupConfigDefaultsToUnconfigured proves a strict-profile config
// without the optional YALLA_BACKUP_STATUS_FILE and YALLA_BACKUP_MAX_AGE
// variables loads cleanly with empty backup state. The
// GET /healthz/backup probe interprets the empty state as "unconfigured".
func TestBackupConfigDefaultsToUnconfigured(t *testing.T) {
	t.Parallel()

	cfg, err := Load(MapLookup(strictEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BackupStatusFile != "" {
		t.Errorf("BackupStatusFile = %q, want empty (unconfigured)", cfg.BackupStatusFile)
	}
	if cfg.BackupMaxAge != 0 {
		t.Errorf("BackupMaxAge = %v, want 0 (unconfigured)", cfg.BackupMaxAge)
	}
}

func TestBackupConfigParsesAbsolutePathAndDuration(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	backupStatusFile := filepath.Join(t.TempDir(), "backup.status")
	env[EnvBackupStatusFile] = backupStatusFile
	env[EnvBackupMaxAge] = "26h"

	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BackupStatusFile != backupStatusFile {
		t.Errorf("BackupStatusFile = %q, want %q", cfg.BackupStatusFile, backupStatusFile)
	}
	if cfg.BackupMaxAge != 26*time.Hour {
		t.Errorf("BackupMaxAge = %v, want 26h", cfg.BackupMaxAge)
	}
}

func TestBackupConfigRejectsRelativePath(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	env[EnvBackupStatusFile] = "var/lib/yalla/backup.status" // relative

	_, err := Load(MapLookup(env))
	if err == nil {
		t.Fatal("Load returned nil error for relative backup status path")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeConfig {
		t.Errorf("error code = %v, want CodeConfig", err)
	}
}

func TestBackupConfigRejectsMalformedDuration(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	env[EnvBackupMaxAge] = "tomorrow"

	_, err := Load(MapLookup(env))
	if err == nil {
		t.Fatal("Load returned nil error for malformed YALLA_BACKUP_MAX_AGE")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeConfig {
		t.Errorf("error code = %v, want CodeConfig", err)
	}
}

func TestBackupConfigRejectsNegativeDuration(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	env[EnvBackupMaxAge] = "-1h"

	_, err := Load(MapLookup(env))
	if err == nil {
		t.Fatal("Load returned nil error for negative YALLA_BACKUP_MAX_AGE")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeConfig {
		t.Errorf("error code = %v, want CodeConfig", err)
	}
}

func TestBackupRedactedConfigSurfacesNonSecretFields(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	backupStatusFile := filepath.Join(t.TempDir(), "backup.status")
	env[EnvBackupStatusFile] = backupStatusFile
	env[EnvBackupMaxAge] = "26h"

	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	r := cfg.Redacted()
	if r.BackupStatusFile != backupStatusFile {
		t.Errorf("BackupStatusFile = %q, want %q (a non-secret operational path)",
			r.BackupStatusFile, backupStatusFile)
	}
	if r.BackupMaxAge != "26h0m0s" {
		t.Errorf("BackupMaxAge = %q, want 26h0m0s", r.BackupMaxAge)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("snapshot", slog.Any("config", cfg))
	if !strings.Contains(buf.String(), "backup_status_file") {
		t.Errorf("LogValue snapshot missing backup_status_file: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "backup_max_age") {
		t.Errorf("LogValue snapshot missing backup_max_age: %s", buf.String())
	}
}

// TestRateLimitRedactedConfigSurfacesEnabledFlag proves the redacted
// projection (the log-safe view) exposes the enabled bit. Operators
// should be able to see at a glance whether the limiter is on without
// reading the per-bucket values, and the enabled bit is not a secret.
func TestRateLimitRedactedConfigSurfacesEnabledFlag(t *testing.T) {
	t.Parallel()

	env := strictEnv()
	cfg, err := Load(MapLookup(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Redacted().RateLimitEnabled {
		t.Error("RateLimitEnabled = false in redacted projection; want true for production defaults")
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("snapshot", slog.Any("config", cfg))
	if !strings.Contains(buf.String(), "rate_limit_enabled") {
		t.Errorf("LogValue snapshot missing rate_limit_enabled: %s", buf.String())
	}
}
