// Package config defines the Yalla Control Plane backend configuration
// contract shared by the HTTP API (cmd/yalla-api) and the provisioning
// worker (cmd/yalla-worker).
//
// Configuration is resolved once at process startup from environment
// variables layered over per-profile defaults. The precedence chain is
// environment variable > profile default. Environment variables are the
// production default for backend processes; CLI flags belong to the
// customer-facing CLI, not these long-running services.
//
// Three contracts are part of yalla's public, versioned surface:
//
//  1. Environment variable names (the Env* constants). Adding a variable is
//     a minor change; renaming or removing one is a major change.
//
//  2. Profile names: "local", "test", "staging", "production". Each profile
//     supplies defaults and decides which fields are mandatory. Staging and
//     production demand a fully-specified config and fail fast otherwise.
//
//  3. The stable CodeConfig error classification for every validation
//     failure, so a misconfigured process exits deterministically.
//
// Secrets — the Postgres DSN, signing keys, secret-encryption keys, the
// Dokploy service token, and the internal worker token — must never reach
// logs, errors, audit metadata, or test output. The Config type implements
// slog.LogValuer and fmt.Stringer with redacted views so an accidental
// structured-log or %v never leaks a credential. Validation errors describe
// which field failed without echoing its value.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/output"
)

// Environment variable names are part of the backend agent contract. Keep
// them in one place so the API binary, the worker binary, and tests cannot
// drift.
const (
	// EnvProfile selects the configuration profile: local, test, staging,
	// or production. Defaults to "local" when unset.
	EnvProfile = "YALLA_PROFILE"
	// EnvAPIAddr is the host:port the HTTP API listens on.
	EnvAPIAddr = "YALLA_API_ADDR"
	// EnvPublicURL is the externally reachable base URL of the API, used to
	// build absolute links in responses and notifications.
	EnvPublicURL = "YALLA_PUBLIC_URL"
	// EnvDatabaseURL is the PostgreSQL DSN for the source-of-truth database.
	// Treated as a secret: never logged.
	EnvDatabaseURL = "YALLA_DATABASE_URL"
	// EnvSigningKeys is a comma-separated list of signing keys. The first
	// entry is the active key; the rest are accepted during rotation.
	// Treated as a secret: never logged.
	EnvSigningKeys = "YALLA_SIGNING_KEYS"
	// EnvSecretKeys is a comma-separated list of hex-encoded 32-byte
	// AES-256 master keys consumed by internal/controlplane/secrets.AESGCM
	// to seal organization (and later project/environment/service)
	// variable values at rest. The first entry is the active key (used by
	// Seal); the rest are accepted for Open during a key rotation. Strict
	// profiles (staging, production) require this variable; local and
	// test profiles fall back to a passthrough Plaintext provider so unit
	// tests and local development can exercise the at-rest seam without
	// real key material. Treated as a secret: never logged.
	EnvSecretKeys = "YALLA_SECRET_KEYS"
	// EnvDokployBaseURL is the base URL of the private Dokploy API.
	EnvDokployBaseURL = "YALLA_DOKPLOY_BASE_URL"
	// EnvDokployToken is the privileged Dokploy service token used by the
	// worker. Treated as a secret: never logged and never exposed to
	// customer-facing endpoints.
	EnvDokployToken = "YALLA_DOKPLOY_TOKEN"
	// EnvInternalWorkerToken is the shared secret accepted by the API for
	// private worker callbacks. It must match the worker's configured value.
	// Treated as a secret: never logged and never exposed to customer-facing
	// endpoints.
	EnvInternalWorkerToken = "YALLA_INTERNAL_WORKER_TOKEN"
	// EnvShutdownTimeout bounds how long a backend process waits to drain
	// in-flight HTTP requests and release in-flight job leases during a
	// graceful shutdown. Accepts any Go duration string (e.g. "15s", "1m").
	EnvShutdownTimeout = "YALLA_SHUTDOWN_TIMEOUT"
	// EnvHTTPReadTimeout bounds reading the full request, including body.
	// Accepts any Go duration string (e.g. "15s", "1m").
	EnvHTTPReadTimeout = "YALLA_HTTP_READ_TIMEOUT"
	// EnvHTTPWriteTimeout bounds response writes. Accepts any Go duration
	// string (e.g. "60s", "2m").
	EnvHTTPWriteTimeout = "YALLA_HTTP_WRITE_TIMEOUT"
	// EnvHTTPIdleTimeout bounds keep-alive idle connections. Accepts any Go
	// duration string (e.g. "120s", "3m").
	EnvHTTPIdleTimeout = "YALLA_HTTP_IDLE_TIMEOUT"
	// EnvTrustedProxyCIDRs is a comma-separated list of reverse-proxy CIDR
	// ranges whose X-Forwarded-For / X-Real-IP headers may be trusted.
	EnvTrustedProxyCIDRs = "YALLA_TRUSTED_PROXY_CIDRS"
	// EnvBackupStatusFile is the absolute path of the file the operator's
	// backup pipeline writes its last-success RFC3339 timestamp to. When
	// set, the unauthenticated GET /healthz/backup probe reports the
	// timestamp; when empty the probe reports "unconfigured". The file
	// content is never logged, so an accidentally misconfigured pipeline
	// that writes a secret instead of a timestamp cannot leak it through
	// Yalla.
	EnvBackupStatusFile = "YALLA_BACKUP_STATUS_FILE"
	// EnvBackupMaxAge is the freshness threshold the GET /healthz/backup
	// probe reports as max_age_seconds. A backup older than this is
	// rendered as fresh=false. Accepts any Go duration string
	// (e.g. "26h"); zero or unset disables the freshness predicate.
	EnvBackupMaxAge = "YALLA_BACKUP_MAX_AGE"
	// EnvLogLevel sets the structured log level: debug, info, warn, error.
	EnvLogLevel = "YALLA_LOG_LEVEL"
	// EnvFeatureFlags is a comma-separated list of feature flags. Each entry
	// is either "name" (enabled) or "name=true" / "name=false".
	EnvFeatureFlags = "YALLA_FEATURE_FLAGS"

	// EnvRateLimitDisabled, when set to a truthy value ("1", "true", "yes",
	// "on"), turns the inbound HTTP rate limiter off. The default is enabled.
	// The flag exists for staging soak tests and local development where the
	// extra layer would be noise; production processes leave it unset.
	EnvRateLimitDisabled = "YALLA_RATE_LIMIT_DISABLED"
	// EnvRateLimitBackend selects the limiter storage backend: "memory" for
	// single-process local enforcement or "redis" for shared multi-replica
	// enforcement.
	EnvRateLimitBackend = "YALLA_RATE_LIMIT_BACKEND"
	// EnvRateLimitRedisURL is the Redis DSN used by the distributed limiter.
	// Treated as a secret because it can embed credentials.
	EnvRateLimitRedisURL = "YALLA_RATE_LIMIT_REDIS_URL"
	// EnvRateLimitRedisPrefix prefixes every Redis limiter key.
	EnvRateLimitRedisPrefix = "YALLA_RATE_LIMIT_REDIS_KEY_PREFIX"
	// EnvRateLimitRedisTimeout bounds Redis dial/read/write operations.
	EnvRateLimitRedisTimeout = "YALLA_RATE_LIMIT_REDIS_TIMEOUT"
	// EnvRateLimitOrgReadRPS sets the steady-state allowed read requests per
	// second per organization. A non-positive value disables the read-side
	// org bucket.
	EnvRateLimitOrgReadRPS = "YALLA_RATE_LIMIT_ORG_READ_RPS"
	// EnvRateLimitOrgReadBurst sets the org bucket's read burst capacity.
	EnvRateLimitOrgReadBurst = "YALLA_RATE_LIMIT_ORG_READ_BURST"
	// EnvRateLimitOrgWriteRPS sets the steady-state allowed mutating
	// requests per second per organization (POST/PUT/PATCH/DELETE).
	EnvRateLimitOrgWriteRPS = "YALLA_RATE_LIMIT_ORG_WRITE_RPS"
	// EnvRateLimitOrgWriteBurst sets the org bucket's write burst capacity.
	EnvRateLimitOrgWriteBurst = "YALLA_RATE_LIMIT_ORG_WRITE_BURST"
	// EnvRateLimitKeyReadRPS sets the per-API-key read rate.
	EnvRateLimitKeyReadRPS = "YALLA_RATE_LIMIT_KEY_READ_RPS"
	// EnvRateLimitKeyReadBurst sets the per-API-key read burst.
	EnvRateLimitKeyReadBurst = "YALLA_RATE_LIMIT_KEY_READ_BURST"
	// EnvRateLimitKeyWriteRPS sets the per-API-key write rate.
	EnvRateLimitKeyWriteRPS = "YALLA_RATE_LIMIT_KEY_WRITE_RPS"
	// EnvRateLimitKeyWriteBurst sets the per-API-key write burst.
	EnvRateLimitKeyWriteBurst = "YALLA_RATE_LIMIT_KEY_WRITE_BURST"
	// EnvRateLimitIPReadRPS sets the per-IP read rate.
	EnvRateLimitIPReadRPS = "YALLA_RATE_LIMIT_IP_READ_RPS"
	// EnvRateLimitIPReadBurst sets the per-IP read burst.
	EnvRateLimitIPReadBurst = "YALLA_RATE_LIMIT_IP_READ_BURST"
	// EnvRateLimitIPWriteRPS sets the per-IP write rate.
	EnvRateLimitIPWriteRPS = "YALLA_RATE_LIMIT_IP_WRITE_RPS"
	// EnvRateLimitIPWriteBurst sets the per-IP write burst.
	EnvRateLimitIPWriteBurst = "YALLA_RATE_LIMIT_IP_WRITE_BURST"
	// EnvRateLimitIdleTTL is the duration after which an unused bucket is
	// pruned from memory. A non-positive value applies the package default
	// (five minutes).
	EnvRateLimitIdleTTL = "YALLA_RATE_LIMIT_IDLE_TTL"
)

// Profile identifies the deployment environment a backend process runs in.
// The string forms are public; scripts, tests, and operators may match on
// them.
type Profile string

// Profile values. Staging and production are strict: every operational
// field must be supplied. Local and test are permissive so the backend is
// easy to run on a developer machine and in unit tests.
const (
	ProfileLocal      Profile = "local"
	ProfileTest       Profile = "test"
	ProfileStaging    Profile = "staging"
	ProfileProduction Profile = "production"
)

// RateLimitBackend identifies where inbound rate-limit bucket state is stored.
type RateLimitBackend string

const (
	// RateLimitBackendMemory keeps bucket state inside one API process.
	RateLimitBackendMemory RateLimitBackend = "memory"
	// RateLimitBackendRedis stores bucket state in Redis for multi-replica APIs.
	RateLimitBackendRedis RateLimitBackend = "redis"
)

// allProfiles is the canonical, ordered list of valid profiles. Used for
// validation messages and tests.
var allProfiles = []Profile{ProfileLocal, ProfileTest, ProfileStaging, ProfileProduction}

// IsStrict reports whether the profile requires a fully-specified
// configuration. Staging and production are strict; local and test are not.
func (p Profile) IsStrict() bool {
	return p == ProfileStaging || p == ProfileProduction
}

// Valid reports whether p is one of the recognised profiles.
func (p Profile) Valid() bool {
	for _, known := range allProfiles {
		if p == known {
			return true
		}
	}
	return false
}

// Config is the resolved, typed backend configuration consumed by the API
// and worker binaries. It is immutable from a caller's perspective: load it
// once at startup and pass it by pointer.
//
// The DatabaseURL, SigningKeys, SecretKeys, DokployToken, and
// InternalWorkerToken fields are secrets. Never log, format, or serialise them
// directly; use Redacted, LogValue, or String, all of which scrub credentials.
type Config struct {
	// Profile is the resolved deployment profile.
	Profile Profile
	// APIAddr is the host:port the HTTP API listens on.
	APIAddr string
	// PublicURL is the externally reachable base URL of the API.
	PublicURL string
	// DatabaseURL is the PostgreSQL DSN. Secret.
	DatabaseURL string
	// SigningKeys holds the signing keys; index 0 is the active key and the
	// remainder are accepted during rotation. Secret.
	SigningKeys []string
	// SecretKeys holds the AES-256 master keys consumed by
	// internal/controlplane/secrets.AESGCM; index 0 is the active key
	// (used by Seal) and the remainder are accepted during rotation
	// (used by Open against rows that still reference a retired key id).
	// Each entry is the hex-encoded form of exactly 32 raw bytes.
	// Secret.
	SecretKeys []string
	// DokployBaseURL is the base URL of the private Dokploy API.
	DokployBaseURL string
	// DokployToken is the privileged Dokploy service token. Secret.
	DokployToken string
	// InternalWorkerToken is the shared secret accepted by the API for
	// private worker callbacks. Secret.
	InternalWorkerToken string
	// ShutdownTimeout bounds graceful shutdown: the HTTP server stops
	// accepting connections and drains in-flight requests within this
	// window, and the worker releases in-flight job leases within it.
	ShutdownTimeout time.Duration
	// HTTPReadTimeout bounds reading the full HTTP request.
	HTTPReadTimeout time.Duration
	// HTTPWriteTimeout bounds writing the HTTP response.
	HTTPWriteTimeout time.Duration
	// HTTPIdleTimeout bounds keep-alive idle connections.
	HTTPIdleTimeout time.Duration
	// TrustedProxyCIDRs are the reverse proxy source ranges from which
	// X-Forwarded-For / X-Real-IP may be trusted.
	TrustedProxyCIDRs []netip.Prefix
	// BackupStatusFile is the absolute path of the file the operator's
	// backup pipeline writes its last-success RFC3339 timestamp to. An
	// empty value disables the GET /healthz/backup probe — the endpoint
	// still serves, but reports "unconfigured".
	BackupStatusFile string
	// BackupMaxAge is the freshness threshold reported through the GET
	// /healthz/backup probe. Zero disables the freshness predicate; the
	// endpoint still reports the age, but makes no claim about it.
	BackupMaxAge time.Duration
	// LogLevel is the resolved structured log level.
	LogLevel slog.Level
	// FeatureFlags maps flag names to their enabled state.
	FeatureFlags map[string]bool
	// RateLimit carries the inbound HTTP rate-limit configuration.
	// Disabled config disables the limiter entirely; otherwise the Org,
	// Key, and IP specs control the three bucket dimensions.
	RateLimit RateLimit
}

// RateLimit holds the resolved inbound HTTP rate-limit configuration. A
// zero RateLimit value disables every dimension; production processes
// pick non-zero values via the YALLA_RATE_LIMIT_* environment variables
// or the per-profile defaults documented on load.go.
type RateLimit struct {
	// Disabled, when true, turns off the limiter for every dimension
	// even if the Specs below carry positive values.
	Disabled bool
	// Backend selects where bucket state is stored.
	Backend RateLimitBackend
	// RedisURL is the Redis DSN for the distributed backend. Secret.
	RedisURL string
	// RedisPrefix prefixes every Redis limiter key.
	RedisPrefix string
	// RedisTimeout bounds Redis dial/read/write operations.
	RedisTimeout time.Duration
	// OrgReadRPS, OrgReadBurst, OrgWriteRPS, OrgWriteBurst control the
	// per-organization bucket. A non-positive RPS or Burst disables the
	// matching side.
	OrgReadRPS    float64
	OrgReadBurst  int
	OrgWriteRPS   float64
	OrgWriteBurst int
	// KeyReadRPS / KeyWriteRPS / KeyReadBurst / KeyWriteBurst control
	// the per-API-key (or per-session-principal) bucket.
	KeyReadRPS    float64
	KeyReadBurst  int
	KeyWriteRPS   float64
	KeyWriteBurst int
	// IPReadRPS / IPWriteRPS / IPReadBurst / IPWriteBurst control the
	// per-client-IP bucket. The IP bucket is the only one a public
	// (unauthenticated) endpoint can fall back to.
	IPReadRPS    float64
	IPReadBurst  int
	IPWriteRPS   float64
	IPWriteBurst int
	// IdleTTL is how long an unused bucket is retained before lazy
	// eviction reclaims it. A non-positive value applies the package
	// default.
	IdleTTL time.Duration
}

// AnyEnabled reports whether the rate-limit configuration enables any
// dimension. A Disabled config always returns false; a zero RateLimit
// also returns false because every bucket spec is zero.
func (r RateLimit) AnyEnabled() bool {
	if r.Disabled {
		return false
	}
	return r.OrgReadRPS > 0 || r.OrgWriteRPS > 0 ||
		r.KeyReadRPS > 0 || r.KeyWriteRPS > 0 ||
		r.IPReadRPS > 0 || r.IPWriteRPS > 0
}

// ActiveSigningKey returns the signing key currently used to mint new
// signatures. It returns an empty string when no signing keys are
// configured (only possible in the non-strict local and test profiles).
func (c *Config) ActiveSigningKey() string {
	if c == nil || len(c.SigningKeys) == 0 {
		return ""
	}
	return c.SigningKeys[0]
}

// DecodedSecretKeys decodes every entry of SecretKeys from hex into the
// raw 32-byte AES-256 key material the internal/controlplane/secrets
// package consumes. Order is preserved: the first entry is the active
// key, the rest are accepted during rotation. The returned slice is a
// fresh allocation; callers may mutate it without affecting the config.
// DecodedSecretKeys returns an error when an entry fails the hex shape
// already enforced by Validate (defence-in-depth — Validate runs at
// process startup, but callers should still error rather than panic if
// the post-condition is somehow violated). The returned error never
// echoes any of the key material.
func (c *Config) DecodedSecretKeys() ([][]byte, error) {
	if c == nil || len(c.SecretKeys) == 0 {
		return nil, nil
	}
	out := make([][]byte, 0, len(c.SecretKeys))
	for i, hexed := range c.SecretKeys {
		raw, err := decodeHexSecretKey(hexed)
		if err != nil {
			return nil, fmt.Errorf("%s entry #%d: %w", EnvSecretKeys, i+1, err)
		}
		out = append(out, raw)
	}
	return out, nil
}

// FeatureEnabled reports whether the named feature flag is enabled. Unknown
// flags are reported as disabled so callers never need a nil check.
func (c *Config) FeatureEnabled(name string) bool {
	if c == nil || c.FeatureFlags == nil {
		return false
	}
	return c.FeatureFlags[name]
}

// RedactedConfig is a credential-free projection of Config that is safe to
// log, serialise into diagnostics, or include in audit metadata. Secret
// fields are reduced to presence indicators and counts; their values never
// appear.
type RedactedConfig struct {
	Profile               Profile         `json:"profile"`
	APIAddr               string          `json:"api_addr"`
	PublicURL             string          `json:"public_url"`
	DatabaseURL           string          `json:"database_url"`
	SigningKeysConfigured int             `json:"signing_keys_configured"`
	SecretKeysConfigured  int             `json:"secret_keys_configured"`
	DokployBaseURL        string          `json:"dokploy_base_url"`
	DokployToken          string          `json:"dokploy_token"`
	InternalWorkerToken   string          `json:"internal_worker_token"`
	ShutdownTimeout       string          `json:"shutdown_timeout"`
	HTTPReadTimeout       string          `json:"http_read_timeout"`
	HTTPWriteTimeout      string          `json:"http_write_timeout"`
	HTTPIdleTimeout       string          `json:"http_idle_timeout"`
	TrustedProxyCIDRs     []string        `json:"trusted_proxy_cidrs"`
	BackupStatusFile      string          `json:"backup_status_file"`
	BackupMaxAge          string          `json:"backup_max_age"`
	LogLevel              string          `json:"log_level"`
	FeatureFlags          map[string]bool `json:"feature_flags"`
	RateLimitEnabled      bool            `json:"rate_limit_enabled"`
	RateLimitBackend      string          `json:"rate_limit_backend"`
	RateLimitRedisURL     string          `json:"rate_limit_redis_url"`
	RateLimitRedisPrefix  string          `json:"rate_limit_redis_prefix"`
	RateLimitRedisTimeout string          `json:"rate_limit_redis_timeout"`
}

// Redacted returns a credential-free projection of the config. Secret values
// that are set collapse to output.Sentinel; secret values that are unset
// stay empty so operators can still tell "configured" from "missing"
// without ever seeing the value.
func (c *Config) Redacted() RedactedConfig {
	if c == nil {
		return RedactedConfig{}
	}
	redact := func(v string) string {
		if v == "" {
			return ""
		}
		return output.Sentinel
	}
	flags := make(map[string]bool, len(c.FeatureFlags))
	for k, v := range c.FeatureFlags {
		flags[k] = v
	}
	return RedactedConfig{
		Profile:               c.Profile,
		APIAddr:               c.APIAddr,
		PublicURL:             c.PublicURL,
		DatabaseURL:           redact(c.DatabaseURL),
		SigningKeysConfigured: len(c.SigningKeys),
		SecretKeysConfigured:  len(c.SecretKeys),
		DokployBaseURL:        c.DokployBaseURL,
		DokployToken:          redact(c.DokployToken),
		InternalWorkerToken:   redact(c.InternalWorkerToken),
		ShutdownTimeout:       c.ShutdownTimeout.String(),
		HTTPReadTimeout:       c.HTTPReadTimeout.String(),
		HTTPWriteTimeout:      c.HTTPWriteTimeout.String(),
		HTTPIdleTimeout:       c.HTTPIdleTimeout.String(),
		TrustedProxyCIDRs:     prefixStrings(c.TrustedProxyCIDRs),
		BackupStatusFile:      c.BackupStatusFile,
		BackupMaxAge:          c.BackupMaxAge.String(),
		LogLevel:              c.LogLevel.String(),
		FeatureFlags:          flags,
		RateLimitEnabled:      c.RateLimit.AnyEnabled(),
		RateLimitBackend:      string(c.RateLimit.Backend),
		RateLimitRedisURL:     redact(c.RateLimit.RedisURL),
		RateLimitRedisPrefix:  c.RateLimit.RedisPrefix,
		RateLimitRedisTimeout: c.RateLimit.RedisTimeout.String(),
	}
}

// LogValue implements slog.LogValuer so a Config logged with slog is
// automatically scrubbed of secrets. This is defence-in-depth: code should
// log Config.Redacted() explicitly, but an accidental slog.Any("config", c)
// still never leaks a credential.
func (c *Config) LogValue() slog.Value {
	r := c.Redacted()
	flags := make([]string, 0, len(r.FeatureFlags))
	for k := range r.FeatureFlags {
		flags = append(flags, k)
	}
	sort.Strings(flags)
	attrs := make([]slog.Attr, 0, len(flags))
	for _, k := range flags {
		attrs = append(attrs, slog.Bool(k, r.FeatureFlags[k]))
	}
	return slog.GroupValue(
		slog.String("profile", string(r.Profile)),
		slog.String("api_addr", r.APIAddr),
		slog.String("public_url", r.PublicURL),
		slog.String("database_url", r.DatabaseURL),
		slog.Int("signing_keys_configured", r.SigningKeysConfigured),
		slog.Int("secret_keys_configured", r.SecretKeysConfigured),
		slog.String("dokploy_base_url", r.DokployBaseURL),
		slog.String("dokploy_token", r.DokployToken),
		slog.String("internal_worker_token", r.InternalWorkerToken),
		slog.String("shutdown_timeout", r.ShutdownTimeout),
		slog.String("http_read_timeout", r.HTTPReadTimeout),
		slog.String("http_write_timeout", r.HTTPWriteTimeout),
		slog.String("http_idle_timeout", r.HTTPIdleTimeout),
		slog.Any("trusted_proxy_cidrs", r.TrustedProxyCIDRs),
		slog.String("backup_status_file", r.BackupStatusFile),
		slog.String("backup_max_age", r.BackupMaxAge),
		slog.String("log_level", r.LogLevel),
		slog.Bool("rate_limit_enabled", r.RateLimitEnabled),
		slog.String("rate_limit_backend", r.RateLimitBackend),
		slog.String("rate_limit_redis_url", r.RateLimitRedisURL),
		slog.String("rate_limit_redis_prefix", r.RateLimitRedisPrefix),
		slog.String("rate_limit_redis_timeout", r.RateLimitRedisTimeout),
		slog.Group("feature_flags", anyAttrs(attrs)...),
	)
}

// decodeHexSecretKey turns a hex-encoded YALLA_SECRET_KEYS entry into the
// raw 32-byte AES-256 key. The error path is value-free: it names only
// the failure classification, never the input bytes.
func decodeHexSecretKey(hexed string) ([]byte, error) {
	raw, err := hex.DecodeString(hexed)
	if err != nil {
		return nil, errors.New("invalid hex encoding")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("must decode to exactly 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// anyAttrs adapts a []slog.Attr to the variadic any signature slog.Group
// expects.
func anyAttrs(attrs []slog.Attr) []any {
	out := make([]any, len(attrs))
	for i := range attrs {
		out[i] = attrs[i]
	}
	return out
}

// String implements fmt.Stringer with a redacted view so an accidental
// fmt.Sprintf("%v", cfg) can never print a secret.
func (c *Config) String() string {
	if c == nil {
		return "config<nil>"
	}
	r := c.Redacted()
	flags := make([]string, 0, len(r.FeatureFlags))
	for k, v := range r.FeatureFlags {
		flags = append(flags, fmt.Sprintf("%s=%t", k, v))
	}
	sort.Strings(flags)
	return fmt.Sprintf(
		"config{profile:%s api_addr:%s public_url:%s database_url:%s signing_keys_configured:%d secret_keys_configured:%d dokploy_base_url:%s dokploy_token:%s internal_worker_token:%s shutdown_timeout:%s http_read_timeout:%s http_write_timeout:%s http_idle_timeout:%s trusted_proxy_cidrs:[%s] backup_status_file:%s backup_max_age:%s log_level:%s rate_limit_enabled:%t rate_limit_backend:%s rate_limit_redis_url:%s rate_limit_redis_prefix:%s rate_limit_redis_timeout:%s feature_flags:[%s]}",
		r.Profile, r.APIAddr, r.PublicURL, r.DatabaseURL, r.SigningKeysConfigured, r.SecretKeysConfigured,
		r.DokployBaseURL, r.DokployToken, r.InternalWorkerToken, r.ShutdownTimeout, r.HTTPReadTimeout,
		r.HTTPWriteTimeout, r.HTTPIdleTimeout, strings.Join(r.TrustedProxyCIDRs, ","), r.BackupStatusFile,
		r.BackupMaxAge, r.LogLevel, r.RateLimitEnabled, r.RateLimitBackend, r.RateLimitRedisURL,
		r.RateLimitRedisPrefix, r.RateLimitRedisTimeout, strings.Join(flags, " "),
	)
}

func prefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.String()
	}
	return out
}
