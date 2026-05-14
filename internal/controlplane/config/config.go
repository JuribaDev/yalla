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
// Secrets — the Postgres DSN, signing keys, and the Dokploy service token —
// must never reach logs, errors, audit metadata, or test output. The Config
// type implements slog.LogValuer and fmt.Stringer with redacted views so an
// accidental structured-log or %v never leaks a credential. Validation
// errors describe which field failed without echoing its value.
package config

import (
	"fmt"
	"log/slog"
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
	// EnvDokployBaseURL is the base URL of the private Dokploy API.
	EnvDokployBaseURL = "YALLA_DOKPLOY_BASE_URL"
	// EnvDokployToken is the privileged Dokploy service token used by the
	// worker. Treated as a secret: never logged and never exposed to
	// customer-facing endpoints.
	EnvDokployToken = "YALLA_DOKPLOY_TOKEN"
	// EnvShutdownTimeout bounds how long a backend process waits to drain
	// in-flight HTTP requests and release in-flight job leases during a
	// graceful shutdown. Accepts any Go duration string (e.g. "15s", "1m").
	EnvShutdownTimeout = "YALLA_SHUTDOWN_TIMEOUT"
	// EnvLogLevel sets the structured log level: debug, info, warn, error.
	EnvLogLevel = "YALLA_LOG_LEVEL"
	// EnvFeatureFlags is a comma-separated list of feature flags. Each entry
	// is either "name" (enabled) or "name=true" / "name=false".
	EnvFeatureFlags = "YALLA_FEATURE_FLAGS"
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
// The DatabaseURL, SigningKeys, and DokployToken fields are secrets. Never
// log, format, or serialise them directly; use Redacted, LogValue, or
// String, all of which scrub credentials.
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
	// DokployBaseURL is the base URL of the private Dokploy API.
	DokployBaseURL string
	// DokployToken is the privileged Dokploy service token. Secret.
	DokployToken string
	// ShutdownTimeout bounds graceful shutdown: the HTTP server stops
	// accepting connections and drains in-flight requests within this
	// window, and the worker releases in-flight job leases within it.
	ShutdownTimeout time.Duration
	// LogLevel is the resolved structured log level.
	LogLevel slog.Level
	// FeatureFlags maps flag names to their enabled state.
	FeatureFlags map[string]bool
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
	DokployBaseURL        string          `json:"dokploy_base_url"`
	DokployToken          string          `json:"dokploy_token"`
	ShutdownTimeout       string          `json:"shutdown_timeout"`
	LogLevel              string          `json:"log_level"`
	FeatureFlags          map[string]bool `json:"feature_flags"`
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
		DokployBaseURL:        c.DokployBaseURL,
		DokployToken:          redact(c.DokployToken),
		ShutdownTimeout:       c.ShutdownTimeout.String(),
		LogLevel:              c.LogLevel.String(),
		FeatureFlags:          flags,
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
		slog.String("dokploy_base_url", r.DokployBaseURL),
		slog.String("dokploy_token", r.DokployToken),
		slog.String("shutdown_timeout", r.ShutdownTimeout),
		slog.String("log_level", r.LogLevel),
		slog.Group("feature_flags", anyAttrs(attrs)...),
	)
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
		"config{profile:%s api_addr:%s public_url:%s database_url:%s signing_keys_configured:%d dokploy_base_url:%s dokploy_token:%s shutdown_timeout:%s log_level:%s feature_flags:[%s]}",
		r.Profile, r.APIAddr, r.PublicURL, r.DatabaseURL, r.SigningKeysConfigured,
		r.DokployBaseURL, r.DokployToken, r.ShutdownTimeout, r.LogLevel, strings.Join(flags, " "),
	)
}
