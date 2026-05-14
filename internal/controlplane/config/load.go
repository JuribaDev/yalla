package config

import (
	"log/slog"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// LookupFunc mirrors os.LookupEnv. Tests inject a map-backed implementation
// so the real process environment never bleeds into assertions.
type LookupFunc func(key string) (string, bool)

// mapLookup adapts an in-memory map to a LookupFunc. Exported for tests via
// MapLookup.
func mapLookup(env map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// MapLookup returns a LookupFunc backed by an in-memory map. It is the
// canonical way to drive Load from tests without touching os.Environ.
func MapLookup(env map[string]string) LookupFunc { return mapLookup(env) }

// profileDefaults holds the per-profile baseline applied before environment
// variables are layered on top.
type profileDefaults struct {
	apiAddr         string
	logLevel        slog.Level
	publicURL       string
	shutdownTimeout time.Duration
}

// defaultsByProfile maps each profile to its baseline. Local is tuned for a
// developer machine (verbose, loopback URL); test is quiet and binds an
// ephemeral port; staging and production are conservative and supply no
// secret defaults — strict profiles must be configured explicitly.
var defaultsByProfile = map[Profile]profileDefaults{
	ProfileLocal: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelDebug,
		publicURL:       "http://localhost:8080",
		shutdownTimeout: 15 * time.Second,
	},
	ProfileTest: {
		apiAddr:         "127.0.0.1:0",
		logLevel:        slog.LevelWarn,
		publicURL:       "http://127.0.0.1",
		shutdownTimeout: 2 * time.Second,
	},
	ProfileStaging: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelInfo,
		shutdownTimeout: 25 * time.Second,
	},
	ProfileProduction: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelInfo,
		shutdownTimeout: 25 * time.Second,
	},
}

// minSigningKeyLen is the shortest signing key Load accepts. A key shorter
// than this is almost always a placeholder or a truncated copy-paste and
// would produce weak signatures, so it is rejected outright.
const minSigningKeyLen = 16

// shutdownTimeout bounds. A non-positive timeout would make graceful
// shutdown a no-op (in-flight work dropped immediately); an unbounded one
// would let a wedged request block process exit indefinitely. Both are
// rejected so shutdown stays predictable.
const (
	minShutdownTimeout = time.Second
	maxShutdownTimeout = 5 * time.Minute
)

// LoadFromEnv resolves the backend configuration from the real process
// environment. It is the entry point both backend binaries call once at
// startup.
func LoadFromEnv() (*Config, error) {
	return Load(os.LookupEnv)
}

// Load resolves a *Config from the supplied environment lookup, layering
// environment variables over the selected profile's defaults and then
// validating the result. Every failure is a typed CodeConfig error so the
// caller can fail fast with a deterministic exit code without
// re-classifying.
func Load(lookup LookupFunc) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	profile, err := resolveProfile(lookup)
	if err != nil {
		return nil, err
	}
	defaults := defaultsByProfile[profile]

	logLevel, err := resolveLogLevel(lookup, defaults.logLevel)
	if err != nil {
		return nil, err
	}

	flags, err := resolveFeatureFlags(lookup)
	if err != nil {
		return nil, err
	}

	shutdownTimeout, err := resolveShutdownTimeout(lookup, defaults.shutdownTimeout)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Profile:         profile,
		APIAddr:         valueOr(lookup, EnvAPIAddr, defaults.apiAddr),
		PublicURL:       valueOr(lookup, EnvPublicURL, defaults.publicURL),
		DatabaseURL:     valueOr(lookup, EnvDatabaseURL, ""),
		SigningKeys:     splitList(valueOr(lookup, EnvSigningKeys, "")),
		DokployBaseURL:  valueOr(lookup, EnvDokployBaseURL, ""),
		DokployToken:    valueOr(lookup, EnvDokployToken, ""),
		ShutdownTimeout: shutdownTimeout,
		LogLevel:        logLevel,
		FeatureFlags:    flags,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks that the resolved config is internally consistent and
// complete enough for its profile. Format checks (URL shape, DSN scheme,
// listen address, signing key length) run for every profile when a value is
// present; presence checks for operational fields run only for the strict
// staging and production profiles.
//
// Validation messages name the offending field but never echo its value, so
// a misconfigured secret cannot leak through an error string.
func (c *Config) Validate() error {
	if c == nil {
		return yerr.New(yerr.CodeConfig, "backend config is not initialised")
	}
	if !c.Profile.Valid() {
		return yerr.Newf(yerr.CodeConfig, "invalid profile %q (want one of %s)", c.Profile, profileList())
	}

	if c.APIAddr == "" {
		return yerr.Newf(yerr.CodeConfig, "%s is required", EnvAPIAddr)
	}
	if err := validateListenAddr(c.APIAddr); err != nil {
		return err
	}

	if c.PublicURL != "" {
		if err := validateHTTPURL(EnvPublicURL, c.PublicURL); err != nil {
			return err
		}
	}
	if c.DokployBaseURL != "" {
		if err := validateHTTPURL(EnvDokployBaseURL, c.DokployBaseURL); err != nil {
			return err
		}
	}
	if c.DatabaseURL != "" {
		if err := validateDatabaseURL(c.DatabaseURL); err != nil {
			return err
		}
	}
	for i, key := range c.SigningKeys {
		if len(key) < minSigningKeyLen {
			return yerr.Newf(yerr.CodeConfig,
				"%s entry #%d is too short (need at least %d characters)",
				EnvSigningKeys, i+1, minSigningKeyLen)
		}
	}

	if c.ShutdownTimeout < minShutdownTimeout || c.ShutdownTimeout > maxShutdownTimeout {
		return yerr.Newf(yerr.CodeConfig,
			"%s %s is out of range (want between %s and %s)",
			EnvShutdownTimeout, c.ShutdownTimeout, minShutdownTimeout, maxShutdownTimeout)
	}

	if c.Profile.IsStrict() {
		if err := c.requireStrictFields(); err != nil {
			return err
		}
	}
	return nil
}

// requireStrictFields enforces that every operational field needed to serve
// real traffic is present. It runs only for staging and production so a
// developer running the local profile is never blocked by a missing
// Dokploy token.
func (c *Config) requireStrictFields() error {
	missing := make([]string, 0, 4)
	if c.PublicURL == "" {
		missing = append(missing, EnvPublicURL)
	}
	if c.DatabaseURL == "" {
		missing = append(missing, EnvDatabaseURL)
	}
	if len(c.SigningKeys) == 0 {
		missing = append(missing, EnvSigningKeys)
	}
	if c.DokployBaseURL == "" {
		missing = append(missing, EnvDokployBaseURL)
	}
	if c.DokployToken == "" {
		missing = append(missing, EnvDokployToken)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return yerr.Newf(yerr.CodeConfig,
			"profile %q requires %s", c.Profile, strings.Join(missing, ", "))
	}
	return nil
}

// resolveProfile reads YALLA_PROFILE, defaulting to local. An unrecognised
// value fails fast rather than silently falling back, so a typo in a
// deployment manifest cannot quietly downgrade a production process to a
// permissive profile.
func resolveProfile(lookup LookupFunc) (Profile, error) {
	raw, ok := lookup(EnvProfile)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return ProfileLocal, nil
	}
	p := Profile(strings.ToLower(raw))
	if !p.Valid() {
		return "", yerr.Newf(yerr.CodeConfig, "invalid %s %q (want one of %s)", EnvProfile, raw, profileList())
	}
	return p, nil
}

// resolveLogLevel parses YALLA_LOG_LEVEL, falling back to the profile
// default. The accepted spellings match slog's level names.
func resolveLogLevel(lookup LookupFunc, fallback slog.Level) (slog.Level, error) {
	raw, ok := lookup(EnvLogLevel)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want debug, info, warn, or error)", EnvLogLevel, raw)
	}
}

// resolveShutdownTimeout parses YALLA_SHUTDOWN_TIMEOUT as a Go duration,
// falling back to the profile default. Range enforcement happens in
// Validate so every profile gets the same bounds check.
func resolveShutdownTimeout(lookup LookupFunc, fallback time.Duration) (time.Duration, error) {
	raw, ok := lookup(EnvShutdownTimeout)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want a Go duration such as 15s or 1m)", EnvShutdownTimeout, raw)
	}
	return d, nil
}

// resolveFeatureFlags parses YALLA_FEATURE_FLAGS into a name->enabled map.
// Each comma-separated entry is either "name" (enabled) or "name=<bool>".
// An empty variable yields an empty, non-nil map.
func resolveFeatureFlags(lookup LookupFunc) (map[string]bool, error) {
	flags := make(map[string]bool)
	raw, ok := lookup(EnvFeatureFlags)
	if !ok || strings.TrimSpace(raw) == "" {
		return flags, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, value, hasValue := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, yerr.Newf(yerr.CodeConfig, "invalid %s entry %q (empty flag name)", EnvFeatureFlags, entry)
		}
		enabled := true
		if hasValue {
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return nil, yerr.Newf(yerr.CodeConfig,
					"invalid %s entry %q (value must be true or false)", EnvFeatureFlags, entry)
			}
			enabled = parsed
		}
		flags[name] = enabled
	}
	return flags, nil
}

// valueOr returns the trimmed environment value for key, or fallback when
// the variable is unset or blank.
func valueOr(lookup LookupFunc, key, fallback string) string {
	if v, ok := lookup(key); ok {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return fallback
}

// splitList parses a comma-separated env value into a slice of trimmed,
// non-empty entries. Order is preserved so the first signing key stays the
// active one.
func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateListenAddr checks that addr is a usable host:port the API can
// bind. A bare ":8080" is valid (all interfaces); an empty host is fine.
func validateListenAddr(addr string) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return yerr.Newf(yerr.CodeConfig, "invalid %s %q: %v", EnvAPIAddr, addr, err)
	}
	return nil
}

// validateHTTPURL checks that raw parses as an absolute http(s) URL with a
// host. envName is used purely for the error message; the value itself is
// echoed because URLs are not secrets — but note this helper is never
// called for the Postgres DSN.
func validateHTTPURL(envName, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return yerr.Newf(yerr.CodeConfig, "invalid %s %q: %v", envName, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return yerr.Newf(yerr.CodeConfig, "invalid %s %q: scheme must be http or https", envName, raw)
	}
	if u.Host == "" {
		return yerr.Newf(yerr.CodeConfig, "invalid %s %q: missing host", envName, raw)
	}
	return nil
}

// validateDatabaseURL checks the Postgres DSN scheme without echoing the DSN
// itself: a DSN embeds the password, so the error message must never
// include the value.
func validateDatabaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return yerr.Newf(yerr.CodeConfig, "invalid %s: not a valid URL", EnvDatabaseURL)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return yerr.Newf(yerr.CodeConfig, "invalid %s: scheme must be postgres or postgresql", EnvDatabaseURL)
	}
	if u.Host == "" {
		return yerr.Newf(yerr.CodeConfig, "invalid %s: missing host", EnvDatabaseURL)
	}
	return nil
}

// profileList renders the valid profiles for error messages.
func profileList() string {
	names := make([]string, len(allProfiles))
	for i, p := range allProfiles {
		names[i] = string(p)
	}
	return strings.Join(names, ", ")
}
