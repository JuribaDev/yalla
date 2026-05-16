package config

import (
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	rateLimit       RateLimit
}

// defaultsByProfile maps each profile to its baseline. Local is tuned for a
// developer machine (verbose, loopback URL); test is quiet and binds an
// ephemeral port; staging and production are conservative and supply no
// secret defaults — strict profiles must be configured explicitly.
//
// The rate-limit defaults are tuned per profile: the test profile disables
// the limiter so contract tests never accidentally trip it; local picks
// permissive specs that still exercise the wiring; staging and production
// pick conservative caps that protect the backend without throttling
// legitimate scripted workloads. Operators may override any field via the
// YALLA_RATE_LIMIT_* environment variables.
var defaultsByProfile = map[Profile]profileDefaults{
	ProfileLocal: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelDebug,
		publicURL:       "http://localhost:8080",
		shutdownTimeout: 15 * time.Second,
		rateLimit: RateLimit{
			OrgReadRPS: 50, OrgReadBurst: 100, OrgWriteRPS: 20, OrgWriteBurst: 40,
			KeyReadRPS: 25, KeyReadBurst: 50, KeyWriteRPS: 10, KeyWriteBurst: 20,
			IPReadRPS: 50, IPReadBurst: 100, IPWriteRPS: 20, IPWriteBurst: 40,
			IdleTTL: 5 * time.Minute,
		},
	},
	ProfileTest: {
		apiAddr:         "127.0.0.1:0",
		logLevel:        slog.LevelWarn,
		publicURL:       "http://127.0.0.1",
		shutdownTimeout: 2 * time.Second,
		rateLimit:       RateLimit{Disabled: true},
	},
	ProfileStaging: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelInfo,
		shutdownTimeout: 25 * time.Second,
		rateLimit: RateLimit{
			OrgReadRPS: 100, OrgReadBurst: 200, OrgWriteRPS: 30, OrgWriteBurst: 60,
			KeyReadRPS: 50, KeyReadBurst: 100, KeyWriteRPS: 15, KeyWriteBurst: 30,
			IPReadRPS: 60, IPReadBurst: 120, IPWriteRPS: 20, IPWriteBurst: 40,
			IdleTTL: 5 * time.Minute,
		},
	},
	ProfileProduction: {
		apiAddr:         ":8080",
		logLevel:        slog.LevelInfo,
		shutdownTimeout: 25 * time.Second,
		rateLimit: RateLimit{
			OrgReadRPS: 100, OrgReadBurst: 200, OrgWriteRPS: 30, OrgWriteBurst: 60,
			KeyReadRPS: 50, KeyReadBurst: 100, KeyWriteRPS: 15, KeyWriteBurst: 30,
			IPReadRPS: 60, IPReadBurst: 120, IPWriteRPS: 20, IPWriteBurst: 40,
			IdleTTL: 5 * time.Minute,
		},
	},
}

// minSigningKeyLen is the shortest signing key Load accepts. A key shorter
// than this is almost always a placeholder or a truncated copy-paste and
// would produce weak signatures, so it is rejected outright.
const minSigningKeyLen = 16

// secretKeyHexLen is the required hex-encoded length of a YALLA_SECRET_KEYS
// entry. Each key seals through AES-256-GCM, which requires exactly 32 raw
// bytes — 64 hex characters. A shorter or longer entry is almost always a
// truncated paste or the wrong key material, so it is rejected outright.
const secretKeyHexLen = 64

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

	backupMaxAge, err := resolveBackupMaxAge(lookup)
	if err != nil {
		return nil, err
	}

	rateLimit, err := resolveRateLimit(lookup, defaults.rateLimit)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Profile:          profile,
		APIAddr:          valueOr(lookup, EnvAPIAddr, defaults.apiAddr),
		PublicURL:        valueOr(lookup, EnvPublicURL, defaults.publicURL),
		DatabaseURL:      valueOr(lookup, EnvDatabaseURL, ""),
		SigningKeys:      splitList(valueOr(lookup, EnvSigningKeys, "")),
		SecretKeys:       splitList(valueOr(lookup, EnvSecretKeys, "")),
		DokployBaseURL:   valueOr(lookup, EnvDokployBaseURL, ""),
		DokployToken:     valueOr(lookup, EnvDokployToken, ""),
		ShutdownTimeout:  shutdownTimeout,
		BackupStatusFile: strings.TrimSpace(valueOr(lookup, EnvBackupStatusFile, "")),
		BackupMaxAge:     backupMaxAge,
		LogLevel:         logLevel,
		FeatureFlags:     flags,
		RateLimit:        rateLimit,
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
	for i, key := range c.SecretKeys {
		if len(key) != secretKeyHexLen {
			return yerr.Newf(yerr.CodeConfig,
				"%s entry #%d has wrong length (want %d hex characters for a 32-byte AES-256 key)",
				EnvSecretKeys, i+1, secretKeyHexLen)
		}
		for _, b := range key {
			isHex := (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
			if !isHex {
				return yerr.Newf(yerr.CodeConfig,
					"%s entry #%d is not valid hex", EnvSecretKeys, i+1)
			}
		}
	}

	if c.ShutdownTimeout < minShutdownTimeout || c.ShutdownTimeout > maxShutdownTimeout {
		return yerr.Newf(yerr.CodeConfig,
			"%s %s is out of range (want between %s and %s)",
			EnvShutdownTimeout, c.ShutdownTimeout, minShutdownTimeout, maxShutdownTimeout)
	}

	if c.BackupStatusFile != "" {
		if !filepath.IsAbs(c.BackupStatusFile) {
			return yerr.Newf(yerr.CodeConfig,
				"%s must be an absolute path", EnvBackupStatusFile)
		}
	}
	if c.BackupMaxAge < 0 {
		return yerr.Newf(yerr.CodeConfig,
			"%s must be a non-negative duration (zero disables the freshness check)",
			EnvBackupMaxAge)
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
	if len(c.SecretKeys) == 0 {
		missing = append(missing, EnvSecretKeys)
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

// resolveBackupMaxAge parses YALLA_BACKUP_MAX_AGE as a Go duration. An unset
// or empty value yields zero, which Validate accepts (zero disables the
// freshness predicate the /healthz/backup probe reports). Negative
// durations are rejected here so the caller sees the offending input
// rather than discovering the violation in Validate.
func resolveBackupMaxAge(lookup LookupFunc) (time.Duration, error) {
	raw, ok := lookup(EnvBackupMaxAge)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want a Go duration such as 26h)",
			EnvBackupMaxAge, raw)
	}
	return d, nil
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

// rateLimitMaxBurst caps the per-bucket burst capacity at a value large
// enough for any plausible legitimate workload but small enough to keep
// the limiter's memory footprint bounded. A misconfigured burst above
// the cap is rejected so a typo cannot quietly disable rate limiting in
// practice (a million-token bucket is indistinguishable from no limiter
// for any sustained throughput a client could generate).
const rateLimitMaxBurst = 100_000

// rateLimitMaxRPS is the matching cap on the steady-state rate.
const rateLimitMaxRPS = 10_000.0

// rateLimitMinIdleTTL bounds the lazy-eviction TTL: a TTL shorter than
// this would have the limiter constantly rebuilding buckets, defeating
// the burst budget.
const (
	rateLimitMinIdleTTL = 10 * time.Second
	rateLimitMaxIdleTTL = time.Hour
)

// resolveRateLimit layers the YALLA_RATE_LIMIT_* environment variables
// over the profile defaults. Each spec field (rate, burst) is resolved
// independently; missing values fall back to the profile default rather
// than to zero, so an operator who only overrides one knob keeps the
// rest of the profile baseline.
//
// The disable flag is the master switch: a truthy value overrides every
// spec and turns the limiter off (the AnyEnabled accessor folds the
// flag in).
func resolveRateLimit(lookup LookupFunc, fallback RateLimit) (RateLimit, error) {
	disabled, err := resolveBool(lookup, EnvRateLimitDisabled, fallback.Disabled)
	if err != nil {
		return RateLimit{}, err
	}
	idleTTL, err := resolveDuration(lookup, EnvRateLimitIdleTTL, fallback.IdleTTL)
	if err != nil {
		return RateLimit{}, err
	}

	out := RateLimit{
		Disabled: disabled,
		IdleTTL:  idleTTL,
	}
	specs := []struct {
		env      string
		fallback float64
		target   *float64
		isBurst  bool
	}{
		{EnvRateLimitOrgReadRPS, fallback.OrgReadRPS, &out.OrgReadRPS, false},
		{EnvRateLimitOrgWriteRPS, fallback.OrgWriteRPS, &out.OrgWriteRPS, false},
		{EnvRateLimitKeyReadRPS, fallback.KeyReadRPS, &out.KeyReadRPS, false},
		{EnvRateLimitKeyWriteRPS, fallback.KeyWriteRPS, &out.KeyWriteRPS, false},
		{EnvRateLimitIPReadRPS, fallback.IPReadRPS, &out.IPReadRPS, false},
		{EnvRateLimitIPWriteRPS, fallback.IPWriteRPS, &out.IPWriteRPS, false},
	}
	for _, s := range specs {
		v, err := resolveFloat(lookup, s.env, s.fallback)
		if err != nil {
			return RateLimit{}, err
		}
		*s.target = v
	}
	bursts := []struct {
		env      string
		fallback int
		target   *int
	}{
		{EnvRateLimitOrgReadBurst, fallback.OrgReadBurst, &out.OrgReadBurst},
		{EnvRateLimitOrgWriteBurst, fallback.OrgWriteBurst, &out.OrgWriteBurst},
		{EnvRateLimitKeyReadBurst, fallback.KeyReadBurst, &out.KeyReadBurst},
		{EnvRateLimitKeyWriteBurst, fallback.KeyWriteBurst, &out.KeyWriteBurst},
		{EnvRateLimitIPReadBurst, fallback.IPReadBurst, &out.IPReadBurst},
		{EnvRateLimitIPWriteBurst, fallback.IPWriteBurst, &out.IPWriteBurst},
	}
	for _, b := range bursts {
		v, err := resolveInt(lookup, b.env, b.fallback)
		if err != nil {
			return RateLimit{}, err
		}
		*b.target = v
	}

	if err := validateRateLimit(out); err != nil {
		return RateLimit{}, err
	}
	return out, nil
}

// validateRateLimit enforces the integer-range and ttl bounds on the
// resolved RateLimit so a misconfigured value fails Load with a stable
// CodeConfig error rather than silently disabling enforcement at
// runtime. Zero values stay valid: they are the documented "disable
// this dimension" sentinel.
func validateRateLimit(r RateLimit) error {
	type rateField struct {
		env string
		v   float64
	}
	for _, f := range []rateField{
		{EnvRateLimitOrgReadRPS, r.OrgReadRPS},
		{EnvRateLimitOrgWriteRPS, r.OrgWriteRPS},
		{EnvRateLimitKeyReadRPS, r.KeyReadRPS},
		{EnvRateLimitKeyWriteRPS, r.KeyWriteRPS},
		{EnvRateLimitIPReadRPS, r.IPReadRPS},
		{EnvRateLimitIPWriteRPS, r.IPWriteRPS},
	} {
		if f.v < 0 {
			return yerr.Newf(yerr.CodeConfig, "%s must be non-negative", f.env)
		}
		if f.v > rateLimitMaxRPS {
			return yerr.Newf(yerr.CodeConfig,
				"%s is out of range (want between 0 and %g requests/second)", f.env, rateLimitMaxRPS)
		}
	}
	type burstField struct {
		env string
		v   int
	}
	for _, f := range []burstField{
		{EnvRateLimitOrgReadBurst, r.OrgReadBurst},
		{EnvRateLimitOrgWriteBurst, r.OrgWriteBurst},
		{EnvRateLimitKeyReadBurst, r.KeyReadBurst},
		{EnvRateLimitKeyWriteBurst, r.KeyWriteBurst},
		{EnvRateLimitIPReadBurst, r.IPReadBurst},
		{EnvRateLimitIPWriteBurst, r.IPWriteBurst},
	} {
		if f.v < 0 {
			return yerr.Newf(yerr.CodeConfig, "%s must be non-negative", f.env)
		}
		if f.v > rateLimitMaxBurst {
			return yerr.Newf(yerr.CodeConfig,
				"%s is out of range (want between 0 and %d)", f.env, rateLimitMaxBurst)
		}
	}
	if r.IdleTTL != 0 && (r.IdleTTL < rateLimitMinIdleTTL || r.IdleTTL > rateLimitMaxIdleTTL) {
		return yerr.Newf(yerr.CodeConfig,
			"%s %s is out of range (want between %s and %s)",
			EnvRateLimitIdleTTL, r.IdleTTL, rateLimitMinIdleTTL, rateLimitMaxIdleTTL)
	}
	return nil
}

// resolveBool parses a truthy/falsy env value with the documented
// spellings ("1", "true", "yes", "on" vs "0", "false", "no", "off",
// "") so an unset variable falls back deterministically.
func resolveBool(lookup LookupFunc, key string, fallback bool) (bool, error) {
	raw, ok := lookup(key)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on", "enabled":
		return true, nil
	case "0", "false", "no", "off", "disabled":
		return false, nil
	}
	return false, yerr.Newf(yerr.CodeConfig,
		"invalid %s %q (want a boolean such as true or false)", key, raw)
}

// resolveDuration parses a Go duration env value, falling back to the
// supplied default when unset. The value itself is echoed because a
// duration is not a secret.
func resolveDuration(lookup LookupFunc, key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := lookup(key)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want a Go duration such as 30s or 5m)", key, raw)
	}
	return d, nil
}

// resolveFloat parses a non-negative float env value, falling back to
// the supplied default when unset.
func resolveFloat(lookup LookupFunc, key string, fallback float64) (float64, error) {
	raw, ok := lookup(key)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want a non-negative number)", key, raw)
	}
	return v, nil
}

// resolveInt parses an int env value, falling back to the supplied
// default when unset.
func resolveInt(lookup LookupFunc, key string, fallback int) (int, error) {
	raw, ok := lookup(key)
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, yerr.Newf(yerr.CodeConfig,
			"invalid %s %q (want an integer)", key, raw)
	}
	return v, nil
}
