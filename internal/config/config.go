// Package config owns yalla's resolved, typed configuration.
//
// The package answers a single question for every subcommand: "given the CLI
// flags the user typed, the environment we run in, and the config file on
// disk, what is the effective Yalla API connection profile right now?"
//
// Three contracts are part of yalla's public API:
//
//  1. Precedence is CLI flag > environment variable > config file > built-in
//     default. The Loader respects the parse-time `Changed` bit on each flag
//     so unchanged flags do not silently overwrite lower-priority sources.
//
//  2. Environment variable names are stable: YALLA_BASE_URL, YALLA_TOKEN,
//     YALLA_CONFIG, YALLA_OUTPUT, and YALLA_NO_INPUT. Adding a new variable
//     is a minor change; renaming or removing one is a major change.
//
//  3. Config keys (base_url, token, output, no_input, verbose) are the
//     `yalla config set <key>` surface and the wire format on disk. They are
//     normalised to snake_case and validated on read so a malformed file
//     fails fast with a stable CodeConfig error rather than producing an
//     unpredictable runtime.
//
// The Config struct surfaces both the resolved value and its Source so
// commands like `yalla config get` and `yalla auth status` can explain
// provenance without re-running the resolver.
package config

import (
	"context"
	"strings"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Environment variable names are part of the agent contract. Keep them in
// one place so callers cannot drift.
const (
	EnvBaseURL = "YALLA_BASE_URL"
	EnvToken   = "YALLA_TOKEN"
	EnvConfig  = "YALLA_CONFIG"
	EnvOutput  = "YALLA_OUTPUT"
	EnvNoInput = "YALLA_NO_INPUT"
)

// Config keys exposed through `yalla config get|set` and serialised to disk.
// The string values are part of the public API: scripts and agents may
// reference them.
const (
	KeyBaseURL = "base_url"
	KeyToken   = "token"
	KeyOutput  = "output"
	KeyNoInput = "no_input"
	KeyVerbose = "verbose"
)

// AllKeys lists every settable config key in canonical, deterministic order.
// `yalla config get` (no args) iterates this slice so its output is stable
// across invocations.
var AllKeys = []string{KeyBaseURL, KeyToken, KeyOutput, KeyNoInput, KeyVerbose}

// Source identifies where a resolved value came from. Reported through
// `yalla config get` and `yalla auth status` so agents can audit how a
// decision was made.
type Source string

// Source values. The string forms are public; tests and scripts may match
// on them.
const (
	SourceDefault Source = "default"
	SourceFile    Source = "file"
	SourceEnv     Source = "env"
	SourceFlag    Source = "flag"
	// SourceCredentialStore means the token came from the host OS secure
	// credential store. Only tokens use this source.
	SourceCredentialStore Source = "credential_store"
)

// OutputFormat is the resolved render mode. `output: json` means
// machine-readable JSON envelopes on stdout; `output: human` means plain
// text with the standard error banners on stderr.
type OutputFormat string

// OutputFormat values. The string forms are public.
const (
	OutputHuman OutputFormat = "human"
	OutputJSON  OutputFormat = "json"
)

// IsJSON is the ergonomic check the renderer cares about: is this run a
// machine-readable run? Centralising the comparison keeps callers from
// importing the constant just to do `f == OutputJSON`.
func (f OutputFormat) IsJSON() bool { return f == OutputJSON }

// Config is the resolved, typed configuration consumed by every subcommand.
// Each field is the final value after precedence resolution; the parallel
// *Source fields explain where the value came from. The struct is immutable
// from the subcommand's perspective — pass it by pointer so the same
// resolution travels through the command tree.
type Config struct {
	BaseURL    string
	Token      string
	Output     OutputFormat
	NoInput    bool
	Verbose    bool
	ConfigPath string

	BaseURLSource    Source
	TokenSource      Source
	OutputSource     Source
	NoInputSource    Source
	VerboseSource    Source
	ConfigPathSource Source

	// FileLoaded reports whether ConfigPath actually existed and parsed at
	// load time. A missing file is intentionally NOT an error so yalla works
	// out of the box, but commands like `auth status` use this to explain
	// gaps to users.
	FileLoaded bool
}

// HasToken reports whether a Yalla API token is configured from any
// source. The check is intentionally string-only so callers never need to
// see the value to make the decision.
func (c *Config) HasToken() bool {
	if c == nil {
		return false
	}
	return c.Token != ""
}

// HasBaseURL reports whether a Yalla API base URL is configured.
func (c *Config) HasBaseURL() bool {
	if c == nil {
		return false
	}
	return c.BaseURL != ""
}

// Ready returns nil when the config is sufficient to make an authenticated
// Yalla API call. Otherwise it returns the most specific typed error so
// the caller can surface it through the standard renderer without
// re-classifying.
//
// Token first, then base URL: an unauthenticated user almost always also
// lacks a base URL, but the token error is the primary blocker. The
// `--no-input` mode is honored by callers, not Ready, because Ready does
// not prompt.
func (c *Config) Ready() error {
	if c == nil {
		return yerr.New(yerr.CodeConfig, "yalla config is not initialised")
	}
	if !c.HasToken() {
		return yerr.New(yerr.CodeAuth, "no Yalla API token configured").
			WithHint("run `yalla auth login`, set YALLA_TOKEN, or pass --token")
	}
	if !c.HasBaseURL() {
		return yerr.New(yerr.CodeConfig, "no Yalla API URL configured").
			WithHint("run `yalla auth login`, set YALLA_BASE_URL, or pass --base-url")
	}
	return nil
}

// FlagValues mirrors the persistent flags bound on the root command together
// with parse-time `Changed` bits. The Loader uses the bits to honor CLI flag
// precedence: an unchanged flag (default value still in place) must not beat
// an env var or file value.
type FlagValues struct {
	JSON       bool
	JSONSet    bool
	NoInput    bool
	NoInputSet bool
	Config     string
	ConfigSet  bool
	BaseURL    string
	BaseURLSet bool
	Token      string
	TokenSet   bool
	Verbose    bool
	VerboseSet bool
}

// ParseOutputFormat normalises a string into an OutputFormat. The accepted
// values are the user-facing surface for the YALLA_OUTPUT env var and the
// `output` config key. "text" is accepted as a forgiving alias for "human".
func ParseOutputFormat(s string) (OutputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "human", "text":
		return OutputHuman, nil
	case "json":
		return OutputJSON, nil
	default:
		return "", yerr.Newf(yerr.CodeConfig, "invalid output format %q (want \"json\" or \"human\")", s)
	}
}

// ParseBool is the loader's relaxed boolean parser used for env vars and
// file values. It mirrors strconv.ParseBool but returns a typed CodeConfig
// error on failure so callers do not need to wrap.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "y", "on":
		return true, nil
	case "0", "f", "false", "no", "n", "off":
		return false, nil
	default:
		return false, yerr.Newf(yerr.CodeConfig, "invalid boolean %q (want true or false)", s)
	}
}

// String renders an OutputFormat for serialisation; the zero value falls
// back to the human default so the file format never embeds an empty string.
func (f OutputFormat) String() string {
	if f == "" {
		return string(OutputHuman)
	}
	return string(f)
}

// configKey is the unexported context key the loader uses to stash a
// resolved *Config. Keeping the type unexported prevents accidental
// collisions with values stashed by other packages.
type configKey struct{}

// WithConfig returns ctx annotated with the supplied resolved configuration.
func WithConfig(ctx context.Context, c *Config) context.Context {
	return context.WithValue(ctx, configKey{}, c)
}

// FromContext returns the resolved configuration stored on ctx. When no
// configuration has been loaded the function returns a zero-valued *Config
// rather than nil so callers can safely call HasToken/HasBaseURL without a
// nil check.
func FromContext(ctx context.Context) *Config {
	if v, ok := ctx.Value(configKey{}).(*Config); ok && v != nil {
		return v
	}
	return &Config{Output: OutputHuman}
}
