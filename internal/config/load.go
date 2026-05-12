package config

import (
	stderrors "errors"
	"os"
	"strings"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Loader resolves a *Config by layering CLI flags, environment variables,
// and the on-disk config file. The dependency-injected hooks let tests
// supply deterministic env and file system behaviour without touching real
// process state.
//
// Construct a Loader once per process via NewLoader; subcommands receive the
// resolved *Config through the command context and never call Load
// themselves.
type Loader struct {
	// LookupEnv mirrors os.LookupEnv. Tests inject a map-backed function so
	// the real environment never bleeds into assertions.
	LookupEnv func(string) (string, bool)
	// ReadFile mirrors os.ReadFile via the readFile helper. Override to
	// short-circuit file IO in tests.
	ReadFile func(path string) (FileData, error)
	// UserConfigDir mirrors os.UserConfigDir; used to compute the default
	// config path.
	UserConfigDir func() (string, error)
	// CredentialLookup optionally resolves a token from the host secure
	// credential store after base_url is known. The CLI layer wires this
	// hook so the config package does not import platform keyring code.
	CredentialLookup func(baseURL string) (string, bool)
}

// NewLoader returns a Loader bound to the real process environment and file
// system. The result is safe to share across goroutines because every method
// is read-only.
func NewLoader() *Loader {
	return &Loader{
		LookupEnv:     os.LookupEnv,
		ReadFile:      readFile,
		UserConfigDir: os.UserConfigDir,
	}
}

// Load resolves the supplied flag values into a *Config, applying the
// precedence chain CLI flag > env > file > default. Validation errors
// (invalid base URL, malformed YAML, bogus YALLA_OUTPUT value) surface as
// typed CodeConfig errors so the renderer can map them to exit code 3
// without re-classifying.
func (l *Loader) Load(flags FlagValues) (*Config, error) {
	if l == nil {
		l = NewLoader()
	}
	if l.LookupEnv == nil {
		l.LookupEnv = os.LookupEnv
	}
	if l.ReadFile == nil {
		l.ReadFile = readFile
	}
	if l.UserConfigDir == nil {
		l.UserConfigDir = os.UserConfigDir
	}

	cfg := &Config{Output: OutputHuman}

	// 1. Resolve the config file path. The path itself follows the same
	//    precedence rules: --config > YALLA_CONFIG > default user-config dir.
	pathSource := SourceDefault
	path := DefaultConfigPath(l.UserConfigDir)
	if envPath, ok := l.LookupEnv(EnvConfig); ok && envPath != "" {
		path = envPath
		pathSource = SourceEnv
	}
	if flags.ConfigSet {
		path = flags.Config
		pathSource = SourceFlag
	}
	cfg.ConfigPath = path
	cfg.ConfigPathSource = pathSource

	// 2. Read the file. A missing default file is silent; an explicit user-
	//    supplied path that is missing is also silent (the user might be
	//    initialising state with `yalla config set`). Other read failures
	//    bubble up so a bad permission or stat error never masquerades as a
	//    successful no-op.
	var file FileData
	if path != "" {
		var err error
		file, err = l.ReadFile(path)
		if err != nil {
			if !IsNotExist(err) {
				var typed *yerr.Error
				if stderrors.As(err, &typed) {
					return nil, err
				}
				return nil, yerr.Newf(yerr.CodeConfig, "read %s: %v", path, err)
			}
		} else {
			cfg.FileLoaded = true
		}
	}

	// 3. Resolve each field. The helpers below encapsulate the "flag > env >
	//    file > default" cascade so the Load body stays linear.
	cfg.BaseURL, cfg.BaseURLSource = l.resolveString(
		flags.BaseURLSet, flags.BaseURL,
		EnvBaseURL,
		file.BaseURL,
		"",
	)
	if cfg.BaseURL != "" {
		if err := validateBaseURL(cfg.BaseURL); err != nil {
			return nil, err
		}
	}

	cfg.Token, cfg.TokenSource = l.resolveString(
		flags.TokenSet, flags.Token,
		EnvToken,
		"",
		"",
	)
	if cfg.Token == "" && cfg.BaseURL != "" && l.CredentialLookup != nil {
		if token, ok := l.CredentialLookup(cfg.BaseURL); ok && token != "" {
			cfg.Token = token
			cfg.TokenSource = SourceCredentialStore
		}
	}
	if cfg.Token == "" && file.Token != "" {
		cfg.Token = file.Token
		cfg.TokenSource = SourceFile
	}

	output, outputSource, err := l.resolveOutput(flags, file)
	if err != nil {
		return nil, err
	}
	cfg.Output = output
	cfg.OutputSource = outputSource

	noInput, noInputSource, err := l.resolveNoInput(flags, file)
	if err != nil {
		return nil, err
	}
	cfg.NoInput = noInput
	cfg.NoInputSource = noInputSource

	verbose, verboseSource := l.resolveVerbose(flags, file)
	cfg.Verbose = verbose
	cfg.VerboseSource = verboseSource

	return cfg, nil
}

// resolveString applies the precedence chain for string-valued fields. The
// envName is consulted only when the CLI flag was not changed; the file
// value wins last and the default closes the chain.
func (l *Loader) resolveString(flagSet bool, flagValue, envName, fileValue, defaultValue string) (string, Source) {
	if flagSet {
		return flagValue, SourceFlag
	}
	if v, ok := l.LookupEnv(envName); ok && v != "" {
		return v, SourceEnv
	}
	if fileValue != "" {
		return fileValue, SourceFile
	}
	return defaultValue, SourceDefault
}

// resolveOutput is its own helper because YALLA_OUTPUT and the `output`
// config key are validated, while `--json` is a bool that maps onto
// OutputJSON / OutputHuman.
func (l *Loader) resolveOutput(flags FlagValues, file FileData) (OutputFormat, Source, error) {
	if flags.JSONSet {
		if flags.JSON {
			return OutputJSON, SourceFlag, nil
		}
		return OutputHuman, SourceFlag, nil
	}
	if v, ok := l.LookupEnv(EnvOutput); ok && v != "" {
		of, err := ParseOutputFormat(v)
		if err != nil {
			return "", "", err
		}
		return of, SourceEnv, nil
	}
	if file.Output != "" {
		return file.Output, SourceFile, nil
	}
	return OutputHuman, SourceDefault, nil
}

// resolveNoInput layers --no-input > YALLA_NO_INPUT > file > default(false).
// The env value is parsed with the relaxed boolean grammar so common shell
// idioms (1/0, yes/no) all work.
func (l *Loader) resolveNoInput(flags FlagValues, file FileData) (bool, Source, error) {
	if flags.NoInputSet {
		return flags.NoInput, SourceFlag, nil
	}
	if v, ok := l.LookupEnv(EnvNoInput); ok && v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return false, "", err
		}
		return b, SourceEnv, nil
	}
	if file.NoInput != nil {
		return *file.NoInput, SourceFile, nil
	}
	return false, SourceDefault, nil
}

// resolveVerbose has no env binding (intentionally — the agent contract
// fixes the env var list) so its precedence chain is flag > file > default.
func (l *Loader) resolveVerbose(flags FlagValues, file FileData) (bool, Source) {
	if flags.VerboseSet {
		return flags.Verbose, SourceFlag
	}
	if file.Verbose != nil {
		return *file.Verbose, SourceFile
	}
	return false, SourceDefault
}

// SetValue applies a single `yalla config set <key> <value>` mutation onto
// an existing FileData. The function is exported so the CLI layer can
// validate the value, merge it into the on-disk shape, and write the result
// without reaching for unexported helpers.
func SetValue(base FileData, key, value string) (FileData, error) {
	switch key {
	case KeyBaseURL:
		v := strings.TrimSpace(value)
		if v != "" {
			if err := validateBaseURL(v); err != nil {
				return FileData{}, err
			}
		}
		base.BaseURL = v
		return base, nil
	case KeyToken:
		base.Token = value
		return base, nil
	case KeyOutput:
		of, err := ParseOutputFormat(value)
		if err != nil {
			return FileData{}, err
		}
		base.Output = of
		return base, nil
	case KeyNoInput:
		b, err := ParseBool(value)
		if err != nil {
			return FileData{}, err
		}
		base.NoInput = &b
		return base, nil
	case KeyVerbose:
		b, err := ParseBool(value)
		if err != nil {
			return FileData{}, err
		}
		base.Verbose = &b
		return base, nil
	default:
		return FileData{}, yerr.Newf(yerr.CodeInvalidInput, "unknown config key %q (want one of %s)", key, strings.Join(AllKeys, ", "))
	}
}

// ResolvedValue returns the resolved value of key together with its source.
// Used by `yalla config get <key>`. Unknown keys return a typed
// CodeInvalidInput error so the JSON envelope stays stable.
func (c *Config) ResolvedValue(key string) (string, Source, error) {
	if c == nil {
		return "", "", yerr.New(yerr.CodeInternal, "yalla config is not initialised")
	}
	switch key {
	case KeyBaseURL:
		return c.BaseURL, c.BaseURLSource, nil
	case KeyToken:
		return c.Token, c.TokenSource, nil
	case KeyOutput:
		return string(c.Output), c.OutputSource, nil
	case KeyNoInput:
		return boolString(c.NoInput), c.NoInputSource, nil
	case KeyVerbose:
		return boolString(c.Verbose), c.VerboseSource, nil
	default:
		return "", "", yerr.Newf(yerr.CodeInvalidInput, "unknown config key %q (want one of %s)", key, strings.Join(AllKeys, ", "))
	}
}

// boolString renders a bool in the canonical surface form. Centralising
// the conversion keeps `yalla config get` output stable across `true/false`
// vs `1/0` shell idioms.
func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// IsKnownKey reports whether key is one of the canonical config keys. The
// helper exists so command code can validate user input without importing
// the AllKeys slice directly.
func IsKnownKey(key string) bool {
	for _, k := range AllKeys {
		if k == key {
			return true
		}
	}
	return false
}

// EnvSnapshot is the read-only env view consumed by the parse-time error
// renderer. The renderer needs YALLA_OUTPUT and YALLA_TOKEN to honor the
// JSON envelope and redaction contracts even when cobra fails before
// PersistentPreRunE runs the full Loader.
type EnvSnapshot struct {
	Output OutputFormat
	Token  string
}

// SnapshotForRenderer returns the minimum env-var view the terminal error
// renderer needs. Unlike Load, this never returns an error: a malformed
// YALLA_OUTPUT just reverts to OutputHuman so an agent that asked for JSON
// still gets a JSON envelope when at least YALLA_OUTPUT=json was set.
func (l *Loader) SnapshotForRenderer() EnvSnapshot {
	if l == nil {
		l = NewLoader()
	}
	snap := EnvSnapshot{Output: OutputHuman}
	if v, ok := l.LookupEnv(EnvOutput); ok {
		if of, err := ParseOutputFormat(v); err == nil {
			snap.Output = of
		}
	}
	if v, ok := l.LookupEnv(EnvToken); ok {
		snap.Token = v
	}
	return snap
}
