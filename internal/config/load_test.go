package config

import (
	stderrors "errors"
	"os"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// envMap is a deterministic env source used in every test. Each test
// constructs its own map so the real os.Environ never bleeds in.
type envMap map[string]string

func (m envMap) Lookup(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// newTestLoader returns a Loader wired to in-memory env and file fixtures.
// Missing files are reported as os.ErrNotExist so the loader's silent-
// absence path is exercised.
func newTestLoader(env envMap, files map[string]FileData) *Loader {
	return &Loader{
		LookupEnv: env.Lookup,
		ReadFile: func(path string) (FileData, error) {
			if d, ok := files[path]; ok {
				return d, nil
			}
			return FileData{}, os.ErrNotExist
		},
		UserConfigDir: func() (string, error) { return "/test/config", nil },
	}
}

func TestLoad_DefaultsWhenNothingSet(t *testing.T) {
	t.Parallel()
	l := newTestLoader(envMap{}, nil)

	cfg, err := l.Load(FlagValues{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty", cfg.BaseURL)
	}
	if cfg.Token != "" {
		t.Errorf("Token = %q, want empty", cfg.Token)
	}
	if cfg.Output != OutputHuman {
		t.Errorf("Output = %q, want %q", cfg.Output, OutputHuman)
	}
	if cfg.NoInput {
		t.Errorf("NoInput = true, want false")
	}
	if cfg.OutputSource != SourceDefault {
		t.Errorf("OutputSource = %q, want %q", cfg.OutputSource, SourceDefault)
	}
	if cfg.ConfigPath != "/test/config/yalla/config.yaml" {
		t.Errorf("ConfigPath = %q, want default", cfg.ConfigPath)
	}
	if cfg.FileLoaded {
		t.Error("FileLoaded = true; expected false when no file exists")
	}
}

func TestLoad_FlagBeatsEverything(t *testing.T) {
	t.Parallel()
	files := map[string]FileData{
		"/test/config/yalla/config.yaml": {
			BaseURL: "https://from-file.example.com",
			Token:   "from-file-token",
			Output:  OutputJSON,
		},
	}
	env := envMap{
		EnvBaseURL: "https://from-env.example.com",
		EnvToken:   "from-env-token",
		EnvOutput:  "human",
	}
	l := newTestLoader(env, files)

	cfg, err := l.Load(FlagValues{
		BaseURL:    "https://from-flag.example.com",
		BaseURLSet: true,
		Token:      "from-flag-token",
		TokenSet:   true,
		JSON:       true,
		JSONSet:    true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://from-flag.example.com" {
		t.Errorf("BaseURL = %q, want flag value", cfg.BaseURL)
	}
	if cfg.BaseURLSource != SourceFlag {
		t.Errorf("BaseURLSource = %q, want %q", cfg.BaseURLSource, SourceFlag)
	}
	if cfg.Token != "from-flag-token" {
		t.Errorf("Token = %q, want flag value", cfg.Token)
	}
	if cfg.TokenSource != SourceFlag {
		t.Errorf("TokenSource = %q, want %q", cfg.TokenSource, SourceFlag)
	}
	if cfg.Output != OutputJSON {
		t.Errorf("Output = %q, want json", cfg.Output)
	}
	if cfg.OutputSource != SourceFlag {
		t.Errorf("OutputSource = %q, want %q", cfg.OutputSource, SourceFlag)
	}
}

func TestLoad_EnvBeatsFile(t *testing.T) {
	t.Parallel()
	files := map[string]FileData{
		"/test/config/yalla/config.yaml": {
			BaseURL: "https://from-file.example.com",
			Token:   "from-file-token",
			Output:  OutputHuman,
		},
	}
	env := envMap{
		EnvBaseURL: "https://from-env.example.com",
		EnvToken:   "from-env-token",
		EnvOutput:  "json",
		EnvNoInput: "true",
	}
	l := newTestLoader(env, files)

	cfg, err := l.Load(FlagValues{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://from-env.example.com" {
		t.Errorf("BaseURL = %q, want env value", cfg.BaseURL)
	}
	if cfg.BaseURLSource != SourceEnv {
		t.Errorf("BaseURLSource = %q, want %q", cfg.BaseURLSource, SourceEnv)
	}
	if cfg.Output != OutputJSON {
		t.Errorf("Output = %q, want json", cfg.Output)
	}
	if !cfg.NoInput {
		t.Errorf("NoInput = false, want true (from env)")
	}
	if cfg.NoInputSource != SourceEnv {
		t.Errorf("NoInputSource = %q, want %q", cfg.NoInputSource, SourceEnv)
	}
}

func TestLoad_FileBeatsDefaults(t *testing.T) {
	t.Parallel()
	noInputTrue := true
	files := map[string]FileData{
		"/test/config/yalla/config.yaml": {
			BaseURL: "https://from-file.example.com",
			Token:   "from-file-token",
			Output:  OutputJSON,
			NoInput: &noInputTrue,
		},
	}
	l := newTestLoader(envMap{}, files)

	cfg, err := l.Load(FlagValues{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://from-file.example.com" {
		t.Errorf("BaseURL = %q, want file value", cfg.BaseURL)
	}
	if cfg.BaseURLSource != SourceFile {
		t.Errorf("BaseURLSource = %q, want %q", cfg.BaseURLSource, SourceFile)
	}
	if !cfg.NoInput {
		t.Errorf("NoInput = false, want true (from file)")
	}
	if cfg.NoInputSource != SourceFile {
		t.Errorf("NoInputSource = %q, want %q", cfg.NoInputSource, SourceFile)
	}
	if !cfg.FileLoaded {
		t.Error("FileLoaded = false; expected true after parsing the file")
	}
}

func TestLoad_FlagJSONFalseStillBeatsEnv(t *testing.T) {
	t.Parallel()
	env := envMap{EnvOutput: "json"}
	l := newTestLoader(env, nil)

	cfg, err := l.Load(FlagValues{
		JSON:    false,
		JSONSet: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output != OutputHuman {
		t.Errorf("Output = %q, want human (explicit --json=false)", cfg.Output)
	}
	if cfg.OutputSource != SourceFlag {
		t.Errorf("OutputSource = %q, want %q", cfg.OutputSource, SourceFlag)
	}
}

func TestLoad_ConfigPathPrecedence(t *testing.T) {
	t.Parallel()
	files := map[string]FileData{
		"/from/flag.yaml": {Token: "flag-file-token"},
		"/from/env.yaml":  {Token: "env-file-token"},
	}
	t.Run("flag wins", func(t *testing.T) {
		l := newTestLoader(envMap{EnvConfig: "/from/env.yaml"}, files)
		cfg, err := l.Load(FlagValues{Config: "/from/flag.yaml", ConfigSet: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ConfigPath != "/from/flag.yaml" {
			t.Errorf("ConfigPath = %q, want flag value", cfg.ConfigPath)
		}
		if cfg.ConfigPathSource != SourceFlag {
			t.Errorf("ConfigPathSource = %q, want %q", cfg.ConfigPathSource, SourceFlag)
		}
		if cfg.Token != "flag-file-token" {
			t.Errorf("Token = %q, want %q", cfg.Token, "flag-file-token")
		}
	})
	t.Run("env wins over default", func(t *testing.T) {
		l := newTestLoader(envMap{EnvConfig: "/from/env.yaml"}, files)
		cfg, err := l.Load(FlagValues{})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ConfigPath != "/from/env.yaml" {
			t.Errorf("ConfigPath = %q, want env value", cfg.ConfigPath)
		}
		if cfg.ConfigPathSource != SourceEnv {
			t.Errorf("ConfigPathSource = %q, want %q", cfg.ConfigPathSource, SourceEnv)
		}
	})
}

func TestLoad_MissingExplicitConfigIsNotAnError(t *testing.T) {
	t.Parallel()
	// The user typed --config /nope/missing.yaml but the file doesn't exist.
	// The agent contract says yalla still works as long as the rest of the
	// configuration covers the gap.
	l := newTestLoader(envMap{EnvBaseURL: "https://example.com", EnvToken: "tok"}, nil)
	cfg, err := l.Load(FlagValues{Config: "/nope/missing.yaml", ConfigSet: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FileLoaded {
		t.Error("FileLoaded = true; expected false for a missing path")
	}
	if cfg.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %q, want env fallback", cfg.BaseURL)
	}
}

func TestLoad_FileReadErrorOtherThanNotExistBubblesUp(t *testing.T) {
	t.Parallel()
	bad := stderrors.New("permission denied")
	l := &Loader{
		LookupEnv:     envMap{}.Lookup,
		ReadFile:      func(path string) (FileData, error) { return FileData{}, bad },
		UserConfigDir: func() (string, error) { return "/test/config", nil },
	}
	_, err := l.Load(FlagValues{})
	if err == nil {
		t.Fatal("Load returned nil for non-not-exist read error")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestLoad_InvalidBaseURLFromFlagFailsWithCodeConfig(t *testing.T) {
	t.Parallel()
	l := newTestLoader(envMap{}, nil)
	_, err := l.Load(FlagValues{BaseURL: "::not-a-url", BaseURLSet: true})
	if err == nil {
		t.Fatal("Load returned nil error for invalid base URL")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestLoad_InvalidBaseURLSchemeFromEnvFails(t *testing.T) {
	t.Parallel()
	env := envMap{EnvBaseURL: "ftp://example.com"}
	l := newTestLoader(env, nil)
	_, err := l.Load(FlagValues{})
	if err == nil {
		t.Fatal("Load returned nil error for unsupported scheme")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
	if !strings.Contains(typed.Message, "scheme") {
		t.Errorf("Message = %q, want to mention scheme", typed.Message)
	}
}

func TestLoad_InvalidYALLAOutputFails(t *testing.T) {
	t.Parallel()
	env := envMap{EnvOutput: "xml"}
	l := newTestLoader(env, nil)
	_, err := l.Load(FlagValues{})
	if err == nil {
		t.Fatal("Load returned nil for invalid YALLA_OUTPUT")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestLoad_InvalidYALLANoInputFails(t *testing.T) {
	t.Parallel()
	env := envMap{EnvNoInput: "kinda"}
	l := newTestLoader(env, nil)
	_, err := l.Load(FlagValues{})
	if err == nil {
		t.Fatal("Load returned nil for invalid YALLA_NO_INPUT")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestLoad_NoInputFromFlagBeatsEnv(t *testing.T) {
	t.Parallel()
	// --no-input always takes priority. An agent passing the flag must never
	// be overridden by an env var that someone else set in the shell.
	l := newTestLoader(envMap{EnvNoInput: "false"}, nil)
	cfg, err := l.Load(FlagValues{NoInput: true, NoInputSet: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.NoInput {
		t.Error("NoInput = false, want true (flag must beat env)")
	}
	if cfg.NoInputSource != SourceFlag {
		t.Errorf("NoInputSource = %q, want %q", cfg.NoInputSource, SourceFlag)
	}
}

func TestConfig_Ready(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     *Config
		wantErr yerr.Code
	}{
		{"missing token", &Config{BaseURL: "https://example.com"}, yerr.CodeAuth},
		{"missing base", &Config{Token: "tok"}, yerr.CodeConfig},
		{"both set", &Config{Token: "tok", BaseURL: "https://example.com"}, ""},
		{"nil receiver", nil, yerr.CodeConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Ready()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Ready() = %v, want nil", err)
				}
				return
			}
			var typed *yerr.Error
			if !stderrors.As(err, &typed) {
				t.Fatalf("error not typed: %v", err)
			}
			if typed.Code != tc.wantErr {
				t.Errorf("Code = %q, want %q", typed.Code, tc.wantErr)
			}
		})
	}
}

func TestSetValue_KnownKeysRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key   string
		value string
		check func(FileData) error
	}{
		{KeyBaseURL, "https://example.com", func(d FileData) error {
			if d.BaseURL != "https://example.com" {
				return stderrors.New("base_url not set")
			}
			return nil
		}},
		{KeyToken, "secret-token-value", func(d FileData) error {
			if d.Token != "secret-token-value" {
				return stderrors.New("token not set")
			}
			return nil
		}},
		{KeyOutput, "json", func(d FileData) error {
			if d.Output != OutputJSON {
				return stderrors.New("output not json")
			}
			return nil
		}},
		{KeyNoInput, "true", func(d FileData) error {
			if d.NoInput == nil || !*d.NoInput {
				return stderrors.New("no_input not true")
			}
			return nil
		}},
		{KeyVerbose, "true", func(d FileData) error {
			if d.Verbose == nil || !*d.Verbose {
				return stderrors.New("verbose not true")
			}
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			out, err := SetValue(FileData{}, tc.key, tc.value)
			if err != nil {
				t.Fatalf("SetValue: %v", err)
			}
			if err := tc.check(out); err != nil {
				t.Fatalf("check: %v", err)
			}
		})
	}
}

func TestSetValue_UnknownKeyReturnsCodeInvalidInput(t *testing.T) {
	t.Parallel()
	_, err := SetValue(FileData{}, "no_such_key", "value")
	if err == nil {
		t.Fatal("SetValue accepted unknown key")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeInvalidInput {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeInvalidInput)
	}
}

func TestSetValue_InvalidBaseURLFails(t *testing.T) {
	t.Parallel()
	_, err := SetValue(FileData{}, KeyBaseURL, "ftp://example.com")
	if err == nil {
		t.Fatal("SetValue accepted invalid scheme")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestParseOutputFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want OutputFormat
		err  bool
	}{
		{"json", OutputJSON, false},
		{"JSON", OutputJSON, false},
		{"human", OutputHuman, false},
		{"text", OutputHuman, false},
		{"", OutputHuman, false},
		{"xml", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseOutputFormat(tc.in)
			if tc.err {
				if err == nil {
					t.Errorf("ParseOutputFormat(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseOutputFormat(%q): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseOutputFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"1", "t", "TRUE", "yes", "y", "on"} {
		got, err := ParseBool(in)
		if err != nil || !got {
			t.Errorf("ParseBool(%q) = %v, %v; want true, nil", in, got, err)
		}
	}
	for _, in := range []string{"0", "false", "no", "OFF"} {
		got, err := ParseBool(in)
		if err != nil || got {
			t.Errorf("ParseBool(%q) = %v, %v; want false, nil", in, got, err)
		}
	}
	if _, err := ParseBool("kinda"); err == nil {
		t.Error("ParseBool(\"kinda\") accepted invalid input")
	}
}

func TestSnapshotForRenderer(t *testing.T) {
	t.Parallel()
	t.Run("env populated", func(t *testing.T) {
		l := newTestLoader(envMap{EnvOutput: "json", EnvToken: "secret-token-value"}, nil)
		snap := l.SnapshotForRenderer()
		if !snap.Output.IsJSON() {
			t.Errorf("Output = %q, want json", snap.Output)
		}
		if snap.Token == "" {
			t.Errorf("Token snapshot empty; expected env value to flow through")
		}
	})
	t.Run("invalid output silently falls back", func(t *testing.T) {
		l := newTestLoader(envMap{EnvOutput: "xml"}, nil)
		snap := l.SnapshotForRenderer()
		if snap.Output != OutputHuman {
			t.Errorf("Output = %q, want human (silent fallback for parse-time renderer)", snap.Output)
		}
	})
}

func TestIsKnownKey(t *testing.T) {
	t.Parallel()
	for _, k := range AllKeys {
		if !IsKnownKey(k) {
			t.Errorf("IsKnownKey(%q) = false, want true", k)
		}
	}
	if IsKnownKey("nonsense") {
		t.Error("IsKnownKey(\"nonsense\") = true, want false")
	}
}
