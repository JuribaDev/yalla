package config

import (
	"errors"
	stdfs "io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fileShape is the on-disk YAML representation. Keep field tags in
// canonical snake_case so the file format matches the `yalla config set`
// surface verbatim. Unknown keys are intentionally rejected so a typo in a
// hand-edited file fails fast instead of being silently ignored.
type fileShape struct {
	BaseURL string `yaml:"base_url,omitempty"`
	Token   string `yaml:"token,omitempty"`
	Output  string `yaml:"output,omitempty"`
	NoInput *bool  `yaml:"no_input,omitempty"`
	Verbose *bool  `yaml:"verbose,omitempty"`
}

// FileData is the validated, in-memory shape of a parsed config file. Each
// *bool stays addressable so the loader can distinguish "key present and
// false" from "key absent" — the latter must defer to lower-priority
// sources, the former must win.
type FileData struct {
	BaseURL string
	Token   string
	Output  OutputFormat
	NoInput *bool
	Verbose *bool

	// Path is the absolute path the data was read from. Empty when the file
	// did not exist.
	Path string
}

// secureFileMode is the permission the loader stamps on newly-written
// config files. 0600 keeps tokens out of other users' read paths on shared
// hosts.
const secureFileMode os.FileMode = 0o600

// secureDirMode is the permission used for directories the loader auto-
// creates (e.g. the platform-specific config dir on first use).
const secureDirMode os.FileMode = 0o700

// readFile opens path, parses it as the canonical config YAML shape, and
// returns the validated FileData. A missing file is reported via os.ErrNotExist
// so callers can decide whether absence is fatal (explicit --config) or
// silent (default path on a fresh install).
func readFile(path string) (FileData, error) {
	if path == "" {
		return FileData{}, os.ErrNotExist
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return FileData{}, err
	}
	var shape fileShape
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&shape); err != nil {
		// An empty file decodes to io.EOF; treat that as "no values" so a
		// freshly-created file does not break the loader.
		if errors.Is(err, errEOF()) {
			return FileData{Path: path}, nil
		}
		return FileData{}, yerr.Newf(yerr.CodeConfig, "parse %s: %v", path, err)
	}
	out := FileData{
		BaseURL: strings.TrimSpace(shape.BaseURL),
		Token:   shape.Token,
		Path:    path,
		NoInput: shape.NoInput,
		Verbose: shape.Verbose,
	}
	if shape.Output != "" {
		of, err := ParseOutputFormat(shape.Output)
		if err != nil {
			return FileData{}, yerr.Newf(yerr.CodeConfig, "parse %s: %v", path, err)
		}
		out.Output = of
	}
	if out.BaseURL != "" {
		if err := validateBaseURL(out.BaseURL); err != nil {
			return FileData{}, yerr.Newf(yerr.CodeConfig, "parse %s: %v", path, err)
		}
	}
	return out, nil
}

// errEOF returns yaml's empty-document sentinel without forcing every caller
// to import the package directly. yaml.v3 surfaces an io.EOF wrapped under
// its own error chain when the file contains no documents.
func errEOF() error { return yamlEOF }

// yamlEOF is captured once so errors.Is comparisons stay cheap.
var yamlEOF = func() error {
	dec := yaml.NewDecoder(strings.NewReader(""))
	var v any
	return dec.Decode(&v)
}()

// validateBaseURL checks that a configured base URL parses as an absolute
// http(s) URL. Catching this at config-load time means raw API calls do not
// fail with cryptic dial errors after the user has already typed a long
// command.
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return yerr.Newf(yerr.CodeConfig, "invalid base URL %q: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return yerr.Newf(yerr.CodeConfig, "invalid base URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return yerr.Newf(yerr.CodeConfig, "invalid base URL %q: missing host", raw)
	}
	return nil
}

// WriteFile serialises the supplied data to path in the canonical YAML shape
// used by `yalla config set`. The parent directory is created with 0700 if
// necessary and the file itself is written with 0600 so credentials never
// land on a world-readable path.
//
// Existing fields not represented in data are preserved by reading the file
// first; callers that want a clean overwrite should pass a fresh struct
// alongside an explicit Token/BaseURL/etc.
func WriteFile(path string, data FileData) error {
	if path == "" {
		return yerr.New(yerr.CodeConfig, "config path is empty; cannot write")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, secureDirMode); err != nil {
			return yerr.Newf(yerr.CodeConfig, "create config dir %s: %v", dir, err)
		}
	}
	shape := fileShape{
		BaseURL: data.BaseURL,
		Token:   data.Token,
		Output:  string(data.Output),
		NoInput: data.NoInput,
		Verbose: data.Verbose,
	}
	if shape.Output == string(OutputHuman) {
		// Persist the explicit "human" only when the user actually typed it.
		// The zero-value path ("") leaves the file lean.
		if data.Output == "" {
			shape.Output = ""
		}
	}
	out, err := yaml.Marshal(shape)
	if err != nil {
		return yerr.Newf(yerr.CodeInternal, "marshal config: %v", err)
	}
	if err := os.WriteFile(path, out, secureFileMode); err != nil {
		return yerr.Newf(yerr.CodeConfig, "write %s: %v", path, err)
	}
	return nil
}

// MergeFileData returns a copy of base with the non-zero fields from update
// applied over it. Pointer-typed booleans only override when explicitly set
// in update, which lets `yalla config set` preserve unrelated keys on disk.
func MergeFileData(base, update FileData) FileData {
	out := base
	if update.BaseURL != "" {
		out.BaseURL = update.BaseURL
	}
	if update.Token != "" {
		out.Token = update.Token
	}
	if update.Output != "" {
		out.Output = update.Output
	}
	if update.NoInput != nil {
		v := *update.NoInput
		out.NoInput = &v
	}
	if update.Verbose != nil {
		v := *update.Verbose
		out.Verbose = &v
	}
	if update.Path != "" {
		out.Path = update.Path
	}
	return out
}

// DefaultConfigPath returns the path the loader uses when neither --config
// nor YALLA_CONFIG points at a specific file. The implementation defers to
// os.UserConfigDir, which is the cross-platform standard:
//
//	macOS:   ~/Library/Application Support/yalla/config.yaml
//	Linux:   $XDG_CONFIG_HOME/yalla/config.yaml or ~/.config/yalla/config.yaml
//	Windows: %AppData%/yalla/config.yaml
//
// The function returns an empty string if no config dir can be determined
// (e.g. an init container with no $HOME); callers must treat that as
// "no default file" rather than as an error.
func DefaultConfigPath(userConfigDir func() (string, error)) string {
	if userConfigDir == nil {
		userConfigDir = os.UserConfigDir
	}
	dir, err := userConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "yalla", "config.yaml")
}

// IsNotExist is a thin wrapper around the standard helpers so the loader can
// stay agnostic about whether the file system surfaced os.ErrNotExist or a
// fs.PathError.
func IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var pathErr *stdfs.PathError
	return errors.As(err, &pathErr) && errors.Is(pathErr.Err, os.ErrNotExist)
}
