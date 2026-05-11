package cli

import (
	"bytes"
	stderrors "errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newConfigCommand builds the `yalla config` subtree. Two subcommands ship
// today: `get` (read resolved values + provenance) and `set` (write a key
// to disk). The structure leaves room for `unset`, `path`, and `validate`
// in later stories without changing the existing surface.
func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and write yalla configuration",
		Long: `Inspect or modify yalla's resolved configuration.

Yalla layers configuration in a fixed precedence order:

  CLI flag > environment variable > config file > built-in default

` + "`yalla config get`" + ` reports the resolved value of every setting
together with the source it came from, so an agent can audit why yalla is
behaving the way it is.

` + "`yalla config set`" + ` persists a key/value pair to the config file at
the resolved --config path (or YALLA_CONFIG, or the platform default), with
0600 perms so credentials never land on a world-readable path.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newConfigGetCommand())
	cmd.AddCommand(newConfigSetCommand())
	return cmd
}

// configValueDoc is the JSON shape returned for a single resolved value.
// `value` is omitted for the `token` key so the secret never appears on
// stdout; the `set` boolean tells agents whether the value is configured
// without revealing it.
type configValueDoc struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Set    bool   `json:"set"`
	Source string `json:"source"`
	// Secret marks the field as redacted in the human renderer and value-
	// suppressed in the JSON renderer. Today only `token` is secret.
	Secret bool `json:"secret,omitempty"`
}

// configGetDoc is the JSON shape returned by `yalla config get` (no args).
// The Items array preserves AllKeys order so agents can rely on a stable
// schema without sorting.
type configGetDoc struct {
	ConfigPath       string           `json:"config_path"`
	ConfigPathSource config.Source    `json:"config_path_source"`
	FileLoaded       bool             `json:"file_loaded"`
	Items            []configValueDoc `json:"items"`
}

// configSetDoc is the JSON shape returned by `yalla config set`. It echoes
// the key (never the value, since it might be a secret) and the path that
// was written so agents can confirm the write landed where they expected.
type configSetDoc struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

func newConfigGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [key]",
		Short: "Print the resolved value of one or all config keys",
		Long: `Print the resolved value of every (or one) config key together with the
source it came from (flag, env, file, default).

The token value is intentionally never printed; only its presence and
source are reported. Keys: ` + strings.Join(config.AllKeys, ", ") + `.`,
		Example: `  yalla config get
  yalla config get base_url
  yalla --json config get`,
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			cfg := config.FromContext(c.Context())
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			if len(args) == 0 {
				return runConfigGetAll(r, cfg)
			}
			return runConfigGetOne(r, cfg, args[0])
		},
	}
	return cmd
}

func newConfigSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Persist a config key to disk",
		Long: `Persist a single config key to the active config file. The file is
created with 0600 perms inside a 0700 parent directory so credentials never
land on a world-readable path.

Allowed keys: ` + strings.Join(config.AllKeys, ", ") + `.

The active config file path follows the same precedence chain as every
other setting: --config > YALLA_CONFIG > the platform-default location
(use ` + "`yalla config get config_path`" + ` to confirm).`,
		Example: `  yalla config set base_url https://dokploy.example.com
  yalla config set token "$DOKPLOY_TOKEN"
  yalla config set output json`,
		Args:          cobra.ExactArgs(2),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			cfg := config.FromContext(c.Context())
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runConfigSet(r, cfg, args[0], args[1])
		},
	}
	return cmd
}

// runConfigGetAll renders every resolved config key together with its
// provenance. Token is rendered with a [REDACTED] placeholder in human mode
// and as `set: true` (no value) in JSON mode.
func runConfigGetAll(r *output.Renderer, cfg *config.Config) error {
	doc := configGetDoc{
		ConfigPath:       cfg.ConfigPath,
		ConfigPathSource: cfg.ConfigPathSource,
		FileLoaded:       cfg.FileLoaded,
		Items:            make([]configValueDoc, 0, len(config.AllKeys)),
	}
	for _, key := range config.AllKeys {
		item, err := buildConfigValueDoc(cfg, key)
		if err != nil {
			return err
		}
		doc.Items = append(doc.Items, item)
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb bytes.Buffer
	headers := []string{"KEY", "VALUE", "SOURCE"}
	rows := make([][]string, 0, len(doc.Items)+1)
	rows = append(rows, []string{"config_path", cfg.ConfigPath, string(cfg.ConfigPathSource)})
	for _, item := range doc.Items {
		display := item.Value
		if item.Secret {
			if item.Set {
				display = output.Sentinel
			} else {
				display = ""
			}
		}
		rows = append(rows, []string{item.Key, display, item.Source})
	}
	if err := output.Table(&sb, headers, rows); err != nil {
		return yerr.Newf(yerr.CodeInternal, "render config table: %v", err)
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// runConfigGetOne renders a single resolved key. Unknown keys round-trip
// through SetValue's typed CodeInvalidInput error.
func runConfigGetOne(r *output.Renderer, cfg *config.Config, key string) error {
	if !config.IsKnownKey(key) {
		return yerr.Newf(yerr.CodeInvalidInput, "unknown config key %q (want one of %s)", key, strings.Join(config.AllKeys, ", "))
	}
	item, err := buildConfigValueDoc(cfg, key)
	if err != nil {
		return err
	}
	if r.JSON() {
		return r.Data(item)
	}
	display := item.Value
	if item.Secret {
		if item.Set {
			display = output.Sentinel
		} else {
			display = ""
		}
	}
	r.Human(display)
	return nil
}

// runConfigSet validates and persists key=value to the active config file.
// The function refuses to write when no path is resolvable (e.g. a sandbox
// with no $HOME and no --config flag) so the user gets a clean CodeConfig
// error instead of a permission-denied stack trace.
func runConfigSet(r *output.Renderer, cfg *config.Config, key, value string) error {
	if cfg.ConfigPath == "" {
		return yerr.New(yerr.CodeConfig, "no config file path resolvable").
			WithHint("pass --config <path> or set YALLA_CONFIG=<path>")
	}

	existing, err := readExistingFile(cfg.ConfigPath)
	if err != nil {
		return err
	}

	updated, err := config.SetValue(existing, key, value)
	if err != nil {
		return err
	}

	if err := config.WriteFile(cfg.ConfigPath, updated); err != nil {
		return err
	}

	doc := configSetDoc{Key: key, Path: cfg.ConfigPath}
	if r.JSON() {
		return r.Data(doc)
	}
	// Human mode never echoes the value (it might be a secret); the path
	// confirmation is enough for an interactive user.
	r.Human("wrote " + key + " to " + cfg.ConfigPath)
	return nil
}

// readExistingFile loads the on-disk file into a FileData so the loader's
// merge semantics are honoured. Missing files are intentionally treated as
// "no prior content" because `yalla config set` is the canonical way to
// initialise a fresh config file from scratch.
func readExistingFile(path string) (config.FileData, error) {
	d, err := readFileForCommand(path)
	if err == nil {
		return d, nil
	}
	if config.IsNotExist(err) {
		return config.FileData{Path: path}, nil
	}
	var typed *yerr.Error
	if stderrors.As(err, &typed) {
		return config.FileData{}, err
	}
	return config.FileData{}, yerr.Newf(yerr.CodeConfig, "read %s: %v", path, err)
}

// readFileForCommand is a thin wrapper that lets future tests stub the
// on-disk read. The real implementation defers to the config package's
// validated reader (re-exported through Loader.ReadFile to avoid leaking
// internal helpers).
var readFileForCommand = func(path string) (config.FileData, error) {
	return config.NewLoader().ReadFile(path)
}

// buildConfigValueDoc renders the per-key shape used by both `config get
// <key>` and `config get` (no args). Centralising the secret-suppression
// rule here means the rendering layer never has to remember which key is a
// token.
//
// `set` means "the user explicitly configured this key" (i.e. the source is
// not the built-in default). Using source-based detection keeps the bit
// meaningful for boolean keys too: a verbose=false default reads as set=false
// even though its rendered value string ("false") is non-empty.
func buildConfigValueDoc(cfg *config.Config, key string) (configValueDoc, error) {
	value, source, err := cfg.ResolvedValue(key)
	if err != nil {
		return configValueDoc{}, err
	}
	doc := configValueDoc{
		Key:    key,
		Source: string(source),
		Set:    source != config.SourceDefault,
	}
	if key == config.KeyToken {
		doc.Secret = true
		// Suppress the literal value in JSON; presence is signalled by Set.
		return doc, nil
	}
	doc.Value = value
	return doc, nil
}

// rendererFromContext constructs a Renderer for a subcommand using the
// resolved global flags. Centralising the construction keeps every
// subcommand on the same Renderer wiring (token redaction, JSON envelope
// suppression of Human writes, etc.).
func rendererFromContext(c *cobra.Command, streams IOStreams) *output.Renderer {
	flags := GlobalFlagsFromContext(c.Context())
	return output.New(streams.Out, streams.ErrOut, flags.JSON, output.NewRedactor(flags.Token))
}
