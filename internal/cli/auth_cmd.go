package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newAuthCommand groups credential-introspection commands. Today it only
// hosts `auth status`; future stories may add `auth login`, `auth logout`,
// or `auth refresh` without changing the existing surface.
func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Inspect Dokploy credentials and connection settings",
		Long: `Inspect the authentication state yalla will use for Dokploy API calls.

The command never echoes the token value; it only reports presence,
provenance, and whether the resolved configuration is sufficient to make a
live API call.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newAuthStatusCommand())
	return cmd
}

// authStatusDoc is the JSON shape returned by `yalla auth status`. The
// nested objects carry presence + source + (for non-secret fields) value
// so an agent can branch on Configured/Ready without parsing strings, while
// a human reader still gets the contextual information.
type authStatusDoc struct {
	BaseURL    fieldDoc `json:"base_url"`
	Token      fieldDoc `json:"token"`
	ConfigPath fieldDoc `json:"config_path"`
	NoInput    bool     `json:"no_input"`
	Output     string   `json:"output"`
	Ready      bool     `json:"ready"`
	Reason     string   `json:"reason,omitempty"`
}

// fieldDoc is the per-field shape used inside authStatusDoc. Value is
// omitted when the field is a secret so the JSON payload stays scrubbed
// without relying on the redactor.
type fieldDoc struct {
	Set    bool          `json:"set"`
	Source config.Source `json:"source"`
	Value  string        `json:"value,omitempty"`
}

func newAuthStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether yalla can authenticate against Dokploy",
		Long: `Report the resolved authentication state without contacting the Dokploy
API. The command always exits 0 when it can compute the status (so agents
can rely on a non-error envelope to detect partial configuration); the
` + "`ready`" + ` boolean inside the payload is the authoritative
"can yalla make an API call right now?" signal.`,
		Example: `  yalla auth status
  yalla --json auth status`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg := config.FromContext(c.Context())
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runAuthStatus(r, cfg)
		},
	}
	return cmd
}

// runAuthStatus assembles the status payload. It never reports the literal
// token value — only its presence and source — so even a buggy renderer
// downstream cannot leak it. `ready` is the boolean an agent should switch
// on; `reason` carries the human-readable classification when ready=false.
func runAuthStatus(r *output.Renderer, cfg *config.Config) error {
	doc := authStatusDoc{
		BaseURL: fieldDoc{
			Set:    cfg.HasBaseURL(),
			Source: cfg.BaseURLSource,
			Value:  cfg.BaseURL,
		},
		Token: fieldDoc{
			Set:    cfg.HasToken(),
			Source: cfg.TokenSource,
			// Value intentionally omitted — never echo the token.
		},
		ConfigPath: fieldDoc{
			Set:    cfg.ConfigPath != "",
			Source: cfg.ConfigPathSource,
			Value:  cfg.ConfigPath,
		},
		NoInput: cfg.NoInput,
		Output:  string(cfg.Output),
		Ready:   cfg.Ready() == nil,
	}
	if !doc.Ready {
		if err := cfg.Ready(); err != nil {
			var typed *yerr.Error
			if e, ok := err.(*yerr.Error); ok {
				typed = e
			}
			if typed != nil {
				doc.Reason = string(typed.Code) + ": " + typed.Message
			} else {
				doc.Reason = err.Error()
			}
		}
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	headers := []string{"FIELD", "STATUS", "SOURCE"}
	rows := [][]string{
		{"base_url", baseURLDisplay(cfg), string(cfg.BaseURLSource)},
		{"token", tokenStatus(cfg), string(cfg.TokenSource)},
		{"config_path", cfg.ConfigPath, string(cfg.ConfigPathSource)},
		{"no_input", boolDisplay(cfg.NoInput), string(cfg.NoInputSource)},
		{"output", string(cfg.Output), string(cfg.OutputSource)},
	}
	if err := output.Table(&sb, headers, rows); err != nil {
		return yerr.Newf(yerr.CodeInternal, "render auth table: %v", err)
	}
	if doc.Ready {
		sb.WriteString("ready: yes\n")
	} else {
		sb.WriteString("ready: no")
		if doc.Reason != "" {
			sb.WriteString(" (")
			sb.WriteString(doc.Reason)
			sb.WriteByte(')')
		}
		sb.WriteByte('\n')
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

func baseURLDisplay(cfg *config.Config) string {
	if !cfg.HasBaseURL() {
		return "(not set)"
	}
	return cfg.BaseURL
}

func tokenStatus(cfg *config.Config) string {
	if cfg.HasToken() {
		return "configured"
	}
	return "not set"
}

func boolDisplay(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
