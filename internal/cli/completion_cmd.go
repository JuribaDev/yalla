package cli

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// supportedShells is the canonical, ordered set of shells yalla can
// produce a completion script for. Adding a shell here also requires
// extending generateCompletion() and the manifest test that asserts the
// `completion` command exposes one subcommand per supported shell.
var supportedShells = []string{"bash", "zsh", "fish", "powershell"}

// completionDoc is the JSON envelope payload emitted when --json is set
// for any `yalla completion <shell>` invocation. The script field is a
// verbatim shell program; agents that pipe it to disk should preserve
// trailing newlines.
type completionDoc struct {
	Shell  string `json:"shell"`
	Script string `json:"script"`
}

// newCompletionCommand builds the `yalla completion` subtree. Cobra's
// own auto-added completion command is suppressed at root construction
// time (cmd.CompletionOptions.DisableDefaultCmd) so this tree wholly
// owns the surface. The split into one subcommand per shell keeps each
// invocation deterministic — `yalla completion bash` either prints the
// script or returns a typed error, never falls back to detection.
func newCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generate shell completion scripts (bash, zsh, fish, powershell)",
		Long: `Generate a shell completion script for yalla.

Pipe the output of the appropriate subcommand to your shell's
completion-loading mechanism. Examples:

  # bash (current shell)
  source <(yalla completion bash)

  # zsh (load from fpath)
  yalla completion zsh > "${fpath[1]}/_yalla"

  # fish
  yalla completion fish | source

  # powershell
  yalla completion powershell | Out-String | Invoke-Expression

The script itself goes to stdout so it can be redirected to a file or
piped into a shell. With --json the script is wrapped in the standard
yalla.output.v1 envelope under the "script" field.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	for _, shell := range supportedShells {
		cmd.AddCommand(newCompletionShellCommand(shell))
	}
	return cmd
}

// newCompletionShellCommand returns the per-shell leaf command. We
// build them in a loop so adding a shell stays a one-line change in
// supportedShells.
func newCompletionShellCommand(shell string) *cobra.Command {
	return &cobra.Command{
		Use:   shell,
		Short: fmt.Sprintf("Generate the %s completion script for yalla", shell),
		Long: fmt.Sprintf(`Generate the %s completion script for yalla.

The script is written to stdout so it can be piped to a file or sourced
directly. With --json the script is wrapped in the standard
yalla.output.v1 envelope under the "script" field.`, shell),
		Example: completionExample(shell),
		Args:    cobra.NoArgs,
		// Hidden from cobra's own completion suggestions: a completion
		// generator should not itself appear inside the generated
		// completion list. Tests still cover it explicitly.
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(c *cobra.Command, _ []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runCompletion(c, r, shell)
		},
	}
}

// completionExample returns the canonical one-liner for sourcing the
// generated script in each shell. Used both for `--help` rendering and
// for the docs Markdown so users always see a working invocation.
func completionExample(shell string) string {
	switch shell {
	case "bash":
		return "  source <(yalla completion bash)"
	case "zsh":
		return `  yalla completion zsh > "${fpath[1]}/_yalla"`
	case "fish":
		return "  yalla completion fish | source"
	case "powershell":
		return "  yalla completion powershell | Out-String | Invoke-Expression"
	default:
		return ""
	}
}

// runCompletion is the testable seam: it generates the script via
// cobra's built-in helpers and routes it through the renderer so JSON
// mode wraps it in the standard envelope and human mode prints the
// script verbatim to stdout. The script bytes are written through the
// raw stdout writer (Renderer.Out) — this is the one and only place
// outside the redactor's purview because shell scripts cannot tolerate
// substring substitution. No yalla token ever appears in a completion
// script.
func runCompletion(c *cobra.Command, r *output.Renderer, shell string) error {
	root := c.Root()
	var buf bytes.Buffer
	if err := generateCompletion(root, &buf, shell); err != nil {
		return err
	}

	if r.JSON() {
		return r.Data(completionDoc{Shell: shell, Script: buf.String()})
	}
	if _, err := r.Out().Write(buf.Bytes()); err != nil {
		return yerr.Newf(yerr.CodeInternal, "write completion script: %v", err)
	}
	return nil
}

// generateCompletion is split out of runCompletion so tests can assert
// the per-shell branches without instantiating the renderer. Each
// branch uses cobra's own generator so the produced scripts stay in
// sync with cobra upgrades; we never hand-roll completion code.
//
// Bash uses GenBashCompletionV2 because v2 is the format every
// supported distribution ships today. PowerShell uses the
// "WithDesc" variant so users see flag descriptions in tab-completion.
func generateCompletion(root *cobra.Command, w *bytes.Buffer, shell string) error {
	switch shell {
	case "bash":
		if err := root.GenBashCompletionV2(w, true); err != nil {
			return yerr.Newf(yerr.CodeInternal, "generate bash completion: %v", err)
		}
	case "zsh":
		if err := root.GenZshCompletion(w); err != nil {
			return yerr.Newf(yerr.CodeInternal, "generate zsh completion: %v", err)
		}
	case "fish":
		if err := root.GenFishCompletion(w, true); err != nil {
			return yerr.Newf(yerr.CodeInternal, "generate fish completion: %v", err)
		}
	case "powershell":
		if err := root.GenPowerShellCompletionWithDesc(w); err != nil {
			return yerr.Newf(yerr.CodeInternal, "generate powershell completion: %v", err)
		}
	default:
		return yerr.Newf(yerr.CodeInvalidInput, "unsupported shell %q", shell).
			WithHintf("supported shells: bash, zsh, fish, powershell")
	}
	return nil
}
