package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// ManifestSchema is the stable schema_version embedded in every
// `yalla manifest` payload. The envelope's outer schema_version remains
// the success envelope identifier (`yalla.output.v1`); this constant
// labels the inner payload so an agent can branch on the manifest
// shape independently of the envelope.
const ManifestSchema = "yalla.manifest.v1"

// manifestDoc is the agent-facing description of the entire CLI surface.
// It bundles binary metadata, the full command tree (with persistent +
// local flags), the canonical error-code table, and the OpenAPI
// operation coverage so an agent can introspect what the binary can do
// without invoking individual help subcommands.
//
// Field order follows the JSON tag order so the marshalled document
// reads top-down (envelope → cli → spec → flags → commands → errors →
// operations).
type manifestDoc struct {
	ManifestSchema      string             `json:"manifest_schema"`
	OutputSchemaVersion string             `json:"output_schema_version"`
	ErrorSchemaVersion  string             `json:"error_schema_version"`
	CLI                 manifestCLI        `json:"cli"`
	Spec                manifestSpec       `json:"spec"`
	GlobalFlags         []manifestFlag     `json:"global_flags"`
	Commands            []manifestCommand  `json:"commands"`
	ErrorCodes          []yerr.CodeDoc     `json:"error_codes"`
	Operations          manifestOperations `json:"operations"`
}

type manifestCLI struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

type manifestSpec struct {
	Title   string `json:"title"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// manifestFlag projects a pflag.Flag into a stable JSON shape. We
// intentionally keep Default as a string because pflag exposes it as a
// string; agents that need a typed default can parse it themselves.
type manifestFlag struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand,omitempty"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// manifestCommand is one node in the recursive command tree. Path is the
// space-separated invocation (e.g. "yalla schema get") so an agent can
// reproduce the exact CLI call without assembling the parent chain.
type manifestCommand struct {
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	Use            string            `json:"use"`
	Short          string            `json:"short,omitempty"`
	Long           string            `json:"long,omitempty"`
	Example        string            `json:"example,omitempty"`
	Hidden         bool              `json:"hidden,omitempty"`
	Runnable       bool              `json:"runnable"`
	HasSubcommands bool              `json:"has_subcommands"`
	Flags          []manifestFlag    `json:"flags"`
	Subcommands    []manifestCommand `json:"subcommands,omitempty"`
}

// manifestOperations summarises the embedded OpenAPI registry coverage.
// The full operation catalogue is reachable through `yalla api operations`
// and `yalla schema get`, but a flat ID list lives here so the manifest
// alone is sufficient to verify "every API operation is covered".
type manifestOperations struct {
	Total int      `json:"total"`
	Tags  []string `json:"tags"`
	IDs   []string `json:"ids"`
}

// newManifestCommand builds `yalla manifest`. The command is read-only
// and never contacts the network; it materialises the in-binary CLI
// surface and registry coverage so agents can discover capabilities
// before acting.
func newManifestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Print the full CLI manifest (commands, flags, error codes, API coverage)",
		Long: `Print yalla's machine-readable manifest.

The manifest is the single artefact agents inspect to discover what
this binary can do. It includes the full command tree (with each
command's flags, examples, and visibility), the canonical error-code
table (with stable exit codes), and the embedded OpenAPI operation
catalogue (count, tags, and operationIds).

The payload is wrapped in the standard ` + "`yalla.output.v1`" + `
envelope when ` + "`--json`" + ` is set; the inner payload carries its
own ` + "`manifest_schema`" + ` (` + ManifestSchema + `) so consumers
can branch on the manifest shape independently of the envelope.`,
		Example: `  yalla --json manifest
  yalla manifest`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			build := BuildInfoFromContext(c.Context())
			return runManifest(c, r, build, api.Default())
		},
	}
	return cmd
}

// runManifest assembles the manifest from the live root command and
// renders it through the supplied renderer. The cobra.Command argument
// is used purely as a tree handle; runManifest never mutates it.
func runManifest(c *cobra.Command, r *output.Renderer, build BuildInfo, reg *api.Registry) error {
	root := c.Root()

	doc := manifestDoc{
		ManifestSchema:      ManifestSchema,
		OutputSchemaVersion: output.SuccessSchema,
		ErrorSchemaVersion:  yerr.SchemaVersion,
		CLI: manifestCLI{
			Name:    root.Name(),
			Version: build.Version,
			Commit:  build.Commit,
			Date:    build.Date,
		},
		Spec: manifestSpec{
			Title:   reg.Title,
			Version: reg.Version,
			SHA256:  reg.SHA256,
		},
		GlobalFlags: collectFlagSet(root.PersistentFlags()),
		Commands:    collectCommandTree(root, root.Name()),
		ErrorCodes:  yerr.AllCodes(),
		Operations: manifestOperations{
			Total: reg.Len(),
			Tags:  reg.Tags(),
			IDs:   reg.IDs(),
		},
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s (commit %s, built %s)\n", doc.CLI.Name, doc.CLI.Version, doc.CLI.Commit, doc.CLI.Date)
	fmt.Fprintf(&sb, "spec: %s %s (sha256 %s)\n", doc.Spec.Title, doc.Spec.Version, shortSHA(doc.Spec.SHA256))
	fmt.Fprintf(&sb, "operations: %d across %d tags\n", doc.Operations.Total, len(doc.Operations.Tags))
	fmt.Fprintf(&sb, "error codes: %d\n", len(doc.ErrorCodes))
	fmt.Fprintf(&sb, "global flags: %d\n", len(doc.GlobalFlags))
	sb.WriteString("commands:\n")
	humanRenderCommandTree(&sb, doc.Commands, 1)
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// collectCommandTree walks every visible (and hidden) subcommand of cmd
// and projects it into a manifestCommand. Cobra's auto-added `help`
// command and synthetic `__complete*` helpers are filtered so the
// manifest reflects the public surface only. The default `completion`
// subcommand is suppressed at root construction time
// (cmd.CompletionOptions.DisableDefaultCmd) so it never appears here in
// place of yalla's own `completion` command.
func collectCommandTree(cmd *cobra.Command, parentPath string) []manifestCommand {
	children := cmd.Commands()
	out := make([]manifestCommand, 0, len(children))
	for _, child := range children {
		if isInternalCobraCmd(child) {
			continue
		}
		path := parentPath + " " + child.Name()
		entry := manifestCommand{
			Name:           child.Name(),
			Path:           path,
			Use:            child.Use,
			Short:          child.Short,
			Long:           child.Long,
			Example:        child.Example,
			Hidden:         child.Hidden,
			Runnable:       child.Runnable(),
			HasSubcommands: child.HasSubCommands(),
			Flags:          collectFlagSet(child.LocalFlags()),
		}
		if child.HasSubCommands() {
			entry.Subcommands = collectCommandTree(child, path)
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// isInternalCobraCmd returns true when cmd is a synthetic helper Cobra
// adds without us asking. We do not want `help`, `__complete`, or
// `__completeNoDesc` to leak into the public manifest.
func isInternalCobraCmd(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "help", "__complete", "__completeNoDesc":
		return true
	}
	return false
}

// collectFlagSet projects a pflag.FlagSet into a deterministic slice of
// manifestFlag. The slice is sorted by flag name so JSON diffs across
// yalla versions are clean.
func collectFlagSet(fs *pflag.FlagSet) []manifestFlag {
	if fs == nil {
		return []manifestFlag{}
	}
	out := make([]manifestFlag, 0)
	fs.VisitAll(func(f *pflag.Flag) {
		out = append(out, manifestFlag{
			Name:        f.Name,
			Shorthand:   f.Shorthand,
			Type:        f.Value.Type(),
			Description: f.Usage,
			Default:     f.DefValue,
			Hidden:      f.Hidden,
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// humanRenderCommandTree prints the manifest's command tree as an
// indented outline on stderr (well, the renderer's Out, which is stdout
// when not in JSON mode). Used only for human-mode rendering — JSON mode
// is handled by the encoder.
func humanRenderCommandTree(w *strings.Builder, cmds []manifestCommand, depth int) {
	indent := strings.Repeat("  ", depth)
	for _, c := range cmds {
		fmt.Fprintf(w, "%s%s — %s\n", indent, c.Name, c.Short)
		if len(c.Subcommands) > 0 {
			humanRenderCommandTree(w, c.Subcommands, depth+1)
		}
	}
}
