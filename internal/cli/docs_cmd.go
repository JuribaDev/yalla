package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newDocsCommand builds the `yalla docs` subtree. Today only the
// `markdown` generator is wired; the subtree exists so future formats
// (man pages, json schema, html) slot in without breaking the
// command surface.
func newDocsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate human-readable documentation for the yalla CLI",
		Long: `Generate human-readable documentation for the yalla CLI.

Subcommands write Markdown (and, in future, other formats) for every
yalla command. The output is fully self-contained — agents can also
inspect ` + "`yalla manifest --json`" + ` for a machine-readable view.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newDocsMarkdownCommand())
	return cmd
}

// docsMarkdownDoc is the JSON envelope payload returned when --json is
// set. Files is non-empty only when --output-dir was supplied; in
// stdout-mode the rendered Markdown lands in Content instead.
type docsMarkdownDoc struct {
	Format       string   `json:"format"` // always "markdown"
	CommandCount int      `json:"command_count"`
	OutputDir    string   `json:"output_dir,omitempty"`
	Files        []string `json:"files,omitempty"`
	Content      string   `json:"content,omitempty"`
}

func newDocsMarkdownCommand() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   "markdown",
		Short: "Generate Markdown reference documentation",
		Long: `Generate Markdown reference documentation for every yalla command.

When ` + "`--output-dir`" + ` is supplied, one Markdown file is written
per command (file names mirror the command path with underscores). When
the flag is omitted, a single combined document is rendered to stdout
so it can be piped into a static site generator or archived as-is.`,
		Example: `  yalla docs markdown --output-dir ./docs/reference
  yalla docs markdown > REFERENCE.md
  yalla --json docs markdown --output-dir ./docs/reference`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runDocsMarkdown(c, r, outputDir)
		},
	}
	cmd.Flags().StringVar(&outputDir, "output-dir", "",
		"directory to write per-command Markdown files into; if unset, a combined document is written to stdout")
	return cmd
}

// runDocsMarkdown is the testable entry point: it walks the command
// tree, builds the per-command Markdown, and either writes the files to
// disk or streams the combined document to the renderer.
func runDocsMarkdown(c *cobra.Command, r *output.Renderer, outputDir string) error {
	root := c.Root()
	pages := collectMarkdownPages(root, root.Name())
	if len(pages) == 0 {
		return yerr.New(yerr.CodeInternal, "command tree produced zero markdown pages")
	}

	if outputDir != "" {
		// 0700 keeps the tree owner-only; per-file 0644 keeps the
		// rendered docs world-readable, matching how documentation is
		// typically published. Tokens never appear in docs output, so
		// no extra redaction is required.
		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return yerr.Newf(yerr.CodeInternal, "create output dir: %v", err)
		}
		written := make([]string, 0, len(pages))
		for _, p := range pages {
			path := filepath.Join(outputDir, p.fileName)
			if err := os.WriteFile(path, []byte(p.content), 0o644); err != nil {
				return yerr.Newf(yerr.CodeInternal, "write %s: %v", path, err)
			}
			written = append(written, path)
		}
		sort.Strings(written)
		if r.JSON() {
			return r.Data(docsMarkdownDoc{
				Format:       "markdown",
				CommandCount: len(pages),
				OutputDir:    outputDir,
				Files:        written,
			})
		}
		r.Logf("wrote %d markdown files to %s", len(written), outputDir)
		return nil
	}

	combined := combineMarkdownPages(pages)
	if r.JSON() {
		return r.Data(docsMarkdownDoc{
			Format:       "markdown",
			CommandCount: len(pages),
			Content:      combined,
		})
	}
	r.Human(strings.TrimRight(combined, "\n"))
	return nil
}

// markdownPage pairs an output filename with its rendered body. The
// filename is relative to --output-dir; combineMarkdownPages joins them
// in deterministic order for the stdout path.
type markdownPage struct {
	fileName string
	content  string
}

// collectMarkdownPages walks the command tree and produces one
// markdownPage per non-internal command (root included). The order is
// stable: depth-first, alphabetical within each level.
func collectMarkdownPages(cmd *cobra.Command, parentPath string) []markdownPage {
	var pages []markdownPage
	pages = append(pages, markdownPage{
		fileName: markdownFileName(parentPath),
		content:  renderMarkdownPage(cmd, parentPath),
	})
	children := append([]*cobra.Command(nil), cmd.Commands()...)
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, child := range children {
		if isInternalCobraCmd(child) {
			continue
		}
		childPath := parentPath + " " + child.Name()
		pages = append(pages, collectMarkdownPages(child, childPath)...)
	}
	return pages
}

// markdownFileName turns a space-separated command path into a
// stable filesystem-safe filename. "yalla schema get" becomes
// "yalla_schema_get.md".
func markdownFileName(path string) string {
	return strings.ReplaceAll(path, " ", "_") + ".md"
}

// renderMarkdownPage emits a single command's reference page. The
// layout is intentionally simple (heading, synopsis, usage, flags
// table, examples, see also) so the output renders cleanly on
// pkg.go.dev / GitHub / static site generators without per-host
// quirks.
func renderMarkdownPage(cmd *cobra.Command, path string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s\n\n", path)
	if cmd.Short != "" {
		fmt.Fprintf(&sb, "%s\n\n", cmd.Short)
	}

	if cmd.Long != "" {
		sb.WriteString("## Synopsis\n\n")
		fmt.Fprintf(&sb, "%s\n\n", cmd.Long)
	}

	if cmd.UseLine() != "" {
		sb.WriteString("## Usage\n\n")
		fmt.Fprintf(&sb, "```\n%s\n```\n\n", strings.TrimSpace(cmd.UseLine()))
	}

	if cmd.Example != "" {
		sb.WriteString("## Examples\n\n")
		fmt.Fprintf(&sb, "```\n%s\n```\n\n", strings.TrimSpace(cmd.Example))
	}

	local := collectFlagSet(cmd.LocalFlags())
	if len(local) > 0 {
		sb.WriteString("## Flags\n\n")
		writeFlagsTable(&sb, local)
		sb.WriteString("\n")
	}

	inherited := collectFlagSet(cmd.InheritedFlags())
	if len(inherited) > 0 {
		sb.WriteString("## Inherited Flags\n\n")
		writeFlagsTable(&sb, inherited)
		sb.WriteString("\n")
	}

	subs := visibleChildren(cmd)
	if cmd.HasParent() || len(subs) > 0 {
		sb.WriteString("## See Also\n\n")
		if cmd.HasParent() {
			parentPath := strings.TrimSuffix(path, " "+cmd.Name())
			fmt.Fprintf(&sb, "* [%s](%s)\n", parentPath, markdownFileName(parentPath))
		}
		for _, s := range subs {
			childPath := path + " " + s.Name()
			short := s.Short
			if short != "" {
				fmt.Fprintf(&sb, "* [%s](%s) — %s\n", childPath, markdownFileName(childPath), short)
			} else {
				fmt.Fprintf(&sb, "* [%s](%s)\n", childPath, markdownFileName(childPath))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// writeFlagsTable renders flags as a Markdown table. The table renders
// reliably across GitHub and most static site generators; pflag's own
// FlagUsages output is human-readable but not Markdown-aware.
func writeFlagsTable(sb *strings.Builder, flags []manifestFlag) {
	sb.WriteString("| Flag | Shorthand | Type | Default | Description |\n")
	sb.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, f := range flags {
		short := f.Shorthand
		if short != "" {
			short = "-" + short
		}
		fmt.Fprintf(sb, "| `--%s` | %s | `%s` | %s | %s |\n",
			f.Name,
			short,
			f.Type,
			markdownDefault(f.Default),
			markdownEscape(f.Description),
		)
	}
}

// markdownDefault renders an empty default as a soft em-dash so the
// table still aligns visually. Non-empty defaults are wrapped in
// backticks to make whitespace-bearing values readable.
func markdownDefault(v string) string {
	if v == "" {
		return ""
	}
	return "`" + v + "`"
}

// markdownEscape escapes the small set of inline characters that break
// table cells. It is intentionally conservative — yalla's flag
// descriptions are short, single-line strings authored by us.
func markdownEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// visibleChildren returns the cmd's non-internal subcommands sorted by
// name so docs output matches the manifest's ordering exactly.
func visibleChildren(cmd *cobra.Command) []*cobra.Command {
	children := cmd.Commands()
	out := make([]*cobra.Command, 0, len(children))
	for _, c := range children {
		if isInternalCobraCmd(c) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// combineMarkdownPages joins per-command pages into a single document
// with a horizontal rule between entries. Used when --output-dir is not
// supplied so callers can pipe the result to a single file.
func combineMarkdownPages(pages []markdownPage) string {
	var sb strings.Builder
	for i, p := range pages {
		if i > 0 {
			sb.WriteString("\n---\n\n")
		}
		sb.WriteString(p.content)
	}
	return sb.String()
}

// Compile-time guard: docsMarkdown depends on the same flag projection
// as the manifest. If pflag.Flag ever changes shape, both touch the
// same code path so a single update keeps them aligned.
var _ = (*pflag.Flag)(nil)
