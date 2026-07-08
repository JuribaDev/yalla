package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newSchemaCommand builds the `yalla schema` subtree. Schema commands are
// the agent-facing way to discover the input/output shape of every
// Dokploy operation without consulting the upstream OpenAPI document
// directly.
func newSchemaCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Inspect Dokploy operation input/output schemas",
		Long: `Inspect the Dokploy operation schemas yalla embeds at build time.

The schema commands are the agent-friendly view of the OpenAPI document:
` + "`schema list`" + ` enumerates every operationId and ` + "`schema get`" + `
returns the full input + output schema set for a single operation. Schemas
are emitted verbatim from the OpenAPI source so any JSON Schema validator
can consume them without massaging.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newSchemaListCommand())
	cmd.AddCommand(newSchemaGetCommand())
	return cmd
}

// schemaListEntry is the per-operation entry in `yalla schema list`. It
// is a thin index — agents that need the actual schema bodies should call
// `yalla schema get <operationId>`.
type schemaListEntry struct {
	OperationID  string `json:"operation_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Tag          string `json:"tag,omitempty"`
	Summary      string `json:"summary,omitempty"`
	HasInputBody bool   `json:"has_input_body"`
	OutputCount  int    `json:"output_count"`
}

// schemaListDoc is the envelope payload for `yalla schema list`. Total is
// duplicated outside the slice so an agent can validate it received a
// complete listing without scanning.
type schemaListDoc struct {
	SpecTitle   string            `json:"spec_title"`
	SpecVersion string            `json:"spec_version"`
	SpecSHA256  string            `json:"spec_sha256"`
	Total       int               `json:"total"`
	Schemas     []schemaListEntry `json:"schemas"`
}

func newSchemaListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every operation that ships with an input/output schema",
		Long: `List every operationId yalla can describe with ` + "`yalla schema get`" + `.

The list is operationId-sorted and matches the size of ` + "`yalla api operations`" + `
exactly — every registered operation has a schema entry.`,
		Example: `  yalla schema list
  yalla --json schema list`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runSchemaList(r, api.Default())
		},
	}
	return cmd
}

// runSchemaList materialises the index payload and routes it through the
// renderer. Decoupled from RunE for unit testing.
func runSchemaList(r *output.Renderer, reg *api.Registry) error {
	ops := reg.Operations()
	entries := make([]schemaListEntry, 0, len(ops))
	for _, op := range ops {
		entries = append(entries, schemaListEntry{
			OperationID:  op.OperationID,
			Method:       op.Method,
			Path:         op.Path,
			Tag:          op.Tag,
			Summary:      op.Summary,
			HasInputBody: op.RequestBody != nil,
			OutputCount:  len(op.Responses),
		})
	}

	doc := schemaListDoc{
		SpecTitle:   reg.Title,
		SpecVersion: reg.Version,
		SpecSHA256:  reg.SHA256,
		Total:       len(entries),
		Schemas:     entries,
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d operations have schemas (spec %s, sha256 %s)\n\n",
		doc.Total, reg.Version, shortSHA(reg.SHA256))

	headers := []string{"OPERATION_ID", "METHOD", "PATH", "TAG", "INPUT_BODY", "OUTPUTS"}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		body := "no"
		if e.HasInputBody {
			body = "yes"
		}
		rows = append(rows, []string{
			e.OperationID, e.Method, e.Path, e.Tag, body,
			fmt.Sprintf("%d", e.OutputCount),
		})
	}
	if err := output.Table(&sb, headers, rows); err != nil {
		return yerr.Newf(yerr.CodeInternal, "render schema list: %v", err)
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

func newSchemaGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <operationId>",
		Short: "Print the input + output schemas for a single operation",
		Long: `Print the full input + output schema set for a single operation.

Schemas are emitted verbatim from Dokploy's OpenAPI document, so JSON
Schema validators (Ajv, JSON Schema Validator, jsonschema in Python, etc.)
can consume them as-is. Use ` + "`yalla schema list`" + ` to discover
operationIds.`,
		Example: `  yalla schema get application-deploy
  yalla --json schema get application-create`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runSchemaGet(r, api.Default(), args[0])
		},
	}
	return cmd
}

// runSchemaGet emits the schema payload for a single operation. Unknown
// operationIds map to E_NOT_FOUND so scripts can branch on exit code 5
// without parsing stderr.
func runSchemaGet(r *output.Renderer, reg *api.Registry, operationID string) error {
	doc, err := reg.Schema(operationID)
	if err != nil {
		return yerr.Newf(yerr.CodeNotFound, "operation %q is not in the registry", operationID).
			WithHint("run `yalla schema list` to see every available operationId")
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  %s %s\n", doc.OperationID, doc.Method, doc.Path)
	if doc.Tag != "" {
		fmt.Fprintf(&sb, "tag: %s\n", doc.Tag)
	}
	if doc.Summary != "" {
		fmt.Fprintf(&sb, "summary: %s\n", doc.Summary)
	}
	if doc.RequiresAuth {
		sb.WriteString("auth: required\n")
	} else {
		sb.WriteString("auth: not required\n")
	}
	if len(doc.Extensions) > 0 {
		sb.WriteString("extensions:\n")
		for _, k := range sortedRawKeys(doc.Extensions) {
			var compact bytes.Buffer
			if err := json.Compact(&compact, doc.Extensions[k]); err == nil {
				fmt.Fprintf(&sb, "  %s: %s\n", k, compact.String())
			}
		}
	}

	if doc.Input != nil && len(doc.Input.Parameters) > 0 {
		sb.WriteString("\nparameters:\n")
		for _, p := range doc.Input.Parameters {
			req := "optional"
			if p.Required {
				req = "required"
			}
			fmt.Fprintf(&sb, "  - %s (%s, %s)\n", p.Name, p.In, req)
		}
	}

	if doc.Input != nil && doc.Input.Body != nil {
		req := "optional"
		if doc.Input.Body.Required {
			req = "required"
		}
		fmt.Fprintf(&sb, "\nrequest body: %s (%s)\n", doc.Input.Body.ContentType, req)
		if len(doc.Input.Body.Schema) > 0 {
			fmt.Fprintf(&sb, "%s\n", string(doc.Input.Body.Schema))
		}
	}

	if len(doc.Outputs) > 0 {
		sb.WriteString("\nresponses:\n")
		for _, o := range doc.Outputs {
			ct := o.ContentType
			if ct == "" {
				ct = "(no body)"
			}
			fmt.Fprintf(&sb, "  - %s  %s  %s\n", o.Status, ct, o.Description)
		}
	}

	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

func sortedRawKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
