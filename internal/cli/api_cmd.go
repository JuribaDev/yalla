package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newAPICommand builds the `yalla api` subtree. It hosts read-only Yalla
// backend OpenAPI inspection. Raw Dokploy operation execution is removed from
// normal CLI usage.
func newAPICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Inspect the Yalla backend OpenAPI surface",
		Long: `Inspect the Yalla Control Plane OpenAPI operation registry.

The backend serves ` + "`/openapi.json`" + ` and is the source of truth shared by
the CLI, frontend, and CI agents.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newAPIOperationsCommand())
	cmd.AddCommand(newAPICallCommand())
	return cmd
}

// apiOperationDoc is the JSON shape returned for a single operation by
// `yalla api operations`. It is intentionally a flat projection of the
// registry's Operation type — agents that need parameter or response
// schemas should call `yalla schema get <operationId>` instead.
type apiOperationDoc struct {
	OperationID    string   `json:"operation_id"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Tag            string   `json:"tag,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Description    string   `json:"description,omitempty"`
	RequiresAuth   bool     `json:"requires_auth"`
	HasRequestBody bool     `json:"has_request_body"`
	ParameterCount int      `json:"parameter_count"`
	ResponseCodes  []string `json:"response_codes"`
}

// apiOperationsDoc is the envelope payload for `yalla api operations`.
// Counting and digesting at the top level lets agents validate they
// received a complete listing without scanning the slice.
type apiOperationsDoc struct {
	SpecTitle   string            `json:"spec_title"`
	SpecVersion string            `json:"spec_version"`
	SpecSHA256  string            `json:"spec_sha256"`
	Total       int               `json:"total"`
	TagCounts   map[string]int    `json:"tag_counts,omitempty"`
	Tag         string            `json:"tag,omitempty"`
	Operations  []apiOperationDoc `json:"operations"`
}

func newAPIOperationsCommand() *cobra.Command {
	var tag string
	cmd := &cobra.Command{
		Use:   "operations",
		Short: "List Yalla backend API operations",
		Long: `List the Yalla backend API operations exposed by ` + "`/openapi.json`" + `.

The output is deterministic (operationId-sorted) so agents can diff results
across Yalla versions to detect API churn. Use ` + "`--tag`" + ` to
restrict the list to a single OpenAPI tag (e.g. ` + "`application`" + `,
` + "`compose`" + `, ` + "`server`" + `).`,
		Example: `  yalla api operations
  yalla --json api operations
  yalla --json api operations --tag application`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			reg, err := yallaBackendRegistry(c.Context(), configFromCommand(c), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			return runAPIOperations(r, reg, tag)
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "filter by OpenAPI tag (e.g. application)")
	return cmd
}

// runAPIOperations renders the operations listing through the supplied
// renderer. Pulled out of RunE for direct unit testing.
func runAPIOperations(r *output.Renderer, reg *api.Registry, tag string) error {
	all := reg.Operations()
	tagCounts := make(map[string]int, 64)
	for _, op := range all {
		key := op.Tag
		if key == "" {
			key = "untagged"
		}
		tagCounts[key]++
	}

	if tag != "" {
		known := false
		for k := range tagCounts {
			if k == tag {
				known = true
				break
			}
		}
		if !known {
			tags := make([]string, 0, len(tagCounts))
			for k := range tagCounts {
				tags = append(tags, k)
			}
			sort.Strings(tags)
			return yerr.Newf(yerr.CodeInvalidInput, "unknown tag %q", tag).
				WithHintf("known tags: %s", strings.Join(tags, ", "))
		}
	}

	docs := make([]apiOperationDoc, 0, len(all))
	for _, op := range all {
		opTag := op.Tag
		if opTag == "" {
			opTag = "untagged"
		}
		if tag != "" && opTag != tag {
			continue
		}
		codes := make([]string, 0, len(op.Responses))
		for _, resp := range op.Responses {
			codes = append(codes, resp.Status)
		}
		docs = append(docs, apiOperationDoc{
			OperationID:    op.OperationID,
			Method:         op.Method,
			Path:           op.Path,
			Tag:            op.Tag,
			Summary:        op.Summary,
			Description:    op.Description,
			RequiresAuth:   op.RequiresAuth,
			HasRequestBody: op.RequestBody != nil,
			ParameterCount: len(op.Parameters),
			ResponseCodes:  codes,
		})
	}

	envelope := apiOperationsDoc{
		SpecTitle:   reg.Title,
		SpecVersion: reg.Version,
		SpecSHA256:  reg.SHA256,
		Total:       len(docs),
		TagCounts:   tagCounts,
		Tag:         tag,
		Operations:  docs,
	}

	if r.JSON() {
		return r.Data(envelope)
	}

	var sb strings.Builder
	if tag == "" {
		fmt.Fprintf(&sb, "%d operations across %d tags (spec %s, sha256 %s)\n\n",
			envelope.Total, len(tagCounts), reg.Version, shortSHA(reg.SHA256))
	} else {
		fmt.Fprintf(&sb, "%d operations in tag %q (spec %s, sha256 %s)\n\n",
			envelope.Total, tag, reg.Version, shortSHA(reg.SHA256))
	}

	headers := []string{"OPERATION_ID", "METHOD", "PATH", "TAG", "AUTH"}
	rows := make([][]string, 0, len(docs))
	for _, d := range docs {
		auth := "no"
		if d.RequiresAuth {
			auth = "yes"
		}
		rows = append(rows, []string{d.OperationID, d.Method, d.Path, d.Tag, auth})
	}
	if err := output.Table(&sb, headers, rows); err != nil {
		return yerr.Newf(yerr.CodeInternal, "render api operations: %v", err)
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// shortSHA truncates a hex digest to 12 characters for human-readable
// output. Agents see the full digest in the JSON envelope.
func shortSHA(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
