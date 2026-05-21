package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/curated"
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
// local flags), the canonical error-code table, and the runtime API
// discovery metadata so an agent can introspect what the binary can do
// without invoking individual help subcommands.
//
// Field order follows the JSON tag order so the marshalled document
// reads top-down (envelope → cli → spec → flags → commands → errors →
// operations).
type manifestDoc struct {
	ManifestSchema      string                   `json:"manifest_schema"`
	OutputSchemaVersion string                   `json:"output_schema_version"`
	ErrorSchemaVersion  string                   `json:"error_schema_version"`
	CLI                 manifestCLI              `json:"cli"`
	Spec                manifestSpec             `json:"spec"`
	GlobalFlags         []manifestFlag           `json:"global_flags"`
	Commands            []manifestCommand        `json:"commands"`
	ErrorCodes          []yerr.CodeDoc           `json:"error_codes"`
	Operations          manifestOperations       `json:"operations"`
	CuratedDomains      []string                 `json:"curated_domains"`
	CuratedCommands     []manifestCuratedCommand `json:"curated_commands"`
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
	OperationID    string            `json:"operation_id,omitempty"`
	Method         string            `json:"method,omitempty"`
	BackendPath    string            `json:"path_template,omitempty"`
	Idempotent     bool              `json:"idempotent"`
	SupportsWait   bool              `json:"supports_wait"`
	RequiredFlags  []string          `json:"required_flags,omitempty"`
	SensitiveFlags []string          `json:"sensitive_flags,omitempty"`
	OutputSchema   map[string]string `json:"json_output_schema,omitempty"`
	Subcommands    []manifestCommand `json:"subcommands,omitempty"`
}

type manifestCommandMetadata struct {
	OperationID    string
	Method         string
	BackendPath    string
	Idempotent     bool
	SupportsWait   bool
	RequiredFlags  []string
	SensitiveFlags []string
	OutputSchema   map[string]string
}

// manifestCuratedCommand projects one curated.Command into the manifest
// payload. The shape is intentionally flat so an agent can join it to
// the operations list by operation_id without traversing the cobra tree.
//
// `operation_ids` is the full set of OpenAPI operationIds this curated
// command dispatches to. Curated commands never replace raw API
// coverage — `yalla api call <operation_id>` and
// `yalla schema get <operation_id>` remain available for every
// operation, including those reachable through a curated entry point.
type manifestCuratedCommand struct {
	Path         string   `json:"path"`
	Domain       string   `json:"domain"`
	Verb         string   `json:"verb"`
	Summary      string   `json:"summary,omitempty"`
	OperationIDs []string `json:"operation_ids"`
	HumanExample string   `json:"human_example,omitempty"`
	JSONExample  string   `json:"json_example,omitempty"`
}

// manifestOperations summarises local operation coverage. Backend API
// operations are discovered at runtime through `yalla api operations` and
// `yalla schema get`; the manifest deliberately does not embed the old
// Dokploy OpenAPI operation catalogue.
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
	table (with stable exit codes), and the backend API discovery surface.

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
			reg, err := backendManifestRegistry()
			if err != nil {
				return yerr.Newf(yerr.CodeInternal, "could not build backend manifest registry: %v", err)
			}
			return runManifest(c, r, build, reg, curated.Default())
		},
	}
	return cmd
}

const backendManifestOpenAPI = `{"openapi":"3.1.0","info":{"title":"Yalla Control Plane API","version":"runtime-discovered"},"paths":{}}`

func backendManifestRegistry() (*api.Registry, error) {
	return api.Load([]byte(backendManifestOpenAPI))
}

// runManifest assembles the manifest from the live root command and
// renders it through the supplied renderer. The cobra.Command argument
// is used purely as a tree handle; runManifest never mutates it.
func runManifest(c *cobra.Command, r *output.Renderer, build BuildInfo, reg *api.Registry, cur *curated.Registry) error {
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
		CuratedDomains:  curatedDomainNames(),
		CuratedCommands: collectCuratedCommands(cur),
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
	fmt.Fprintf(&sb, "curated commands: %d across %d domains\n", len(doc.CuratedCommands), len(doc.CuratedDomains))
	sb.WriteString("commands:\n")
	humanRenderCommandTree(&sb, doc.Commands, 1)
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// curatedDomainNames returns the canonical curated domain set as a
// slice of strings so the manifest payload stays JSON-friendly without
// leaking the internal Domain type.
func curatedDomainNames() []string {
	domains := curated.Domains()
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = string(d)
	}
	return out
}

// collectCuratedCommands projects the curated registry into the
// manifest payload. The slice is deterministic (curated.Registry sorts
// by Path) and is never nil so JSON consumers can rely on the field
// being a present `[]` even when no curated commands exist yet.
func collectCuratedCommands(cur *curated.Registry) []manifestCuratedCommand {
	src := cur.Commands()
	out := make([]manifestCuratedCommand, 0, len(src))
	for _, c := range src {
		ops := append([]string(nil), c.OperationIDs...)
		out = append(out, manifestCuratedCommand{
			Path:         c.Path,
			Domain:       string(c.Domain),
			Verb:         c.Verb,
			Summary:      c.Summary,
			OperationIDs: ops,
			HumanExample: c.HumanExample,
			JSONExample:  c.JSONExample,
		})
	}
	return out
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
		if meta, ok := commandMetadata(path); ok {
			entry.OperationID = meta.OperationID
			entry.Method = meta.Method
			entry.BackendPath = meta.BackendPath
			entry.Idempotent = meta.Idempotent
			entry.SupportsWait = meta.SupportsWait
			entry.RequiredFlags = meta.RequiredFlags
			entry.SensitiveFlags = meta.SensitiveFlags
			entry.OutputSchema = meta.OutputSchema
		}
		if child.HasSubCommands() {
			entry.Subcommands = collectCommandTree(child, path)
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func commandMetadata(path string) (manifestCommandMetadata, bool) {
	payload := func(name string) map[string]string { return map[string]string{"data": name} }
	meta := map[string]manifestCommandMetadata{
		"yalla project list":            {OperationID: "listProjects", Method: "GET", BackendPath: "/v1/projects", Idempotent: true, OutputSchema: payload("projects")},
		"yalla project get":             {OperationID: "getProject", Method: "GET", BackendPath: "/v1/projects/{project_id}", Idempotent: true, RequiredFlags: []string{"project-id"}, OutputSchema: payload("project")},
		"yalla project create":          {OperationID: "createProject", Method: "POST", BackendPath: "/v1/projects", Idempotent: true, RequiredFlags: []string{"name"}, OutputSchema: payload("project")},
		"yalla project update":          {OperationID: "updateProject", Method: "PATCH", BackendPath: "/v1/projects/{project_id}", RequiredFlags: []string{"project-id"}, OutputSchema: payload("project")},
		"yalla project delete":          {OperationID: "deleteProject", Method: "DELETE", BackendPath: "/v1/projects/{project_id}", SupportsWait: true, RequiredFlags: []string{"project-id"}, OutputSchema: payload("project")},
		"yalla project restore":         {OperationID: "restoreProject", Method: "POST", BackendPath: "/v1/projects/{project_id}/restore", SupportsWait: true, RequiredFlags: []string{"project-id"}, OutputSchema: payload("project")},
		"yalla environment list":        {OperationID: "listProjectEnvironments", Method: "GET", BackendPath: "/v1/projects/{project_id}/environments", Idempotent: true, RequiredFlags: []string{"project-id"}, OutputSchema: payload("environments")},
		"yalla environment get":         {OperationID: "getEnvironment", Method: "GET", BackendPath: "/v1/environments/{environment_id}", Idempotent: true, RequiredFlags: []string{"environment-id"}, OutputSchema: payload("environment")},
		"yalla environment create":      {OperationID: "createProjectEnvironment", Method: "POST", BackendPath: "/v1/projects/{project_id}/environments", Idempotent: true, RequiredFlags: []string{"project-id", "name"}, OutputSchema: payload("environment")},
		"yalla environment update":      {OperationID: "updateEnvironment", Method: "PATCH", BackendPath: "/v1/environments/{environment_id}", RequiredFlags: []string{"environment-id"}, OutputSchema: payload("environment")},
		"yalla environment delete":      {OperationID: "deleteEnvironment", Method: "DELETE", BackendPath: "/v1/environments/{environment_id}", SupportsWait: true, RequiredFlags: []string{"environment-id"}, OutputSchema: payload("environment")},
		"yalla environment clone":       {OperationID: "cloneEnvironment", Method: "POST", BackendPath: "/v1/environments/{environment_id}/clone", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"environment-id", "name"}, OutputSchema: payload("environment")},
		"yalla service list":            {OperationID: "listEnvironmentServices", Method: "GET", BackendPath: "/v1/environments/{environment_id}/services", Idempotent: true, RequiredFlags: []string{"environment-id"}, OutputSchema: payload("services")},
		"yalla service get":             {OperationID: "getService", Method: "GET", BackendPath: "/v1/services/{service_id}", Idempotent: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("service")},
		"yalla service create":          {OperationID: "createEnvironmentService", Method: "POST", BackendPath: "/v1/environments/{environment_id}/services", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"environment-id", "name"}, SensitiveFlags: []string{"registry-secret-ref"}, OutputSchema: payload("service")},
		"yalla service update":          {OperationID: "updateService", Method: "PATCH", BackendPath: "/v1/services/{service_id}", RequiredFlags: []string{"service-id"}, OutputSchema: payload("service")},
		"yalla service delete":          {OperationID: "deleteService", Method: "DELETE", BackendPath: "/v1/services/{service_id}", SupportsWait: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("service")},
		"yalla service restore":         {OperationID: "restoreService", Method: "POST", BackendPath: "/v1/services/{service_id}/restore", SupportsWait: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("service")},
		"yalla service deploy":          {OperationID: "createServiceDeployment", Method: "POST", BackendPath: "/v1/services/{service_id}/deployments", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("deployment")},
		"yalla service build get":       {OperationID: "getServiceBuildConfig", Method: "GET", BackendPath: "/v1/services/{service_id}/build-config", Idempotent: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("build_config")},
		"yalla service build set":       {OperationID: "setServiceBuildConfig", Method: "PUT", BackendPath: "/v1/services/{service_id}/build-config", Idempotent: true, RequiredFlags: []string{"service-id", "build-type"}, SensitiveFlags: []string{"registry-secret-ref"}, OutputSchema: payload("build_config")},
		"yalla deploy compose":          {OperationID: "createServiceDeployment", Method: "POST", BackendPath: "/v1/services/{service_id}/deployments", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("deployment")},
		"yalla database list":           {OperationID: "listEnvironmentServices", Method: "GET", BackendPath: "/v1/environments/{environment_id}/services", Idempotent: true, RequiredFlags: []string{"environment-id"}, OutputSchema: payload("services")},
		"yalla database create":         {OperationID: "createEnvironmentService", Method: "POST", BackendPath: "/v1/environments/{environment_id}/services", Idempotent: true, RequiredFlags: []string{"environment-id", "name"}, OutputSchema: payload("service")},
		"yalla database deploy":         {OperationID: "createServiceDeployment", Method: "POST", BackendPath: "/v1/services/{service_id}/deployments", Idempotent: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("deployment")},
		"yalla database delete":         {OperationID: "deleteService", Method: "DELETE", BackendPath: "/v1/services/{service_id}", RequiredFlags: []string{"service-id"}, OutputSchema: payload("service")},
		"yalla database backup list":    {OperationID: "listServiceBackups", Method: "GET", BackendPath: "/v1/services/{service_id}/backups", Idempotent: true, RequiredFlags: []string{"service-id"}, OutputSchema: payload("backups")},
		"yalla database backup create":  {OperationID: "createServiceBackup", Method: "POST", BackendPath: "/v1/services/{service_id}/backups", Idempotent: true, RequiredFlags: []string{"service-id", "display-name", "schedule"}, OutputSchema: payload("backup")},
		"yalla database backup update":  {OperationID: "updateServiceBackup", Method: "PATCH", BackendPath: "/v1/services/{service_id}/backups/{backup_id}", RequiredFlags: []string{"service-id", "backup-id"}, OutputSchema: payload("backup")},
		"yalla database backup run":     {OperationID: "runServiceBackup", Method: "POST", BackendPath: "/v1/services/{service_id}/backups/{backup_id}/run", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"service-id", "backup-id"}, OutputSchema: payload("backup")},
		"yalla database backup restore": {OperationID: "restoreServiceBackup", Method: "POST", BackendPath: "/v1/services/{service_id}/backups/{backup_id}/restore", Idempotent: true, SupportsWait: true, RequiredFlags: []string{"service-id", "backup-id"}, OutputSchema: payload("backup")},
		"yalla database backup delete":  {OperationID: "deleteServiceBackup", Method: "DELETE", BackendPath: "/v1/services/{service_id}/backups/{backup_id}", RequiredFlags: []string{"service-id", "backup-id"}, OutputSchema: payload("backup")},
	}
	got, ok := meta[path]
	return got, ok
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
