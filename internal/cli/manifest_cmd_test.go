package cli

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/curated"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// TestManifest_JSONDoesNotExposeEmbeddedDokployOperations locks the backend-only
// CLI contract: the local manifest describes the command tree and points users
// at runtime backend discovery, but it does not publish the embedded Dokploy
// OpenAPI operation catalogue as a callable command contract.
func TestManifest_JSONDoesNotExposeEmbeddedDokployOperations(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	var env struct {
		SchemaVersion string      `json:"schema_version"`
		Data          manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("envelope schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.ManifestSchema != ManifestSchema {
		t.Errorf("manifest_schema = %q, want %q", env.Data.ManifestSchema, ManifestSchema)
	}
	if env.Data.OutputSchemaVersion != output.SuccessSchema {
		t.Errorf("output_schema_version = %q", env.Data.OutputSchemaVersion)
	}
	if env.Data.ErrorSchemaVersion != yerr.SchemaVersion {
		t.Errorf("error_schema_version = %q", env.Data.ErrorSchemaVersion)
	}
	if env.Data.Spec.Title != "Yalla Control Plane API" {
		t.Errorf("spec.title = %q, want Yalla Control Plane API", env.Data.Spec.Title)
	}
	if env.Data.Operations.Total != 0 {
		t.Errorf("operations.total = %d, want 0", env.Data.Operations.Total)
	}
	if len(env.Data.Operations.IDs) != 0 {
		t.Errorf("operations.ids = %v, want empty", env.Data.Operations.IDs)
	}
}

// TestManifest_JSONListsAllSubcommands verifies the public command tree
// is emitted in full. Adding a new top-level command without updating
// this list is intentional friction — every public surface must be
// discoverable through the manifest.
func TestManifest_JSONListsAllSubcommands(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr non-empty in JSON mode: %q", stderr)
	}

	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantTopLevel := []string{
		"api", "audit", "auth", "completion", "config", "database", "deploy", "docs", "environment", "manifest", "project", "rescue", "schema", "service", "teardown", "upgrade", "wait",
	}
	gotTop := make([]string, 0, len(env.Data.Commands))
	for _, c := range env.Data.Commands {
		gotTop = append(gotTop, c.Name)
	}
	sort.Strings(gotTop)
	sort.Strings(wantTopLevel)
	if strings.Join(gotTop, ",") != strings.Join(wantTopLevel, ",") {
		t.Errorf("top-level commands = %v, want %v", gotTop, wantTopLevel)
	}

	// Cobra's auto-added `help` and `__complete*` helpers must NOT leak
	// into the manifest.
	for _, c := range env.Data.Commands {
		switch c.Name {
		case "help", "__complete", "__completeNoDesc":
			t.Errorf("manifest must filter internal cobra command %q", c.Name)
		}
	}
}

// TestManifest_JSONListsAllErrorCodes verifies every public error code
// shipped by internal/errors is exposed through the manifest with its
// canonical exit code. The check is symmetric — manifest must contain
// exactly the codes in yerr.AllCodes(), no more, no less.
func TestManifest_JSONListsAllErrorCodes(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := yerr.AllCodes()
	if len(env.Data.ErrorCodes) != len(want) {
		t.Fatalf("error_codes length = %d, want %d", len(env.Data.ErrorCodes), len(want))
	}
	gotByCode := make(map[string]int, len(env.Data.ErrorCodes))
	for _, c := range env.Data.ErrorCodes {
		gotByCode[c.Code] = c.ExitCode
	}
	for _, w := range want {
		got, ok := gotByCode[w.Code]
		if !ok {
			t.Errorf("manifest missing error_code %s", w.Code)
			continue
		}
		if got != w.ExitCode {
			t.Errorf("manifest %s exit_code = %d, want %d", w.Code, got, w.ExitCode)
		}
	}
}

// TestManifest_JSONListsGlobalFlags verifies the persistent flag
// surface is emitted with shorthand and type. The list must match the
// root command's persistent flags exactly so an agent can configure
// every supported global option from the manifest alone.
func TestManifest_JSONListsGlobalFlags(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantFlags := []string{"base-url", "config", "json", "no-input", "token", "verbose"}
	gotFlags := make([]string, 0, len(env.Data.GlobalFlags))
	for _, f := range env.Data.GlobalFlags {
		gotFlags = append(gotFlags, f.Name)
	}
	sort.Strings(gotFlags)
	if strings.Join(gotFlags, ",") != strings.Join(wantFlags, ",") {
		t.Errorf("global_flags = %v, want %v", gotFlags, wantFlags)
	}

	for _, f := range env.Data.GlobalFlags {
		if f.Type == "" {
			t.Errorf("flag %s missing type", f.Name)
		}
		if f.Name == "verbose" && f.Shorthand != "v" {
			t.Errorf("flag verbose shorthand = %q, want %q", f.Shorthand, "v")
		}
	}
}

// TestManifest_HumanShowsSummary covers the non-JSON render path: it
// writes a short banner to stdout (data path) so users running the
// command interactively can see at a glance what the binary covers.
func TestManifest_HumanShowsSummary(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	for _, want := range []string{"yalla", "spec:", "operations:", "error codes:", "commands:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("manifest human output missing %q; got:\n%s", want, stdout)
		}
	}
}

// TestManifest_StableTopLevelOrder is a regression check: the top-level
// command slice MUST come back alphabetically sorted so JSON diffs across
// yalla versions stay clean.
func TestManifest_StableTopLevelOrder(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for i := 1; i < len(env.Data.Commands); i++ {
		if env.Data.Commands[i-1].Name >= env.Data.Commands[i].Name {
			t.Fatalf("commands not alphabetically sorted at index %d: %q >= %q",
				i, env.Data.Commands[i-1].Name, env.Data.Commands[i].Name)
		}
	}
}

// TestManifest_JSONListsCuratedDomains locks the curated-policy
// foundation contract: every public curated domain (US-0012) is
// emitted in the manifest, in canonical order. Adding or removing a
// domain is a public-API change and must update both this test and
// curated.Domains() together.
func TestManifest_JSONListsCuratedDomains(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"app", "compose", "database", "project", "provider", "server", "settings"}
	if strings.Join(env.Data.CuratedDomains, ",") != strings.Join(want, ",") {
		t.Errorf("curated_domains = %v, want %v", env.Data.CuratedDomains, want)
	}
}

// TestManifest_JSONIncludesCuratedCommands asserts that the curated
// command surface is rendered through the manifest as an always-present
// (possibly empty) array. The default registry is empty until the
// first curated-command story lands; the assertion lives here so a
// regression in the registry wiring trips the manifest contract.
func TestManifest_JSONIncludesCuratedCommands(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Decode into a generic map so the test asserts on the JSON wire
	// shape (a `curated_commands` key that is always emitted) rather
	// than on the typed struct (which can hide a missing field).
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, ok := env.Data["curated_commands"]
	if !ok {
		t.Fatalf("manifest payload missing curated_commands field")
	}
	if string(raw) != "[]" && raw[0] != '[' {
		t.Fatalf("curated_commands must be a JSON array, got %s", string(raw))
	}
}

// TestManifest_RendersCuratedCommandPayload exercises the curated →
// manifest projection end to end with a custom registry. It bypasses
// the cobra entrypoint to keep the test isolated from the global
// curated.Default() and uses a representative real operationId so the
// shape mirrors what an agent will see in production.
func TestManifest_RendersCuratedCommandPayload(t *testing.T) {
	cmd := curated.Command{
		Path:         "yalla app deploy",
		Domain:       curated.DomainApp,
		Verb:         "deploy",
		Summary:      "Deploy an application service",
		OperationIDs: []string{"createServiceDeployment"},
		HumanExample: "yalla app deploy --service-id svc_123",
		JSONExample:  "yalla --json app deploy --id app_123",
	}
	reg, err := curated.NewRegistry(cmd)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	got := collectCuratedCommands(reg)
	if len(got) != 1 {
		t.Fatalf("collectCuratedCommands len = %d, want 1", len(got))
	}
	if got[0].Path != cmd.Path {
		t.Errorf("path = %q, want %q", got[0].Path, cmd.Path)
	}
	if got[0].Domain != string(curated.DomainApp) {
		t.Errorf("domain = %q, want %q", got[0].Domain, curated.DomainApp)
	}
	if got[0].Verb != cmd.Verb {
		t.Errorf("verb = %q, want %q", got[0].Verb, cmd.Verb)
	}
	if got[0].Summary != cmd.Summary {
		t.Errorf("summary = %q, want %q", got[0].Summary, cmd.Summary)
	}
	if len(got[0].OperationIDs) != 1 || got[0].OperationIDs[0] != "createServiceDeployment" {
		t.Errorf("operation_ids = %v, want [createServiceDeployment]", got[0].OperationIDs)
	}
	if got[0].HumanExample != cmd.HumanExample {
		t.Errorf("human_example = %q, want %q", got[0].HumanExample, cmd.HumanExample)
	}
	if got[0].JSONExample != cmd.JSONExample {
		t.Errorf("json_example = %q, want %q", got[0].JSONExample, cmd.JSONExample)
	}

	// The projection must be a defensive copy — mutating the manifest
	// slice cannot bleed back into the curated registry.
	got[0].OperationIDs[0] = "mutated"
	if reg.Commands()[0].OperationIDs[0] == "mutated" {
		t.Errorf("manifest projection shares storage with curated registry")
	}
}
