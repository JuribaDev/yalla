package cli

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// TestManifest_JSONIncludesEveryAPIOperation locks the central acceptance
// criterion of US-0007: every Dokploy API operation in the registry must
// appear in the manifest's operations.ids list, and the count must equal
// the registry size. A regression in either the registry parser or the
// manifest collector fails this test before it can ship.
func TestManifest_JSONIncludesEveryAPIOperation(t *testing.T) {
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
	if env.Data.Spec.SHA256 != api.EmbeddedSpecSHA256 {
		t.Errorf("spec.sha256 = %q, want %q", env.Data.Spec.SHA256, api.EmbeddedSpecSHA256)
	}
	if env.Data.Operations.Total != expectedOpCount {
		t.Errorf("operations.total = %d, want %d", env.Data.Operations.Total, expectedOpCount)
	}
	if len(env.Data.Operations.IDs) != expectedOpCount {
		t.Errorf("operations.ids length = %d, want %d", len(env.Data.Operations.IDs), expectedOpCount)
	}

	// IDs must be the exact set the registry exposes — no missing, no
	// extras, no duplicates.
	want := api.Default().IDs()
	got := append([]string(nil), env.Data.Operations.IDs...)
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("ids set size mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids[%d] = %q, want %q", i, got[i], want[i])
		}
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
		"api", "auth", "completion", "config", "docs", "manifest", "schema",
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
