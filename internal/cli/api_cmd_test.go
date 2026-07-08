package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/output"
)

// expectedOpCount mirrors api.expectedOperationCount but lives in the cli
// package so a CLI-level regression also fails this assertion. The two
// constants must be bumped together.
const expectedOpCount = 455

func TestAPIOperations_JSONListsEveryOperation(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "api", "operations")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	var env struct {
		SchemaVersion string           `json:"schema_version"`
		Data          apiOperationsDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.Total != expectedOpCount {
		t.Errorf("total = %d, want %d", env.Data.Total, expectedOpCount)
	}
	if len(env.Data.Operations) != expectedOpCount {
		t.Errorf("operations = %d, want %d", len(env.Data.Operations), expectedOpCount)
	}
	if env.Data.SpecSHA256 != api.EmbeddedSpecSHA256 {
		t.Errorf("spec_sha256 = %q, want %q", env.Data.SpecSHA256, api.EmbeddedSpecSHA256)
	}
	// Spot-check operation_id sortedness so a regression in the registry's
	// canonical order fails the CLI test too.
	for i := 1; i < len(env.Data.Operations); i++ {
		if env.Data.Operations[i-1].OperationID >= env.Data.Operations[i].OperationID {
			t.Fatalf("operations not sorted at %d: %q before %q",
				i, env.Data.Operations[i-1].OperationID, env.Data.Operations[i].OperationID)
		}
	}
}

func TestAPIOperations_JSONFiltersByTag(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "api", "operations", "--tag", "application")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data apiOperationsDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Tag != "application" {
		t.Errorf("tag = %q", env.Data.Tag)
	}
	if env.Data.Total == 0 {
		t.Fatal("application tag produced 0 operations")
	}
	for _, op := range env.Data.Operations {
		if op.Tag != "application" {
			t.Errorf("op %q tag = %q, want application", op.OperationID, op.Tag)
		}
	}
}

func TestAPIOperations_UnknownTagFailsWithInvalidInput(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "api", "operations", "--tag", "definitely-not-a-tag")
	if err == nil {
		t.Fatal("expected error for unknown tag")
	}
	// Error envelopes are part of the diagnostic stream — they land on
	// stderr so stdout stays reserved for successful data.
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	if !strings.Contains(stderr, "E_INVALID_INPUT") {
		t.Errorf("want E_INVALID_INPUT in JSON error envelope on stderr; got %q", stderr)
	}
	if !strings.Contains(stderr, "yalla.error.v1") {
		t.Errorf("want error schema_version in stderr; got %q", stderr)
	}
}

func TestAPIOperations_HumanRendersTable(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "api", "operations", "--tag", "admin")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty on success; got %q", stderr)
	}
	if !strings.Contains(stdout, "OPERATION_ID") {
		t.Errorf("missing header row: %q", stdout)
	}
	if !strings.Contains(stdout, "admin-setupMonitoring") {
		t.Errorf("missing operation row: %q", stdout)
	}
}

func TestAPIOperations_NoSubcommandShowsHelp(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "api")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty for help path; got %q", stdout)
	}
	if !strings.Contains(stderr, "operations") {
		t.Errorf("help on stderr should mention operations subcommand: %q", stderr)
	}
}
