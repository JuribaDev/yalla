package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestSchemaList_JSONListsEveryOperation(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "schema", "list")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	var env struct {
		SchemaVersion string        `json:"schema_version"`
		Data          schemaListDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q", env.SchemaVersion)
	}
	if env.Data.Total != expectedOpCount {
		t.Errorf("total = %d, want %d", env.Data.Total, expectedOpCount)
	}
	if len(env.Data.Schemas) != expectedOpCount {
		t.Errorf("schemas = %d, want %d", len(env.Data.Schemas), expectedOpCount)
	}
	if env.Data.SpecSHA256 != api.EmbeddedSpecSHA256 {
		t.Errorf("spec_sha256 = %q", env.Data.SpecSHA256)
	}
}

func TestSchemaGet_JSONIncludesInputAndOutputs(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "schema", "get", "application-deploy")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	var env struct {
		Data api.SchemaDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.OperationID != "application-deploy" {
		t.Errorf("operation_id = %q", env.Data.OperationID)
	}
	if env.Data.Method == "" || env.Data.Path == "" {
		t.Errorf("method/path missing: %+v", env.Data)
	}
	if env.Data.Input == nil {
		t.Fatal("input is nil")
	}
	if env.Data.Input.Body == nil {
		t.Error("application-deploy should have a request body schema")
	}
	if len(env.Data.Outputs) == 0 {
		t.Error("outputs is empty")
	}
}

func TestSchemaGet_UnknownOperationReturnsNotFound(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "schema", "get", "definitely-not-an-op")
	if err == nil {
		t.Fatal("expected error for unknown operationId")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	if !strings.Contains(stderr, "E_NOT_FOUND") {
		t.Errorf("want E_NOT_FOUND error envelope on stderr; got %q", stderr)
	}
	if !strings.Contains(stderr, "yalla.error.v1") {
		t.Errorf("want error schema_version in stderr; got %q", stderr)
	}
}

func TestSchemaGet_RequiresOperationID(t *testing.T) {
	_, stderr, err := runRootArgs(t, "schema", "get")
	if err == nil {
		t.Fatal("expected error for missing operationId")
	}
	// Cobra's missing-arg error is mapped to E_USAGE by the typed renderer.
	if !strings.Contains(stderr, "E_USAGE") {
		t.Errorf("want E_USAGE on stderr; got %q", stderr)
	}
}

func TestSchemaGet_HumanRendersStructuredText(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "schema", "get", "admin-setupMonitoring")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty on success; got %q", stderr)
	}
	for _, want := range []string{"admin-setupMonitoring", "POST", "/admin.setupMonitoring", "auth: required"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("human output missing %q; full output: %q", want, stdout)
		}
	}
}

func TestSchemaList_HumanShowsSummary(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "schema", "list")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	if !strings.Contains(stdout, "OPERATION_ID") {
		t.Errorf("missing header in schema list output")
	}
	// The summary banner mentions the total.
	if !strings.Contains(stdout, "operations have schemas") {
		t.Errorf("missing summary banner in schema list output")
	}
}
