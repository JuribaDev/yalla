package openapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestOperationRendersPathParameters proves an endpoint that declares path
// parameters surfaces them as OpenAPI parameter objects — each required, in
// "path", with a string schema — while an endpoint with no path parameters
// omits the parameters field entirely.
func TestOperationRendersPathParameters(t *testing.T) {
	t.Parallel()

	endpoints := []Endpoint{
		{
			Method:         http.MethodGet,
			Path:           "/v1/organizations/{org_id}",
			OperationID:    "getOrganization",
			Summary:        "Get an organization",
			RequiresAuth:   true,
			RequiredAction: "organization.read",
			PathParams: []PathParam{{
				Name:        "org_id",
				Description: "The id of the organization to retrieve.",
			}},
		},
		{
			Method:      http.MethodGet,
			Path:        "/healthz",
			OperationID: "getHealthz",
			Summary:     "Liveness probe",
		},
	}
	doc := Build(sampleInfo(), endpoints)

	op := doc.Paths["/v1/organizations/{org_id}"]["get"]
	if len(op.Parameters) != 1 {
		t.Fatalf("parameters = %+v, want exactly one path parameter", op.Parameters)
	}
	p := op.Parameters[0]
	if p.Name != "org_id" {
		t.Errorf("parameter name = %q, want org_id", p.Name)
	}
	if p.In != "path" {
		t.Errorf("parameter in = %q, want path", p.In)
	}
	if !p.Required {
		t.Error("parameter required = false, want true: path parameters are always required")
	}
	if p.Schema.Type != "string" {
		t.Errorf("parameter schema type = %q, want string", p.Schema.Type)
	}
	if p.Description == "" {
		t.Error("parameter description is empty, want the declared description")
	}

	opJSON, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal operation: %v", err)
	}
	if !strings.Contains(string(opJSON), `"in":"path"`) {
		t.Errorf("operation JSON missing path parameter: %s", opJSON)
	}

	publicOp := doc.Paths["/healthz"]["get"]
	if publicOp.Parameters != nil {
		t.Errorf("public operation Parameters = %+v, want nil", publicOp.Parameters)
	}
	publicJSON, err := json.Marshal(publicOp)
	if err != nil {
		t.Fatalf("marshal public operation: %v", err)
	}
	if strings.Contains(string(publicJSON), "parameters") {
		t.Errorf("operation with no path parameters should omit the parameters field: %s", publicJSON)
	}
}
