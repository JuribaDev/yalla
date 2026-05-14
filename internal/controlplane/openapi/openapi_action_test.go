package openapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestOperationRendersRequiredAction proves an authenticated endpoint's
// RequiredAction surfaces as the x-required-action OpenAPI extension, so
// agents and tooling can discover the authorization contract from the
// document, while a public endpoint omits the extension entirely.
func TestOperationRendersRequiredAction(t *testing.T) {
	t.Parallel()

	endpoints := []Endpoint{
		{
			Method:         http.MethodPost,
			Path:           "/v1/projects",
			OperationID:    "createProject",
			Summary:        "Create project",
			RequiresAuth:   true,
			RequiredAction: "project.create",
			SuccessStatus:  http.StatusCreated,
		},
		{
			Method:      http.MethodGet,
			Path:        "/healthz",
			OperationID: "getHealthz",
			Summary:     "Liveness probe",
		},
	}
	doc := Build(sampleInfo(), endpoints)

	authOp := doc.Paths["/v1/projects"]["post"]
	if authOp.RequiredAction != "project.create" {
		t.Errorf("authenticated operation RequiredAction = %q, want %q", authOp.RequiredAction, "project.create")
	}
	authJSON, err := json.Marshal(authOp)
	if err != nil {
		t.Fatalf("marshal authenticated operation: %v", err)
	}
	if !strings.Contains(string(authJSON), `"x-required-action":"project.create"`) {
		t.Errorf("authenticated operation JSON missing x-required-action: %s", authJSON)
	}

	publicOp := doc.Paths["/healthz"]["get"]
	if publicOp.RequiredAction != "" {
		t.Errorf("public operation RequiredAction = %q, want empty", publicOp.RequiredAction)
	}
	publicJSON, err := json.Marshal(publicOp)
	if err != nil {
		t.Fatalf("marshal public operation: %v", err)
	}
	if strings.Contains(string(publicJSON), "x-required-action") {
		t.Errorf("public operation JSON should omit x-required-action: %s", publicJSON)
	}
}
