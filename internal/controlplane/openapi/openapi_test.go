package openapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// sampleEndpoints exercises both a public and an authenticated endpoint so the
// security wiring is covered.
func sampleEndpoints() []Endpoint {
	return []Endpoint{
		{
			Method:             http.MethodGet,
			Path:               "/healthz",
			OperationID:        "getHealthz",
			Summary:            "Liveness probe",
			Description:        "Reports liveness.",
			Tags:               []string{"operations"},
			SuccessDescription: "Alive.",
		},
		{
			Method:        http.MethodPost,
			Path:          "/v1/projects",
			OperationID:   "createProject",
			Summary:       "Create project",
			RequiresAuth:  true,
			SuccessStatus: http.StatusCreated,
		},
	}
}

func sampleInfo() Info {
	return Info{Title: "Yalla Control Plane API", Version: "1.2.3", Description: "Test."}
}

func TestBuildEmitsOpenAPI31Identity(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", doc.OpenAPI)
	}
	if doc.Info.Version != "1.2.3" {
		t.Errorf("info.version = %q, want 1.2.3", doc.Info.Version)
	}
	if len(doc.Servers) == 0 {
		t.Errorf("servers is empty, want at least one entry")
	}
}

func TestBuildDefinesEnvelopeAndErrorSchemas(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	for _, name := range []string{SchemaSuccessEnvelope, SchemaErrorEnvelope, SchemaErrorBody, SchemaOpenAPIDocument} {
		if _, ok := doc.Components.Schemas[name]; !ok {
			t.Errorf("components.schemas is missing %q", name)
		}
	}

	success := doc.Components.Schemas[SchemaSuccessEnvelope]
	if got := success.Properties["schema_version"]; got == nil || len(got.Enum) != 1 || got.Enum[0] != output.SuccessSchema {
		t.Errorf("SuccessEnvelope.schema_version enum = %+v, want [%q]", got, output.SuccessSchema)
	}
	errEnv := doc.Components.Schemas[SchemaErrorEnvelope]
	if got := errEnv.Properties["schema_version"]; got == nil || len(got.Enum) != 1 || got.Enum[0] != yerr.SchemaVersion {
		t.Errorf("ErrorEnvelope.schema_version enum = %+v, want [%q]", got, yerr.SchemaVersion)
	}
	if ref := errEnv.Properties["error"]; ref == nil || ref.Ref != schemaRef(SchemaErrorBody) {
		t.Errorf("ErrorEnvelope.error ref = %+v, want $ref %q", ref, schemaRef(SchemaErrorBody))
	}
}

func TestBuildDefinesApiKeySecurityScheme(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	scheme, ok := doc.Components.SecuritySchemes[SecuritySchemeName]
	if !ok {
		t.Fatalf("security scheme %q not defined", SecuritySchemeName)
	}
	if scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Errorf("security scheme = %+v, want http/bearer", scheme)
	}
}

func TestBuildDocumentsEveryEndpointWithBothResponses(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	if got := doc.OperationCount(); got != 2 {
		t.Fatalf("operation count = %d, want 2", got)
	}

	op := doc.Paths["/healthz"]["get"]
	if op.OperationID != "getHealthz" {
		t.Errorf("operationId = %q, want getHealthz", op.OperationID)
	}
	if _, ok := op.Responses["200"]; !ok {
		t.Errorf("/healthz GET missing 200 response")
	}
	if _, ok := op.Responses["default"]; !ok {
		t.Errorf("/healthz GET missing default error response")
	}
	if ref := op.Responses["default"].Content["application/json"].Schema.Ref; ref != schemaRef(SchemaErrorEnvelope) {
		t.Errorf("default response ref = %q, want %q", ref, schemaRef(SchemaErrorEnvelope))
	}

	// A custom success status is honoured.
	created := doc.Paths["/v1/projects"]["post"]
	if _, ok := created.Responses["201"]; !ok {
		t.Errorf("/v1/projects POST missing 201 response, have %v", created.Responses)
	}
}

func TestPublicEndpointHasEmptySecurityAndAuthEndpointRequiresApiKey(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())

	public := doc.Paths["/healthz"]["get"]
	if public.Security == nil || len(public.Security) != 0 {
		t.Errorf("public endpoint security = %+v, want an explicit empty slice", public.Security)
	}

	authed := doc.Paths["/v1/projects"]["post"]
	if len(authed.Security) != 1 {
		t.Fatalf("authenticated endpoint security = %+v, want one requirement", authed.Security)
	}
	if _, ok := authed.Security[0][SecuritySchemeName]; !ok {
		t.Errorf("authenticated endpoint does not require %q", SecuritySchemeName)
	}
}

func TestHasOperationReportsMethodAndPath(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	if !doc.HasOperation(http.MethodGet, "/healthz") {
		t.Errorf("HasOperation(GET, /healthz) = false, want true")
	}
	if !doc.HasOperation("get", "/healthz") {
		t.Errorf("HasOperation is not case-insensitive on method")
	}
	if doc.HasOperation(http.MethodPost, "/healthz") {
		t.Errorf("HasOperation(POST, /healthz) = true, want false")
	}
	if doc.HasOperation(http.MethodGet, "/missing") {
		t.Errorf("HasOperation(GET, /missing) = true, want false")
	}
}

func TestBuildMarshalsToDeterministicJSON(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	first, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal #%d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("marshal is not deterministic:\n#0: %s\n#%d: %s", first, i, again)
		}
	}

	// Sanity: the marshalled document is itself valid JSON.
	var generic map[string]any
	if err := json.Unmarshal(first, &generic); err != nil {
		t.Fatalf("marshalled document is not valid JSON: %v", err)
	}
}

// secretLikePattern matches a credential-shaped token that is NOT redacted.
// Examples in the document must use output.Sentinel instead of a real value.
var secretLikePattern = regexp.MustCompile(`yalla_sk_[a-zA-Z]+_[a-zA-Z0-9]{6,}`)

func TestExamplesUseRedactedSampleSecrets(t *testing.T) {
	t.Parallel()

	doc := Build(sampleInfo(), sampleEndpoints())
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("document contains no %s sentinel, expected redacted sample secrets", output.Sentinel)
	}
	if loc := secretLikePattern.FindString(body); loc != "" {
		t.Errorf("document contains an unredacted secret-shaped value %q", loc)
	}

	// The success envelope example must carry a redacted, not real, credential.
	success := doc.Components.Schemas[SchemaSuccessEnvelope]
	if !strings.Contains(string(success.Example), output.Sentinel) {
		t.Errorf("SuccessEnvelope example = %s, want a redacted sample secret", success.Example)
	}
	// The security scheme documents the bearer token with a redacted example.
	scheme := doc.Components.SecuritySchemes[SecuritySchemeName]
	if !strings.Contains(scheme.Description, output.Sentinel) {
		t.Errorf("security scheme description = %q, want a redacted sample token", scheme.Description)
	}
}
