// Package openapi — canonical OpenAPI 3.1 schema conformance suite
// (BE-0382).
//
// The functions in this file are the load-bearing reference contract
// the OpenAPI conformance gate documented in SECURITY.md
// ("## OpenAPI Schema Conformance Tests") and CONTRIBUTING.md
// ("Required Checks Before Every Commit", step 8) is built on. The
// PRD's `verificationLoop.requiredBackendCommands` array carries
// `go test -run TestOpenAPI ./...` and binds to the function names
// declared here — a rename silently de-gates the conformance suite
// for any caller relying on the `-run` filter.
//
// Three conformance tests cover the three load-bearing wire
// invariants the published `/openapi.json` document MUST satisfy:
//
//  1. TestOpenAPIConformance — end-to-end document conformance. Every
//     documented operation has a success response and a stable error
//     envelope response, every authenticated operation requires the
//     ApiKeyAuth bearer scheme and advertises `x-required-action`,
//     every public endpoint advertises an explicit empty security
//     slice, and every path parameter renders as `required: true`,
//     `in: path`, with a string schema.
//  2. TestOpenAPIEnvelopesReferenceStableSchemaVersions — the
//     published `SuccessEnvelope` and `ErrorEnvelope` component
//     schemas pin the `schema_version` enum to the exact constants
//     callers depend on (`output.SuccessSchema` /
//     `yerr.SchemaVersion`). A silent drift in either constant would
//     surface immediately.
//  3. TestOpenAPIExamplesAreRedacted — the published document MUST
//     contain at least one redaction sentinel and MUST NOT carry any
//     credential-shaped sample token. Examples that resemble secrets
//     are rendered through `output.Sentinel`, never with a live
//     value.
//
// The fixtures are deterministic: a hand-curated public +
// authenticated endpoint pair, deterministic JSON marshalling driven
// by `marshalSortedMap`, and redaction sentinels in every example
// body. The suite never reaches a live Postgres, a live Dokploy, or
// any network. Any external smoke remains opt-in via
// `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`.
package openapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// conformanceEndpoints is the deterministic fixture every test in
// this file builds on. It exercises both a public liveness endpoint
// (security: [], no required-action) and an authenticated
// resource-owning endpoint (ApiKeyAuth required, required-action
// declared, path parameter declared). Keeping the fixture small and
// hand-curated keeps every assertion auditable from a single read.
func conformanceEndpoints() []Endpoint {
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
			Method:         http.MethodGet,
			Path:           "/v1/organizations/{org_id}",
			OperationID:    "getOrganization",
			Summary:        "Get an organization",
			Description:    "Returns the organization identified by org_id.",
			Tags:           []string{"organizations"},
			RequiresAuth:   true,
			RequiredAction: "organization.read",
			PathParams: []PathParam{{
				Name:        "org_id",
				Description: "Opaque id of the organization to retrieve.",
			}},
		},
	}
}

func conformanceInfo() Info {
	return Info{Title: "Yalla Control Plane API", Version: "1.2.3", Description: "Conformance fixture."}
}

// TestOpenAPIConformance is the canonical end-to-end conformance gate
// the PRD's `go test -run TestOpenAPI ./...` filter binds to. It
// asserts every documented operation satisfies the load-bearing wire
// invariants the published `/openapi.json` artifact MUST keep: a
// pinned OpenAPI 3.1.0 identity, both response rows present (success
// + default error envelope), correct security wiring (public => empty
// security slice, authenticated => ApiKeyAuth requirement +
// x-required-action), and every path parameter rendered as required
// string in path. A regression in any of these surfaces fails this
// test before the document ships.
func TestOpenAPIConformance(t *testing.T) {
	t.Parallel()
	doc := Build(conformanceInfo(), conformanceEndpoints())

	if doc.OpenAPI != Version {
		t.Errorf("openapi = %q, want %q (operationId getHealthz, getOrganization) — document identity drifted from the published constant", doc.OpenAPI, Version)
	}
	if doc.Info.Version != "1.2.3" {
		t.Errorf("info.version = %q, want 1.2.3", doc.Info.Version)
	}
	if got := doc.OperationCount(); got != 2 {
		t.Fatalf("operation count = %d, want 2 — conformance fixture lost an operation", got)
	}

	// 1. Public endpoint contract: empty security slice, no
	//    x-required-action, success response under the documented
	//    status, and a default error-envelope response.
	public, ok := doc.Paths["/healthz"]["get"]
	if !ok {
		t.Fatalf("public operation GET /healthz missing from document")
	}
	if public.OperationID != "getHealthz" {
		t.Errorf("public operationId = %q, want getHealthz", public.OperationID)
	}
	if public.Security == nil || len(public.Security) != 0 {
		t.Errorf("public operation security = %+v (operationId %s, method GET, path /healthz), want explicit empty slice []", public.Security, public.OperationID)
	}
	if public.RequiredAction != "" {
		t.Errorf("public operation x-required-action = %q (operationId %s), want empty", public.RequiredAction, public.OperationID)
	}
	if _, ok := public.Responses["200"]; !ok {
		t.Errorf("public operation (operationId %s, method GET, path /healthz) missing 200 success response, have %v", public.OperationID, public.Responses)
	}
	if _, ok := public.Responses["default"]; !ok {
		t.Errorf("public operation (operationId %s, method GET, path /healthz) missing default error-envelope response, have %v", public.OperationID, public.Responses)
	}

	// 2. Authenticated endpoint contract: exactly one ApiKeyAuth
	//    security requirement, x-required-action declared, success
	//    response present, default error-envelope response present,
	//    and every path parameter rendered as required string in
	//    path.
	authed, ok := doc.Paths["/v1/organizations/{org_id}"]["get"]
	if !ok {
		t.Fatalf("authenticated operation GET /v1/organizations/{org_id} missing from document")
	}
	if authed.OperationID != "getOrganization" {
		t.Errorf("authenticated operationId = %q, want getOrganization", authed.OperationID)
	}
	if len(authed.Security) != 1 {
		t.Fatalf("authenticated operation security = %+v (operationId %s), want exactly one requirement", authed.Security, authed.OperationID)
	}
	if _, ok := authed.Security[0][SecuritySchemeName]; !ok {
		t.Errorf("authenticated operation (operationId %s) does not require %q security scheme; have %+v", authed.OperationID, SecuritySchemeName, authed.Security[0])
	}
	if authed.RequiredAction != "organization.read" {
		t.Errorf("authenticated operation x-required-action = %q (operationId %s), want organization.read", authed.RequiredAction, authed.OperationID)
	}
	if _, ok := authed.Responses["200"]; !ok {
		t.Errorf("authenticated operation (operationId %s, method GET, path /v1/organizations/{org_id}) missing 200 success response, have %v", authed.OperationID, authed.Responses)
	}
	if _, ok := authed.Responses["default"]; !ok {
		t.Errorf("authenticated operation (operationId %s, method GET, path /v1/organizations/{org_id}) missing default error-envelope response, have %v", authed.OperationID, authed.Responses)
	}
	if len(authed.Parameters) != 1 {
		t.Fatalf("authenticated operation parameters = %+v (operationId %s), want exactly one path parameter", authed.Parameters, authed.OperationID)
	}
	param := authed.Parameters[0]
	if param.Name != "org_id" {
		t.Errorf("path parameter name = %q (operationId %s), want org_id", param.Name, authed.OperationID)
	}
	if param.In != "path" {
		t.Errorf("path parameter in = %q (operationId %s, parameter %s), want path", param.In, authed.OperationID, param.Name)
	}
	if !param.Required {
		t.Errorf("path parameter required = false (operationId %s, parameter %s), want true — every path parameter MUST be required", authed.OperationID, param.Name)
	}
	if param.Schema.Type != "string" {
		t.Errorf("path parameter schema = %+v (operationId %s, parameter %s), want schema with type=string", param.Schema, authed.OperationID, param.Name)
	}

	// 3. HasOperation is the route-coverage seam every served route
	//    relies on to prove it is documented. Asserting both
	//    operations are reachable through it catches a regression
	//    that breaks the route-coverage test without ever building
	//    the JSON.
	if !doc.HasOperation(http.MethodGet, "/healthz") {
		t.Errorf("HasOperation(GET, /healthz) = false, want true — public endpoint route-coverage seam broken")
	}
	if !doc.HasOperation(http.MethodGet, "/v1/organizations/{org_id}") {
		t.Errorf("HasOperation(GET, /v1/organizations/{org_id}) = false, want true — authenticated endpoint route-coverage seam broken")
	}
}

// TestOpenAPIEnvelopesReferenceStableSchemaVersions pins the
// `SuccessEnvelope` and `ErrorEnvelope` component schemas to the
// canonical schema_version enum values callers depend on
// (`output.SuccessSchema` and `yerr.SchemaVersion`). A silent drift
// in either constant would let an SDK or AI agent decode payloads
// under the wrong contract. The conformance suite catches it at the
// document-build boundary.
func TestOpenAPIEnvelopesReferenceStableSchemaVersions(t *testing.T) {
	t.Parallel()
	doc := Build(conformanceInfo(), conformanceEndpoints())

	for _, name := range []string{SchemaSuccessEnvelope, SchemaErrorEnvelope, SchemaErrorBody, SchemaOpenAPIDocument} {
		if _, ok := doc.Components.Schemas[name]; !ok {
			t.Errorf("components.schemas missing %q — every conformance caller depends on the stable component name", name)
		}
	}

	success := doc.Components.Schemas[SchemaSuccessEnvelope]
	if success == nil {
		t.Fatalf("SuccessEnvelope schema missing; cannot validate schema_version enum")
	}
	gotSuccess := success.Properties["schema_version"]
	if gotSuccess == nil || len(gotSuccess.Enum) != 1 || gotSuccess.Enum[0] != output.SuccessSchema {
		t.Errorf("SuccessEnvelope.schema_version enum = %+v, want [%q] — yalla.output.v1 envelope contract drifted from the published constant", gotSuccess, output.SuccessSchema)
	}

	errEnv := doc.Components.Schemas[SchemaErrorEnvelope]
	if errEnv == nil {
		t.Fatalf("ErrorEnvelope schema missing; cannot validate schema_version enum")
	}
	gotError := errEnv.Properties["schema_version"]
	if gotError == nil || len(gotError.Enum) != 1 || gotError.Enum[0] != yerr.SchemaVersion {
		t.Errorf("ErrorEnvelope.schema_version enum = %+v, want [%q] — yalla.error.v1 envelope contract drifted from the published constant", gotError, yerr.SchemaVersion)
	}

	// The error envelope MUST $ref the error body schema so the
	// wire contract is described once and reused.
	if ref := errEnv.Properties["error"]; ref == nil || ref.Ref != schemaRef(SchemaErrorBody) {
		t.Errorf("ErrorEnvelope.error ref = %+v, want $ref %q — error-body component reference drifted", ref, schemaRef(SchemaErrorBody))
	}

	// The ApiKeyAuth security scheme MUST be defined for the
	// `RequiresAuth: true` operations to bind to.
	scheme, ok := doc.Components.SecuritySchemes[SecuritySchemeName]
	if !ok {
		t.Fatalf("security scheme %q not defined; authenticated operations cannot bind to it", SecuritySchemeName)
	}
	if scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Errorf("security scheme = %+v, want http/bearer", scheme)
	}
}

// TestOpenAPIExamplesAreRedacted is the load-bearing assertion that
// the published document never carries a live credential. Every
// example body that resembles a secret is rendered through
// `output.Sentinel` and the credential-shaped token pattern
// (`yalla_sk_<env>_<value>`) MUST NOT appear in the marshalled
// artifact. A regression here would publish a real key in the
// publicly served OpenAPI document, which is the worst-case
// regression for an API consumed by AI agents and SDKs that may
// cache examples.
func TestOpenAPIExamplesAreRedacted(t *testing.T) {
	t.Parallel()
	doc := Build(conformanceInfo(), conformanceEndpoints())

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("published document contains no %q sentinel — examples that resemble credentials MUST be rendered through output.Sentinel, never with a live value", output.Sentinel)
	}

	// The credential-shaped pattern is the legacy live-secret
	// shape `yalla_sk_<env>_<value>`. Detecting it in the
	// marshalled document is the load-bearing negative assertion
	// that no example accidentally embeds a real key.
	if loc := secretLikePattern.FindStringIndex(body); loc != nil {
		t.Errorf("published document contains a credential-shaped token at offset %d-%d; examples MUST be rendered through output.Sentinel rather than a live value", loc[0], loc[1])
	}
}
