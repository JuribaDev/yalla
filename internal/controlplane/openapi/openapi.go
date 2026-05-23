// Package openapi builds the published OpenAPI 3.1 document for the Yalla
// Control Plane API.
//
// The document is assembled from a neutral []Endpoint slice supplied by the
// httpapi route table, which is the single source of truth for what the API
// serves. Keeping generation data-driven means a newly registered route is
// documented automatically, and the route-coverage test fails loudly if the
// served routes and the document ever drift apart.
//
// Every operation references the two stable response envelopes —
// SuccessEnvelope (yalla.output.v1) and ErrorEnvelope (yalla.error.v1) — so
// the wire contract is described once and reused. Sample values that resemble
// secrets are rendered with the standard redaction sentinel; the document
// never contains a real credential.
//
// Maps are marshalled with deterministically sorted keys so the published
// artifact is byte-stable across builds and easy to diff in review.
package openapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Version is the OpenAPI specification version this package emits.
const Version = "3.1.0"

// SecuritySchemeName is the components.securitySchemes key for the Yalla API
// key bearer-token scheme. It is part of the public contract.
const SecuritySchemeName = "ApiKeyAuth"

// Stable component schema names. They are exported because callers (the
// httpapi route table) reference them when an operation documents a non-default
// response body.
const (
	SchemaSuccessEnvelope = "SuccessEnvelope"
	SchemaErrorEnvelope   = "ErrorEnvelope"
	SchemaErrorBody       = "ErrorBody"
	SchemaOpenAPIDocument = "OpenAPIDocument"
	SchemaHTMLDocument    = "HTMLDocument"
)

func schemaRef(name string) string { return "#/components/schemas/" + name }

// Info carries the document-level identity block.
type Info struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// Endpoint is the neutral metadata describing one documented HTTP operation.
// The httpapi route table builds these and feeds them to Build; nothing in
// this package knows how a route is actually served.
type Endpoint struct {
	Method             string      // HTTP method, e.g. http.MethodGet.
	Path               string      // Route pattern, e.g. "/healthz".
	OperationID        string      // Stable, unique operationId.
	Summary            string      // One-line summary.
	Description        string      // Longer human description.
	Tags               []string    // Grouping tags.
	RequiresAuth       bool        // false => public (security: []).
	RequiredAction     string      // Policy action the operation authorizes; "" for public endpoints.
	PathParams         []PathParam // Path-template parameters, e.g. {org_id}; in declaration order.
	SuccessStatus      int         // Documented success status; 0 => 200.
	SuccessDescription string      // Description of the success response.
	SuccessSchema      string      // Success body component schema; "" => SuccessEnvelope.
	SuccessContentType string      // Success media type; "" => application/json.
}

// PathParam describes one {placeholder} segment of an Endpoint's path. Every
// path parameter is a required, non-secret string identifier — the control
// plane addresses resources by opaque ids — so the rendered OpenAPI parameter
// is always required:true with a string schema. The httpapi route table is the
// single source of truth: a route whose path contains a placeholder declares
// the matching PathParam here so the published document describes it.
type PathParam struct {
	Name        string // Placeholder name without braces, e.g. "org_id".
	Description string // Human description of what the parameter identifies.
}

// Document is the root OpenAPI 3.1 document.
type Document struct {
	OpenAPI    string     `json:"openapi"`
	Info       Info       `json:"info"`
	Servers    []Server   `json:"servers,omitempty"`
	Paths      Paths      `json:"paths"`
	Components Components `json:"components"`
}

// HasOperation reports whether the document describes the given method+path.
// The httpapi route-coverage test relies on it to prove every served route is
// documented.
func (d Document) HasOperation(method, path string) bool {
	item, ok := d.Paths[path]
	if !ok {
		return false
	}
	_, ok = item[strings.ToLower(method)]
	return ok
}

// OperationCount returns the total number of documented operations across all
// paths.
func (d Document) OperationCount() int {
	n := 0
	for _, item := range d.Paths {
		n += len(item)
	}
	return n
}

// Server is a single OpenAPI server entry.
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Paths maps a route pattern to its operations. It marshals with sorted keys.
type Paths map[string]PathItem

// MarshalJSON renders the paths object with deterministically sorted keys.
func (p Paths) MarshalJSON() ([]byte, error) { return marshalSortedMap(map[string]PathItem(p)) }

// PathItem maps a lower-case HTTP method to its operation. Sorted on marshal.
type PathItem map[string]Operation

// MarshalJSON renders the path item with deterministically sorted keys.
func (p PathItem) MarshalJSON() ([]byte, error) { return marshalSortedMap(map[string]Operation(p)) }

// Operation describes one HTTP operation. Security is always emitted (never
// omitempty) so a public endpoint explicitly advertises an empty requirement.
//
// RequiredAction is rendered as the x-required-action OpenAPI extension: it
// names the stable policy action this operation authorizes, so agents and
// tooling can discover the authorization contract straight from the document.
// It is omitted for public endpoints, which have no action.
type Operation struct {
	Tags           []string              `json:"tags,omitempty"`
	OperationID    string                `json:"operationId"`
	Summary        string                `json:"summary"`
	Description    string                `json:"description,omitempty"`
	Security       []map[string][]string `json:"security"`
	Parameters     []Parameter           `json:"parameters,omitempty"`
	RequiredAction string                `json:"x-required-action,omitempty"`
	Responses      Responses             `json:"responses"`
}

// Parameter is a single OpenAPI operation parameter. Only path parameters are
// emitted today, so In is always "path" and Required is always true; the shape
// is deliberately minimal and extends cleanly if query or header parameters are
// documented later.
type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
	Schema      Schema `json:"schema"`
}

// Responses maps a status code (or "default") to its response. Sorted on marshal.
type Responses map[string]Response

// MarshalJSON renders the responses object with deterministically sorted keys.
func (r Responses) MarshalJSON() ([]byte, error) { return marshalSortedMap(map[string]Response(r)) }

// Response is a single OpenAPI response object.
type Response struct {
	Description string     `json:"description"`
	Content     ContentMap `json:"content,omitempty"`
}

// ContentMap maps a media type to its payload schema. Sorted on marshal.
type ContentMap map[string]Media

// MarshalJSON renders the content object with deterministically sorted keys.
func (c ContentMap) MarshalJSON() ([]byte, error) { return marshalSortedMap(map[string]Media(c)) }

// Media is the schema wrapper for one media type.
type Media struct {
	Schema Schema `json:"schema"`
}

// Components holds the reusable schema and security-scheme definitions.
type Components struct {
	Schemas         SchemaMap         `json:"schemas"`
	SecuritySchemes SecuritySchemeMap `json:"securitySchemes"`
}

// SchemaMap maps a schema name to its definition. Sorted on marshal.
type SchemaMap map[string]*Schema

// MarshalJSON renders the schema object with deterministically sorted keys.
func (s SchemaMap) MarshalJSON() ([]byte, error) { return marshalSortedMap(map[string]*Schema(s)) }

// Schema is a deliberately small subset of JSON Schema — enough to describe
// the control-plane envelopes and reference component schemas.
type Schema struct {
	Ref         string          `json:"$ref,omitempty"`
	Type        string          `json:"type,omitempty"`
	Description string          `json:"description,omitempty"`
	Properties  SchemaMap       `json:"properties,omitempty"`
	Required    []string        `json:"required,omitempty"`
	Enum        []string        `json:"enum,omitempty"`
	Items       *Schema         `json:"items,omitempty"`
	Example     json.RawMessage `json:"example,omitempty"`
}

// SecuritySchemeMap maps a scheme name to its definition. Sorted on marshal.
type SecuritySchemeMap map[string]SecurityScheme

// MarshalJSON renders the security-scheme object with deterministically
// sorted keys.
func (s SecuritySchemeMap) MarshalJSON() ([]byte, error) {
	return marshalSortedMap(map[string]SecurityScheme(s))
}

// SecurityScheme describes one authentication scheme.
type SecurityScheme struct {
	Type        string `json:"type"`
	Scheme      string `json:"scheme,omitempty"`
	Description string `json:"description,omitempty"`
}

// Build assembles the OpenAPI document from the document identity and the
// supplied endpoints. The standard envelope schemas and security scheme are
// always included so every operation can reference them.
func Build(info Info, endpoints []Endpoint) Document {
	doc := Document{
		OpenAPI: Version,
		Info:    info,
		Servers: []Server{{
			URL:         "/",
			Description: "Relative to the deployed control-plane API host.",
		}},
		Paths: Paths{},
		Components: Components{
			Schemas:         standardSchemas(),
			SecuritySchemes: standardSecuritySchemes(),
		},
	}
	for _, ep := range endpoints {
		item := doc.Paths[ep.Path]
		if item == nil {
			item = PathItem{}
			doc.Paths[ep.Path] = item
		}
		item[strings.ToLower(ep.Method)] = operationFor(ep)
	}
	return doc
}

// operationFor renders a single Endpoint into an OpenAPI operation. Every
// operation documents its success response and a "default" error response so
// the error envelope is always discoverable.
func operationFor(ep Endpoint) Operation {
	status := ep.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	successDesc := ep.SuccessDescription
	if successDesc == "" {
		successDesc = "Successful response."
	}
	successSchema := ep.SuccessSchema
	if successSchema == "" {
		successSchema = SchemaSuccessEnvelope
	}

	// A public endpoint advertises "security": [] explicitly, which overrides
	// any document-level requirement; an authenticated endpoint requires the
	// API key bearer scheme.
	security := []map[string][]string{}
	if ep.RequiresAuth {
		security = []map[string][]string{{SecuritySchemeName: {}}}
	}

	return Operation{
		Tags:           ep.Tags,
		OperationID:    ep.OperationID,
		Summary:        ep.Summary,
		Description:    ep.Description,
		Security:       security,
		Parameters:     pathParameters(ep.PathParams),
		RequiredAction: ep.RequiredAction,
		Responses: Responses{
			strconv.Itoa(status): contentResponse(successDesc, successSchema, ep.SuccessContentType),
			"default":            jsonResponse("Error response using the stable yalla.error.v1 envelope.", SchemaErrorEnvelope),
		},
	}
}

// pathParameters renders an endpoint's path placeholders into OpenAPI
// parameter objects. It returns nil for an endpoint with no path parameters so
// the parameters field is omitted entirely rather than emitted as an empty
// array. Every path parameter is a required string identifier.
func pathParameters(params []PathParam) []Parameter {
	if len(params) == 0 {
		return nil
	}
	out := make([]Parameter, 0, len(params))
	for _, p := range params {
		out = append(out, Parameter{
			Name:        p.Name,
			In:          "path",
			Required:    true,
			Description: p.Description,
			Schema:      Schema{Type: "string"},
		})
	}
	return out
}

// jsonResponse builds an application/json response referencing a component
// schema by name.
func jsonResponse(description, schemaName string) Response {
	return contentResponse(description, schemaName, "application/json")
}

// contentResponse builds a response for the given media type referencing a
// component schema by name.
func contentResponse(description, schemaName, mediaType string) Response {
	if mediaType == "" {
		mediaType = "application/json"
	}
	return Response{
		Description: description,
		Content: ContentMap{
			mediaType: Media{Schema: Schema{Ref: schemaRef(schemaName)}},
		},
	}
}

// standardSchemas defines the reusable component schemas. The two envelope
// schemas describe the entire stable wire contract. Their examples deliberately
// render secret-shaped values with output.Sentinel so the published document
// never carries a real credential.
func standardSchemas() SchemaMap {
	return SchemaMap{
		SchemaSuccessEnvelope: {
			Type:        "object",
			Description: "Stable success envelope (yalla.output.v1). Every successful API response uses this shape.",
			Required:    []string{"data", "ok", "request_id", "schema_version"},
			Properties: SchemaMap{
				"schema_version": {Type: "string", Enum: []string{output.SuccessSchema}, Description: `Wire-contract version. Always "` + output.SuccessSchema + `".`},
				"ok":             {Type: "boolean", Description: "Always true for a success envelope."},
				"data":           {Description: "Operation-specific payload. Its shape depends on the endpoint."},
				"request_id":     {Type: "string", Description: "Correlates this response with logs and audit records."},
				"warnings":       {Type: "array", Description: "Optional non-fatal advisories. Entitlement warnings include entitlement_key, usage, threshold, limit, period, and hint.", Items: &Schema{Ref: schemaRef("SuccessWarning")}},
			},
			Example: json.RawMessage(`{"schema_version":"` + output.SuccessSchema + `","ok":true,"data":{"api_key":"yalla_sk_live_` + output.Sentinel + `"},"request_id":"req_2f9c1a7b"}`),
		},
		"SuccessWarning": {
			Type:        "object",
			Description: "Structured non-fatal warning carried by a success envelope.",
			Required:    []string{"code"},
			Properties: SchemaMap{
				"code":            {Type: "string", Description: "Stable warning code, for example ENTITLEMENT_THRESHOLD_WARNING or ENTITLEMENT_LIMIT_EXCEEDED."},
				"message":         {Type: "string", Description: "Human-readable non-secret warning text."},
				"entitlement_key": {Type: "string", Description: "Stable entitlement or usage key the warning applies to."},
				"usage":           {Type: "integer", Description: "Current usage observed for the entitlement period."},
				"threshold":       {Type: "integer", Description: "Reached warning threshold percentage."},
				"limit":           {Type: "integer", Description: "Configured entitlement limit."},
				"period": {
					Type:        "object",
					Description: "Billing or reset period the warning applies to.",
					Properties: SchemaMap{
						"kind":  {Type: "string", Description: "Period kind, usually billing_period."},
						"start": {Type: "string", Description: "Inclusive period start as RFC3339."},
						"end":   {Type: "string", Description: "Exclusive period end as RFC3339."},
					},
				},
				"hint": {Type: "string", Description: "Recovery or upgrade guidance."},
			},
		},
		SchemaErrorEnvelope: {
			Type:        "object",
			Description: "Stable error envelope (yalla.error.v1). Every failed API response uses this shape.",
			Required:    []string{"error", "ok", "request_id", "schema_version"},
			Properties: SchemaMap{
				"schema_version": {Type: "string", Enum: []string{yerr.SchemaVersion}, Description: `Wire-contract version. Always "` + yerr.SchemaVersion + `".`},
				"ok":             {Type: "boolean", Description: "Always false for an error envelope."},
				"error":          {Ref: schemaRef(SchemaErrorBody)},
				"request_id":     {Type: "string", Description: "Correlates this response with logs and audit records."},
			},
			Example: json.RawMessage(`{"schema_version":"` + yerr.SchemaVersion + `","ok":false,"error":{"code":"E_NOT_FOUND","message":"route not found","documentation_url":"https://docs.yalla.dev/api/errors/E_NOT_FOUND"},"request_id":"req_2f9c1a7b"}`),
		},
		SchemaErrorBody: {
			Type:        "object",
			Description: "The error detail carried by an error envelope.",
			Required:    []string{"code", "message"},
			Properties: SchemaMap{
				"code":              {Type: "string", Description: "Stable machine-readable error code, e.g. E_NOT_FOUND."},
				"message":           {Type: "string", Description: "Human-readable summary. Never contains secrets."},
				"hint":              {Type: "string", Description: "Optional remediation suggestion."},
				"documentation_url": {Type: "string", Description: "Optional link to the documentation for this error code."},
			},
		},
		SchemaOpenAPIDocument: {
			Type:        "object",
			Description: "An OpenAPI 3.1 document. Free-form; consult the OpenAPI specification for its shape.",
		},
		SchemaHTMLDocument: {
			Type:        "string",
			Description: "An HTML document served directly to browsers.",
		},
	}
}

// standardSecuritySchemes defines the Yalla API key bearer-token scheme. Its
// description includes a redacted sample credential.
func standardSecuritySchemes() SecuritySchemeMap {
	return SecuritySchemeMap{
		SecuritySchemeName: {
			Type:   "http",
			Scheme: "bearer",
			Description: "Yalla API key supplied as an HTTP bearer token. " +
				"Example: `Authorization: Bearer yalla_sk_live_" + output.Sentinel + "`. " +
				"Real keys are never shown in this document.",
		},
	}
}

// marshalSortedMap marshals a string-keyed map with its keys in sorted order so
// the rendered document is deterministic and diff-friendly.
func marshalSortedMap[V any](m map[string]V) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
