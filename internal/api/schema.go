package api

import (
	"encoding/json"
	"fmt"
	"sort"
)

// SchemaDoc is the agent-facing extraction of a single operation's input
// and output schemas. It is the JSON shape returned by `yalla schema get
// <operationId> --json` and consumed by manifest tooling.
//
// The doc is a strict superset of OperationID/Method/Path so an agent can
// extract a schema by id in one round trip without correlating against a
// separate operations list. Schemas are preserved as raw JSON to keep the
// full OpenAPI/JSON Schema fidelity (oneOf/allOf/anyOf, $defs, examples).
type SchemaDoc struct {
	OperationID  string                `json:"operation_id"`
	Method       string                `json:"method"`
	Path         string                `json:"path"`
	Tag          string                `json:"tag,omitempty"`
	Summary      string                `json:"summary,omitempty"`
	Description  string                `json:"description,omitempty"`
	RequiresAuth bool                  `json:"requires_auth"`
	Security     []SecurityRequirement `json:"security,omitempty"`

	// Input describes everything an agent must supply to invoke the op:
	// path/query/header/cookie parameters and the request body schema.
	// Always non-nil so the JSON shape is stable.
	Input *InputSchema `json:"input"`

	// Outputs is the per-status response schema set, in canonical order.
	// Always non-nil; an empty slice signals an op with no documented
	// responses (which would be a spec defect).
	Outputs []ResponseSchema `json:"outputs"`
}

// InputSchema separates the parameter list from the request body so an
// agent can branch without inspecting the OpenAPI shape directly.
type InputSchema struct {
	Parameters []ParameterSchema `json:"parameters"`
	Body       *BodySchema       `json:"body,omitempty"`
}

// ParameterSchema mirrors api.Parameter but lives in the SchemaDoc tree so
// the schema commands can evolve their public shape independently of the
// registry's internal representation.
type ParameterSchema struct {
	Name        string          `json:"name"`
	In          string          `json:"in"`
	Required    bool            `json:"required"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// BodySchema describes the request body envelope. Required defaults to the
// OpenAPI `requestBody.required` boolean; ContentType is the media type
// used for the embedded schema.
type BodySchema struct {
	Required    bool            `json:"required"`
	ContentType string          `json:"content_type"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// ResponseSchema is the per-status response contract. Status preserves the
// OpenAPI key (numeric or "default"); ContentType is empty when the
// response has no JSON body.
type ResponseSchema struct {
	Status      string          `json:"status"`
	Description string          `json:"description,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// Schema returns the SchemaDoc for the supplied operationId. The returned
// pointer is freshly allocated so the caller may serialise it directly
// without copying.
func (r *Registry) Schema(operationID string) (*SchemaDoc, error) {
	op, ok := r.Get(operationID)
	if !ok {
		return nil, fmt.Errorf("api: operation %q not found", operationID)
	}
	return r.schemaFor(op), nil
}

// AllSchemas materialises a SchemaDoc for every operation in the registry,
// preserving the canonical operationId order. Mainly used by `yalla schema
// list --json --full` and the manifest builder; not on a hot path.
func (r *Registry) AllSchemas() []*SchemaDoc {
	out := make([]*SchemaDoc, len(r.ops))
	for i, op := range r.ops {
		out[i] = r.schemaFor(op)
	}
	return out
}

// schemaFor projects a single Operation into a SchemaDoc. Internal so the
// registry stays the single source of truth — every external caller goes
// through Schema/AllSchemas.
func (r *Registry) schemaFor(op Operation) *SchemaDoc {
	params := make([]ParameterSchema, 0, len(op.Parameters))
	for _, p := range op.Parameters {
		params = append(params, ParameterSchema{
			Name:        p.Name,
			In:          p.In,
			Required:    p.Required,
			Description: p.Description,
			Schema:      p.Schema,
		})
	}
	sort.SliceStable(params, func(i, j int) bool {
		// Path params before query before header before cookie keeps the
		// agent ergonomics consistent across operations. Within a group,
		// preserve OpenAPI declaration order via SliceStable.
		return paramOrder(params[i].In) < paramOrder(params[j].In)
	})

	input := &InputSchema{Parameters: params}
	if op.RequestBody != nil {
		input.Body = &BodySchema{
			Required:    op.RequestBody.Required,
			ContentType: op.RequestBody.ContentType,
			Description: op.RequestBody.Description,
			Schema:      op.RequestBody.Schema,
		}
	}

	outputs := make([]ResponseSchema, 0, len(op.Responses))
	for _, resp := range op.Responses {
		outputs = append(outputs, ResponseSchema{
			Status:      resp.Status,
			Description: resp.Description,
			ContentType: resp.ContentType,
			Schema:      resp.Schema,
		})
	}

	return &SchemaDoc{
		OperationID:  op.OperationID,
		Method:       op.Method,
		Path:         op.Path,
		Tag:          op.Tag,
		Summary:      op.Summary,
		Description:  op.Description,
		RequiresAuth: op.RequiresAuth,
		Security:     op.Security,
		Input:        input,
		Outputs:      outputs,
	}
}

// paramOrder maps OpenAPI parameter locations to a sort weight. Unknown
// locations bucket to the end of the list rather than panic so a future
// spec extension never breaks `yalla schema get`.
func paramOrder(in string) int {
	switch in {
	case "path":
		return 0
	case "query":
		return 1
	case "header":
		return 2
	case "cookie":
		return 3
	default:
		return 99
	}
}
