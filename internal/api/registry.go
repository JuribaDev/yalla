package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Operation is a yalla-flavoured projection of a single OpenAPI operation.
// The fields are the public contract of the registry: every yalla command
// that consumes the registry (raw API executor, schema/manifest commands,
// docs generator, contract tests) reads from this struct, not the raw
// OpenAPI document.
//
// JSON tags use snake_case so the same shape can be serialised directly into
// `yalla api operations --json` and `yalla manifest --json` envelopes
// without a separate DTO layer.
type Operation struct {
	// OperationID is the OpenAPI operationId, e.g. "application-deploy".
	// It is the stable handle used by `yalla api call <operationId>` and is
	// guaranteed unique across the registry.
	OperationID string `json:"operation_id"`

	// Method is the upper-cased HTTP verb (GET, POST, PUT, PATCH, DELETE).
	Method string `json:"method"`

	// Path is the OpenAPI-style path with leading slash, e.g.
	// "/application.deploy". Dokploy uses dotted operation paths rather than
	// REST-style resources; the registry preserves them verbatim.
	Path string `json:"path"`

	// Tag is the single OpenAPI tag attached to this operation, or the
	// empty string for the one untagged endpoint. The OpenAPI spec
	// technically allows multiple tags per operation; Dokploy never uses
	// more than one and the registry locks that invariant.
	Tag string `json:"tag"`

	// Summary and Description mirror the OpenAPI fields. Both can be empty.
	Summary     string `json:"summary,omitempty"`
	Description string `json:"description,omitempty"`

	// Parameters is the list of path/query/header/cookie parameters. The
	// slice is never nil (`[]Parameter{}` for parameter-less operations) so
	// downstream JSON marshalling stays deterministic.
	Parameters []Parameter `json:"parameters"`

	// RequestBody is non-nil iff the operation accepts a request body.
	RequestBody *RequestBody `json:"request_body,omitempty"`

	// Responses is keyed by HTTP status code (e.g. "200", "default") in
	// canonical OpenAPI order. The map is preserved as a slice so the JSON
	// output is deterministic regardless of Go's map iteration order.
	Responses []Response `json:"responses"`

	// Security mirrors the operation's security requirement. The slice is
	// non-empty for every authenticated Dokploy operation; an empty slice
	// signals an unauthenticated endpoint.
	Security []SecurityRequirement `json:"security,omitempty"`

	// RequiresAuth is the convenience boolean for `requires len(Security) > 0`.
	// Agents can branch on it without inspecting the raw security blocks.
	RequiresAuth bool `json:"requires_auth"`
}

// Parameter is a single OpenAPI parameter description. Schema is preserved
// as raw JSON so the full OpenAPI/JSON Schema surface (oneOf, allOf,
// references, $defs, examples) survives the round trip without lossy
// re-modelling.
type Parameter struct {
	Name        string          `json:"name"`
	In          string          `json:"in"`
	Required    bool            `json:"required"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// RequestBody is the typed request body description for an operation.
// ContentType is the canonical media type ("application/json" today; the
// Dokploy spec does not currently use multipart). Schema preserves the
// OpenAPI schema verbatim.
type RequestBody struct {
	Required    bool            `json:"required"`
	ContentType string          `json:"content_type"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Description string          `json:"description,omitempty"`
}

// Response is a single OpenAPI response by status code. The status is kept
// as a string because OpenAPI permits "default" alongside numeric codes.
// ContentType is empty when the response has no body (e.g. some 204 paths,
// or error envelopes that the spec leaves abstract).
type Response struct {
	Status      string          `json:"status"`
	Description string          `json:"description,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// SecurityRequirement mirrors a single entry in an operation's security
// array. The map keys reference securitySchemes by name; the value is the
// OAuth scope list (always empty for API key auth, kept for fidelity).
type SecurityRequirement map[string][]string

// SecurityScheme is a yalla-flavoured projection of a single OpenAPI
// security scheme declared in `components.securitySchemes`. The fields
// cover the two scheme types Dokploy declares today (apiKey-in-header and
// HTTP bearer); other types parse with empty auxiliary fields and a
// faithful Type so future spec drops do not silently regress.
//
// JSON tags use snake_case so the same shape can be emitted in
// `yalla manifest --json` without a separate DTO.
type SecurityScheme struct {
	// Name is the key used in `components.securitySchemes`
	// (e.g. "apiKey" for the Dokploy spec).
	Name string `json:"name"`

	// Type is the OpenAPI scheme type ("apiKey", "http", "oauth2", ...).
	Type string `json:"type"`

	// In is the apiKey location ("header", "query", "cookie") or empty
	// for non-apiKey types.
	In string `json:"in,omitempty"`

	// HeaderName is the apiKey header / query parameter / cookie name
	// (e.g. "x-api-key"). Empty for non-apiKey types.
	HeaderName string `json:"header_name,omitempty"`

	// Scheme is the HTTP auth scheme ("bearer", "basic") or empty for
	// non-HTTP types.
	Scheme string `json:"scheme,omitempty"`
}

// Registry is the parsed, indexed view of the OpenAPI document. Construct
// it once via Load() (or Default() for the embedded copy) and pass the
// pointer wherever it is needed; the type is immutable after construction
// and safe for concurrent reads.
type Registry struct {
	// Title and Version mirror the OpenAPI `info` block.
	Title   string
	Version string

	// SHA256 is the hex digest of the source document. For Default() this
	// matches EmbeddedSpecSHA256; for Load() it matches the input bytes.
	SHA256 string

	// ServerPath is the path component of the first declared OpenAPI
	// server URL (e.g. "/api" for Dokploy). Empty when the spec declares
	// no server or the server URL has no path. Callers prepend this to a
	// host-only base URL (the typical YALLA_BASE_URL of `https://host`)
	// so the request still hits the API router instead of the upstream
	// SPA. An explicit user-supplied path takes precedence to keep
	// reverse-proxied installs (e.g. `https://example.com/dokploy/api`)
	// working without a flag.
	ServerPath string

	// ops is the canonical operation list, sorted by OperationID for
	// deterministic JSON output.
	ops []Operation

	// byID indexes ops for O(1) Get(operationId) lookup.
	byID map[string]int

	// securitySchemes maps scheme name → parsed scheme. Indexed once at
	// load time so PrimarySecurityScheme is a cheap map lookup.
	securitySchemes map[string]SecurityScheme

	// primarySchemeName is the scheme name from the first global security
	// requirement (`security[0]`), or empty when the spec declares no
	// global security. Per-operation security overrides are intentionally
	// NOT used here: the Dokploy spec's per-op `security` blocks
	// reference an undeclared "Authorization" scheme that the live server
	// rejects, so the document-level `apiKey` requirement is the only
	// one we trust to drive the wire transport.
	primarySchemeName string
}

// Load parses an OpenAPI 3.1 document into a Registry. The bytes must be
// JSON; YAML is rejected upstream by go:embed. Errors are wrapped with
// enough context to identify the offending operation when the spec is
// malformed.
//
// Load fails on:
//   - invalid JSON,
//   - missing or duplicate operationId,
//   - more than one tag on a single operation,
//   - an unsupported request body media type (anything other than
//     application/json today; future media types should land alongside
//     executor support, not silently here).
func Load(spec []byte) (*Registry, error) {
	var doc rawDoc
	dec := json.NewDecoder(strings.NewReader(string(spec)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("api: decode openapi: %w", err)
	}

	ops := make([]Operation, 0, len(doc.Paths)*2)
	seen := make(map[string]string, len(doc.Paths))

	// Iterate paths in sorted order so any spec-level reorder still
	// produces the same registry slice. Operation iteration within a path
	// uses the canonicalMethods order below.
	pathKeys := make([]string, 0, len(doc.Paths))
	for k := range doc.Paths {
		pathKeys = append(pathKeys, k)
	}
	sort.Strings(pathKeys)

	for _, path := range pathKeys {
		item := doc.Paths[path]
		for _, method := range canonicalMethods {
			raw, ok := item[method]
			if !ok {
				continue
			}
			var op rawOperation
			if err := json.Unmarshal(raw, &op); err != nil {
				return nil, fmt.Errorf("api: decode %s %s: %w", strings.ToUpper(method), path, err)
			}
			if op.OperationID == "" {
				return nil, fmt.Errorf("api: %s %s missing operationId", strings.ToUpper(method), path)
			}
			if prev, dup := seen[op.OperationID]; dup {
				return nil, fmt.Errorf("api: duplicate operationId %q (first seen at %s, again at %s %s)", op.OperationID, prev, strings.ToUpper(method), path)
			}
			seen[op.OperationID] = strings.ToUpper(method) + " " + path

			tag := ""
			switch len(op.Tags) {
			case 0:
				tag = ""
			case 1:
				tag = op.Tags[0]
			default:
				return nil, fmt.Errorf("api: %s %s has %d tags; yalla expects at most one", strings.ToUpper(method), path, len(op.Tags))
			}

			built, err := buildOperation(op, strings.ToUpper(method), path, tag)
			if err != nil {
				return nil, fmt.Errorf("api: build %s: %w", op.OperationID, err)
			}
			ops = append(ops, built)
		}
	}

	sort.Slice(ops, func(i, j int) bool { return ops[i].OperationID < ops[j].OperationID })

	idx := make(map[string]int, len(ops))
	for i, op := range ops {
		idx[op.OperationID] = i
	}

	sum := sha256.Sum256(spec)

	// Server path: the first declared server URL contributes only its
	// path component (e.g. "/api"). The host/scheme is supplied by the
	// user via YALLA_BASE_URL — the spec's placeholder host is meaningless
	// for a real install. A "/" path is normalised to "" so callers can
	// treat empty as "no prefix needed".
	serverPath := ""
	if len(doc.Servers) > 0 {
		if p, perr := serverPathOf(doc.Servers[0].URL); perr == nil {
			serverPath = p
		}
	}

	// Security schemes: project every declared scheme into the public
	// SecurityScheme shape. Unknown types still land in the map so the
	// manifest emitter sees them; only the recognised types (apiKey,
	// http) are actionable by the client.
	schemes := make(map[string]SecurityScheme, len(doc.Components.SecuritySchemes))
	for name, raw := range doc.Components.SecuritySchemes {
		schemes[name] = SecurityScheme{
			Name:       name,
			Type:       raw.Type,
			In:         raw.In,
			HeaderName: raw.Name,
			Scheme:     raw.Scheme,
		}
	}

	// Primary scheme: the first key of the first global security
	// requirement. OpenAPI permits multiple alternative requirements;
	// yalla treats only the first as canonical because no Dokploy
	// install has ever needed more than one.
	primary := ""
	for _, req := range doc.Security {
		for k := range req {
			primary = k
			break
		}
		if primary != "" {
			break
		}
	}

	return &Registry{
		Title:             doc.Info.Title,
		Version:           doc.Info.Version,
		SHA256:            hex.EncodeToString(sum[:]),
		ServerPath:        serverPath,
		ops:               ops,
		byID:              idx,
		securitySchemes:   schemes,
		primarySchemeName: primary,
	}, nil
}

// serverPathOf returns the path component of an OpenAPI server URL.
// "/" is normalised to "" so callers can treat the result as
// "no prefix needed" with a simple zero-value check. A trailing slash is
// stripped for the same reason — joining `"/api"` with `"/foo"` gives
// `"/api/foo"` directly, no double-slash. The function tolerates a
// scheme-less or relative server URL: only the parsed Path matters.
func serverPathOf(serverURL string) (string, error) {
	s := strings.TrimSpace(serverURL)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	p := u.Path
	if p == "" || p == "/" {
		return "", nil
	}
	return strings.TrimSuffix(p, "/"), nil
}

// Default returns the lazily-constructed registry built from EmbeddedSpec.
// The first call parses the document; subsequent calls return the cached
// pointer. A parse failure here is a programmer error (the embedded spec
// must always parse) and panics so misuse surfaces during binary boot.
func Default() *Registry {
	defaultOnce.Do(func() {
		r, err := Load(EmbeddedSpec)
		if err != nil {
			panic(fmt.Sprintf("api: embedded openapi failed to parse: %v", err))
		}
		defaultRegistry = r
	})
	return defaultRegistry
}

var (
	defaultOnce     sync.Once
	defaultRegistry *Registry
)

// Operations returns the registry's operations in deterministic
// (operationId-sorted) order. The returned slice is a fresh copy; callers
// may mutate it without affecting the registry.
func (r *Registry) Operations() []Operation {
	out := make([]Operation, len(r.ops))
	copy(out, r.ops)
	return out
}

// Len reports the operation count. Equivalent to len(Operations()) but
// allocation-free, which keeps test diagnostics readable.
func (r *Registry) Len() int { return len(r.ops) }

// Get returns the operation with the supplied operationId together with a
// found flag. The returned Operation is a value copy — mutations on the
// caller side do not bleed back into the registry.
func (r *Registry) Get(operationID string) (Operation, bool) {
	idx, ok := r.byID[operationID]
	if !ok {
		return Operation{}, false
	}
	return r.ops[idx], true
}

// IDs returns the operationIds in deterministic order. Convenient for
// stable test diffs and `yalla api operations --json --ids-only` (US-0007).
func (r *Registry) IDs() []string {
	out := make([]string, len(r.ops))
	for i, op := range r.ops {
		out[i] = op.OperationID
	}
	return out
}

// PrimarySecurityScheme returns the resolved scheme referenced by the
// document-level `security[0]`. The boolean is false when the spec
// declares no global security or when the referenced scheme is missing
// from `components.securitySchemes` (which the Dokploy spec does for the
// stale per-operation "Authorization" references).
//
// Callers (most importantly the HTTP client builder in `internal/cli`)
// branch on the returned scheme to decide which header carries the
// token. A `false` return means "fall back to the legacy Bearer
// transport"; the registry never mutates client behaviour silently.
func (r *Registry) PrimarySecurityScheme() (SecurityScheme, bool) {
	if r == nil || r.primarySchemeName == "" {
		return SecurityScheme{}, false
	}
	s, ok := r.securitySchemes[r.primarySchemeName]
	return s, ok
}

// SecuritySchemes returns a fresh copy of every parsed security scheme
// keyed by name. The copy isolates callers from registry internals so a
// future manifest emitter can mutate its working set without bleeding
// back into the singleton Registry. Order is map-iteration order;
// callers that need a stable list should sort the keys themselves.
func (r *Registry) SecuritySchemes() map[string]SecurityScheme {
	if r == nil || len(r.securitySchemes) == 0 {
		return map[string]SecurityScheme{}
	}
	out := make(map[string]SecurityScheme, len(r.securitySchemes))
	for k, v := range r.securitySchemes {
		out[k] = v
	}
	return out
}

// Tags returns the unique tag set in alphabetical order. The empty-tag
// untagged operation is reported as "" so callers can decide whether to
// surface or filter it.
func (r *Registry) Tags() []string {
	seen := make(map[string]struct{}, 64)
	for _, op := range r.ops {
		seen[op.Tag] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// canonicalMethods is the iteration order yalla uses when projecting an
// OpenAPI path item into operations. The order matches the OpenAPI spec's
// own field order so the registry's secondary sort (by operationId) is the
// only ordering that affects callers.
var canonicalMethods = []string{
	"get", "put", "post", "delete", "options", "head", "patch", "trace",
}

// rawDoc is the minimal subset of the OpenAPI document the registry parses
// directly. Component schemas (the `components.schemas` namespace, $defs,
// etc.) are still preserved as raw JSON via the per-operation Schema
// fields; only fields the runtime client actually branches on get an
// explicit struct here.
type rawDoc struct {
	Info struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Servers    []rawServer           `json:"servers"`
	Security   []SecurityRequirement `json:"security"`
	Components struct {
		SecuritySchemes map[string]rawSecurityScheme `json:"securitySchemes"`
	} `json:"components"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// rawServer mirrors a single OpenAPI `servers[]` entry. Only the URL is
// material to the runtime; description and `variables` are intentionally
// dropped because yalla never substitutes server variables — the user's
// YALLA_BASE_URL is the substitution.
type rawServer struct {
	URL string `json:"url"`
}

// rawSecurityScheme mirrors a single OpenAPI `components.securitySchemes`
// entry. The four fields cover the only types Dokploy declares; the
// projection layer copies them verbatim into [SecurityScheme] so an
// unsupported type still appears in the registry without surprising the
// client (which only acts on the recognised combinations).
type rawSecurityScheme struct {
	Type   string `json:"type"`
	In     string `json:"in"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
}

// rawOperation captures the OpenAPI operation fields the registry projects.
// We hold raw JSON for the schema-bearing pieces (parameter schemas, body
// schemas, response schemas) so the public Operation type can preserve the
// full OpenAPI/JSON Schema surface without lossy re-modelling.
type rawOperation struct {
	OperationID string                `json:"operationId"`
	Tags        []string              `json:"tags"`
	Summary     string                `json:"summary"`
	Description string                `json:"description"`
	Parameters  []rawParameter        `json:"parameters"`
	RequestBody *rawRequestBody       `json:"requestBody"`
	Responses   map[string]rawResp    `json:"responses"`
	Security    []SecurityRequirement `json:"security"`
}

type rawParameter struct {
	Name        string          `json:"name"`
	In          string          `json:"in"`
	Required    bool            `json:"required"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
}

type rawRequestBody struct {
	Required    bool                  `json:"required"`
	Description string                `json:"description"`
	Content     map[string]rawContent `json:"content"`
}

type rawResp struct {
	Description string                `json:"description"`
	Content     map[string]rawContent `json:"content"`
}

type rawContent struct {
	Schema json.RawMessage `json:"schema"`
}

// buildOperation projects a rawOperation into the public Operation type.
// All slices are normalised to non-nil so JSON output is deterministic.
func buildOperation(op rawOperation, method, path, tag string) (Operation, error) {
	out := Operation{
		OperationID:  op.OperationID,
		Method:       method,
		Path:         path,
		Tag:          tag,
		Summary:      op.Summary,
		Description:  op.Description,
		Parameters:   make([]Parameter, 0, len(op.Parameters)),
		Responses:    make([]Response, 0, len(op.Responses)),
		Security:     op.Security,
		RequiresAuth: len(op.Security) > 0,
	}

	for _, p := range op.Parameters {
		out.Parameters = append(out.Parameters, Parameter{
			Name:        p.Name,
			In:          p.In,
			Required:    p.Required,
			Description: p.Description,
			Schema:      p.Schema,
		})
	}

	if op.RequestBody != nil {
		ct, body, ok := pickJSONContent(op.RequestBody.Content)
		if !ok && len(op.RequestBody.Content) > 0 {
			// Fall back to the first declared content type. The executor
			// will reject it if it cannot serialise; we do not silently
			// drop the body.
			for k, v := range op.RequestBody.Content {
				ct, body = k, v.Schema
				break
			}
		}
		out.RequestBody = &RequestBody{
			Required:    op.RequestBody.Required,
			ContentType: ct,
			Schema:      body,
			Description: op.RequestBody.Description,
		}
	}

	statuses := make([]string, 0, len(op.Responses))
	for s := range op.Responses {
		statuses = append(statuses, s)
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statusLess(statuses[i], statuses[j])
	})
	for _, s := range statuses {
		r := op.Responses[s]
		ct, body, _ := pickJSONContent(r.Content)
		out.Responses = append(out.Responses, Response{
			Status:      s,
			Description: r.Description,
			ContentType: ct,
			Schema:      body,
		})
	}

	return out, nil
}

// pickJSONContent prefers application/json over any other content type
// because that is the only media yalla currently serialises against. The
// `ok` return signals whether application/json was found explicitly.
func pickJSONContent(content map[string]rawContent) (string, json.RawMessage, bool) {
	if content == nil {
		return "", nil, false
	}
	if c, ok := content["application/json"]; ok {
		return "application/json", c.Schema, true
	}
	return "", nil, false
}

// statusLess orders status keys numerically when possible so "200" < "400" <
// "500" in JSON output. Non-numeric keys (such as "default") sort to the end.
func statusLess(a, b string) bool {
	an, aok := atoi(a)
	bn, bok := atoi(b)
	switch {
	case aok && bok:
		return an < bn
	case aok && !bok:
		return true
	case !aok && bok:
		return false
	default:
		return a < b
	}
}

// atoi is a tiny localized integer parser that avoids the strconv import
// solely for keeping the registry's parse hot path allocation-free. The
// caller treats parse failure as "not numeric".
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
