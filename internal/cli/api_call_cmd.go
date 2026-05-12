package cli

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// apiCallInput is the JSON shape consumed by `yalla api call --input`. The
// schema is closed: unknown top-level fields fail the parse with a stable
// CodeInvalidInput so an agent typing `bdoy` instead of `body` learns
// immediately rather than seeing a silently-ignored payload.
//
// `path_params` carries values for OpenAPI `{name}` placeholders in the
// operation path. `query` and `headers` use the canonical
// `map[string][]string` shape so an agent can repeat keys without a
// special grammar (`{"projectId":["a","b"]}`). `body` is opaque JSON
// preserved as `json.RawMessage` so number precision and key order survive
// the round trip into Dokploy.
//
// `files` is populated only for operations whose request body is declared
// as `multipart/form-data` in the OpenAPI spec (today: the single
// `application-dropDeployment` endpoint). Each map entry is keyed by the
// multipart form field name and carries a local file path, optionally
// with a per-part filename / content_type override. For ergonomics each
// value may be supplied as a bare path string (`"zip": "/path/to/x.zip"`)
// or as a verbose object (`"zip": {"path": "...", "filename": "..."}`).
type apiCallInput struct {
	PathParams map[string]string      `json:"path_params,omitempty"`
	Query      map[string][]string    `json:"query,omitempty"`
	Headers    map[string][]string    `json:"headers,omitempty"`
	Body       json.RawMessage        `json:"body,omitempty"`
	Files      map[string]apiCallFile `json:"files,omitempty"`
}

// apiCallFile describes a single multipart file part. Path is the only
// required field. Filename and ContentType override the per-part defaults
// (Filename defaults to filepath.Base(Path); ContentType defaults to
// application/octet-stream so binaries do not get mislabelled as text).
type apiCallFile struct {
	Path        string `json:"path,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// UnmarshalJSON accepts both the shorthand (`"zip": "/abs/path"`) and the
// verbose (`"zip": {"path": "...", "filename": "..."}`) shapes. Unknown
// fields in the verbose form are rejected for the same reason
// [apiCallInput] rejects unknown top-level fields: a typo never silently
// drops a value on the floor.
func (f *apiCallFile) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		f.Path = s
		return nil
	}
	type alias apiCallFile
	var a alias
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*f = apiCallFile(a)
	return nil
}

// apiCallSuccessDoc is the JSON envelope payload emitted on a successful
// API call (success defined as Result.Success() == true). The Dokploy
// response body is embedded verbatim as JSON when the upstream
// Content-Type is JSON-shaped so downstream agents can read fields without
// a second decode pass; otherwise the raw text is preserved in body_text.
type apiCallSuccessDoc struct {
	OperationID string          `json:"operation_id"`
	Method      string          `json:"method"`
	URL         string          `json:"url"`
	Status      int             `json:"status"`
	StatusText  string          `json:"status_text"`
	DurationMs  int64           `json:"duration_ms"`
	Attempts    int             `json:"attempts"`
	RequestID   string          `json:"request_id,omitempty"`
	TraceID     string          `json:"trace_id,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Body        json.RawMessage `json:"body,omitempty"`
	BodyText    string          `json:"body_text,omitempty"`
}

// apiCallDryRunDoc is emitted by `--dry-run`. It mirrors what the executor
// would have sent: the resolved URL, method, redacted headers (Bearer
// substituted with [REDACTED]), and the body. Agents can validate URL +
// body construction in a CI gate without ever hitting Dokploy.
//
// Body carries JSON request bodies verbatim so number precision and key
// order survive the round trip. BodyText carries the raw string when the
// body is not valid JSON — today that is the multipart/form-data envelope
// emitted for `application-dropDeployment`, where the body is a
// deterministic ASCII envelope with file content replaced by a redaction
// sentinel.
type apiCallDryRunDoc struct {
	OperationID string              `json:"operation_id"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	ContentType string              `json:"content_type,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Body        json.RawMessage     `json:"body,omitempty"`
	BodyText    string              `json:"body_text,omitempty"`
	DryRun      bool                `json:"dry_run"`
}

// apiCallClientArgs is the input to apiCallClientFactory. Tests override
// the factory to inject a custom http.RoundTripper or a tighter timeout
// (for the network-timeout test) without going through env vars.
type apiCallClientArgs struct {
	Config  *config.Config
	Build   BuildInfo
	Timeout time.Duration
}

// apiCallClientFactory builds the HTTP client used by `yalla api call`.
// The default delegates to api.NewClient with the resolved config; tests
// override the variable to inject a stub RoundTripper or a per-attempt
// timeout that fires faster than the default 30s.
//
// Retries default to zero because Dokploy's POST surface is mutating: an
// agent that wants idempotent retries can opt in via a future flag, but
// the safe default is exactly one attempt per call.
//
// Auth scheme + base-path prefix are resolved from the embedded OpenAPI
// document via [resolveAPIClientDefaults] so the wire transport tracks
// the spec automatically: a future Dokploy spec drop that switches auth
// types or relocates the API mount point applies without a code change
// at this call site.
var apiCallClientFactory = func(args apiCallClientArgs) (*api.Client, error) {
	scheme, headerName, basePath := resolveAPIClientDefaults(api.Default())
	cc := api.ClientConfig{
		BaseURL:        args.Config.BaseURL,
		Token:          args.Config.Token,
		AuthScheme:     scheme,
		AuthHeaderName: headerName,
		BasePathPrefix: basePath,
		UserAgent:      "yalla/" + args.Build.Version,
		Timeout:        args.Timeout,
		MaxRetries:     0,
	}
	return api.NewClient(cc)
}

// resolveAPIClientDefaults projects the registry's primary security
// scheme and server path into the [api.ClientConfig] values that drive
// the HTTP transport. The function returns zero values when the spec
// declares no global security or no server path, so the client falls
// back to its legacy Bearer + bare-BaseURL behaviour.
//
// Recognised scheme combinations:
//   - apiKey + in:header   → AuthSchemeAPIKeyHeader, header from spec.
//   - http  + scheme:bearer → AuthSchemeBearer.
//
// Anything else returns the unspecified scheme so the client uses its
// Bearer fallback rather than producing a malformed request.
func resolveAPIClientDefaults(reg *api.Registry) (api.AuthScheme, string, string) {
	basePath := ""
	if reg != nil {
		basePath = reg.ServerPath
	}
	if reg == nil {
		return api.AuthSchemeUnspecified, "", basePath
	}
	scheme, ok := reg.PrimarySecurityScheme()
	if !ok {
		return api.AuthSchemeUnspecified, "", basePath
	}
	switch {
	case scheme.Type == "apiKey" && strings.EqualFold(scheme.In, "header"):
		return api.AuthSchemeAPIKeyHeader, scheme.HeaderName, basePath
	case scheme.Type == "http" && strings.EqualFold(scheme.Scheme, "bearer"):
		return api.AuthSchemeBearer, "", basePath
	default:
		return api.AuthSchemeUnspecified, "", basePath
	}
}

func newAPICallCommand() *cobra.Command {
	var (
		inputPath string
		dryRun    bool
		timeout   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "call <operationId>",
		Short: "Invoke any Dokploy API operation through its operationId",
		Long: `Invoke a Dokploy API operation by its operationId.

This is the universal escape hatch: every Dokploy operation registered in
` + "`yalla api operations`" + ` can be called here, even when no curated
yalla command exists for it. Provide path/query/header/body inputs through
a JSON document supplied via ` + "`--input`" + ` (or ` + "`-`" + ` for
stdin).

The input shape is:

  {
    "path_params": {"id": "abc"},
    "query":       {"page": ["1"]},
    "headers":     {"X-Custom": ["value"]},
    "body":        {"projectId": "abc"},
    "files":       {"zip": "/abs/path/to/dist.zip"}
  }

Unknown top-level keys are rejected so a typo never silently corrupts the
request. Use ` + "`yalla schema get <operationId>`" + ` to discover the
expected body schema for any specific operation.

` + "`files`" + ` is only valid for operations whose request body is
declared as ` + "`multipart/form-data`" + ` in the OpenAPI spec (today:
` + "`application-dropDeployment`" + `). Each entry is keyed by the
multipart form field name; the value is either a bare path string or
an object ` + "`{\"path\":..., \"filename\":..., \"content_type\":...}`" + `
when you need to override the per-part filename or Content-Type.

In ` + "`--dry-run`" + ` mode the resolved request is printed without
sending it. Authorization headers are replaced with ` + "`[REDACTED]`" + `
so the dry-run envelope is safe to log or paste. Multipart dry-runs use
a deterministic boundary and substitute a redaction sentinel for file
content so the rendered envelope never carries a binary payload.`,
		Example: `  yalla api call project-all --json
  yalla api call application-deploy --input request.json --json
  echo '{"body":{"applicationId":"abc"}}' | yalla api call application-deploy --input - --json
  yalla api call application-deploy --input request.json --dry-run --json
  yalla api call application-dropDeployment --input drop.json --json   # drop.json carries "files":{"zip":"/abs/path/to/dist.zip"}`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := config.FromContext(ctx)
			streams := IOStreamsFromContext(ctx)
			r := rendererFromContext(c, streams)

			input, err := loadAPICallInput(streams, inputPath)
			if err != nil {
				return err
			}
			return runAPICall(ctx, r, api.Default(), cfg, args[0], input, apiCallOptions{
				DryRun:  dryRun,
				Timeout: timeout,
				Build:   BuildInfoFromContext(ctx),
			})
		},
	}
	cmd.Flags().StringVar(&inputPath, "input", "", "path to a JSON input file (use - for stdin)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the resolved request without sending it")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "override the per-attempt HTTP timeout (e.g. 5s, 30s); 0 keeps the default")
	return cmd
}

// apiCallOptions bundles the per-invocation knobs separately from the
// per-call inputs so unit tests can drive runAPICall without parsing flags.
type apiCallOptions struct {
	DryRun  bool
	Timeout time.Duration
	Build   BuildInfo
}

// loadAPICallInput reads and decodes the --input JSON. An empty path means
// "no input"; "-" means stdin. Unknown top-level fields are rejected so a
// typo surfaces as CodeInvalidInput instead of being silently dropped.
//
// `--no-input` does not affect this function: the function only reads from
// stdin when the user explicitly asked for it via "-". The contract is
// "yalla never prompts in --no-input mode"; reading explicit stdin is not
// a prompt, it is the requested data source.
func loadAPICallInput(streams IOStreams, path string) (apiCallInput, error) {
	var in apiCallInput
	if path == "" {
		return in, nil
	}
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(streams.In)
		if err != nil {
			return in, yerr.Newf(yerr.CodeInvalidInput, "read --input from stdin: %v", err)
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return in, yerr.Newf(yerr.CodeInvalidInput, "read --input file %q: %v", path, err)
		}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return in, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, yerr.Newf(yerr.CodeInvalidInput, "parse --input JSON: %v", err)
	}
	return in, nil
}

// runAPICall is the testable seam shared by RunE and the unit tests. It
// resolves the operation, validates path params, optionally short-circuits
// via --dry-run, otherwise builds an HTTP client and emits a typed
// envelope on stdout. All failure paths return a *yerr.Error so the
// terminal renderer maps them to a stable exit code.
func runAPICall(ctx context.Context, r *output.Renderer, reg *api.Registry, cfg *config.Config, opID string, in apiCallInput, opts apiCallOptions) error {
	op, ok := reg.Get(opID)
	if !ok {
		return yerr.Newf(yerr.CodeNotFound, "unknown operation %q", opID).
			WithHint("run `yalla api operations --json` to see every supported operationId")
	}

	resolvedPath, err := substitutePathParams(op.Path, in.PathParams)
	if err != nil {
		return err
	}

	query := url.Values{}
	for k, vs := range in.Query {
		for _, v := range vs {
			query.Add(k, v)
		}
	}

	headers := http.Header{}
	for k, vs := range in.Headers {
		for _, v := range vs {
			headers.Add(k, v)
		}
	}

	body, contentType, err := buildAPICallRequestBody(op, in.Body, in.Files, opts.DryRun)
	if err != nil {
		return err
	}

	if !opts.DryRun {
		if cfg.BaseURL == "" {
			return yerr.New(yerr.CodeConfig, "no Dokploy base URL configured").
				WithHint("run `yalla auth login`, set YALLA_BASE_URL, or pass --base-url")
		}
		if op.RequiresAuth && cfg.Token == "" {
			return yerr.Newf(yerr.CodeAuth, "operation %q requires authentication; no Dokploy API token configured", op.OperationID).
				WithHint("run `yalla auth login`, set YALLA_TOKEN, or pass --token")
		}
	}

	scheme, headerName, basePath := resolveAPIClientDefaults(reg)
	effectiveBase := applyServerPath(cfg.BaseURL, basePath)
	targetURL := joinAPIURL(effectiveBase, resolvedPath, query)

	if opts.DryRun {
		return emitAPICallDryRun(r, op, targetURL, headers, body, contentType, cfg, scheme, headerName)
	}

	cli, err := apiCallClientFactory(apiCallClientArgs{
		Config:  cfg,
		Build:   opts.Build,
		Timeout: opts.Timeout,
	})
	if err != nil {
		return errAsTyped(err, yerr.CodeConfig)
	}

	req := &api.Request{
		Method:      op.Method,
		Path:        resolvedPath,
		Query:       query,
		Headers:     headers,
		Body:        body,
		ContentType: contentType,
		Idempotent:  isIdempotentMethod(op.Method),
	}

	result, err := cli.Do(ctx, req)
	if err != nil {
		return errAsTyped(err, yerr.CodeNetwork)
	}
	if !result.Success() {
		return result.AsError()
	}
	return emitAPICallSuccess(r, op, targetURL, result)
}

// pathParamRE matches OpenAPI-style `{name}` placeholders. Dokploy does
// not currently use path params, but the executor honours them so a future
// spec drop with `/foo/{id}` works without a code change.
var pathParamRE = regexp.MustCompile(`\{([^}]+)\}`)

// substitutePathParams replaces every "{name}" placeholder in path with
// the percent-encoded value from params. Missing placeholders accumulate
// into a single CodeInvalidInput error so an agent learns about every
// missing key in one round trip.
func substitutePathParams(path string, params map[string]string) (string, error) {
	var missing []string
	out := pathParamRE.ReplaceAllStringFunc(path, func(m string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(m, "{"), "}")
		if v, ok := params[name]; ok {
			return url.PathEscape(v)
		}
		missing = append(missing, name)
		return m
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", yerr.Newf(yerr.CodeInvalidInput, "missing path param(s): %s", strings.Join(missing, ", ")).
			WithHintf(`provide them under "path_params" in --input (e.g. {"path_params":{"%s":"..."}})`, missing[0])
	}
	return out, nil
}

// buildAPICallRequestBody is the single dispatch point that picks the
// right wire encoding for an operation's request body:
//
//   - multipart/form-data → real multipart envelope built via
//     [api.BuildMultipart]. Scalar fields come from `--input "body"` (a
//     JSON object); file paths come from `--input "files"`. Live wire
//     uses a random boundary; --dry-run uses
//     [api.DefaultDryRunMultipartBoundary] and substitutes a redaction
//     sentinel for file bytes so the rendered envelope is safe to log.
//   - anything else → the bytes from `--input "body"` are forwarded
//     verbatim with the registry-declared content type (defaulting to
//     application/json), preserving the byte-for-byte forwarding
//     contract every existing operation depends on.
//
// Operations that do not declare multipart/form-data must not carry a
// `files` field — surfacing the mismatch as CodeInvalidInput is much more
// useful than silently dropping the files on the floor.
func buildAPICallRequestBody(op api.Operation, rawBody json.RawMessage, files map[string]apiCallFile, dryRun bool) ([]byte, string, error) {
	isMultipart := op.RequestBody != nil && api.IsMultipartFormData(op.RequestBody.ContentType)

	if !isMultipart {
		if len(files) > 0 {
			return nil, "", yerr.Newf(yerr.CodeInvalidInput,
				"operation %q does not accept file uploads (request body is %s)",
				op.OperationID, declaredContentType(op)).
				WithHint(`remove "files" from --input; run "yalla schema get <operationId>" to see the declared content type`)
		}
		return resolveJSONRequestBody(op, rawBody)
	}

	return buildMultipartRequestBody(op, rawBody, files, dryRun)
}

// declaredContentType returns the registry-declared request body content
// type, or "(none)" when the operation has no request body. Surfaces in
// CodeInvalidInput hints so the agent immediately sees why a `files`
// payload was rejected.
func declaredContentType(op api.Operation) string {
	if op.RequestBody == nil {
		return "(none)"
	}
	if op.RequestBody.ContentType == "" {
		return api.ContentTypeJSON
	}
	return op.RequestBody.ContentType
}

// resolveJSONRequestBody is the JSON-body codepath every non-multipart
// operation has used since US-0005. A nil body for a required-body
// operation surfaces as CodeInvalidInput so the spec contract is enforced
// before the wire call.
func resolveJSONRequestBody(op api.Operation, body json.RawMessage) ([]byte, string, error) {
	if len(body) == 0 {
		if op.RequestBody != nil && op.RequestBody.Required {
			return nil, "", yerr.Newf(yerr.CodeInvalidInput, "operation %q requires a request body", op.OperationID).
				WithHint(`supply it as "body" in the --input JSON; run "yalla schema get <operationId>" for the expected shape`)
		}
		return nil, "", nil
	}
	ct := api.ContentTypeJSON
	if op.RequestBody != nil && op.RequestBody.ContentType != "" {
		ct = op.RequestBody.ContentType
	}
	return []byte(body), ct, nil
}

// buildMultipartRequestBody encodes a multipart/form-data envelope for
// the operation. Scalar form fields are read from rawBody (a JSON object
// keyed by field name); file parts are read from files. Both maps may be
// empty for an operation that declares the body as optional, but
// `requestBody.required: true` ops (today the only multipart op,
// `application-dropDeployment`) get the same CodeInvalidInput as the
// JSON path when both are absent.
//
// dryRun toggles two safety behaviours: a deterministic boundary so the
// rendered envelope is byte-stable, and a redaction sentinel substituted
// for file bytes so logging the dry-run output never leaks a binary
// payload.
func buildMultipartRequestBody(op api.Operation, rawBody json.RawMessage, files map[string]apiCallFile, dryRun bool) ([]byte, string, error) {
	var scalars map[string]json.RawMessage
	if len(rawBody) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawBody))
		dec.UseNumber()
		if err := dec.Decode(&scalars); err != nil {
			return nil, "", yerr.Newf(yerr.CodeInvalidInput,
				"operation %q expects a JSON object in \"body\" for multipart form fields: %v",
				op.OperationID, err).
				WithHint(`use {"body":{"fieldName":"value", ...},"files":{"fileField":"/path/to/file"}}`)
		}
	}

	fieldNames := make([]string, 0, len(scalars))
	for k := range scalars {
		fieldNames = append(fieldNames, k)
	}
	sort.Strings(fieldNames)
	mFields := make([]api.MultipartField, 0, len(scalars))
	for _, k := range fieldNames {
		mFields = append(mFields, api.MultipartField{
			Name:  k,
			Value: jsonRawToFormValue(scalars[k]),
		})
	}

	fileFieldNames := make([]string, 0, len(files))
	for k := range files {
		fileFieldNames = append(fileFieldNames, k)
	}
	sort.Strings(fileFieldNames)
	mFiles := make([]api.MultipartFile, 0, len(files))
	for _, name := range fileFieldNames {
		spec := files[name]
		path := strings.TrimSpace(spec.Path)
		if path == "" {
			return nil, "", yerr.Newf(yerr.CodeInvalidInput,
				"operation %q: file field %q has no \"path\"", op.OperationID, name).
				WithHint(`use {"files":{"<field>":"/abs/path"}} or {"files":{"<field>":{"path":"/abs/path"}}}`)
		}
		filename := spec.Filename
		if filename == "" {
			filename = filepath.Base(path)
		}

		var content []byte
		if dryRun {
			info, err := os.Stat(path)
			if err != nil {
				return nil, "", yerr.Newf(yerr.CodeInvalidInput,
					"stat file %q for field %q: %v", path, name, err).
					WithHint("dry-run validates that referenced files exist before emitting the envelope")
			}
			content = []byte(formatDryRunFilePlaceholder(filename, info.Size()))
		} else {
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, "", yerr.Newf(yerr.CodeInvalidInput,
					"read file %q for field %q: %v", path, name, err).
					WithHint("path must point to an existing, readable file")
			}
			content = b
		}

		mFiles = append(mFiles, api.MultipartFile{
			FieldName:   name,
			Filename:    filename,
			ContentType: strings.TrimSpace(spec.ContentType),
			Content:     content,
		})
	}

	if op.RequestBody != nil && op.RequestBody.Required && len(mFields) == 0 && len(mFiles) == 0 {
		return nil, "", yerr.Newf(yerr.CodeInvalidInput, "operation %q requires a request body", op.OperationID).
			WithHint(`supply form fields under "body" and/or file paths under "files" in --input`)
	}

	boundary := ""
	if dryRun {
		boundary = api.DefaultDryRunMultipartBoundary
	}

	bodyBytes, ct, err := api.BuildMultipart(mFields, mFiles, boundary)
	if err != nil {
		return nil, "", yerr.Newf(yerr.CodeInvalidInput,
			"encode multipart body for operation %q: %v", op.OperationID, err)
	}
	return bodyBytes, ct, nil
}

// jsonRawToFormValue flattens a JSON value into the string a multipart
// form part carries on the wire. Strings are unquoted; numbers, booleans,
// nulls, and nested objects are serialised verbatim so a complex value
// still round-trips into the upstream server. Dokploy's only multipart
// schema today is all strings, but staying lossless keeps the door open.
func jsonRawToFormValue(v json.RawMessage) string {
	s := strings.TrimSpace(string(v))
	if len(s) == 0 {
		return ""
	}
	if s[0] == '"' {
		var unquoted string
		if err := json.Unmarshal(v, &unquoted); err == nil {
			return unquoted
		}
	}
	return s
}

// formatDryRunFilePlaceholder is the byte sequence substituted for real
// file content in --dry-run multipart envelopes. The placeholder includes
// the file's size and basename so an agent can verify that the right file
// is being uploaded, while the output redactor's [output.Sentinel] marker
// makes the line indistinguishable from a redacted secret to any
// downstream log scrubber.
func formatDryRunFilePlaceholder(filename string, size int64) string {
	return fmt.Sprintf("%s file=%q size=%d", output.Sentinel, filename, size)
}

// applyServerPath mirrors the prefix logic in [api.NewClient]: when the
// caller-supplied BaseURL has no path of its own (empty or "/"), the
// spec's server path is prepended so the dry-run URL and the live wire
// URL agree on byte-for-byte composition. An explicit BaseURL path wins
// for the same reason as in NewClient — reverse-proxied installs.
//
// Returns the input verbatim when prefix is empty, when BaseURL is empty
// (dry-run with no --base-url is the documented "show-me-the-path" mode),
// or when BaseURL fails to parse (the dry-run renderer surfaces the raw
// string anyway, so a parse error is recoverable).
func applyServerPath(baseURL, prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || baseURL == "" {
		return baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	if u.Path != "" && u.Path != "/" {
		return baseURL
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	u.Path = strings.TrimSuffix(prefix, "/")
	return u.String()
}

// joinAPIURL returns the full URL the executor would send the request to.
// Used by --dry-run (which does not own an http.Request) and by the
// success envelope. Mirrors api.Client.resolvePath so the dry-run output
// matches what would actually go on the wire.
func joinAPIURL(baseURL, path string, query url.Values) string {
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if baseURL == "" {
		// Dry-run before --base-url is set: emit the resolved path so the
		// agent can still verify path/query construction.
		if len(query) > 0 {
			return path + "?" + query.Encode()
		}
		return path
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}
	switch {
	case u.Path == "" || u.Path == "/":
		u.Path = path
	default:
		u.Path = strings.TrimSuffix(u.Path, "/") + path
	}
	if len(query) > 0 {
		merged := u.Query()
		for k, vs := range query {
			for _, v := range vs {
				merged.Add(k, v)
			}
		}
		u.RawQuery = merged.Encode()
	}
	return u.String()
}

// isIdempotentMethod reports whether retries are safe for a given HTTP
// verb. Conservative: only GET and HEAD are eligible. Dokploy's POST
// surface includes mutating operations (deploy, restart, delete) that
// must never double-fire from a transparent retry.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

// emitAPICallSuccess renders the success envelope. The Dokploy response
// body is embedded verbatim when it is JSON (so downstream agents can
// query fields without a second parse) or surfaced as plain text otherwise.
func emitAPICallSuccess(r *output.Renderer, op api.Operation, targetURL string, result *api.Result) error {
	doc := apiCallSuccessDoc{
		OperationID: op.OperationID,
		Method:      op.Method,
		URL:         targetURL,
		Status:      result.Status,
		StatusText:  result.StatusText,
		DurationMs:  result.Duration.Milliseconds(),
		Attempts:    result.Attempts,
		RequestID:   result.RequestID,
		TraceID:     result.TraceID,
		ContentType: result.ContentType,
	}
	if len(result.Body) > 0 {
		if isJSONContentType(result.ContentType) && json.Valid(result.Body) {
			doc.Body = append(json.RawMessage(nil), result.Body...)
		} else {
			doc.BodyText = string(result.Body)
		}
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n", op.Method, targetURL)
	fmt.Fprintf(&sb, "%d %s (%dms, %d attempt(s))\n", doc.Status, http.StatusText(doc.Status), doc.DurationMs, doc.Attempts)
	if doc.RequestID != "" {
		fmt.Fprintf(&sb, "request_id: %s\n", doc.RequestID)
	}
	if doc.TraceID != "" {
		fmt.Fprintf(&sb, "trace_id: %s\n", doc.TraceID)
	}
	if len(doc.Body) > 0 {
		sb.WriteString("\n")
		sb.Write(doc.Body)
	} else if doc.BodyText != "" {
		sb.WriteString("\n")
		sb.WriteString(doc.BodyText)
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// emitAPICallDryRun renders the resolved request without sending it. The
// active auth header is rendered with the redaction sentinel in place of
// the secret value so a `--dry-run --json` envelope is safe to log or
// paste. The scheme + header name come from the same resolver the live
// client uses, so the dry-run header matches the wire header byte for
// byte — agents diffing dry-run vs live no longer see a phantom
// "Authorization" entry that the server would never receive.
func emitAPICallDryRun(r *output.Renderer, op api.Operation, targetURL string, headers http.Header, body []byte, contentType string, cfg *config.Config, scheme api.AuthScheme, headerName string) error {
	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	if len(body) > 0 && h.Get(api.HeaderContentType) == "" {
		h.Set(api.HeaderContentType, contentType)
	}
	if cfg.HasToken() {
		authHeader, authValue := dryRunAuthRedaction(scheme, headerName)
		if h.Get(authHeader) == "" {
			h.Set(authHeader, authValue)
		}
	}

	docHeaders := make(map[string][]string, len(h))
	for k, vs := range h {
		docHeaders[k] = append([]string(nil), vs...)
	}

	doc := apiCallDryRunDoc{
		OperationID: op.OperationID,
		Method:      op.Method,
		URL:         targetURL,
		ContentType: contentType,
		Headers:     docHeaders,
		DryRun:      true,
	}
	if len(body) > 0 {
		// JSON bodies stay as json.RawMessage so number precision and key
		// order survive the envelope. Multipart (and any future non-JSON
		// body) goes through BodyText — embedding non-JSON bytes in a
		// json.RawMessage would explode at marshal time. Mirrors the
		// pattern apiCallSuccessDoc uses on the response side.
		if isJSONContentType(contentType) && json.Valid(body) {
			doc.Body = append(json.RawMessage(nil), body...)
		} else {
			doc.BodyText = string(body)
		}
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "DRY RUN\n%s %s\n", op.Method, targetURL)
	if len(h) > 0 {
		sb.WriteString("\nheaders:\n")
		keys := make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&sb, "  %s: %s\n", k, strings.Join(h[k], ", "))
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&sb, "\nbody (%s):\n%s\n", contentType, string(body))
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

// dryRunAuthRedaction returns the (header name, sentinel value) pair the
// dry-run renderer should use for the resolved auth scheme. APIKey
// schemes carry the raw token, so the sentinel replaces the value
// outright; bearer schemes keep the "Bearer " prefix so the rendered
// envelope still reads like a real Authorization header to a human.
func dryRunAuthRedaction(scheme api.AuthScheme, headerName string) (string, string) {
	switch scheme {
	case api.AuthSchemeAPIKeyHeader:
		h := strings.TrimSpace(headerName)
		if h == "" {
			h = api.DefaultAPIKeyHeader
		}
		return h, output.Sentinel
	default:
		return api.HeaderAuthorization, "Bearer " + output.Sentinel
	}
}

// errAsTyped narrows a generic error into a *yerr.Error. Anything
// unrecognised is wrapped under the supplied fallback code so the
// renderer always receives a typed value.
func errAsTyped(err error, fallback yerr.Code) error {
	if err == nil {
		return nil
	}
	var typed *yerr.Error
	if stderrors.As(err, &typed) {
		return typed
	}
	return yerr.Newf(fallback, "%v", err)
}

// isJSONContentType reports whether ct describes a JSON payload. Matches
// "application/json" and any "+json" suffix (e.g.
// "application/problem+json"). The `; charset=...` suffix is stripped
// before comparison.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == api.ContentTypeJSON || strings.HasSuffix(ct, "+json")
}
