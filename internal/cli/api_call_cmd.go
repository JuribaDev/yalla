package cli

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
type apiCallInput struct {
	PathParams map[string]string   `json:"path_params,omitempty"`
	Query      map[string][]string `json:"query,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       json.RawMessage     `json:"body,omitempty"`
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
type apiCallDryRunDoc struct {
	OperationID string              `json:"operation_id"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	ContentType string              `json:"content_type,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Body        json.RawMessage     `json:"body,omitempty"`
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
var apiCallClientFactory = func(args apiCallClientArgs) (*api.Client, error) {
	cc := api.ClientConfig{
		BaseURL:    args.Config.BaseURL,
		Token:      args.Config.Token,
		UserAgent:  "yalla/" + args.Build.Version,
		Timeout:    args.Timeout,
		MaxRetries: 0,
	}
	return api.NewClient(cc)
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
    "body":        {"projectId": "abc"}
  }

Unknown top-level keys are rejected so a typo never silently corrupts the
request. Use ` + "`yalla schema get <operationId>`" + ` to discover the
expected body schema for any specific operation.

In ` + "`--dry-run`" + ` mode the resolved request is printed without
sending it. Authorization headers are replaced with ` + "`[REDACTED]`" + `
so the dry-run envelope is safe to log or paste.`,
		Example: `  yalla api call project-all --json
  yalla api call application-deploy --input request.json --json
  echo '{"body":{"applicationId":"abc"}}' | yalla api call application-deploy --input - --json
  yalla api call application-deploy --input request.json --dry-run --json`,
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

	body, contentType, err := resolveRequestBody(op, in.Body)
	if err != nil {
		return err
	}

	if !opts.DryRun {
		if cfg.BaseURL == "" {
			return yerr.New(yerr.CodeConfig, "no Dokploy base URL configured").
				WithHint("set YALLA_BASE_URL, pass --base-url, or run `yalla config set base_url https://dokploy.example.com`")
		}
		if op.RequiresAuth && cfg.Token == "" {
			return yerr.Newf(yerr.CodeAuth, "operation %q requires authentication; no Dokploy API token configured", op.OperationID).
				WithHint("set YALLA_TOKEN, pass --token, or run `yalla config set token <value>`")
		}
	}

	targetURL := joinAPIURL(cfg.BaseURL, resolvedPath, query)

	if opts.DryRun {
		return emitAPICallDryRun(r, op, targetURL, headers, body, contentType, cfg)
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

// resolveRequestBody selects the bytes and content-type for the outgoing
// request. A nil body for a required-body operation surfaces as a typed
// CodeInvalidInput so the spec contract is enforced before the wire call.
func resolveRequestBody(op api.Operation, body json.RawMessage) ([]byte, string, error) {
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
// Authorization header is rendered with [REDACTED] in place of the bearer
// value so a `--dry-run --json` envelope is safe to log or paste.
func emitAPICallDryRun(r *output.Renderer, op api.Operation, targetURL string, headers http.Header, body []byte, contentType string, cfg *config.Config) error {
	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	if len(body) > 0 && h.Get(api.HeaderContentType) == "" {
		h.Set(api.HeaderContentType, contentType)
	}
	if cfg.HasToken() && h.Get(api.HeaderAuthorization) == "" {
		h.Set(api.HeaderAuthorization, "Bearer "+output.Sentinel)
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
		doc.Body = append(json.RawMessage(nil), body...)
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
