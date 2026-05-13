package dokploy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Input is the narrow request envelope composite commands pass to Dokploy.
// It deliberately mirrors the public api-call envelope without importing the
// cli package.
type Input struct {
	PathParams map[string]string
	Query      map[string][]string
	Headers    map[string][]string
	Body       json.RawMessage
}

// Result is a stable operation result returned by orchestration services.
type Result struct {
	OperationID string          `json:"operation_id"`
	Status      int             `json:"status"`
	Body        json.RawMessage `json:"body,omitempty"`
	Duration    time.Duration   `json:"-"`
	DurationMs  int64           `json:"duration_ms"`
	RequestID   string          `json:"request_id,omitempty"`
	TraceID     string          `json:"trace_id,omitempty"`
}

// Runner is the small execution boundary used by lifecycle/deploy/wait code.
type Runner interface {
	Call(ctx context.Context, operationID string, input Input) (*Result, error)
}

// HTTPRunner executes Dokploy operations through internal/api.Client.
type HTTPRunner struct {
	reg    *api.Registry
	client *api.Client
}

// NewHTTPRunner constructs a Runner backed by the supplied API client.
func NewHTTPRunner(reg *api.Registry, client *api.Client) *HTTPRunner {
	if reg == nil {
		reg = api.Default()
	}
	return &HTTPRunner{reg: reg, client: client}
}

// Call resolves and executes operationID with the supplied input.
func (r *HTTPRunner) Call(ctx context.Context, operationID string, input Input) (*Result, error) {
	op, ok := r.reg.Get(operationID)
	if !ok {
		return nil, yerr.Newf(yerr.CodeNotFound, "unknown operation %q", operationID)
	}
	path, err := substitutePathParams(op.Path, input.PathParams)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	for k, vs := range input.Query {
		for _, v := range vs {
			query.Add(k, v)
		}
	}
	headers := http.Header{}
	for k, vs := range input.Headers {
		for _, v := range vs {
			headers.Add(k, v)
		}
	}
	var body []byte
	contentType := ""
	if len(input.Body) > 0 {
		body = []byte(input.Body)
		contentType = api.ContentTypeJSON
		if op.RequestBody != nil && op.RequestBody.ContentType != "" {
			contentType = op.RequestBody.ContentType
		}
	}
	start := time.Now()
	res, err := r.client.Do(ctx, &api.Request{
		Method:      op.Method,
		Path:        path,
		Query:       query,
		Headers:     headers,
		Body:        body,
		ContentType: contentType,
		Idempotent:  op.Method == http.MethodGet || op.Method == http.MethodHead,
	})
	if err != nil {
		return nil, err
	}
	out := &Result{
		OperationID: operationID,
		Status:      res.Status,
		Duration:    time.Since(start),
		DurationMs:  time.Since(start).Milliseconds(),
		RequestID:   res.RequestID,
		TraceID:     res.TraceID,
	}
	if len(res.Body) > 0 && json.Valid(res.Body) {
		out.Body = append(json.RawMessage(nil), res.Body...)
	} else if len(res.Body) > 0 {
		out.Body, _ = json.Marshal(map[string]string{"body_text": string(res.Body)})
	}
	if !res.Success() {
		if known := MatchKnownIssue(operationID, res.Status, res.Body); known != nil {
			return out, known
		}
		return out, res.AsError()
	}
	return out, nil
}

var pathParamRE = regexp.MustCompile(`\{([^}]+)\}`)

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
		return "", yerr.Newf(yerr.CodeInvalidInput, "missing path param(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// JSONBody marshals v into a RawMessage for planned operation payloads.
func JSONBody(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
