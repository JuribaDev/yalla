package api_test

// HTTP client tests. Every test stands up an httptest.Server (or a stub
// http.RoundTripper) so the suite never requires a live Dokploy endpoint
// and never reaches the public internet.

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// withTestServer is the canonical setup helper. It returns a client whose
// Transport routes through the supplied handler's httptest.Server. Retries
// are enabled but the backoff is set to zero so the suite stays fast.
func withTestServer(t *testing.T, token string, handler http.Handler) (*api.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:    srv.URL,
		Token:      token,
		UserAgent:  "yalla/test",
		MaxRetries: 2,
		RetryBase:  0,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestNewClient_RejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  api.ClientConfig
		want yerr.Code
		hint string
	}{
		{"empty base url", api.ClientConfig{}, yerr.CodeConfig, "set YALLA_BASE_URL"},
		{"missing scheme", api.ClientConfig{BaseURL: "dokploy.example.com"}, yerr.CodeConfig, "must use http or https"},
		{"unknown scheme", api.ClientConfig{BaseURL: "ftp://example.com"}, yerr.CodeConfig, "must use http or https"},
		{"missing host", api.ClientConfig{BaseURL: "https://"}, yerr.CodeConfig, "missing a host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := api.NewClient(tc.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var typed *yerr.Error
			if !stderrors.As(err, &typed) {
				t.Fatalf("expected *yerr.Error, got %T", err)
			}
			if typed.Code != tc.want {
				t.Errorf("code = %s, want %s", typed.Code, tc.want)
			}
			combined := typed.Message + " " + typed.Hint
			if !strings.Contains(combined, tc.hint) {
				t.Errorf("missing hint %q in %q", tc.hint, combined)
			}
		})
	}
}

func TestNewClient_AcceptsValidConfig(t *testing.T) {
	c, err := api.NewClient(api.ClientConfig{
		BaseURL: "https://dokploy.example.com/api",
		Token:   "abcd1234efgh5678",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !c.HasToken() {
		t.Error("HasToken() = false, want true")
	}
	if c.BaseURL() != "https://dokploy.example.com/api" {
		t.Errorf("BaseURL() = %q", c.BaseURL())
	}
	if c.UserAgent() != "yalla/dev" {
		t.Errorf("UserAgent() default = %q", c.UserAgent())
	}
}

func TestClient_AttachesBearerTokenAndHeaders(t *testing.T) {
	const token = "supersecrettoken1234"
	var (
		gotAuth      string
		gotUA        string
		gotAccept    string
		gotCT        string
		gotBody      []byte
		gotMethod    string
		gotPath      string
		gotRawQuery  string
		gotXOverride string
	)
	c, _ := withTestServer(t, token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotCT = r.Header.Get("Content-Type")
		gotXOverride = r.Header.Get("X-Override")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-abc-123")
		w.Header().Set("X-Trace-Id", "trace-xyz")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	headers := http.Header{}
	headers.Set("X-Override", "yes")
	res, err := c.Do(t.Context(), &api.Request{
		Method:  "POST",
		Path:    "/application.deploy",
		Query:   map[string][]string{"trace": {"1"}},
		Headers: headers,
		Body:    []byte(`{"applicationId":"abc"}`),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !res.Success() {
		t.Fatalf("Success() = false, status=%d", res.Status)
	}
	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotUA != "yalla/test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotXOverride != "yes" {
		t.Errorf("caller header lost: %q", gotXOverride)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotPath != "/application.deploy" {
		t.Errorf("path = %q", gotPath)
	}
	if gotRawQuery != "trace=1" {
		t.Errorf("query = %q", gotRawQuery)
	}
	if string(gotBody) != `{"applicationId":"abc"}` {
		t.Errorf("body = %q", gotBody)
	}

	// Result captures observability headers and body.
	if res.RequestID != "req-abc-123" {
		t.Errorf("RequestID = %q", res.RequestID)
	}
	if res.TraceID != "trace-xyz" {
		t.Errorf("TraceID = %q", res.TraceID)
	}
	if string(res.Body) != `{"ok":true}` {
		t.Errorf("Body = %q", res.Body)
	}
	if res.ContentType != "application/json" {
		t.Errorf("ContentType = %q", res.ContentType)
	}
	if res.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", res.Attempts)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want >0", res.Duration)
	}
}

func TestClient_OmitsAuthWhenTokenEmpty(t *testing.T) {
	var got string
	c, _ := withTestServer(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	_, err := c.Do(t.Context(), &api.Request{Method: "GET", Path: "/health"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "" {
		t.Errorf("Authorization should be empty when no token, got %q", got)
	}
}

func TestClient_PreservesCallerAuthOverride(t *testing.T) {
	var got string
	c, _ := withTestServer(t, "client-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	headers := http.Header{}
	headers.Set("Authorization", "Token caller-supplied-1234")
	_, err := c.Do(t.Context(), &api.Request{
		Method:  "GET",
		Path:    "/whoami",
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "Token caller-supplied-1234" {
		t.Errorf("Authorization = %q (caller override should win)", got)
	}
}

func TestClient_StatusMappingViaAsError(t *testing.T) {
	cases := []struct {
		status int
		want   yerr.Code
	}{
		{http.StatusBadRequest, yerr.CodeInvalidInput},
		{http.StatusUnauthorized, yerr.CodeAuth},
		{http.StatusForbidden, yerr.CodeForbidden},
		{http.StatusNotFound, yerr.CodeNotFound},
		{http.StatusConflict, yerr.CodeConflict},
		{http.StatusUnprocessableEntity, yerr.CodeInvalidInput},
		{http.StatusTooManyRequests, yerr.CodeRateLimited},
		{http.StatusInternalServerError, yerr.CodeServer},
		{http.StatusBadGateway, yerr.CodeServer},
		{http.StatusServiceUnavailable, yerr.CodeServer},
		{http.StatusGatewayTimeout, yerr.CodeServer},
		{http.StatusTeapot, yerr.CodeInvalidInput},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"error":"status %d"}`, tc.status)
			}))
			res, err := c.Do(t.Context(), &api.Request{Method: "POST", Path: "/op"})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if res.Success() {
				t.Fatalf("Success() = true for status %d", res.Status)
			}
			typed := res.AsError()
			if typed == nil {
				t.Fatalf("AsError() = nil for status %d", res.Status)
			}
			if typed.Code != tc.want {
				t.Errorf("status %d: code = %s, want %s", tc.status, typed.Code, tc.want)
			}
			if !strings.Contains(typed.Hint, "response body") {
				t.Errorf("status %d: hint missing body: %q", tc.status, typed.Hint)
			}
		})
	}
}

func TestClient_AsErrorHintTruncatesLongBody(t *testing.T) {
	long := strings.Repeat("x", 600)
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(long))
	}))
	res, err := c.Do(t.Context(), &api.Request{Method: "POST", Path: "/op"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	typed := res.AsError()
	if typed == nil {
		t.Fatal("AsError() = nil")
	}
	if !strings.HasSuffix(typed.Hint, "…") {
		t.Errorf("hint should be truncated with …, got %q", typed.Hint)
	}
	if len(typed.Hint) > 320 {
		t.Errorf("hint too long: %d", len(typed.Hint))
	}
}

func TestClient_AsErrorMultilineCollapsed(t *testing.T) {
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("line1\nline2\rline3"))
	}))
	res, err := c.Do(t.Context(), &api.Request{Method: "POST", Path: "/op"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	typed := res.AsError()
	if typed == nil {
		t.Fatal("AsError() = nil")
	}
	if strings.ContainsAny(typed.Hint, "\r\n") {
		t.Errorf("hint must be single-line: %q", typed.Hint)
	}
}

func TestClient_RetriesIdempotent503ThenSucceeds(t *testing.T) {
	var hits int32
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	res, err := c.Do(t.Context(), &api.Request{
		Method:     "GET",
		Path:       "/health",
		Idempotent: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("server hits = %d, want 3", got)
	}
	if res.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", res.Attempts)
	}
}

func TestClient_DoesNotRetryNonIdempotent503(t *testing.T) {
	var hits int32
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	res, err := c.Do(t.Context(), &api.Request{
		Method: "POST",
		Path:   "/application.deploy",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hits = %d, want 1 (no retry on non-idempotent)", got)
	}
	if res.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d", res.Status)
	}
	if typed := res.AsError(); typed == nil || typed.Code != yerr.CodeServer {
		t.Errorf("AsError() = %v, want CodeServer", typed)
	}
}

func TestClient_DoesNotRetry500(t *testing.T) {
	// 500 is deterministic — retrying just hammers a known-broken endpoint.
	var hits int32
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, err := c.Do(t.Context(), &api.Request{
		Method:     "GET",
		Path:       "/op",
		Idempotent: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hits = %d, want 1", got)
	}
}

func TestClient_RetriesIdempotentNetworkErrorThenSucceeds(t *testing.T) {
	var hits int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		n := atomic.AddInt32(&hits, 1)
		if n < 2 {
			return nil, &net.OpError{Op: "dial", Err: stderrors.New("connection refused")}
		}
		// success
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    r,
		}, nil
	})
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:    "http://stub.invalid",
		Token:      "tok",
		MaxRetries: 2,
		RetryBase:  0,
		Transport:  rt,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(t.Context(), &api.Request{
		Method:     "GET",
		Path:       "/health",
		Idempotent: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("Status = %d", res.Status)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("hits = %d, want 2", got)
	}
}

func TestClient_TimeoutMapsToCodeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the test client gives up.
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:    srv.URL,
		Token:      "tok",
		Timeout:    50 * time.Millisecond,
		MaxRetries: 0,
		RetryBase:  0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(t.Context(), &api.Request{Method: "GET", Path: "/slow"})
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("expected *yerr.Error, got %T", err)
	}
	if typed.Code != yerr.CodeTimeout {
		t.Errorf("code = %s, want %s", typed.Code, yerr.CodeTimeout)
	}
}

func TestClient_CancelMapsToCodeCanceled(t *testing.T) {
	gotReq := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:   srv.URL,
		Token:     "tok",
		RetryBase: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		<-gotReq
		cancel()
	}()
	_, err = c.Do(ctx, &api.Request{Method: "GET", Path: "/slow"})
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("expected *yerr.Error, got %T", err)
	}
	if typed.Code != yerr.CodeCanceled {
		t.Errorf("code = %s, want %s", typed.Code, yerr.CodeCanceled)
	}
}

func TestClient_NetworkErrorMapsToCodeNetwork(t *testing.T) {
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Err: stderrors.New("connection refused")}
	})
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:   "http://stub.invalid",
		Token:     "tok",
		Transport: rt,
		RetryBase: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(t.Context(), &api.Request{Method: "POST", Path: "/op"})
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("expected *yerr.Error, got %T", err)
	}
	if typed.Code != yerr.CodeNetwork {
		t.Errorf("code = %s, want %s", typed.Code, yerr.CodeNetwork)
	}
}

func TestClient_RetriesExhaustedReturnsTransportError(t *testing.T) {
	var hits int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&hits, 1)
		return nil, &net.OpError{Op: "dial", Err: stderrors.New("refused")}
	})
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:    "http://stub.invalid",
		Token:      "tok",
		MaxRetries: 2,
		RetryBase:  0,
		Transport:  rt,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(t.Context(), &api.Request{Method: "GET", Path: "/x", Idempotent: true})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("hits = %d, want 3 (1 + 2 retries)", got)
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) || typed.Code != yerr.CodeNetwork {
		t.Errorf("err = %v, want CodeNetwork", err)
	}
}

func TestClient_RedactsSecretsInErrorOutput(t *testing.T) {
	const secret = "tok-supersecret-1234"
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// Force a transport error that contains the URL — the URL itself
		// must not embed the bearer token (it lives in a header), but we
		// also want to prove the renderer scrubs anything that sneaks
		// through.
		return nil, fmt.Errorf("dial tcp: lookup host with %s: no such host", secret)
	})
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:   "http://stub.invalid",
		Token:     secret,
		Transport: rt,
		RetryBase: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(t.Context(), &api.Request{Method: "POST", Path: "/op"})
	if err == nil {
		t.Fatal("expected error")
	}

	// The renderer is the contract surface for user-visible output. After
	// scrubbing, no part of the secret should remain in either the message
	// or the hint, even though the cause string contains it.
	r := output.New(io.Discard, io.Discard, true, output.NewRedactor(secret))
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("expected *yerr.Error, got %T", err)
	}
	scrubbed := r.Redactor().Redact(typed.Message + " " + typed.Hint + " " + typed.Error())
	if strings.Contains(scrubbed, secret) {
		t.Errorf("secret leaked through redactor: %q", scrubbed)
	}
	if !strings.Contains(scrubbed, output.Sentinel) {
		t.Errorf("expected redaction sentinel, got %q", scrubbed)
	}
}

func TestClient_ResolvesPathAgainstBaseURLWithPrefix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	// Base URL with a /api prefix is preserved when joining with the
	// request path.
	c, err := api.NewClient(api.ClientConfig{
		BaseURL:   srv.URL + "/api",
		Token:     "tok",
		RetryBase: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(t.Context(), &api.Request{Method: "GET", Path: "/health"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotPath != "/api/health" {
		t.Errorf("path = %q, want /api/health", gotPath)
	}
}

func TestClient_RejectsIncompleteRequest(t *testing.T) {
	c, _ := withTestServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not have been called")
		w.WriteHeader(http.StatusOK)
	}))
	cases := []struct {
		name string
		req  *api.Request
	}{
		{"nil", nil},
		{"missing method", &api.Request{Path: "/op"}},
		{"missing path", &api.Request{Method: "GET"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Do(t.Context(), tc.req)
			if err == nil {
				t.Fatal("expected error")
			}
			var typed *yerr.Error
			if !stderrors.As(err, &typed) || typed.Code != yerr.CodeInternal {
				t.Errorf("err = %v, want CodeInternal", err)
			}
		})
	}
}

// roundTripperFunc lets tests inject a stub transport without mocking the
// full http.RoundTripper interface manually.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
