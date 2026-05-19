package apienvelope

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// decodedSuccess mirrors the yalla.output.v1 wire shape for assertions.
type decodedSuccess struct {
	SchemaVersion string         `json:"schema_version"`
	OK            bool           `json:"ok"`
	Data          map[string]any `json:"data"`
	RequestID     string         `json:"request_id"`
	Warnings      []string       `json:"warnings"`
}

// decodedError mirrors the yalla.error.v1 wire shape for assertions.
type decodedError struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Error         struct {
		Code             string `json:"code"`
		Message          string `json:"message"`
		Hint             string `json:"hint"`
		DocumentationURL string `json:"documentation_url"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func TestWriteDataSuccessEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteData(rec, http.StatusOK, "req-123", map[string]string{"status": "ok"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var env decodedSuccess
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.SchemaVersion != SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, SuccessSchema)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID != "req-123" {
		t.Errorf("request_id = %q, want req-123", env.RequestID)
	}
	if env.Data["status"] != "ok" {
		t.Errorf("data.status = %v, want ok", env.Data["status"])
	}
	// Warnings is optional and must be absent from the wire when empty.
	if strings.Contains(rec.Body.String(), "warnings") {
		t.Errorf("empty warnings should be omitted, body = %s", rec.Body.String())
	}
}

func TestWriteDataIncludesWarnings(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteData(rec, http.StatusOK, "req-1", map[string]string{}, "deprecated field used")

	var env decodedSuccess
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Warnings) != 1 || env.Warnings[0] != "deprecated field used" {
		t.Errorf("warnings = %v, want [deprecated field used]", env.Warnings)
	}
}

// TestWriteErrorDerivesStatusAndEnvelope covers the acceptance-criteria paths:
// validation failure, authorization failure, and not-found, plus the conflict
// path, asserting both the derived HTTP status and the stable envelope shape.
func TestWriteErrorDerivesStatusAndEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        *yerr.Error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "validation failure",
			err:        yerr.New(yerr.CodeValidation, "name is required").WithHint("provide a non-empty name"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "E_VALIDATION",
		},
		{
			name:       "authentication failure",
			err:        yerr.New(yerr.CodeAuthInvalid, "the supplied credentials are invalid"),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "E_AUTH_INVALID",
		},
		{
			name:       "authorization failure",
			err:        yerr.New(yerr.CodeForbidden, "not authorized for action"),
			wantStatus: http.StatusForbidden,
			wantCode:   "E_FORBIDDEN",
		},
		{
			name:       "not found",
			err:        yerr.New(yerr.CodeNotFound, "route not found"),
			wantStatus: http.StatusNotFound,
			wantCode:   "E_NOT_FOUND",
		},
		{
			name:       "conflict",
			err:        yerr.New(yerr.CodeConflict, "resource already exists"),
			wantStatus: http.StatusConflict,
			wantCode:   "E_CONFLICT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			WriteError(rec, "req-err", tt.err)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			var env decodedError
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if env.SchemaVersion != ErrorSchema {
				t.Errorf("schema_version = %q, want %q", env.SchemaVersion, ErrorSchema)
			}
			if env.OK {
				t.Errorf("ok = true, want false")
			}
			if env.Error.Code != tt.wantCode {
				t.Errorf("error.code = %q, want %q", env.Error.Code, tt.wantCode)
			}
			if env.Error.Message != tt.err.Message {
				t.Errorf("error.message = %q, want %q", env.Error.Message, tt.err.Message)
			}
			if env.Error.Hint != tt.err.Hint {
				t.Errorf("error.hint = %q, want %q", env.Error.Hint, tt.err.Hint)
			}
			wantDoc := DocsBaseURL + "/" + tt.wantCode
			if env.Error.DocumentationURL != wantDoc {
				t.Errorf("documentation_url = %q, want %q", env.Error.DocumentationURL, wantDoc)
			}
			if env.RequestID != "req-err" {
				t.Errorf("request_id = %q, want req-err", env.RequestID)
			}
		})
	}
}

// TestStatusForCode pins the full, documented code-to-status mapping.
func TestStatusForCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code yerr.Code
		want int
	}{
		{yerr.CodeValidation, http.StatusBadRequest},
		{yerr.CodeUsage, http.StatusBadRequest},
		{yerr.CodeAuthenticationRequired, http.StatusUnauthorized},
		{yerr.CodeAuthInvalid, http.StatusUnauthorized},
		{yerr.CodeAuthExpired, http.StatusUnauthorized},
		{yerr.CodeAuth, http.StatusUnauthorized},
		{yerr.CodeForbidden, http.StatusForbidden},
		{yerr.CodeScopeRequired, http.StatusBadRequest},
		{yerr.CodeNotFound, http.StatusNotFound},
		{yerr.CodeConflict, http.StatusConflict},
		{yerr.CodeInvalidStateTransition, http.StatusConflict},
		{yerr.CodeIdempotencyConflict, http.StatusConflict},
		{yerr.CodeRateLimited, http.StatusTooManyRequests},
		{yerr.CodeQuotaExceeded, http.StatusTooManyRequests},
		{yerr.CodeUnsupported, http.StatusNotImplemented},
		{yerr.CodeServer, http.StatusBadGateway},
		{yerr.CodeDokployAuth, http.StatusBadGateway},
		{yerr.CodeDokployForbidden, http.StatusBadGateway},
		{yerr.CodeDokployConflict, http.StatusBadGateway},
		{yerr.CodeDokployRateLimited, http.StatusBadGateway},
		{yerr.CodeDokployUnavailable, http.StatusBadGateway},
		{yerr.CodeDokployBadResponse, http.StatusBadGateway},
		{yerr.CodeUpstreamBug, http.StatusBadGateway},
		{yerr.CodeNetwork, http.StatusBadGateway},
		{yerr.CodeTimeout, http.StatusGatewayTimeout},
		{yerr.CodeDBUnavailable, http.StatusServiceUnavailable},
		{yerr.CodeMigrationRequired, http.StatusServiceUnavailable},
		{yerr.CodeUnavailable, http.StatusServiceUnavailable},
		{yerr.CodeCanceled, 499},
		{yerr.CodeInternal, http.StatusInternalServerError},
		{yerr.CodeUnknown, http.StatusInternalServerError},
		{yerr.CodeConfig, http.StatusInternalServerError},
		{yerr.CodeOrphan, http.StatusInternalServerError},
		{yerr.CodeNoInput, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		if got := StatusForCode(tt.code); got != tt.want {
			t.Errorf("StatusForCode(%s) = %d, want %d", tt.code, got, tt.want)
		}
	}

	// Every catalogued code must map to a non-zero status so a future code
	// can never silently fall through to a zero/200 result.
	for _, doc := range yerr.AllCodes() {
		if got := StatusForCode(yerr.Code(doc.Code)); got < 400 {
			t.Errorf("StatusForCode(%s) = %d, want a >= 400 failure status", doc.Code, got)
		}
	}
}

func TestWriteErrorDBUnavailableContract(t *testing.T) {
	t.Parallel()

	const secret = "postgres://yalla:super-secret-db-password@db.internal:5432/yalla"
	err := yerr.New(yerr.CodeDBUnavailable, "the Yalla datastore is temporarily unavailable").
		WithHint("this is a transient failure; retry after a short backoff").
		Wrap(stderrors.New("pgx connect failed with dsn " + secret))

	rec := httptest.NewRecorder()
	WriteError(rec, "req-db-unavailable", err)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) || strings.Contains(body, "super-secret-db-password") || strings.Contains(body, "db.internal") {
		t.Fatalf("error envelope leaked datastore cause: %s", body)
	}
	var env decodedError
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &env); decodeErr != nil {
		t.Fatalf("decode: %v", decodeErr)
	}
	if env.SchemaVersion != ErrorSchema || env.OK {
		t.Fatalf("envelope = %+v, want %s error envelope", env, ErrorSchema)
	}
	if env.RequestID != "req-db-unavailable" {
		t.Errorf("request_id = %q, want req-db-unavailable", env.RequestID)
	}
	if env.Error.Code != string(yerr.CodeDBUnavailable) {
		t.Errorf("error.code = %q, want %q", env.Error.Code, yerr.CodeDBUnavailable)
	}
	if env.Error.Message != "the Yalla datastore is temporarily unavailable" {
		t.Errorf("error.message = %q", env.Error.Message)
	}
	if env.Error.Hint != "this is a transient failure; retry after a short backoff" {
		t.Errorf("error.hint = %q", env.Error.Hint)
	}
	wantDoc := DocsBaseURL + "/" + string(yerr.CodeDBUnavailable)
	if env.Error.DocumentationURL != wantDoc {
		t.Errorf("documentation_url = %q, want %q", env.Error.DocumentationURL, wantDoc)
	}
}

func TestWriteErrorDokployUnavailableContract(t *testing.T) {
	t.Parallel()

	const secret = "dkp_live_super_secret_contract_value"
	err := yerr.New(yerr.CodeDokployUnavailable, "the Dokploy provisioning backend is unavailable").
		WithHint("this is a transient upstream failure; retry after a short backoff").
		Wrap(stderrors.New("dial tcp 10.0.0.42:443: token " + secret))

	rec := httptest.NewRecorder()
	WriteError(rec, "req-dokploy-unavailable", err)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if body := rec.Body.String(); strings.Contains(body, secret) || strings.Contains(body, "10.0.0.42") {
		t.Fatalf("error envelope leaked upstream cause: %s", body)
	}
	var env decodedError
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &env); decodeErr != nil {
		t.Fatalf("decode: %v", decodeErr)
	}
	if env.SchemaVersion != ErrorSchema || env.OK {
		t.Fatalf("envelope = %+v, want %s error envelope", env, ErrorSchema)
	}
	if env.RequestID != "req-dokploy-unavailable" {
		t.Errorf("request_id = %q, want req-dokploy-unavailable", env.RequestID)
	}
	if env.Error.Code != string(yerr.CodeDokployUnavailable) {
		t.Errorf("error.code = %q, want %q", env.Error.Code, yerr.CodeDokployUnavailable)
	}
	if env.Error.Message != "the Dokploy provisioning backend is unavailable" {
		t.Errorf("error.message = %q", env.Error.Message)
	}
	if env.Error.Hint != "this is a transient upstream failure; retry after a short backoff" {
		t.Errorf("error.hint = %q", env.Error.Hint)
	}
	wantDoc := DocsBaseURL + "/" + string(yerr.CodeDokployUnavailable)
	if env.Error.DocumentationURL != wantDoc {
		t.Errorf("documentation_url = %q, want %q", env.Error.DocumentationURL, wantDoc)
	}
}

func TestWriteErrorStatusExplicitOverride(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	// CodeServer normally derives 502; the explicit override must win.
	WriteErrorStatus(rec, http.StatusServiceUnavailable, "req-x",
		yerr.New(yerr.CodeServer, "service is not ready"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var env decodedError
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "E_SERVER" {
		t.Errorf("error.code = %q, want E_SERVER", env.Error.Code)
	}
}

func TestWriteErrorNilErrorIsInternal(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, "req-nil", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var env decodedError
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != string(yerr.CodeInternal) {
		t.Errorf("error.code = %q, want %s", env.Error.Code, yerr.CodeInternal)
	}
	if env.Error.Message == "" {
		t.Errorf("error.message must not be empty for a nil error")
	}
}

// TestEnvelopeRedactsSecrets proves the renderer is a redaction backstop:
// secrets that slip into an error message, hint, or warning never reach the
// wire.
func TestEnvelopeRedactsSecrets(t *testing.T) {
	t.Parallel()

	const secretHeader = "Authorization: Bearer super-secret-token-value"
	const secretQuery = "https://dokploy.internal/api?token=leaked-token-value&x=1"

	rec := httptest.NewRecorder()
	WriteError(rec, "req-redact",
		yerr.New(yerr.CodeServer, "upstream call failed with "+secretHeader).
			WithHint("retry without "+secretQuery))
	body := rec.Body.String()
	if strings.Contains(body, "super-secret-token-value") {
		t.Errorf("error body leaked a bearer token: %s", body)
	}
	if strings.Contains(body, "leaked-token-value") {
		t.Errorf("error body leaked a query token: %s", body)
	}
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("expected redaction sentinel %q in body: %s", output.Sentinel, body)
	}

	rec = httptest.NewRecorder()
	WriteData(rec, http.StatusOK, "req-redact", map[string]string{}, "saw "+secretHeader)
	if strings.Contains(rec.Body.String(), "super-secret-token-value") {
		t.Errorf("warning leaked a bearer token: %s", rec.Body.String())
	}
}

func TestDocURLForCode(t *testing.T) {
	t.Parallel()

	if got := DocURLForCode(yerr.CodeNotFound); got != DocsBaseURL+"/E_NOT_FOUND" {
		t.Errorf("DocURLForCode = %q, want %s/E_NOT_FOUND", got, DocsBaseURL)
	}
	if got := DocURLForCode(""); got != "" {
		t.Errorf("DocURLForCode(\"\") = %q, want empty", got)
	}
}

// decodedErrorWithDetails extends decodedError with the optional details map
// the envelope renders for errors that carry agent-readable metadata (a
// stale-write current_version, a quota's limit, a retry_after).
type decodedErrorWithDetails struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Error         struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Hint    string            `json:"hint"`
		Details map[string]string `json:"details"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

// TestWriteErrorRendersDetails proves a yerr.Error with structured Details
// surfaces them under "error.details" in the envelope, while an error with no
// Details omits the field entirely so agents can switch on field presence.
func TestWriteErrorRendersDetails(t *testing.T) {
	t.Parallel()

	withDetails := yerr.New(yerr.CodeConflict, "stale write").
		WithDetail("current_version", "5").
		WithDetail("retry_after", "30")

	rec := httptest.NewRecorder()
	WriteError(rec, "req-d", withDetails)

	var env decodedErrorWithDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Details["current_version"] != "5" {
		t.Errorf("details[current_version] = %q, want 5", env.Error.Details["current_version"])
	}
	if env.Error.Details["retry_after"] != "30" {
		t.Errorf("details[retry_after] = %q, want 30", env.Error.Details["retry_after"])
	}

	// An error without Details must not emit the field at all (omitempty).
	rec = httptest.NewRecorder()
	WriteError(rec, "req-d", yerr.New(yerr.CodeConflict, "no details"))
	if strings.Contains(rec.Body.String(), `"details"`) {
		t.Errorf("error body without details leaked a details field: %s", rec.Body.String())
	}
}

// TestWriteErrorRedactsDetailValues proves the envelope's regex-based
// redaction backstop is applied to detail values too, the same way it
// covers Message and Hint, so a stray secret in a detail can never reach
// the wire.
func TestWriteErrorRedactsDetailValues(t *testing.T) {
	t.Parallel()

	const secret = "Authorization: Bearer should-be-redacted"
	withSecret := yerr.New(yerr.CodeConflict, "x").WithDetail("captured_header", secret)

	rec := httptest.NewRecorder()
	WriteError(rec, "req-d", withSecret)

	body := rec.Body.String()
	if strings.Contains(body, "should-be-redacted") {
		t.Errorf("envelope leaked a secret in details: %s", body)
	}
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("expected redaction sentinel %q in body: %s", output.Sentinel, body)
	}
}
