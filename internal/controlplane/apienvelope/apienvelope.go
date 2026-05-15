// Package apienvelope is the single, canonical renderer for every Yalla
// Control Plane HTTP response. All API handlers — success and failure alike —
// must emit their bodies through WriteData or WriteError so the wire contract
// stays deterministic for scripts and AI agents.
//
// Two stable envelope shapes are guaranteed:
//
//	yalla.output.v1 — success: {schema_version, ok:true, data, request_id, warnings?}
//	yalla.error.v1  — failure: {schema_version, ok:false, error{code,message,hint?,details?,documentation_url?}, request_id}
//
// The error block's optional details map carries small, agent-readable
// metadata about the failure (a stale write's current_version, a quota's
// limit, a retry_after) so callers do not have to parse a human-readable
// hint to recover. Keys are stable per error code; the catalog is the source
// of truth.
//
// The envelope structs are intentionally unexported: handlers cannot construct
// or marshal them directly, which guarantees no handler writes ad hoc JSON
// outside this package. The HTTP-status-to-error-code mapping lives here too
// (StatusForCode) so status selection is centralised and testable rather than
// hand-picked per handler.
package apienvelope

import (
	"encoding/json"
	"net/http"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// SuccessSchema and ErrorSchema are the stable schema_version values embedded
// in every envelope. They are re-exported from their defining packages so
// callers and tests in the control plane have a single import for the wire
// contract. Bumping either is a public-API change.
const (
	SuccessSchema = output.SuccessSchema // "yalla.output.v1"
	ErrorSchema   = yerr.SchemaVersion   // "yalla.error.v1"
)

// DocsBaseURL is the stable root of the public error-code documentation. Each
// error envelope links to DocsBaseURL + "/" + code so agents can resolve a
// human-readable explanation deterministically. Changing it is a public-API
// change.
const DocsBaseURL = "https://docs.yalla.dev/api/errors"

// successEnvelope is the wire shape of a yalla.output.v1 response. It is
// unexported so no handler can hand-roll one outside this package.
type successEnvelope struct {
	SchemaVersion string   `json:"schema_version"`
	OK            bool     `json:"ok"`
	Data          any      `json:"data"`
	RequestID     string   `json:"request_id"`
	Warnings      []string `json:"warnings,omitempty"`
}

// errorEnvelope is the wire shape of a yalla.error.v1 response.
type errorEnvelope struct {
	SchemaVersion string       `json:"schema_version"`
	OK            bool         `json:"ok"`
	Error         errorPayload `json:"error"`
	RequestID     string       `json:"request_id"`
}

// errorPayload is the inner error block. Hint, Details, and DocumentationURL
// are omitempty because not every failure has a remediation suggestion or a
// structured context block, and emitting an empty value would corrupt agents
// that switch on field presence.
type errorPayload struct {
	Code             string            `json:"code"`
	Message          string            `json:"message"`
	Hint             string            `json:"hint,omitempty"`
	Details          map[string]string `json:"details,omitempty"`
	DocumentationURL string            `json:"documentation_url,omitempty"`
}

// envelopeRedactor scrubs well-known secret patterns (Authorization headers,
// token-bearing query params) from any text we place on the wire. It carries
// no registered literal secrets — those are redacted closer to their source —
// but the regex-based patterns are a defence-in-depth backstop so a stray
// token in an error message or warning never escapes the renderer.
var envelopeRedactor = output.NewRedactor()

// StatusForCode maps a stable error Code to the HTTP status the API returns
// for it. The mapping is deterministic and part of the public contract:
// agents and scripts may rely on these pairings.
//
//	E_INVALID_INPUT, E_USAGE                  -> 400 Bad Request
//	E_AUTH                                    -> 401 Unauthorized
//	E_FORBIDDEN                               -> 403 Forbidden
//	E_NOT_FOUND                               -> 404 Not Found
//	E_CONFLICT, E_IDEMPOTENCY_CONFLICT        -> 409 Conflict
//	E_RATE_LIMITED, E_QUOTA_EXCEEDED          -> 429 Too Many Requests
//	E_UNSUPPORTED                             -> 501 Not Implemented
//	E_SERVER, E_UPSTREAM_BUG, E_NETWORK       -> 502 Bad Gateway
//	E_TIMEOUT                                 -> 504 Gateway Timeout
//	E_UNAVAILABLE                             -> 503 Service Unavailable
//	E_CANCELED                                -> 499 Client Closed Request
//	everything else (E_INTERNAL, E_CONFIG, …) -> 500 Internal Server Error
func StatusForCode(code yerr.Code) int {
	switch code {
	case yerr.CodeInvalidInput, yerr.CodeUsage:
		return http.StatusBadRequest
	case yerr.CodeAuth:
		return http.StatusUnauthorized
	case yerr.CodeForbidden:
		return http.StatusForbidden
	case yerr.CodeNotFound:
		return http.StatusNotFound
	case yerr.CodeConflict, yerr.CodeIdempotencyConflict:
		return http.StatusConflict
	case yerr.CodeRateLimited, yerr.CodeQuotaExceeded:
		return http.StatusTooManyRequests
	case yerr.CodeUnsupported:
		return http.StatusNotImplemented
	case yerr.CodeServer, yerr.CodeUpstreamBug, yerr.CodeNetwork:
		return http.StatusBadGateway
	case yerr.CodeTimeout:
		return http.StatusGatewayTimeout
	case yerr.CodeUnavailable:
		return http.StatusServiceUnavailable
	case yerr.CodeCanceled:
		// 499 is the de facto "client closed request" status. It has no
		// net/http constant, but it is the deterministic value agents expect.
		return 499
	default:
		// CodeInternal, CodeUnknown, CodeConfig, CodeOrphan, CodeNoInput, and
		// any future code we have not classified yet all collapse to 500 so a
		// missing case never leaks an unclassified status.
		return http.StatusInternalServerError
	}
}

// DocURLForCode returns the stable documentation URL for an error code, or the
// empty string for an empty code.
func DocURLForCode(code yerr.Code) string {
	if code == "" {
		return ""
	}
	return DocsBaseURL + "/" + string(code)
}

// WriteData renders a yalla.output.v1 success envelope. requestID is always
// included (empty until request-ID middleware lands). warnings is optional and
// omitted from the wire when empty; warning strings are redacted defensively.
func WriteData(w http.ResponseWriter, status int, requestID string, data any, warnings ...string) {
	writeJSON(w, status, successEnvelope{
		SchemaVersion: SuccessSchema,
		OK:            true,
		Data:          data,
		RequestID:     requestID,
		Warnings:      redactAll(warnings),
	})
}

// WriteError renders a yalla.error.v1 envelope, deriving the HTTP status from
// the error's Code via StatusForCode. This is the path every handler should
// use; the status follows the code automatically and stays consistent.
//
// A nil err is treated as an unclassified internal failure so the renderer
// never panics and never emits a misleading 200.
func WriteError(w http.ResponseWriter, requestID string, err *yerr.Error) {
	code := errorCode(err)
	WriteErrorStatus(w, StatusForCode(code), requestID, err)
}

// WriteErrorStatus renders a yalla.error.v1 envelope with an explicit HTTP
// status, for the rare cases where the status cannot be derived from the code
// alone (for example /readyz returning 503 with E_SERVER while startup gates
// are pending). Prefer WriteError everywhere else.
func WriteErrorStatus(w http.ResponseWriter, status int, requestID string, err *yerr.Error) {
	code := errorCode(err)
	message := "internal error"
	hint := ""
	var details map[string]string
	if err != nil {
		if err.Message != "" {
			message = err.Message
		}
		hint = err.Hint
		details = redactDetails(err.Details)
	}
	writeJSON(w, status, errorEnvelope{
		SchemaVersion: ErrorSchema,
		OK:            false,
		Error: errorPayload{
			Code:             string(code),
			Message:          envelopeRedactor.Redact(message),
			Hint:             envelopeRedactor.Redact(hint),
			Details:          details,
			DocumentationURL: DocURLForCode(code),
		},
		RequestID: requestID,
	})
}

// redactDetails returns a redacted copy of in, dropping blank keys, or nil
// when the input is empty so the omitempty tag drops the field from the wire.
// Values are run through the regex backstop the same way Message and Hint
// are; the originating constructor remains responsible for not naming a
// secret in the first place.
func redactDetails(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "" {
			continue
		}
		out[k] = envelopeRedactor.Redact(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// errorCode extracts the stable Code from err, defaulting to CodeInternal for
// a nil error or an error with no code set.
func errorCode(err *yerr.Error) yerr.Code {
	if err == nil || err.Code == "" {
		return yerr.CodeInternal
	}
	return err.Code
}

// redactAll returns a redacted copy of the supplied strings, or nil when the
// input is empty so the omitempty tag drops the field from the wire.
func redactAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = envelopeRedactor.Redact(s)
	}
	return out
}

// writeJSON is the single point where an envelope reaches the socket. It is
// unexported, so the only way to produce an envelope body is through WriteData
// or WriteError.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
