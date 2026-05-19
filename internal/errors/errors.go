// Package errors defines yalla's typed error contract: stable error codes,
// human messages, optional hints, and the exit-code mapping the CLI guarantees
// to scripts and AI agents.
//
// Every failure surfaced to the user must round-trip through a *Error. The
// CLI's terminal renderer (in internal/output) emits either the
// "yalla.error.v1" JSON envelope (when --json is set) or a stable
// human-readable line on stderr. Either way, the binary's exit code is
// derived from the error's Code via ExitCode(), so changing the constants in
// this file is a public-API change.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// SchemaVersion is the stable schema identifier embedded in every JSON error
// envelope. Bumping this constant is a public-API change.
const SchemaVersion = "yalla.error.v1"

// Code is a stable, machine-readable error identifier. Values are part of the
// CLI's public contract: scripts and agents may switch on them.
type Code string

// Stable error codes. Every visible failure must classify as one of these so
// the JSON envelope and exit code remain deterministic.
const (
	CodeUnknown  Code = "E_UNKNOWN"
	CodeInternal Code = "E_INTERNAL"
	CodeUsage    Code = "E_USAGE"
	// CodeValidation marks request payload, path, query, or compatibility
	// contract validation failures in the backend API. It is distinct from
	// CodeInvalidInput so backend agents can switch on the public API contract
	// without inheriting older CLI terminology.
	CodeValidation   Code = "E_VALIDATION"
	CodeInvalidInput Code = "E_INVALID_INPUT"
	CodeConfig       Code = "E_CONFIG"
	CodeOrphan       Code = "E_ORPHAN"
	// CodeAuthenticationRequired marks a request that did not provide any
	// usable authentication material. It is distinct from CodeAuth so agents
	// can tell "send credentials" apart from "supplied credentials failed".
	CodeAuthenticationRequired Code = "E_AUTHENTICATION_REQUIRED"
	// CodeAuthInvalid marks supplied authentication credentials that failed
	// verification. It is intentionally generic so callers cannot distinguish
	// unknown, revoked, malformed, or otherwise rejected credentials.
	CodeAuthInvalid Code = "E_AUTH_INVALID"
	// CodeAuthExpired marks authentication credentials that were structurally
	// valid but are no longer accepted because their validity window elapsed.
	// It remains a generic authentication failure: responses must never reveal
	// credential material or timing internals.
	CodeAuthExpired Code = "E_AUTH_EXPIRED"
	CodeAuth        Code = "E_AUTH"
	CodeForbidden   Code = "E_FORBIDDEN"
	// CodeScopeRequired marks a request that reached authorization without
	// the organization/resource scope needed to evaluate the action.
	CodeScopeRequired Code = "E_SCOPE_REQUIRED"
	CodeNotFound      Code = "E_NOT_FOUND"
	CodeConflict      Code = "E_CONFLICT"
	// CodeJobNotClaimed marks a provisioning-job outcome write attempted by a
	// worker that no longer holds the job lease. It is distinct from generic
	// conflict so worker supervisors and agents can treat stale lease ownership
	// as a queue coordination failure instead of a resource precondition.
	CodeJobNotClaimed Code = "E_JOB_NOT_CLAIMED"
	// CodeJobCancelled marks a provisioning-job outcome write or follow-up
	// operation rejected because the job has already been cancelled. It is
	// distinct from generic conflict so workers and agents can stop retrying
	// the cancelled job without parsing lifecycle text.
	CodeJobCancelled Code = "E_JOB_CANCELLED"
	// CodeInvalidStateTransition marks a lifecycle transition that is not
	// allowed by the resource's documented state machine. It is distinct from
	// CodeConflict so agents can tell "retry with a fresh version" apart from
	// "this edge is impossible from the current state".
	CodeInvalidStateTransition Code = "E_INVALID_STATE_TRANSITION"
	// CodeIdempotencyConflict marks a request that reused an idempotency key
	// for a request that does not match the one the key was first claimed for.
	// It is distinct from CodeConflict (a generic state collision): it always
	// means "this key already names a different request", so a client must
	// either replay the original request unchanged or choose a fresh key.
	CodeIdempotencyConflict Code = "E_IDEMPOTENCY_CONFLICT"
	CodeRateLimited         Code = "E_RATE_LIMITED"
	// CodeQuotaExceeded marks a request rejected because an organization quota
	// or plan limit is exhausted. It is distinct from CodeRateLimited (a
	// transient throughput cap): a quota failure persists until the limit is
	// raised or usage is released.
	CodeQuotaExceeded Code = "E_QUOTA_EXCEEDED"
	// CodeUnsupportedServiceType marks a service type Yalla does not support
	// as part of its public service contract. It is distinct from the generic
	// CodeUnsupported operation/build code so agents can correct service
	// intent without treating the whole endpoint as unavailable.
	CodeUnsupportedServiceType Code = "E_UNSUPPORTED_SERVICE_TYPE"
	CodeServer                 Code = "E_SERVER"
	// CodeDokployAuth marks a private Dokploy provisioning backend response
	// that rejected Yalla's own upstream credentials. It is distinct from
	// customer authentication/authorization codes and from transient Dokploy
	// outages: retrying the same request will not help until operators fix
	// the upstream credential or permission configuration.
	CodeDokployAuth Code = "E_DOKPLOY_AUTH"
	// CodeDokployForbidden marks a private Dokploy provisioning backend
	// response that authenticated Yalla's upstream credential but denied the
	// specific provisioning operation. It is distinct from customer-facing
	// E_FORBIDDEN because customers never call Dokploy directly.
	CodeDokployForbidden Code = "E_DOKPLOY_FORBIDDEN"
	// CodeDokployNotFound marks a private Dokploy provisioning backend
	// response that could not find an upstream resource Yalla expected to
	// exist. It is distinct from customer-facing E_NOT_FOUND because customers
	// never address Dokploy resources directly.
	CodeDokployNotFound Code = "E_DOKPLOY_NOT_FOUND"
	// CodeDokployConflict marks a private Dokploy provisioning backend
	// response that rejected an operation because the upstream resource state
	// conflicts with Yalla's desired provisioning action. It is distinct from
	// customer-facing E_CONFLICT because customers never call Dokploy directly.
	CodeDokployConflict Code = "E_DOKPLOY_CONFLICT"
	// CodeDokployRateLimited marks a private Dokploy provisioning backend
	// response that rate limited Yalla's upstream provisioning request. It is
	// distinct from customer-facing E_RATE_LIMITED because customers never
	// call Dokploy directly and may not be the source of the upstream throttle.
	CodeDokployRateLimited Code = "E_DOKPLOY_RATE_LIMITED"
	// CodeDokployUnavailable marks a transient outage or unusable response from
	// the private Dokploy provisioning backend. It is distinct from
	// CodeDBUnavailable and CodeUnavailable, which are reserved for Yalla-owned
	// dependencies.
	CodeDokployUnavailable Code = "E_DOKPLOY_UNAVAILABLE"
	// CodeDokployBadResponse marks a successful private Dokploy provisioning
	// backend response whose body did not match the typed contract Yalla
	// expected. It is distinct from transient availability failures because
	// retrying may keep returning the same incompatible payload until operators
	// fix the upstream contract mismatch.
	CodeDokployBadResponse Code = "E_DOKPLOY_BAD_RESPONSE"
	CodeUpstreamBug        Code = "E_UPSTREAM_BUG"
	CodeNetwork            Code = "E_NETWORK"
	// CodeDBUnavailable marks a failure caused by Yalla's Postgres datastore
	// being temporarily unavailable. It is distinct from the generic
	// CodeUnavailable queue/dependency code so agents can distinguish a data
	// plane outage from durable-queue pressure without parsing messages.
	CodeDBUnavailable Code = "E_DB_UNAVAILABLE"
	// CodeMigrationRequired marks a service startup or request path blocked
	// because the database schema has not been migrated to the application
	// contract required by this build. It is distinct from CodeDBUnavailable:
	// Postgres is reachable, but operator action is required before the
	// service can safely continue.
	CodeMigrationRequired Code = "E_MIGRATION_REQUIRED"
	// CodeSecretDecryption marks an internal failure to decrypt sealed
	// secret material. Public responses must keep this generic: they must
	// never expose plaintext, ciphertext bytes, key ids, provider ids, or
	// low-level cryptographic causes.
	CodeSecretDecryption Code = "E_SECRET_DECRYPTION"
	// CodeDriftReviewRequired marks a reconciliation path blocked because a
	// dangerous drift finding requires explicit human/operator review before
	// Yalla may continue with repair or provisioning.
	CodeDriftReviewRequired Code = "E_DRIFT_REVIEW_REQUIRED"
	// CodeUnavailable marks a failure caused by a Yalla-owned non-Postgres
	// dependency, such as the durable job queue, being temporarily unavailable.
	// It is distinct from Dokploy-specific upstream dependency codes.
	CodeUnavailable Code = "E_UNAVAILABLE"
	CodeTimeout     Code = "E_TIMEOUT"
	CodeCanceled    Code = "E_CANCELED"
	CodeNoInput     Code = "E_NO_INPUT_REQUIRED"
	CodeUnsupported Code = "E_UNSUPPORTED"
)

// CodeDoc is a single entry in the canonical error-code table emitted by
// `yalla manifest --json`. It pairs a stable code with its exit code and a
// short, agent-readable description so consumers can render diagnostic
// tables without scraping help text.
type CodeDoc struct {
	Code        string `json:"code"`
	ExitCode    int    `json:"exit_code"`
	Description string `json:"description"`
}

// codeDescriptions maps every stable Code to a one-line description. It is
// the source of truth for the manifest's error-code table; adding a new
// Code constant requires adding an entry here so the manifest stays
// complete (the manifest test enforces parity).
var codeDescriptions = map[Code]string{
	CodeUnknown:                "uncategorised internal failure",
	CodeInternal:               "internal error in yalla itself",
	CodeUsage:                  "command-line usage error (unknown flag, bad subcommand, etc.)",
	CodeValidation:             "request payload, path, or query parameter rejected by backend validation",
	CodeInvalidInput:           "request payload, flag value, or registry filter rejected",
	CodeConfig:                 "configuration is missing, malformed, or incomplete",
	CodeOrphan:                 "operation left Dokploy or Docker resources behind",
	CodeAuthenticationRequired: "authentication credentials are required for this request",
	CodeAuthInvalid:            "supplied authentication credentials are invalid",
	CodeAuthExpired:            "supplied authentication credentials have expired",
	CodeAuth:                   "supplied authentication credentials are invalid",
	CodeForbidden:              "credentials are valid but not authorised for the action",
	CodeScopeRequired:          "required organization or resource scope was not supplied",
	CodeNotFound:               "resource, operationId, or schema does not exist",
	CodeConflict:               "request rejected because of a precondition or state conflict",
	CodeJobNotClaimed:          "provisioning job outcome rejected because the worker does not hold the lease",
	CodeJobCancelled:           "provisioning job operation rejected because the job has been cancelled",
	CodeInvalidStateTransition: "requested lifecycle transition is not allowed by the resource state machine",
	CodeIdempotencyConflict:    "idempotency key reused for a request that differs from the original",
	CodeRateLimited:            "request rejected because the caller exceeded a request rate limit",
	CodeQuotaExceeded:          "request rejected because an organization quota or plan limit is exhausted",
	CodeUnsupportedServiceType: "requested service type is not supported by Yalla",
	CodeServer:                 "upstream Dokploy server returned an error",
	CodeDokployAuth:            "upstream Dokploy provisioning backend rejected Yalla credentials",
	CodeDokployForbidden:       "upstream Dokploy provisioning backend denied the requested operation",
	CodeDokployNotFound:        "upstream Dokploy provisioning backend could not find a required resource",
	CodeDokployConflict:        "upstream Dokploy provisioning backend reported a state conflict",
	CodeDokployRateLimited:     "upstream Dokploy provisioning backend is rate limiting Yalla requests",
	CodeDokployUnavailable:     "upstream Dokploy provisioning backend is temporarily unavailable",
	CodeDokployBadResponse:     "upstream Dokploy provisioning backend returned an incompatible response",
	CodeUpstreamBug:            "known upstream Dokploy bug encountered; use the documented workaround",
	CodeNetwork:                "transport-level network failure reaching Dokploy",
	CodeDBUnavailable:          "Yalla Postgres datastore is temporarily unavailable",
	CodeMigrationRequired:      "database migrations must be applied before the service can continue",
	CodeSecretDecryption:       "sealed secret material could not be decrypted",
	CodeDriftReviewRequired:    "drift reconciliation requires manual review before it can continue",
	CodeUnavailable:            "a Yalla-owned dependency, such as the job queue, is temporarily unavailable",
	CodeTimeout:                "request exceeded the configured timeout",
	CodeCanceled:               "context canceled (e.g. SIGINT)",
	CodeNoInput:                "interactive prompt required but --no-input was set",
	CodeUnsupported:            "operation not supported by the current build or transport",
}

// AllCodes returns the canonical, sorted list of every stable error code
// shipped by yalla together with its exit code and description. Used by
// `yalla manifest --json` to publish the table agents must switch on.
//
// The returned slice is freshly allocated on every call; callers may
// mutate it without bleeding back into the registry.
func AllCodes() []CodeDoc {
	codes := []Code{
		CodeUnknown, CodeInternal, CodeUsage, CodeValidation, CodeInvalidInput,
		CodeConfig, CodeOrphan, CodeAuthenticationRequired, CodeAuthInvalid, CodeAuthExpired, CodeAuth, CodeForbidden, CodeScopeRequired, CodeNotFound,
		CodeConflict, CodeJobNotClaimed, CodeJobCancelled, CodeInvalidStateTransition, CodeIdempotencyConflict, CodeRateLimited, CodeQuotaExceeded, CodeUnsupportedServiceType,
		CodeServer, CodeDokployAuth, CodeDokployForbidden, CodeDokployNotFound, CodeDokployConflict, CodeDokployRateLimited, CodeDokployUnavailable, CodeDokployBadResponse, CodeUpstreamBug,
		CodeNetwork, CodeDBUnavailable, CodeMigrationRequired, CodeSecretDecryption, CodeDriftReviewRequired, CodeUnavailable, CodeTimeout, CodeCanceled, CodeNoInput, CodeUnsupported,
	}
	out := make([]CodeDoc, 0, len(codes))
	for _, c := range codes {
		out = append(out, CodeDoc{
			Code:        string(c),
			ExitCode:    c.ExitCode(),
			Description: codeDescriptions[c],
		})
	}
	return out
}

// ExitCode returns the stable POSIX-style exit code the CLI uses for this
// error code. Scripts and agents may rely on these values; changing the map
// is a public-API change.
//
// 0   success
// 1   internal/unknown failure
// 2   usage / invalid input
// 3   configuration error
// 4   authentication or authorization failure
// 5   resource not found
// 6   conflict (precondition / state)
// 7   rate limited or quota exhausted (back off, retry, or raise the limit)
// 8   network / timeout / upstream server / dependency unavailable
// 9   --no-input was set but a prompt would be required
// 10  unsupported operation
// 130 canceled (POSIX SIGINT convention)
func (c Code) ExitCode() int {
	switch c {
	case "":
		return 0
	case CodeUsage, CodeValidation, CodeInvalidInput, CodeScopeRequired, CodeUnsupportedServiceType:
		return 2
	case CodeConfig, CodeOrphan, CodeMigrationRequired:
		return 3
	case CodeAuthenticationRequired, CodeAuthInvalid, CodeAuthExpired, CodeAuth, CodeForbidden:
		return 4
	case CodeNotFound:
		return 5
	case CodeConflict, CodeJobNotClaimed, CodeJobCancelled, CodeInvalidStateTransition, CodeIdempotencyConflict, CodeDriftReviewRequired:
		return 6
	case CodeRateLimited, CodeQuotaExceeded:
		return 7
	case CodeNetwork, CodeTimeout, CodeServer, CodeDokployAuth, CodeDokployForbidden, CodeDokployNotFound, CodeDokployConflict, CodeDokployRateLimited, CodeDokployUnavailable, CodeDokployBadResponse, CodeUpstreamBug, CodeDBUnavailable, CodeUnavailable:
		return 8
	case CodeNoInput:
		return 9
	case CodeUnsupported:
		return 10
	case CodeCanceled:
		return 130
	default: // CodeUnknown, CodeInternal, and any unrecognised future code
		return 1
	}
}

// Error is the canonical failure type returned from internal packages and the
// command tree. It carries a stable Code, a user-facing Message, an optional
// Hint that suggests a remedy, optional structured Details (small key/value
// metadata such as a precondition's current_version, a quota's limit, or a
// retry_after), and an optional underlying Cause so errors.Is/As traversal
// still works.
//
// Details is the agent-friendly counterpart to Hint: callers that wire a
// machine-readable failure context (for example, a stale write whose recovery
// path is "GET the current version, then retry") attach it here so the caller
// does not have to parse a human-readable string. Values must be free of
// secrets — the renderer treats Details the same way it treats Message and
// Hint and runs them through the redaction backstop, but the originating
// constructor remains responsible for not naming a token in the first place.
type Error struct {
	Code    Code
	Message string
	Hint    string
	Details map[string]string
	Cause   error
}

// New constructs a new typed error. Callers should prefer this over
// fmt.Errorf so the error carries a stable code through the rendering
// pipeline.
func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Newf is a printf-style convenience constructor.
func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithHint returns a copy of e with the supplied hint attached. Hints are
// optional, single-line, user-actionable text rendered alongside the message.
func (e *Error) WithHint(hint string) *Error {
	if e == nil {
		return nil
	}
	cp := *e
	cp.Hint = hint
	return &cp
}

// WithHintf is a printf-style variant of WithHint.
func (e *Error) WithHintf(format string, args ...any) *Error {
	return e.WithHint(fmt.Sprintf(format, args...))
}

// WithDetail returns a copy of e with the supplied key/value attached to its
// structured Details map. An empty key is dropped silently — Details is
// agent-readable metadata, and a blank key would corrupt a switch on the
// returned map. Existing values for the same key are overwritten so a caller
// can refine a detail attached upstream.
//
// The receiver's own Details map is never mutated; the copy carries an
// independent map so a single base error can be reused for multiple
// downstream annotations.
func (e *Error) WithDetail(key, value string) *Error {
	if e == nil {
		return nil
	}
	cp := *e
	if strings.TrimSpace(key) == "" {
		return &cp
	}
	merged := make(map[string]string, len(e.Details)+1)
	for k, v := range e.Details {
		merged[k] = v
	}
	merged[key] = value
	cp.Details = merged
	return &cp
}

// Wrap returns a copy of e annotated with an underlying cause. Code, Message,
// and Hint are preserved so the public-facing classification stays stable
// even when the cause changes.
func (e *Error) Wrap(cause error) *Error {
	if e == nil {
		return nil
	}
	cp := *e
	cp.Cause = cause
	return &cp
}

// Error renders the error in "code: message" form. This is intended for Go
// logs and error chains, not direct user display; the CLI renders the
// user-facing form via internal/output.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause so errors.Is / errors.As traversal
// works through Yalla's typed errors.
func (e *Error) Unwrap() error { return e.Cause }

// ExitCode delegates to Code.ExitCode and tolerates a nil receiver so the
// caller can skip nil-checking on the success path.
func (e *Error) ExitCode() int {
	if e == nil {
		return 0
	}
	return e.Code.ExitCode()
}

// From normalises an arbitrary error into a *Error. Errors that are already a
// *Error pass through unchanged. Cobra's plain errors for unknown commands,
// unknown flags, and missing arguments are mapped to CodeUsage (exit 2);
// everything else falls back to CodeInternal so scripts get a deterministic
// exit code.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var typed *Error
	if stderrors.As(err, &typed) {
		return typed
	}
	msg := err.Error()
	if isUsageMessage(msg) {
		return &Error{Code: CodeUsage, Message: msg, Cause: err}
	}
	return &Error{Code: CodeInternal, Message: msg, Cause: err}
}

// usagePrefixes are the plain-string heuristics used to detect Cobra's own
// pre-RunE errors. Cobra does not expose typed sentinels for these, so the
// shim matches on the documented messages it emits. The list is intentionally
// permissive — any uncategorised parsing failure is still preferable as
// CodeUsage than CodeInternal because it points at the caller, not the CLI.
var usagePrefixes = []string{
	"unknown command",
	"unknown flag",
	"unknown shorthand flag",
	"required flag",
	"invalid argument",
	"flag needs an argument",
	"accepts ", // "accepts N arg(s), received M"
	"bad flag syntax",
}

func isUsageMessage(msg string) bool {
	for _, p := range usagePrefixes {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
