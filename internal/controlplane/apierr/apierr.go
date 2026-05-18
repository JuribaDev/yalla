// Package apierr is the Yalla Control Plane backend error taxonomy. It is the
// single place where backend code constructs the typed errors that handlers,
// workers, and the provisioner return, so the wire contract — stable error
// codes, deterministic HTTP statuses, message-redaction policy, and retry
// semantics — stays consistent across every endpoint.
//
// Every constructor returns a *yerr.Error so the value flows straight into
// apienvelope.WriteError; this package never renders JSON itself. The codes it
// emits are the codes catalogued here, and the catalogue is the documented
// source of truth:
//
//   - Auth / policy:        AuthenticationRequired, Unauthenticated, Forbidden
//   - Validation:           InvalidInput (with field paths), Invalid
//   - Not found / conflict: NotFound, Conflict
//   - Quota:                QuotaExceeded
//   - Dependency failures:  DokployUnavailable, StoreUnavailable,
//     QueueUnavailable, NetworkFailure, Timeout — each distinguishes which
//     dependency failed via DependencyOf.
//   - Internal:             Internal
//
// Two cross-cutting guarantees back the taxonomy:
//
//   - Message policy. Codes are either MessageSpecific (the Message may
//     describe the specific failure because it only contains classification or
//     caller-supplied, non-sensitive text) or MessageGeneric (the Message is a
//     fixed, generic string; the real cause is preserved only as the wrapped
//     error for server-side logging and is never echoed to the client).
//   - Field paths without values. A FieldViolation carries a stable dotted
//     field path and a human reason — never the submitted value — so validation
//     errors can name the offending field without leaking secrets.
//
// HTTP status is intentionally not stored in this package: it is derived from
// apienvelope.StatusForCode so the code-to-status mapping has exactly one
// source of truth.
package apierr

import (
	stderrors "errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// DetailKeyCurrentVersion is the stable details key carried on a stale-write
// E_CONFLICT (built by ConflictStale): it surfaces the resource's
// authoritative version so the caller can re-issue the request with a fresh
// If-Match header without an extra GET. The value is a base-10 integer
// rendered as a string so the wire shape stays JSON-friendly across clients
// that lack a 64-bit numeric type.
const DetailKeyCurrentVersion = "current_version"

// DetailKeyRetryAfter is the stable details key carried on a rate-limited
// 429 E_RATE_LIMITED (built by RateLimited): it tells the caller how many
// whole seconds to wait before issuing the next attempt. The value is a
// base-10 integer rendered as a string so the wire shape stays JSON-friendly
// across clients that lack a 64-bit numeric type, and it mirrors the
// integer value of the Retry-After response header the middleware sets.
const DetailKeyRetryAfter = "retry_after"

// DetailKeyRateLimitScope is the stable details key naming the limiter
// bucket that throttled the request — "organization", "api_key", or "ip".
// The bucket identity (org id, key id, IP address) is never echoed; only
// the bucket dimension, so a 429 cannot leak who else shares the bucket.
const DetailKeyRateLimitScope = "scope"

// MessagePolicy classifies whether an error code's user-facing Message is
// allowed to describe the specific failure.
type MessagePolicy string

const (
	// MessageSpecific marks codes whose Message may describe the specific
	// failure. The text is limited to classification or caller-supplied,
	// non-sensitive values (a field path, a resource name), so it is safe to
	// place on the wire.
	MessageSpecific MessagePolicy = "specific"
	// MessageGeneric marks codes whose Message must remain a fixed, generic
	// string. The real cause is preserved only as the wrapped error for
	// server-side logging and must never be interpolated into the Message.
	MessageGeneric MessagePolicy = "generic"
)

// Dependency identifies the backend dependency that caused a failure. It lets
// callers distinguish a Dokploy outage from a datastore, job-queue, or generic
// network failure even when several share the same error Code.
type Dependency string

const (
	// DependencyDokploy is the upstream Dokploy provisioning backend.
	DependencyDokploy Dependency = "dokploy"
	// DependencyStore is the Yalla-owned Postgres datastore.
	DependencyStore Dependency = "postgres"
	// DependencyQueue is the Yalla-owned durable job queue.
	DependencyQueue Dependency = "queue"
	// DependencyNetwork is an unclassified transport-level network failure.
	DependencyNetwork Dependency = "network"
)

// CatalogEntry documents one error code in the backend taxonomy.
type CatalogEntry struct {
	// Code is the stable, machine-readable error identifier.
	Code yerr.Code
	// HTTPStatus is the deterministic HTTP status the API returns for Code. It
	// is derived from apienvelope.StatusForCode, never stored independently.
	HTTPStatus int
	// Retryable reports whether the same request may succeed on a later retry
	// (transient failures: dependency outages, timeouts, rate/quota limits).
	Retryable bool
	// MessagePolicy states whether the user-facing Message may be specific.
	MessagePolicy MessagePolicy
	// Description is a one-line, agent-readable explanation of the code.
	Description string
}

// taxonomy is the source-of-truth backend error taxonomy. HTTP status is
// excluded on purpose — Lookup derives it from apienvelope.StatusForCode.
var taxonomy = map[yerr.Code]struct {
	retryable   bool
	policy      MessagePolicy
	description string
}{
	yerr.CodeInvalidInput:           {false, MessageSpecific, "request payload, path, or query parameter was rejected by validation"},
	yerr.CodeAuthenticationRequired: {false, MessageSpecific, "no usable authentication credentials were supplied"},
	yerr.CodeAuth:                   {false, MessageSpecific, "authentication credentials were supplied but could not be authenticated"},
	yerr.CodeForbidden:              {false, MessageSpecific, "the principal is authenticated but not authorized for the action"},
	yerr.CodeNotFound:               {false, MessageSpecific, "the requested resource does not exist or is not visible to the principal"},
	yerr.CodeConflict:               {false, MessageSpecific, "the request conflicts with the current state of the resource"},
	yerr.CodeInvalidStateTransition: {false, MessageSpecific, "the requested lifecycle transition is not allowed by the resource state machine"},
	yerr.CodeIdempotencyConflict:    {false, MessageSpecific, "an idempotency key was reused for a request that differs from the original"},
	yerr.CodeQuotaExceeded:          {true, MessageSpecific, "an organization quota or plan limit is exhausted"},
	yerr.CodeRateLimited:            {true, MessageSpecific, "the caller exceeded a request rate limit; back off and retry"},
	yerr.CodeUnsupported:            {false, MessageSpecific, "the requested operation is not supported by this build"},
	yerr.CodeServer:                 {true, MessageGeneric, "the upstream Dokploy provisioning backend returned an error"},
	yerr.CodeUpstreamBug:            {false, MessageGeneric, "a known upstream Dokploy defect was encountered"},
	yerr.CodeUnavailable:            {true, MessageGeneric, "a Yalla-owned dependency (datastore or job queue) is temporarily unavailable"},
	yerr.CodeNetwork:                {true, MessageGeneric, "a network failure occurred while contacting a dependency"},
	yerr.CodeTimeout:                {true, MessageGeneric, "a dependency call exceeded its timeout"},
	yerr.CodeCanceled:               {false, MessageGeneric, "the request was canceled before completion"},
	yerr.CodeConfig:                 {false, MessageGeneric, "the service is misconfigured"},
	yerr.CodeInternal:               {false, MessageGeneric, "an unexpected internal error occurred"},
	yerr.CodeUnknown:                {false, MessageGeneric, "an unclassified internal error occurred"},
}

// Lookup returns the catalogue entry for code. The boolean is false for any
// code outside the backend taxonomy.
func Lookup(code yerr.Code) (CatalogEntry, bool) {
	t, ok := taxonomy[code]
	if !ok {
		return CatalogEntry{}, false
	}
	return CatalogEntry{
		Code:          code,
		HTTPStatus:    apienvelope.StatusForCode(code),
		Retryable:     t.retryable,
		MessagePolicy: t.policy,
		Description:   t.description,
	}, true
}

// Catalog returns the full backend error taxonomy sorted by code. The slice is
// freshly allocated on every call, so callers may mutate it freely.
func Catalog() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(taxonomy))
	for code := range taxonomy {
		entry, _ := Lookup(code)
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Retryable reports whether err carries a catalogued, retryable error code.
// Non-typed errors and codes outside the taxonomy are treated as non-retryable.
func Retryable(err error) bool {
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		return false
	}
	entry, ok := Lookup(ye.Code)
	return ok && entry.Retryable
}

// FieldViolation describes a single rejected request field. Field is a stable
// dotted path such as "spec.replicas" or "metadata.name"; Reason is a short,
// human-readable explanation. Neither field ever carries the submitted value,
// so a FieldViolation is always safe to place in a client-facing envelope, a
// log record, or audit metadata.
type FieldViolation struct {
	Field  string
	Reason string
}

// String renders the violation as "field: reason", tolerating an empty field
// or reason without producing misleading output.
func (v FieldViolation) String() string {
	switch {
	case v.Field == "" && v.Reason == "":
		return "invalid field"
	case v.Field == "":
		return v.Reason
	case v.Reason == "":
		return v.Field + ": invalid"
	default:
		return v.Field + ": " + v.Reason
	}
}

// validationError is wrapped as the cause of an InvalidInput error so callers
// can recover the structured violations via ViolationsOf without parsing the
// human-readable message.
type validationError struct {
	violations []FieldViolation
}

func (e *validationError) Error() string {
	parts := make([]string, len(e.violations))
	for i, v := range e.violations {
		parts[i] = v.String()
	}
	return "request validation failed: " + strings.Join(parts, "; ")
}

// ViolationsOf returns the field violations attached to err by InvalidInput.
// The boolean is false when err was not built from field violations. The
// returned slice is a copy and is safe to mutate.
func ViolationsOf(err error) ([]FieldViolation, bool) {
	var ve *validationError
	if stderrors.As(err, &ve) {
		return append([]FieldViolation(nil), ve.violations...), true
	}
	return nil, false
}

// dependencyError is wrapped as the cause of a dependency-failure error so
// callers can recover which dependency failed via DependencyOf, even when two
// dependencies (datastore and queue) share the same error Code. Its own cause
// is the underlying transport/driver error, kept for server-side logging only.
type dependencyError struct {
	dep   Dependency
	cause error
}

func (e *dependencyError) Error() string {
	if e.cause != nil {
		return "dependency " + string(e.dep) + " failure: " + e.cause.Error()
	}
	return "dependency " + string(e.dep) + " failure"
}

func (e *dependencyError) Unwrap() error { return e.cause }

// DependencyOf reports which backend dependency caused err, when err was built
// by one of this package's dependency constructors.
func DependencyOf(err error) (Dependency, bool) {
	var de *dependencyError
	if stderrors.As(err, &de) {
		return de.dep, true
	}
	return "", false
}

// AuthenticationRequired builds an E_AUTHENTICATION_REQUIRED error (HTTP 401)
// for requests that supplied no usable credential. It has a fixed public
// message and no hint because recovery is structurally obvious: authenticate
// the request.
func AuthenticationRequired() *yerr.Error {
	return yerr.New(yerr.CodeAuthenticationRequired, "authentication is required")
}

// Unauthenticated builds an E_AUTH error (HTTP 401) for supplied credentials
// that failed to authenticate. message may describe the authentication
// problem; it must never contain the supplied credential.
func Unauthenticated(message string) *yerr.Error {
	if strings.TrimSpace(message) == "" {
		message = "the supplied credentials are invalid"
	}
	return yerr.New(yerr.CodeAuth, message)
}

// Forbidden builds an E_FORBIDDEN error (HTTP 403) for an authenticated
// principal that lacks authorization for the requested action.
func Forbidden(message string) *yerr.Error {
	if strings.TrimSpace(message) == "" {
		message = "not authorized to perform this action"
	}
	return yerr.New(yerr.CodeForbidden, message)
}

// NotFound builds an E_NOT_FOUND error (HTTP 404). resource is the kind of
// thing that was missing (for example "project"); id is the caller-supplied
// identifier and is echoed back verbatim — callers must pass the request's own
// identifier so the response never reflects another tenant's data.
func NotFound(resource, id string) *yerr.Error {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		resource = "resource"
	}
	if strings.TrimSpace(id) == "" {
		return yerr.Newf(yerr.CodeNotFound, "%s not found", resource)
	}
	return yerr.Newf(yerr.CodeNotFound, "%s %q not found", resource, id)
}

// Conflict builds an E_CONFLICT error (HTTP 409) for a request that collides
// with the current state of a resource.
func Conflict(message string) *yerr.Error {
	if strings.TrimSpace(message) == "" {
		message = "request conflicts with the current resource state"
	}
	return yerr.New(yerr.CodeConflict, message)
}

// InvalidStateTransition builds an E_INVALID_STATE_TRANSITION error (HTTP 409)
// for a lifecycle edge rejected by a resource's documented state machine.
func InvalidStateTransition(resource, from, to string) *yerr.Error {
	resource = strings.TrimSpace(resource)
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if resource == "" {
		resource = "resource"
	}
	message := "invalid state transition"
	if from != "" && to != "" {
		message = resource + " cannot transition from " + from + " to " + to
	}
	return yerr.New(yerr.CodeInvalidStateTransition, message).
		WithDetail("resource", resource).
		WithDetail("previous_state", from).
		WithDetail("next_state", to)
}

// ConflictStale builds an E_CONFLICT error (HTTP 409) for a stale write —
// the caller's expected version (typically the strong ETag carried in the
// If-Match request header) does not match the resource's current version.
// The current version is attached as structured details under
// DetailKeyCurrentVersion so the caller can re-issue the request with a
// fresh If-Match header without an extra GET. A non-positive currentVersion
// is treated as "unknown" and the detail is omitted: the version sequence is
// always strictly positive (the schema CHECK guarantees it), so a zero or
// negative value can only arise from a programming error.
func ConflictStale(currentVersion int64) *yerr.Error {
	e := yerr.New(yerr.CodeConflict, "request is based on a stale version of the resource").
		WithHint("re-fetch the resource and retry with the current version in the If-Match header")
	if currentVersion <= 0 {
		return e
	}
	return e.WithDetail(DetailKeyCurrentVersion, strconv.FormatInt(currentVersion, 10))
}

// CurrentVersionOf returns the resource's authoritative version attached to a
// stale-write E_CONFLICT by ConflictStale. The boolean is false when err
// carries no version detail (it was not built by ConflictStale, the
// ConflictStale call had no usable version, or the value is unparseable). The
// caller never needs to parse the human-readable Hint to recover the version.
func CurrentVersionOf(err error) (int64, bool) {
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye == nil {
		return 0, false
	}
	raw, ok := ye.Details[DetailKeyCurrentVersion]
	if !ok {
		return 0, false
	}
	v, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// IdempotencyConflict builds an E_IDEMPOTENCY_CONFLICT error (HTTP 409) for a
// request that reused an idempotency key for a request that does not match the
// one the key was first claimed for. The message may describe the conflict but
// must never echo a request body or a secret. A fixed hint tells the client
// how to recover: replay the original request unchanged, or choose a fresh
// key.
func IdempotencyConflict(message string) *yerr.Error {
	if strings.TrimSpace(message) == "" {
		message = "the idempotency key was already used for a different request"
	}
	return yerr.New(yerr.CodeIdempotencyConflict, message).
		WithHint("replay the original request unchanged, or retry with a new Idempotency-Key")
}

// InvalidInput builds an E_INVALID_INPUT error (HTTP 400) from one or more
// field violations. Violations are de-duplicated of blank entries and sorted
// deterministically so the message, hint, and recovered slice never depend on
// caller argument order. The structured violations are recoverable via
// ViolationsOf. With no usable violations it degrades to a generic invalid
// request, equivalent to Invalid.
func InvalidInput(violations ...FieldViolation) *yerr.Error {
	cleaned := make([]FieldViolation, 0, len(violations))
	for _, v := range violations {
		v.Field = strings.TrimSpace(v.Field)
		v.Reason = strings.TrimSpace(v.Reason)
		if v.Field == "" && v.Reason == "" {
			continue
		}
		cleaned = append(cleaned, v)
	}
	if len(cleaned) == 0 {
		return Invalid("")
	}
	sort.SliceStable(cleaned, func(i, j int) bool {
		if cleaned[i].Field != cleaned[j].Field {
			return cleaned[i].Field < cleaned[j].Field
		}
		return cleaned[i].Reason < cleaned[j].Reason
	})
	parts := make([]string, len(cleaned))
	for i, v := range cleaned {
		parts[i] = v.String()
	}
	return yerr.New(yerr.CodeInvalidInput, "request validation failed").
		WithHint(strings.Join(parts, "; ")).
		Wrap(&validationError{violations: cleaned})
}

// Invalid builds an E_INVALID_INPUT error (HTTP 400) from a free-form message,
// for validation failures that are not tied to a specific request field. The
// message must not contain the submitted value of any secret field.
func Invalid(message string) *yerr.Error {
	if strings.TrimSpace(message) == "" {
		message = "request is invalid"
	}
	return yerr.New(yerr.CodeInvalidInput, message)
}

// RateLimited builds an E_RATE_LIMITED error (HTTP 429) for a request that
// exceeded a throughput cap on one of the limiter's buckets (organization,
// API key, or IP). scope names the bucket dimension and is the only
// identity-related value that reaches the wire; retryAfter is exposed both
// as a structured DetailKeyRetryAfter detail (whole seconds) and as a hint,
// and matches the integer the middleware writes into the Retry-After
// response header.
//
// A blank scope is replaced by a generic "caller" label so the message
// never lies about which bucket throttled the request, and a non-positive
// retryAfter is clamped to one second so a client never sees a "retry in
// 0 seconds" instruction it cannot act on.
func RateLimited(scope string, retryAfter time.Duration) *yerr.Error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "caller"
	}
	seconds := int64(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return yerr.Newf(yerr.CodeRateLimited, "rate limit exceeded for %s", scope).
		WithHintf("retry after %d second(s)", seconds).
		WithDetail(DetailKeyRateLimitScope, scope).
		WithDetail(DetailKeyRetryAfter, strconv.FormatInt(seconds, 10))
}

// RetryAfterOf returns the integer retry_after seconds attached to err by
// RateLimited. The second return is false when err is nil, not a typed
// E_RATE_LIMITED, or carries no retry_after detail — so callers can switch
// on presence and never act on a zero value as if it were a real delay.
func RetryAfterOf(err error) (int64, bool) {
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye == nil {
		return 0, false
	}
	if ye.Code != yerr.CodeRateLimited {
		return 0, false
	}
	raw, ok := ye.Details[DetailKeyRetryAfter]
	if !ok || raw == "" {
		return 0, false
	}
	v, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil {
		return 0, false
	}
	return v, true
}

// QuotaExceeded builds an E_QUOTA_EXCEEDED error (HTTP 429) for a request that
// would exceed an organization quota or plan limit. resource names the limited
// resource; a positive limit is surfaced as a hint.
func QuotaExceeded(resource string, limit int64) *yerr.Error {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		resource = "resource"
	}
	e := yerr.Newf(yerr.CodeQuotaExceeded, "quota exceeded for %s", resource)
	if limit > 0 {
		e = e.WithHintf("the configured limit is %d; release usage or request a higher quota", limit)
	}
	return e
}

// DokployUnavailable builds an E_SERVER error (HTTP 502) for a failed call to
// the upstream Dokploy provisioning backend. The cause is preserved for
// server-side logging via Unwrap but is never echoed in the Message.
func DokployUnavailable(cause error) *yerr.Error {
	return yerr.New(yerr.CodeServer, "the Dokploy provisioning backend is unavailable").
		WithHint("this is a transient upstream failure; retry after a short backoff").
		Wrap(&dependencyError{dep: DependencyDokploy, cause: cause})
}

// StoreUnavailable builds an E_UNAVAILABLE error (HTTP 503) for a failed call
// to the Yalla Postgres datastore. The cause is preserved via Unwrap only.
func StoreUnavailable(cause error) *yerr.Error {
	return yerr.New(yerr.CodeUnavailable, "the Yalla datastore is temporarily unavailable").
		WithHint("this is a transient failure; retry after a short backoff").
		Wrap(&dependencyError{dep: DependencyStore, cause: cause})
}

// QueueUnavailable builds an E_UNAVAILABLE error (HTTP 503) for a failed call
// to the Yalla durable job queue. The cause is preserved via Unwrap only.
func QueueUnavailable(cause error) *yerr.Error {
	return yerr.New(yerr.CodeUnavailable, "the Yalla job queue is temporarily unavailable").
		WithHint("this is a transient failure; retry after a short backoff").
		Wrap(&dependencyError{dep: DependencyQueue, cause: cause})
}

// NetworkFailure builds an E_NETWORK error (HTTP 502) for an unclassified
// transport-level failure while contacting a dependency. The cause is preserved
// via Unwrap only.
func NetworkFailure(cause error) *yerr.Error {
	return yerr.New(yerr.CodeNetwork, "a network failure occurred while contacting an upstream dependency").
		WithHint("this is a transient failure; retry after a short backoff").
		Wrap(&dependencyError{dep: DependencyNetwork, cause: cause})
}

// Timeout builds an E_TIMEOUT error (HTTP 504) for a dependency call that
// exceeded its deadline. dep records which dependency timed out (recoverable
// via DependencyOf); pass an empty Dependency when it is not known. The cause
// is preserved via Unwrap only.
func Timeout(dep Dependency, cause error) *yerr.Error {
	e := yerr.New(yerr.CodeTimeout, "a dependency call exceeded its timeout").
		WithHint("this is a transient failure; retry after a short backoff")
	if dep == "" {
		return e.Wrap(cause)
	}
	return e.Wrap(&dependencyError{dep: dep, cause: cause})
}

// Internal builds an E_INTERNAL error (HTTP 500) for an unexpected failure. The
// Message is a fixed, generic string; cause is preserved via Unwrap for
// server-side logging and is never echoed to the client.
func Internal(cause error) *yerr.Error {
	return yerr.New(yerr.CodeInternal, "an internal error occurred").Wrap(cause)
}
