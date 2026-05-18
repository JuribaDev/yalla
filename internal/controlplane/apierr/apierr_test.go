package apierr

import (
	stderrors "errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// TestCatalogStatusesAreDeterministicFailures asserts every catalogued code has
// a deterministic HTTP status, that the status matches apienvelope (the single
// source of truth), and that no error code maps to a non-failure status.
func TestCatalogStatusesAreDeterministicFailures(t *testing.T) {
	t.Parallel()

	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("Catalog() is empty")
	}
	for _, entry := range cat {
		if entry.Code == "" {
			t.Errorf("catalogue entry has an empty code: %+v", entry)
		}
		if want := apienvelope.StatusForCode(entry.Code); entry.HTTPStatus != want {
			t.Errorf("%s HTTPStatus = %d, want %d (apienvelope is the source of truth)",
				entry.Code, entry.HTTPStatus, want)
		}
		if entry.HTTPStatus < 400 {
			t.Errorf("%s maps to status %d, want a >= 400 failure status",
				entry.Code, entry.HTTPStatus)
		}
		if entry.MessagePolicy != MessageSpecific && entry.MessagePolicy != MessageGeneric {
			t.Errorf("%s has an unknown message policy %q", entry.Code, entry.MessagePolicy)
		}
		if entry.Description == "" {
			t.Errorf("%s has no description", entry.Code)
		}
	}
}

// TestCatalogIsSortedAndCoversCategories proves the catalogue is deterministic
// and covers every category named by the story: auth, policy, validation,
// quota, conflict, dependency failures, and internal failures.
func TestCatalogIsSortedAndCoversCategories(t *testing.T) {
	t.Parallel()

	cat := Catalog()
	for i := 1; i < len(cat); i++ {
		if cat[i-1].Code >= cat[i].Code {
			t.Fatalf("Catalog() not sorted: %s before %s", cat[i-1].Code, cat[i].Code)
		}
	}
	required := []yerr.Code{
		yerr.CodeAuthenticationRequired, yerr.CodeAuthInvalid, yerr.CodeAuthExpired, yerr.CodeAuth, yerr.CodeForbidden, yerr.CodeInvalidInput,
		yerr.CodeNotFound, yerr.CodeConflict, yerr.CodeInvalidStateTransition, yerr.CodeIdempotencyConflict,
		yerr.CodeQuotaExceeded,
		yerr.CodeServer, yerr.CodeUnavailable, yerr.CodeNetwork,
		yerr.CodeTimeout, yerr.CodeInternal,
	}
	for _, code := range required {
		if _, ok := Lookup(code); !ok {
			t.Errorf("taxonomy is missing required code %s", code)
		}
	}
}

func TestLookupUnknownCode(t *testing.T) {
	t.Parallel()

	if entry, ok := Lookup(yerr.Code("E_NOT_A_REAL_CODE")); ok {
		t.Errorf("Lookup of an unknown code returned ok with %+v", entry)
	}
}

// TestConstructorsEmitCataloguedCodes proves every constructor produces a code
// that is documented in the catalogue with the expected status.
func TestConstructorsEmitCataloguedCodes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        *yerr.Error
		wantCode   yerr.Code
		wantStatus int
	}{
		{"authentication required", AuthenticationRequired(), yerr.CodeAuthenticationRequired, 401},
		{"auth invalid", AuthInvalid(), yerr.CodeAuthInvalid, 401},
		{"auth expired", AuthExpired(), yerr.CodeAuthExpired, 401},
		{"unauthenticated", Unauthenticated(""), yerr.CodeAuth, 401},
		{"forbidden", Forbidden(""), yerr.CodeForbidden, 403},
		{"not found", NotFound("project", "p1"), yerr.CodeNotFound, 404},
		{"conflict", Conflict(""), yerr.CodeConflict, 409},
		{"invalid state transition", InvalidStateTransition("deployment", "queued", "succeeded"), yerr.CodeInvalidStateTransition, 409},
		{"idempotency conflict", IdempotencyConflict(""), yerr.CodeIdempotencyConflict, 409},
		{"invalid input", InvalidInput(FieldViolation{Field: "name", Reason: "required"}), yerr.CodeInvalidInput, 400},
		{"invalid", Invalid(""), yerr.CodeInvalidInput, 400},
		{"quota exceeded", QuotaExceeded("services", 5), yerr.CodeQuotaExceeded, 429},
		{"rate limited", RateLimited("organization", 3*time.Second), yerr.CodeRateLimited, 429},
		{"dokploy unavailable", DokployUnavailable(stderrors.New("x")), yerr.CodeServer, 502},
		{"store unavailable", StoreUnavailable(stderrors.New("x")), yerr.CodeUnavailable, 503},
		{"queue unavailable", QueueUnavailable(stderrors.New("x")), yerr.CodeUnavailable, 503},
		{"network failure", NetworkFailure(stderrors.New("x")), yerr.CodeNetwork, 502},
		{"timeout", Timeout(DependencyDokploy, stderrors.New("x")), yerr.CodeTimeout, 504},
		{"internal", Internal(stderrors.New("x")), yerr.CodeInternal, 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", tc.err.Code, tc.wantCode)
			}
			entry, ok := Lookup(tc.err.Code)
			if !ok {
				t.Fatalf("%s is not catalogued", tc.err.Code)
			}
			if entry.HTTPStatus != tc.wantStatus {
				t.Errorf("status = %d, want %d", entry.HTTPStatus, tc.wantStatus)
			}
			if tc.err.Message == "" {
				t.Errorf("%s produced an empty message", tc.name)
			}
		})
	}
}

func TestUnauthenticatedAndForbiddenDefaults(t *testing.T) {
	t.Parallel()

	if got := Unauthenticated(""); got.Message == "" {
		t.Error("Unauthenticated(\"\") must supply a default message")
	}
	if got := Unauthenticated("token expired"); got.Message != "token expired" {
		t.Errorf("Unauthenticated message = %q, want passthrough", got.Message)
	}
	if got := Forbidden(""); got.Message == "" {
		t.Error("Forbidden(\"\") must supply a default message")
	}
}

func TestAuthInvalidContract(t *testing.T) {
	t.Parallel()

	const leaked = "Authorization: Bearer yka_secret_token_value"
	err := AuthInvalid().WithHint("retry without " + leaked)
	if err.Code != yerr.CodeAuthInvalid {
		t.Fatalf("code = %q, want %q", err.Code, yerr.CodeAuthInvalid)
	}
	if err.Message != "the supplied credentials are invalid" {
		t.Fatalf("message = %q, want fixed generic invalid-credentials message", err.Message)
	}
	if entry, ok := Lookup(err.Code); !ok {
		t.Fatalf("%s is not catalogued", err.Code)
	} else {
		if entry.HTTPStatus != 401 {
			t.Errorf("HTTPStatus = %d, want 401", entry.HTTPStatus)
		}
		if entry.MessagePolicy != MessageGeneric {
			t.Errorf("MessagePolicy = %q, want %q", entry.MessagePolicy, MessageGeneric)
		}
	}

	rec := httptest.NewRecorder()
	apienvelope.WriteError(rec, "req-auth-invalid", err)
	body := rec.Body.String()
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, body)
	}
	if !strings.Contains(body, `"schema_version":"yalla.error.v1"`) ||
		!strings.Contains(body, `"request_id":"req-auth-invalid"`) ||
		!strings.Contains(body, apienvelope.DocURLForCode(yerr.CodeAuthInvalid)) {
		t.Errorf("envelope body missing schema, request id, or docs link: %s", body)
	}
	if strings.Contains(body, "yka_secret_token_value") || strings.Contains(body, "Bearer") {
		t.Errorf("auth invalid envelope leaked credential material: %s", body)
	}
}

func TestAuthExpiredContract(t *testing.T) {
	t.Parallel()

	const leaked = "Authorization: Bearer yka_expired_secret_token_value"
	err := AuthExpired().WithHint("refresh without " + leaked)
	if err.Code != yerr.CodeAuthExpired {
		t.Fatalf("code = %q, want %q", err.Code, yerr.CodeAuthExpired)
	}
	if err.Message != "authentication credentials have expired" {
		t.Fatalf("message = %q, want fixed expired-credentials message", err.Message)
	}
	if entry, ok := Lookup(err.Code); !ok {
		t.Fatalf("%s is not catalogued", err.Code)
	} else {
		if entry.HTTPStatus != 401 {
			t.Errorf("HTTPStatus = %d, want 401", entry.HTTPStatus)
		}
		if entry.MessagePolicy != MessageGeneric {
			t.Errorf("MessagePolicy = %q, want %q", entry.MessagePolicy, MessageGeneric)
		}
	}

	rec := httptest.NewRecorder()
	apienvelope.WriteError(rec, "req-auth-expired", err)
	body := rec.Body.String()
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, body)
	}
	if !strings.Contains(body, `"schema_version":"yalla.error.v1"`) ||
		!strings.Contains(body, `"request_id":"req-auth-expired"`) ||
		!strings.Contains(body, apienvelope.DocURLForCode(yerr.CodeAuthExpired)) {
		t.Errorf("envelope body missing schema, request id, or docs link: %s", body)
	}
	if strings.Contains(body, "yka_expired_secret_token_value") || strings.Contains(body, "Bearer") {
		t.Errorf("auth expired envelope leaked credential material: %s", body)
	}
}

func TestForbiddenContract(t *testing.T) {
	t.Parallel()

	err := Forbidden("  denied_no_capability  ").
		WithHint("do not retry with Authorization: Bearer forbidden-secret-token")
	if err.Code != yerr.CodeForbidden {
		t.Fatalf("code = %q, want %q", err.Code, yerr.CodeForbidden)
	}
	if err.Message != "denied_no_capability" {
		t.Fatalf("message = %q, want trimmed stable policy reason", err.Message)
	}
	if entry, ok := Lookup(err.Code); !ok {
		t.Fatalf("%s is not catalogued", err.Code)
	} else {
		if entry.HTTPStatus != 403 {
			t.Errorf("HTTPStatus = %d, want 403", entry.HTTPStatus)
		}
		if entry.MessagePolicy != MessageSpecific {
			t.Errorf("MessagePolicy = %q, want %q", entry.MessagePolicy, MessageSpecific)
		}
		if entry.Retryable {
			t.Error("E_FORBIDDEN must not be retryable")
		}
	}

	rec := httptest.NewRecorder()
	apienvelope.WriteError(rec, "req-forbidden", err)
	body := rec.Body.String()
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, body)
	}
	if !strings.Contains(body, `"schema_version":"yalla.error.v1"`) ||
		!strings.Contains(body, `"request_id":"req-forbidden"`) ||
		!strings.Contains(body, apienvelope.DocURLForCode(yerr.CodeForbidden)) {
		t.Errorf("envelope body missing schema, request id, or docs link: %s", body)
	}
	if strings.Contains(body, "forbidden-secret-token") || strings.Contains(body, "Bearer") {
		t.Errorf("forbidden envelope leaked credential material: %s", body)
	}
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("expected redaction sentinel %q in forbidden envelope: %s", output.Sentinel, body)
	}
}

// TestNotFoundEchoesCallerIdentifierOnly proves NotFound names the resource and
// reflects the caller-supplied id verbatim, and never invents one.
func TestNotFoundEchoesCallerIdentifierOnly(t *testing.T) {
	t.Parallel()

	withID := NotFound("project", "proj-123")
	if !strings.Contains(withID.Message, "project") || !strings.Contains(withID.Message, "proj-123") {
		t.Errorf("message = %q, want it to name the resource and the caller id", withID.Message)
	}
	blank := NotFound("", "")
	if blank.Message != "resource not found" {
		t.Errorf("NotFound(\"\",\"\") message = %q, want \"resource not found\"", blank.Message)
	}
}

// TestInvalidInputSortsViolationsAndExposesFieldPaths proves validation errors
// carry stable, deterministic field paths recoverable via ViolationsOf,
// independent of caller argument order, and that the hint lists those paths.
func TestInvalidInputSortsViolationsAndExposesFieldPaths(t *testing.T) {
	t.Parallel()

	err := InvalidInput(
		FieldViolation{Field: "  spec.replicas  ", Reason: " must be >= 1 "},
		FieldViolation{Field: "", Reason: ""}, // dropped
		FieldViolation{Field: "metadata.name", Reason: "required"},
	)
	if err.Code != yerr.CodeInvalidInput {
		t.Fatalf("code = %q, want E_INVALID_INPUT", err.Code)
	}
	violations, ok := ViolationsOf(err)
	if !ok {
		t.Fatal("ViolationsOf returned false for an InvalidInput error")
	}
	if len(violations) != 2 {
		t.Fatalf("violations = %+v, want 2 (blank entry dropped)", violations)
	}
	// Sorted by field path regardless of argument order; values trimmed.
	if violations[0].Field != "metadata.name" || violations[1].Field != "spec.replicas" {
		t.Errorf("violations not sorted by field path: %+v", violations)
	}
	if violations[1].Reason != "must be >= 1" {
		t.Errorf("reason not trimmed: %q", violations[1].Reason)
	}
	if !strings.Contains(err.Hint, "metadata.name") || !strings.Contains(err.Hint, "spec.replicas") {
		t.Errorf("hint = %q, want it to list both field paths", err.Hint)
	}
}

func TestInvalidInputWithNoUsableViolationsDegrades(t *testing.T) {
	t.Parallel()

	err := InvalidInput(FieldViolation{}, FieldViolation{Field: "  "})
	if err.Code != yerr.CodeInvalidInput {
		t.Fatalf("code = %q, want E_INVALID_INPUT", err.Code)
	}
	if _, ok := ViolationsOf(err); ok {
		t.Error("ViolationsOf must be false when no usable violations were supplied")
	}
	if err.Message == "" {
		t.Error("degraded InvalidInput must still carry a message")
	}
}

func TestViolationsOfAndDependencyOfReturnFalseForUnrelatedErrors(t *testing.T) {
	t.Parallel()

	plain := stderrors.New("boom")
	if _, ok := ViolationsOf(plain); ok {
		t.Error("ViolationsOf must be false for a non-validation error")
	}
	if _, ok := DependencyOf(plain); ok {
		t.Error("DependencyOf must be false for a non-dependency error")
	}
	if _, ok := ViolationsOf(Conflict("nope")); ok {
		t.Error("ViolationsOf must be false for a Conflict error")
	}
}

func TestQuotaExceeded(t *testing.T) {
	t.Parallel()

	withLimit := QuotaExceeded("services", 10)
	if !strings.Contains(withLimit.Message, "services") {
		t.Errorf("message = %q, want it to name the resource", withLimit.Message)
	}
	if !strings.Contains(withLimit.Hint, "10") {
		t.Errorf("hint = %q, want it to surface the limit", withLimit.Hint)
	}
	noLimit := QuotaExceeded("projects", 0)
	if noLimit.Hint != "" {
		t.Errorf("hint = %q, want empty when no positive limit is supplied", noLimit.Hint)
	}
}

// TestDependencyErrorsAreDistinguished proves every dependency failure is
// machine-distinguishable via DependencyOf — including the datastore and the
// queue, which deliberately share the E_UNAVAILABLE code.
func TestDependencyErrorsAreDistinguished(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      *yerr.Error
		wantDep  Dependency
		wantCode yerr.Code
	}{
		{"dokploy", DokployUnavailable(stderrors.New("x")), DependencyDokploy, yerr.CodeServer},
		{"store", StoreUnavailable(stderrors.New("x")), DependencyStore, yerr.CodeUnavailable},
		{"queue", QueueUnavailable(stderrors.New("x")), DependencyQueue, yerr.CodeUnavailable},
		{"network", NetworkFailure(stderrors.New("x")), DependencyNetwork, yerr.CodeNetwork},
		{"timeout", Timeout(DependencyStore, stderrors.New("x")), DependencyStore, yerr.CodeTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", tc.err.Code, tc.wantCode)
			}
			dep, ok := DependencyOf(tc.err)
			if !ok {
				t.Fatalf("DependencyOf returned false for %s", tc.name)
			}
			if dep != tc.wantDep {
				t.Errorf("dependency = %q, want %q", dep, tc.wantDep)
			}
		})
	}

	// The store and the queue share E_UNAVAILABLE but stay distinguishable.
	store, _ := DependencyOf(StoreUnavailable(stderrors.New("x")))
	queue, _ := DependencyOf(QueueUnavailable(stderrors.New("x")))
	if store == queue {
		t.Error("store and queue failures must be distinguishable despite sharing a code")
	}

	// Timeout with an unknown dependency wraps the cause directly.
	if _, ok := DependencyOf(Timeout("", stderrors.New("x"))); ok {
		t.Error("Timeout with no dependency must not report one")
	}
}

// TestGenericMessageCodesNeverEchoCause proves MessageGeneric constructors keep
// the cause out of the user-facing Message and Hint while still preserving it
// in the error chain for server-side logging.
func TestGenericMessageCodesNeverEchoCause(t *testing.T) {
	t.Parallel()

	const secret = "super-secret-token-9f3a2b1c"
	cause := stderrors.New("connect failed: Authorization: Bearer " + secret)

	cases := []struct {
		name string
		err  *yerr.Error
	}{
		{"internal", Internal(cause)},
		{"dokploy", DokployUnavailable(cause)},
		{"store", StoreUnavailable(cause)},
		{"queue", QueueUnavailable(cause)},
		{"network", NetworkFailure(cause)},
		{"timeout", Timeout(DependencyDokploy, cause)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry, ok := Lookup(tc.err.Code)
			if !ok || entry.MessagePolicy != MessageGeneric {
				t.Fatalf("%s expected a MessageGeneric code, got %+v ok=%v", tc.name, entry, ok)
			}
			if strings.Contains(tc.err.Message, secret) {
				t.Errorf("%s leaked the cause into Message: %q", tc.name, tc.err.Message)
			}
			if strings.Contains(tc.err.Hint, secret) {
				t.Errorf("%s leaked the cause into Hint: %q", tc.name, tc.err.Hint)
			}
			// The cause must still be reachable for server-side logging.
			if !stderrors.Is(tc.err, cause) {
				t.Errorf("%s dropped the cause from the error chain", tc.name)
			}
		})
	}
}

// TestEnvelopeRedactsSecretsFromSpecificMessages proves the apienvelope
// redaction backstop scrubs secrets even from a MessageSpecific error whose
// caller-supplied text accidentally carried a token.
func TestEnvelopeRedactsSecretsFromSpecificMessages(t *testing.T) {
	t.Parallel()

	const secret = "leaked-token-value-abc123"
	err := Conflict("rejected request carrying Authorization: Bearer " + secret)

	rec := httptest.NewRecorder()
	apienvelope.WriteError(rec, "req-redact", err)
	body := rec.Body.String()

	if strings.Contains(body, secret) {
		t.Errorf("envelope leaked a secret: %s", body)
	}
	if !strings.Contains(body, output.Sentinel) {
		t.Errorf("expected redaction sentinel %q in body: %s", output.Sentinel, body)
	}
}

func TestRetryable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"quota", QuotaExceeded("x", 1), true},
		{"dokploy", DokployUnavailable(stderrors.New("x")), true},
		{"store", StoreUnavailable(stderrors.New("x")), true},
		{"network", NetworkFailure(stderrors.New("x")), true},
		{"timeout", Timeout(DependencyStore, stderrors.New("x")), true},
		{"invalid", Invalid("bad"), false},
		{"forbidden", Forbidden(""), false},
		{"not found", NotFound("x", "y"), false},
		{"conflict", Conflict(""), false},
		{"internal", Internal(stderrors.New("x")), false},
		{"non-typed", stderrors.New("plain"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Retryable(tc.err); got != tc.want {
				t.Errorf("Retryable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFieldViolationString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		v    FieldViolation
		want string
	}{
		{FieldViolation{Field: "spec.replicas", Reason: "must be >= 1"}, "spec.replicas: must be >= 1"},
		{FieldViolation{Field: "spec.replicas"}, "spec.replicas: invalid"},
		{FieldViolation{Reason: "request is malformed"}, "request is malformed"},
		{FieldViolation{}, "invalid field"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("FieldViolation%+v.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// TestConflictStaleAttachesCurrentVersion proves ConflictStale renders an
// E_CONFLICT carrying the resource's authoritative version under the stable
// DetailKeyCurrentVersion key, recoverable round-trip via CurrentVersionOf.
// The Hint stays a fixed, non-secret remediation string so a leaked log line
// can never reflect business state.
func TestConflictStaleAttachesCurrentVersion(t *testing.T) {
	t.Parallel()

	err := ConflictStale(7)
	if err.Code != yerr.CodeConflict {
		t.Errorf("Code = %q, want E_CONFLICT", err.Code)
	}
	if err.Hint == "" {
		t.Error("Hint is empty, want a non-empty remediation string")
	}
	if got := err.Details[DetailKeyCurrentVersion]; got != "7" {
		t.Errorf("Details[%s] = %q, want \"7\"", DetailKeyCurrentVersion, got)
	}

	got, ok := CurrentVersionOf(err)
	if !ok {
		t.Fatal("CurrentVersionOf returned false for a ConflictStale error")
	}
	if got != 7 {
		t.Errorf("CurrentVersionOf = %d, want 7", got)
	}
}

// TestConflictStaleOmitsNonPositiveVersion proves a non-positive version is
// treated as "unknown" and the detail is omitted entirely — the schema CHECK
// guarantees a positive version, so a zero or negative value can only arise
// from a programming error and must not pretend to carry information.
func TestConflictStaleOmitsNonPositiveVersion(t *testing.T) {
	t.Parallel()

	for _, v := range []int64{0, -1, -42} {
		err := ConflictStale(v)
		if err.Code != yerr.CodeConflict {
			t.Errorf("ConflictStale(%d).Code = %q, want E_CONFLICT", v, err.Code)
		}
		if _, ok := err.Details[DetailKeyCurrentVersion]; ok {
			t.Errorf("ConflictStale(%d) attached a current_version detail; want it omitted", v)
		}
		if _, ok := CurrentVersionOf(err); ok {
			t.Errorf("CurrentVersionOf(ConflictStale(%d)) returned true; want false", v)
		}
	}
}

// TestCurrentVersionOfHandlesUnrelatedErrors proves the recovery helper
// returns false (and not, say, zero) for a plain Conflict, a non-typed
// error, and a nil receiver — so callers can switch on it safely.
func TestCurrentVersionOfHandlesUnrelatedErrors(t *testing.T) {
	t.Parallel()

	if _, ok := CurrentVersionOf(Conflict("plain")); ok {
		t.Error("CurrentVersionOf must be false for a plain Conflict error")
	}
	if _, ok := CurrentVersionOf(stderrors.New("boom")); ok {
		t.Error("CurrentVersionOf must be false for a non-typed error")
	}
	if _, ok := CurrentVersionOf(nil); ok {
		t.Error("CurrentVersionOf must be false for nil")
	}
}

// TestRateLimitedAttachesScopeAndRetryAfter proves the rate-limit error
// carries the bucket name and a positive whole-second retry hint via both
// the structured details map and a human hint. The bucket name is the only
// identity-related value that may reach the wire; the bucket identity (a
// specific org id, key id, or IP) never appears.
func TestRateLimitedAttachesScopeAndRetryAfter(t *testing.T) {
	t.Parallel()

	err := RateLimited("organization", 2500*time.Millisecond)
	if err.Code != yerr.CodeRateLimited {
		t.Fatalf("Code = %q, want E_RATE_LIMITED", err.Code)
	}
	if !strings.Contains(err.Message, "organization") {
		t.Errorf("Message = %q, want it to name the bucket scope", err.Message)
	}
	if got := err.Details[DetailKeyRateLimitScope]; got != "organization" {
		t.Errorf("scope detail = %q, want organization", got)
	}
	// 2.5s rounds up to 3 whole seconds so a client never sees a sub-second
	// instruction it cannot act on through an integer Retry-After header.
	if got := err.Details[DetailKeyRetryAfter]; got != "3" {
		t.Errorf("retry_after detail = %q, want 3", got)
	}
	if v, ok := RetryAfterOf(err); !ok || v != 3 {
		t.Errorf("RetryAfterOf = (%d, %v), want (3, true)", v, ok)
	}
}

// TestRateLimitedClampsNonPositiveRetryAfter proves a zero or negative
// retry-after collapses to one second so the wire always carries an
// actionable instruction. A blank scope falls back to a generic label.
func TestRateLimitedClampsNonPositiveRetryAfter(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second, -100 * time.Millisecond} {
		err := RateLimited("", d)
		if got := err.Details[DetailKeyRetryAfter]; got != "1" {
			t.Errorf("RateLimited(%s) retry_after = %q, want 1", d, got)
		}
		if got := err.Details[DetailKeyRateLimitScope]; got != "caller" {
			t.Errorf("RateLimited(empty scope) = %q, want caller", got)
		}
		if !strings.Contains(err.Message, "caller") {
			t.Errorf("Message = %q, want it to name the generic fallback scope", err.Message)
		}
	}
}

// TestRateLimitedDoesNotEchoSecretScope proves the scope label is the only
// identity-related value on the wire. The constructor strips whitespace
// but otherwise places scope into the message verbatim, so the call site
// is responsible for passing a bucket dimension ("organization", "api_key",
// "ip") rather than a tenant id, an API key id, or an IP address. The
// envelope's regex-based redaction still scrubs any header-style secret if
// it ever reaches this layer.
func TestRateLimitedDoesNotEchoSecretScope(t *testing.T) {
	t.Parallel()

	err := RateLimited("  api_key  ", time.Second)
	if got := err.Details[DetailKeyRateLimitScope]; got != "api_key" {
		t.Errorf("scope detail = %q, want trimmed api_key", got)
	}
	body := strings.Join([]string{
		err.Message,
		err.Hint,
		err.Details[DetailKeyRateLimitScope],
		err.Details[DetailKeyRetryAfter],
	}, "|")
	for _, leak := range []string{"Bearer", "Authorization:", "yk_"} {
		if strings.Contains(body, leak) {
			t.Errorf("RateLimited rendering leaked a credential-shaped token %q in %q", leak, body)
		}
	}
}

// TestRetryAfterOfHandlesUnrelatedErrors proves the recovery helper returns
// false for a non-typed error, a typed error of a different code, and a
// nil receiver — so callers can switch on it safely.
func TestRetryAfterOfHandlesUnrelatedErrors(t *testing.T) {
	t.Parallel()

	if _, ok := RetryAfterOf(Conflict("plain")); ok {
		t.Error("RetryAfterOf must be false for a non-rate-limited error")
	}
	if _, ok := RetryAfterOf(stderrors.New("boom")); ok {
		t.Error("RetryAfterOf must be false for a non-typed error")
	}
	if _, ok := RetryAfterOf(nil); ok {
		t.Error("RetryAfterOf must be false for nil")
	}
}
