package errors

import (
	stderrors "errors"
	"fmt"
	"testing"
)

func TestCode_ExitCodeMappingIsStable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code Code
		want int
	}{
		{"", 0},
		{CodeUsage, 2},
		{CodeValidation, 2},
		{CodeInvalidInput, 2},
		{CodeConfig, 3},
		{CodeOrphan, 3},
		{CodeMigrationRequired, 3},
		{CodeAuthenticationRequired, 4},
		{CodeAuthInvalid, 4},
		{CodeAuthExpired, 4},
		{CodeAuth, 4},
		{CodeForbidden, 4},
		{CodeScopeRequired, 2},
		{CodeNotFound, 5},
		{CodeConflict, 6},
		{CodeInvalidStateTransition, 6},
		{CodeIdempotencyConflict, 6},
		{CodeRateLimited, 7},
		{CodeQuotaExceeded, 7},
		{CodeNetwork, 8},
		{CodeTimeout, 8},
		{CodeServer, 8},
		{CodeDokployAuth, 8},
		{CodeDokployForbidden, 8},
		{CodeDokployNotFound, 8},
		{CodeDokployConflict, 8},
		{CodeDokployRateLimited, 8},
		{CodeDokployUnavailable, 8},
		{CodeDokployBadResponse, 8},
		{CodeUpstreamBug, 8},
		{CodeDBUnavailable, 8},
		{CodeUnavailable, 8},
		{CodeNoInput, 9},
		{CodeUnsupported, 10},
		{CodeCanceled, 130},
		{CodeUnknown, 1},
		{CodeInternal, 1},
		{Code("E_FUTURE_VALUE"), 1},
	}
	for _, tc := range cases {
		if got := tc.code.ExitCode(); got != tc.want {
			t.Errorf("Code(%q).ExitCode() = %d, want %d", tc.code, got, tc.want)
		}
	}
}

func TestDBUnavailableDescriptionNamesPostgresOutage(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDBUnavailable) {
			got = doc.Description
			break
		}
	}
	const want = "Yalla Postgres datastore is temporarily unavailable"
	if got != want {
		t.Fatalf("E_DB_UNAVAILABLE description = %q, want %q", got, want)
	}
}

func TestMigrationRequiredDescriptionNamesSchemaMismatch(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeMigrationRequired) {
			got = doc.Description
			break
		}
	}
	const want = "database migrations must be applied before the service can continue"
	if got != want {
		t.Fatalf("E_MIGRATION_REQUIRED description = %q, want %q", got, want)
	}
}

func TestDokployAuthDescriptionNamesUpstreamCredentialRejection(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployAuth) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend rejected Yalla credentials"
	if got != want {
		t.Fatalf("E_DOKPLOY_AUTH description = %q, want %q", got, want)
	}
}

func TestDokployNotFoundDescriptionNamesUpstreamMissingResource(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployNotFound) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend could not find a required resource"
	if got != want {
		t.Fatalf("E_DOKPLOY_NOT_FOUND description = %q, want %q", got, want)
	}
}

func TestDokployForbiddenDescriptionNamesUpstreamPermissionRejection(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployForbidden) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend denied the requested operation"
	if got != want {
		t.Fatalf("E_DOKPLOY_FORBIDDEN description = %q, want %q", got, want)
	}
}

func TestDokployConflictDescriptionNamesUpstreamStateConflict(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployConflict) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend reported a state conflict"
	if got != want {
		t.Fatalf("E_DOKPLOY_CONFLICT description = %q, want %q", got, want)
	}
}

func TestDokployUnavailableDescriptionNamesUpstreamOutage(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployUnavailable) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend is temporarily unavailable"
	if got != want {
		t.Fatalf("E_DOKPLOY_UNAVAILABLE description = %q, want %q", got, want)
	}
}

func TestDokployBadResponseDescriptionNamesUpstreamContractMismatch(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployBadResponse) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend returned an incompatible response"
	if got != want {
		t.Fatalf("E_DOKPLOY_BAD_RESPONSE description = %q, want %q", got, want)
	}
}

func TestDokployRateLimitedDescriptionNamesUpstreamThrottle(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeDokployRateLimited) {
			got = doc.Description
			break
		}
	}
	const want = "upstream Dokploy provisioning backend is rate limiting Yalla requests"
	if got != want {
		t.Fatalf("E_DOKPLOY_RATE_LIMITED description = %q, want %q", got, want)
	}
}

func TestRateLimitedDescriptionNamesCallerRateLimit(t *testing.T) {
	t.Parallel()

	var got string
	for _, doc := range AllCodes() {
		if doc.Code == string(CodeRateLimited) {
			got = doc.Description
			break
		}
	}
	const want = "request rejected because the caller exceeded a request rate limit"
	if got != want {
		t.Fatalf("E_RATE_LIMITED description = %q, want %q", got, want)
	}
}

func TestNewAndError(t *testing.T) {
	t.Parallel()
	e := New(CodeNotFound, "project foo not found")
	if e.Code != CodeNotFound {
		t.Fatalf("Code = %q, want %q", e.Code, CodeNotFound)
	}
	if got, want := e.Error(), "E_NOT_FOUND: project foo not found"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestNewfFormatsMessage(t *testing.T) {
	t.Parallel()
	e := Newf(CodeInvalidInput, "field %q out of range [%d,%d]", "port", 1, 65535)
	if got, want := e.Message, `field "port" out of range [1,65535]`; got != want {
		t.Errorf("Message = %q, want %q", got, want)
	}
}

func TestErrorEmptyMessageRendersCodeOnly(t *testing.T) {
	t.Parallel()
	e := &Error{Code: CodeAuth}
	if got, want := e.Error(), "E_AUTH"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestNilReceiverIsSafe(t *testing.T) {
	t.Parallel()
	var e *Error
	if got := e.Error(); got != "" {
		t.Errorf("nil.Error() = %q, want empty", got)
	}
	if got := e.ExitCode(); got != 0 {
		t.Errorf("nil.ExitCode() = %d, want 0", got)
	}
	if got := e.WithHint("nope"); got != nil {
		t.Errorf("nil.WithHint = %v, want nil", got)
	}
	if got := e.Wrap(fmt.Errorf("x")); got != nil {
		t.Errorf("nil.Wrap = %v, want nil", got)
	}
}

func TestWithHintReturnsCopy(t *testing.T) {
	t.Parallel()
	e := New(CodeNotFound, "missing")
	withHint := e.WithHint("try again")
	if e.Hint != "" {
		t.Errorf("original mutated: Hint = %q", e.Hint)
	}
	if withHint.Hint != "try again" {
		t.Errorf("copy.Hint = %q, want %q", withHint.Hint, "try again")
	}
	if withHint.Code != e.Code || withHint.Message != e.Message {
		t.Error("WithHint must preserve Code and Message")
	}
}

func TestWithHintfFormats(t *testing.T) {
	t.Parallel()
	e := New(CodeUsage, "bad").WithHintf("see %s", "docs")
	if e.Hint != "see docs" {
		t.Errorf("Hint = %q", e.Hint)
	}
}

func TestWrapPreservesIdentityAndUnwrap(t *testing.T) {
	t.Parallel()
	cause := stderrors.New("root cause")
	e := New(CodeNetwork, "connection failed").Wrap(cause)
	if !stderrors.Is(e, cause) {
		t.Error("errors.Is should find wrapped cause")
	}
	if e.Code != CodeNetwork || e.Message != "connection failed" {
		t.Error("Wrap must not change Code or Message")
	}
}

func TestErrorsAsRecoversTypedError(t *testing.T) {
	t.Parallel()
	original := New(CodeAuth, "bad token")
	wrapped := fmt.Errorf("call site context: %w", original)
	var typed *Error
	if !stderrors.As(wrapped, &typed) {
		t.Fatal("errors.As must recover *Error through fmt.Errorf wrapping")
	}
	if typed.Code != CodeAuth {
		t.Errorf("typed.Code = %q, want %q", typed.Code, CodeAuth)
	}
}

func TestFromNilReturnsNil(t *testing.T) {
	t.Parallel()
	if got := From(nil); got != nil {
		t.Errorf("From(nil) = %+v, want nil", got)
	}
}

func TestFromPassesTypedErrorsThrough(t *testing.T) {
	t.Parallel()
	original := New(CodeRateLimited, "slow down")
	got := From(original)
	if got != original {
		t.Errorf("From(*Error) returned a different pointer; want pass-through")
	}
}

func TestFromUnwrapsTypedErrorThroughChain(t *testing.T) {
	t.Parallel()
	typed := New(CodeNotFound, "missing")
	wrapped := fmt.Errorf("ctx: %w", typed)
	got := From(wrapped)
	if got.Code != CodeNotFound {
		t.Errorf("From(wrapped).Code = %q, want %q", got.Code, CodeNotFound)
	}
}

func TestFromMapsCobraStyleUsageErrors(t *testing.T) {
	t.Parallel()
	cases := []string{
		`unknown command "foo" for "yalla"`,
		`unknown flag: --bogus`,
		`unknown shorthand flag: 'x' in -x`,
		`required flag(s) "token" not set`,
		`invalid argument "abc" for "--port" flag`,
		`flag needs an argument: --token`,
		`accepts 1 arg(s), received 0`,
		`bad flag syntax: ---json`,
	}
	for _, msg := range cases {
		got := From(stderrors.New(msg))
		if got.Code != CodeUsage {
			t.Errorf("From(%q).Code = %q, want %q", msg, got.Code, CodeUsage)
		}
		if got.ExitCode() != 2 {
			t.Errorf("From(%q).ExitCode() = %d, want 2", msg, got.ExitCode())
		}
	}
}

func TestFromFallsBackToInternal(t *testing.T) {
	t.Parallel()
	got := From(stderrors.New("something exploded in the runtime"))
	if got.Code != CodeInternal {
		t.Errorf("Code = %q, want %q", got.Code, CodeInternal)
	}
	if got.ExitCode() != 1 {
		t.Errorf("ExitCode() = %d, want 1", got.ExitCode())
	}
}

func TestSchemaVersionIsStable(t *testing.T) {
	t.Parallel()
	// Schema version is part of the public contract. Any change here must
	// be deliberate, version-bumped, and announced in release notes.
	if SchemaVersion != "yalla.error.v1" {
		t.Errorf("SchemaVersion = %q, want %q", SchemaVersion, "yalla.error.v1")
	}
}

// TestWithDetailAttachesAndDoesNotMutateReceiver proves WithDetail returns a
// copy with the supplied key/value attached, and never mutates the receiver
// — so a single base error can be reused as a template for multiple
// downstream annotations.
func TestWithDetailAttachesAndDoesNotMutateReceiver(t *testing.T) {
	t.Parallel()

	base := New(CodeConflict, "stale write")
	if base.Details != nil {
		t.Fatalf("Details = %v, want nil for a freshly constructed error", base.Details)
	}

	annotated := base.WithDetail("current_version", "5")
	if annotated == base {
		t.Error("WithDetail returned the same pointer; want a fresh copy")
	}
	if got := annotated.Details["current_version"]; got != "5" {
		t.Errorf("Details[current_version] = %q, want 5", got)
	}
	if base.Details != nil {
		t.Errorf("base Details was mutated to %v, want nil", base.Details)
	}

	// Layering a second detail must not bleed back into the first copy.
	withTwo := annotated.WithDetail("retry_after", "30")
	if got := withTwo.Details["retry_after"]; got != "30" {
		t.Errorf("Details[retry_after] = %q, want 30", got)
	}
	if _, ok := annotated.Details["retry_after"]; ok {
		t.Error("first WithDetail copy was mutated by a downstream WithDetail call")
	}
}

// TestWithDetailDropsBlankKey proves WithDetail silently drops a blank key
// rather than storing a value under it: blank keys would corrupt callers
// that switch on the recovered map.
func TestWithDetailDropsBlankKey(t *testing.T) {
	t.Parallel()

	got := New(CodeConflict, "x").WithDetail("   ", "value")
	if got.Details != nil {
		t.Errorf("Details = %v, want nil — a blank key must not be stored", got.Details)
	}
}

// TestWithDetailOverwritesExistingKey proves a second WithDetail call for
// the same key replaces the value rather than silently keeping the first.
func TestWithDetailOverwritesExistingKey(t *testing.T) {
	t.Parallel()

	got := New(CodeConflict, "x").WithDetail("k", "v1").WithDetail("k", "v2")
	if got.Details["k"] != "v2" {
		t.Errorf("Details[k] = %q, want v2 — second WithDetail must overwrite", got.Details["k"])
	}
}

// TestWithDetailOnNilReturnsNil proves the nil-receiver branch returns nil
// without panicking, mirroring the other With* helpers.
func TestWithDetailOnNilReturnsNil(t *testing.T) {
	t.Parallel()

	var nilErr *Error
	if got := nilErr.WithDetail("k", "v"); got != nil {
		t.Errorf("WithDetail on nil returned %+v, want nil", got)
	}
}
