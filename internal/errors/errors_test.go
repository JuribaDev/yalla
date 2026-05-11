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
		{CodeInvalidInput, 2},
		{CodeConfig, 3},
		{CodeAuth, 4},
		{CodeForbidden, 4},
		{CodeNotFound, 5},
		{CodeConflict, 6},
		{CodeRateLimited, 7},
		{CodeNetwork, 8},
		{CodeTimeout, 8},
		{CodeServer, 8},
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
