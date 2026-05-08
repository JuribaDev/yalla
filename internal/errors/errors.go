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
	CodeUnknown      Code = "E_UNKNOWN"
	CodeInternal     Code = "E_INTERNAL"
	CodeUsage        Code = "E_USAGE"
	CodeInvalidInput Code = "E_INVALID_INPUT"
	CodeConfig       Code = "E_CONFIG"
	CodeAuth         Code = "E_AUTH"
	CodeForbidden    Code = "E_FORBIDDEN"
	CodeNotFound     Code = "E_NOT_FOUND"
	CodeConflict     Code = "E_CONFLICT"
	CodeRateLimited  Code = "E_RATE_LIMITED"
	CodeServer       Code = "E_SERVER"
	CodeNetwork      Code = "E_NETWORK"
	CodeTimeout      Code = "E_TIMEOUT"
	CodeCanceled     Code = "E_CANCELED"
	CodeNoInput      Code = "E_NO_INPUT_REQUIRED"
	CodeUnsupported  Code = "E_UNSUPPORTED"
)

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
// 7   rate limited (back off and retry)
// 8   network / timeout / upstream server error
// 9   --no-input was set but a prompt would be required
// 10  unsupported operation
// 130 canceled (POSIX SIGINT convention)
func (c Code) ExitCode() int {
	switch c {
	case "":
		return 0
	case CodeUsage, CodeInvalidInput:
		return 2
	case CodeConfig:
		return 3
	case CodeAuth, CodeForbidden:
		return 4
	case CodeNotFound:
		return 5
	case CodeConflict:
		return 6
	case CodeRateLimited:
		return 7
	case CodeNetwork, CodeTimeout, CodeServer:
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
// Hint that suggests a remedy, and an optional underlying Cause so
// errors.Is/As traversal still works.
type Error struct {
	Code    Code
	Message string
	Hint    string
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
