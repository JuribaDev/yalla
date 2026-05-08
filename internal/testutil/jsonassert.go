package testutil

import (
	"encoding/json"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// SuccessEnvelope is the canonical decoded form of yalla.output.v1. The Data
// field stays as json.RawMessage so callers can decode it into a domain-
// specific struct in a second pass without paying for a generic map detour.
type SuccessEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
}

// ErrorEnvelope is the canonical decoded form of yalla.error.v1.
type ErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint,omitempty"`
	} `json:"error"`
}

// MustBeValidJSON fails the test if raw is not a single, well-formed JSON
// document. Trailing whitespace is tolerated; multiple documents are not.
// This is the bedrock check every JSON-mode test should run before any
// schema-level decoding.
func MustBeValidJSON(t testing.TB, raw string) {
	t.Helper()
	if raw == "" {
		t.Fatal("expected JSON document, got empty string")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("invalid JSON: %v\nraw=%q", err, raw)
	}
	// Anything decodable after the first value violates the
	// single-document contract. io.EOF (the only non-error terminator)
	// is fine; any other token-or-error path means we found extra data.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		t.Fatalf("expected single JSON document; found trailing %q\nraw=%q", string(extra), raw)
	}
}

// DecodeSuccess decodes a yalla.output.v1 envelope and returns it. It fails
// the test if schema_version is missing or wrong. The caller is expected to
// then unmarshal env.Data into the command-specific payload.
func DecodeSuccess(t testing.TB, raw string) SuccessEnvelope {
	t.Helper()
	MustBeValidJSON(t, raw)
	var env SuccessEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("decode success envelope: %v\nraw=%q", err, raw)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Fatalf("schema_version = %q, want %q\nraw=%q", env.SchemaVersion, output.SuccessSchema, raw)
	}
	return env
}

// DecodeSuccessInto decodes the success envelope and unmarshals the Data
// field into target in one shot. Use this when the caller already has a
// typed payload struct.
func DecodeSuccessInto(t testing.TB, raw string, target any) SuccessEnvelope {
	t.Helper()
	env := DecodeSuccess(t, raw)
	if err := json.Unmarshal(env.Data, target); err != nil {
		t.Fatalf("decode success data: %v\nraw=%q", err, env.Data)
	}
	return env
}

// DecodeError decodes a yalla.error.v1 envelope and returns it. It fails the
// test if the schema_version is wrong or the code is empty.
func DecodeError(t testing.TB, raw string) ErrorEnvelope {
	t.Helper()
	MustBeValidJSON(t, raw)
	var env ErrorEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("decode error envelope: %v\nraw=%q", err, raw)
	}
	if env.SchemaVersion != yerr.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q\nraw=%q", env.SchemaVersion, yerr.SchemaVersion, raw)
	}
	if env.Error.Code == "" {
		t.Fatalf("error.code is empty\nraw=%q", raw)
	}
	return env
}

// AssertExit fails the test when got differs from want and adds the
// canonical (Code, ExitCode) reference so the failure message is actionable.
// Tests should pass the descriptive want value (e.g. yerr.CodeUsage.ExitCode())
// rather than a magic number when possible.
func AssertExit(t testing.TB, got, want int) {
	t.Helper()
	if got == want {
		return
	}
	t.Errorf("exit code = %d, want %d (%s)", got, want, exitCodeName(want))
}

// AssertCode fails the test when the JSON error envelope's code field
// differs from the supplied yalla error Code. It is the JSON-mode counterpart
// to checking the typed banner on stderr.
func AssertCode(t testing.TB, env ErrorEnvelope, want yerr.Code) {
	t.Helper()
	if env.Error.Code != string(want) {
		t.Errorf("error.code = %q, want %q", env.Error.Code, string(want))
	}
}

// AssertExitForCode bundles the two assertions every JSON-error test wants:
// the envelope is a yalla.error.v1, its code matches `want`, and the
// returned exit code is the canonical value for that code. The function
// fails the test (without t.Fatal) so multiple assertions can compound.
func AssertExitForCode(t testing.TB, res RunResult, want yerr.Code) ErrorEnvelope {
	t.Helper()
	env := DecodeError(t, res.Stderr)
	AssertCode(t, env, want)
	AssertExit(t, res.Exit, want.ExitCode())
	return env
}

// AssertStdoutEmpty fails the test if stdout is not empty. Every error path
// and every JSON-error test must satisfy this — the agent contract reserves
// stdout for data only.
func AssertStdoutEmpty(t testing.TB, got string) {
	t.Helper()
	if got != "" {
		t.Errorf("stdout must be empty; got %q", got)
	}
}

// AssertStderrEmpty fails the test when stderr is not empty. Use this for
// pure JSON-success assertions where any stderr byte is a contract bug.
func AssertStderrEmpty(t testing.TB, got string) {
	t.Helper()
	if got != "" {
		t.Errorf("stderr must be empty in JSON-success mode; got %q", got)
	}
}

// AssertStderrContains fails the test if stderr does not contain the given
// substring. The substring is reported back so the diff is obvious.
func AssertStderrContains(t testing.TB, stderr, want string) {
	t.Helper()
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr missing %q\nstderr=%q", want, stderr)
	}
}

// AssertNotContains fails the test if got contains banned. It is the
// regression net for secret leaks: tests pass the literal --token value to
// catch any path that bypasses the redactor.
func AssertNotContains(t testing.TB, got, banned string) {
	t.Helper()
	if banned == "" {
		return
	}
	if strings.Contains(got, banned) {
		t.Errorf("output contained banned substring %q (likely redactor bypass)\noutput=%q", banned, got)
	}
}

// exitCodeName provides a friendly mnemonic alongside the exit code in
// failure messages. Unknown codes get a generic label.
func exitCodeName(code int) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "E_INTERNAL/E_UNKNOWN"
	case 2:
		return "E_USAGE/E_INVALID_INPUT"
	case 3:
		return "E_CONFIG"
	case 4:
		return "E_AUTH/E_FORBIDDEN"
	case 5:
		return "E_NOT_FOUND"
	case 6:
		return "E_CONFLICT"
	case 7:
		return "E_RATE_LIMITED"
	case 8:
		return "E_NETWORK/E_TIMEOUT/E_SERVER"
	case 9:
		return "E_NO_INPUT_REQUIRED"
	case 10:
		return "E_UNSUPPORTED"
	case 130:
		return "E_CANCELED"
	default:
		return "?"
	}
}
