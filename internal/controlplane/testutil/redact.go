package testutil

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/output"
)

// AssertRedacted fails t if any of secrets appears verbatim in s. It is the
// standard guard for "this log line / error message / audit metadata / dry-run
// or test output must not leak a secret" assertions across the backend suite.
// Empty secrets are ignored. The failure message itself never prints the raw
// secret — it reports the leaked length and a redacted view of s.
func AssertRedacted(t testing.TB, s string, secrets ...string) {
	t.Helper()
	for _, leaked := range scanLeaks(s, secrets) {
		t.Errorf("testutil: secret leaked into test output (%d-char value); redacted view: %s",
			len(leaked), strings.ReplaceAll(s, leaked, output.Sentinel))
	}
}

// AssertRedactedValue fails t if any of secrets appears in any standard
// rendering of v — its JSON encoding and its fmt %+v / %#v forms. Use it to
// prove a struct (an audit record, an error payload, a config projection) does
// not leak a secret through an exported field, a String method, or JSON
// marshalling. Empty secrets are ignored.
func AssertRedactedValue(t testing.TB, v any, secrets ...string) {
	t.Helper()
	for _, rendering := range valueRenderings(v) {
		for _, leaked := range scanLeaks(rendering, secrets) {
			t.Errorf("testutil: secret leaked into rendered value (%d-char value); redacted view: %s",
				len(leaked), strings.ReplaceAll(rendering, leaked, output.Sentinel))
		}
	}
}

// scanLeaks returns the subset of secrets that appear verbatim in s. It is
// split out so the leak-detection logic is unit-testable without a *testing.T.
func scanLeaks(s string, secrets []string) []string {
	var leaks []string
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(s, secret) {
			leaks = append(leaks, secret)
		}
	}
	return leaks
}

// valueRenderings returns every textual rendering of v that AssertRedactedValue
// scans for leaks. JSON is included only when v marshals cleanly.
func valueRenderings(v any) []string {
	renderings := []string{
		fmt.Sprintf("%+v", v),
		fmt.Sprintf("%#v", v),
	}
	if b, err := json.Marshal(v); err == nil {
		renderings = append(renderings, string(b))
	}
	return renderings
}
