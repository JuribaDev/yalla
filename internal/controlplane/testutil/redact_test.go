package testutil_test

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// The leak-detection logic itself (scanLeaks) is exhaustively covered by the
// white-box TestScanLeaks in internal_test.go, including the leak-detected
// branch. testing.TB is a sealed interface and cannot be faked, so these
// black-box tests assert the public wrappers do not false-positive on clean
// output — the half that can be verified without a fake recorder.

func TestAssertRedactedPassesOnCleanOutput(t *testing.T) {
	t.Parallel()

	// No secret present: AssertRedacted must not fail this test.
	testutil.AssertRedacted(t, `{"ok":true,"token":"[REDACTED]"}`, "super-secret-value")
	// Empty secrets are ignored even against arbitrary output.
	testutil.AssertRedacted(t, "anything at all", "")
}

func TestAssertRedactedValuePassesWhenStructHasNoSecret(t *testing.T) {
	t.Parallel()

	type record struct {
		Org   string
		Token string
	}
	// The secret never appears in any rendering of the value: it must pass.
	testutil.AssertRedactedValue(t, record{Org: "org_abc", Token: "[REDACTED]"}, "live-secret-token")
}

// A factory-built API key carries a fake plaintext secret. Once that secret is
// replaced by the redaction sentinel, AssertRedacted confirms it is gone — the
// realistic shape of every "this output must not leak a key" backend test.
func TestAssertRedactedGuardsAFixtureSecret(t *testing.T) {
	t.Parallel()

	f := testutil.NewFactory(t)
	org := f.Organization("acme")
	user := f.User(org, "ada")
	key := f.APIKey(org, user, "ci")

	if key.Secret == "" {
		t.Fatal("fixture API key has an empty secret")
	}
	rendered := "issued key for " + key.ID + " (secret omitted)"
	testutil.AssertRedacted(t, rendered, key.Secret)
}
