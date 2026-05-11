package testutil_test

import (
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/testutil"
)

// The harness drives the production exit-code path, so a bare `yalla` should
// emit the help banner on stderr only and exit 0.
func TestRun_NoArgs_PrintsHelpToStderrOnly(t *testing.T) {
	testutil.IsolateEnv(t)
	res := testutil.RunArgs(t)
	testutil.AssertStdoutEmpty(t, res.Stdout)
	testutil.AssertExit(t, res.Exit, 0)
	testutil.AssertStderrContains(t, res.Stderr, "Yalla is a production-grade")
}

// An unknown subcommand must fail with E_USAGE (exit 2), keep stdout empty,
// and surface the error banner on stderr — that is the contract every
// future command test will rely on.
func TestRun_UnknownCommand_E_USAGE(t *testing.T) {
	testutil.IsolateEnv(t)
	res := testutil.RunArgs(t, "definitely-not-a-command")
	testutil.AssertStdoutEmpty(t, res.Stdout)
	testutil.AssertExit(t, res.Exit, yerr.CodeUsage.ExitCode())
	testutil.AssertStderrContains(t, res.Stderr, "Error [E_USAGE]")
}

// JSON-mode error rendering must produce a single yalla.error.v1 envelope on
// stderr with code=E_USAGE and exit=2. The harness's DecodeError + AssertExit
// helpers should recognise that contract end to end.
func TestRun_UnknownCommandJSON_DecodesEnvelope(t *testing.T) {
	testutil.IsolateEnv(t)
	res := testutil.RunArgs(t, "--json", "definitely-not-a-command")
	testutil.AssertStdoutEmpty(t, res.Stdout)
	env := testutil.AssertExitForCode(t, res, yerr.CodeUsage)
	if env.Error.Message == "" {
		t.Errorf("expected a non-empty message; got %+v", env)
	}
}

// The success envelope decoder must round-trip command output cleanly.
// `config get --json` is the simplest deterministic surface available right
// now and exercises both the schema_version assertion and the typed Data
// payload path.
func TestRun_ConfigGetJSON_DecodesSuccessEnvelope(t *testing.T) {
	testutil.IsolateEnv(t)
	testutil.WriteTempConfig(t, "")
	res := testutil.RunArgs(t, "--json", "config", "get")
	testutil.AssertExit(t, res.Exit, 0)
	testutil.AssertStderrEmpty(t, res.Stderr)

	var payload struct {
		ConfigPath string `json:"config_path"`
		FileLoaded bool   `json:"file_loaded"`
		Items      []any  `json:"items"`
	}
	testutil.DecodeSuccessInto(t, res.Stdout, &payload)
	if payload.ConfigPath == "" {
		t.Errorf("config_path missing from decoded payload")
	}
	if len(payload.Items) == 0 {
		t.Errorf("items missing from decoded payload")
	}
}

// MustBeValidJSON should reject empty, malformed, and multi-document inputs
// while accepting a single value plus trailing whitespace.
func TestMustBeValidJSON_Cases(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testutil.MustBeValidJSON(t, `{"a":1}`)
	})
	t.Run("trailing-whitespace", func(t *testing.T) {
		testutil.MustBeValidJSON(t, "{\"a\":1}\n  ")
	})
	t.Run("invalid", func(t *testing.T) {
		// Use a sub-test scoped fakeT so we can confirm the helper
		// raises a fatal without aborting this test.
		ft := &fakeT{TB: t}
		testutil.MustBeValidJSON(ft, "not json")
		if !ft.failed {
			t.Errorf("expected MustBeValidJSON to fail on invalid input")
		}
	})
	t.Run("multi-document", func(t *testing.T) {
		ft := &fakeT{TB: t}
		testutil.MustBeValidJSON(ft, `{"a":1}{"b":2}`)
		if !ft.failed {
			t.Errorf("expected MustBeValidJSON to fail on multi-document input")
		}
	})
}

// AssertNotContains is the secret-leak regression net. Tests pass the
// literal --token value and the helper must catch any path that bypasses
// the redactor.
func TestAssertNotContains(t *testing.T) {
	ft := &fakeT{TB: t}
	testutil.AssertNotContains(ft, `{"token":"sekret-XYZ-123"}`, "sekret-XYZ-123")
	if !ft.failed {
		t.Errorf("expected AssertNotContains to fail when banned substring is present")
	}
	clean := &fakeT{TB: t}
	testutil.AssertNotContains(clean, `{"token":"[REDACTED]"}`, "sekret-XYZ-123")
	if clean.failed {
		t.Errorf("AssertNotContains incorrectly flagged a clean buffer")
	}
}

// fakeT is a TB shim that captures Errorf/Fatalf without stopping the parent
// test. It lets us assert the negative path of helpers that call t.Fatal.
type fakeT struct {
	testing.TB
	failed bool
	msg    string
}

func (f *fakeT) Errorf(format string, args ...any) {
	f.failed = true
	f.msg = strings.TrimSpace(format)
}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = strings.TrimSpace(format)
	// Do not call FailNow / runtime.Goexit — that would also stop the
	// parent test. We rely on callers checking f.failed.
}

func (f *fakeT) Fatal(args ...any) {
	f.failed = true
}

func (f *fakeT) Helper() {}
