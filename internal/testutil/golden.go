package testutil

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateGoldenFlag is registered at package init so `go test -update-golden`
// is recognised by every test binary that imports testutil. Tests should not
// read the variable directly — call UpdateGolden() so the override path
// stays a single function for future tooling (e.g. an env var fallback).
//
// Naming note: the flag avoids the bare `-update` name to dodge collisions
// with frameworks that already register that name and to make the intent
// obvious in CI logs.
var updateGoldenFlag = flag.Bool(
	"update-golden",
	false,
	"regenerate testdata/*.golden files instead of asserting against them",
)

// UpdateGolden reports whether the test binary was invoked with
// -update-golden. Helpers and bespoke goldens both consult this hook.
func UpdateGolden() bool {
	return updateGoldenFlag != nil && *updateGoldenFlag
}

// SetUpdateGoldenForTest pins the -update-golden flag value for the duration
// of a single test, restoring the previous value via t.Cleanup. Tests that
// verify the comparison branch of Golden need this so the suite still works
// when the developer invoked `go test -update-golden ./...` for an unrelated
// package — without the override the helper would always rewrite the golden
// and silently mask logic regressions.
func SetUpdateGoldenForTest(t testing.TB, on bool) {
	t.Helper()
	if updateGoldenFlag == nil {
		return
	}
	prev := *updateGoldenFlag
	*updateGoldenFlag = on
	t.Cleanup(func() { *updateGoldenFlag = prev })
}

// GoldenOptions tunes a Golden assertion. The zero value compares the raw
// `got` bytes against the file as-is, which is the right default for stable
// human output.
type GoldenOptions struct {
	// Normalizers are applied in order to both `got` and the on-disk
	// golden before comparison. They are NOT applied when writing a new
	// golden (that would defeat the purpose of -update-golden) — the
	// stripper output IS the canonical content.
	//
	// Use Normalizers to drop dynamic fields (request_id, duration_ms,
	// timestamps) that change every run. The normalize.go file ships
	// reusable building blocks.
	Normalizers []func(string) string
	// PrettyJSON, when true, re-encodes both `got` and the golden through
	// json.Indent before comparison. This makes diffs readable for
	// JSON-heavy goldens (manifest, schema get) without forcing the
	// command itself to emit indented JSON. The reformat is best-effort:
	// non-JSON input falls through unchanged so callers can mix golden
	// kinds in one suite.
	PrettyJSON bool
}

// Golden compares `got` against testdata/<name>.golden. With -update-golden,
// the file is rewritten with the (un-normalized, raw) `got` value and the
// test passes. The directory is created on demand so new tests do not have
// to remember `mkdir testdata`.
//
// The function reports a single t.Errorf with a unified diff snippet so the
// failure is actionable without dropping into a debugger.
func Golden(t testing.TB, name, got string, opts GoldenOptions) {
	t.Helper()
	if name == "" {
		t.Fatal("Golden: name is required")
	}
	path := goldenPath(name)

	gotForCompare := got
	if opts.PrettyJSON {
		gotForCompare = prettyJSONIfPossible(gotForCompare)
	}
	for _, fn := range opts.Normalizers {
		gotForCompare = fn(gotForCompare)
	}

	if UpdateGolden() {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create testdata dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(gotForCompare), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden: %s", path)
		return
	}

	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\n(hint: rerun with -update-golden to create it)", path, err)
	}
	want := string(wantBytes)
	if opts.PrettyJSON {
		want = prettyJSONIfPossible(want)
	}
	for _, fn := range opts.Normalizers {
		want = fn(want)
	}
	if gotForCompare == want {
		return
	}
	t.Errorf("golden mismatch for %s\n--- want\n%s\n--- got\n%s", path, want, gotForCompare)
}

// GoldenJSON is a convenience wrapper that always pretty-prints both sides
// before comparison. It is the right helper for JSON envelopes, manifests,
// and schemas — anywhere whitespace and key order are not the contract.
func GoldenJSON(t testing.TB, name, got string, normalizers ...func(string) string) {
	t.Helper()
	Golden(t, name, got, GoldenOptions{
		Normalizers: normalizers,
		PrettyJSON:  true,
	})
}

// goldenPath resolves the on-disk path for a named golden file. Names are
// allowed to contain forward slashes so callers can group by feature
// (e.g. "manifest/json", "errors/auth") without flattening into long names.
func goldenPath(name string) string {
	parts := strings.Split(name, "/")
	parts[len(parts)-1] += ".golden"
	return filepath.Join(append([]string{"testdata"}, parts...)...)
}

// prettyJSONIfPossible re-encodes raw JSON with two-space indentation. It
// returns the input unchanged when the bytes are not valid JSON so callers
// can pipeline it without conditional logic.
func prettyJSONIfPossible(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(trimmed), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}
