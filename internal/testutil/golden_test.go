package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JuribaDev/yalla/internal/testutil"
)

// Golden mismatches must produce a t.Errorf with the diff embedded; success
// paths must stay silent. We exercise both branches via a fakeT so the test
// suite itself does not depend on a checked-in golden file at the real
// testdata path (the suite runs from internal/testutil and we want it to
// be self-contained).
func TestGolden_Match(t *testing.T) {
	testutil.SetUpdateGoldenForTest(t, false)
	cwd := chdirTemp(t)
	writeGolden(t, cwd, "match", "hello\n")
	ft := &fakeT{TB: t}
	testutil.Golden(ft, "match", "hello\n", testutil.GoldenOptions{})
	if ft.failed {
		t.Errorf("Golden flagged a matching value: %s", ft.msg)
	}
}

func TestGolden_Mismatch(t *testing.T) {
	testutil.SetUpdateGoldenForTest(t, false)
	cwd := chdirTemp(t)
	writeGolden(t, cwd, "mismatch", "expected\n")
	ft := &fakeT{TB: t}
	testutil.Golden(ft, "mismatch", "actual\n", testutil.GoldenOptions{})
	if !ft.failed {
		t.Errorf("Golden missed a mismatch")
	}
}

// Normalisers must be applied to both sides before comparison so dynamic
// fields are stripped consistently.
func TestGolden_NormalisersStripDynamicFields(t *testing.T) {
	testutil.SetUpdateGoldenForTest(t, false)
	cwd := chdirTemp(t)
	writeGolden(t, cwd, "normalised", `{"request_id":"[REQUEST_ID]","duration_ms":0}`+"\n")
	got := `{"request_id":"abc-123","duration_ms":47}` + "\n"
	ft := &fakeT{TB: t}
	testutil.Golden(ft, "normalised", got, testutil.GoldenOptions{
		Normalizers: testutil.DefaultJSONNormalizers(),
	})
	if ft.failed {
		t.Errorf("Golden flagged a value the normalisers should have flattened: %s", ft.msg)
	}
}

// PrettyJSON must allow whitespace-insensitive comparison so a command can
// emit compact JSON while the golden file is hand-readable.
func TestGolden_PrettyJSON(t *testing.T) {
	testutil.SetUpdateGoldenForTest(t, false)
	cwd := chdirTemp(t)
	writeGolden(t, cwd, "pretty", "{\n  \"a\": 1\n}")
	ft := &fakeT{TB: t}
	testutil.GoldenJSON(ft, "pretty", `{"a":1}`)
	if ft.failed {
		t.Errorf("GoldenJSON flagged compact-vs-pretty equivalence: %s", ft.msg)
	}
}

// With -update-golden flipped on, Golden must (re)create the file rather
// than asserting equality. The branch is otherwise hard to reach without
// invoking the binary twice.
func TestGolden_UpdateModeWritesFile(t *testing.T) {
	testutil.SetUpdateGoldenForTest(t, true)
	cwd := chdirTemp(t)
	ft := &fakeT{TB: t}
	testutil.Golden(ft, "fresh", "freshly-baked\n", testutil.GoldenOptions{})
	if ft.failed {
		t.Errorf("Golden flagged a write-only update path: %s", ft.msg)
	}
	written, err := os.ReadFile(filepath.Join(cwd, "testdata", "fresh.golden"))
	if err != nil {
		t.Fatalf("read written golden: %v", err)
	}
	if string(written) != "freshly-baked\n" {
		t.Errorf("written golden = %q, want %q", written, "freshly-baked\n")
	}
}

// chdirTemp makes the current working directory a fresh tempdir for the
// duration of the test so testdata/ writes do not collide with the package's
// real fixtures and so subsequent tests start from a clean slate.
func chdirTemp(t *testing.T) string {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

func writeGolden(t *testing.T, cwd, name, contents string) {
	t.Helper()
	path := filepath.Join(cwd, "testdata", name+".golden")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
}
