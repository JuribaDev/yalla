package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/output"
)

// TestDocsMarkdown_StdoutEmitsCombinedDocument covers the no-output-dir
// path: a single, concatenated Markdown document is written to stdout
// so the result can be piped into a static site generator or saved with
// a single redirection.
func TestDocsMarkdown_StdoutEmitsCombinedDocument(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "docs", "markdown")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in human stdout mode; got %q", stderr)
	}
	for _, want := range []string{
		"# yalla\n",
		"## Synopsis",
		"## Usage",
		"# yalla manifest",
		"# yalla schema get",
		"# yalla completion bash",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("combined markdown missing %q", want)
		}
	}
	if !strings.Contains(stdout, "\n---\n") {
		t.Errorf("combined markdown missing horizontal rule between pages")
	}
}

// TestDocsMarkdown_OutputDirWritesPerCommandFiles covers the file-output
// path: one Markdown file per command, deterministic file names, and a
// JSON envelope listing the produced files when --json is set.
func TestDocsMarkdown_OutputDirWritesPerCommandFiles(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, err := runRootArgs(t, "--json", "docs", "markdown", "--output-dir", dir)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	var env struct {
		SchemaVersion string          `json:"schema_version"`
		Data          docsMarkdownDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("envelope schema_version = %q", env.SchemaVersion)
	}
	if env.Data.Format != "markdown" {
		t.Errorf("format = %q, want %q", env.Data.Format, "markdown")
	}
	if env.Data.OutputDir != dir {
		t.Errorf("output_dir = %q, want %q", env.Data.OutputDir, dir)
	}
	if env.Data.CommandCount < 5 {
		t.Errorf("command_count = %d, want >= 5", env.Data.CommandCount)
	}
	if len(env.Data.Files) != env.Data.CommandCount {
		t.Errorf("files length = %d, want %d", len(env.Data.Files), env.Data.CommandCount)
	}
	if env.Data.Content != "" {
		t.Errorf("content must be empty when output_dir is set; got %q", env.Data.Content)
	}

	// The root file must always be present and contain the expected
	// heading. We round-trip through the filesystem because that is the
	// guarantee callers rely on.
	rootFile := filepath.Join(dir, "yalla.md")
	body, readErr := os.ReadFile(rootFile)
	if readErr != nil {
		t.Fatalf("read %s: %v", rootFile, readErr)
	}
	if !strings.HasPrefix(string(body), "# yalla\n") {
		t.Errorf("yalla.md does not start with `# yalla` heading; got first 80 bytes: %q", string(body[:min(80, len(body))]))
	}

	// Spot-check a leaf command to verify nested paths resolve correctly.
	leafFile := filepath.Join(dir, "yalla_schema_get.md")
	if _, err := os.Stat(leafFile); err != nil {
		t.Errorf("expected %s to exist: %v", leafFile, err)
	}
}

// TestDocsMarkdown_JSONStdoutWrapsContent covers the combination of
// --json and no --output-dir: the renderer must wrap the combined
// Markdown in the standard envelope instead of streaming raw bytes.
func TestDocsMarkdown_JSONStdoutWrapsContent(t *testing.T) {
	stdout, _, err := runRootArgs(t, "--json", "docs", "markdown")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data docsMarkdownDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.OutputDir != "" {
		t.Errorf("output_dir should be empty in stdout mode; got %q", env.Data.OutputDir)
	}
	if !strings.Contains(env.Data.Content, "# yalla") {
		t.Error("content does not contain the root heading")
	}
	if env.Data.CommandCount < 5 {
		t.Errorf("command_count = %d, want >= 5", env.Data.CommandCount)
	}
}

// TestDocsMarkdown_OutputDirHumanModeLogsToStderr asserts the
// human-mode contract for the file-output path: stdout stays empty and
// the per-file count lands on stderr (logs/diagnostics).
func TestDocsMarkdown_OutputDirHumanModeLogsToStderr(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, err := runRootArgs(t, "docs", "markdown", "--output-dir", dir)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty when writing files; got %q", stdout)
	}
	if !strings.Contains(stderr, "wrote") || !strings.Contains(stderr, dir) {
		t.Errorf("stderr should include progress line with target dir; got %q", stderr)
	}
}
