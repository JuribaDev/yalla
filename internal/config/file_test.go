package config

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestReadFile_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const body = "" +
		"base_url: https://dokploy.example.com\n" +
		"token: secret-token-value\n" +
		"output: json\n" +
		"no_input: true\n" +
		"verbose: false\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	got, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if got.BaseURL != "https://dokploy.example.com" {
		t.Errorf("BaseURL = %q", got.BaseURL)
	}
	if got.Token != "secret-token-value" {
		t.Errorf("Token = %q", got.Token)
	}
	if got.Output != OutputJSON {
		t.Errorf("Output = %q", got.Output)
	}
	if got.NoInput == nil || !*got.NoInput {
		t.Errorf("NoInput = %v, want *true", got.NoInput)
	}
	if got.Verbose == nil || *got.Verbose {
		t.Errorf("Verbose = %v, want *false", got.Verbose)
	}
	if got.Path != path {
		t.Errorf("Path = %q, want %q", got.Path, path)
	}
}

func TestReadFile_EmptyFileIsValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	got, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if got.BaseURL != "" || got.Token != "" {
		t.Errorf("expected zero-valued FileData; got %+v", got)
	}
}

func TestReadFile_RejectsUnknownKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "base_url: https://example.com\nmystery_key: hello\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := readFile(path)
	if err == nil {
		t.Fatal("readFile accepted unknown key")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestReadFile_InvalidBaseURLInFileFailsOnRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("base_url: ftp://example.com\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := readFile(path)
	if err == nil {
		t.Fatal("readFile accepted invalid scheme")
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		t.Fatalf("error not typed: %v", err)
	}
	if typed.Code != yerr.CodeConfig {
		t.Errorf("Code = %q, want %q", typed.Code, yerr.CodeConfig)
	}
}

func TestReadFile_MissingFileReturnsErrNotExist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := readFile(filepath.Join(dir, "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("readFile returned nil for missing file")
	}
	if !IsNotExist(err) {
		t.Errorf("IsNotExist(%v) = false, want true", err)
	}
}

func TestWriteFile_RoundTripPreservesShape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.yaml")

	noInput := true
	in := FileData{
		BaseURL: "https://dokploy.example.com",
		Token:   "secret-token-value",
		Output:  OutputJSON,
		NoInput: &noInput,
	}
	if err := WriteFile(path, in); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != secureFileMode {
		t.Errorf("file perm = %o, want %o", info.Mode().Perm(), secureFileMode)
	}

	got, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if got.BaseURL != in.BaseURL || got.Token != in.Token {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, in)
	}
	if got.Output != OutputJSON {
		t.Errorf("Output = %q, want %q", got.Output, OutputJSON)
	}
	if got.NoInput == nil || !*got.NoInput {
		t.Errorf("NoInput = %v, want *true", got.NoInput)
	}
}

func TestWriteFile_DoesNotLeakTokenInDirListing(t *testing.T) {
	t.Parallel()
	// Defence-in-depth: even though tokens live inside the file, the
	// directory listing must not contain the literal value (as a sanity
	// check against accidental filename templating).
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := WriteFile(path, FileData{Token: "literal-secret"}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "literal-secret") {
			t.Errorf("token leaked into filename %q", e.Name())
		}
	}
}

func TestMergeFileData_PreservesUnchangedFields(t *testing.T) {
	t.Parallel()
	noInput := true
	base := FileData{
		BaseURL: "https://kept.example.com",
		Token:   "kept-token",
		Output:  OutputJSON,
		NoInput: &noInput,
	}
	update := FileData{Token: "new-token"}
	got := MergeFileData(base, update)
	if got.BaseURL != "https://kept.example.com" {
		t.Errorf("BaseURL clobbered: %q", got.BaseURL)
	}
	if got.Token != "new-token" {
		t.Errorf("Token = %q, want new-token", got.Token)
	}
	if got.Output != OutputJSON {
		t.Errorf("Output clobbered: %q", got.Output)
	}
	if got.NoInput == nil || !*got.NoInput {
		t.Errorf("NoInput pointer clobbered: %v", got.NoInput)
	}
}

func TestDefaultConfigPath_RespectsUserConfigDir(t *testing.T) {
	t.Parallel()
	got := DefaultConfigPath(func() (string, error) { return "/a/b", nil })
	want := filepath.Join("/a/b", "yalla", "config.yaml")
	if got != want {
		t.Errorf("DefaultConfigPath = %q, want %q", got, want)
	}
}

func TestDefaultConfigPath_NilFallsBackToOSStdlib(t *testing.T) {
	t.Parallel()
	// Nil hook must not panic; the result depends on the host OS so we just
	// assert it stays a non-nil string (could be empty on some test hosts).
	_ = DefaultConfigPath(nil)
}

func TestDefaultConfigPath_ErrorReturnsEmpty(t *testing.T) {
	t.Parallel()
	got := DefaultConfigPath(func() (string, error) { return "", os.ErrNotExist })
	if got != "" {
		t.Errorf("DefaultConfigPath = %q, want empty", got)
	}
}
