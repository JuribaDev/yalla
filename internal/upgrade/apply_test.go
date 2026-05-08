package upgrade

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/release"
)

// makeTarGz builds an in-memory tar.gz archive containing a single file
// named binaryName with the supplied content. The fixture mirrors the
// layout GoReleaser produces.
func makeTarGz(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0o755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// makeZip mirrors makeTarGz for Windows targets.
func makeZip(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(binaryName)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestApplyManual_DownloadVerifyReplace(t *testing.T) {
	target := release.Target{OS: "linux", Arch: "amd64"}
	version := "0.2.0"
	binaryContent := []byte("FAKE-NEW-BINARY-CONTENT")
	archive := makeTarGz(t, target.BinaryName(), binaryContent)
	checksumLine := sha256Hex(archive) + "  " + target.ArchiveName(version) + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/archive", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksumLine))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "yalla")
	if err := os.WriteFile(bin, []byte("OLD"), 0o755); err != nil {
		t.Fatalf("seed bin: %v", err)
	}

	var logged []string
	err := ApplyManual(t.Context(), ApplyOptions{
		HTTPClient:   srv.Client(),
		Version:      version,
		Target:       target,
		BinaryPath:   bin,
		ArchiveURL:   srv.URL + "/archive",
		ChecksumsURL: srv.URL + "/checksums",
		Logf: func(f string, a ...any) {
			logged = append(logged, f)
		},
	})
	if err != nil {
		t.Fatalf("ApplyManual: %v", err)
	}
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read replaced bin: %v", err)
	}
	if !bytes.Equal(got, binaryContent) {
		t.Errorf("replaced contents = %q, want %q", got, binaryContent)
	}
	if len(logged) == 0 {
		t.Error("Logf never fired; expected at least one progress line")
	}
}

func TestApplyManual_ChecksumMismatchAborts(t *testing.T) {
	target := release.Target{OS: "linux", Arch: "amd64"}
	version := "0.2.0"
	archive := makeTarGz(t, target.BinaryName(), []byte("NEW"))

	// Wrong sha intentionally — file should NOT be replaced.
	wrong := strings.Repeat("0", 64)
	checksumLine := wrong + "  " + target.ArchiveName(version) + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/archive", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksumLine)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "yalla")
	if err := os.WriteFile(bin, []byte("OLD"), 0o755); err != nil {
		t.Fatalf("seed bin: %v", err)
	}

	err := ApplyManual(t.Context(), ApplyOptions{
		HTTPClient:   srv.Client(),
		Version:      version,
		Target:       target,
		BinaryPath:   bin,
		ArchiveURL:   srv.URL + "/archive",
		ChecksumsURL: srv.URL + "/checksums",
	})
	if err == nil {
		t.Fatal("ApplyManual returned nil error on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error = %q, want to contain 'checksum mismatch'", err.Error())
	}
	got, _ := os.ReadFile(bin)
	if string(got) != "OLD" {
		t.Errorf("binary was overwritten on checksum failure: got %q", string(got))
	}
}

func TestApplyManual_MissingChecksumEntryAborts(t *testing.T) {
	target := release.Target{OS: "linux", Arch: "amd64"}
	version := "0.2.0"
	archive := makeTarGz(t, target.BinaryName(), []byte("NEW"))

	// Checksums file references a different filename so the lookup
	// fails — exact same protection against tampered metadata.
	checksumLine := sha256Hex(archive) + "  some_other_file.tar.gz\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/archive", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksumLine)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "yalla")
	_ = os.WriteFile(bin, []byte("OLD"), 0o755)

	err := ApplyManual(t.Context(), ApplyOptions{
		HTTPClient:   srv.Client(),
		Version:      version,
		Target:       target,
		BinaryPath:   bin,
		ArchiveURL:   srv.URL + "/archive",
		ChecksumsURL: srv.URL + "/checksums",
	})
	if err == nil {
		t.Fatal("ApplyManual returned nil error on missing checksum entry")
	}
	got, _ := os.ReadFile(bin)
	if string(got) != "OLD" {
		t.Errorf("binary was overwritten: got %q", string(got))
	}
}

func TestApplyManual_WindowsZip(t *testing.T) {
	target := release.Target{OS: "windows", Arch: "amd64"}
	version := "0.2.0"
	binaryContent := []byte("FAKE-WINDOWS-EXE")
	archive := makeZip(t, target.BinaryName(), binaryContent)
	checksumLine := sha256Hex(archive) + "  " + target.ArchiveName(version) + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/archive", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksumLine)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpDir := t.TempDir()
	// Even on Linux CI we exercise the .zip path; the file name does
	// not need to end in .exe — atomicReplace renames blindly.
	bin := filepath.Join(tmpDir, "yalla.exe")
	_ = os.WriteFile(bin, []byte("OLD"), 0o755)

	err := ApplyManual(t.Context(), ApplyOptions{
		HTTPClient:   srv.Client(),
		Version:      version,
		Target:       target,
		BinaryPath:   bin,
		ArchiveURL:   srv.URL + "/archive",
		ChecksumsURL: srv.URL + "/checksums",
	})
	if err != nil {
		t.Fatalf("ApplyManual (zip): %v", err)
	}
	got, _ := os.ReadFile(bin)
	if !bytes.Equal(got, binaryContent) {
		t.Errorf("replaced contents = %q, want %q", got, binaryContent)
	}
}
