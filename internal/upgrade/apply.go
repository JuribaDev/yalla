package upgrade

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/JuribaDev/yalla/internal/release"
)

// ApplyOptions configures a self-replacement run. The CLI builds these
// values from the resolved Plan, the configured target, and the
// network coordinates returned by Check.
type ApplyOptions struct {
	// HTTPClient downloads the archive and the checksums file. The
	// caller is responsible for setting an appropriate timeout; the
	// CLI defaults to 60s for archive downloads.
	HTTPClient *http.Client

	// Version is the SemVer string (without leading `v`) being applied.
	// Combined with Target it determines the archive and checksums
	// filenames (via internal/release).
	Version string

	// Target is the (GOOS, GOARCH) coordinate to download. The CLI
	// passes runtime.GOOS / runtime.GOARCH; tests override the pair to
	// exercise the windows/zip path on Unix CI.
	Target release.Target

	// BinaryPath is the on-disk file to replace. Must be writable by
	// the calling user; the function returns a typed error otherwise.
	BinaryPath string

	// ArchiveURL and ChecksumsURL are the resolved download URLs. When
	// empty, the function falls back to the public GitHub Releases
	// CDN: https://github.com/<owner>/<repo>/releases/download/v<ver>/<name>.
	ArchiveURL   string
	ChecksumsURL string

	// Owner / Repo govern the fallback URL builder. Both default to
	// JuribaDev / yalla.
	Owner string
	Repo  string

	// Logf, when non-nil, receives single-line progress messages
	// suitable for stderr. The CLI wires this to Renderer.Logf so
	// users see "downloading...", "verifying checksum...", "replacing
	// binary..." lines while --json mode keeps them off stdout.
	Logf func(format string, args ...any)
}

// ApplyManual performs a manual-install upgrade: download the archive,
// download the checksums file, verify the SHA-256 of the archive, extract
// the binary, then atomically rename it over BinaryPath.
//
// The function is the only place yalla writes into its own install
// directory. It refuses to run when:
//
//   - BinaryPath is empty.
//   - The on-disk binary is not writable by the current user.
//   - The checksum verification fails.
//
// Each failure surfaces as a plain error string; the CLI layer wraps
// the error into a *errors.Error with the appropriate Code so the JSON
// envelope carries a stable identifier.
func ApplyManual(ctx context.Context, opts ApplyOptions) error {
	if opts.BinaryPath == "" {
		return fmt.Errorf("BinaryPath is empty")
	}
	if opts.Version == "" {
		return fmt.Errorf("Version is empty")
	}
	if opts.HTTPClient == nil {
		return fmt.Errorf("HTTPClient is nil")
	}
	if opts.Owner == "" {
		opts.Owner = DefaultOwner
	}
	if opts.Repo == "" {
		opts.Repo = DefaultRepo
	}

	archiveName := opts.Target.ArchiveName(opts.Version)
	checksumsName := release.ChecksumsName(opts.Version)
	if opts.ArchiveURL == "" {
		opts.ArchiveURL = defaultDownloadURL(opts.Owner, opts.Repo, opts.Version, archiveName)
	}
	if opts.ChecksumsURL == "" {
		opts.ChecksumsURL = defaultDownloadURL(opts.Owner, opts.Repo, opts.Version, checksumsName)
	}

	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	logf("upgrade: downloading checksums (%s)", opts.ChecksumsURL)
	checksumsBlob, err := download(ctx, opts.HTTPClient, opts.ChecksumsURL, 1<<20)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	wantSum, err := lookupChecksum(checksumsBlob, archiveName)
	if err != nil {
		return err
	}

	logf("upgrade: downloading archive (%s)", opts.ArchiveURL)
	// Cap archive size at 64 MiB. yalla's release archives are well
	// under 20 MiB; the limit guards against a hostile mirror serving
	// an unbounded body.
	archiveBlob, err := download(ctx, opts.HTTPClient, opts.ArchiveURL, 64<<20)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	gotSum := sha256Hex(archiveBlob)
	if !strings.EqualFold(gotSum, wantSum) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", archiveName, gotSum, wantSum)
	}
	logf("upgrade: checksum verified (%s)", gotSum)

	binBytes, err := extractBinary(archiveBlob, opts.Target)
	if err != nil {
		return fmt.Errorf("extract binary from %s: %w", archiveName, err)
	}

	if err := atomicReplace(opts.BinaryPath, binBytes); err != nil {
		return fmt.Errorf("replace binary at %s: %w", opts.BinaryPath, err)
	}
	logf("upgrade: replaced %s (%d bytes)", opts.BinaryPath, len(binBytes))
	return nil
}

func defaultDownloadURL(owner, repo, version, name string) string {
	return "https://github.com/" + owner + "/" + repo + "/releases/download/v" + version + "/" + name
}

func download(ctx context.Context, c *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "yalla-upgrade")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	if max <= 0 {
		max = 64 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response from %s exceeded %d bytes", url, max)
	}
	return body, nil
}

// lookupChecksum scans a GoReleaser-style checksums file (lines of
// `<sha256>  <filename>`) for the supplied filename and returns its
// SHA-256 hex digest. The format matches `.goreleaser.yaml`'s
// `checksum.algorithm: sha256` default.
func lookupChecksum(blob []byte, name string) (string, error) {
	scanner := strings.Split(string(blob), "\n")
	for _, line := range scanner {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerate one or many spaces; GoReleaser writes two.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found in checksums.txt", name)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// extractBinary pulls the yalla binary out of a release archive. tar.gz
// archives use the standard library; .zip archives use archive/zip.
// Both inspect every entry by basename so a future archive layout
// change (e.g. a top-level directory) does not break extraction.
func extractBinary(archive []byte, target release.Target) ([]byte, error) {
	want := target.BinaryName()
	if strings.HasSuffix(strings.ToLower(target.ArchiveExt()), ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("open zip: %w", err)
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) != want {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open %s in zip: %w", f.Name, err)
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 200<<20))
		}
		return nil, fmt.Errorf("zip archive does not contain %s", want)
	}

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if filepath.Base(hdr.Name) != want {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, 200<<20))
	}
	return nil, fmt.Errorf("tar.gz archive does not contain %s", want)
}

// atomicReplace writes content to a sibling temp file in the target
// directory, then renames it over dst. On Unix the rename is atomic
// because both files share a directory and a filesystem; on Windows
// os.Rename calls MoveFileEx with MOVEFILE_REPLACE_EXISTING which is
// equivalent for our purposes (a partial download never replaces the
// running binary).
func atomicReplace(dst string, content []byte) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".yalla-upgrade-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer func() {
		// Cleanup only fires when we did not Rename (success path
		// removes the file from disk). Use a sentinel via os.Stat.
		if _, err := os.Stat(tmpName); err == nil {
			cleanup()
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// 0o755 mirrors a typical Unix executable. On Windows the call is
	// a no-op (mode bits are advisory) but harmless.
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}
