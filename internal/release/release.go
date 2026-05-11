// Package release groups the assertions that keep the production
// distribution surface honest.
//
// The release pipeline (GoReleaser + GitHub Actions + the npm wrapper)
// is *external* to the binary, but the matrix of OS/arch coordinates,
// archive name templates, and checksum format is part of the public
// agent contract. This package exposes the canonical constants the
// tests use and that future stories (US-0010 channel-aware upgrade,
// US-0011 verification gates) can re-import without re-deriving the
// values from the goreleaser config.
package release

// SupportedTargets enumerates every (GOOS, GOARCH) pair yalla ships.
// Update this together with the matching `builds` section in
// .goreleaser.yaml and lib/platform.js in the npm wrapper.
var SupportedTargets = []Target{
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "windows", Arch: "amd64"},
	{OS: "windows", Arch: "arm64"},
}

// Target is a build-matrix coordinate. The string form
// `<os>_<arch>` is a public identifier embedded in archive names and
// the npm wrapper's release URL builder; renaming a target is a
// breaking change.
type Target struct {
	OS, Arch string
}

// ArchiveExt returns the archive extension for the target. Windows
// uses zip (matches `format_overrides` in .goreleaser.yaml); the rest
// use tar.gz.
func (t Target) ArchiveExt() string {
	if t.OS == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

// BinaryName returns the bare binary filename inside an archive.
func (t Target) BinaryName() string {
	if t.OS == "windows" {
		return "yalla.exe"
	}
	return "yalla"
}

// ArchiveName builds the archive name for a given semver string.
// It mirrors `archives[0].name_template` in .goreleaser.yaml so the
// npm wrapper's `lib/platform.js` and the GoReleaser output stay in
// lockstep — the test in this package fails fast when they drift.
func (t Target) ArchiveName(version string) string {
	return "yalla_" + version + "_" + t.OS + "_" + t.Arch + t.ArchiveExt()
}

// ChecksumsName mirrors `checksum.name_template` in .goreleaser.yaml.
func ChecksumsName(version string) string {
	return "yalla_" + version + "_checksums.txt"
}
