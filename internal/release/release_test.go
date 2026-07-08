package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/JuribaDev/yalla/internal/release"
)

// projectRoot walks up from this test file until it finds go.mod. We
// avoid hardcoding "../.." so a future package move only fails one
// place — `runtime.Caller` always reports the test file's absolute
// path under `go test`.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot resolve project root")
	}
	dir := filepath.Dir(self)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod walking up from test file")
		}
		dir = parent
	}
}

func readYAML(t *testing.T, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(false) // GoReleaser adds keys we don't model here.
	if err := dec.Decode(into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// goreleaserConfig is the subset of `.goreleaser.yaml` we assert on.
// We deliberately model only the fields whose drift would break the
// distribution contract; everything else is opaque YAML that
// `KnownFields(false)` lets through.
type goreleaserConfig struct {
	Version       int                 `yaml:"version"`
	ProjectName   string              `yaml:"project_name"`
	Builds        []goreleaserBuild   `yaml:"builds"`
	Archives      []goreleaserArchive `yaml:"archives"`
	Checksum      goreleaserChecksum  `yaml:"checksum"`
	HomebrewCasks []map[string]any    `yaml:"homebrew_casks"`
	Scoops        []map[string]any    `yaml:"scoops"`
	Winget        []map[string]any    `yaml:"winget"`
	Release       map[string]any      `yaml:"release"`
	Snapshot      map[string]any      `yaml:"snapshot"`
}

type goreleaserBuild struct {
	ID      string   `yaml:"id"`
	Main    string   `yaml:"main"`
	Binary  string   `yaml:"binary"`
	Goos    []string `yaml:"goos"`
	Goarch  []string `yaml:"goarch"`
	Ldflags []string `yaml:"ldflags"`
	Flags   []string `yaml:"flags"`
}

type goreleaserArchive struct {
	ID              string   `yaml:"id"`
	NameTemplate    string   `yaml:"name_template"`
	Formats         []string `yaml:"formats"`
	FormatOverrides []struct {
		Goos    string   `yaml:"goos"`
		Formats []string `yaml:"formats"`
	} `yaml:"format_overrides"`
	Files []string `yaml:"files"`
}

type goreleaserChecksum struct {
	NameTemplate string `yaml:"name_template"`
	Algorithm    string `yaml:"algorithm"`
}

func TestGoReleaserConfig_CoversEveryTarget(t *testing.T) {
	root := projectRoot(t)
	var cfg goreleaserConfig
	readYAML(t, filepath.Join(root, ".goreleaser.yaml"), &cfg)

	if cfg.Version != 2 {
		t.Fatalf("goreleaser config version = %d, want 2", cfg.Version)
	}
	if cfg.ProjectName != "yalla" {
		t.Fatalf("project_name = %q, want yalla", cfg.ProjectName)
	}
	if len(cfg.Builds) == 0 {
		t.Fatal("builds: must have at least one entry")
	}
	build := cfg.Builds[0]
	if build.Main != "./cmd/yalla" {
		t.Errorf("builds[0].main = %q, want ./cmd/yalla", build.Main)
	}
	if build.Binary != "yalla" {
		t.Errorf("builds[0].binary = %q, want yalla", build.Binary)
	}

	wantOS := map[string]bool{"linux": false, "darwin": false, "windows": false}
	for _, os := range build.Goos {
		if _, ok := wantOS[os]; ok {
			wantOS[os] = true
		}
	}
	for os, seen := range wantOS {
		if !seen {
			t.Errorf("builds[0].goos missing %s", os)
		}
	}

	wantArch := map[string]bool{"amd64": false, "arm64": false}
	for _, a := range build.Goarch {
		if _, ok := wantArch[a]; ok {
			wantArch[a] = true
		}
	}
	for a, seen := range wantArch {
		if !seen {
			t.Errorf("builds[0].goarch missing %s", a)
		}
	}

	mustHaveLDFlag := []string{
		"-X main.Version={{ .Version }}",
		"-X main.Commit={{ .Commit }}",
	}
	joined := strings.Join(build.Ldflags, "\n")
	for _, w := range mustHaveLDFlag {
		if !strings.Contains(joined, w) {
			t.Errorf("ldflags missing %q\nhave:\n%s", w, joined)
		}
	}
	if !contains(build.Flags, "-trimpath") {
		t.Errorf("builds[0].flags missing -trimpath, have %v", build.Flags)
	}
}

func TestGoReleaserConfig_ArchivesAndChecksums(t *testing.T) {
	root := projectRoot(t)
	var cfg goreleaserConfig
	readYAML(t, filepath.Join(root, ".goreleaser.yaml"), &cfg)

	if len(cfg.Archives) == 0 {
		t.Fatal("archives: must have at least one entry")
	}
	a := cfg.Archives[0]
	if !contains(a.Formats, "tar.gz") {
		t.Errorf("archives[0].formats missing tar.gz, have %v", a.Formats)
	}
	foundZip := false
	for _, ov := range a.FormatOverrides {
		if ov.Goos == "windows" && contains(ov.Formats, "zip") {
			foundZip = true
		}
	}
	if !foundZip {
		t.Error("archives[0].format_overrides must map windows -> zip")
	}
	for _, f := range []string{"LICENSE", "README.md"} {
		if !contains(a.Files, f) {
			t.Errorf("archives[0].files missing %s, have %v", f, a.Files)
		}
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("archive references %s but file is missing on disk: %v", f, err)
		}
	}

	if cfg.Checksum.Algorithm != "sha256" {
		t.Errorf("checksum.algorithm = %q, want sha256", cfg.Checksum.Algorithm)
	}
	if got, want := cfg.Checksum.NameTemplate, "{{ .ProjectName }}_{{ .Version }}_checksums.txt"; got != want {
		t.Errorf("checksum.name_template = %q, want %q", got, want)
	}
}

func TestGoReleaserConfig_PackageManagerChannels(t *testing.T) {
	root := projectRoot(t)
	var cfg goreleaserConfig
	readYAML(t, filepath.Join(root, ".goreleaser.yaml"), &cfg)

	if len(cfg.HomebrewCasks) == 0 {
		t.Error("homebrew_casks: at least one tap entry required")
	}
	if len(cfg.Scoops) == 0 {
		t.Error("scoops: at least one bucket entry required")
	}
	if len(cfg.Winget) == 0 {
		t.Error("winget: at least one entry required")
	}
}

func TestArchiveNamesMatchGoReleaserTemplate(t *testing.T) {
	// The npm wrapper builds archive URLs using
	// `yalla_<version>_<os>_<arch><ext>`. The goreleaser config produces
	// the same string from its template. If either side drifts the npm
	// install breaks silently — verify the helper covers every target
	// and produces predictable output.
	for _, tgt := range release.SupportedTargets {
		got := tgt.ArchiveName("1.2.3")
		want := "yalla_1.2.3_" + tgt.OS + "_" + tgt.Arch + tgt.ArchiveExt()
		if got != want {
			t.Errorf("ArchiveName(%s/%s) = %q, want %q", tgt.OS, tgt.Arch, got, want)
		}
	}
	if got, want := release.ChecksumsName("9.9.9"), "yalla_9.9.9_checksums.txt"; got != want {
		t.Errorf("ChecksumsName = %q, want %q", got, want)
	}
}

type npmPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Bin     map[string]string `json:"bin"`
	Files   []string          `json:"files"`
	Scripts map[string]string `json:"scripts"`
	Engines map[string]string `json:"engines"`
	OS      []string          `json:"os"`
	CPU     []string          `json:"cpu"`
}

func TestNPMWrapperPackage(t *testing.T) {
	root := projectRoot(t)
	npm := filepath.Join(root, "npm")

	var pkg npmPackage
	readJSON(t, filepath.Join(npm, "package.json"), &pkg)

	if pkg.Name != "@juriba/yalla-cli" {
		t.Errorf("npm/package.json name = %q, want @juriba/yalla-cli", pkg.Name)
	}
	if got := pkg.Bin["yalla"]; got != "bin/yalla.js" {
		t.Errorf(`bin["yalla"] = %q, want "bin/yalla.js"`, got)
	}
	if pkg.Scripts["postinstall"] == "" {
		t.Error("scripts.postinstall is required so the binary downloads on install")
	}
	if !contains(pkg.Files, "bin/") || !contains(pkg.Files, "lib/") {
		t.Errorf("files must include bin/ and lib/, have %v", pkg.Files)
	}
	wantOSAny := map[string]bool{"darwin": true, "linux": true, "win32": true}
	for _, o := range pkg.OS {
		delete(wantOSAny, o)
	}
	if len(wantOSAny) > 0 {
		t.Errorf("npm os[] must declare darwin/linux/win32, missing %v", wantOSAny)
	}
	wantCPU := map[string]bool{"x64": true, "arm64": true}
	for _, c := range pkg.CPU {
		delete(wantCPU, c)
	}
	if len(wantCPU) > 0 {
		t.Errorf("npm cpu[] must declare x64/arm64, missing %v", wantCPU)
	}

	for _, rel := range []string{
		"bin/yalla.js",
		"install.js",
		"lib/platform.js",
		"lib/install.js",
		"test/wrapper.test.js",
		"AGENTS.md",
		"README.md",
	} {
		if _, err := os.Stat(filepath.Join(npm, rel)); err != nil {
			t.Errorf("npm wrapper missing %s: %v", rel, err)
		}
	}
}

func TestNPMWrapperPlatformMappingMatchesGo(t *testing.T) {
	// Read npm/lib/platform.js and assert the OS/arch maps line up with
	// `release.SupportedTargets`. We do not execute Node from Go tests
	// (Node may not be installed); instead we look for the literal map
	// entries we expect.
	root := projectRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "npm", "lib", "platform.js"))
	if err != nil {
		t.Fatalf("read platform.js: %v", err)
	}
	src := string(body)

	for _, m := range []string{
		"darwin: 'darwin'",
		"linux: 'linux'",
		"win32: 'windows'",
		"x64: 'amd64'",
		"arm64: 'arm64'",
	} {
		if !strings.Contains(src, m) {
			t.Errorf("npm/lib/platform.js missing literal %q — npm wrapper out of sync with release matrix", m)
		}
	}

	// Sanity: every supported target must be expressible by the wrapper.
	seenOS := map[string]bool{}
	seenArch := map[string]bool{}
	for _, tgt := range release.SupportedTargets {
		seenOS[tgt.OS] = true
		seenArch[tgt.Arch] = true
	}
	for _, must := range []string{"darwin", "linux", "windows"} {
		if !seenOS[must] {
			t.Errorf("SupportedTargets must include OS %q", must)
		}
	}
	for _, must := range []string{"amd64", "arm64"} {
		if !seenArch[must] {
			t.Errorf("SupportedTargets must include arch %q", must)
		}
	}
}

func TestReleaseWorkflowsExist(t *testing.T) {
	root := projectRoot(t)
	for _, rel := range []string{
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
	} {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("workflow %s missing: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("workflow %s is empty", rel)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
