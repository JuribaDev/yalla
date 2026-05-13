package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/output"
	"github.com/JuribaDev/yalla/internal/upgrade"
)

// withUpgradeProbe overrides the channel-detection probe and restores
// the original at test cleanup. Tests use this to drive specific
// channels without relying on the host filesystem layout.
func withUpgradeProbe(t *testing.T, probe upgrade.Probe) {
	t.Helper()
	orig := upgradeProbeFactory
	upgradeProbeFactory = func() (upgrade.Probe, error) { return probe, nil }
	t.Cleanup(func() { upgradeProbeFactory = orig })
}

// withUpgradeCheckBaseURL points the GitHub-Releases lookup at an
// httptest.Server so unit tests never hit the public API.
func withUpgradeCheckBaseURL(t *testing.T, url string) {
	t.Helper()
	orig := upgradeCheckBaseURL
	upgradeCheckBaseURL = url
	t.Cleanup(func() { upgradeCheckBaseURL = orig })
}

// fakeReleasesServer returns a stub /releases/latest endpoint that
// responds with the supplied tag and asset list.
func fakeReleasesServer(t *testing.T, tag string, assets []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body := map[string]any{
			"tag_name":   tag,
			"name":       tag,
			"prerelease": false,
			"draft":      false,
			"html_url":   "https://example.invalid/releases/" + tag,
			"assets":     assets,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpgradeCheck_JSON_NoUpdateAvailable(t *testing.T) {
	withTempConfig(t, "")
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: "/usr/local/bin/yalla",
		GOOS:       "linux",
		Env:        func(string) (string, bool) { return "", false },
	})
	srv := fakeReleasesServer(t, "v0.1.0", nil)
	withUpgradeCheckBaseURL(t, srv.URL)

	streams, stdout, stderr := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.1.0"})
	cmd.SetArgs([]string{"--json", "upgrade", "--check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr.String())
	}
	if stderr.String() != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr.String())
	}
	var env struct {
		SchemaVersion string           `json:"schema_version"`
		Data          upgradeStatusDoc `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout.String())
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.UpdateAvailable {
		t.Error("update_available = true; want false")
	}
	if env.Data.Action != upgradeActionUpToDate {
		t.Errorf("action = %q, want %q", env.Data.Action, upgradeActionUpToDate)
	}
	if env.Data.Plan.Channel != upgrade.ChannelManual {
		t.Errorf("plan.channel = %q, want %q", env.Data.Plan.Channel, upgrade.ChannelManual)
	}
}

func TestUpgradeCheck_JSON_HomebrewReportsBrewCommand(t *testing.T) {
	withTempConfig(t, "")
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: "/opt/homebrew/Cellar/yalla/0.1.0/bin/yalla",
		GOOS:       "darwin",
		Env:        func(string) (string, bool) { return "", false },
	})
	srv := fakeReleasesServer(t, "v0.2.0", nil)
	withUpgradeCheckBaseURL(t, srv.URL)

	streams, stdout, _ := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.1.0"})
	cmd.SetArgs([]string{"--json", "upgrade", "--check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var env struct {
		Data upgradeStatusDoc `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !env.Data.UpdateAvailable {
		t.Fatal("update_available = false; want true")
	}
	if env.Data.Action != upgradeActionReportPackageMgr {
		t.Errorf("action = %q, want %q", env.Data.Action, upgradeActionReportPackageMgr)
	}
	if env.Data.Plan.Channel != upgrade.ChannelHomebrew {
		t.Errorf("plan.channel = %q, want %q", env.Data.Plan.Channel, upgrade.ChannelHomebrew)
	}
	if env.Data.Plan.Command != "brew upgrade yalla" {
		t.Errorf("plan.command = %q, want %q", env.Data.Plan.Command, "brew upgrade yalla")
	}
	if env.Data.Plan.SelfUpgradable {
		t.Error("plan.self_upgradable = true; want false on homebrew")
	}
}

// Each remaining package-manager channel is verified through the same
// pattern: the JSON envelope must surface the canonical command and
// must NOT mark self_upgradable=true.
func TestUpgradeCheck_JSON_PackageManagerChannels(t *testing.T) {
	cases := []struct {
		name    string
		probe   upgrade.Probe
		channel upgrade.Channel
		command string
	}{
		{
			name: "npm",
			probe: upgrade.Probe{
				BinaryPath: "/usr/local/lib/node_modules/@juriba/yalla-cli/bin/yalla",
				GOOS:       "linux",
			},
			channel: upgrade.ChannelNPM,
			command: "npm install -g @juriba/yalla-cli@latest",
		},
		{
			name: "npx",
			probe: upgrade.Probe{
				BinaryPath: "/home/dev/.npm/_npx/abc/node_modules/@juriba/yalla-cli/bin/yalla",
				GOOS:       "linux",
			},
			channel: upgrade.ChannelNPX,
			command: "npx @juriba/yalla-cli@latest",
		},
		{
			name: "scoop",
			probe: upgrade.Probe{
				BinaryPath: `C:\Users\dev\scoop\shims\yalla.exe`,
				GOOS:       "windows",
			},
			channel: upgrade.ChannelScoop,
			command: "scoop update yalla",
		},
		{
			name: "winget",
			probe: upgrade.Probe{
				BinaryPath: `C:\Program Files\WindowsApps\JuribaDev.Yalla__placeholder\yalla.exe`,
				GOOS:       "windows",
			},
			channel: upgrade.ChannelWinGet,
			command: "winget upgrade JuribaDev.Yalla",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTempConfig(t, "")
			tc.probe.Env = func(string) (string, bool) { return "", false }
			withUpgradeProbe(t, tc.probe)
			srv := fakeReleasesServer(t, "v0.2.0", nil)
			withUpgradeCheckBaseURL(t, srv.URL)

			streams, stdout, _ := testStreams()
			cmd := NewRootCommand(streams, BuildInfo{Version: "0.1.0"})
			cmd.SetArgs([]string{"--json", "upgrade", "--check"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			var env struct {
				Data upgradeStatusDoc `json:"data"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if env.Data.Plan.Channel != tc.channel {
				t.Errorf("channel = %q, want %q", env.Data.Plan.Channel, tc.channel)
			}
			if env.Data.Plan.Command != tc.command {
				t.Errorf("command = %q, want %q", env.Data.Plan.Command, tc.command)
			}
			if env.Data.Plan.SelfUpgradable {
				t.Error("self_upgradable = true; want false on package-managed channel")
			}
		})
	}
}

func TestUpgradeYes_NonManualChannel_ReturnsUnsupported(t *testing.T) {
	withTempConfig(t, "")
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: "/opt/homebrew/Cellar/yalla/0.1.0/bin/yalla",
		GOOS:       "darwin",
		Env:        func(string) (string, bool) { return "", false },
	})
	srv := fakeReleasesServer(t, "v0.2.0", nil)
	withUpgradeCheckBaseURL(t, srv.URL)

	stdout, stderr, err := runRootArgs(t, "--json", "upgrade", "--yes")
	if err == nil {
		t.Fatalf("expected error from --yes on homebrew, got nil; stdout=%q stderr=%q", stdout, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty on error; got %q", stdout)
	}
	if !strings.Contains(stderr, "E_UNSUPPORTED") {
		t.Errorf("stderr missing E_UNSUPPORTED; got %q", stderr)
	}
	if !strings.Contains(stderr, "brew upgrade yalla") {
		t.Errorf("stderr should suggest the brew command; got %q", stderr)
	}
}

func TestUpgradeYes_ManualChannel_DownloadsAndReplaces(t *testing.T) {
	withTempConfig(t, "")

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Path ends in /bin/yalla so Detect classifies it as Manual.
	bin := filepath.Join(binDir, "yalla")
	if err := os.WriteFile(bin, []byte("OLD"), 0o755); err != nil {
		t.Fatalf("seed bin: %v", err)
	}
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: bin,
		GOOS:       runtime.GOOS,
		Env:        func(string) (string, bool) { return "", false },
	})

	// Build a fresh archive matching the current GOOS/GOARCH so the
	// runtime target picked by runUpgrade resolves to a known asset.
	binaryContent := []byte("NEW-BINARY")
	var archiveBuf bytes.Buffer
	gz := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gz)
	binaryName := "yalla"
	if runtime.GOOS == "windows" {
		binaryName = "yalla.exe"
	}
	hdr := &tar.Header{Name: binaryName, Mode: 0o755, Size: int64(len(binaryContent))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	archive := archiveBuf.Bytes()
	if runtime.GOOS == "windows" {
		// On Windows the archive is .zip — skip the deep apply path on
		// non-windows runners since the URL/release wiring is identical.
		t.Skip("windows zip variant covered by upgrade.ApplyManual_WindowsZip")
	}

	sum := sha256.Sum256(archive)
	checksumLine := hex.EncodeToString(sum[:]) + "  yalla_0.2.0_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/download/archive", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc("/download/checksums", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksumLine)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// The /releases/latest handler embeds the archive URL the apply
	// path will hit. Registering it after the server is up lets us
	// inline srv.URL.
	mux.HandleFunc("/repos/JuribaDev/yalla/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"tag_name": "v0.2.0", "name": "v0.2.0", "prerelease": false, "draft": false,
			"html_url": "https://example.invalid/releases/v0.2.0",
			"assets": []map[string]any{
				{
					"name":                 "yalla_0.2.0_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz",
					"size":                 int64(len(archive)),
					"browser_download_url": srv.URL + "/download/archive",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	// The upgrade asset URL embedded in the GitHub payload matters
	// only for the JSON envelope; the apply path consults
	// upgradeApplyArchiveURL/upgradeApplyChecksums when set. Override
	// both to point at our stub server.
	withUpgradeCheckBaseURL(t, srv.URL)
	origArchive, origChecksums := upgradeApplyArchiveURL, upgradeApplyChecksums
	upgradeApplyArchiveURL = srv.URL + "/download/archive"
	upgradeApplyChecksums = srv.URL + "/download/checksums"
	t.Cleanup(func() {
		upgradeApplyArchiveURL = origArchive
		upgradeApplyChecksums = origChecksums
	})

	streams, stdout, _ := testStreams()
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.1.0"})
	cmd.SetArgs([]string{"--json", "upgrade", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var env struct {
		Data upgradeStatusDoc `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout.String())
	}
	if !env.Data.Applied {
		t.Errorf("applied = false; want true")
	}
	if env.Data.Action != upgradeActionApplied {
		t.Errorf("action = %q, want %q", env.Data.Action, upgradeActionApplied)
	}
	got, _ := os.ReadFile(bin)
	if !bytes.Equal(got, binaryContent) {
		t.Errorf("replaced contents = %q, want %q", got, binaryContent)
	}
}

func TestUpgrade_NoInputDoesNotPrompt(t *testing.T) {
	withTempConfig(t, "")
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: "/usr/local/bin/yalla",
		GOOS:       "linux",
		Env:        func(string) (string, bool) { return "", false },
	})
	srv := fakeReleasesServer(t, "v0.1.0", nil)
	withUpgradeCheckBaseURL(t, srv.URL)

	streams, stdout, _ := testStreams()
	streams.In = blockingReader{}
	cmd := NewRootCommand(streams, BuildInfo{Version: "0.1.0"})
	cmd.SetArgs([]string{"--no-input", "--json", "upgrade", "--check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("expected JSON envelope on stdout")
	}
}

func TestUpgrade_CheckAndYesAreMutuallyExclusive(t *testing.T) {
	withTempConfig(t, "")
	stdout, stderr, err := runRootArgs(t, "--json", "upgrade", "--check", "--yes")
	if err == nil {
		t.Fatal("expected error when --check and --yes are combined")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "E_USAGE") {
		t.Errorf("stderr should classify as E_USAGE; got %q", stderr)
	}
}

func TestUpgrade_NetworkErrorMapsToCodeNetwork(t *testing.T) {
	withTempConfig(t, "")
	withUpgradeProbe(t, upgrade.Probe{
		BinaryPath: "/usr/local/bin/yalla",
		GOOS:       "linux",
		Env:        func(string) (string, bool) { return "", false },
	})
	// Closed server URL triggers a connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()
	withUpgradeCheckBaseURL(t, srv.URL)

	stdout, stderr, err := runRootArgs(t, "--json", "upgrade", "--check")
	if err == nil {
		t.Fatal("expected network error")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on error", stdout)
	}
	if !strings.Contains(stderr, "E_NETWORK") {
		t.Errorf("stderr should be E_NETWORK; got %q", stderr)
	}
}
