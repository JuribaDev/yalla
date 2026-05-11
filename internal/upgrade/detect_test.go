package upgrade

import (
	"path/filepath"
	"testing"
)

// TestDetect_AllChannels exercises every install-method decision branch
// listed in the US-0010 acceptance criteria. Each entry pins one
// representative path for the channel; the test fails fast when any
// branch is reclassified, so renaming a channel is automatically a
// public-API change.
func TestDetect_AllChannels(t *testing.T) {
	noEnv := func(string) (string, bool) { return "", false }

	cases := []struct {
		name       string
		probe      Probe
		wantChan   Channel
		wantSelfUp bool
	}{
		// Homebrew: classic Cellar layout under /usr/local on Intel
		// macOS. The Cellar segment is the canonical signal regardless
		// of the prefix.
		{
			name:     "homebrew_cellar_intel_mac",
			probe:    Probe{BinaryPath: "/usr/local/Cellar/yalla/0.1.0/bin/yalla", GOOS: "darwin", Env: noEnv},
			wantChan: ChannelHomebrew,
		},
		// Homebrew Apple Silicon prefix (`/opt/homebrew`).
		{
			name:     "homebrew_cellar_apple_silicon",
			probe:    Probe{BinaryPath: "/opt/homebrew/Cellar/yalla/0.1.0/bin/yalla", GOOS: "darwin", Env: noEnv},
			wantChan: ChannelHomebrew,
		},
		// Homebrew on Linux defaults to `/home/linuxbrew/.linuxbrew`.
		{
			name:     "homebrew_linux",
			probe:    Probe{BinaryPath: "/home/linuxbrew/.linuxbrew/Cellar/yalla/0.1.0/bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan: ChannelHomebrew,
		},
		// Homebrew via HOMEBREW_PREFIX env when the path-segment check
		// somehow missed (rare, e.g. custom symlink).
		{
			name: "homebrew_env_prefix_match",
			probe: Probe{
				BinaryPath: "/opt/custom-brew/yalla-bin/yalla",
				GOOS:       "darwin",
				Env: func(k string) (string, bool) {
					if k == "HOMEBREW_PREFIX" {
						return "/opt/custom-brew", true
					}
					return "", false
				},
			},
			wantChan: ChannelHomebrew,
		},
		// npm global on Linux: prefix/lib/node_modules/yalla-cli/bin/yalla.js
		// is what the yalla shim resolves to.
		{
			name:     "npm_global_linux",
			probe:    Probe{BinaryPath: "/usr/local/lib/node_modules/yalla-cli/bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan: ChannelNPM,
		},
		// npm via .bin shim path (yarn workspaces).
		{
			name:     "npm_bin_shim",
			probe:    Probe{BinaryPath: "/home/dev/project/node_modules/.bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan: ChannelNPM,
		},
		// npm on Windows uses backslashes.
		{
			name:     "npm_global_windows",
			probe:    Probe{BinaryPath: `C:\Users\dev\AppData\Roaming\npm\node_modules\yalla-cli\bin\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan: ChannelNPM,
		},
		// npx cache (npm 7+): the `_npx/` segment beats the
		// node_modules check because it is more specific.
		{
			name:     "npx_npm7_cache",
			probe:    Probe{BinaryPath: "/home/dev/.npm/_npx/abc123/node_modules/yalla-cli/bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan: ChannelNPX,
		},
		// Scoop: `<scoop>\apps\yalla\<version>\yalla.exe`.
		{
			name:     "scoop_apps",
			probe:    Probe{BinaryPath: `C:\Users\dev\scoop\apps\yalla\current\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan: ChannelScoop,
		},
		// Scoop shims path.
		{
			name:     "scoop_shim",
			probe:    Probe{BinaryPath: `C:\Users\dev\scoop\shims\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan: ChannelScoop,
		},
		// WinGet user-scope packages folder.
		{
			name:     "winget_packages",
			probe:    Probe{BinaryPath: `C:\Users\dev\AppData\Local\Microsoft\WinGet\Packages\JuribaDev.Yalla__DefaultSource\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan: ChannelWinGet,
		},
		// WindowsApps system-scope folder.
		{
			name:     "winget_windowsapps",
			probe:    Probe{BinaryPath: `C:\Program Files\WindowsApps\JuribaDev.Yalla_0.1.0.0_x64__placeholder\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan: ChannelWinGet,
		},
		// Manual: hand-installed into /usr/local/bin without any
		// package manager footprint.
		{
			name:       "manual_usr_local_bin",
			probe:      Probe{BinaryPath: "/usr/local/bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan:   ChannelManual,
			wantSelfUp: true,
		},
		// Manual: ~/.local/bin/yalla — the modern XDG default.
		{
			name:       "manual_dot_local_bin",
			probe:      Probe{BinaryPath: "/home/dev/.local/bin/yalla", GOOS: "linux", Env: noEnv},
			wantChan:   ChannelManual,
			wantSelfUp: true,
		},
		// Manual on Windows: a hand-installed yalla.exe somewhere not
		// owned by Scoop/WinGet/npm.
		{
			name:       "manual_windows_loose",
			probe:      Probe{BinaryPath: `C:\Tools\bin\yalla.exe`, GOOS: "windows", Env: noEnv},
			wantChan:   ChannelManual,
			wantSelfUp: true,
		},
		// Unknown layout: a chroot path that does not match any of
		// the heuristics. We must NOT classify as Manual to avoid
		// overwriting a binary we do not own.
		{
			name:     "unknown_chroot_path",
			probe:    Probe{BinaryPath: "/srv/containers/app/build/output/yalla", GOOS: "linux", Env: noEnv},
			wantChan: ChannelUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.probe)
			if got != tc.wantChan {
				t.Fatalf("Detect(%q on %s) = %q, want %q", tc.probe.BinaryPath, tc.probe.GOOS, got, tc.wantChan)
			}
			plan := PlanFor(got, tc.probe.BinaryPath)
			if plan.SelfUpgradable != tc.wantSelfUp {
				t.Errorf("PlanFor(%q).SelfUpgradable = %v, want %v", got, plan.SelfUpgradable, tc.wantSelfUp)
			}
			if plan.Note == "" {
				t.Error("PlanFor must always supply a Note string")
			}
			// Manual + Unknown are the only channels with no command.
			switch got {
			case ChannelManual, ChannelUnknown:
				if plan.Command != "" {
					t.Errorf("PlanFor(%q).Command = %q, want empty", got, plan.Command)
				}
			default:
				if plan.Command == "" {
					t.Errorf("PlanFor(%q).Command = empty, want a package-manager command", got)
				}
			}
		})
	}
}

// TestDetect_NilEnvLookup proves a Probe with a nil Env lookup does not
// panic. Production callers always pass os.LookupEnv but the public
// surface should be defensive.
func TestDetect_NilEnvLookup(t *testing.T) {
	got := Detect(Probe{BinaryPath: "/usr/local/bin/yalla", GOOS: "linux"})
	if got != ChannelManual {
		t.Errorf("Detect(nil env) = %q, want %q", got, ChannelManual)
	}
}

// TestDefaultProbe_NormalisesPath ensures filepath.Clean is applied so
// detection cannot be fooled by a redundant `..` segment in the
// resolved executable path. The expected value runs through
// filepath.FromSlash so the assertion holds on Windows runners (where
// filepath.Clean swaps `/` for `\`) without weakening the Unix shape.
func TestDefaultProbe_NormalisesPath(t *testing.T) {
	p := DefaultProbe("/usr/local/lib/../bin/yalla", "linux", nil)
	want := filepath.FromSlash("/usr/local/bin/yalla")
	if p.BinaryPath != want {
		t.Errorf("DefaultProbe.BinaryPath = %q, want %q", p.BinaryPath, want)
	}
}
