// Package upgrade implements yalla's channel-aware self-update support.
//
// The package never reaches for package-level globals: every public function
// takes its dependencies (HTTP client, environment lookup, GOOS, binary
// path) explicitly so the CLI layer drives them in production and tests
// drive them in-memory.
//
// Two contracts matter for US-0010:
//
//  1. Detection is non-destructive. It only inspects strings (the binary
//     path and a small set of environment variables) — it never spawns
//     subprocesses, never touches the network, and never opens files. That
//     keeps `yalla upgrade --check` cheap, safe, and deterministic in CI.
//
//  2. Self-replacement is gated to the "manual" channel. For every other
//     channel (Homebrew, npm, npx, Scoop, WinGet) yalla reports the native
//     package-manager command and refuses to overwrite files it does not
//     own. This matches the PRD note "Self-update is allowed only for
//     unmanaged/manual binaries."
package upgrade

import (
	"path/filepath"
	"strings"
)

// Channel classifies how the running binary was installed. Values are part
// of the public agent contract: `yalla upgrade --check --json` emits the
// raw string and downstream tooling may switch on it.
type Channel string

// Stable channel identifiers. Renaming any of these is a public-API change
// and must update the JSON envelope, the docs, and the channel test
// matrix together.
const (
	ChannelHomebrew Channel = "homebrew"
	ChannelNPM      Channel = "npm"
	ChannelNPX      Channel = "npx"
	ChannelScoop    Channel = "scoop"
	ChannelWinGet   Channel = "winget"
	ChannelManual   Channel = "manual"
	ChannelUnknown  Channel = "unknown"
)

// Probe is the input to Detect. Every dependency is injected so the
// detector is a pure function: tests construct a Probe with a synthetic
// path + GOOS + env lookup; production passes os.Executable + runtime.GOOS
// + os.LookupEnv via DefaultProbe.
type Probe struct {
	// BinaryPath is the absolute path to the running yalla executable.
	// On most platforms this is what os.Executable returns; on Windows
	// it includes the .exe suffix.
	BinaryPath string

	// GOOS is the runtime OS ("linux", "darwin", "windows", ...). Used to
	// branch on Windows-only channels (Scoop, WinGet) without firing
	// false positives on Unix paths that happen to contain similar
	// substrings.
	GOOS string

	// Env returns the value of an environment variable plus a present
	// bit. Tests inject a closure backed by a map so the detector stays
	// hermetic regardless of the host shell's environment.
	Env func(string) (string, bool)
}

// Detect classifies the running binary's install channel. The order of
// the checks matters: more-specific signals (npx cache) win over
// broader ones (npm node_modules) so `npx yalla upgrade` is reported
// distinctly from `npm install -g @juriba/yalla-cli`.
//
// When no channel matches Detect returns ChannelUnknown rather than
// ChannelManual: ChannelManual is reserved for cases where yalla is
// confident it owns the binary (writable file outside any package
// manager's tree). The CLI layer treats Unknown the same as Manual for
// the purposes of "report a non-package-manager upgrade", but the JSON
// envelope preserves the distinction so an agent can choose to be
// stricter than yalla itself.
func Detect(p Probe) Channel {
	if p.Env == nil {
		p.Env = func(string) (string, bool) { return "", false }
	}
	path := p.BinaryPath

	// npx ships a per-invocation cache that lives under either
	// `~/.npm/_npx/` (older npm) or `<prefix>/_npx/` (npm 7+). The
	// folder name is stable enough to use as a channel signal.
	if pathContainsAny(path, "/_npx/", `\_npx\`) {
		return ChannelNPX
	}

	// Homebrew installs cellar binaries under
	// `<prefix>/Cellar/yalla/<version>/bin/yalla` and links them into
	// `<prefix>/bin/yalla`. The Cellar segment is the canonical signal.
	if pathContainsAny(path, "/Cellar/yalla/", "/Cellar/yalla@") {
		return ChannelHomebrew
	}
	// `<prefix>/opt/yalla/bin/yalla` is also a Homebrew layout (used by
	// keg-only formulae). Match the segment directly so we do not depend
	// on the exact prefix (`/usr/local`, `/opt/homebrew`, ...).
	if pathContainsAny(path, "/opt/yalla/bin/", "/opt/yalla@") {
		return ChannelHomebrew
	}
	if v, ok := p.Env("HOMEBREW_PREFIX"); ok && v != "" {
		// HOMEBREW_PREFIX is exported by `brew shellenv`; if the binary
		// lives under that prefix and we somehow missed the Cellar
		// signal above, classify as Homebrew.
		if hasPathPrefix(path, v) {
			return ChannelHomebrew
		}
	}

	// Scoop on Windows installs apps under
	// `<scoop>\apps\yalla\<version>\yalla.exe` and creates a shim at
	// `<scoop>\shims\yalla.exe`. Both are deterministic markers.
	if p.GOOS == "windows" {
		if pathContainsAny(path, `\scoop\apps\yalla\`, `\scoop\shims\yalla.exe`, `/scoop/apps/yalla/`, `/scoop/shims/yalla.exe`) {
			return ChannelScoop
		}
		if v, ok := p.Env("SCOOP"); ok && v != "" && hasPathPrefix(path, v) {
			return ChannelScoop
		}

		// WinGet installs into either the per-user
		// `%LOCALAPPDATA%\Microsoft\WinGet\Packages\<id>__<source>\` tree
		// or the system `Program Files\WindowsApps\<id>` tree. Either
		// path segment is a stable marker.
		if pathContainsAny(path, `\Microsoft\WinGet\Packages\`, `\WindowsApps\`) {
			return ChannelWinGet
		}
	}

	// npm global installs land under
	// `<prefix>/lib/node_modules/@juriba/yalla-cli/` (Linux/macOS) or
	// `<prefix>\node_modules\@juriba\yalla-cli\` (Windows). The
	// scoped `node_modules/@juriba/yalla-cli/` segment is the source of truth — the
	// trampoline script is at `bin/yalla.js` and a shim is created at
	// `<prefix>/bin/yalla` (or `<prefix>\yalla.cmd` on Windows). When the
	// shim is invoked the resolved binary still lives inside
	// `node_modules/@juriba/yalla-cli`.
	if pathContainsAny(path, "/node_modules/@juriba/yalla-cli/", `\node_modules\@juriba\yalla-cli\`, "/node_modules/yalla-cli/", `\node_modules\yalla-cli\`, "/node_modules/.bin/yalla", `\node_modules\.bin\yalla`) {
		return ChannelNPM
	}

	// Final manual heuristic: yalla looks installed by hand into a
	// "normal" location like `/usr/local/bin`, `~/.local/bin`, or
	// `~/bin`. We classify those as Manual so the CLI knows it can
	// safely self-replace. Anything else falls through to Unknown.
	if pathContainsAny(path,
		"/usr/local/bin/",
		"/usr/bin/",
		"/.local/bin/",
		"/bin/yalla",
	) {
		return ChannelManual
	}
	if p.GOOS == "windows" && (strings.HasSuffix(strings.ToLower(path), `\yalla.exe`) || strings.HasSuffix(strings.ToLower(path), "/yalla.exe")) {
		// On Windows, a bare `yalla.exe` somewhere outside a package
		// manager tree is treated as Manual so `yalla upgrade --yes`
		// can replace it. The Cellar/Scoop/WinGet checks above run
		// first, so we only reach here for hand-installed binaries.
		return ChannelManual
	}

	return ChannelUnknown
}

// DefaultProbe returns a Probe wired to the live process. The CLI layer
// passes the result of os.Executable as binaryPath; runtime.GOOS as goos.
func DefaultProbe(binaryPath, goos string, lookupEnv func(string) (string, bool)) Probe {
	if lookupEnv == nil {
		lookupEnv = func(string) (string, bool) { return "", false }
	}
	return Probe{
		BinaryPath: filepath.Clean(binaryPath),
		GOOS:       goos,
		Env:        lookupEnv,
	}
}

// pathContainsAny reports whether s contains any of the supplied
// substrings. The check is case-sensitive on Unix and case-insensitive
// on Windows-style paths so `C:\Users\X\Scoop\` matches `\scoop\`.
func pathContainsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// hasPathPrefix reports whether s starts with prefix, treating both
// forward and backward slashes as separators. It tolerates trailing
// slashes on the prefix.
func hasPathPrefix(s, prefix string) bool {
	prefix = strings.TrimRight(prefix, `/\`)
	if prefix == "" {
		return false
	}
	if strings.HasPrefix(s, prefix+"/") || strings.HasPrefix(s, prefix+`\`) {
		return true
	}
	low := strings.ToLower(s)
	lp := strings.ToLower(prefix)
	return strings.HasPrefix(low, lp+"/") || strings.HasPrefix(low, lp+`\`)
}
