package upgrade

// Plan describes how to upgrade yalla on the detected channel. It is the
// machine-readable structure embedded in the `yalla upgrade --check
// --json` envelope so an agent can render the appropriate command for
// the detected channel without parsing strings.
type Plan struct {
	// Channel is the detected install channel.
	Channel Channel `json:"channel"`

	// BinaryPath is the resolved location of the running yalla binary.
	BinaryPath string `json:"binary_path,omitempty"`

	// SelfUpgradable reports whether `yalla upgrade --yes` is allowed
	// to overwrite the binary itself. True only for ChannelManual; every
	// other channel must defer to its package manager.
	SelfUpgradable bool `json:"self_upgradable"`

	// Command is the suggested package-manager invocation for this
	// channel. Empty when the channel is self-upgradable (Manual) or
	// unknown.
	Command string `json:"command,omitempty"`

	// Note is a one-line, human-readable description of the channel and
	// the recommended upgrade path. It is safe to print to stderr.
	Note string `json:"note"`
}

// PlanFor returns the upgrade plan for the supplied channel. The
// returned Plan is deterministic given (channel, binaryPath); it does
// not contact the network or shell out.
func PlanFor(channel Channel, binaryPath string) Plan {
	p := Plan{Channel: channel, BinaryPath: binaryPath}
	switch channel {
	case ChannelHomebrew:
		p.Command = "brew upgrade yalla"
		p.Note = "yalla is managed by Homebrew. Run `brew upgrade yalla` to update."
	case ChannelNPM:
		p.Command = "npm install -g yalla-cli@latest"
		p.Note = "yalla is managed by npm. Run `npm install -g yalla-cli@latest` to update."
	case ChannelNPX:
		p.Command = "npx yalla-cli@latest"
		p.Note = "yalla was launched via npx; the cache is per-invocation. Re-run `npx yalla-cli@latest` to fetch a newer version."
	case ChannelScoop:
		p.Command = "scoop update yalla"
		p.Note = "yalla is managed by Scoop. Run `scoop update yalla` to update."
	case ChannelWinGet:
		p.Command = "winget upgrade JuribaDev.Yalla"
		p.Note = "yalla is managed by WinGet. Run `winget upgrade JuribaDev.Yalla` to update."
	case ChannelManual:
		p.SelfUpgradable = true
		p.Note = "yalla appears to be a manually-installed binary. Run `yalla upgrade --yes` to download and replace it atomically."
	default:
		// ChannelUnknown: be conservative and refuse to self-replace.
		// The agent contract is "never overwrite something we do not
		// own"; an unknown layout might be a corporate package manager,
		// a chroot, or a CI cache that we should leave alone.
		p.Note = "yalla's install layout is not recognised. Re-download from https://github.com/JuribaDev/yalla/releases or use your package manager."
	}
	return p
}
