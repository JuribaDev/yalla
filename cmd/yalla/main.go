// Command yalla is the production binary for the agent-first Dokploy CLI.
//
// Build-time tooling (GoReleaser) overrides Version, Commit, and Date through
// -ldflags. Local builds keep the placeholder values so `yalla --version`
// always returns something useful.
package main

import (
	"os"

	"github.com/JuribaDev/yalla/internal/cli"
)

// Version is the semantic version of the binary. Overridden at release time
// via -ldflags "-X main.Version=...". Plain `go build` keeps the dev sentinel.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func main() {
	os.Exit(cli.Execute(cli.BuildInfo{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}))
}
