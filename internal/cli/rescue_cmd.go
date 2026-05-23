package cli

import (
	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newRescueCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "rescue", Short: "Backend-mediated rescue diagnostics", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newRescueOrphansCommand())
	return cmd
}

func newRescueOrphansCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "orphans", Short: "Deprecated direct Dokploy orphan cleanup", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		return yerr.New(yerr.CodeUnsupported, "direct Dokploy orphan cleanup is not available in backend-only CLI mode").
			WithHint("use audited Yalla backend admin diagnostics")
	}}
	return cmd
}
