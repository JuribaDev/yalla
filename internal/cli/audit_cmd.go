package cli

import (
	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/audit"
)

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect yalla mutation audit log", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newAuditTailCommand())
	return cmd
}

func newAuditTailCommand() *cobra.Command {
	var lines int
	cmd := &cobra.Command{Use: "tail", Short: "Print recent audit records", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		got, err := audit.DefaultLogger().Tail(lines)
		if err != nil {
			return err
		}
		if r.JSON() {
			return r.Data(map[string]any{"lines": got})
		}
		for _, line := range got {
			r.Human(line)
		}
		return nil
	}}
	cmd.Flags().IntVar(&lines, "lines", 50, "number of lines")
	return cmd
}
