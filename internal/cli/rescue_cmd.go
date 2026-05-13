package cli

import (
	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/dokploy"
)

func newRescueCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "rescue", Short: "Recover from orphaned Dokploy resources", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newRescueOrphansCommand())
	return cmd
}

func newRescueOrphansCommand() *cobra.Command {
	var opts dokploy.RescueOptions
	cmd := &cobra.Command{Use: "orphans", Short: "Remove orphan containers by appName", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		runner, err := newDokployRunner(configFromCommand(c), BuildInfoFromContext(c.Context()), 0)
		if err != nil {
			return err
		}
		res, err := dokploy.RescueOrphans(c.Context(), runner, opts)
		if err != nil {
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		if res.Command != "" {
			r.Human(res.Command)
		} else {
			r.Human(opts.AppName)
		}
		return nil
	}}
	cmd.Flags().StringVar(&opts.AppName, "app-name", "", "Dokploy appName")
	cmd.Flags().StringVar(&opts.SSH, "ssh", "", "SSH target for fallback cleanup")
	cmd.Flags().BoolVar(&opts.ExecuteSSH, "execute-ssh", false, "execute the SSH fallback command")
	_ = cmd.MarkFlagRequired("app-name")
	return cmd
}
