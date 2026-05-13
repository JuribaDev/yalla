package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/dokploy"
)

func newDeployCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "deploy", Short: "Deploy composite Dokploy resources", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newDeployComposeCommand())
	return cmd
}

func newDeployComposeCommand() *cobra.Command {
	var opts dokploy.DeployComposeOptions
	cmd := &cobra.Command{Use: "compose", Short: "Deploy a Docker Compose stack", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		if opts.DryRun {
			res, err := dokploy.DeployCompose(c.Context(), nil, opts)
			if err != nil {
				return err
			}
			if r.JSON() {
				return r.Data(res)
			}
			r.Human("DRY RUN")
			return nil
		}
		runner, err := newDokployRunner(configFromCommand(c), BuildInfoFromContext(c.Context()), opts.Timeout)
		if err != nil {
			return err
		}
		res, err := dokploy.DeployCompose(c.Context(), runner, opts)
		if err != nil {
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		r.Human(res.Status)
		return nil
	}}
	cmd.Flags().StringVar(&opts.Project, "project", "", "project name")
	cmd.Flags().StringVar(&opts.Environment, "env", "", "environment name")
	cmd.Flags().StringVar(&opts.ComposeFile, "compose-file", "", "docker compose file")
	cmd.Flags().StringVar(&opts.EnvFile, "env-file", "", "env file")
	cmd.Flags().StringArrayVar(&opts.Domains, "domain", nil, "domain binding host:service:port")
	cmd.Flags().BoolVar(&opts.GetOrCreate, "get-or-create", false, "reuse existing exact-name resources")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "print planned operations without mutating Dokploy")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "deployment timeout")
	return cmd
}
