package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/dokploy"
)

func newTeardownCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "teardown", Short: "Safely remove Dokploy resources", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newTeardownProjectCommand())
	return cmd
}

func newTeardownProjectCommand() *cobra.Command {
	var opts dokploy.TeardownOptions
	cmd := &cobra.Command{Use: "project", Short: "Teardown a project and assert no orphans remain", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		if opts.NoCascade {
			r.Logf("warning: --no-cascade uses raw project-remove behavior and may leave resources behind")
		}
		if opts.DryRun {
			res, err := dokploy.TeardownProject(c.Context(), nil, opts)
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
		res, err := dokploy.TeardownProject(c.Context(), runner, opts)
		if err != nil {
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		r.Human("removed " + res.Project)
		return nil
	}}
	cmd.Flags().StringVar(&opts.Project, "project", "", "project name or id")
	cmd.Flags().BoolVar(&opts.NoCascade, "no-cascade", false, "use raw project-remove behavior")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "print planned operations")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "teardown timeout")
	_ = cmd.MarkFlagRequired("project")
	return cmd
}
