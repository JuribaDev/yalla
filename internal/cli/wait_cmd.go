package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/dokploy"
)

func newWaitCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "wait", Short: "Wait for Dokploy state", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newWaitComposeCommand(), newWaitURLCommand(), newWaitOrphansCommand())
	return cmd
}

func newWaitComposeCommand() *cobra.Command {
	var id, status string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "compose", Short: "Wait for a compose status", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		runner, err := newDokployRunner(configFromCommand(c), BuildInfoFromContext(c.Context()), 0)
		if err != nil {
			return err
		}
		ctx := c.Context()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		res, err := dokploy.WaitCompose(ctx, runner, id, status, time.Second)
		if err != nil {
			if res != nil {
				return dokploy.TimeoutError(res)
			}
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		r.Human(res.Status)
		return nil
	}}
	cmd.Flags().StringVar(&id, "id", "", "compose id")
	cmd.Flags().StringVar(&status, "status", "done", "desired status")
	cmd.Flags().DurationVar(&timeout, "timeout", 300*time.Second, "maximum wait")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newWaitURLCommand() *cobra.Command {
	var rawURL, class string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "url", Short: "Wait for an HTTP status class", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		ctx := c.Context()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		res, err := dokploy.WaitURL(ctx, rawURL, class, time.Second)
		if err != nil {
			if res != nil {
				return dokploy.TimeoutError(res)
			}
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		r.Human(res.Status)
		return nil
	}}
	cmd.Flags().StringVar(&rawURL, "url", "", "URL to probe")
	cmd.Flags().StringVar(&class, "status-class", "2xx", "desired status class")
	cmd.Flags().DurationVar(&timeout, "timeout", 120*time.Second, "maximum wait")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func newWaitOrphansCommand() *cobra.Command {
	var appName string
	var count int
	var timeout time.Duration
	cmd := &cobra.Command{Use: "orphans", Short: "Wait for orphan container count", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		runner, err := newDokployRunner(configFromCommand(c), BuildInfoFromContext(c.Context()), 0)
		if err != nil {
			return err
		}
		ctx := c.Context()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		res, err := dokploy.WaitOrphans(ctx, runner, appName, count, time.Second)
		if err != nil {
			if res != nil {
				return dokploy.TimeoutError(res)
			}
			return err
		}
		if r.JSON() {
			return r.Data(res)
		}
		r.Human(appName)
		return nil
	}}
	cmd.Flags().StringVar(&appName, "app-name", "", "Dokploy appName")
	cmd.Flags().IntVar(&count, "count", 0, "desired count")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "maximum wait")
	_ = cmd.MarkFlagRequired("app-name")
	return cmd
}
