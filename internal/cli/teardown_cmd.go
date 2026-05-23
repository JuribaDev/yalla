package cli

import (
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newTeardownCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "teardown", Short: "Remove Yalla resources through the backend", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newTeardownProjectCommand())
	return cmd
}

func newTeardownProjectCommand() *cobra.Command {
	var projectID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "project", Short: "Delete a project through the Yalla backend", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		if strings.TrimSpace(projectID) == "" {
			return yerr.New(yerr.CodeInvalidInput, "project ID is required").WithHint("pass --project-id")
		}
		cli, err := newYallaAPIClient(configFromCommand(c), BuildInfoFromContext(c.Context()), timeout)
		if err != nil {
			return err
		}
		data, _, err := yallaJSONRequest(c.Context(), cli, http.MethodDelete, yallaPath("v1/projects", pathID(projectID)), nil, false)
		if err != nil {
			return err
		}
		if r.JSON() {
			return r.Data(data)
		}
		r.Human("project deletion accepted")
		return nil
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "request timeout")
	return cmd
}
