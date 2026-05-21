package cli

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newProjectCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "project", Short: "Manage projects through the Yalla backend", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(
		newProjectListCommand(),
		newProjectGetCommand(),
		newProjectCreateCommand(),
		newProjectUpdateCommand(),
		newProjectDeleteCommand(),
		newProjectRestoreCommand(),
	)
	return cmd
}

func newProjectListCommand() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{Use: "list", Short: "List projects", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		data, err := yallaBackendRequest(c, http.MethodGet, "/v1/projects", nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "projects")
	}}
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newProjectGetCommand() *cobra.Command {
	var projectID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "get", Short: "Get a project", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/projects", pathID(projectID)), nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "project")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newProjectCreateCommand() *cobra.Command {
	var projectID, name, displayName, idempotencyKey string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "create", Short: "Create a project", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(name, "project name", "--name"); err != nil {
			return err
		}
		if strings.TrimSpace(projectID) == "" {
			projectID = domain.MustNewID(domain.KindProject).String()
		}
		if strings.TrimSpace(displayName) == "" {
			displayName = name
		}
		body := map[string]string{"project_id": projectID, "slug": name, "display_name": displayName}
		if strings.TrimSpace(idempotencyKey) != "" {
			body["idempotency_key"] = idempotencyKey
		}
		data, err := yallaBackendRequest(c, http.MethodPost, "/v1/projects", body, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "project created")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID; generated when omitted")
	cmd.Flags().StringVar(&name, "name", "", "project slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "project display name")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newProjectUpdateCommand() *cobra.Command {
	var projectID, name, displayName string
	var ifMatch int64
	var timeout time.Duration
	cmd := &cobra.Command{Use: "update", Short: "Update a project", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		body := map[string]string{}
		if strings.TrimSpace(name) != "" {
			body["slug"] = name
		}
		if strings.TrimSpace(displayName) != "" {
			body["display_name"] = displayName
		}
		if len(body) == 0 {
			return yerr.New(yerr.CodeInvalidInput, "at least one project field is required").WithHint("pass --name or --display-name")
		}
		data, err := yallaBackendRequest(c, http.MethodPatch, yallaPath("v1/projects", pathID(projectID)), body, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "project updated")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().StringVar(&name, "name", "", "project slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "project display name")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newProjectDeleteCommand() *cobra.Command {
	var projectID string
	var ifMatch int64
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "delete", Short: "Delete a project", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodDelete, yallaPath("v1/projects", pathID(projectID)), nil, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		if wait {
			if waited, waitErr := waitOnBackendJobFromData(c, data, timeout, pollInterval); waitErr != nil {
				return waitErr
			} else if waited != nil {
				data = waited
			}
		}
		return renderBackendData(c, data, "project deletion accepted")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func newProjectRestoreCommand() *cobra.Command {
	var projectID string
	var ifMatch int64
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "restore", Short: "Restore a soft-deleted project", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodPost, yallaPath("v1/projects", pathID(projectID), "restore"), nil, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		if wait {
			if waited, waitErr := waitOnBackendJobFromData(c, data, timeout, pollInterval); waitErr != nil {
				return waitErr
			} else if waited != nil {
				data = waited
			}
		}
		return renderBackendData(c, data, "project restored")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func ifMatchHeader(version int64) http.Header {
	if version <= 0 {
		return nil
	}
	h := http.Header{}
	h.Set("If-Match", strconv.FormatInt(version, 10))
	return h
}
