package cli

import (
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newEnvironmentCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "environment", Short: "Manage environments through the Yalla backend", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(
		newEnvironmentListCommand(),
		newEnvironmentGetCommand(),
		newEnvironmentCreateCommand(),
		newEnvironmentUpdateCommand(),
		newEnvironmentDeleteCommand(),
		newEnvironmentCloneCommand(),
	)
	return cmd
}

func newEnvironmentListCommand() *cobra.Command {
	var projectID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "list", Short: "List project environments", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/projects", pathID(projectID), "environments"), nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "environments")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newEnvironmentGetCommand() *cobra.Command {
	var environmentID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "get", Short: "Get an environment", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/environments", pathID(environmentID)), nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "environment")
	}}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newEnvironmentCreateCommand() *cobra.Command {
	var projectID, environmentID, name, displayName, kind, idempotencyKey string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "create", Short: "Create an environment", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(projectID, "project ID", "--project-id"); err != nil {
			return err
		}
		if err := requireFlag(name, "environment name", "--name"); err != nil {
			return err
		}
		if strings.TrimSpace(environmentID) == "" {
			environmentID = domain.MustNewID(domain.KindEnvironment).String()
		}
		if strings.TrimSpace(displayName) == "" {
			displayName = name
		}
		if strings.TrimSpace(kind) == "" {
			kind = "standard"
		}
		body := map[string]string{"environment_id": environmentID, "slug": name, "display_name": displayName, "kind": kind}
		if strings.TrimSpace(idempotencyKey) != "" {
			body["idempotency_key"] = idempotencyKey
		}
		data, err := yallaBackendRequest(c, http.MethodPost, yallaPath("v1/projects", pathID(projectID), "environments"), body, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "environment created")
	}}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Yalla project ID")
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID; generated when omitted")
	cmd.Flags().StringVar(&name, "name", "", "environment slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "environment display name")
	cmd.Flags().StringVar(&kind, "kind", "standard", "environment kind: standard or preview")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newEnvironmentUpdateCommand() *cobra.Command {
	var environmentID, name, displayName string
	var ifMatch int64
	var timeout time.Duration
	cmd := &cobra.Command{Use: "update", Short: "Update an environment", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
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
			return yerr.New(yerr.CodeInvalidInput, "at least one environment field is required").WithHint("pass --name or --display-name")
		}
		data, err := yallaBackendRequest(c, http.MethodPatch, yallaPath("v1/environments", pathID(environmentID)), body, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "environment updated")
	}}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().StringVar(&name, "name", "", "environment slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "environment display name")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newEnvironmentDeleteCommand() *cobra.Command {
	var environmentID string
	var ifMatch int64
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "delete", Short: "Delete an environment", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodDelete, yallaPath("v1/environments", pathID(environmentID)), nil, ifMatchHeader(ifMatch), timeout)
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
		return renderBackendData(c, data, "environment deletion accepted")
	}}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func newEnvironmentCloneCommand() *cobra.Command {
	var environmentID, newEnvironmentID, name, displayName, kind, idempotencyKey string
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "clone", Short: "Clone an environment", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
			return err
		}
		if err := requireFlag(name, "environment name", "--name"); err != nil {
			return err
		}
		if strings.TrimSpace(newEnvironmentID) == "" {
			newEnvironmentID = domain.MustNewID(domain.KindEnvironment).String()
		}
		if strings.TrimSpace(displayName) == "" {
			displayName = name
		}
		if strings.TrimSpace(kind) == "" {
			kind = "preview"
		}
		body := map[string]string{"environment_id": newEnvironmentID, "slug": name, "display_name": displayName, "kind": kind}
		if strings.TrimSpace(idempotencyKey) != "" {
			body["idempotency_key"] = idempotencyKey
		}
		data, err := yallaBackendRequest(c, http.MethodPost, yallaPath("v1/environments", pathID(environmentID), "clone"), body, nil, timeout)
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
		return renderBackendData(c, data, "environment clone accepted")
	}}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "source Yalla environment ID")
	cmd.Flags().StringVar(&newEnvironmentID, "new-environment-id", "", "new Yalla environment ID; generated when omitted")
	cmd.Flags().StringVar(&newEnvironmentID, "clone-environment-id", "", "alias for --new-environment-id")
	cmd.Flags().StringVar(&name, "name", "", "new environment slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "new environment display name")
	cmd.Flags().StringVar(&kind, "kind", "preview", "new environment kind: preview or standard")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}
