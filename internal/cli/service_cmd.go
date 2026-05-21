package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newServiceCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Manage services through the Yalla backend", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(
		newServiceListCommand(),
		newServiceGetCommand(),
		newServiceCreateCommand(),
		newServiceUpdateCommand(),
		newServiceDeleteCommand(),
		newServiceRestoreCommand(),
		newServiceDeployCommand(),
		newServiceBuildCommand(),
	)
	return cmd
}

func newServiceListCommand() *cobra.Command {
	var environmentID, kind string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "list", Short: "List environment services", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/environments", pathID(environmentID), "services"), nil, nil, timeout)
		if err != nil {
			return err
		}
		if strings.TrimSpace(kind) != "" {
			data, err = filterServicesByKind(data, kind)
			if err != nil {
				return err
			}
		}
		return renderBackendData(c, data, "services")
	}}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().StringVar(&kind, "kind", "", "filter by service kind: application, compose, or database")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newServiceGetCommand() *cobra.Command {
	var serviceID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "get", Short: "Get a service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/services", pathID(serviceID)), nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "service")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newServiceCreateCommand() *cobra.Command {
	var serviceID, environmentID, name, displayName, kind, idempotencyKey string
	var deploy, wait bool
	var timeout, pollInterval time.Duration
	var buildFlags serviceBuildFlags
	cmd := &cobra.Command{Use: "create", Short: "Create a service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		body, resolvedEnvironmentID, resolvedName, err := serviceCreateBodyFromFlags(serviceID, environmentID, name, displayName, kind, buildFlags)
		if err != nil {
			return err
		}
		if id, ok := body["service_id"].(string); ok {
			serviceID = id
		}
		environmentID = resolvedEnvironmentID
		name = resolvedName
		if err := requireFlag(environmentID, "environment ID", "--environment-id"); err != nil {
			return err
		}
		if err := requireFlag(name, "service name", "--name"); err != nil {
			return err
		}
		if strings.TrimSpace(idempotencyKey) != "" {
			body["idempotency_key"] = idempotencyKey
		}
		data, err := yallaBackendRequest(c, http.MethodPost, yallaPath("v1/environments", pathID(environmentID), "services"), body, nil, timeout)
		if err != nil {
			return err
		}
		if deploy {
			deployData, err := deployService(c, serviceID, sourceForBuildType(buildFlags.BuildType), sourceRefFromBuildFlags(buildFlags), generatedIdempotencyKey(), timeout)
			if err != nil {
				return err
			}
			data = mergeRawObjects(data, "deployment", deployData)
			if wait {
				if waited, waitErr := waitOnBackendJobFromData(c, deployData, timeout, pollInterval); waitErr != nil {
					return waitErr
				} else if waited != nil {
					data = mergeRawObjects(data, "job", waited)
				}
			}
		}
		return renderBackendData(c, data, "service created")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID; generated when omitted")
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().StringVar(&name, "name", "", "service slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "service display name")
	cmd.Flags().StringVar(&kind, "kind", "application", "service kind: application, compose, or database")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	cmd.Flags().BoolVar(&deploy, "deploy", false, "enqueue a deployment after creation")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for the deployment job to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "request or wait timeout")
	cmd.Flags().DurationVar(&pollInterval, "poll-interval", time.Second, "wait polling interval")
	addServiceBuildFlags(cmd, &buildFlags)
	return cmd
}

func newServiceUpdateCommand() *cobra.Command {
	var serviceID, name, displayName string
	var ifMatch int64
	var timeout time.Duration
	cmd := &cobra.Command{Use: "update", Short: "Update a service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
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
			return yerr.New(yerr.CodeInvalidInput, "at least one service field is required").WithHint("pass --name or --display-name")
		}
		data, err := yallaBackendRequest(c, http.MethodPatch, yallaPath("v1/services", pathID(serviceID)), body, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "service updated")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().StringVar(&name, "name", "", "service slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "service display name")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newServiceDeleteCommand() *cobra.Command {
	var serviceID string
	var ifMatch int64
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "delete", Short: "Delete a service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodDelete, yallaPath("v1/services", pathID(serviceID)), nil, ifMatchHeader(ifMatch), timeout)
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
		return renderBackendData(c, data, "service deletion accepted")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func newServiceRestoreCommand() *cobra.Command {
	var serviceID string
	var ifMatch int64
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "restore", Short: "Restore a soft-deleted service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "restore"), nil, ifMatchHeader(ifMatch), timeout)
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
		return renderBackendData(c, data, "service restored")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected resource version")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func newServiceDeployCommand() *cobra.Command {
	var serviceID, source, sourceRef, idempotencyKey string
	var wait bool
	var timeout, pollInterval time.Duration
	cmd := &cobra.Command{Use: "deploy", Short: "Deploy a service", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		data, err := deployService(c, serviceID, source, sourceRef, idempotencyKey, timeout)
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
		return renderBackendData(c, data, "deployment accepted")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().StringVar(&source, "source", "manual", "deployment source")
	cmd.Flags().StringVar(&sourceRef, "source-ref", "", "deployment source reference")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	addWaitFlags(cmd, &wait, &timeout, &pollInterval)
	return cmd
}

func newServiceBuildCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "build", Short: "Manage service build configuration", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newServiceBuildGetCommand(), newServiceBuildSetCommand())
	return cmd
}

func newServiceBuildGetCommand() *cobra.Command {
	var serviceID string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "get", Short: "Get service build configuration", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		data, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/services", pathID(serviceID), "build-config"), nil, nil, timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "service build config")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newServiceBuildSetCommand() *cobra.Command {
	var serviceID string
	var ifMatch int64
	var timeout time.Duration
	var buildFlags serviceBuildFlags
	cmd := &cobra.Command{Use: "set", Short: "Set service build configuration", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if err := requireFlag(serviceID, "service ID", "--service-id"); err != nil {
			return err
		}
		payload, err := buildConfigPayload(buildFlags)
		if err != nil {
			return err
		}
		if payload == nil {
			return yerr.New(yerr.CodeInvalidInput, "build type is required").WithHint("pass --build-type")
		}
		data, err := yallaBackendRequest(c, http.MethodPut, yallaPath("v1/services", pathID(serviceID), "build-config"), payload, ifMatchHeader(ifMatch), timeout)
		if err != nil {
			return err
		}
		return renderBackendData(c, data, "service build config updated")
	}}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID")
	cmd.Flags().Int64Var(&ifMatch, "if-match", 0, "expected build config version")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	addServiceBuildFlags(cmd, &buildFlags)
	return cmd
}

func deployService(c *cobra.Command, serviceID, source, sourceRef, idempotencyKey string, timeout time.Duration) (json.RawMessage, error) {
	if strings.TrimSpace(source) == "" {
		source = "manual"
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		idempotencyKey = generatedIdempotencyKey()
	}
	return yallaBackendRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "deployments"), map[string]string{
		"source":          source,
		"source_ref":      sourceRef,
		"idempotency_key": idempotencyKey,
	}, nil, timeout)
}

func filterServicesByKind(data json.RawMessage, kind string) (json.RawMessage, error) {
	var payload struct {
		Services []map[string]any `json:"services"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, yerr.Newf(yerr.CodeServer, "backend returned malformed services payload: %v", err)
	}
	filtered := make([]map[string]any, 0, len(payload.Services))
	for _, svc := range payload.Services {
		if got, _ := svc["kind"].(string); got == kind {
			filtered = append(filtered, svc)
		}
	}
	out, err := json.Marshal(map[string]any{"services": filtered})
	if err != nil {
		return nil, yerr.Newf(yerr.CodeServer, "could not encode services: %v", err)
	}
	return out, nil
}
