package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newDatabaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "database",
		Short:         "Manage database services through the Yalla backend",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		newDatabaseListCommand(),
		newDatabaseCreateCommand(),
		newDatabaseDeployCommand(),
		newDatabaseDeleteCommand(),
		newDatabaseBackupCommand(),
	)
	return cmd
}

func newDatabaseListCommand() *cobra.Command {
	var environmentID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List database services in an environment",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(environmentID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "environment ID is required").WithHint("pass --environment-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodGet, yallaPath("v1/environments", pathID(environmentID), "services"), nil, timeout)
			if err != nil {
				return err
			}
			filtered, err := filterDatabaseServices(data)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, filtered, "database services")
		},
	}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseCreateCommand() *cobra.Command {
	var serviceID, environmentID, name, displayName, engine string
	var deploy bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "create",
		Short:         "Create a database service",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateBackendDatabaseEngine(engine); err != nil {
				return err
			}
			if strings.TrimSpace(environmentID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "environment ID is required").WithHint("pass --environment-id")
			}
			if strings.TrimSpace(name) == "" {
				return yerr.New(yerr.CodeInvalidInput, "database name is required").WithHint("pass --name")
			}
			if strings.TrimSpace(serviceID) == "" {
				serviceID = domain.MustNewID(domain.KindService).String()
			}
			if strings.TrimSpace(displayName) == "" {
				displayName = name
			}
			body := map[string]string{
				"service_id":   serviceID,
				"slug":         name,
				"display_name": displayName,
				"kind":         "database",
			}
			data, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/environments", pathID(environmentID), "services"), body, timeout)
			if err != nil {
				return err
			}
			if deploy {
				deployData, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "deployments"), map[string]string{
					"source":          "manual",
					"idempotency_key": generatedIdempotencyKey(),
				}, timeout)
				if err != nil {
					return err
				}
				data = mergeRawObjects(data, "deployment", deployData)
			}
			return renderDatabaseData(c, data, "database service created")
		},
	}
	cmd.Flags().StringVar(&environmentID, "environment-id", "", "Yalla environment ID")
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla service ID; generated when omitted")
	cmd.Flags().StringVar(&name, "name", "", "database service slug")
	cmd.Flags().StringVar(&displayName, "display-name", "", "database service display name")
	cmd.Flags().StringVar(&engine, "engine", "postgres", "database engine supported by the backend")
	cmd.Flags().BoolVar(&deploy, "deploy", false, "enqueue a deployment after creation")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseDeployCommand() *cobra.Command {
	var serviceID, source, sourceRef, idempotencyKey string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "deploy",
		Short:         "Deploy a database service",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(source) == "" {
				source = "manual"
			}
			if strings.TrimSpace(idempotencyKey) == "" {
				idempotencyKey = generatedIdempotencyKey()
			}
			data, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "deployments"), map[string]string{
				"source":          source,
				"source_ref":      sourceRef,
				"idempotency_key": idempotencyKey,
			}, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database deployment accepted")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&source, "source", "manual", "deployment source")
	cmd.Flags().StringVar(&sourceRef, "source-ref", "", "deployment source reference")
	cmd.Flags().StringVar(&idempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseDeleteCommand() *cobra.Command {
	var serviceID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "delete",
		Short:         "Delete a database service",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodDelete, yallaPath("v1/services", pathID(serviceID)), nil, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database deletion accepted")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "backup",
		Short:         "Manage database backup policies",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		newDatabaseBackupListCommand(),
		newDatabaseBackupCreateCommand(),
		newDatabaseBackupUpdateCommand(),
		newDatabaseBackupRunCommand(),
		newDatabaseBackupRestoreCommand(),
		newDatabaseBackupDeleteCommand(),
	)
	return cmd
}

func newDatabaseBackupListCommand() *cobra.Command {
	var serviceID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List database backup policies",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodGet, yallaPath("v1/services", pathID(serviceID), "backups"), nil, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backups")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupCreateCommand() *cobra.Command {
	var serviceID, backupID, displayName, schedule string
	var retentionCount int
	var disabled bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "create",
		Short:         "Create a database backup policy",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(displayName) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup display name is required").WithHint("pass --display-name")
			}
			if strings.TrimSpace(schedule) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup schedule is required").WithHint("pass --schedule")
			}
			if strings.TrimSpace(backupID) == "" {
				backupID = domain.MustNewID(domain.KindServiceBackup).String()
			}
			body := map[string]any{
				"id":           backupID,
				"display_name": displayName,
				"schedule":     schedule,
				"enabled":      !disabled,
			}
			if retentionCount > 0 {
				body["retention_count"] = retentionCount
			}
			data, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "backups"), body, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backup created")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Yalla backup policy ID; generated when omitted")
	cmd.Flags().StringVar(&displayName, "display-name", "", "backup display name")
	cmd.Flags().StringVar(&schedule, "schedule", "", "cron-style backup schedule")
	cmd.Flags().IntVar(&retentionCount, "retention-count", 0, "number of successful backups to retain")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the backup policy disabled")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupUpdateCommand() *cobra.Command {
	var serviceID, backupID, displayName, schedule string
	var retentionCount int
	var enabled, disabled bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "update",
		Short:         "Update a database backup policy",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(backupID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
			}
			if enabled && disabled {
				return yerr.New(yerr.CodeInvalidInput, "--enabled and --disabled cannot be used together")
			}
			body := map[string]any{}
			if c.Flags().Changed("display-name") {
				body["display_name"] = displayName
			}
			if c.Flags().Changed("schedule") {
				body["schedule"] = schedule
			}
			if c.Flags().Changed("retention-count") {
				body["retention_count"] = retentionCount
			}
			if enabled {
				body["enabled"] = true
			}
			if disabled {
				body["enabled"] = false
			}
			if len(body) == 0 {
				return yerr.New(yerr.CodeInvalidInput, "at least one backup update flag is required").
					WithHint("pass --display-name, --schedule, --retention-count, --enabled, or --disabled")
			}
			data, err := yallaDatabaseRequest(c, http.MethodPatch, yallaPath("v1/services", pathID(serviceID), "backups", pathID(backupID)), body, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backup updated")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Yalla backup policy ID")
	cmd.Flags().StringVar(&displayName, "display-name", "", "backup display name")
	cmd.Flags().StringVar(&schedule, "schedule", "", "cron-style backup schedule")
	cmd.Flags().IntVar(&retentionCount, "retention-count", 0, "number of successful backups to retain")
	cmd.Flags().BoolVar(&enabled, "enabled", false, "enable the backup policy")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "disable the backup policy")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupRunCommand() *cobra.Command {
	var serviceID, backupID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "run",
		Short:         "Run a database backup policy",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(backupID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "backups", pathID(backupID), "run"), nil, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backup run accepted")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Yalla backup policy ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupRestoreCommand() *cobra.Command {
	var serviceID, backupID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "restore",
		Short:         "Restore a database backup policy",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(backupID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodPost, yallaPath("v1/services", pathID(serviceID), "backups", pathID(backupID), "restore"), nil, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backup restore accepted")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Yalla backup policy ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newDatabaseBackupDeleteCommand() *cobra.Command {
	var serviceID, backupID string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:           "delete",
		Short:         "Delete a database backup policy",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if strings.TrimSpace(serviceID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
			}
			if strings.TrimSpace(backupID) == "" {
				return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
			}
			data, err := yallaDatabaseRequest(c, http.MethodDelete, yallaPath("v1/services", pathID(serviceID), "backups", pathID(backupID)), nil, timeout)
			if err != nil {
				return err
			}
			return renderDatabaseData(c, data, "database backup deleted")
		},
	}
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Yalla database service ID")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Yalla backup policy ID")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func validateBackendDatabaseEngine(engine string) error {
	if strings.TrimSpace(engine) == "" || strings.EqualFold(engine, "postgres") {
		return nil
	}
	return yerr.Newf(yerr.CodeUnsupported, "database engine %q is not exposed by the Yalla backend service route", engine).
		WithHint("use --engine postgres until backend database engine selection is added")
}

func yallaDatabaseRequest(c *cobra.Command, method, path string, body any, timeout time.Duration) (json.RawMessage, error) {
	cli, err := newYallaAPIClient(configFromCommand(c), BuildInfoFromContext(c.Context()), timeout)
	if err != nil {
		return nil, err
	}
	data, _, err := yallaJSONRequest(c.Context(), cli, method, path, body, method == http.MethodGet)
	return data, err
}

func renderDatabaseData(c *cobra.Command, data json.RawMessage, human string) error {
	r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
	if r.JSON() {
		return r.Data(data)
	}
	r.Human(human)
	return nil
}

func filterDatabaseServices(data json.RawMessage) (json.RawMessage, error) {
	var payload struct {
		Services []map[string]any `json:"services"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, yerr.Newf(yerr.CodeServer, "backend returned malformed services payload: %v", err)
	}
	filtered := make([]map[string]any, 0, len(payload.Services))
	for _, svc := range payload.Services {
		if kind, _ := svc["kind"].(string); kind == "database" {
			filtered = append(filtered, svc)
		}
	}
	out, err := json.Marshal(map[string]any{"services": filtered})
	if err != nil {
		return nil, yerr.Newf(yerr.CodeServer, "could not encode database services: %v", err)
	}
	return out, nil
}

func mergeRawObjects(base json.RawMessage, key string, extra json.RawMessage) json.RawMessage {
	var out map[string]json.RawMessage
	if err := json.Unmarshal(base, &out); err != nil {
		return base
	}
	out[key] = extra
	merged, err := json.Marshal(out)
	if err != nil {
		return base
	}
	return merged
}
