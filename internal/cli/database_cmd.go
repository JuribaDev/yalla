package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/output"
)

func newDatabaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "database",
		Short: "Manage Dokploy databases",
		Long:  "Manage Dokploy databases with friendly commands backed by the Dokploy API.",
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newDatabaseCreateCommand())
	cmd.AddCommand(newDatabaseDeployCommand())
	cmd.AddCommand(newDatabaseUpdateCommand())
	cmd.AddCommand(newDatabaseBackupCommand())
	return cmd
}

func newDatabaseCreateCommand() *cobra.Command {
	var opts databaseCreateOptions
	cmd := &cobra.Command{
		Use:   "create <engine>",
		Short: "Create a Dokploy database",
		Long:  "Create a Dokploy-managed database resource and optionally deploy it immediately.",
		Example: `  yalla database create postgres --environment-id env_123 --name app-postgres --database-name app --database-user app --database-password "$DATABASE_PASSWORD"
  yalla database create redis --environment-id env_123 --name app-redis --database-password "$REDIS_PASSWORD" --deploy
  yalla --json database create mongo --environment-id env_123 --name app-mongo --database-user app --database-password "$MONGO_PASSWORD" --replica-sets`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			if err := validateDatabaseCreate(opts); err != nil {
				return err
			}

			streams := IOStreamsFromContext(c.Context())
			r := databaseRendererFromContext(c, streams, opts.DatabasePassword, opts.RootPassword)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.Create(opts)
			if err != nil {
				return redactErrorWithSecret(redactErrorWithSecret(err, opts.DatabasePassword), opts.RootPassword)
			}
			return renderDatabaseCreate(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.EnvironmentID, "environment-id", "", "Dokploy environment ID")
	cmd.Flags().StringVar(&opts.Name, "name", "", "database resource name")
	cmd.Flags().StringVar(&opts.AppName, "app-name", "", "optional Dokploy appName override")
	cmd.Flags().StringVar(&opts.DatabaseName, "database-name", "", "database name inside the server")
	cmd.Flags().StringVar(&opts.DatabaseUser, "database-user", "", "database user")
	cmd.Flags().StringVar(&opts.DatabasePassword, "database-password", "", "database password")
	cmd.Flags().StringVar(&opts.RootPassword, "root-password", "", "MySQL/MariaDB root password")
	cmd.Flags().StringVar(&opts.Description, "description", "", "database description")
	cmd.Flags().StringVar(&opts.ServerID, "server-id", "", "target Dokploy server ID")
	cmd.Flags().StringVar(&opts.Image, "image", "", "Docker image override")
	cmd.Flags().BoolVar(&opts.ReplicaSets, "replica-sets", false, "enable MongoDB replica sets")
	cmd.Flags().BoolVar(&opts.Deploy, "deploy", false, "deploy the database immediately after creating it")
	return cmd
}

func newDatabaseDeployCommand() *cobra.Command {
	var opts databaseDeployOptions
	cmd := &cobra.Command{
		Use:   "deploy <engine>",
		Short: "Deploy a Dokploy database",
		Long:  "Deploy an existing Dokploy-managed database resource.",
		Example: `  yalla database deploy postgres --id postgres_123
  yalla --json database deploy redis --id redis_123`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			if err := validateDatabaseDeploy(opts); err != nil {
				return err
			}

			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.Deploy(opts)
			if err != nil {
				return err
			}
			return renderDatabaseDeploy(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.ID, "id", "", "database ID")
	return cmd
}

func newDatabaseUpdateCommand() *cobra.Command {
	var opts databaseUpdateOptions
	cmd := &cobra.Command{
		Use:   "update <engine>",
		Short: "Update and scale a Dokploy database",
		Long:  "Update CPU, memory, and replica settings for a Dokploy-managed database resource.",
		Example: `  yalla database update postgres --id postgres_123 --memory-reservation 512M --memory-limit 1G --cpu-reservation 0.25 --cpu-limit 1 --replicas 1
  yalla --json database update redis --id redis_123 --memory-limit 512M --cpu-limit 0.5`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			opts.MemoryReservationSet = c.Flags().Changed("memory-reservation")
			opts.MemoryLimitSet = c.Flags().Changed("memory-limit")
			opts.CPUReservationSet = c.Flags().Changed("cpu-reservation")
			opts.CPULimitSet = c.Flags().Changed("cpu-limit")
			opts.ReplicasSet = c.Flags().Changed("replicas")
			if err := validateDatabaseUpdate(opts); err != nil {
				return err
			}

			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.Update(opts)
			if err != nil {
				return err
			}
			return renderDatabaseUpdate(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.ID, "id", "", "database ID")
	cmd.Flags().StringVar(&opts.MemoryReservation, "memory-reservation", "", "reserved memory, e.g. 512M")
	cmd.Flags().StringVar(&opts.MemoryLimit, "memory-limit", "", "maximum memory, e.g. 1G")
	cmd.Flags().StringVar(&opts.CPUReservation, "cpu-reservation", "", "reserved CPU units, e.g. 0.25")
	cmd.Flags().StringVar(&opts.CPULimit, "cpu-limit", "", "maximum CPU units, e.g. 1")
	cmd.Flags().IntVar(&opts.Replicas, "replicas", 0, "replica count")
	return cmd
}

func newDatabaseBackupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Manage Dokploy database backups",
		Long:  "Create, run, inspect, update, and remove Dokploy database backups with friendly commands.",
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newDatabaseBackupCreateCommand())
	cmd.AddCommand(newDatabaseBackupRunCommand())
	cmd.AddCommand(newDatabaseBackupUpdateCommand())
	cmd.AddCommand(newDatabaseBackupGetCommand())
	cmd.AddCommand(newDatabaseBackupDeleteCommand())
	cmd.AddCommand(newDatabaseBackupListFilesCommand())
	return cmd
}

func newDatabaseBackupCreateCommand() *cobra.Command {
	var opts databaseBackupCreateOptions
	cmd := &cobra.Command{
		Use:   "create <engine>",
		Short: "Create a scheduled database backup",
		Long:  "Create a scheduled backup for a Dokploy-managed Postgres, MySQL, MariaDB, or MongoDB database.",
		Example: `  yalla database backup create postgres --id postgres_123 --destination-id dst_123 --database app --prefix backups/app/ --schedule "0 2 * * *" --keep-latest 7
  yalla --json database backup create mongo --id mongo_123 --destination-id dst_123 --database app --prefix backups/mongo/ --schedule "0 3 * * *" --disabled`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			opts.KeepLatestSet = c.Flags().Changed("keep-latest")
			if err := validateDatabaseBackupCreate(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.CreateBackup(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupCreate(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.DatabaseID, "id", "", "database ID")
	cmd.Flags().StringVar(&opts.DestinationID, "destination-id", "", "backup destination ID")
	cmd.Flags().StringVar(&opts.Database, "database", "", "database name to back up")
	cmd.Flags().StringVar(&opts.Prefix, "prefix", "", "backup file prefix/path")
	cmd.Flags().StringVar(&opts.Schedule, "schedule", "", "cron schedule, e.g. \"0 2 * * *\"")
	cmd.Flags().IntVar(&opts.KeepLatest, "keep-latest", 0, "number of latest backups to retain")
	cmd.Flags().BoolVar(&opts.Disabled, "disabled", false, "create the backup schedule disabled")
	return cmd
}

func newDatabaseBackupRunCommand() *cobra.Command {
	var opts databaseBackupActionOptions
	cmd := &cobra.Command{
		Use:   "run <engine>",
		Short: "Run a database backup now",
		Long:  "Trigger a manual run for an existing scheduled database backup.",
		Example: `  yalla database backup run postgres --backup-id backup_123
  yalla --json database backup run mysql --backup-id backup_123`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			if err := validateDatabaseBackupAction(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.RunBackup(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupAction(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.BackupID, "backup-id", "", "backup schedule ID")
	return cmd
}

func newDatabaseBackupUpdateCommand() *cobra.Command {
	var opts databaseBackupUpdateOptions
	cmd := &cobra.Command{
		Use:   "update <engine>",
		Short: "Update a scheduled database backup",
		Long:  "Patch a scheduled database backup by fetching the current configuration and overlaying changed flags.",
		Example: `  yalla database backup update postgres --backup-id backup_123 --schedule "0 4 * * *" --keep-latest 14
  yalla --json database backup update mongo --backup-id backup_123 --prefix backups/mongo/ --disabled`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			engine, err := parseDatabaseEngine(args[0])
			if err != nil {
				return err
			}
			opts.Engine = engine
			opts.ScheduleSet = c.Flags().Changed("schedule")
			opts.PrefixSet = c.Flags().Changed("prefix")
			opts.DestinationIDSet = c.Flags().Changed("destination-id")
			opts.DatabaseSet = c.Flags().Changed("database")
			opts.KeepLatestSet = c.Flags().Changed("keep-latest")
			opts.ServiceNameSet = c.Flags().Changed("service-name")
			opts.EnabledSet = c.Flags().Changed("enabled")
			opts.DisabledSet = c.Flags().Changed("disabled")
			if err := validateDatabaseBackupUpdate(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.UpdateBackup(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupUpdate(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.BackupID, "backup-id", "", "backup schedule ID")
	cmd.Flags().StringVar(&opts.Schedule, "schedule", "", "cron schedule, e.g. \"0 2 * * *\"")
	cmd.Flags().StringVar(&opts.Prefix, "prefix", "", "backup file prefix/path")
	cmd.Flags().StringVar(&opts.DestinationID, "destination-id", "", "backup destination ID")
	cmd.Flags().StringVar(&opts.Database, "database", "", "database name to back up")
	cmd.Flags().IntVar(&opts.KeepLatest, "keep-latest", 0, "number of latest backups to retain")
	cmd.Flags().StringVar(&opts.ServiceName, "service-name", "", "compose service name; usually empty for database backups")
	cmd.Flags().BoolVar(&opts.Enabled, "enabled", false, "enable the backup schedule")
	cmd.Flags().BoolVar(&opts.Disabled, "disabled", false, "disable the backup schedule")
	return cmd
}

func newDatabaseBackupGetCommand() *cobra.Command {
	var opts databaseBackupGetOptions
	cmd := &cobra.Command{
		Use:           "get",
		Short:         "Get a database backup schedule",
		Example:       `  yalla database backup get --backup-id backup_123`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateDatabaseBackupGet(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.GetBackup(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupGet(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.BackupID, "backup-id", "", "backup schedule ID")
	return cmd
}

func newDatabaseBackupDeleteCommand() *cobra.Command {
	var opts databaseBackupActionOptions
	cmd := &cobra.Command{
		Use:           "delete",
		Short:         "Delete a database backup schedule",
		Example:       `  yalla database backup delete --backup-id backup_123`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateDatabaseBackupAction(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.DeleteBackup(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupAction(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.BackupID, "backup-id", "", "backup schedule ID")
	return cmd
}

func newDatabaseBackupListFilesCommand() *cobra.Command {
	var opts databaseBackupListFilesOptions
	cmd := &cobra.Command{
		Use:   "list-files",
		Short: "List backup files for a destination and prefix",
		Example: `  yalla database backup list-files --destination-id dst_123 --prefix backups/app/
  yalla --json database backup list-files --destination-id dst_123 --prefix backups/app/ --server-id server_123`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateDatabaseBackupListFiles(opts); err != nil {
				return err
			}
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			svc, err := newDatabaseService(c.Context(), config.FromContext(c.Context()), BuildInfoFromContext(c.Context()))
			if err != nil {
				return err
			}
			doc, err := svc.ListBackupFiles(opts)
			if err != nil {
				return err
			}
			return renderDatabaseBackupListFiles(r, doc)
		},
	}
	cmd.Flags().StringVar(&opts.DestinationID, "destination-id", "", "backup destination ID")
	cmd.Flags().StringVar(&opts.Prefix, "prefix", "", "backup file prefix/path to search")
	cmd.Flags().StringVar(&opts.ServerID, "server-id", "", "target Dokploy server ID")
	return cmd
}

func databaseRendererFromContext(c *cobra.Command, streams IOStreams, secrets ...string) *output.Renderer {
	flags := GlobalFlagsFromContext(c.Context())
	allSecrets := append([]string{flags.Token}, secrets...)
	return output.New(streams.Out, streams.ErrOut, flags.JSON, output.NewRedactor(allSecrets...))
}

func renderDatabaseBackupCreate(r *output.Renderer, doc databaseBackupCreateDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	lines := []string{fmt.Sprintf("Created %s backup schedule", doc.Engine)}
	if doc.BackupID != "" {
		lines = append(lines, "Backup ID: "+doc.BackupID)
	} else {
		lines = append(lines, "Backup ID: not returned by API")
	}
	lines = append(lines,
		"Database ID: "+doc.DatabaseID,
		"Destination ID: "+doc.DestinationID,
		"Database: "+doc.Database,
		"Prefix: "+doc.Prefix,
		"Schedule: "+doc.Schedule,
		fmt.Sprintf("Enabled: %t", doc.Enabled),
	)
	if doc.KeepLatestSet {
		lines = append(lines, fmt.Sprintf("Keep latest: %d", doc.KeepLatest))
	}
	r.Human(strings.Join(lines, "\n"))
	return nil
}

func renderDatabaseBackupAction(r *output.Renderer, doc databaseBackupActionDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	switch doc.Operation {
	case "run":
		r.Human(fmt.Sprintf("Started %s backup %s", doc.Engine, doc.BackupID))
	case "delete":
		r.Human("Deleted backup schedule " + doc.BackupID)
	default:
		r.Human(fmt.Sprintf("%s backup %s", doc.Operation, doc.BackupID))
	}
	return nil
}

func renderDatabaseBackupUpdate(r *output.Renderer, doc databaseBackupUpdateDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	lines := []string{fmt.Sprintf("Updated %s backup %s", doc.Engine, doc.BackupID)}
	if doc.Schedule != "" {
		lines = append(lines, "Schedule: "+doc.Schedule)
	}
	if doc.Prefix != "" {
		lines = append(lines, "Prefix: "+doc.Prefix)
	}
	lines = append(lines, fmt.Sprintf("Enabled: %t", doc.Enabled))
	if doc.KeepLatestSet {
		lines = append(lines, fmt.Sprintf("Keep latest: %d", doc.KeepLatest))
	}
	r.Human(strings.Join(lines, "\n"))
	return nil
}

func renderDatabaseBackupGet(r *output.Renderer, doc databaseBackupGetDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	r.Human(fmt.Sprintf("Backup %s\nDatabase type: %s\nPrefix: %s", doc.BackupID, valueOrDash(doc.DatabaseType), valueOrDash(doc.Prefix)))
	return nil
}

func renderDatabaseBackupListFiles(r *output.Renderer, doc databaseBackupListFilesDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	lines := []string{fmt.Sprintf("Backup files for %s", doc.Prefix)}
	if len(doc.Files) == 0 {
		lines = append(lines, "No files found")
	} else {
		lines = append(lines, doc.Files...)
	}
	r.Human(strings.Join(lines, "\n"))
	return nil
}

func renderDatabaseCreate(r *output.Renderer, doc databaseCreateDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	lines := []string{fmt.Sprintf("Created %s database %s", doc.Engine, doc.Name)}
	if doc.ID != "" {
		lines = append(lines, "ID: "+doc.ID)
	} else {
		lines = append(lines, "ID: not recovered")
	}
	if doc.AppName != "" {
		lines = append(lines, "App name: "+doc.AppName)
	}
	if doc.Deployed {
		lines = append(lines, "Deploy: queued")
	} else {
		lines = append(lines, "Deploy: skipped")
	}
	if doc.Warning != "" {
		lines = append(lines, "Warning: "+doc.Warning)
	}
	r.Human(strings.Join(lines, "\n"))
	return nil
}

func renderDatabaseDeploy(r *output.Renderer, doc databaseDeployDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	r.Human(fmt.Sprintf("Deployed %s database %s", doc.Engine, doc.ID))
	return nil
}

func renderDatabaseUpdate(r *output.Renderer, doc databaseUpdateDoc) error {
	if r.JSON() {
		return r.Data(doc)
	}
	lines := []string{fmt.Sprintf("Updated %s database %s", doc.Engine, doc.ID)}
	if doc.MemoryReservation != "" || doc.MemoryLimit != "" {
		lines = append(lines, fmt.Sprintf("Memory: reservation=%s limit=%s", valueOrDash(doc.MemoryReservation), valueOrDash(doc.MemoryLimit)))
	}
	if doc.CPUReservation != "" || doc.CPULimit != "" {
		lines = append(lines, fmt.Sprintf("CPU: reservation=%s limit=%s", valueOrDash(doc.CPUReservation), valueOrDash(doc.CPULimit)))
	}
	if doc.ReplicasSet {
		lines = append(lines, fmt.Sprintf("Replicas: %d", doc.Replicas))
	}
	r.Human(strings.Join(lines, "\n"))
	return nil
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
