package jobs

// TypeEnsureDokployOrganization mirrors a Yalla organization into Dokploy.
const TypeEnsureDokployOrganization = "ensure_dokploy_organization"

// TypeEnsureProject mirrors a Yalla project into Dokploy.
const TypeEnsureProject = "ensure_project"

// TypeEnsureEnvironment mirrors a Yalla environment into Dokploy.
const TypeEnsureEnvironment = "ensure_environment"

// TypeEnsureApplicationService mirrors an application service into Dokploy.
const TypeEnsureApplicationService = "ensure_application_service"

// TypeEnsureComposeService mirrors a compose service into Dokploy.
const TypeEnsureComposeService = "ensure_compose_service"

// TypeEnsureDatabaseService mirrors a database service into Dokploy.
const TypeEnsureDatabaseService = "ensure_database_service"

// TypeDeployService deploys a service.
const TypeDeployService = "service.deploy"

// TypeDeployServiceAlias is accepted for manually seeded deploy jobs.
const TypeDeployServiceAlias = "deploy_service"

// TypeRestartService restarts a service.
const TypeRestartService = "service.restart"

// TypeRestartServiceAlias is accepted for manually seeded restart jobs.
const TypeRestartServiceAlias = "restart_service"

// TypeRollbackService rolls a service back to a prior deployment.
const TypeRollbackService = "service.rollback"

// TypeRollbackServiceAlias is accepted for manually seeded rollback jobs.
const TypeRollbackServiceAlias = "rollback_service"

// TypeStopService stops a service.
const TypeStopService = "service.stop"

// TypeStopServiceAlias is accepted for manually seeded stop jobs.
const TypeStopServiceAlias = "stop_service"

// TypeStartService starts a service.
const TypeStartService = "service.start"

// TypeStartServiceAlias is accepted for manually seeded start jobs.
const TypeStartServiceAlias = "start_service"

// TypeDeleteService deletes a service.
const TypeDeleteService = "service.delete"

// TypeDeleteServiceAlias is accepted for manually seeded service delete jobs.
const TypeDeleteServiceAlias = "delete_service"

// TypeDeleteEnvironment deletes an environment.
const TypeDeleteEnvironment = "environment.delete"

// TypeDeleteEnvironmentAlias is accepted for manually seeded environment delete jobs.
const TypeDeleteEnvironmentAlias = "delete_environment"

// TypeDeleteProject deletes a project.
const TypeDeleteProject = "project.delete"

// TypeDeleteProjectAlias is accepted for manually seeded project delete jobs.
const TypeDeleteProjectAlias = "delete_project"

// TypeSyncDomains reconciles service domain bindings.
const TypeSyncDomains = "sync_domains"

// TypeSyncVariables reconciles effective service variables.
const TypeSyncVariables = "sync_variables"

// TypeReconcileService converges a full service surface.
const TypeReconcileService = "reconcile_service"

// TypeRunBackup triggers a service backup run.
const TypeRunBackup = "run_backup"

// TypeRestoreBackup restores a service from a backup.
const TypeRestoreBackup = "restore_backup"

// TypeCreatePreviewEnvironment creates a preview environment clone.
const TypeCreatePreviewEnvironment = "create_preview_environment"

// TypeDeletePreviewEnvironment deletes a preview environment clone.
const TypeDeletePreviewEnvironment = "delete_preview_environment"

// TypeImportDokployResource imports an assigned Dokploy organization snapshot.
const TypeImportDokployResource = "import_dokploy_resource"
