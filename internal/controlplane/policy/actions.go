package policy

import "sort"

// Action constants. Every backend operation a principal can attempt is named
// here as a stable, dotted permission string. These constants are the public
// authorization contract: endpoint handlers, OpenAPI metadata, audit records,
// and scoped grants all reference the constant, never a bare string literal,
// so the catalog can be enumerated and a typo becomes a compile error rather
// than a silently uncatalogued action.
//
// The dotted string value of each constant is itself part of the contract and
// must never change. Adding a backend operation means adding its constant
// here, listing it in allActions, and mapping it to a capability in
// defaultActionCatalog — the well-formedness tests fail if those three drift.
const (
	// Identity actions: any authenticated principal acting on itself.
	ActionAuthMe             Action = "auth.me"
	ActionAuthOrgs           Action = "auth.orgs"
	ActionOrganizationCreate Action = "organization.create"

	// Organization lifecycle and administration.
	ActionOrganizationRead   Action = "organization.read"
	ActionOrganizationUpdate Action = "organization.update"
	ActionOrganizationDelete Action = "organization.delete"
	ActionMembersRead        Action = "members.read"
	ActionMembersManage      Action = "members.manage"
	ActionKeysRead           Action = "keys.read"
	ActionKeysManage         Action = "keys.manage"
	ActionAuditRead          Action = "audit.read"
	ActionLimitsRead         Action = "limits.read"
	ActionLimitsWrite        Action = "limits.write"

	// Project actions.
	ActionProjectRead        Action = "project.read"
	ActionProjectCreate      Action = "project.create"
	ActionProjectUpdate      Action = "project.update"
	ActionProjectDelete      Action = "project.delete"
	ActionProjectRestore     Action = "project.restore"
	ActionProjectGrantsRead  Action = "project.grants.read"
	ActionProjectGrantsWrite Action = "project.grants.write"

	// Environment actions.
	ActionEnvironmentRead        Action = "environment.read"
	ActionEnvironmentCreate      Action = "environment.create"
	ActionEnvironmentUpdate      Action = "environment.update"
	ActionEnvironmentDelete      Action = "environment.delete"
	ActionEnvironmentGrantsRead  Action = "environment.grants.read"
	ActionEnvironmentGrantsWrite Action = "environment.grants.write"

	// Service actions.
	ActionServiceRead    Action = "service.read"
	ActionServiceCreate  Action = "service.create"
	ActionServiceUpdate  Action = "service.update"
	ActionServiceDelete  Action = "service.delete"
	ActionServiceRestore Action = "service.restore"
	ActionServiceRestart Action = "service.restart"
	ActionServiceStart   Action = "service.start"
	ActionServiceStop    Action = "service.stop"

	// Environment-variable actions.
	ActionEnvRead  Action = "env.read"
	ActionEnvWrite Action = "env.write"

	// Domain actions.
	ActionDomainRead   Action = "domain.read"
	ActionDomainCreate Action = "domain.create"
	ActionDomainUpdate Action = "domain.update"
	ActionDomainDelete Action = "domain.delete"

	// Deployment actions.
	ActionDeploymentRead     Action = "deployment.read"
	ActionDeploymentCreate   Action = "deployment.create"
	ActionDeploymentCancel   Action = "deployment.cancel"
	ActionDeploymentRollback Action = "deployment.rollback"

	// Backup actions.
	ActionBackupRead   Action = "backup.read"
	ActionBackupCreate Action = "backup.create"
	ActionBackupUpdate Action = "backup.update"
	ActionBackupDelete Action = "backup.delete"
	ActionBackupRun    Action = "backup.run"

	// Provisioning-job actions.
	ActionJobRead   Action = "job.read"
	ActionJobCancel Action = "job.cancel"
	ActionJobRetry  Action = "job.retry"

	// Observability actions.
	ActionLogsRead    Action = "logs.read"
	ActionMetricsRead Action = "metrics.read"

	// Preview-environment actions.
	ActionPreviewRead   Action = "preview.read"
	ActionPreviewCreate Action = "preview.create"
	ActionPreviewDelete Action = "preview.delete"

	// Internal break-glass / support actions.
	ActionAdminRead           Action = "admin.read"
	ActionAdminImport         Action = "admin.import"
	ActionAdminReconcile      Action = "admin.reconcile"
	ActionAdminConfigValidate Action = "admin.config.validate"
	ActionAdminPlansManage    Action = "admin.plans.manage"
	ActionAdminBreakGlass     Action = "admin.break_glass"
)

// allActions is the authoritative enumeration of every catalogued action. It
// is the single source of truth for "which actions exist": [Actions] returns a
// sorted copy of it, and the well-formedness tests assert it is exactly the
// key set of [defaultActionCatalog], so an action can never be enumerated
// without a capability mapping (or mapped without being enumerated).
var allActions = []Action{
	ActionAuthMe,
	ActionAuthOrgs,
	ActionOrganizationCreate,
	ActionOrganizationRead,
	ActionOrganizationUpdate,
	ActionOrganizationDelete,
	ActionMembersRead,
	ActionMembersManage,
	ActionKeysRead,
	ActionKeysManage,
	ActionAuditRead,
	ActionLimitsRead,
	ActionLimitsWrite,
	ActionProjectRead,
	ActionProjectCreate,
	ActionProjectUpdate,
	ActionProjectDelete,
	ActionProjectRestore,
	ActionProjectGrantsRead,
	ActionProjectGrantsWrite,
	ActionEnvironmentRead,
	ActionEnvironmentCreate,
	ActionEnvironmentUpdate,
	ActionEnvironmentDelete,
	ActionEnvironmentGrantsRead,
	ActionEnvironmentGrantsWrite,
	ActionServiceRead,
	ActionServiceCreate,
	ActionServiceUpdate,
	ActionServiceDelete,
	ActionServiceRestore,
	ActionServiceRestart,
	ActionServiceStart,
	ActionServiceStop,
	ActionEnvRead,
	ActionEnvWrite,
	ActionDomainRead,
	ActionDomainCreate,
	ActionDomainUpdate,
	ActionDomainDelete,
	ActionDeploymentRead,
	ActionDeploymentCreate,
	ActionDeploymentCancel,
	ActionDeploymentRollback,
	ActionBackupRead,
	ActionBackupCreate,
	ActionBackupUpdate,
	ActionBackupDelete,
	ActionBackupRun,
	ActionJobRead,
	ActionJobCancel,
	ActionJobRetry,
	ActionLogsRead,
	ActionMetricsRead,
	ActionPreviewRead,
	ActionPreviewCreate,
	ActionPreviewDelete,
	ActionAdminRead,
	ActionAdminImport,
	ActionAdminReconcile,
	ActionAdminConfigValidate,
	ActionAdminPlansManage,
	ActionAdminBreakGlass,
}

// Actions returns every catalogued action in a stable, sorted order. It lets
// callers (tests, the authorization middleware, documentation generators)
// enumerate the action contract without reaching into package internals.
func Actions() []Action {
	out := make([]Action, len(allActions))
	copy(out, allActions)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Catalogued reports whether action is a known, catalogued action — that is,
// whether it has a required-capability mapping. The authorization middleware
// uses it to reject an endpoint wired to an unknown action before any
// authorization decision is attempted, and tests use it to prove every
// authenticated route references a real action.
func Catalogued(action Action) bool {
	_, ok := defaultActionCatalog[action]
	return ok
}
