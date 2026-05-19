package policy

import "sort"

// capSet is a set of capabilities. It is the unit a role confers and the
// engine intersects against an action's required capability.
type capSet map[Capability]struct{}

// has reports whether the set contains c.
func (s capSet) has(c Capability) bool {
	_, ok := s[c]
	return ok
}

// newCapSet builds a capSet from a capability list.
func newCapSet(caps ...Capability) capSet {
	s := make(capSet, len(caps))
	for _, c := range caps {
		s[c] = struct{}{}
	}
	return s
}

// builtinRoleCaps is the authoritative role-to-capability matrix for the six
// built-in roles. It is the single source of truth for what each role can do;
// the per-action verdict is the intersection of this matrix with the action
// catalog. Capabilities are not hierarchical — each role's set is listed in
// full so the matrix can be read without tracing inheritance.
var builtinRoleCaps = map[Role]capSet{
	RoleOwner:     newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin, CapOwner),
	RoleAdmin:     newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin),
	RoleDeveloper: newCapSet(CapSelf, CapRead, CapDeploy, CapWrite),
	RoleViewer:    newCapSet(CapSelf, CapRead),
	RoleCI:        newCapSet(CapSelf, CapRead, CapDeploy),
	RoleSupport:   newCapSet(CapSelf, CapRead, CapSupport),
}

// BuiltinRoles returns the built-in role names in a stable, sorted order. It
// lets callers (tests, admin tooling, documentation generators) enumerate the
// role contract without reaching into package internals.
func BuiltinRoles() []Role {
	out := make([]Role, 0, len(builtinRoleCaps))
	for r := range builtinRoleCaps {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// defaultActionCatalog maps every catalogued action to the single capability
// it requires. It is the authoritative action-to-capability contract: every
// action in [allActions] appears here exactly once, and adding an endpoint
// means adding its action constant in actions.go, listing it in allActions,
// and mapping it here. The store layer duplicates a few of these strings
// (project.create, service_account.create) as plain constants on purpose to
// avoid a build dependency; this catalog is where they are owned.
//
// Keys are the [Action] constants from actions.go, never bare string literals,
// so an uncatalogued or mistyped action is a compile error.
var defaultActionCatalog = map[Action]Capability{
	// Identity: any authenticated principal acting on itself.
	ActionAuthMe:             CapSelf,
	ActionAuthOrgs:           CapSelf,
	ActionOrganizationCreate: CapSelf,

	// Reads within an organization.
	ActionOrganizationRead:      CapRead,
	ActionMembersRead:           CapRead,
	ActionProjectRead:           CapRead,
	ActionProjectGrantsRead:     CapRead,
	ActionEnvironmentRead:       CapRead,
	ActionEnvironmentGrantsRead: CapRead,
	ActionServiceRead:           CapRead,
	ActionEnvRead:               CapRead,
	ActionDomainRead:            CapRead,
	ActionDeploymentRead:        CapRead,
	ActionBackupRead:            CapRead,
	ActionJobRead:               CapRead,
	ActionLogsRead:              CapRead,
	ActionMetricsRead:           CapRead,
	ActionLimitsRead:            CapRead,
	ActionPreviewRead:           CapRead,

	// Lifecycle actions against existing resources (no desired-state change).
	ActionDeploymentCreate:   CapDeploy,
	ActionDeploymentCancel:   CapDeploy,
	ActionDeploymentRollback: CapDeploy,
	ActionBackupRun:          CapDeploy,
	ActionJobCancel:          CapDeploy,
	ActionJobRetry:           CapDeploy,
	ActionServiceRestart:     CapDeploy,
	ActionServiceStart:       CapDeploy,
	ActionServiceStop:        CapDeploy,
	ActionPreviewCreate:      CapDeploy,
	ActionPreviewDelete:      CapDeploy,

	// Desired-state writes.
	ActionProjectCreate:     CapWrite,
	ActionProjectUpdate:     CapWrite,
	ActionProjectDelete:     CapWrite,
	ActionProjectRestore:    CapWrite,
	ActionEnvironmentCreate: CapWrite,
	ActionEnvironmentUpdate: CapWrite,
	ActionEnvironmentDelete: CapWrite,
	ActionServiceCreate:     CapWrite,
	ActionServiceUpdate:     CapWrite,
	ActionServiceDelete:     CapWrite,
	ActionServiceRestore:    CapWrite,
	ActionEnvWrite:          CapWrite,
	ActionDomainCreate:      CapWrite,
	ActionDomainUpdate:      CapWrite,
	ActionDomainDelete:      CapWrite,
	ActionBackupCreate:      CapWrite,
	ActionBackupUpdate:      CapWrite,
	ActionBackupDelete:      CapWrite,

	// Organization administration: members, credentials, grants, plan, audit.
	ActionOrganizationUpdate:     CapAdmin,
	ActionMembersManage:          CapAdmin,
	ActionKeysRead:               CapAdmin,
	ActionKeysManage:             CapAdmin,
	ActionProjectGrantsWrite:     CapAdmin,
	ActionEnvironmentGrantsWrite: CapAdmin,
	ActionLimitsWrite:            CapAdmin,
	ActionAuditRead:              CapAdmin,

	// Irreversible owner-only organization actions.
	ActionOrganizationDelete: CapOwner,

	// Internal break-glass / support tooling.
	ActionAdminRead:           CapSupport,
	ActionAdminImport:         CapSupport,
	ActionAdminReconcile:      CapSupport,
	ActionAdminConfigValidate: CapSupport,
	ActionAdminPlansManage:    CapSupport,
	ActionAdminMeteringManage: CapSupport,
	ActionAdminBreakGlass:     CapSupport,
}

// CustomRoleResolver resolves a non-built-in role name to its capability set.
// It is the extension hook for organization-defined custom roles: the engine
// calls it for any Role that is not one of the six built-ins. It must be pure
// and is expected to return ok=false for an unknown role rather than an empty
// set, so the engine can distinguish "custom role with no capabilities" from
// "role does not exist".
type CustomRoleResolver func(Role) (caps []Capability, ok bool)
