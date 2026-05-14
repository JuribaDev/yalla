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

// defaultActionCatalog maps every public action to the single capability it
// requires. It is the authoritative action contract: every requiredAction in
// the API surface appears here exactly once, and adding an endpoint means
// adding its action here. The store layer duplicates a few of these strings
// (project.create, service_account.create) as plain constants on purpose to
// avoid a build dependency; this catalog is where they are owned.
var defaultActionCatalog = map[Action]Capability{
	// Identity: any authenticated principal acting on itself.
	"auth.me":             CapSelf,
	"auth.orgs":           CapSelf,
	"organization.create": CapSelf,

	// Reads within an organization.
	"organization.read":       CapRead,
	"members.read":            CapRead,
	"project.read":            CapRead,
	"project.grants.read":     CapRead,
	"environment.read":        CapRead,
	"environment.grants.read": CapRead,
	"service.read":            CapRead,
	"env.read":                CapRead,
	"domain.read":             CapRead,
	"deployment.read":         CapRead,
	"backup.read":             CapRead,
	"job.read":                CapRead,
	"logs.read":               CapRead,
	"metrics.read":            CapRead,
	"limits.read":             CapRead,
	"preview.read":            CapRead,

	// Lifecycle actions against existing resources (no desired-state change).
	"deployment.create":   CapDeploy,
	"deployment.cancel":   CapDeploy,
	"deployment.rollback": CapDeploy,
	"backup.run":          CapDeploy,
	"job.cancel":          CapDeploy,
	"job.retry":           CapDeploy,
	"service.restart":     CapDeploy,
	"service.start":       CapDeploy,
	"service.stop":        CapDeploy,
	"preview.create":      CapDeploy,
	"preview.delete":      CapDeploy,

	// Desired-state writes.
	"project.create":     CapWrite,
	"project.update":     CapWrite,
	"project.delete":     CapWrite,
	"project.restore":    CapWrite,
	"environment.create": CapWrite,
	"environment.update": CapWrite,
	"environment.delete": CapWrite,
	"service.create":     CapWrite,
	"service.update":     CapWrite,
	"service.delete":     CapWrite,
	"service.restore":    CapWrite,
	"env.write":          CapWrite,
	"domain.create":      CapWrite,
	"domain.update":      CapWrite,
	"domain.delete":      CapWrite,
	"backup.create":      CapWrite,
	"backup.update":      CapWrite,
	"backup.delete":      CapWrite,

	// Organization administration: members, credentials, grants, plan, audit.
	"organization.update":      CapAdmin,
	"members.manage":           CapAdmin,
	"keys.read":                CapAdmin,
	"keys.manage":              CapAdmin,
	"project.grants.write":     CapAdmin,
	"environment.grants.write": CapAdmin,
	"limits.write":             CapAdmin,
	"audit.read":               CapAdmin,

	// Irreversible owner-only organization actions.
	"organization.delete": CapOwner,

	// Internal break-glass / support tooling.
	"admin.read":        CapSupport,
	"admin.import":      CapSupport,
	"admin.reconcile":   CapSupport,
	"admin.break_glass": CapSupport,
}

// Actions returns every catalogued action in a stable, sorted order.
func Actions() []Action {
	out := make([]Action, 0, len(defaultActionCatalog))
	for a := range defaultActionCatalog {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CustomRoleResolver resolves a non-built-in role name to its capability set.
// It is the extension hook for organization-defined custom roles: the engine
// calls it for any Role that is not one of the six built-ins. It must be pure
// and is expected to return ok=false for an unknown role rather than an empty
// set, so the engine can distinguish "custom role with no capabilities" from
// "role does not exist".
type CustomRoleResolver func(Role) (caps []Capability, ok bool)
