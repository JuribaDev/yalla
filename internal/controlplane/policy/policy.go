// Package policy is the Yalla Control Plane authorization engine. It is the
// single, authoritative place where the backend decides whether a principal
// may perform an action against a scoped resource. Dokploy permissions may be
// configured as defense-in-depth, but this engine — not Dokploy — is the
// source of truth for authorization.
//
// The engine is a pure decision function: given a [Principal], an [Action],
// and a [Resource], [Engine.Decide] returns a [Decision] carrying allow/deny
// plus a stable [Reason] code. It performs no I/O, reads no clock, and never
// panics on zero-value input, so it is trivially table-testable and safe to
// call inside a database transaction.
//
// The model has three layers:
//
//   - Roles. A principal carries one organization-wide [Role] (owner, admin,
//     developer, viewer, ci, support) plus, optionally, a set of scoped
//     [Grant]s. Custom roles are resolved through a registered hook.
//   - Capabilities. Every [Action] maps to exactly one [Capability]; every
//     role maps to a set of capabilities. An action is allowed when the
//     principal holds its capability at the resource's scope. This indirection
//     keeps the role/action matrix small and total.
//   - Scopes. A [Grant] narrows (or, within an org, widens) a principal's
//     capabilities to a project, environment, or service subtree. A principal
//     with no organization role and only project grants can act only inside
//     those projects — grants narrow visibility and allowed actions.
//
// Cross-tenant access is denied by construction: a resource in a different
// organization than the principal is refused unless the principal holds the
// support capability and is performing a read. IDs, roles, and actions are not
// secrets, so nothing in this package is redacted; callers must still avoid
// logging a full [Principal] alongside credential material from other layers.
package policy

import "github.com/JuribaDev/yalla/internal/controlplane/domain"

// Role is an organization-wide or grant-scoped role name. The six built-in
// roles are a public compatibility contract; any other value is treated as a
// custom role and resolved through the engine's custom-role hook.
type Role string

// The built-in roles. Their capability sets are defined by builtinRoleCaps.
const (
	// RoleOwner has every capability in its organization, including the
	// owner-only capability that gates irreversible organization actions.
	RoleOwner Role = "owner"
	// RoleAdmin manages the organization, its members, keys, and grants, and
	// can read, deploy, and write — but cannot perform owner-only actions.
	RoleAdmin Role = "admin"
	// RoleDeveloper can read, deploy, and write resources but cannot manage
	// the organization, its members, or its credentials.
	RoleDeveloper Role = "developer"
	// RoleViewer has read-only access to its organization.
	RoleViewer Role = "viewer"
	// RoleCI is a non-human automation role: it can read and deploy but cannot
	// otherwise mutate desired state or manage the organization.
	RoleCI Role = "ci"
	// RoleSupport is the internal break-glass role: cross-tenant read access
	// plus the support capability that gates admin break-glass actions. It
	// deliberately holds no write capability.
	RoleSupport Role = "support"
)

// Capability classifies what an action does. Roles grant capabilities rather
// than enumerating individual actions, which keeps the authorization matrix
// small and total. Capability values are an internal contract; the stable
// external contract is the set of Action strings and Role names.
type Capability string

const (
	// CapSelf marks actions a principal performs against its own identity
	// (reading the current principal, listing the principal's organizations,
	// creating a brand-new organization). Any authenticated, enabled principal
	// holds it, regardless of role or scope.
	CapSelf Capability = "self"
	// CapRead marks actions that view resources within an organization.
	CapRead Capability = "read"
	// CapDeploy marks actions that trigger provisioning or lifecycle changes
	// against existing resources (deploy, rollback, restart, run backup) but
	// do not change desired-state configuration.
	CapDeploy Capability = "deploy"
	// CapWrite marks actions that create, update, delete, or restore
	// desired-state resources and their configuration.
	CapWrite Capability = "write"
	// CapAdmin marks actions that manage the organization itself: members,
	// API keys, scoped grants, plan limits, audit log, and organization
	// settings.
	CapAdmin Capability = "admin"
	// CapOwner marks irreversible organization-level actions reserved for the
	// owner, such as deleting the organization.
	CapOwner Capability = "owner"
	// CapSupport marks the internal break-glass capability: admin import,
	// reconcile, break-glass access, and cross-tenant support reads.
	CapSupport Capability = "support"
)

// Action is a stable, dotted action identifier (for example "project.create").
// Every public endpoint maps to exactly one Action; the action-to-capability
// catalog in this package is the authoritative mapping.
type Action string

// Scope identifies the resource subtree a grant or resource belongs to. An
// empty field means "not narrowed at this level": a Scope with only
// OrganizationID set covers the whole organization, while one that also sets
// ProjectID covers only that project's environments and services. Scope
// mirrors the Dokploy hierarchy Organization -> Project -> Environment ->
// Service.
type Scope struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// covers reports whether s (a grant scope) contains the resource scope r.
// A grant covers a resource when, at every level the grant pins, the resource
// matches; levels the grant leaves empty are unrestricted. Both scopes must
// name the same organization — grants never cross tenants.
func (s Scope) covers(r Scope) bool {
	if s.OrganizationID == "" || s.OrganizationID != r.OrganizationID {
		return false
	}
	if s.ProjectID != "" && s.ProjectID != r.ProjectID {
		return false
	}
	if s.EnvironmentID != "" && s.EnvironmentID != r.EnvironmentID {
		return false
	}
	if s.ServiceID != "" && s.ServiceID != r.ServiceID {
		return false
	}
	return true
}

// Grant narrows or widens a principal's authority within its organization to a
// specific resource subtree. A principal whose organization Role lacks a
// capability can still perform an action when a Grant covering the resource
// supplies it; a principal with no organization Role at all is authorized
// purely by its Grants. Grants never cross organizations.
type Grant struct {
	// Role is the role the grant confers within Scope. It may be a built-in
	// role or a custom role resolved through the engine's hook; an
	// unresolvable grant role contributes no capabilities and is ignored.
	Role Role
	// Scope is the resource subtree the grant applies to. Its OrganizationID
	// must match the principal's organization or the grant is ignored.
	Scope Scope
}

// Resource identifies the thing an action targets. Kind is the domain kind of
// the resource; Scope locates it in the Organization -> Project -> Environment
// -> Service hierarchy. For organization-level actions only Scope.OrganizationID
// is set; deeper actions also set the enclosing project/environment/service
// IDs so that scoped grants can be evaluated.
type Resource struct {
	Kind  domain.Kind
	Scope Scope
}

// Principal is the authenticated identity an action is authorized for. Both
// API-key authentication and human session authentication resolve to this
// single concrete type, so the policy engine has exactly one input shape.
type Principal struct {
	// ID is the principal's domain ID (a user or service-account ID). An
	// empty ID means "no authenticated principal".
	ID string
	// Kind is the principal's domain kind: domain.KindUser for a human or
	// domain.KindServiceAccount for automation.
	Kind domain.Kind
	// OrganizationID is the principal's home organization. Authorization for
	// any resource outside this organization is denied unless the principal
	// holds the support capability and is performing a read.
	OrganizationID string
	// Role is the principal's organization-wide role. It may be empty, in
	// which case the principal is authorized purely by Grants.
	Role Role
	// Grants are scoped roles that narrow or widen the principal's authority
	// within its organization.
	Grants []Grant
	// Disabled marks a principal whose access has been revoked (a disabled
	// service account, a deactivated user). A disabled principal is denied
	// every action.
	Disabled bool
}

// Reason is a stable, machine-readable explanation for a [Decision]. Reason
// values are part of the public contract: they appear in audit records and
// authorization-denied responses, so callers may branch on them.
type Reason string

const (
	// ReasonAllowedByRole means the principal's organization role granted the
	// action's capability.
	ReasonAllowedByRole Reason = "allowed_by_role"
	// ReasonAllowedByGrant means a scoped grant covering the resource granted
	// the action's capability; the organization role alone would not have.
	ReasonAllowedByGrant Reason = "allowed_by_grant"
	// ReasonAllowedSelf means the action targets the principal's own identity
	// and is allowed for any authenticated, enabled principal.
	ReasonAllowedSelf Reason = "allowed_self"
	// ReasonAllowedBySupport means the principal holds the support capability
	// and performed a permitted cross-tenant read or break-glass action.
	ReasonAllowedBySupport Reason = "allowed_by_support"

	// ReasonDeniedNoPrincipal means no authenticated principal was supplied.
	ReasonDeniedNoPrincipal Reason = "denied_no_principal"
	// ReasonDeniedPrincipalDisabled means the principal's access is revoked.
	ReasonDeniedPrincipalDisabled Reason = "denied_principal_disabled"
	// ReasonDeniedUnknownAction means the action is not in the catalog.
	ReasonDeniedUnknownAction Reason = "denied_unknown_action"
	// ReasonDeniedUnknownRole means the principal's organization role is not a
	// built-in role and could not be resolved by the custom-role hook.
	ReasonDeniedUnknownRole Reason = "denied_unknown_role"
	// ReasonDeniedCrossTenant means the resource belongs to a different
	// organization than the principal and the principal cannot reach it.
	ReasonDeniedCrossTenant Reason = "denied_cross_tenant"
	// ReasonDeniedOutOfScope means the principal holds the required capability
	// somewhere, but not at the resource's scope.
	ReasonDeniedOutOfScope Reason = "denied_out_of_scope"
	// ReasonDeniedNoCapability means neither the principal's role nor any of
	// its grants confers the action's capability.
	ReasonDeniedNoCapability Reason = "denied_no_capability"
)

// Decision is the result of an authorization check. Allow is the verdict;
// Reason is the stable code explaining it. A Decision is always populated with
// a Reason, including on allow, so audit records can record why access was
// granted as well as why it was refused.
type Decision struct {
	// Allow is true when the principal may perform the action.
	Allow bool
	// Reason is the stable code explaining the verdict.
	Reason Reason
}

// allowed reports whether a Reason represents an allow verdict.
func (r Reason) allowed() bool {
	switch r {
	case ReasonAllowedByRole, ReasonAllowedByGrant, ReasonAllowedSelf, ReasonAllowedBySupport:
		return true
	default:
		return false
	}
}
