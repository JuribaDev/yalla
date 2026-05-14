package policy

import (
	"context"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// Engine is the authorization decision engine. It holds the action catalog and
// the custom-role hook; it is immutable after construction and safe for
// concurrent use. Construct one with [NewEngine] at process startup and share
// it across requests.
type Engine struct {
	catalog     map[Action]Capability
	customRoles CustomRoleResolver
}

// Option configures an [Engine] at construction time.
type Option func(*Engine)

// WithCustomRoles registers the hook that resolves organization-defined custom
// roles. Without it, any role that is not a built-in is treated as unknown.
func WithCustomRoles(r CustomRoleResolver) Option {
	return func(e *Engine) { e.customRoles = r }
}

// WithAction registers or overrides a single action's required capability.
// It is the extension point for actions introduced by later stories without
// editing the default catalog.
func WithAction(action Action, capability Capability) Option {
	return func(e *Engine) { e.catalog[action] = capability }
}

// NewEngine builds an Engine seeded with the default action catalog. Options
// are applied in order, so a later WithAction overrides an earlier one.
func NewEngine(opts ...Option) *Engine {
	catalog := make(map[Action]Capability, len(defaultActionCatalog))
	for a, c := range defaultActionCatalog {
		catalog[a] = c
	}
	e := &Engine{catalog: catalog}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// ActionCapability returns the capability an action requires, and whether the
// action is catalogued at all.
func (e *Engine) ActionCapability(action Action) (Capability, bool) {
	c, ok := e.catalog[action]
	return c, ok
}

// roleCaps resolves a role to its capability set. Built-in roles come from the
// static matrix; any other role is passed to the custom-role hook. ok is false
// when the role cannot be resolved at all, which the caller treats differently
// for a principal's organization role (a hard deny) than for a grant role (the
// grant is ignored).
func (e *Engine) roleCaps(role Role) (capSet, bool) {
	if caps, ok := builtinRoleCaps[role]; ok {
		return caps, true
	}
	if e.customRoles != nil {
		if caps, ok := e.customRoles(role); ok {
			return newCapSet(caps...), true
		}
	}
	return nil, false
}

// Decide authorizes principal to perform action against resource and returns a
// [Decision] carrying the verdict and a stable [Reason]. It is a pure function:
// it performs no I/O, never panics on zero-value input, and is safe to call
// concurrently and inside a database transaction.
//
// The evaluation order is fixed and deny-by-default:
//
//  1. A missing or disabled principal is denied outright.
//  2. An uncatalogued action is denied.
//  3. CapSelf actions are allowed for any authenticated, enabled principal.
//  4. The principal's organization role must resolve, or the request is denied.
//  5. A resource in another organization is denied unless the principal holds
//     the support capability and the action is a read or support action.
//  6. Otherwise the action is allowed iff the principal's organization role,
//     or a grant whose scope covers the resource, confers the action's
//     capability.
func (e *Engine) Decide(principal Principal, action Action, resource Resource) Decision {
	if principal.ID == "" {
		return deny(ReasonDeniedNoPrincipal)
	}
	if principal.Disabled {
		return deny(ReasonDeniedPrincipalDisabled)
	}

	required, ok := e.catalog[action]
	if !ok {
		return deny(ReasonDeniedUnknownAction)
	}

	// Self actions target the principal's own identity; they are allowed for
	// any authenticated, enabled principal regardless of role, scope, or the
	// organization the resource names.
	if required == CapSelf {
		return allow(ReasonAllowedSelf)
	}

	roleCaps, roleOK := e.roleCaps(principal.Role)
	if principal.Role != "" && !roleOK {
		return deny(ReasonDeniedUnknownRole)
	}

	// Cross-tenant resources are unreachable except for support reads.
	if resource.Scope.OrganizationID != principal.OrganizationID {
		if roleCaps.has(CapSupport) && (required == CapRead || required == CapSupport) {
			return allow(ReasonAllowedBySupport)
		}
		return deny(ReasonDeniedCrossTenant)
	}

	// Within the principal's organization, the organization role applies
	// everywhere.
	if roleCaps.has(required) {
		return allow(ReasonAllowedByRole)
	}

	// A grant whose scope covers the resource can supply a capability the
	// organization role lacks. A grant whose scope does not cover the resource
	// is remembered so an out-of-scope denial can be distinguished from a
	// flat-out missing capability.
	heldOutOfScope := false
	for _, g := range principal.Grants {
		grantCaps, ok := e.roleCaps(g.Role)
		if !ok || !grantCaps.has(required) {
			continue
		}
		if g.Scope.OrganizationID != principal.OrganizationID {
			continue
		}
		if g.Scope.covers(resource.Scope) {
			return allow(ReasonAllowedByGrant)
		}
		heldOutOfScope = true
	}

	if heldOutOfScope {
		return deny(ReasonDeniedOutOfScope)
	}
	return deny(ReasonDeniedNoCapability)
}

// Authorize is the imperative form of [Decide]: it returns nil when the action
// is allowed and a typed [apierr] error when it is not, so handlers and store
// units of work can authorize with a single `if err != nil` check. A missing
// principal maps to apierr.Unauthenticated (HTTP 401); every other denial maps
// to apierr.Forbidden (HTTP 403). The error message carries only the action
// and the stable reason code — never the principal ID or any resource ID — so
// it is safe to place on the wire and in logs.
func (e *Engine) Authorize(principal Principal, action Action, resource Resource) error {
	d := e.Decide(principal, action, resource)
	if d.Allow {
		return nil
	}
	if d.Reason == ReasonDeniedNoPrincipal {
		return apierr.Unauthenticated("authentication is required for action " + string(action))
	}
	return apierr.Forbidden("not authorized for action " + string(action) + " (" + string(d.Reason) + ")")
}

// AuthorizeCtx is [Authorize] with the principal resolved from ctx via
// [PrincipalFromContext]. A context with no principal is treated as a missing
// principal and yields apierr.Unauthenticated. It is the entry point HTTP
// middleware and store units of work use once the auth layer has placed the
// principal on the request context.
func (e *Engine) AuthorizeCtx(ctx context.Context, action Action, resource Resource) error {
	p, _ := PrincipalFromContext(ctx)
	return e.Authorize(p, action, resource)
}

func allow(r Reason) Decision { return Decision{Allow: true, Reason: r} }
func deny(r Reason) Decision  { return Decision{Allow: false, Reason: r} }

// principalContextKey is the unexported context key the principal is stored
// under, so no other package can collide with or forge it.
type principalContextKey struct{}

// WithPrincipal returns a child context carrying principal. The auth layer
// calls it once it has authenticated a request; downstream middleware,
// handlers, and store units of work read it back with [PrincipalFromContext].
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns the principal carried by ctx. ok is false when
// no principal has been attached, in which case the zero Principal is returned
// — and the zero Principal is denied every action by [Engine.Decide].
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}
