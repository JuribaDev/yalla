package policy

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// orgA and orgB are two distinct organizations used to prove tenant isolation.
const (
	orgA = "org_0000000000000000000000aaaa"
	orgB = "org_0000000000000000000000bbbb"
)

// principalIn builds an enabled user principal in orgA with the given role.
func principalIn(org string, role Role, grants ...Grant) Principal {
	return Principal{
		ID:             "usr_00000000000000000000000001",
		Kind:           domain.KindUser,
		OrganizationID: org,
		Role:           role,
		Grants:         grants,
	}
}

// resourceIn builds an organization-scoped resource in org.
func resourceIn(org string) Resource {
	return Resource{Kind: domain.KindProject, Scope: Scope{OrganizationID: org}}
}

// TestPolicyMatrix exhaustively checks every built-in role against every
// catalogued action on an in-organization resource. The expected verdict is
// derived from the role/capability matrix and the action catalog, so the test
// fails the moment either drifts from the other.
func TestPolicyMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	for _, role := range BuiltinRoles() {
		role := role
		for _, action := range Actions() {
			action := action
			t.Run(string(role)+"/"+string(action), func(t *testing.T) {
				t.Parallel()
				required, ok := e.ActionCapability(action)
				if !ok {
					t.Fatalf("action %q missing from catalog", action)
				}
				got := e.Decide(principalIn(orgA, role), action, resourceIn(orgA))

				switch {
				case required == CapSelf:
					assertDecision(t, got, true, ReasonAllowedSelf)
				case builtinRoleCaps[role].has(required):
					assertDecision(t, got, true, ReasonAllowedByRole)
				default:
					assertDecision(t, got, false, ReasonDeniedNoCapability)
				}
			})
		}
	}
}

// TestPolicyMatrixDeniesCrossTenant exhaustively checks every built-in role
// against every catalogued action on a resource in a *different* organization.
// The expected verdict is the cross-tenant invariant the engine guarantees:
// CapSelf actions are organization-independent and always allowed; the support
// role's CapSupport bridges the tenant boundary for read and break-glass
// actions; every other role must be denied with ReasonDeniedCrossTenant. A
// drift in either the role/capability matrix, the action catalog, or the
// engine's cross-tenant ordering fails this matrix immediately so a future
// regression cannot silently leak data across tenants.
func TestPolicyMatrixDeniesCrossTenant(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	for _, role := range BuiltinRoles() {
		role := role
		for _, action := range Actions() {
			action := action
			t.Run(string(role)+"/"+string(action), func(t *testing.T) {
				t.Parallel()
				required, ok := e.ActionCapability(action)
				if !ok {
					t.Fatalf("action %q missing from catalog", action)
				}
				got := e.Decide(principalIn(orgA, role), action, resourceIn(orgB))

				switch {
				case required == CapSelf:
					// Self actions are organization-independent: the cross-tenant
					// check is gated behind the CapSelf shortcut in engine.Decide.
					assertDecision(t, got, true, ReasonAllowedSelf)
				case builtinRoleCaps[role].has(CapSupport) && (required == CapRead || required == CapSupport):
					// Support role's CapSupport bridges the tenant boundary
					// for CapRead and CapSupport actions only — every other
					// required capability falls through to the cross-tenant
					// deny per the engine.Decide cross-tenant clause.
					assertDecision(t, got, true, ReasonAllowedBySupport)
				default:
					// Every other role acting on a foreign tenant must be
					// denied with the cross-tenant reason — never with a
					// generic capability denial that could mask the leak.
					assertDecision(t, got, false, ReasonDeniedCrossTenant)
				}
			})
		}
	}
}

// TestDecideNoPrincipal denies the zero principal outright.
func TestDecideNoPrincipal(t *testing.T) {
	t.Parallel()
	got := NewEngine().Decide(Principal{}, "project.read", resourceIn(orgA))
	assertDecision(t, got, false, ReasonDeniedNoPrincipal)
}

// TestDecideDisabledPrincipal denies a principal whose access is revoked, even
// for an action its role would otherwise allow.
func TestDecideDisabledPrincipal(t *testing.T) {
	t.Parallel()
	p := principalIn(orgA, RoleOwner)
	p.Disabled = true
	got := NewEngine().Decide(p, "project.read", resourceIn(orgA))
	assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
}

// TestDecideUnknownAction denies an action that is not in the catalog.
func TestDecideUnknownAction(t *testing.T) {
	t.Parallel()
	got := NewEngine().Decide(principalIn(orgA, RoleOwner), "nonsense.action", resourceIn(orgA))
	assertDecision(t, got, false, ReasonDeniedUnknownAction)
}

// TestDecideUnknownRole denies a principal whose organization role is neither
// built-in nor resolvable by a custom-role hook — but still allows self
// actions, which never depend on a role.
func TestDecideUnknownRole(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	p := principalIn(orgA, Role("wizard"))

	assertDecision(t, e.Decide(p, "project.read", resourceIn(orgA)), false, ReasonDeniedUnknownRole)
	assertDecision(t, e.Decide(p, "auth.me", resourceIn(orgA)), true, ReasonAllowedSelf)
}

// TestDecideCustomRole resolves an organization-defined role through the hook,
// both as a principal's organization role and as a grant role.
func TestDecideCustomRole(t *testing.T) {
	t.Parallel()
	e := NewEngine(WithCustomRoles(func(r Role) ([]Capability, bool) {
		if r == "deployer" {
			return []Capability{CapSelf, CapRead, CapDeploy}, true
		}
		return nil, false
	}))

	p := principalIn(orgA, Role("deployer"))
	assertDecision(t, e.Decide(p, "deployment.create", resourceIn(orgA)), true, ReasonAllowedByRole)
	assertDecision(t, e.Decide(p, "project.create", resourceIn(orgA)), false, ReasonDeniedNoCapability)

	// The same custom role used as a scoped grant.
	projScope := Scope{OrganizationID: orgA, ProjectID: "proj_0000000000000000000000aa"}
	g := principalIn(orgA, RoleViewer, Grant{Role: Role("deployer"), Scope: projScope})
	assertDecision(t, e.Decide(g, "deployment.create", Resource{Kind: domain.KindService, Scope: projScope}), true, ReasonAllowedByGrant)

	// A role the hook cannot resolve is still unknown.
	assertDecision(t, e.Decide(principalIn(orgA, Role("ghost")), "project.read", resourceIn(orgA)), false, ReasonDeniedUnknownRole)
}

// TestDecideGrantsNarrowAndWiden proves that scoped grants both narrow
// authority (a principal with no organization role acts only inside its grant
// scopes) and widen it (a viewer gains write inside a granted project).
func TestDecideGrantsNarrowAndWiden(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	projP := "proj_000000000000000000000ppp"
	projQ := "proj_000000000000000000000qqq"
	scopeP := Scope{OrganizationID: orgA, ProjectID: projP}
	scopeQ := Scope{OrganizationID: orgA, ProjectID: projQ}

	// A viewer with a developer grant on project P: write inside P, but not in P.
	viewer := principalIn(orgA, RoleViewer, Grant{Role: RoleDeveloper, Scope: scopeP})
	assertDecision(t, e.Decide(viewer, "service.create", Resource{Kind: domain.KindService, Scope: scopeP}), true, ReasonAllowedByGrant)
	// The grant covers a deeper environment/service inside P.
	deep := Scope{OrganizationID: orgA, ProjectID: projP, EnvironmentID: "env_00000000000000000000000ee", ServiceID: "svc_0000000000000000000000sss"}
	assertDecision(t, e.Decide(viewer, "service.update", Resource{Kind: domain.KindService, Scope: deep}), true, ReasonAllowedByGrant)
	// But not project Q — the principal holds write, just not at that scope.
	assertDecision(t, e.Decide(viewer, "service.create", Resource{Kind: domain.KindService, Scope: scopeQ}), false, ReasonDeniedOutOfScope)
	// Read still works org-wide via the viewer organization role.
	assertDecision(t, e.Decide(viewer, "project.read", Resource{Kind: domain.KindProject, Scope: scopeQ}), true, ReasonAllowedByRole)

	// A principal with NO organization role is authorized purely by grants.
	scoped := Principal{ID: "usr_00000000000000000000000002", Kind: domain.KindUser, OrganizationID: orgA, Grants: []Grant{{Role: RoleDeveloper, Scope: scopeP}}}
	assertDecision(t, e.Decide(scoped, "service.create", Resource{Kind: domain.KindService, Scope: scopeP}), true, ReasonAllowedByGrant)
	assertDecision(t, e.Decide(scoped, "service.create", Resource{Kind: domain.KindService, Scope: scopeQ}), false, ReasonDeniedOutOfScope)
	// A capability no grant supplies anywhere is a flat missing-capability deny.
	assertDecision(t, e.Decide(scoped, "members.manage", resourceIn(orgA)), false, ReasonDeniedNoCapability)
}

// TestDecideGrantsIgnoredWhenInvalid proves grants with an unresolvable role
// or a foreign-organization scope contribute nothing.
func TestDecideGrantsIgnoredWhenInvalid(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	scopeP := Scope{OrganizationID: orgA, ProjectID: "proj_000000000000000000000ppp"}

	// Grant role that cannot be resolved → ignored.
	unknownGrant := principalIn(orgA, RoleViewer, Grant{Role: Role("ghost"), Scope: scopeP})
	assertDecision(t, e.Decide(unknownGrant, "service.create", Resource{Kind: domain.KindService, Scope: scopeP}), false, ReasonDeniedNoCapability)

	// Grant scoped to a different organization → ignored.
	foreignGrant := principalIn(orgA, RoleViewer, Grant{Role: RoleOwner, Scope: Scope{OrganizationID: orgB, ProjectID: "proj_000000000000000000000ppp"}})
	assertDecision(t, e.Decide(foreignGrant, "service.create", Resource{Kind: domain.KindService, Scope: scopeP}), false, ReasonDeniedNoCapability)
}

// TestDecideCrossTenant proves a resource in another organization is
// unreachable except for support reads and support break-glass actions.
func TestDecideCrossTenant(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	// An owner of orgA cannot even read orgB.
	owner := principalIn(orgA, RoleOwner)
	assertDecision(t, e.Decide(owner, "project.read", resourceIn(orgB)), false, ReasonDeniedCrossTenant)
	assertDecision(t, e.Decide(owner, "project.create", resourceIn(orgB)), false, ReasonDeniedCrossTenant)

	// A support principal may read across tenants and use break-glass actions,
	// but never write.
	support := principalIn(orgA, RoleSupport)
	assertDecision(t, e.Decide(support, "project.read", resourceIn(orgB)), true, ReasonAllowedBySupport)
	assertDecision(t, e.Decide(support, "admin.break_glass", resourceIn(orgB)), true, ReasonAllowedBySupport)
	assertDecision(t, e.Decide(support, "project.create", resourceIn(orgB)), false, ReasonDeniedCrossTenant)

	// Self actions are organization-independent.
	assertDecision(t, e.Decide(owner, "auth.me", resourceIn(orgB)), true, ReasonAllowedSelf)
}

// TestScopeCovers unit-tests the scope-containment helper directly.
func TestScopeCovers(t *testing.T) {
	t.Parallel()
	orgScope := Scope{OrganizationID: orgA}
	projScope := Scope{OrganizationID: orgA, ProjectID: "proj_1"}
	svcScope := Scope{OrganizationID: orgA, ProjectID: "proj_1", EnvironmentID: "env_1", ServiceID: "svc_1"}

	cases := []struct {
		name  string
		grant Scope
		res   Scope
		want  bool
	}{
		{"org covers org", orgScope, orgScope, true},
		{"org covers project", orgScope, projScope, true},
		{"org covers service", orgScope, svcScope, true},
		{"project covers same project", projScope, projScope, true},
		{"project covers deeper service", projScope, svcScope, true},
		{"project does not cover org", projScope, orgScope, false},
		{"project does not cover other project", projScope, Scope{OrganizationID: orgA, ProjectID: "proj_2"}, false},
		{"service covers only itself", svcScope, svcScope, true},
		{"service does not cover project", svcScope, projScope, false},
		{"different org never covers", Scope{OrganizationID: orgB}, orgScope, false},
		{"empty org never covers", Scope{}, orgScope, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.grant.covers(tc.res); got != tc.want {
				t.Fatalf("covers() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAuthorize maps decisions onto typed apierr errors and proves the error
// message leaks neither the principal ID nor any resource ID.
func TestAuthorize(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	if err := e.Authorize(principalIn(orgA, RoleOwner), "project.create", resourceIn(orgA)); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}

	// No principal → CodeAuth.
	if code := codeOf(t, e.Authorize(Principal{}, "project.read", resourceIn(orgA))); code != yerr.CodeAuth {
		t.Fatalf("no-principal code = %s, want %s", code, yerr.CodeAuth)
	}

	// Authenticated but unauthorized → CodeForbidden.
	denied := e.Authorize(principalIn(orgA, RoleViewer), "project.create", resourceIn(orgA))
	if code := codeOf(t, denied); code != yerr.CodeForbidden {
		t.Fatalf("forbidden code = %s, want %s", code, yerr.CodeForbidden)
	}
	// The message names the action and the reason, never the IDs.
	msg := denied.Error()
	if !strings.Contains(msg, "project.create") || !strings.Contains(msg, string(ReasonDeniedNoCapability)) {
		t.Fatalf("message %q missing action or reason", msg)
	}
	for _, secret := range []string{orgA, "usr_00000000000000000000000001"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("message %q leaked identifier %q", msg, secret)
		}
	}
}

// TestContextCarrier round-trips a principal through a context and proves
// AuthorizeCtx treats a context with no principal as unauthenticated.
func TestContextCarrier(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	// A nil context must be handled defensively, not panic. The nil travels
	// through a variable so the guard is exercised at runtime.
	var nilCtx context.Context
	if _, ok := PrincipalFromContext(nilCtx); ok {
		t.Fatal("nil context must carry no principal")
	}

	ctx := WithPrincipal(t.Context(), principalIn(orgA, RoleAdmin))
	got, ok := PrincipalFromContext(ctx)
	if !ok || got.Role != RoleAdmin || got.OrganizationID != orgA {
		t.Fatalf("round trip failed: %+v ok=%v", got, ok)
	}
	if err := e.AuthorizeCtx(ctx, "members.manage", resourceIn(orgA)); err != nil {
		t.Fatalf("AuthorizeCtx with admin principal: %v", err)
	}
	if code := codeOf(t, e.AuthorizeCtx(t.Context(), "members.manage", resourceIn(orgA))); code != yerr.CodeAuth {
		t.Fatalf("AuthorizeCtx with no principal code = %s, want %s", code, yerr.CodeAuth)
	}
}

// TestCatalogAndRolesAreWellFormed guards the static contract: every action
// maps to a known capability, every built-in role has a capability set, and
// the public enumerators are stable and sorted.
func TestCatalogAndRolesAreWellFormed(t *testing.T) {
	t.Parallel()
	known := map[Capability]struct{}{
		CapSelf: {}, CapRead: {}, CapDeploy: {}, CapWrite: {}, CapAdmin: {}, CapOwner: {}, CapSupport: {},
	}
	for action, required := range defaultActionCatalog {
		if _, ok := known[required]; !ok {
			t.Fatalf("action %q maps to unknown capability %q", action, required)
		}
	}
	if len(defaultActionCatalog) != 61 {
		t.Fatalf("catalog has %d actions, want 61", len(defaultActionCatalog))
	}

	roles := BuiltinRoles()
	if len(roles) != 6 {
		t.Fatalf("BuiltinRoles returned %d, want 6", len(roles))
	}
	for i := 1; i < len(roles); i++ {
		if roles[i-1] >= roles[i] {
			t.Fatalf("BuiltinRoles not sorted: %v", roles)
		}
	}
	for _, r := range roles {
		if _, ok := builtinRoleCaps[r]; !ok {
			t.Fatalf("BuiltinRoles returned %q with no capability set", r)
		}
		// Every built-in role can act on its own identity.
		if !builtinRoleCaps[r].has(CapSelf) {
			t.Fatalf("role %q is missing CapSelf", r)
		}
	}

	actions := Actions()
	for i := 1; i < len(actions); i++ {
		if actions[i-1] >= actions[i] {
			t.Fatalf("Actions not sorted: %v", actions)
		}
	}

	// WithAction extends the catalog without touching the package default.
	ext := NewEngine(WithAction("future.action", CapWrite))
	if got, ok := ext.ActionCapability("future.action"); !ok || got != CapWrite {
		t.Fatalf("WithAction did not register the action")
	}
	if _, ok := defaultActionCatalog["future.action"]; ok {
		t.Fatal("WithAction mutated the package-level default catalog")
	}
}

// assertDecision fails the test unless got matches the expected verdict and
// reason.
func assertDecision(t *testing.T, got Decision, wantAllow bool, wantReason Reason) {
	t.Helper()
	if got.Allow != wantAllow || got.Reason != wantReason {
		t.Fatalf("decision = {allow:%v reason:%s}, want {allow:%v reason:%s}", got.Allow, got.Reason, wantAllow, wantReason)
	}
	if got.Reason.allowed() != got.Allow {
		t.Fatalf("reason %q allowed() = %v but Allow = %v", got.Reason, got.Reason.allowed(), got.Allow)
	}
}

// codeOf extracts the stable error code from a typed backend error.
func codeOf(t *testing.T, err error) yerr.Code {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("error %v is not a *yerr.Error", err)
	}
	return ye.Code
}
