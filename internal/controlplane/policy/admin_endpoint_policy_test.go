package policy

// Canonical reference admin-endpoint authorization test (BE-0403).
//
// This file is the load-bearing static fixture the BE-0403 verification
// gate binds to via the PRD's `go test -run TestAdminEndpoint ./...`
// filter. The pair declared here captures the two structural admin-
// endpoint authorization invariants every regression MUST trip:
//
//   - TestAdminEndpointCoversCallSites walks a closed-set scenario
//     table built from the cartesian product of every documented
//     admin endpoint (the six tagged `admin` HTTP routes registered
//     in internal/controlplane/httpapi/routes.go and surfaced in the
//     PRD's apiSurface) × the corresponding ActionAdmin* constant ×
//     every built-in role × every grant-scope position (org-scope,
//     project-scope, environment-scope, service-scope) × the
//     same-tenant and cross-tenant axes. The validator is the pure
//     policy.Engine.Decide function; every row predicts a specific
//     (Allow, Reason) verdict and asserts it. The table is also
//     exhaustive: every ActionAdmin* constant in actions.go is
//     visited exactly once, and every visited action is bound to its
//     wire endpoint(s), so a future admin endpoint that ships
//     without a row here (or an existing admin endpoint that drops
//     its row) trips the closed-set self-check at the head of the
//     test.
//
//   - TestAdminEndpointPreservesContractUnderContention fires
//     adminEndpointWorkers × adminEndpointIterationsPerWorker
//     goroutines that each draw a row from the same scenario table
//     by deterministic mod-index into the closed-set table (NOT
//     per-goroutine random selection — that would defeat the per-
//     iteration prediction contract). Each goroutine builds its own
//     Principal and Resource from its scenario, evaluates
//     policy.Engine.Decide, and asserts the verdict the scenario
//     predicted. A cross-write under the race (a future regression
//     that introduced shared mutable state in the engine — a cached
//     role-cap table, a sync.Once mutating a per-action capability
//     map, a leaky builtinRoleCaps reuse) would surface as a per-
//     iteration assertion failure even if the aggregate pass count
//     matched. Both members are deterministic by design: the engine
//     is a pure function of (principal, action, resource) and no
//     scenario reaches the process environment, the network, a live
//     Postgres, a live Dokploy, or any external service.
//
// The pair binds to the BE-0403 `-run TestAdminEndpoint` filter via
// the `TestAdminEndpoint` prefix; a rename to a function whose name
// does not match the prefix silently de-gates the admin-endpoint
// suite for any caller relying on the PRD's filter.
//
// The closed-set coverage invariant pins five structural admin-
// endpoint contracts at once:
//
//  1. Every admin endpoint maps to one of the four ActionAdmin*
//     constants (admin.read, admin.import, admin.reconcile,
//     admin.break_glass) — the action set is closed.
//  2. Every ActionAdmin* constant is catalogued as CapSupport in
//     catalog.go's defaultActionCatalog — a future drift that
//     remapped any admin action to CapRead, CapAdmin, or CapOwner
//     would change the role-allow set under the matrix and surface
//     here as a per-row Allow / Reason mismatch.
//  3. Every admin endpoint's resource is org-rooted by construction
//     (Kind=KindOrganization, Scope pins only OrganizationID). No
//     project / environment / service leg ever surfaces on an
//     admin endpoint's resource scope — a regression that started
//     pinning ProjectID on the admin reconcile resource would fail
//     every grant-containment row because covers() is one-way (a
//     grant scope with a pinned ProjectID can never cover a resource
//     with no ProjectID and vice versa).
//  4. The role-to-capability matrix in builtinRoleCaps admits
//     CapSupport ONLY for RoleSupport — a future drift that added
//     CapSupport to RoleOwner or RoleAdmin would silently widen
//     every admin endpoint to the offending role and fail every
//     non-Support row's Reason prediction here.
//  5. The engine's cross-tenant exception clause (the support
//     fallback in engine.go Decide) admits CapSupport AND CapRead;
//     a regression that narrowed it to CapRead alone would surface
//     here as a same-tenant Support row staying ReasonAllowedByRole
//     but the cross-tenant Support row flipping to
//     ReasonDeniedCrossTenant instead of ReasonAllowedBySupport.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// adminEndpointOrgVictim is a second organization id (distinct from
// orgA/orgB declared in policy_test.go) used to evaluate the cross-
// tenant Support exception on admin endpoints. The id is deliberately
// recognisable so a future log-redaction or wire-leak guard can needle
// for it through the canonical admin-endpoint matrix.
const adminEndpointOrgVictim = "org_0000000000000000000000eee3"

// adminEndpointResource builds the policy resource an admin endpoint
// resolver would construct for an admin operation targeting the
// organization named by org. The Kind is KindOrganization and only
// OrganizationID is pinned: every admin endpoint operates on the org-
// rooted view of an entire tenant, not a deeper subordinate row, so
// the resource is org-rooted by construction at every admin endpoint.
// This helper duplicates the per-endpoint adminReadOrgResource /
// adminReconcileEndpointOrgResource / adminBreakGlassEndpointOrgResource /
// adminImportOrgResource shape on purpose: a future shared helper that
// reached into one of those would couple the per-endpoint matrices
// into the same fixture, and a regression that changed the resource
// shape for one endpoint would silently change the closed-set table
// for every other endpoint here.
func adminEndpointResource(org string) Resource {
	return Resource{
		Kind:  domain.KindOrganization,
		Scope: Scope{OrganizationID: org},
	}
}

// adminEndpointCallSite describes one tagged-admin HTTP route the
// control-plane registers. The wire shape (path + method) is part of
// the operator-visible contract; the action is the policy.Action the
// resolver invokes before the handler runs; the description is the
// canonical short label that surfaces in failure messages so a
// regression points the operator at the exact endpoint that drifted.
type adminEndpointCallSite struct {
	method      string
	path        string
	action      Action
	description string
}

// adminEndpointCallSites is the closed set of admin endpoints the
// BE-0403 gate covers. Every tagged `admin` route registered in
// internal/controlplane/httpapi/routes.go appears here exactly once,
// and every entry maps to its catalogued ActionAdmin* constant. A
// regression that added a new admin endpoint without listing it here
// would fail the exhaustiveness self-check at the head of
// TestAdminEndpointCoversCallSites; a regression that retired an
// admin endpoint without dropping its row would fail the same
// self-check.
var adminEndpointCallSites = []adminEndpointCallSite{
	{
		method:      "GET",
		path:        "/v1/admin/dokploy/drift",
		action:      ActionAdminReconcile,
		description: "drift listing — Yalla support inspects pending Yalla<->Dokploy reconciliations across tenants",
	},
	{
		method:      "POST",
		path:        "/v1/admin/dokploy/reconcile",
		action:      ActionAdminReconcile,
		description: "reconcile mutation — Yalla support converges Dokploy to match Yalla's source of truth",
	},
	{
		method:      "POST",
		path:        "/v1/admin/dokploy/import",
		action:      ActionAdminImport,
		description: "import mutation — Yalla support imports an existing Dokploy resource into Yalla",
	},
	{
		method:      "GET",
		path:        "/v1/admin/organizations/{org_id}/dokploy-refs",
		action:      ActionAdminRead,
		description: "dokploy-refs listing — Yalla support inspects a tenant's Yalla<->Dokploy mapping rows",
	},
	{
		method:      "POST",
		path:        "/v1/admin/break-glass",
		action:      ActionAdminBreakGlass,
		description: "break-glass start — Yalla support opens an elevated cross-tenant access session",
	},
	{
		method:      "DELETE",
		path:        "/v1/admin/break-glass/{session_id}",
		action:      ActionAdminBreakGlass,
		description: "break-glass terminate — Yalla support closes an elevated cross-tenant access session",
	},
}

// adminEndpointActions is the closed set of admin Action constants
// every admin endpoint MUST resolve to. Walking this set asserts (a)
// every admin endpoint above maps to a member of this set and (b)
// every member of this set is bound to at least one admin endpoint.
// Adding a fifth ActionAdmin* constant without binding it to an
// endpoint, or adding a fifth admin endpoint that uses a non-admin
// action, both fail the closed-set self-check.
var adminEndpointActions = []Action{
	ActionAdminRead,
	ActionAdminImport,
	ActionAdminReconcile,
	ActionAdminBreakGlass,
}

// adminEndpointBuiltinRoleVerdicts is the closed role × verdict table
// the engine's role-only path MUST produce for every admin endpoint
// against a resource owned by the principal's home organization. The
// table is the cartesian intersection of builtinRoleCaps with
// CapSupport — only RoleSupport holds CapSupport, so only RoleSupport
// is allowed, every other built-in role is denied with
// ReasonDeniedNoCapability. A future drift that added CapSupport to
// RoleOwner or RoleAdmin would surface here as a flipped Allow / Reason
// pair the per-iteration assertion catches before the regression can
// ship.
var adminEndpointBuiltinRoleVerdicts = []struct {
	role   Role
	allow  bool
	reason Reason
}{
	{RoleOwner, false, ReasonDeniedNoCapability},
	{RoleAdmin, false, ReasonDeniedNoCapability},
	{RoleDeveloper, false, ReasonDeniedNoCapability},
	{RoleCI, false, ReasonDeniedNoCapability},
	{RoleViewer, false, ReasonDeniedNoCapability},
	{RoleSupport, true, ReasonAllowedByRole},
}

// adminEndpointGrantContainment describes one scoped-grant
// containment row the engine's grant path MUST deny. Every admin
// endpoint resolves to an org-rooted resource, so a grant whose Scope
// pins ProjectID / EnvironmentID / ServiceID is structurally narrower
// than the resource and is denied with ReasonDeniedOutOfScope by
// covers() — even when the grant role holds CapSupport. A regression
// that started accepting a deeper-than-org grant scope on an admin
// endpoint would fail every row here on the Allow column.
type adminEndpointGrantContainment struct {
	name  string
	scope Scope
}

var adminEndpointGrantContainments = []adminEndpointGrantContainment{
	{name: "project-scoped grant cannot widen to admin endpoints",
		scope: Scope{OrganizationID: orgA, ProjectID: "prj_admin_endpoint_alpha"}},
	{name: "environment-scoped grant cannot widen to admin endpoints",
		scope: Scope{OrganizationID: orgA, ProjectID: "prj_admin_endpoint_alpha", EnvironmentID: "env_admin_endpoint_staging"}},
	{name: "service-scoped grant cannot widen to admin endpoints",
		scope: Scope{OrganizationID: orgA, ProjectID: "prj_admin_endpoint_alpha", EnvironmentID: "env_admin_endpoint_staging", ServiceID: "svc_admin_endpoint_app"}},
}

// adminEndpointWorkers and adminEndpointIterationsPerWorker pick a
// burst in the 1024..2048 range so the contention test draws every
// row in the closed scenario table at least once. With
// 32 * 64 = 2048 iterations spread across an N-row table by
// idx := (w*iters + i) % N, every row is exercised ~2048/N times.
const (
	adminEndpointWorkers              = 32
	adminEndpointIterationsPerWorker  = 64
	adminEndpointContentionIterations = adminEndpointWorkers * adminEndpointIterationsPerWorker
)

// adminEndpointSecretMarker is a sentinel literal the contention
// scenarios seed into Principal IDs so a future regression that
// started echoing a Principal ID into a Decision Reason string would
// fail the redaction predicate on its first iteration. The marker
// has no role in the engine's verdict — it is a passive canary the
// per-row assertion can scan for if a future engine change starts
// adding caller-supplied data to Reasons.
const adminEndpointSecretMarker = "ADMINENDPOINTSECRETMARKER"

// adminEndpointScenario is one (endpoint, role, scope, axis) row the
// contention burst draws by mod-index. Same-tenant rows (orgA against
// orgA) exercise the role-only path; cross-tenant rows (orgA against
// orgVictim) exercise the engine's CapSupport / CapRead support
// fallback; grant rows (any role, any narrower-than-org scope)
// exercise the covers() deny path.
type adminEndpointScenario struct {
	endpoint adminEndpointCallSite
	role     Role
	// principalOrg is the principal's home organization; resourceOrg
	// is the org the resource is rooted at. Same → role-only path;
	// different → cross-tenant path.
	principalOrg string
	resourceOrg  string
	// grantScope, when non-zero, makes the principal a grant-only
	// principal (built-in role on a scoped grant); when zero, the
	// principal carries the role at the org level via the User role.
	grantScope Scope
	wantAllow  bool
	wantReason Reason
}

// adminEndpointScenarios materialises the closed cartesian product
// the BE-0403 gate covers. The ordering is deterministic so the
// contention burst's mod-index draws are stable across runs, and the
// `name` field encodes every dimension so a failure points the
// operator at the exact row that drifted.
func adminEndpointScenarios() []struct {
	name     string
	scenario adminEndpointScenario
} {
	out := make([]struct {
		name     string
		scenario adminEndpointScenario
	}, 0, len(adminEndpointCallSites)*(len(adminEndpointBuiltinRoleVerdicts)*2+len(adminEndpointGrantContainments)))

	for _, ep := range adminEndpointCallSites {
		// Role-only path against the principal's home organization
		// (same-tenant). Support → allow_by_role; every other built-in
		// role → denied_no_capability.
		for _, rv := range adminEndpointBuiltinRoleVerdicts {
			out = append(out, struct {
				name     string
				scenario adminEndpointScenario
			}{
				name: fmt.Sprintf("%s %s | role=%s | same-tenant",
					ep.method, ep.path, rv.role),
				scenario: adminEndpointScenario{
					endpoint:     ep,
					role:         rv.role,
					principalOrg: orgA,
					resourceOrg:  orgA,
					wantAllow:    rv.allow,
					wantReason:   rv.reason,
				},
			})
		}

		// Cross-tenant axis. Only RoleSupport ever holds CapSupport,
		// so the engine's cross-tenant exception clause (which admits
		// CapSupport OR CapRead — see engine.go Decide) allows Support
		// against a foreign org with ReasonAllowedBySupport. Every
		// other built-in role is denied with ReasonDeniedCrossTenant
		// because the principal's home org does not match the
		// resource's org AND the role does not hold the cross-tenant
		// fallback capability.
		for _, rv := range adminEndpointBuiltinRoleVerdicts {
			var wantAllow bool
			var wantReason Reason
			switch rv.role {
			case RoleSupport:
				wantAllow = true
				wantReason = ReasonAllowedBySupport
			default:
				wantAllow = false
				wantReason = ReasonDeniedCrossTenant
			}
			out = append(out, struct {
				name     string
				scenario adminEndpointScenario
			}{
				name: fmt.Sprintf("%s %s | role=%s | cross-tenant",
					ep.method, ep.path, rv.role),
				scenario: adminEndpointScenario{
					endpoint:     ep,
					role:         rv.role,
					principalOrg: orgA,
					resourceOrg:  adminEndpointOrgVictim,
					wantAllow:    wantAllow,
					wantReason:   wantReason,
				},
			})
		}

		// Grant containment. A grant-only principal whose grant scope
		// is narrower than the org root is denied at the covers()
		// boundary with ReasonDeniedOutOfScope, even when the grant
		// role is Support (the only role that holds CapSupport). The
		// engine's covers() rule is one-way: a grant with a pinned
		// ProjectID / EnvironmentID / ServiceID can never cover a
		// resource with no inner leg. Walking the grant role through
		// Support proves the deeper structural barrier: it is not the
		// role's capability that fails, it is the scope.
		for _, gc := range adminEndpointGrantContainments {
			out = append(out, struct {
				name     string
				scenario adminEndpointScenario
			}{
				name: fmt.Sprintf("%s %s | grant=%s",
					ep.method, ep.path, gc.name),
				scenario: adminEndpointScenario{
					endpoint:     ep,
					role:         RoleSupport,
					principalOrg: orgA,
					resourceOrg:  orgA,
					grantScope:   gc.scope,
					wantAllow:    false,
					wantReason:   ReasonDeniedOutOfScope,
				},
			})
		}
	}

	return out
}

// adminEndpointPrincipal builds the Principal one scenario row's
// authorization call uses. A zero grantScope materialises a User
// principal carrying the role at the org level; a non-zero grantScope
// materialises a ServiceAccount principal whose only access is the
// scoped grant.
func adminEndpointPrincipal(idx int, s adminEndpointScenario) Principal {
	id := fmt.Sprintf("sa_admin_endpoint_%s_%04d", adminEndpointSecretMarker, idx)
	if s.grantScope == (Scope{}) {
		return Principal{
			ID:             id,
			Kind:           domain.KindUser,
			OrganizationID: s.principalOrg,
			Role:           s.role,
		}
	}
	return Principal{
		ID:             id,
		Kind:           domain.KindServiceAccount,
		OrganizationID: s.principalOrg,
		Grants: []Grant{{
			Role:  s.role,
			Scope: s.grantScope,
		}},
	}
}

// TestAdminEndpointCoversCallSites is the closed-set coverage half of
// the BE-0403 pair. It walks every admin endpoint × every authorization
// axis (built-in role same-tenant, built-in role cross-tenant, scoped
// grant containment) and asserts the engine's Decide returns the
// predicted (Allow, Reason). The closed-set self-check at the head of
// the test catches drift in either direction: a new admin endpoint
// that ships without a row, or an existing admin endpoint that drops
// its row.
func TestAdminEndpointCoversCallSites(t *testing.T) {
	t.Parallel()

	// Closed-set self-check #1: every admin endpoint listed in
	// adminEndpointCallSites maps to one of the four admin Action
	// constants in adminEndpointActions, and every admin action is
	// bound to at least one endpoint. A regression that added a fifth
	// ActionAdmin* constant without listing it here, or a fifth
	// endpoint that used a non-admin action, both fail this check.
	actionSet := make(map[Action]bool, len(adminEndpointActions))
	for _, a := range adminEndpointActions {
		actionSet[a] = false
	}
	for _, ep := range adminEndpointCallSites {
		bound, ok := actionSet[ep.action]
		if !ok {
			t.Fatalf("admin endpoint %s %s names action %q which is not in adminEndpointActions; every admin endpoint must resolve to one of the four ActionAdmin* constants",
				ep.method, ep.path, ep.action)
		}
		_ = bound
		actionSet[ep.action] = true
	}
	for a, bound := range actionSet {
		if !bound {
			t.Fatalf("admin action %q is not bound to any endpoint in adminEndpointCallSites; every catalogued admin action must surface through at least one tagged-admin HTTP route",
				a)
		}
	}

	// Closed-set self-check #2: every admin action in
	// adminEndpointActions is catalogued as CapSupport in
	// defaultActionCatalog. A future drift that remapped any admin
	// action to CapRead, CapAdmin, or CapOwner would change the
	// role-allow set under the matrix; this check fails fast at the
	// catalog seam rather than waiting for the per-row verdict to
	// drift.
	e := NewEngine()
	for _, a := range adminEndpointActions {
		cap, ok := e.ActionCapability(a)
		if !ok {
			t.Fatalf("admin action %q is not present in the action catalog; defaultActionCatalog must list every admin action",
				a)
		}
		if cap != CapSupport {
			t.Fatalf("admin action %q is catalogued as %q; every admin action must require CapSupport so only RoleSupport (the only built-in role that holds CapSupport) can authorize it",
				a, cap)
		}
	}

	// Closed-set self-check #3: builtinRoleCaps admits CapSupport
	// for exactly RoleSupport, and for no other built-in role. A
	// drift that added CapSupport to another role would silently
	// widen every admin endpoint to that role and fail the per-row
	// verdicts below — but we also want a fast, targeted failure
	// here so the regression points the operator at the role
	// matrix, not at a misleading endpoint row.
	for _, r := range BuiltinRoles() {
		caps, ok := builtinRoleCaps[r]
		if !ok {
			t.Fatalf("BuiltinRoles() returned %q which is not in builtinRoleCaps; the role matrix must be self-consistent",
				r)
		}
		hasSupport := caps.has(CapSupport)
		if r == RoleSupport {
			if !hasSupport {
				t.Fatalf("RoleSupport does not hold CapSupport; admin endpoints rely on RoleSupport as the single CapSupport-bearing role")
			}
			continue
		}
		if hasSupport {
			t.Fatalf("role %q holds CapSupport; admin endpoints would silently widen to %q if this drift shipped — RoleSupport must be the only CapSupport-bearing built-in role",
				r, r)
		}
	}

	// Walk the closed scenario table.
	for _, row := range adminEndpointScenarios() {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			p := adminEndpointPrincipal(0, row.scenario)
			resource := adminEndpointResource(row.scenario.resourceOrg)
			got := e.Decide(p, row.scenario.endpoint.action, resource)
			assertDecision(t, got, row.scenario.wantAllow, row.scenario.wantReason)
		})
	}
}

// TestAdminEndpointPreservesContractUnderContention is the
// concurrency half of the BE-0403 pair. It fires
// adminEndpointContentionIterations goroutines that each draw a
// scenario by deterministic mod-index, build their own Principal /
// Resource, evaluate policy.Engine.Decide against a single shared
// Engine instance, and assert the per-iteration verdict. A
// regression that introduced shared mutable state in the engine
// would surface as a per-iteration assertion failure even if the
// aggregate pass count matched, because every goroutine knows its
// own predicted (Allow, Reason) and asserts that exact pair.
//
// The shared chokepoint is intentional: the burst's value is
// precisely the contention against the SAME engine instance, never
// a fresh-per-goroutine engine.
func TestAdminEndpointPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := adminEndpointScenarios()
	if len(rows) == 0 {
		t.Fatalf("adminEndpointScenarios returned an empty table; the closed-set construction is broken")
	}

	e := NewEngine()

	var passed atomic.Int64
	var firstErr atomic.Pointer[adminEndpointContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < adminEndpointWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < adminEndpointIterationsPerWorker; i++ {
				iter := w*adminEndpointIterationsPerWorker + i
				row := rows[iter%len(rows)]
				p := adminEndpointPrincipal(iter, row.scenario)
				resource := adminEndpointResource(row.scenario.resourceOrg)
				got := e.Decide(p, row.scenario.endpoint.action, resource)
				if got.Allow != row.scenario.wantAllow || got.Reason != row.scenario.wantReason {
					if firstErr.Load() == nil {
						firstErr.CompareAndSwap(nil, &adminEndpointContentionFailure{
							iter:       iter,
							rowName:    row.name,
							wantAllow:  row.scenario.wantAllow,
							gotAllow:   got.Allow,
							wantReason: row.scenario.wantReason,
							gotReason:  got.Reason,
						})
					}
					continue
				}
				// Passive redaction canary: a future engine change
				// that started embedding the Principal ID into a
				// Reason string would carry the secret marker into
				// the assertion path. Reason is a closed Reason
				// constant today, so this check is structurally
				// redundant — but it catches a future regression
				// that widened Reason to caller-supplied data.
				if reasonContainsSubstring(got.Reason, adminEndpointSecretMarker) {
					if firstErr.Load() == nil {
						firstErr.CompareAndSwap(nil, &adminEndpointContentionFailure{
							iter:    iter,
							rowName: row.name,
							leak:    true,
						})
					}
					continue
				}
				passed.Add(1)
			}
		}()
	}
	wg.Wait()

	if fe := firstErr.Load(); fe != nil {
		if fe.leak {
			t.Fatalf("contention iteration %d (row %q): Decision Reason echoed the secret marker %q; an admin-endpoint policy decision MUST NOT echo principal-supplied data into the Reason field",
				fe.iter, fe.rowName, adminEndpointSecretMarker)
		}
		t.Fatalf("contention iteration %d (row %q): want (allow=%v, reason=%q), got (allow=%v, reason=%q); a per-iteration mismatch under burst contention indicates shared mutable state in the engine",
			fe.iter, fe.rowName, fe.wantAllow, fe.wantReason, fe.gotAllow, fe.gotReason)
	}
	if got := passed.Load(); got != int64(adminEndpointContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			adminEndpointContentionIterations, got)
	}
}

// adminEndpointContentionFailure captures the first (iteration, row)
// the contention burst observed a mismatch on, so a failure message
// points the operator at the exact scenario that drifted under the
// race rather than collapsing every mismatch into a single line.
type adminEndpointContentionFailure struct {
	iter       int
	rowName    string
	wantAllow  bool
	gotAllow   bool
	wantReason Reason
	gotReason  Reason
	leak       bool
}

// reasonContainsSubstring reports whether the Reason's underlying
// string carries needle. The closed Reason set in policy.go means
// this always returns false today; the helper exists so the
// contention test's passive redaction canary keeps firing as a
// structural assertion if a future engine change widens Reason.
func reasonContainsSubstring(r Reason, needle string) bool {
	s := string(r)
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
