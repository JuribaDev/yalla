package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage pinned specifically to the wire
// endpoint POST /v1/admin/dokploy/reconcile (BE-0288). BE-0285 already
// landed the action-level engine pin for admin.reconcile in
// admin_reconcile_policy_test.go, framed around the GET
// /v1/admin/dokploy/drift listing endpoint and documented as "the
// authorization contract admin.reconcile must satisfy regardless of
// which endpoint surfaces it". This file is the endpoint-pinned twin:
// it re-evaluates the same engine contract through the lens of the
// MUTATING reconcile verb, so a future endpoint regression that wired
// POST /v1/admin/dokploy/reconcile to the wrong action (e.g.
// admin.read so a Viewer could trigger Dokploy mutation across the
// tenant, or a non-Support CapAdmin action so every customer Owner
// could re-synchronise source-of-truth into the upstream provisioner)
// cannot ship without flipping one of these expectations.
//
// The two reconcile-family files are kept structurally parallel but
// state-independent: every canonical id is renamed with the
// "endpoint" suffix (canonicalAdminReconcileEndpointProjectID,
// canonicalAdminReconcileEndpointSiblingID) so a future shared helper
// cannot accidentally couple the drift-listing matrix and the
// reconcile-mutation matrix into the same fixture. The two files use
// different ServiceAccount IDs for the same reason — a future log-
// redaction test that needles for one matrix's principal ids cannot
// silently pass through the other matrix's principals.
//
// The wire endpoint POST /v1/admin/dokploy/reconcile is unscoped under
// /v1/admin and intentionally has no parent organization in the path:
// the resolver constructs a Resource that names either the principal's
// home organization (for in-tenant support workflows) or the
// organization named by a future query / body parameter (for the
// cross-tenant Yalla-support drift triage workflow). Both cases
// reduce at the engine seam to the same admin.reconcile authorization
// question and so the matrix below covers both — same-org against
// orgA, cross-tenant against orgB.
//
// admin.reconcile is catalogued as CapSupport (catalog.go:
// ActionAdminReconcile -> CapSupport), and the role-to-capability
// matrix (catalog.go's builtinRoleCaps) admits CapSupport only for
// RoleSupport. So the per-role matrix is "support allow, the other
// five built-in roles deny via ReasonDeniedNoCapability" — the
// photo-negative of CapRead actions and the load-bearing distinction
// from CapAdmin actions (audit.read, members.manage) where Owner +
// Admin allow but Support denies. Pinning every built-in role here
// keeps a future catalog drift that downgraded admin.reconcile to
// CapAdmin from silently letting every customer Admin and Owner
// trigger Dokploy drift MUTATION across the organization through the
// reconcile endpoint, and keeps an upgrade to CapOwner from silently
// locking Yalla support out of the canonical break-glass mutation
// path.
//
// Crucially, CapSupport IS inside the engine's cross-tenant exception
// clause `roleCaps.has(CapSupport) && (required == CapRead || required
// == CapSupport)`, so a Support principal of org_yalla authorizing
// admin.reconcile against an org_victim resource is ALLOWED with
// ReasonAllowedBySupport — the load-bearing distinction from CapDeploy
// verbs (job.retry, job.cancel) where Support is denied cross-tenant.
// The MUTATING reconcile endpoint is the canonical action under which
// this cross-tenant ALLOW is reached: an engine regression that
// demoted admin.reconcile out of CapSupport would silently lock Yalla
// support out of cross-tenant drift re-synchronisation while leaving
// the LISTING (drift) path nominally intact — pinning the cross-
// tenant ALLOW for the mutating verb is the structural barrier
// against that asymmetric regression.
//
// The grant-containment cases below pin every shape project-, env-,
// and service-scoped grants could otherwise have against an org-
// rooted admin.reconcile resource reached through the reconcile
// endpoint. The reconcile verb is a MUTATING re-sync of source-of-
// truth into the upstream provisioner, so a misrouted reconcile could
// overwrite desired-state across every project in the tenant or
// partially mutate state at Dokploy in the wrong tenant. The pin here
// guards specifically against a future regression where the
// reconcile endpoint's resolver promoted a project- or service-
// scoped grant to reach admin.reconcile (e.g. by misimplementing
// covers() so deep scopes covered shallow ones, or by binding the
// route to a different action constant whose capability matrix is
// laxer) — the engine pin catches both regression classes before
// they can ship.

// canonicalAdminReconcileEndpointProjectID and ...SiblingID are the
// canonical project ids the reconcile-endpoint containment matrix
// evaluates against. The ids are deliberately recognisable so a
// future wire-level leak guard in the reconcile endpoint's contract
// test suite can needle for them, and deliberately distinct from
// canonicalAdminReconcileProjectID / canonicalJobCancelProjectID /
// canonicalJobReadProjectID / canonicalJobReadByIDProjectID /
// canonicalJobRetryProjectID so the drift-listing engine matrix and
// the reconcile-endpoint engine matrix cannot accidentally share
// state through a future shared helper.
const (
	canonicalAdminReconcileEndpointProjectID = "prj_admin_reconcile_endpoint_alpha"
	canonicalAdminReconcileEndpointSiblingID = "prj_admin_reconcile_endpoint_beta"
)

// adminReconcileEndpointOrgResource builds the policy resource the
// POST /v1/admin/dokploy/reconcile resolver would construct for a
// reconcile mutation targeting the organization named by org. The
// Kind is KindOrganization and only OrganizationID is pinned:
// admin.reconcile operates on the source-of-truth view of an entire
// organization, not a deeper subordinate row, so the resource is
// org-rooted by construction at this endpoint as well.
func adminReconcileEndpointOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindOrganization,
		Scope: Scope{OrganizationID: org},
	}
}

// TestAdminReconcileEndpointPolicyMatrixRoles drives every built-in
// role through the engine against the canonical reconcile-endpoint
// resource owned at the principal's own organization. CapSupport
// splits the matrix into a one-row allow (Support — ReasonAllowedByRole)
// and five denies (Owner, Admin, Developer, CI, Viewer —
// ReasonDeniedNoCapability). The case names mirror PRD BE-0288
// ("owner, admin, developer, viewer, ci, support"). The verdict is
// pinned alongside the reason so a catalog or builtinRoleCaps
// regression that downgraded admin.reconcile to CapAdmin would fail
// here — silently letting every customer Admin and Owner trigger
// Dokploy drift mutation through the reconcile endpoint, the precise
// privilege-escalation acceptance criterion BE-0288 forbids — and an
// upgrade to CapOwner would also fail here, silently denying
// RoleSupport which is the only built-in role that holds CapSupport.
func TestAdminReconcileEndpointPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminReconcileEndpointOrgResource(orgA)

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"owner", RoleOwner, false, ReasonDeniedNoCapability},
		{"admin", RoleAdmin, false, ReasonDeniedNoCapability},
		{"developer", RoleDeveloper, false, ReasonDeniedNoCapability},
		{"ci", RoleCI, false, ReasonDeniedNoCapability},
		{"viewer", RoleViewer, false, ReasonDeniedNoCapability},
		{"support", RoleSupport, true, ReasonAllowedByRole},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionAdminReconcile, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestAdminReconcileEndpointPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// surfaced to the engine as a Disabled principal — is denied at the
// reconcile endpoint even when the underlying role is RoleSupport
// (the one role whose working credential WOULD allow
// admin.reconcile). The case names mirror PRD BE-0288 ("revoked key,
// expired key"). The deny reason is ReasonDeniedPrincipalDisabled —
// the engine's first-line check fires before the catalog lookup and
// before the cross-tenant exception clause, so a stale support key
// whose lease has expired cannot be replayed to mutate Dokploy
// drift in any tenant through the reconcile endpoint after the auth
// layer should have refused it.
func TestAdminReconcileEndpointPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminReconcileEndpointOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_admin_reconcile_endpoint_revoked"},
		{"expired key", "sa_admin_reconcile_endpoint_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleSupport)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionAdminReconcile, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestAdminReconcileEndpointPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for admin.reconcile reached through the
// reconcile endpoint. CapSupport IS inside the engine's cross-tenant
// exception clause `roleCaps.has(CapSupport) && (required == CapRead
// || required == CapSupport)`, so a Support principal of org_yalla
// authorizing admin.reconcile against an org_victim resource is
// ALLOWED with ReasonAllowedBySupport — the load-bearing distinction
// from CapDeploy verbs (job.retry, job.cancel) where Support is
// denied cross-tenant. The other five built-in roles (Owner, Admin,
// Developer, CI, Viewer) are denied with ReasonDeniedCrossTenant
// because their capability sets do not contain CapSupport.
//
// This case matters more at the mutating reconcile endpoint than at
// the drift listing endpoint: a misrouted cross-tenant reconcile
// could overwrite desired-state at Dokploy for the wrong tenant, an
// upstream side effect that no in-Yalla rollback can cleanly undo
// without re-rendering and re-applying every affected service. The
// engine pin keeps a future catalog upgrade of admin.reconcile (e.g.
// to CapAdmin) from silently locking Yalla support out of cross-
// tenant drift re-synchronisation while leaving the listing path
// nominally intact, and keeps an engine regression that re-broadened
// the cross-tenant exception to non-Support capabilities from
// silently letting a customer Admin trigger Dokploy mutation against
// a foreign tenant.
//
// At the wire, a cross-tenant reconcile that names a foreign
// organization is additionally audited as a cross-tenant support
// access — the support audit-trail invariant lives in the contract
// test for the reconcile endpoint when it lands and is not in scope
// for this engine-level file.
func TestAdminReconcileEndpointPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := adminReconcileEndpointOrgResource(orgB)

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"owner", RoleOwner, false, ReasonDeniedCrossTenant},
		{"admin", RoleAdmin, false, ReasonDeniedCrossTenant},
		{"developer", RoleDeveloper, false, ReasonDeniedCrossTenant},
		{"ci", RoleCI, false, ReasonDeniedCrossTenant},
		{"viewer", RoleViewer, false, ReasonDeniedCrossTenant},
		{"support", RoleSupport, true, ReasonAllowedBySupport},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionAdminReconcile, foreign)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestAdminReconcileEndpointPolicyProjectGrantContainment proves
// project-level grants cannot widen to admin.reconcile reached
// through the reconcile endpoint. covers() is one-way: a deeper-
// scope grant cannot reach a shallower resource. So a project-scoped
// Support grant — for the target project or for a sibling project —
// cannot authorize admin.reconcile against the org-rooted resource
// (ReasonDeniedOutOfScope). And a project-scoped Admin grant on the
// same project denies ReasonDeniedNoCapability: Admin does not hold
// CapSupport, so the grant cannot supply the action's required
// capability before scope is even considered.
//
// The sibling-project shape is pinned independently of the same-
// project shape so a future endpoint regression that read the
// grant's project_id at the wrong end of covers() (treating the
// grant as authoritative over its own project's siblings) fails
// here. The Admin-on-target case is pinned independently of the
// Support-on-target case so a future catalog drift that downgraded
// admin.reconcile to CapAdmin would fail here through the reconcile
// endpoint as well as through the drift listing endpoint — silently
// letting every project-scoped Admin grantee trigger Dokploy drift
// mutation across the organization through a key that was never
// meant to reach beyond a single project.
func TestAdminReconcileEndpointPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID}
	siblingScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointSiblingID}
	orgResource := adminReconcileEndpointOrgResource(orgA)

	supportTargetGrant := Grant{Role: RoleSupport, Scope: targetScope}
	supportSiblingGrant := Grant{Role: RoleSupport, Scope: siblingScope}
	adminTargetGrant := Grant{Role: RoleAdmin, Scope: targetScope}

	t.Run("support on target project denies org rooted reconcile", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminReconcile, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on sibling project denies org rooted reconcile", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_sibling_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportSiblingGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminReconcile, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("admin on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminReconcile, orgResource), false, ReasonDeniedNoCapability)
	})
}

// TestAdminReconcileEndpointPolicyEnvironmentGrantContainment proves
// environment-level grants do not widen to admin.reconcile through
// the reconcile endpoint. The reconcile resource is org-rooted; an
// env grant — whether for staging or production — names a strictly
// deeper scope, and covers() is one-way.
//
//   - env-staging Support grant denies admin.reconcile on the org
//     root — ReasonDeniedOutOfScope. A staging-scoped key cannot
//     widen to org-level drift mutation through the reconcile
//     endpoint.
//   - env-production Support grant ALSO denies admin.reconcile on
//     the org root — ReasonDeniedOutOfScope. The pin matters because
//     it applies the load-bearing AC "environment-level grants do
//     not imply access to production unless production is explicitly
//     granted" symmetrically: an env-production grant does not
//     silently widen to org-level drift mutation either, even though
//     it explicitly names production. The resource is the
//     organization, not production, and the engine refuses to
//     silently promote an env grant past its own depth even when the
//     env id happens to be the "powerful" one.
//   - As a defence-in-depth pin, a staging-scoped Admin grant
//     authorizing env.write against the production environment of
//     the same project is also denied — staging never widens to
//     production by accident, and the same one-way containment
//     underpins the env-grant deny against admin.reconcile.
//   - env-production Admin grant denies ReasonDeniedNoCapability —
//     Admin never holds CapSupport, so the grant cannot supply the
//     action's required capability regardless of scope. This pins
//     the CapSupport requirement against the env-grant path through
//     the reconcile endpoint so a future catalog drop of
//     admin.reconcile to CapAdmin would fail here as well.
func TestAdminReconcileEndpointPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminReconcileEndpointOrgResource(orgA)

	stagingSupport := Principal{
		ID: "sa_env_staging_support_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: stagingScope}},
	}
	productionSupport := Principal{
		ID: "sa_env_prod_support_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: productionScope}},
	}
	stagingAdminWritingProd := Principal{
		ID: "sa_env_staging_admin_to_prod_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}
	productionAdmin := Principal{
		ID: "sa_env_prod_admin_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: productionScope}},
	}

	t.Run("env staging support denies org rooted reconcile", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(stagingSupport, ActionAdminReconcile, orgResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env production support denies org rooted reconcile", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(productionSupport, ActionAdminReconcile, orgResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("staging grant denies production env write", func(t *testing.T) {
		t.Parallel()
		productionResource := Resource{Kind: domain.KindEnvironment, Scope: productionScope}
		got := e.Decide(stagingAdminWritingProd, ActionEnvWrite, productionResource)
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a staging env grant must not widen to production write", got)
		}
	})

	t.Run("env production admin denies no capability", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(productionAdmin, ActionAdminReconcile, orgResource),
			false, ReasonDeniedNoCapability)
	})
}

// TestAdminReconcileEndpointPolicyServiceGrantContainment proves
// service-level grants do not expose parent-level resources via
// admin.reconcile reached through the reconcile endpoint. A service-
// scoped grant on svc_a:
//
//   - cannot authorize admin.reconcile on the org-rooted resource —
//     that would let a service-scoped key trigger Dokploy drift
//     mutation across every project, environment, and service in
//     the tenant, the exact "service grant exposes parent-level
//     secrets or unrelated services" escalation BE-0288's acceptance
//     criterion forbids. ReasonDeniedOutOfScope.
//   - cannot authorize env.write on the parent environment —
//     pinning the parent-environment exposure boundary independently
//     of admin.reconcile.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service boundary
//     independently of the parent-environment boundary.
//   - even a service-scoped Admin grant denies admin.reconcile with
//     ReasonDeniedNoCapability — Admin does not hold CapSupport.
//     This pins the CapSupport requirement at the service-grant
//     depth through the reconcile endpoint as well.
func TestAdminReconcileEndpointPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminReconcileEndpointProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminReconcileEndpointOrgResource(orgA)

	svcSupport := Principal{
		ID: "sa_svc_support_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: svcAScope}},
	}
	svcAdmin := Principal{
		ID: "sa_svc_admin_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped support denies org rooted reconcile", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcSupport, ActionAdminReconcile, orgResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped admin denies parent env write", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcAdmin, ActionEnvWrite,
			Resource{Kind: domain.KindEnvironment, Scope: parentEnvScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not expose parent env.write", got)
		}
	})

	t.Run("service scoped admin denies sibling service update", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcAdmin, ActionServiceUpdate,
			Resource{Kind: domain.KindService, Scope: svcBScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not reach svc_b", got)
		}
	})

	t.Run("service scoped admin denies org rooted reconcile no capability", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcAdmin, ActionAdminReconcile, orgResource),
			false, ReasonDeniedNoCapability)
	})
}

// TestAdminReconcileEndpointPolicyOrgGrantCapabilityMatrix pins the
// capability split for organization-level grants against
// admin.reconcile reached through the reconcile endpoint. An org-
// level grant covers any resource within the same org by
// construction, so this case isolates the role capability from the
// grant scope: the scope is sufficient at every depth, the role's
// capability set is what decides.
//
//   - Org-level Support grant: scope OK, Support holds CapSupport —
//     allowed (ReasonAllowedByGrant). This is the canonical path by
//     which a Yalla-internal automation principal scoped to a single
//     tenant triggers Dokploy drift re-synchronisation through the
//     reconcile endpoint for that tenant.
//   - Org-level Owner grant: scope OK, Owner holds CapOwner +
//     CapAdmin but NOT CapSupport — denied
//     (ReasonDeniedNoCapability). Owner has the most capabilities of
//     any built-in role, and a future catalog drop of
//     admin.reconcile to CapAdmin or CapOwner would silently allow
//     every Owner grantee to trigger Dokploy drift mutation through
//     the reconcile endpoint. The engine pin catches that regression
//     before it can ship.
//   - Org-level Admin / Developer / Viewer / CI grants: scope OK,
//     the role does not hold CapSupport — denied
//     (ReasonDeniedNoCapability). Pinning every non-Support built-in
//     role against the org-grant path closes off every capability-
//     class catalog drift that would widen admin.reconcile beyond
//     Yalla support at the reconcile endpoint.
func TestAdminReconcileEndpointPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminReconcileEndpointOrgResource(orgA)
	orgScope := Scope{OrganizationID: orgA}

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"support", RoleSupport, true, ReasonAllowedByGrant},
		{"owner", RoleOwner, false, ReasonDeniedNoCapability},
		{"admin", RoleAdmin, false, ReasonDeniedNoCapability},
		{"developer", RoleDeveloper, false, ReasonDeniedNoCapability},
		{"ci", RoleCI, false, ReasonDeniedNoCapability},
		{"viewer", RoleViewer, false, ReasonDeniedNoCapability},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Principal{
				ID: "sa_org_reconcile_endpoint_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionAdminReconcile, resource), tc.allow, tc.reason)
		})
	}
}

// TestAdminReconcileEndpointPolicyForeignHomeOrgGrant pins the
// cross-tenant guard on the grant path at the reconcile endpoint. An
// organization-scoped Support grant for orgA, carried by a
// ServiceAccount principal whose home org is orgB, cannot be used to
// authorize admin.reconcile against a resource in orgB. The
// principal's home org equals the resource org (both orgB), so the
// cross-tenant clause does NOT fire (it requires resource org !=
// principal home org). The engine then evaluates the principal's
// organization role (empty for this grant-only ServiceAccount, which
// the engine treats as "no role capabilities" without erroring) and
// grants. The grant's Scope.OrganizationID is orgA, the principal's
// home org is orgB, so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role
// caps, the verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property at the reconcile endpoint: a scoped grant minted for
// orgA cannot be carried by a principal whose home tenant is orgB
// to mutate the home tenant's state. CapSupport's cross-tenant
// exception is gated on the PRINCIPAL'S role caps, not on a grant's
// role caps; pinning that distinction at the reconcile endpoint
// prevents a future regression where a foreign-org Support GRANT
// silently smuggled the support capability across tenants and let an
// exfiltrated key trigger Dokploy drift mutation in the wrong
// organization.
func TestAdminReconcileEndpointPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminReconcileEndpointOrgResource(orgB)
	foreignGrant := Grant{
		Role:  RoleSupport,
		Scope: Scope{OrganizationID: orgA},
	}
	p := Principal{
		ID: "sa_stolen_reconcile_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionAdminReconcile, resource), false, ReasonDeniedNoCapability)
}
