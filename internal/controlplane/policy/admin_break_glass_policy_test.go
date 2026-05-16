package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action admin.break_glass
// (BE-0297). The wire endpoint POST /v1/admin/break-glass and its
// contract tests have not landed yet; this file pins the
// authorization contract admin.break_glass must satisfy regardless
// of which endpoint surfaces it, mirroring the engine-only
// precedent BE-0273 established for the GET /v1/jobs list variant,
// BE-0276 for the GET /v1/jobs/{job_id} bare-id fetch variant,
// BE-0279 for the POST /v1/jobs/{job_id}/retry destructive re-issue
// verb, BE-0282 for the POST /v1/jobs/{job_id}/cancel abort verb,
// BE-0285 for the GET /v1/admin/dokploy/drift listing endpoint,
// BE-0288 for the POST /v1/admin/dokploy/reconcile mutating verb,
// BE-0291 for the POST /v1/admin/dokploy/import onboarding verb,
// and BE-0294 for the GET
// /v1/admin/organizations/{org_id}/dokploy-refs admin-listing verb.
// The same engine-only pin precedent that holds for previews, the
// job lifecycle variants, and the drift / reconcile / import /
// dokploy-refs siblings holds here.
//
// admin.break_glass is catalogued as CapSupport (catalog.go:
// ActionAdminBreakGlass -> CapSupport), grouped with the other
// internal break-glass / support tooling actions admin.read,
// admin.import, and admin.reconcile. The role-to-capability matrix
// (catalog.go's builtinRoleCaps) admits CapSupport only for
// RoleSupport: Owner, Admin, Developer, CI, and Viewer all lack
// it. So the role matrix for a principal acting on its own
// organization is "support allow, the other five built-in roles
// deny via ReasonDeniedNoCapability" — a one-row allow, the
// photo-negative of CapRead actions where five of six allow, and
// the load-bearing distinction from CapAdmin actions (audit.read,
// members.manage) where Owner+Admin allow but Support denies. The
// pin keeps a future catalog drift that demoted admin.break_glass
// to CapRead or CapAdmin from silently letting every customer
// Owner / Admin / Viewer mint a break-glass session against their
// own tenant (an escalation that would let a compromised customer
// principal acquire elevated cross-tenant inspection / mutation
// capability without Yalla support involvement), and keeps an
// upgrade to CapOwner from silently locking even RoleSupport out
// of the canonical session-creation flow.
//
// Crucially, CapSupport IS inside the engine's cross-tenant
// exception clause `roleCaps.has(CapSupport) && (required ==
// CapRead || required == CapSupport)`, so a Support principal of
// org_yalla authorizing admin.break_glass against an org_victim
// resource is ALLOWED with ReasonAllowedBySupport — the load-
// bearing distinction from CapDeploy verbs (job.retry, job.cancel)
// where Support is denied cross-tenant. admin.break_glass is
// exactly the action Yalla support uses to mint a time-bounded
// elevated session into a tenant's environment during incident
// response, customer-initiated escalation, and onboarding handoffs,
// so the cross-tenant ALLOW is intentional: an engine regression
// that demoted admin.break_glass out of CapSupport (e.g. to
// CapAdmin) would silently lock Yalla support out of every
// incident-response workflow that depends on time-bounded
// cross-tenant access, and an upgrade to CapOwner would block
// even the canonical RoleSupport session-creation flow at the
// principal's own tenant. The engine pin here is the structural
// barrier against both regressions.
//
// The route the wire endpoint will register pins the organization
// the session targets in the request body (POST
// /v1/admin/break-glass takes the target organization, optional
// project / environment / service scope, justification, and TTL
// in the body). At authorization time the resolver constructs a
// Resource that names the target organization — typically a
// foreign org named in the body for cross-tenant Yalla support
// session creation, or the principal's home organization for an
// internal escalation. The grant-containment cases below pin
// every shape project-, env-, and service-scoped grants would
// otherwise have against an org-rooted admin.break_glass resource:
// a future endpoint regression that promoted a project- or
// service-scoped grant to reach admin.break_glass (e.g. by
// misimplementing covers() so deep scopes covered shallow ones)
// would silently let a tenant's project-scoped or service-scoped
// automation key mint a break-glass session that elevates the
// caller beyond the single project or service the grant was
// originally minted for. For a session-creation verb that
// produces a time-bounded elevated principal, this containment
// matrix is especially load-bearing: a misrouted session
// creation widens the caller's effective horizon to projects,
// environments, and services they had no grant for, and persists
// that widening for the lifetime of the issued session.

// canonicalAdminBreakGlassProjectID and
// canonicalAdminBreakGlassSiblingID are the canonical project ids
// the admin-break-glass containment matrix evaluates against. The
// ids are deliberately recognisable so a future leak guard in a
// wire-level test for the endpoint can needle for them, and
// deliberately distinct from canonicalAdminReadProjectID /
// canonicalAdminReadSiblingID / canonicalAdminImportProjectID /
// canonicalAdminImportSiblingID / canonicalAdminReconcileProjectID /
// canonicalAdminReconcileSiblingID /
// canonicalAdminReconcileEndpointProjectID /
// canonicalAdminReconcileEndpointSiblingID / canonicalJobCancelProjectID /
// canonicalJobReadProjectID / canonicalJobReadByIDProjectID /
// canonicalJobRetryProjectID (used by the sibling admin and job
// engine files) so the admin-action matrices cannot accidentally
// share state through a future shared helper.
const (
	canonicalAdminBreakGlassProjectID = "prj_admin_break_glass_matrix_alpha"
	canonicalAdminBreakGlassSiblingID = "prj_admin_break_glass_matrix_beta"
)

// adminBreakGlassOrgResource builds the policy resource the
// POST /v1/admin/break-glass resolver would construct for a
// session-creation request targeting the organization named by org.
// The Kind is KindOrganization and only OrganizationID is pinned:
// admin.break_glass operates on the org-rooted intent of issuing a
// time-bounded elevated principal against the entire organization
// (or, in a future variant, a deeper scope named separately in the
// request body); the engine's authorization decision is rooted at
// the organization the session is requested for.
func adminBreakGlassOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindOrganization,
		Scope: Scope{OrganizationID: org},
	}
}

// TestAdminBreakGlassPolicyMatrixRoles drives every built-in role
// through the engine against the canonical break-glass resource
// owned at the principal's own organization. CapSupport splits the
// matrix into a one-row allow: RoleSupport holds CapSupport and is
// allowed (ReasonAllowedByRole); Owner, Admin, Developer, CI, and
// Viewer do NOT hold CapSupport and are denied
// (ReasonDeniedNoCapability). The case names mirror PRD BE-0297
// ("owner, admin, developer, viewer, ci, support"). The verdict
// is pinned alongside the reason so a catalog or builtinRoleCaps
// regression that downgraded admin.break_glass to CapRead would
// fail here (silently letting every customer Viewer mint an
// elevated session into their own tenant — the precise escalation
// BE-0297 forbids) and an upgrade to CapOwner would also fail here
// (silently denying RoleSupport, the only built-in role that holds
// CapSupport).
func TestAdminBreakGlassPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassOrgResource(orgA)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionAdminBreakGlass, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestAdminBreakGlassPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action admin.break_glass, even when the
// underlying role would have allowed it. The underlying role is
// RoleSupport so a working credential WOULD allow admin.break_glass;
// Disabled is the only thing in the way and must be load-bearing.
// The case names mirror PRD BE-0297 ("revoked key, expired key").
// The deny reason is ReasonDeniedPrincipalDisabled — the engine's
// first-line check fires before the catalog lookup, so an action
// that is not even catalogued would still surface this exact
// reason for a disabled principal. The auth layer's reject-before-
// policy posture for revoked keys (the API layer 401s before
// policy ever runs) remains the load-bearing first guard at the
// wire; this engine pin is the defence-in-depth.
//
// For admin.break_glass this defence-in-depth is especially load-
// bearing: a stale Yalla-support key whose lease has expired (or
// has been rotated after an incident) must never be able to mint a
// new elevated session that would extend the attacker's window
// well past the moment the credential was revoked. CapSupport is
// exactly the capability the cross-tenant exception widens for,
// and a disabled principal must short-circuit BEFORE that
// exception fires — otherwise a revoked support key could be
// replayed to bootstrap a fresh break-glass session against every
// tenant after the auth layer should have refused it, escalating a
// momentary credential leak into a durable cross-tenant foothold.
func TestAdminBreakGlassPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_admin_break_glass_revoked"},
		{"expired key", "sa_admin_break_glass_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleSupport)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionAdminBreakGlass, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestAdminBreakGlassPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for admin.break_glass. CapSupport IS inside
// the engine's cross-tenant exception clause
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`, so admin.break_glass (catalogued as CapSupport) is
// one of the canonical actions under which a Support principal of
// org_yalla authorizing against an org_victim resource is ALLOWED
// with ReasonAllowedBySupport. Every other built-in role — Owner,
// Admin, Developer, CI, Viewer — is denied with
// ReasonDeniedCrossTenant because their capability sets do not
// contain CapSupport.
//
// This is the load-bearing distinction from the cross-tenant
// matrix for CapDeploy verbs (job.retry, job.cancel): on those
// verbs Support is denied cross-tenant because the exception
// clause excludes CapDeploy. admin.break_glass flips that single
// row from deny to allow at the cross-tenant boundary — the
// entire point of admin.break_glass is privileged cross-tenant
// session creation by Yalla support during incident response and
// onboarding handoffs, so the engine-level pin is what keeps a
// future catalog upgrade of admin.break_glass (e.g. to CapAdmin)
// from silently locking support out of every tenant during the
// exact window when cross-tenant access is most urgent, and what
// keeps a future endpoint that wired admin.break_glass to a
// different scope from silently re-broadening the cross-tenant
// boundary to non-support principals.
//
// At the wire, a cross-tenant break-glass request that names a
// foreign organization will additionally be authenticated against
// the principal's home credential and audited as a cross-tenant
// support session — the support audit-trail invariant lives in
// the contract test for the wire endpoint and is not in scope for
// this engine-level file.
func TestAdminBreakGlassPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := adminBreakGlassOrgResource(orgB)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionAdminBreakGlass, foreign)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestAdminBreakGlassPolicyProjectGrantContainment proves project-
// level grants cannot widen to admin.break_glass, which targets
// the organization root (Resource{Kind=KindOrganization,
// Scope={org}}). covers() is one-way: a deeper-scope grant cannot
// reach a shallower resource. So:
//
//   - A project-scoped Support grant for THIS project CANNOT
//     authorize admin.break_glass against the org-rooted resource.
//     The grant's scope pins a project; the resource's scope does
//     not. covers() denies. ReasonDeniedOutOfScope. This is the
//     load-bearing AC "project-level grants do not imply access to
//     sibling projects" applied to admin.break_glass: the deep
//     grant cannot widen to the shallow resource at all — whether
//     the grant's project_id matches the resource's project or not
//     is irrelevant because the resource has no project leg.
//   - A project-scoped Support grant naming a SIBLING project also
//     denies admin.break_glass against the org root for the same
//     one-way containment reason — pinning the sibling-project
//     shape independently of the same-project shape so a future
//     endpoint regression that read the grant's project_id at the
//     wrong end of covers() (treating the grant as authoritative
//     over its own project's siblings) fails here.
//   - A project-scoped Admin grant — even on the same project — is
//     denied ReasonDeniedNoCapability: Admin does NOT hold
//     CapSupport, so the grant cannot supply the action's required
//     capability before scope is even considered. This pins the
//     CapSupport requirement against the project-grant path so a
//     future catalog drift that downgraded admin.break_glass to
//     CapRead would fail here (silently letting every project-
//     scoped grantee with at least CapRead mint an elevated
//     session that escapes the very project the grant was minted
//     for).
func TestAdminBreakGlassPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID}
	siblingScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassSiblingID}
	orgResource := adminBreakGlassOrgResource(orgA)

	supportTargetGrant := Grant{Role: RoleSupport, Scope: targetScope}
	supportSiblingGrant := Grant{Role: RoleSupport, Scope: siblingScope}
	adminTargetGrant := Grant{Role: RoleAdmin, Scope: targetScope}

	t.Run("support on target project denies org rooted break glass", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on sibling project denies org rooted break glass", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_sibling_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportSiblingGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("admin on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedNoCapability)
	})
}

// TestAdminBreakGlassPolicyEnvironmentGrantContainment proves
// environment-level grants do not widen to admin.break_glass. The
// break-glass resource is org-rooted; an env grant — whether for
// staging or production — names a strictly deeper scope, and
// covers() is one-way.
//
//   - env-staging Support grant denies admin.break_glass on the
//     org root — ReasonDeniedOutOfScope. A staging-scoped key
//     cannot widen to org-level session creation.
//   - env-production Support grant ALSO denies admin.break_glass
//     on the org root — ReasonDeniedOutOfScope. The pin matters
//     because it applies the load-bearing AC "environment-level
//     grants do not imply access to production unless production
//     is explicitly granted" symmetrically: an env-production
//     grant does not silently widen to org-level session
//     creation either, even though it explicitly names production.
//     The resource here is the organization, not production, and
//     the engine refuses to silently promote an env grant past
//     its own depth even when the env id happens to be the
//     "powerful" one.
//   - As a defence-in-depth pin, a staging-scoped Admin grant
//     authorizing env.write against the production environment of
//     the same project is also denied — staging never widens to
//     production by accident, and the same one-way containment
//     underpins the env-grant deny against admin.break_glass.
//   - env-production Admin grant denies ReasonDeniedNoCapability —
//     Admin never holds CapSupport, so the grant cannot supply the
//     action's required capability regardless of scope. This pins
//     the CapSupport requirement against the env-grant path so a
//     future catalog drop of admin.break_glass to CapRead would
//     fail here (silently letting every env-scoped reader mint an
//     elevated session that escapes the very environment the
//     grant was minted for).
func TestAdminBreakGlassPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminBreakGlassOrgResource(orgA)

	stagingSupport := Principal{
		ID: "sa_env_staging_support_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: stagingScope}},
	}
	productionSupport := Principal{
		ID: "sa_env_prod_support_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: productionScope}},
	}
	stagingAdminWritingProd := Principal{
		ID: "sa_env_staging_admin_to_prod_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}
	productionAdmin := Principal{
		ID: "sa_env_prod_admin_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: productionScope}},
	}

	t.Run("env staging support denies org rooted break glass", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(stagingSupport, ActionAdminBreakGlass, orgResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env production support denies org rooted break glass", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(productionSupport, ActionAdminBreakGlass, orgResource),
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
			e.Decide(productionAdmin, ActionAdminBreakGlass, orgResource),
			false, ReasonDeniedNoCapability)
	})
}

// TestAdminBreakGlassPolicyServiceGrantContainment proves service-
// level grants do not expose parent-level resources via
// admin.break_glass. A service-scoped grant on svc_a:
//
//   - cannot authorize admin.break_glass on the org-rooted
//     resource — that would let a service-scoped key mint an
//     elevated session whose effective horizon spans every
//     project, environment, and service in the tenant, the exact
//     "service grant exposes parent-level secrets or unrelated
//     services" escalation the acceptance criterion forbids.
//     ReasonDeniedOutOfScope.
//   - cannot authorize env.write on the parent environment —
//     pinning the parent-environment exposure boundary
//     independently of admin.break_glass, so a future endpoint
//     that authorized parent env.write through a service grant
//     would fail here before it could regress a real customer.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service
//     boundary independently of the parent-environment boundary,
//     so the containment matrix proves both directions, not just
//     one.
//   - even a service-scoped Admin grant denies admin.break_glass
//     with ReasonDeniedNoCapability — Admin does not hold
//     CapSupport. This pins the CapSupport requirement at the
//     service-grant depth as well, closing off any capability-
//     class catalog drift that would let a deeper grant supply
//     CapSupport via a non-Support role.
func TestAdminBreakGlassPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminBreakGlassOrgResource(orgA)

	svcSupport := Principal{
		ID: "sa_svc_support_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: svcAScope}},
	}
	svcAdmin := Principal{
		ID: "sa_svc_admin_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped support denies org rooted break glass", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcSupport, ActionAdminBreakGlass, orgResource),
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

	t.Run("service scoped admin denies org rooted break glass no capability", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcAdmin, ActionAdminBreakGlass, orgResource),
			false, ReasonDeniedNoCapability)
	})
}

// TestAdminBreakGlassPolicyOrgGrantCapabilityMatrix pins the
// capability split for organization-level grants against
// admin.break_glass. An organization-level grant covers any
// resource within the same org by construction (covers() with an
// empty ProjectID matches any project; equally so for the empty
// environment and service fields), so this case isolates the role
// capability from the grant scope: the scope is sufficient at
// every depth, the role's capability set is what decides.
//
//   - Org-level Support grant: scope OK, Support holds CapSupport —
//     allowed (ReasonAllowedByGrant). This is the only role-grant
//     combination at any scope that can authorize admin.break_glass
//     from a grant, and it is the canonical path by which a Yalla-
//     internal automation principal scoped to a single tenant
//     mints an elevated session for that tenant during a support
//     workflow.
//   - Org-level Owner grant: scope OK, Owner holds CapOwner+CapAdmin
//     but NOT CapSupport — denied (ReasonDeniedNoCapability).
//     Pinning Owner here is load-bearing: Owner has the most
//     capabilities of any built-in role, and a future catalog drop
//     of admin.break_glass to CapAdmin or CapOwner would silently
//     allow every Owner grantee to mint an elevated session into
//     the tenant. The engine pin catches that regression before it
//     can ship.
//   - Org-level Admin / Developer / Viewer / CI grants: scope OK,
//     the role does not hold CapSupport — denied
//     (ReasonDeniedNoCapability). Pinning every non-Support
//     built-in role against the org-grant path closes off every
//     capability-class catalog drift that would widen
//     admin.break_glass beyond Yalla support.
func TestAdminBreakGlassPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassOrgResource(orgA)
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
				ID: "sa_org_break_glass_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionAdminBreakGlass, resource), tc.allow, tc.reason)
		})
	}
}

// TestAdminBreakGlassPolicyForeignHomeOrgGrant pins the cross-
// tenant guard on the grant path. An organization-scoped Support
// grant for orgA, carried by a ServiceAccount principal whose home
// org is orgB, cannot be used to authorize admin.break_glass
// against a resource in orgB. The principal's home org equals the
// resource org (both orgB), so the cross-tenant clause does NOT
// fire (it requires resource org != principal home org). The
// engine then evaluates the principal's organization role (empty
// for this grant-only ServiceAccount, which the engine treats as
// "no role capabilities" without erroring) and grants. The grant's
// Scope.OrganizationID is orgA, the principal's home org is orgB,
// so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role
// caps, the verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property: a scoped grant minted for orgA cannot be carried
// by a principal whose home tenant is orgB to act on the home
// tenant's state — and admin.break_glass, which mints elevated
// sessions and which the engine deliberately widens via CapSupport
// cross-tenant, is the strongest case for this guard. CapSupport's
// cross-tenant exception is gated on the PRINCIPAL'S role caps,
// not on a grant's role caps; pinning that distinction here
// prevents a future regression where a foreign-org Support GRANT
// silently smuggled the support capability across tenants and let
// an exfiltrated key mint an elevated session into the wrong
// organization.
func TestAdminBreakGlassPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassOrgResource(orgB)
	foreignGrant := Grant{
		Role:  RoleSupport,
		Scope: Scope{OrganizationID: orgA},
	}
	p := Principal{
		ID: "sa_stolen_break_glass", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionAdminBreakGlass, resource), false, ReasonDeniedNoCapability)
}
