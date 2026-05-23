package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage pinned specifically to the wire
// endpoint DELETE /v1/admin/break-glass/{session_id} (BE-0300).
// BE-0297 already landed the action-level engine pin for
// admin.break_glass in admin_break_glass_policy_test.go, framed
// around the POST /v1/admin/break-glass session-creation endpoint
// and documented as "the authorization contract admin.break_glass
// must satisfy regardless of which endpoint surfaces it". This file
// is the endpoint-pinned twin: it re-evaluates the same engine
// contract through the lens of the MUTATING session-terminate verb,
// so a future endpoint regression that wired DELETE
// /v1/admin/break-glass/{session_id} to the wrong action (e.g.
// admin.read so a Viewer could end an active break-glass session
// out from under Yalla support during an incident, or a non-Support
// CapAdmin action so every customer Owner could revoke an active
// support session into their own tenant during onboarding or
// incident response) cannot ship without flipping one of these
// expectations.
//
// The two break-glass-family engine files are kept structurally
// parallel but state-independent: every canonical id is renamed with
// the "endpoint" suffix (canonicalAdminBreakGlassEndpointProjectID,
// canonicalAdminBreakGlassEndpointSiblingID) so a future shared
// helper cannot accidentally couple the session-creation matrix
// (BE-0297) and the session-terminate matrix (BE-0300) into the
// same fixture, mirroring the BE-0288 endpoint-pinned twin precedent
// for admin.reconcile. The two files use different ServiceAccount
// IDs (suffix "_break_glass_endpoint" deliberately distinct from
// "_break_glass") for the same reason — a future log-redaction test
// that needles for one matrix's principal ids cannot silently pass
// through the other matrix's principals.
//
// The wire endpoint DELETE /v1/admin/break-glass/{session_id} is
// unscoped under /v1/admin and the path carries only an opaque
// session id — no organization id, no project / environment /
// service leg. The resolver loads the session row, materialises the
// organization it was minted for, and constructs a Resource that
// names that organization. The resource may name either the
// principal's home organization (for ending an in-tenant Yalla-
// support session — e.g. completing an onboarding handoff or
// closing the incident-response window) or a foreign organization
// (for a cross-tenant Yalla-support session terminate). Both cases
// reduce at the engine seam to the same admin.break_glass
// authorization question and so the matrix below covers both —
// same-org against orgA, cross-tenant against orgB.
//
// admin.break_glass is catalogued as CapSupport (catalog.go:
// ActionAdminBreakGlass -> CapSupport), grouped with the other
// internal break-glass / support tooling actions admin.read,
// admin.import, and admin.reconcile. The role-to-capability matrix
// (catalog.go's builtinRoleCaps) admits CapSupport only for
// RoleSupport: Owner, Admin, Developer, CI, and Viewer all lack it.
// So the per-role matrix is "support allow, the other five built-in
// roles deny via ReasonDeniedNoCapability" — a one-row allow, the
// photo-negative of CapRead actions where five of six allow, and
// the load-bearing distinction from CapAdmin actions (audit.read,
// members.manage) where Owner+Admin allow but Support denies. The
// pin keeps a future catalog drift that demoted admin.break_glass
// to CapRead or CapAdmin from silently letting every customer
// Owner / Admin / Viewer terminate an active break-glass session in
// their own tenant (a denial-of-service escalation against Yalla
// support's incident-response window, where a compromised customer
// principal could close the support session and lock the
// responder out the moment they tried to mitigate), and keeps an
// upgrade to CapOwner from silently locking RoleSupport out of
// completing the canonical session lifecycle.
//
// Crucially, CapSupport IS inside the engine's cross-tenant
// exception clause `roleCaps.has(CapSupport) && (required == CapRead
// || required == CapSupport)`, so a Support principal of org_yalla
// authorizing admin.break_glass against an org_victim resource is
// ALLOWED with ReasonAllowedBySupport — the load-bearing distinction
// from CapDeploy verbs (job.retry, job.cancel) where Support is
// denied cross-tenant. The MUTATING session-terminate verb is the
// canonical action under which this cross-tenant ALLOW is reached:
// a Yalla-support responder must be able to end a session into a
// foreign tenant the moment the incident or onboarding handoff
// completes (or the moment the session is revoked for any reason),
// and an engine regression that demoted admin.break_glass out of
// CapSupport would silently lock Yalla support out of the
// session-revocation path while leaving the session-creation path
// nominally intact — an asymmetric regression that would let a
// support session outlive its operational mandate. Pinning the
// cross-tenant ALLOW for the MUTATING terminate verb specifically
// is the structural barrier against that regression.
//
// The grant-containment cases below pin every shape project-, env-,
// and service-scoped grants could otherwise have against an org-
// rooted admin.break_glass resource reached through the terminate
// endpoint. For a session-terminate verb that revokes an already-
// elevated principal mid-flight, this containment matrix is
// especially load-bearing: a misrouted terminate decision driven by
// a deep-scope grant would let a project-scoped or service-scoped
// automation key end the support session even though the grant was
// minted to act on a single project or service, prematurely cutting
// off Yalla support's window into the tenant during an incident.
// The engine pin here is the structural barrier against that
// regression.

// canonicalAdminBreakGlassEndpointProjectID and ...SiblingID are the
// canonical project ids the break-glass-endpoint containment matrix
// evaluates against. The ids are deliberately recognisable so a
// future wire-level leak guard in the terminate endpoint's contract
// test suite can needle for them, and deliberately distinct from
// canonicalAdminBreakGlassProjectID / canonicalAdminBreakGlassSiblingID
// (used by the session-creation engine file BE-0297) and from
// canonicalAdminReconcileProjectID / canonicalAdminReconcileEndpointProjectID
// / canonicalAdminReadProjectID / canonicalAdminImportProjectID /
// canonicalJobCancelProjectID / canonicalJobReadProjectID /
// canonicalJobReadByIDProjectID / canonicalJobRetryProjectID (used by
// the sibling admin and job engine files) so the session-creation
// matrix and the session-terminate matrix cannot accidentally share
// state through a future shared helper.
const (
	canonicalAdminBreakGlassEndpointProjectID = "prj_admin_break_glass_endpoint_alpha"
	canonicalAdminBreakGlassEndpointSiblingID = "prj_admin_break_glass_endpoint_beta"
)

// adminBreakGlassEndpointOrgResource builds the policy resource the
// DELETE /v1/admin/break-glass/{session_id} resolver would construct
// for a session-terminate request whose loaded session row is owned
// by the organization named by org. The Kind is KindOrganization and
// only OrganizationID is pinned: admin.break_glass operates on the
// org-rooted intent of terminating a time-bounded elevated principal
// against the entire organization the session was originally minted
// for; the engine's authorization decision is rooted at the
// organization the session lives in, not at any deeper scope the
// session may have been narrowed to in the originating create
// request.
func adminBreakGlassEndpointOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindOrganization,
		Scope: Scope{OrganizationID: org},
	}
}

// TestAdminBreakGlassEndpointPolicyMatrixRoles drives every built-in
// role through the engine against the canonical break-glass-endpoint
// resource owned at the principal's own organization. CapSupport
// splits the matrix into a one-row allow: RoleSupport holds
// CapSupport and is allowed (ReasonAllowedByRole); Owner, Admin,
// Developer, CI, and Viewer do NOT hold CapSupport and are denied
// (ReasonDeniedNoCapability). The case names mirror PRD BE-0300
// ("owner, admin, developer, viewer, ci, support"). The verdict is
// pinned alongside the reason so a catalog or builtinRoleCaps
// regression that downgraded admin.break_glass to CapRead would
// fail here (silently letting every customer Viewer end an active
// Yalla-support session into their own tenant — a denial-of-service
// against the support window during the precise moment Yalla
// support is mid-incident — the exact escalation BE-0300 forbids)
// and an upgrade to CapOwner would also fail here (silently
// denying RoleSupport, the only built-in role that holds CapSupport
// and the only role expected to drive the session-revocation flow).
// Pinning this matrix at the endpoint level specifically (and not
// just relying on the action-level pin from BE-0297) guards against
// an asymmetric regression that left the session-creation matrix
// intact while flipping a single capability check for the terminate
// verb — the most plausible regression shape for a future
// "fine-grained admin actions" catalog change.
func TestAdminBreakGlassEndpointPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassEndpointOrgResource(orgA)

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

// TestAdminBreakGlassEndpointPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action admin.break_glass at the
// terminate endpoint, even when the underlying role would have
// allowed it. The underlying role is RoleSupport so a working
// credential WOULD allow admin.break_glass; Disabled is the only
// thing in the way and must be load-bearing. The case names mirror
// PRD BE-0300 ("revoked key, expired key"). The deny reason is
// ReasonDeniedPrincipalDisabled — the engine's first-line check
// fires before the catalog lookup, so an action that is not even
// catalogued would still surface this exact reason for a disabled
// principal. The auth layer's reject-before-policy posture for
// revoked keys (the API layer 401s before policy ever runs) remains
// the load-bearing first guard at the wire; this engine pin is the
// defence-in-depth.
//
// For the session-terminate verb specifically, this defence-in-
// depth is especially load-bearing: a stale Yalla-support key whose
// lease has expired (or has been rotated mid-incident) must never
// be able to drive a fresh terminate request against an active
// session — that would let an attacker who exfiltrated a since-
// revoked support key prematurely close the legitimate responder's
// window into the tenant, extending the attacker's effective
// foothold by removing the only operator equipped to evict them.
// CapSupport is exactly the capability the cross-tenant exception
// widens for, and a disabled principal must short-circuit BEFORE
// that exception fires — otherwise a revoked support key could be
// replayed to terminate active break-glass sessions across every
// tenant after the auth layer should have refused it, converting a
// momentary credential leak into a durable denial-of-service
// against Yalla support's incident-response capability.
func TestAdminBreakGlassEndpointPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassEndpointOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_admin_break_glass_endpoint_revoked"},
		{"expired key", "sa_admin_break_glass_endpoint_expired"},
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

// TestAdminBreakGlassEndpointPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for admin.break_glass reached through
// the DELETE session terminate endpoint. CapSupport IS inside the
// engine's cross-tenant exception clause `roleCaps.has(CapSupport)
// && (required == CapRead || required == CapSupport)`, so
// admin.break_glass (catalogued as CapSupport) is one of the
// canonical actions under which a Support principal of org_yalla
// authorizing against an org_victim resource is ALLOWED with
// ReasonAllowedBySupport. Every other built-in role — Owner, Admin,
// Developer, CI, Viewer — is denied with ReasonDeniedCrossTenant
// because their capability sets do not contain CapSupport.
//
// This is the load-bearing distinction from the cross-tenant matrix
// for CapDeploy verbs (job.retry, job.cancel): on those verbs
// Support is denied cross-tenant because the exception clause
// excludes CapDeploy. admin.break_glass flips that single row from
// deny to allow at the cross-tenant boundary — the entire point of
// the break-glass terminate verb is privileged cross-tenant session
// revocation by Yalla support at the close of an incident-response
// window, so the engine-level pin is what keeps a future catalog
// upgrade of admin.break_glass (e.g. to CapAdmin) from silently
// locking support out of every tenant during the exact window when
// cross-tenant session cleanup is most urgent, and what keeps a
// future endpoint that wired DELETE /v1/admin/break-glass/{session_id}
// to a different action constant from silently re-broadening the
// cross-tenant boundary to non-support principals. Pinning the
// cross-tenant ALLOW at the terminate verb specifically (in
// addition to BE-0297's pin at the create verb) guards against an
// asymmetric regression that left create intact while flipping
// terminate to deny — exactly the regression shape that would let a
// support session outlive its operational mandate because the only
// role that could end it had been silently locked out of the
// terminate endpoint at the cross-tenant boundary.
//
// At the wire, a cross-tenant terminate request that resolves to a
// foreign organization will additionally be authenticated against
// the principal's home credential and audited as a cross-tenant
// support session terminate — the support audit-trail invariant
// lives in the contract test for the wire endpoint and is not in
// scope for this engine-level file.
func TestAdminBreakGlassEndpointPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := adminBreakGlassEndpointOrgResource(orgB)

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

// TestAdminBreakGlassEndpointPolicyProjectGrantContainment proves
// project-level grants cannot widen to admin.break_glass on the
// terminate endpoint, which targets the organization root
// (Resource{Kind=KindOrganization, Scope={org}}). covers() is one-
// way: a deeper-scope grant cannot reach a shallower resource. So:
//
//   - A project-scoped Support grant for THIS project CANNOT
//     authorize admin.break_glass against the org-rooted resource.
//     The grant's scope pins a project; the resource's scope does
//     not. covers() denies. ReasonDeniedOutOfScope. This is the
//     load-bearing AC "project-level grants do not imply access to
//     sibling projects" applied to the break-glass terminate verb:
//     the deep grant cannot widen to the shallow resource at all —
//     whether the grant's project_id matches the resource's project
//     or not is irrelevant because the resource has no project leg.
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
//     scoped grantee with at least CapRead terminate the support
//     session that spans the very project the grant was minted
//     for — the precise denial-of-service-against-incident-response
//     shape BE-0300 forbids).
func TestAdminBreakGlassEndpointPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID}
	siblingScope := Scope{OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointSiblingID}
	orgResource := adminBreakGlassEndpointOrgResource(orgA)

	supportTargetGrant := Grant{Role: RoleSupport, Scope: targetScope}
	supportSiblingGrant := Grant{Role: RoleSupport, Scope: siblingScope}
	adminTargetGrant := Grant{Role: RoleAdmin, Scope: targetScope}

	t.Run("support on target project denies org rooted break glass terminate", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on sibling project denies org rooted break glass terminate", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_sibling_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportSiblingGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("admin on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminTargetGrant},
		}
		assertDecision(t, e.Decide(p, ActionAdminBreakGlass, orgResource), false, ReasonDeniedNoCapability)
	})
}

// TestAdminBreakGlassEndpointPolicyEnvironmentGrantContainment
// proves environment-level grants do not widen to admin.break_glass
// at the terminate endpoint. The break-glass resource is org-rooted;
// an env grant — whether for staging or production — names a
// strictly deeper scope, and covers() is one-way.
//
//   - env-staging Support grant denies admin.break_glass on the
//     org root — ReasonDeniedOutOfScope. A staging-scoped key
//     cannot widen to org-level session termination.
//   - env-production Support grant ALSO denies admin.break_glass
//     on the org root — ReasonDeniedOutOfScope. The pin matters
//     because it applies the load-bearing AC "environment-level
//     grants do not imply access to production unless production
//     is explicitly granted" symmetrically: an env-production grant
//     does not silently widen to org-level session termination
//     either, even though it explicitly names production. The
//     resource here is the organization, not production, and the
//     engine refuses to silently promote an env grant past its own
//     depth even when the env id happens to be the "powerful" one.
//   - As a defence-in-depth pin, a staging-scoped Admin grant
//     authorizing env.write against the production environment of
//     the same project is also denied — staging never widens to
//     production by accident, and the same one-way containment
//     underpins the env-grant deny against admin.break_glass at the
//     terminate endpoint.
//   - env-production Admin grant denies ReasonDeniedNoCapability —
//     Admin never holds CapSupport, so the grant cannot supply the
//     action's required capability regardless of scope. This pins
//     the CapSupport requirement against the env-grant path so a
//     future catalog drop of admin.break_glass to CapRead would
//     fail here (silently letting every env-scoped reader terminate
//     the support session that spans the very environment the
//     grant was minted for).
func TestAdminBreakGlassEndpointPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminBreakGlassEndpointOrgResource(orgA)

	stagingSupport := Principal{
		ID: "sa_env_staging_support_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: stagingScope}},
	}
	productionSupport := Principal{
		ID: "sa_env_prod_support_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: productionScope}},
	}
	stagingAdminWritingProd := Principal{
		ID: "sa_env_staging_admin_to_prod_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}
	productionAdmin := Principal{
		ID: "sa_env_prod_admin_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: productionScope}},
	}

	t.Run("env staging support denies org rooted break glass terminate", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(stagingSupport, ActionAdminBreakGlass, orgResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env production support denies org rooted break glass terminate", func(t *testing.T) {
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

// TestAdminBreakGlassEndpointPolicyServiceGrantContainment proves
// service-level grants do not expose parent-level resources via
// admin.break_glass at the terminate endpoint. A service-scoped
// grant on svc_a:
//
//   - cannot authorize admin.break_glass on the org-rooted
//     resource — that would let a service-scoped key terminate the
//     active support session whose effective horizon spans every
//     project, environment, and service in the tenant, the exact
//     "service grant exposes parent-level secrets or unrelated
//     services" escalation the acceptance criterion forbids
//     reapplied to the destructive session-revocation direction.
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
func TestAdminBreakGlassEndpointPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalAdminBreakGlassEndpointProjectID, EnvironmentID: "env_prod",
	}
	orgResource := adminBreakGlassEndpointOrgResource(orgA)

	svcSupport := Principal{
		ID: "sa_svc_support_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleSupport, Scope: svcAScope}},
	}
	svcAdmin := Principal{
		ID: "sa_svc_admin_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped support denies org rooted break glass terminate", func(t *testing.T) {
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

	t.Run("service scoped admin denies org rooted break glass terminate no capability", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcAdmin, ActionAdminBreakGlass, orgResource),
			false, ReasonDeniedNoCapability)
	})
}

// TestAdminBreakGlassEndpointPolicyOrgGrantCapabilityMatrix pins
// the capability split for organization-level grants against
// admin.break_glass at the terminate endpoint. An organization-
// level grant covers any resource within the same org by
// construction (covers() with an empty ProjectID matches any
// project; equally so for the empty environment and service
// fields), so this case isolates the role capability from the grant
// scope: the scope is sufficient at every depth, the role's
// capability set is what decides.
//
//   - Org-level Support grant: scope OK, Support holds CapSupport —
//     allowed (ReasonAllowedByGrant). This is the only role-grant
//     combination at any scope that can authorize admin.break_glass
//     from a grant, and it is the canonical path by which a Yalla-
//     internal automation principal scoped to a single tenant
//     terminates an active support session for that tenant at the
//     close of an incident-response or onboarding window.
//   - Org-level Owner grant: scope OK, Owner holds CapOwner+CapAdmin
//     but NOT CapSupport — denied (ReasonDeniedNoCapability).
//     Pinning Owner here is load-bearing: Owner has the most
//     capabilities of any built-in role, and a future catalog drop
//     of admin.break_glass to CapAdmin or CapOwner would silently
//     allow every Owner grantee to terminate the active support
//     session into the tenant — the canonical denial-of-service
//     shape against Yalla support's incident-response window. The
//     engine pin catches that regression before it can ship.
//   - Org-level Admin / Developer / Viewer / CI grants: scope OK,
//     the role does not hold CapSupport — denied
//     (ReasonDeniedNoCapability). Pinning every non-Support
//     built-in role against the org-grant path closes off every
//     capability-class catalog drift that would widen
//     admin.break_glass beyond Yalla support at the terminate
//     endpoint.
func TestAdminBreakGlassEndpointPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassEndpointOrgResource(orgA)
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
				ID: "sa_org_break_glass_endpoint_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionAdminBreakGlass, resource), tc.allow, tc.reason)
		})
	}
}

// TestAdminBreakGlassEndpointPolicyForeignHomeOrgGrant pins the
// cross-tenant guard on the grant path for the terminate endpoint.
// An organization-scoped Support grant for orgA, carried by a
// ServiceAccount principal whose home org is orgB, cannot be used
// to authorize admin.break_glass against a resource in orgB. The
// principal's home org equals the resource org (both orgB), so the
// cross-tenant clause does NOT fire (it requires resource org !=
// principal home org). The engine then evaluates the principal's
// organization role (empty for this grant-only ServiceAccount,
// which the engine treats as "no role capabilities" without
// erroring) and grants. The grant's Scope.OrganizationID is orgA,
// the principal's home org is orgB, so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role
// caps, the verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property: a scoped grant minted for orgA cannot be carried
// by a principal whose home tenant is orgB to act on the home
// tenant's state — and admin.break_glass, which mints and revokes
// elevated sessions and which the engine deliberately widens via
// CapSupport cross-tenant, is the strongest case for this guard.
// CapSupport's cross-tenant exception is gated on the PRINCIPAL'S
// role caps, not on a grant's role caps; pinning that distinction
// here prevents a future regression where a foreign-org Support
// GRANT silently smuggled the support capability across tenants and
// let an exfiltrated key terminate an active break-glass session in
// the wrong organization, prematurely closing a legitimate Yalla-
// support responder's window during an incident.
func TestAdminBreakGlassEndpointPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := adminBreakGlassEndpointOrgResource(orgB)
	foreignGrant := Grant{
		Role:  RoleSupport,
		Scope: Scope{OrganizationID: orgA},
	}
	p := Principal{
		ID: "sa_stolen_break_glass_endpoint", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionAdminBreakGlass, resource), false, ReasonDeniedNoCapability)
}
