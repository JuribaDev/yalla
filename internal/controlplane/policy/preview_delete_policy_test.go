package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action preview.delete
// (BE-0270). The wire endpoint DELETE
// /v1/projects/{project_id}/previews/{preview_id} itself lands with
// BE-0268 and gets its own httpapi-side policy file then; this file
// pins the authorization contract preview.delete must satisfy
// regardless of which endpoint exposes it. Pinning the engine verdict
// here also means a future {org_id}-scoped or {project_id}-scoped
// variant inherits a working policy boundary — the engine, not the
// route, is the source of truth.
//
// preview.delete is catalogued as CapDeploy (catalog.go:
// ActionPreviewDelete -> CapDeploy), the same capability class as
// preview.create / deployment.create / deployment.rollback /
// service.restart / service.start / service.stop / backup.run. The
// role matrix for a principal acting on its own organization
// therefore splits along the deploy capability class:
// Owner/Admin/Developer/CI hold CapDeploy and are allowed
// (ReasonAllowedByRole); Viewer/Support do not hold CapDeploy and are
// denied (ReasonDeniedNoCapability). This is the load-bearing
// distinction from preview.read (CapRead — six-row allow including
// Support) and from environment.create (CapWrite — three-role split
// without CI): CI tears down preview environments at the end of a
// pipeline but does not write, Support reads but does not deploy.
// Crucially, the engine's cross-tenant support exception is gated on
// `required == CapRead || required == CapSupport`, so CapDeploy is
// OUTSIDE that exception — privileged Yalla support that needs to
// tear down a preview environment on a customer's behalf must go
// through explicit break-glass admin tooling, never through this
// customer-facing action. Pinning the support cross-tenant DENY here
// is what keeps a future cross-tenant variant safe by default.
//
// The route the wire endpoint will register is gated by a
// projectIDResolver, so the policy resource it constructs has Kind
// KindProject and scope {principal_home_org, path_project_id} —
// never a foreign-org scope from the path parameter, never the
// preview environment's id from the {preview_id} segment. The
// preview environment id is a routing artefact for which row to
// delete; the policy boundary is the parent project, exactly as for
// preview.create. This is what keeps the destructive variant of the
// action under the same scope as the creating variant — a key that
// can mint a preview can also tear one down, and a key that cannot
// mint one cannot tear one down. The fixture rows below build the
// same Kind=KindProject resource shape (mirroring the
// projectIDResolver-bound posture pinned in
// preview_create_policy_test.go) so a future endpoint regression that
// resolved into a deeper scope (preview-environment id) or a
// shallower scope (parent organization id) fails one of the grant-
// containment cases.

// canonicalPreviewDeleteProject is the canonical project the preview-
// delete matrix evaluates against. The id is deliberately recognisable
// so a future leak guard in a wire-level test for the endpoint can
// needle for it, and deliberately distinct from
// canonicalPreviewProjectID (used by preview_create_policy_test.go)
// and canonicalPreviewReadProjectID (used by
// preview_read_policy_test.go) so the three preview matrices cannot
// accidentally share fixture state through a future shared helper.
const (
	canonicalPreviewDeleteProjectID = "prj_previews_delete_matrix_alpha"
	canonicalPreviewDeleteSiblingID = "prj_previews_delete_matrix_beta"
)

// previewDeleteProjectResource builds the policy resource the
// projectIDResolver would construct for a preview-delete call whose
// principal's home organization is org and whose path {project_id}
// is projectID. The path {preview_id} segment is intentionally NOT
// part of the resource — it is a routing artefact for which row the
// handler must remove, not part of the policy boundary.
func previewDeleteProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindProject,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// TestPreviewDeletePolicyMatrixRoles drives every built-in role
// through the engine against the canonical project resource in the
// principal's own organization. CapDeploy splits the matrix:
// Owner/Admin/Developer/CI are allowed (ReasonAllowedByRole);
// Viewer/Support are denied (ReasonDeniedNoCapability). The case
// names mirror PRD BE-0270 ("owner, admin, developer, viewer, ci,
// support"). The verdict is pinned alongside the reason so a catalog
// or builtinRoleCaps regression that downgraded preview.delete to
// CapRead would fail here (silently allowing every Viewer to tear
// down preview environments — a destructive customer-data
// operation) and an upgrade to CapWrite would also fail here
// (silently denying CI, which is the precise principal that would
// automate preview teardown from a CI pipeline at the end of a merged
// pull request).
func TestPreviewDeletePolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"owner", RoleOwner, true, ReasonAllowedByRole},
		{"admin", RoleAdmin, true, ReasonAllowedByRole},
		{"developer", RoleDeveloper, true, ReasonAllowedByRole},
		{"ci", RoleCI, true, ReasonAllowedByRole},
		{"viewer", RoleViewer, false, ReasonDeniedNoCapability},
		{"support", RoleSupport, false, ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewDelete, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestPreviewDeletePolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action preview.delete, even when the
// underlying role would have allowed it. The underlying role is
// Owner so a working credential WOULD allow preview.delete; Disabled
// is the only thing in the way and must be load-bearing. The case
// names mirror PRD BE-0270 ("revoked key, expired key"). The deny
// reason is ReasonDeniedPrincipalDisabled — the engine's first-line
// check fires before the catalog lookup, so an action that is not
// even catalogued would still surface this exact reason for a
// disabled principal. The destructive verb makes this pin
// especially load-bearing: a stale CI key whose lease has expired
// must never be able to tear down a preview environment minted by a
// later, healthy CI run on the same pipeline.
func TestPreviewDeletePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_preview_delete_revoked"},
		{"expired key", "sa_preview_delete_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionPreviewDelete, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestPreviewDeletePolicyWrongOrganizationPrincipal pins the cross-
// tenant boundary for preview.delete. Every built-in role — including
// Support — must be denied with ReasonDeniedCrossTenant when the
// resource's organization id differs from the principal's home
// organization id. CapDeploy is OUTSIDE the engine's support cross-
// tenant exception (the clause is `roleCaps.has(CapSupport) &&
// (required == CapRead || required == CapSupport)`), so a Support
// principal of org_yalla authorizing preview.delete against an
// org_victim resource is DENIED — privileged Yalla support that
// needs to tear down a preview on a customer's behalf must go through
// explicit break-glass admin tooling, never this customer-facing
// action.
//
// This is the load-bearing distinction from the cross-tenant matrix
// for preview.read (CapRead — Support is allowed via
// ReasonAllowedBySupport): three additional roles deny here at the
// cross-tenant boundary, and the engine-level pin prevents a future
// endpoint that constructed a resource with a foreign-org scope from
// silently leaking destructive deploy authority across tenants. For
// a destructive verb, the cross-tenant guard is even more load-
// bearing than for create: a misrouted delete is unrecoverable
// without a backup, and an unintended cross-tenant delete is a data-
// loss incident, not just an unauthorised resource minting.
func TestPreviewDeletePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := previewDeleteProjectResource(orgB, canonicalPreviewDeleteProjectID)

	roles := []struct {
		name string
		role Role
	}{
		{"owner", RoleOwner},
		{"admin", RoleAdmin},
		{"developer", RoleDeveloper},
		{"ci", RoleCI},
		{"viewer", RoleViewer},
		{"support", RoleSupport},
	}
	for _, tc := range roles {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewDelete, foreign)
			assertDecision(t, got, false, ReasonDeniedCrossTenant)
		})
	}
}

// TestPreviewDeletePolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for. A scoped API key is authorized purely by its grants (it
// carries no organization role); the engine confines those grants —
// a grant for prj_alpha cannot reach prj_beta.
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     preview.delete (ReasonAllowedByGrant) — Admin confers CapDeploy
//     at the project scope, which is exactly what preview.delete
//     needs.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, the grant scope does not contain the
//     sibling resource. The denial is ReasonDeniedOutOfScope. For a
//     destructive verb this pin is what stops a key scoped to
//     prj_alpha from tearing down a preview that belongs to prj_beta
//     just because the wire endpoint happens to accept the sibling's
//     {project_id} on the path.
//   - A project-level CI grant naming THIS project also authorizes
//     preview.delete — CI is the canonical principal for automating
//     preview teardown from a pipeline at the end of a merged pull
//     request, so the CI-grants-by-project case is pinned explicitly.
//   - A project-level Viewer grant naming THIS project is denied
//     ReasonDeniedNoCapability — Viewer does NOT hold CapDeploy.
//     The grant's scope covers the resource; the grant role's
//     capability set does not. This pins the CapDeploy requirement
//     against the project-grant path so a future catalog change that
//     downgraded preview.delete to CapRead would fail here (silently
//     allowing every project-scoped Viewer grantee to delete preview
//     environments) before it could regress a real customer.
func TestPreviewDeletePolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID}
	targetResource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)
	siblingResource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteSiblingID)

	adminGrant := Grant{Role: RoleAdmin, Scope: targetScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetScope}
	viewerGrant := Grant{Role: RoleViewer, Scope: targetScope}

	t.Run("admin on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewDelete, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("admin on target project denies sibling", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewDelete, siblingResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("ci on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewDelete, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewDelete, targetResource), false, ReasonDeniedNoCapability)
	})
}

// TestPreviewDeletePolicyEnvironmentGrantContainment proves
// environment-level grants do not imply access to production unless
// production is explicitly granted, and do not reach the shallower
// project resource at all. A staging-environment grant cannot
// escalate to deleting a preview environment under the parent
// project — that would let a staging-scoped key tear down a sibling
// environment alongside staging, the precise escalation the engine
// forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. preview.delete is evaluated against a PROJECT-level
// resource (the projectIDResolver scope is {home_org,
// path_project_id}), so an environment-level Admin grant on the
// staging environment under THIS project is denied
// ReasonDeniedOutOfScope when authorizing preview.delete against the
// parent project. As a defence-in-depth pin, an env-scoped staging
// grant authorizing env.write against the production environment of
// the same project is also denied — staging never widens to
// production by accident, and the same containment underpins the
// preview-delete deny.
func TestPreviewDeletePolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)

	envAdminGrantee := Principal{
		ID: "sa_env_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies parent project preview delete", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionPreviewDelete, parentProjectResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("staging grant denies production env write", func(t *testing.T) {
		t.Parallel()
		productionResource := Resource{Kind: domain.KindEnvironment, Scope: productionScope}
		got := e.Decide(envAdminGrantee, ActionEnvWrite, productionResource)
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a staging env grant must not widen to production", got)
		}
	})
}

// TestPreviewDeletePolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources. A service-scoped Admin
// grant on svc_a:
//
//   - cannot authorize preview.delete on the parent project — that
//     would let a service-scoped key tear down a sibling preview
//     environment alongside its own service, the exact "service grant
//     exposes parent-level secrets or unrelated services" escalation
//     the acceptance criterion forbids. The denial is
//     ReasonDeniedOutOfScope (covers() is one-way: a service scope
//     cannot reach the shallower project resource).
//   - cannot authorize env.write on the parent environment — pinning
//     the parent-secret-exposure boundary independently of
//     preview.delete, so a future endpoint that authorized parent
//     env.write through a service grant would fail here before it
//     could regress a real customer.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service boundary
//     independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
func TestPreviewDeletePolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)

	svcGrantee := Principal{
		ID: "sa_svc_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies parent project preview delete", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionPreviewDelete, parentProjectResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent env write", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcGrantee, ActionEnvWrite,
			Resource{Kind: domain.KindEnvironment, Scope: parentEnvScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not expose parent env.write", got)
		}
	})

	t.Run("service scoped grant denies sibling service update", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcGrantee, ActionServiceUpdate,
			Resource{Kind: domain.KindService, Scope: svcBScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not reach svc_b", got)
		}
	})
}

// TestPreviewDeletePolicyOrgGrantCapabilityMatrix pins the capability
// split for organization-level grants against preview.delete. An
// organization-level grant covers any project resource within the
// same org by construction (covers() with an empty ProjectID
// matches any project), so this case isolates the role capability
// from the grant scope: the scope is sufficient, the role's
// capability set is what decides.
//
//   - Org-level CI grant: scope OK, CI holds CapDeploy — allowed
//     (ReasonAllowedByGrant). CI is the canonical principal for
//     automating preview teardown from a pipeline at organization
//     scope.
//   - Org-level Developer grant: scope OK, Developer holds CapDeploy
//     — allowed (ReasonAllowedByGrant).
//   - Org-level Viewer grant: scope OK, Viewer does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). This pins the
//     CapDeploy requirement against the org-grant path so a future
//     catalog change that downgraded preview.delete to CapRead would
//     fail here (silently allowing every org-level Viewer grantee to
//     tear down previews) before it could regress a real customer.
//   - Org-level Support grant: scope OK, Support does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). Support reads
//     widely but never deploys; this is the load-bearing distinction
//     between preview.read (Support allowed) and preview.delete
//     (Support denied) at the org-grant path, mirroring the role
//     matrix denial above. The destructive verb makes this pin
//     especially load-bearing: a stolen or misused support token
//     must never be able to destroy a preview environment.
func TestPreviewDeletePolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewDeleteProjectResource(orgA, canonicalPreviewDeleteProjectID)
	orgScope := Scope{OrganizationID: orgA}

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"ci", RoleCI, true, ReasonAllowedByGrant},
		{"developer", RoleDeveloper, true, ReasonAllowedByGrant},
		{"viewer", RoleViewer, false, ReasonDeniedNoCapability},
		{"support", RoleSupport, false, ReasonDeniedNoCapability},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Principal{
				ID: "sa_org_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionPreviewDelete, resource), tc.allow, tc.reason)
		})
	}
}

// TestPreviewDeletePolicyForeignHomeOrgGrant pins the cross-tenant
// guard on the grant path. A project-scoped Admin grant for
// canonicalPreviewDeleteProjectID inside orgA, carried by a principal
// whose home org is orgB, cannot be used to authorize preview.delete
// against a resource in orgB. The cross-tenant resource-vs-home guard
// does NOT fire here because the resource org id (orgB) equals the
// principal home org id (orgB); the grant path is consulted instead,
// but the grant's Scope.OrganizationID is orgA while the principal's
// home org is orgB, so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role, the
// verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped key"
// property: a scoped grant minted for one tenant cannot be carried
// by a principal whose home tenant is another, so theft of a key
// cannot smuggle destructive deploy authority across tenants even if
// the foreign project_id happens to exist on the path. For a
// destructive verb this guard is what stops an exfiltrated grant
// from being used to delete preview environments in the wrong
// organization — a data-loss incident that would otherwise be
// indistinguishable from a legitimate teardown until the customer
// noticed the missing rows.
func TestPreviewDeletePolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewDeleteProjectResource(orgB, canonicalPreviewDeleteProjectID)
	foreignGrant := Grant{
		Role:  RoleAdmin,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalPreviewDeleteProjectID},
	}
	p := Principal{
		ID: "sa_stolen", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionPreviewDelete, resource), false, ReasonDeniedNoCapability)
}
