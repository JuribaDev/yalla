package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action preview.create
// (BE-0264). The wire endpoint POST /v1/projects/{project_id}/previews
// itself lands with BE-0262 and gets its own httpapi-side policy file
// then; this file pins the authorization contract preview.create must
// satisfy regardless of which endpoint exposes it. Pinning the engine
// verdict here also means a future {org_id}-scoped or
// {project_id}-scoped variant inherits a working policy boundary —
// the engine, not the route, is the source of truth.
//
// preview.create is catalogued as CapDeploy (catalog.go:
// ActionPreviewCreate -> CapDeploy), the same capability class as
// deployment.create / deployment.rollback / service.restart /
// service.start / service.stop / backup.run. The role matrix for a
// principal acting on its own organization therefore splits along the
// deploy capability class: Owner/Admin/Developer/CI hold CapDeploy
// and are allowed (ReasonAllowedByRole); Viewer/Support do not hold
// CapDeploy and are denied (ReasonDeniedNoCapability). This is the
// load-bearing distinction from preview.read (CapRead — six-row
// allow) and from environment.create (CapWrite — three-role split
// without CI): CI deploys but does not write, Support reads but does
// not deploy. Crucially, the engine's cross-tenant support exception
// is gated on `required == CapRead || required == CapSupport`, so
// CapDeploy is OUTSIDE that exception — privileged Yalla support that
// needs to mint a preview environment on a customer's behalf must go
// through explicit break-glass admin tooling, never through this
// customer-facing action. Pinning the support cross-tenant DENY here
// is what keeps a future cross-tenant variant safe by default.
//
// The route the wire endpoint will register is gated by a
// projectIDResolver, so the policy resource it constructs has Kind
// KindProject and scope {principal_home_org, path_project_id} — never
// a foreign-org scope from the path parameter, never the not-yet-
// minted preview environment's id. This is the same projectIDResolver-
// bound posture that environment.create lives under
// (projects_environments_create_policy_test.go) but with one critical
// difference: CapDeploy is the required capability, not CapWrite, so
// CI is allowed here while CI is denied for environment.create. The
// fixture rows below build the same Kind=KindProject resource shape
// so a future endpoint regression that resolved into a deeper or
// shallower scope fails one of the grant-containment cases.

// canonicalPreviewProject is the canonical project the preview-create
// matrix evaluates against. The id is deliberately recognisable so a
// future leak guard in a wire-level test for the endpoint can needle
// for it, and deliberately distinct from canonicalEnvironmentsProject
// (used by projects_environments_create_policy_test.go) so the two
// matrices cannot accidentally share fixture state through a future
// shared helper.
const (
	canonicalPreviewProjectID = "prj_previews_matrix_alpha"
	canonicalPreviewSiblingID = "prj_previews_matrix_beta"
)

// previewProjectResource builds the policy resource the
// projectIDResolver would construct for a preview-create call whose
// principal's home organization is org and whose path {project_id}
// is projectID.
func previewProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindProject,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// TestPreviewCreatePolicyMatrixRoles drives every built-in role
// through the engine against the canonical project resource in the
// principal's own organization. CapDeploy splits the matrix:
// Owner/Admin/Developer/CI are allowed (ReasonAllowedByRole);
// Viewer/Support are denied (ReasonDeniedNoCapability). The case
// names mirror PRD BE-0264 ("owner, admin, developer, viewer, ci,
// support"). The verdict is pinned alongside the reason so a catalog
// or builtinRoleCaps regression that downgraded preview.create to
// CapRead would fail here (silently allowing every Viewer to mint
// preview environments) and an upgrade to CapWrite would also fail
// here (silently denying CI, which is the precise principal that
// would automate preview minting from a CI pipeline).
func TestPreviewCreatePolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewProjectResource(orgA, canonicalPreviewProjectID)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewCreate, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestPreviewCreatePolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action preview.create, even when the
// underlying role would have allowed it. The underlying role is
// Owner so a working credential WOULD allow preview.create; Disabled
// is the only thing in the way and must be load-bearing. The case
// names mirror PRD BE-0264 ("revoked key, expired key"). The deny
// reason is ReasonDeniedPrincipalDisabled — the engine's first-line
// check fires before the catalog lookup, so an action that is not
// even catalogued would still surface this exact reason for a
// disabled principal.
func TestPreviewCreatePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewProjectResource(orgA, canonicalPreviewProjectID)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_preview_revoked"},
		{"expired key", "sa_preview_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionPreviewCreate, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestPreviewCreatePolicyWrongOrganizationPrincipal pins the cross-
// tenant boundary for preview.create. Every built-in role — including
// Support — must be denied with ReasonDeniedCrossTenant when the
// resource's organization id differs from the principal's home
// organization id. CapDeploy is OUTSIDE the engine's support cross-
// tenant exception (the clause is `roleCaps.has(CapSupport) &&
// (required == CapRead || required == CapSupport)`), so a Support
// principal of org_yalla authorizing preview.create against an
// org_victim resource is DENIED — privileged Yalla support that needs
// to mint a preview on a customer's behalf must go through explicit
// break-glass admin tooling, never this customer-facing action.
//
// This is the load-bearing distinction from the cross-tenant matrix
// for preview.read (CapRead — Support is allowed via
// ReasonAllowedBySupport): three additional roles deny here at the
// cross-tenant boundary, and the engine-level pin prevents a future
// endpoint that constructed a resource with a foreign-org scope from
// silently leaking deploy authority across tenants.
func TestPreviewCreatePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := previewProjectResource(orgB, canonicalPreviewProjectID)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewCreate, foreign)
			assertDecision(t, got, false, ReasonDeniedCrossTenant)
		})
	}
}

// TestPreviewCreatePolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for. A scoped API key is authorized purely by its grants (it carries
// no organization role); the engine confines those grants — a grant
// for prj_alpha cannot reach prj_beta.
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     preview.create (ReasonAllowedByGrant) — Admin confers CapDeploy
//     at the project scope, which is exactly what preview.create
//     needs.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, the grant scope does not contain the
//     sibling resource. The denial is ReasonDeniedOutOfScope.
//   - A project-level CI grant naming THIS project also authorizes
//     preview.create — CI is the canonical principal for automating
//     preview minting from a pipeline, so the CI-grants-by-project
//     case is pinned explicitly.
//   - A project-level Viewer grant naming THIS project is denied
//     ReasonDeniedNoCapability — Viewer does NOT hold CapDeploy.
//     The grant's scope covers the resource; the grant role's
//     capability set does not. This pins the CapDeploy requirement
//     against the project-grant path so a future catalog change that
//     downgraded preview.create to CapRead would fail here (silently
//     allowing every project-scoped Viewer grantee to mint previews)
//     before it could regress a real customer.
func TestPreviewCreatePolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalPreviewProjectID}
	targetResource := previewProjectResource(orgA, canonicalPreviewProjectID)
	siblingResource := previewProjectResource(orgA, canonicalPreviewSiblingID)

	adminGrant := Grant{Role: RoleAdmin, Scope: targetScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetScope}
	viewerGrant := Grant{Role: RoleViewer, Scope: targetScope}

	t.Run("admin on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewCreate, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("admin on target project denies sibling", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewCreate, siblingResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("ci on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewCreate, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewCreate, targetResource), false, ReasonDeniedNoCapability)
	})
}

// TestPreviewCreatePolicyEnvironmentGrantContainment proves
// environment-level grants do not imply access to production unless
// production is explicitly granted, and do not reach the shallower
// project resource at all. A staging-environment grant cannot escalate
// to creating a preview environment under the parent project — that
// would let a staging-scoped key mint a sibling environment alongside
// staging, the precise escalation the engine forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. preview.create is evaluated against a PROJECT-level
// resource (the projectIDResolver scope is {home_org,
// path_project_id}), so an environment-level Admin grant on the
// staging environment under THIS project is denied
// ReasonDeniedOutOfScope when authorizing preview.create against the
// parent project. As a defence-in-depth pin, an env-scoped staging
// grant authorizing env.write against the production environment of
// the same project is also denied — staging never widens to
// production by accident, and the same containment underpins the
// preview-create deny.
func TestPreviewCreatePolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewProjectResource(orgA, canonicalPreviewProjectID)

	envAdminGrantee := Principal{
		ID: "sa_env_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies parent project preview create", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionPreviewCreate, parentProjectResource),
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

// TestPreviewCreatePolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources. A service-scoped Admin
// grant on svc_a:
//
//   - cannot authorize preview.create on the parent project — that
//     would let a service-scoped key mint a sibling preview environment
//     alongside its own service, the exact "service grant exposes
//     parent-level secrets or unrelated services" escalation the
//     acceptance criterion forbids. The denial is
//     ReasonDeniedOutOfScope (covers() is one-way: a service scope
//     cannot reach the shallower project resource).
//   - cannot authorize env.write on the parent environment — pinning
//     the parent-secret-exposure boundary independently of
//     preview.create, so a future endpoint that authorized parent
//     env.write through a service grant would fail here before it
//     could regress a real customer.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service boundary
//     independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
func TestPreviewCreatePolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewProjectResource(orgA, canonicalPreviewProjectID)

	svcGrantee := Principal{
		ID: "sa_svc_admin", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies parent project preview create", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionPreviewCreate, parentProjectResource),
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

// TestPreviewCreatePolicyOrgGrantCapabilityMatrix pins the capability
// split for organization-level grants against preview.create. An
// organization-level grant covers any project resource within the
// same org by construction (covers() with an empty ProjectID
// matches any project), so this case isolates the role capability
// from the grant scope: the scope is sufficient, the role's
// capability set is what decides.
//
//   - Org-level CI grant: scope OK, CI holds CapDeploy — allowed
//     (ReasonAllowedByGrant). CI is the canonical principal for
//     automating preview minting from a pipeline at organization
//     scope.
//   - Org-level Developer grant: scope OK, Developer holds CapDeploy
//     — allowed (ReasonAllowedByGrant).
//   - Org-level Viewer grant: scope OK, Viewer does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). This pins the
//     CapDeploy requirement against the org-grant path so a future
//     catalog change that downgraded preview.create to CapRead would
//     fail here (silently allowing every org-level Viewer grantee to
//     mint previews) before it could regress a real customer.
//   - Org-level Support grant: scope OK, Support does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). Support reads
//     widely but never deploys; this is the load-bearing distinction
//     between preview.read (Support allowed) and preview.create
//     (Support denied) at the org-grant path, mirroring the role
//     matrix denial above.
func TestPreviewCreatePolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewProjectResource(orgA, canonicalPreviewProjectID)
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
			assertDecision(t, e.Decide(p, ActionPreviewCreate, resource), tc.allow, tc.reason)
		})
	}
}

// TestPreviewCreatePolicyForeignHomeOrgGrant pins the cross-tenant
// guard on the grant path. A project-scoped Admin grant for
// canonicalPreviewProjectID inside orgA, carried by a principal whose
// home org is orgB, cannot be used to authorize preview.create against
// a resource in orgB. The cross-tenant guard fires first because the
// resource org id (orgB) differs from the principal home org id —
// wait, actually the resource here is in orgB and the principal home
// is orgB, so the cross-tenant guard does NOT fire. Then the grant
// path is consulted, but the grant's Scope.OrganizationID is orgA
// while the principal's home org is orgB, so the engine's grant
// filter `g.Scope.OrganizationID != principal.OrganizationID` skips
// the grant entirely. With no usable grant and no organization role,
// the verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped key"
// property: a scoped grant minted for one tenant cannot be carried
// by a principal whose home tenant is another, so theft of a key
// cannot smuggle deploy authority across tenants even if the foreign
// project_id happens to exist on the path.
func TestPreviewCreatePolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewProjectResource(orgB, canonicalPreviewProjectID)
	foreignGrant := Grant{
		Role:  RoleAdmin,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalPreviewProjectID},
	}
	p := Principal{
		ID: "sa_stolen", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionPreviewCreate, resource), false, ReasonDeniedNoCapability)
}
