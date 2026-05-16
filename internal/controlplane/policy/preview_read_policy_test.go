package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action preview.read
// (BE-0267). The wire endpoint GET /v1/projects/{project_id}/previews
// itself lands with BE-0265 and gets its own httpapi-side policy file
// then; this file pins the authorization contract preview.read must
// satisfy regardless of which endpoint exposes it. Pinning the engine
// verdict here also means a future {env_id}-scoped or {project_id}-
// scoped variant inherits a working policy boundary — the engine, not
// the route, is the source of truth.
//
// preview.read is catalogued as CapRead (catalog.go:
// ActionPreviewRead -> CapRead), the same capability class as every
// other "read" action (project.read, environment.read, service.read,
// deployment.read, backup.read, logs.read, metrics.read, etc.). The
// role matrix for a principal acting on its own organization therefore
// admits every built-in role — Owner/Admin/Developer/Viewer/CI/Support
// all hold CapRead and are allowed (ReasonAllowedByRole). This is the
// load-bearing distinction from preview.create (CapDeploy — four-role
// allow with Viewer/Support denied) and from preview.delete (CapDeploy
// — same four-role split): a Viewer can list preview environments,
// but cannot mint them; Support can list preview environments, and
// can also list them across tenants via the engine's CapRead support
// exception, but cannot mint or delete them. Pinning the Viewer +
// Support allow rows here is what would catch a future catalog change
// that upgraded preview.read to CapDeploy (silently denying every
// Viewer who tries to list previews) before it could regress a real
// customer.
//
// The route the wire endpoint will register is gated by a
// projectIDResolver, so the policy resource it constructs has Kind
// KindProject and scope {principal_home_org, path_project_id} — never
// a foreign-org scope from the path parameter, never a deeper scope
// that includes a specific preview environment id (the list endpoint
// has no preview id on the path). This is the same projectIDResolver-
// bound posture that preview.create lives under
// (preview_create_policy_test.go) and that environment.read lives
// under, but with one critical difference: CapRead is the required
// capability, not CapDeploy, so Viewer and Support are allowed here
// while both are denied for preview.create. The fixture rows below
// build the same Kind=KindProject resource shape so a future endpoint
// regression that resolved into a deeper or shallower scope fails one
// of the grant-containment cases.

// canonicalPreviewReadProject is the canonical project the preview-
// read matrix evaluates against. The id is deliberately recognisable
// so a future leak guard in a wire-level test for the endpoint can
// needle for it, and deliberately distinct from
// canonicalPreviewProjectID (used by preview_create_policy_test.go)
// so the create-matrix and read-matrix fixtures cannot accidentally
// share state through a future shared helper.
const (
	canonicalPreviewReadProjectID = "prj_previews_read_matrix_alpha"
	canonicalPreviewReadSiblingID = "prj_previews_read_matrix_beta"
)

// previewReadProjectResource builds the policy resource the
// projectIDResolver would construct for a preview-read call whose
// principal's home organization is org and whose path {project_id}
// is projectID. The Kind is KindProject because the list endpoint
// scopes by parent project, not by a specific preview environment.
func previewReadProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindProject,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// TestPreviewReadPolicyMatrixRoles drives every built-in role through
// the engine against the canonical project resource in the
// principal's own organization. CapRead is held by every built-in
// role, so Owner/Admin/Developer/Viewer/CI/Support are all allowed
// (ReasonAllowedByRole). The case names mirror PRD BE-0267 ("owner,
// admin, developer, viewer, ci, support"). The verdict is pinned
// alongside the reason so a catalog or builtinRoleCaps regression
// that upgraded preview.read to CapDeploy would fail here (silently
// denying every Viewer/Support that lists preview environments) and
// a regression that stripped CapRead from a built-in role would also
// fail here (denying a role that should retain read access).
func TestPreviewReadPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"owner", RoleOwner, true, ReasonAllowedByRole},
		{"admin", RoleAdmin, true, ReasonAllowedByRole},
		{"developer", RoleDeveloper, true, ReasonAllowedByRole},
		{"viewer", RoleViewer, true, ReasonAllowedByRole},
		{"ci", RoleCI, true, ReasonAllowedByRole},
		{"support", RoleSupport, true, ReasonAllowedByRole},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewRead, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestPreviewReadPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action preview.read, even when the underlying role would
// have allowed it. The underlying role is Owner so a working
// credential WOULD allow preview.read; Disabled is the only thing in
// the way and must be load-bearing. The case names mirror PRD
// BE-0267 ("revoked key, expired key"). The deny reason is
// ReasonDeniedPrincipalDisabled — the engine's first-line check
// fires before the catalog lookup, so an action that is not even
// catalogued would still surface this exact reason for a disabled
// principal.
func TestPreviewReadPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_preview_read_revoked"},
		{"expired key", "sa_preview_read_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionPreviewRead, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestPreviewReadPolicyWrongOrganizationPrincipal pins the cross-
// tenant boundary for preview.read. Five of the six built-in roles
// must be denied with ReasonDeniedCrossTenant when the resource's
// organization id differs from the principal's home organization id.
// Support is the singular exception: the engine's clause
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)` allows Support to read across tenants and returns
// ReasonAllowedBySupport. This is the load-bearing distinction from
// the cross-tenant matrix for preview.create / preview.delete
// (CapDeploy — Support also denied at cross-tenant): one row flips
// from deny to allow at the cross-tenant boundary, and the engine-
// level pin prevents a future catalog change that downgraded
// preview.read out of the CapRead+CapSupport exception (silently
// denying privileged Yalla support's ability to read previews
// across tenants for incident response) or upgraded it past the
// exception (silently leaking cross-tenant preview lists to a
// non-Support role).
func TestPreviewReadPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := previewReadProjectResource(orgB, canonicalPreviewReadProjectID)

	cases := []struct {
		name   string
		role   Role
		allow  bool
		reason Reason
	}{
		{"owner", RoleOwner, false, ReasonDeniedCrossTenant},
		{"admin", RoleAdmin, false, ReasonDeniedCrossTenant},
		{"developer", RoleDeveloper, false, ReasonDeniedCrossTenant},
		{"viewer", RoleViewer, false, ReasonDeniedCrossTenant},
		{"ci", RoleCI, false, ReasonDeniedCrossTenant},
		{"support", RoleSupport, true, ReasonAllowedBySupport},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), ActionPreviewRead, foreign)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestPreviewReadPolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for. A scoped API key is authorized purely by its grants (it
// carries no organization role); the engine confines those grants —
// a grant for prj_alpha cannot reach prj_beta.
//
//   - A project-level Viewer grant naming THIS project CAN authorize
//     preview.read (ReasonAllowedByGrant) — Viewer confers CapRead at
//     the project scope, which is exactly what preview.read needs.
//     This is the load-bearing distinction from preview.create at the
//     project-grant path: a Viewer grant allows read but denies
//     create. A regression that upgraded preview.read to CapDeploy
//     would fail this case (silently denying every project-scoped
//     Viewer grantee that lists preview environments) before it
//     could regress a real customer.
//   - A project-level Viewer grant naming a SIBLING project CANNOT —
//     covers() is one-way, the grant scope does not contain the
//     sibling resource. The denial is ReasonDeniedOutOfScope.
//   - A project-level Support grant naming THIS project also
//     authorizes preview.read — Support holds CapRead, so the read
//     path is allowed via the role's capability set (the cross-
//     tenant Support exception is a separate, more-specific guard
//     that applies only when home_org != resource_org; here both are
//     orgA, so the grant path resolves through capability matching).
//   - A project-level CI grant naming THIS project also authorizes
//     preview.read — CI holds CapRead, so listing previews from a
//     pipeline is allowed.
//
// The deny-no-capability case (a role that lacks CapRead) is omitted
// here on purpose because all six built-in roles hold CapRead, so
// there is no first-class role to anchor it against. Custom roles
// can construct such a principal; the unknown/custom-role behavior
// is already pinned by policy_test.go TestDecideCustomRole.
func TestPreviewReadPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID}
	targetResource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)
	siblingResource := previewReadProjectResource(orgA, canonicalPreviewReadSiblingID)

	viewerGrant := Grant{Role: RoleViewer, Scope: targetScope}
	supportGrant := Grant{Role: RoleSupport, Scope: targetScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetScope}

	t.Run("viewer on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewRead, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies sibling", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewRead, siblingResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewRead, targetResource), true, ReasonAllowedByGrant)
	})

	t.Run("ci on target project allows", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionPreviewRead, targetResource), true, ReasonAllowedByGrant)
	})
}

// TestPreviewReadPolicyEnvironmentGrantContainment proves environment-
// level grants do not imply access to production unless production is
// explicitly granted, and do not reach the shallower project
// resource at all. A staging-environment grant cannot escalate to
// listing preview environments under the parent project — that would
// let a staging-scoped key enumerate sibling environments alongside
// staging, the precise leak the engine forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. preview.read is evaluated against a PROJECT-level
// resource (the projectIDResolver scope is {home_org,
// path_project_id}), so an environment-level Viewer grant on the
// staging environment under THIS project is denied
// ReasonDeniedOutOfScope when authorizing preview.read against the
// parent project. As a defence-in-depth pin, an env-scoped staging
// grant authorizing env.read against the production environment of
// the same project is also denied — staging never widens to
// production by accident, and the same containment underpins the
// preview-read deny.
func TestPreviewReadPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)

	envViewerGrantee := Principal{
		ID: "sa_env_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies parent project preview read", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionPreviewRead, parentProjectResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("staging grant denies production env read", func(t *testing.T) {
		t.Parallel()
		productionResource := Resource{Kind: domain.KindEnvironment, Scope: productionScope}
		got := e.Decide(envViewerGrantee, ActionEnvRead, productionResource)
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a staging env grant must not widen to production read", got)
		}
	})
}

// TestPreviewReadPolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources. A service-scoped
// Viewer grant on svc_a:
//
//   - cannot authorize preview.read on the parent project — that
//     would let a service-scoped key enumerate sibling preview
//     environments alongside its own service, the exact "service
//     grant exposes parent-level secrets or unrelated services"
//     escalation the acceptance criterion forbids. The denial is
//     ReasonDeniedOutOfScope (covers() is one-way: a service scope
//     cannot reach the shallower project resource).
//   - cannot authorize env.read on the parent environment — pinning
//     the parent-environment exposure boundary independently of
//     preview.read, so a future endpoint that authorized parent
//     env.read through a service grant would fail here before it
//     could regress a real customer.
//   - cannot authorize service.read on a sibling service in the
//     same parent environment — pinning the sibling-service
//     boundary independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
func TestPreviewReadPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)

	svcGrantee := Principal{
		ID: "sa_svc_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies parent project preview read", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionPreviewRead, parentProjectResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent env read", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcGrantee, ActionEnvRead,
			Resource{Kind: domain.KindEnvironment, Scope: parentEnvScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not expose parent env.read", got)
		}
	})

	t.Run("service scoped grant denies sibling service read", func(t *testing.T) {
		t.Parallel()
		got := e.Decide(svcGrantee, ActionServiceRead,
			Resource{Kind: domain.KindService, Scope: svcBScope})
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a service grant must not reach svc_b", got)
		}
	})
}

// TestPreviewReadPolicyOrgGrantCapabilityMatrix pins the capability
// admission for organization-level grants against preview.read. An
// organization-level grant covers any project resource within the
// same org by construction (covers() with an empty ProjectID matches
// any project), so this case isolates the role capability from the
// grant scope: the scope is sufficient, the role's capability set is
// what decides.
//
// Every built-in role holds CapRead, so org-level grants for any of
// the six roles allow preview.read at the canonical project
// resource. This is the load-bearing distinction from the org-grant
// capability matrix for preview.create / preview.delete (Viewer and
// Support denied via ReasonDeniedNoCapability): for preview.read,
// the Viewer and Support rows flip to allow, and the engine-level
// pin would catch a future catalog change that upgraded preview.read
// to CapDeploy (silently denying every org-level Viewer/Support
// grantee that lists preview environments) before it could regress a
// real customer. CI and Developer are pinned alongside Viewer and
// Support so the matrix proves the entire CapRead set, not just the
// load-bearing rows.
func TestPreviewReadPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewReadProjectResource(orgA, canonicalPreviewReadProjectID)
	orgScope := Scope{OrganizationID: orgA}

	cases := []struct {
		name string
		role Role
	}{
		{"ci", RoleCI},
		{"developer", RoleDeveloper},
		{"viewer", RoleViewer},
		{"support", RoleSupport},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Principal{
				ID: "sa_org_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionPreviewRead, resource), true, ReasonAllowedByGrant)
		})
	}
}

// TestPreviewReadPolicyForeignHomeOrgGrant pins the cross-tenant
// guard on the grant path. A project-scoped Viewer grant for
// canonicalPreviewReadProjectID inside orgA, carried by a principal
// whose home org is orgB, cannot be used to authorize preview.read
// against a resource in orgB. The resource here is in orgB and the
// principal home is orgB, so the cross-tenant guard does NOT fire.
// Then the grant path is consulted, but the grant's
// Scope.OrganizationID is orgA while the principal's home org is
// orgB, so the engine's grant filter `g.Scope.OrganizationID !=
// principal.OrganizationID` skips the grant entirely. With no usable
// grant and no organization role (the principal is a ServiceAccount
// with grants only), the verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property: a scoped grant minted for one tenant cannot be
// carried by a principal whose home tenant is another, so theft of
// a key cannot smuggle even READ authority across tenants even if
// the foreign project_id happens to exist on the path. CapRead is
// inside the engine's support cross-tenant exception, but that
// exception is gated on roleCaps from the principal's HOME-org role
// — a stolen scoped key carries no home-org role for its bearer's
// home tenant, so the exception does not fire here.
func TestPreviewReadPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := previewReadProjectResource(orgB, canonicalPreviewReadProjectID)
	foreignGrant := Grant{
		Role:  RoleViewer,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalPreviewReadProjectID},
	}
	p := Principal{
		ID: "sa_stolen_read", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionPreviewRead, resource), false, ReasonDeniedNoCapability)
}
