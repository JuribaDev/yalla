package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action job.read (BE-0273).
// The wire endpoint GET /v1/jobs (BE-0271) and its contract tests
// (BE-0272) have not landed yet; this file pins the authorization
// contract job.read must satisfy regardless of which endpoint
// surfaces it. Pinning the engine verdict here also means a future
// project-scoped, environment-scoped, or service-scoped filtered
// variant (when query parameters such as ?project_id=... land)
// inherits a working policy boundary — the engine, not the route,
// is the source of truth. The same engine-only pin precedent is in
// preview_read_policy_test.go (BE-0267), preview_create_policy_test.go
// (BE-0264), and preview_delete_policy_test.go (BE-0270).
//
// job.read is catalogued as CapRead (catalog.go: ActionJobRead ->
// CapRead), the same capability class as every other "read" action
// (project.read, environment.read, service.read, deployment.read,
// backup.read, logs.read, metrics.read, preview.read). The role
// matrix for a principal acting on its own organization therefore
// admits every built-in role — Owner/Admin/Developer/Viewer/CI/
// Support all hold CapRead and are allowed (ReasonAllowedByRole).
// This is the load-bearing distinction from job.cancel and
// job.retry (CapDeploy — four-role allow with Viewer/Support
// denied): a Viewer can list provisioning jobs, but cannot cancel
// or retry them; Support can list provisioning jobs, and can also
// list them across tenants via the engine's CapRead support
// exception, but cannot cancel or retry them. Pinning the Viewer +
// Support allow rows here is what would catch a future catalog
// change that upgraded job.read to CapDeploy (silently denying
// every Viewer who tries to list provisioning jobs) before it
// could regress a real customer.
//
// The route the wire endpoint will register is an organization-
// level list (GET /v1/jobs has no path parameter), so the policy
// resource it constructs has Kind KindJob and scope
// {principal_home_org} — only OrganizationID is pinned at this
// level, because the list endpoint does not narrow to a specific
// project, environment, or service. When BE-0271 lands and adds
// optional ?project_id=, ?environment_id=, or ?service_id= query
// filters, the resolver will construct a deeper Scope (still Kind
// KindJob) so a project-scoped grant naming that project can
// satisfy the filtered view. The grant-containment cases below
// pin both directions of that contract: a project-scoped grant
// cannot reach the org-level list resource (covers() is one-way:
// a deeper grant cannot widen to a shallower resource), but the
// same grant CAN authorize a project-filtered list whose resource
// scope matches the grant scope exactly.

// canonicalJobReadProjectID and canonicalJobReadSiblingID are the
// canonical project ids the job-read containment matrix evaluates
// against. The ids are deliberately recognisable so a future leak
// guard in a wire-level test for the endpoint can needle for them,
// and deliberately distinct from canonicalPreviewReadProjectID
// (used by preview_read_policy_test.go) so the preview-read and
// job-read fixtures cannot accidentally share state through a
// future shared helper.
const (
	canonicalJobReadProjectID = "prj_jobs_read_matrix_alpha"
	canonicalJobReadSiblingID = "prj_jobs_read_matrix_beta"
)

// jobReadOrgResource builds the policy resource the org-level list
// resolver would construct for a GET /v1/jobs call whose principal
// home organization is org. The Kind is KindJob and only
// OrganizationID is pinned: the list endpoint surveys every job in
// the tenant and does not narrow to a specific project,
// environment, or service.
func jobReadOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org},
	}
}

// jobReadProjectResource builds the policy resource a future
// project-filtered list call (GET /v1/jobs?project_id=projectID)
// would construct. The Kind stays KindJob, but the Scope narrows
// to a specific project so a project-scoped grant can satisfy it.
func jobReadProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// TestJobReadPolicyMatrixRoles drives every built-in role through
// the engine against the canonical org-level job-list resource in
// the principal's own organization. CapRead is held by every
// built-in role, so Owner/Admin/Developer/Viewer/CI/Support are
// all allowed (ReasonAllowedByRole). The case names mirror PRD
// BE-0273 ("owner, admin, developer, viewer, ci, support"). The
// verdict is pinned alongside the reason so a catalog or
// builtinRoleCaps regression that upgraded job.read to CapDeploy
// would fail here (silently denying every Viewer/Support that
// lists provisioning jobs) and a regression that stripped CapRead
// from a built-in role would also fail here (denying a role that
// should retain read access).
func TestJobReadPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadOrgResource(orgA)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobRead, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestJobReadPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal
// — is denied action job.read, even when the underlying role
// would have allowed it. The underlying role is Owner so a working
// credential WOULD allow job.read; Disabled is the only thing in
// the way and must be load-bearing. The case names mirror PRD
// BE-0273 ("revoked key, expired key"). The deny reason is
// ReasonDeniedPrincipalDisabled — the engine's first-line check
// fires before the catalog lookup, so an action that is not even
// catalogued would still surface this exact reason for a disabled
// principal.
func TestJobReadPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_job_read_revoked"},
		{"expired key", "sa_job_read_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionJobRead, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestJobReadPolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for job.read. Five of the six built-in roles must be
// denied with ReasonDeniedCrossTenant when the resource's
// organization id differs from the principal's home organization
// id. Support is the singular exception: the engine's clause
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)` allows Support to read across tenants and returns
// ReasonAllowedBySupport. This is the load-bearing distinction
// from the cross-tenant matrix for job.cancel / job.retry
// (CapDeploy — Support also denied at cross-tenant): one row
// flips from deny to allow at the cross-tenant boundary, and the
// engine-level pin prevents a future catalog change that
// downgraded job.read out of the CapRead+CapSupport exception
// (silently denying privileged Yalla support's ability to read
// provisioning jobs across tenants for incident response) or
// upgraded it past the exception (silently leaking cross-tenant
// job lists to a non-Support role).
func TestJobReadPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := jobReadOrgResource(orgB)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobRead, foreign)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestJobReadPolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for, and pins BOTH directions of the project-grant containment:
//
//   - A project-level Viewer grant naming THIS project CAN
//     authorize job.read against the project-narrowed resource
//     (Kind=KindJob, Scope={org, project}). This is the shape a
//     future GET /v1/jobs?project_id=THIS_project resolver will
//     construct, and it proves a project-scoped automation key
//     can list provisioning jobs scoped to its own project. The
//     verdict is ReasonAllowedByGrant.
//   - The same project-level Viewer grant CANNOT reach the org-
//     level list resource (Kind=KindJob, Scope={org} only — no
//     project narrowing). covers() is one-way: a deeper grant
//     scope cannot reach a shallower resource scope. The denial
//     is ReasonDeniedOutOfScope. This is what stops a project-
//     scoped key from listing every job in the tenant via a bare
//     GET /v1/jobs.
//   - A project-level Viewer grant naming the SIBLING project
//     CANNOT authorize a project-filtered list against THIS
//     project — covers() is one-way and the grant's project does
//     not match the resource's project. The denial is
//     ReasonDeniedOutOfScope. This is the load-bearing AC
//     "project-level grants do not imply access to sibling
//     projects".
//   - A project-level Support grant naming THIS project also
//     authorizes job.read at the project-narrowed resource —
//     Support holds CapRead, so the read path is allowed via the
//     role's capability set (the cross-tenant Support exception
//     is a separate, more-specific guard that applies only when
//     home_org != resource_org; here both are orgA, so the grant
//     path resolves through capability matching).
//   - A project-level CI grant naming THIS project also
//     authorizes job.read at the project-narrowed resource — CI
//     holds CapRead, so reading provisioning jobs from a pipeline
//     is allowed.
//
// The deny-no-capability case (a role that lacks CapRead) is
// omitted here on purpose because all six built-in roles hold
// CapRead, so there is no first-class role to anchor it against.
// Custom roles can construct such a principal; the unknown/custom-
// role behavior is already pinned by policy_test.go
// TestDecideCustomRole.
func TestJobReadPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetProjectScope := Scope{OrganizationID: orgA, ProjectID: canonicalJobReadProjectID}
	targetProjectResource := jobReadProjectResource(orgA, canonicalJobReadProjectID)
	siblingProjectResource := jobReadProjectResource(orgA, canonicalJobReadSiblingID)
	orgListResource := jobReadOrgResource(orgA)

	viewerGrant := Grant{Role: RoleViewer, Scope: targetProjectScope}
	supportGrant := Grant{Role: RoleSupport, Scope: targetProjectScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetProjectScope}

	t.Run("viewer on target project allows project filtered list", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies org level list", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, orgListResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("viewer on target project denies sibling project list", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, siblingProjectResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on target project allows project filtered list", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectResource), true, ReasonAllowedByGrant)
	})

	t.Run("ci on target project allows project filtered list", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectResource), true, ReasonAllowedByGrant)
	})
}

// TestJobReadPolicyEnvironmentGrantContainment proves environment-
// level grants do not imply access to production unless production
// is explicitly granted, and do not reach the shallower org-list
// or parent-project resources at all. A staging-environment grant
// cannot escalate to listing every provisioning job under the
// parent project or the parent organization — that would let a
// staging-scoped key enumerate jobs against sibling environments
// alongside staging, the precise leak the engine forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a
// shallower resource. So:
//
//   - env-staging grant denies job.read against the org-level
//     list resource (Scope={org} only). ReasonDeniedOutOfScope.
//   - env-staging grant denies job.read against the parent-project
//     resource (Scope={org, project}). ReasonDeniedOutOfScope.
//   - env-staging grant ALLOWS job.read against the staging-
//     environment resource (Scope={org, project, env_staging}) —
//     covers() matches because the grant scope equals the resource
//     scope. This is what a future ?environment_id= filter would
//     resolve to and proves the env-scoped automation key path.
//
// As a defence-in-depth pin, an env-scoped staging grant
// authorizing env.read against the production environment of the
// same project is also denied — staging never widens to production
// by accident, and the same containment underpins the job-read
// deny: a staging grant cannot list production jobs.
func TestJobReadPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := jobReadProjectResource(orgA, canonicalJobReadProjectID)
	orgListResource := jobReadOrgResource(orgA)
	stagingJobResource := Resource{Kind: domain.KindJob, Scope: stagingScope}

	envViewerGrantee := Principal{
		ID: "sa_env_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies org level list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, orgListResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant denies parent project list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, parentProjectResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant allows staging environment list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, stagingJobResource),
			true, ReasonAllowedByGrant)
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

// TestJobReadPolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources. A service-scoped
// Viewer grant on svc_a:
//
//   - cannot authorize job.read on the org-level list resource —
//     that would let a service-scoped key enumerate every job in
//     the tenant, the exact "service grant exposes parent-level
//     secrets or unrelated services" escalation the acceptance
//     criterion forbids. ReasonDeniedOutOfScope.
//   - cannot authorize job.read on the parent-project resource —
//     pinning the parent-project exposure boundary independently
//     of the org-level pin. ReasonDeniedOutOfScope.
//   - cannot authorize env.read on the parent environment —
//     pinning the parent-environment exposure boundary
//     independently of job.read, so a future endpoint that
//     authorized parent env.read through a service grant would
//     fail here before it could regress a real customer.
//   - cannot authorize service.read on a sibling service in the
//     same parent environment — pinning the sibling-service
//     boundary independently of the parent-project boundary, so
//     the containment matrix proves both directions, not just one.
//   - CAN authorize job.read on its own service scope ({org,
//     project, env, svc_a}) — covers() matches because the grant
//     scope equals the resource scope. This is what a future
//     ?service_id=svc_a filter would resolve to and proves the
//     service-scoped automation key path stays usable inside its
//     own service.
func TestJobReadPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadProjectID, EnvironmentID: "env_prod",
	}
	parentProjectResource := jobReadProjectResource(orgA, canonicalJobReadProjectID)
	orgListResource := jobReadOrgResource(orgA)
	svcAJobResource := Resource{Kind: domain.KindJob, Scope: svcAScope}

	svcGrantee := Principal{
		ID: "sa_svc_viewer", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies org level list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, orgListResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent project list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, parentProjectResource),
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

	t.Run("service scoped grant allows own service job list", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, svcAJobResource),
			true, ReasonAllowedByGrant)
	})
}

// TestJobReadPolicyOrgGrantCapabilityMatrix pins the capability
// admission for organization-level grants against job.read. An
// organization-level grant covers any resource within the same org
// by construction (covers() with an empty ProjectID matches any
// project; equally so for the empty environment and service
// fields), so this case isolates the role capability from the
// grant scope: the scope is sufficient at every depth, the role's
// capability set is what decides.
//
// Every built-in role holds CapRead, so org-level grants for any
// of the six roles allow job.read at the canonical org-level list
// resource. This is the load-bearing distinction from the org-
// grant capability matrix for job.cancel / job.retry (Viewer and
// Support denied via ReasonDeniedNoCapability): for job.read, the
// Viewer and Support rows flip to allow, and the engine-level pin
// would catch a future catalog change that upgraded job.read to
// CapDeploy (silently denying every org-level Viewer/Support
// grantee that lists provisioning jobs) before it could regress a
// real customer. CI and Developer are pinned alongside Viewer and
// Support so the matrix proves the entire CapRead set, not just
// the load-bearing rows.
func TestJobReadPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadOrgResource(orgA)
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
			assertDecision(t, e.Decide(p, ActionJobRead, resource), true, ReasonAllowedByGrant)
		})
	}
}

// TestJobReadPolicyForeignHomeOrgGrant pins the cross-tenant guard
// on the grant path. A project-scoped Viewer grant for
// canonicalJobReadProjectID inside orgA, carried by a principal
// whose home org is orgB, cannot be used to authorize job.read
// against a resource in orgB. The resource here is in orgB and
// the principal home is orgB, so the cross-tenant guard does NOT
// fire. Then the grant path is consulted, but the grant's
// Scope.OrganizationID is orgA while the principal's home org is
// orgB, so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role
// (the principal is a ServiceAccount with grants only), the
// verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property: a scoped grant minted for one tenant cannot be
// carried by a principal whose home tenant is another, so theft
// of a key cannot smuggle even READ authority across tenants even
// if the foreign project_id happens to exist on the path. CapRead
// is inside the engine's support cross-tenant exception, but that
// exception is gated on roleCaps from the principal's HOME-org
// role — a stolen scoped key carries no home-org role for its
// bearer's home tenant, so the exception does not fire here.
func TestJobReadPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadProjectResource(orgB, canonicalJobReadProjectID)
	foreignGrant := Grant{
		Role:  RoleViewer,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalJobReadProjectID},
	}
	p := Principal{
		ID: "sa_stolen_read", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionJobRead, resource), false, ReasonDeniedNoCapability)
}
