package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action job.read on the
// bare-{job_id} fetch variant (BE-0276). The wire endpoint
// GET /v1/jobs/{job_id} (BE-0274) and its contract tests (BE-0275)
// have not landed yet; this file pins the authorization contract the
// bare-id fetch must satisfy regardless of which endpoint surfaces
// it. The list variant (GET /v1/jobs) is pinned independently in
// job_read_policy_test.go (BE-0273); both files cover ActionJobRead
// but exercise the two resource shapes the resolver will construct —
// the org-level list shape (Scope={org}) for /v1/jobs and the
// row-owning-scope shape (Scope={org, project?, env?, svc?}) for
// /v1/jobs/{job_id}. The same engine-only pin precedent that holds
// for previews (preview_read/create/delete) holds here.
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
// denied): a Viewer can fetch a single provisioning job by id, but
// cannot cancel or retry it; Support can fetch a single provisioning
// job by id, and can also do so across tenants via the engine's
// CapRead support exception, but cannot cancel or retry it. Pinning
// the Viewer + Support allow rows here is what would catch a future
// catalog change that upgraded job.read to CapDeploy (silently
// denying every Viewer who fetches a provisioning job by id) before
// it could regress a real customer.
//
// The route the wire endpoint will register is bare-{job_id} under
// the organization (GET /v1/jobs/{job_id} has no parent project,
// environment, or service in the path). The {job_id} path segment
// is a routing artefact — which row to fetch — not the policy
// boundary. The policy boundary is the JOB ROW'S OWNING SCOPE, which
// the resolver looks up before deciding: a job owned by the org
// root resolves into Resource{Kind=KindJob, Scope={org}}; a job
// owned by a project resolves into Resource{Kind=KindJob, Scope=
// {org, project}}; a job owned by an environment resolves into
// Resource{Kind=KindJob, Scope={org, project, env}}; a job owned by
// a service resolves into Resource{Kind=KindJob, Scope={org,
// project, env, svc}}. The grant-containment cases below pin every
// one of these owning-scope shapes so a future endpoint regression
// that collapsed every job's owning scope to the org root (silently
// allowing every project-, env-, or service-scoped key to fetch any
// job in the tenant by id) or that lifted the owning scope to the
// {job_id} segment alone (a shape Scope cannot represent and which
// would bypass project/env/svc containment) fails one of the cases
// here.

// canonicalJobReadByIDProjectID and canonicalJobReadByIDSiblingID
// are the canonical project ids the job-read-by-id containment
// matrix evaluates against. The ids are deliberately recognisable so
// a future leak guard in a wire-level test for the endpoint can
// needle for them, and deliberately distinct from
// canonicalJobReadProjectID (used by job_read_policy_test.go's list
// variant) so the list and by-id matrices cannot accidentally share
// state through a future shared helper.
const (
	canonicalJobReadByIDProjectID = "prj_jobs_read_byid_matrix_alpha"
	canonicalJobReadByIDSiblingID = "prj_jobs_read_byid_matrix_beta"
)

// jobReadByIDOrgResource builds the policy resource the bare-{job_id}
// resolver would construct for a GET /v1/jobs/{job_id} call whose
// principal home organization is org and whose target row is owned
// at the org root (no parent project, environment, or service). The
// Kind is KindJob and only OrganizationID is pinned: the resolver
// reflects the job row's actual owning scope, and an org-rooted job
// row has no narrower owning scope to reflect.
func jobReadByIDOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org},
	}
}

// jobReadByIDProjectResource builds the policy resource the bare-
// {job_id} resolver would construct for a job row owned by a
// project. A project-scoped grant naming that project can satisfy
// it; an org-level role (or org-level grant) for the same tenant
// can also satisfy it via covers() because the grant scope leaves
// the project field empty.
func jobReadByIDProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// jobReadByIDEnvResource builds the policy resource the bare-{job_id}
// resolver would construct for a job row owned by an environment.
// An env-scoped grant naming that env can satisfy it; a project-
// scoped grant naming the parent project also satisfies it via
// covers() because the grant scope leaves the env field empty.
func jobReadByIDEnvResource(org, projectID, envID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID},
	}
}

// jobReadByIDServiceResource builds the policy resource the bare-
// {job_id} resolver would construct for a job row owned by a
// service. A service-scoped grant naming that service can satisfy
// it; an env- or project-scoped grant naming a parent of the
// service also satisfies it via covers() because the grant scope
// leaves the deeper fields empty.
func jobReadByIDServiceResource(org, projectID, envID, svcID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID, ServiceID: svcID},
	}
}

// TestJobReadByIDPolicyMatrixRoles drives every built-in role through
// the engine against the canonical bare-{job_id} resource owned at
// the org root in the principal's own organization. CapRead is held
// by every built-in role, so Owner/Admin/Developer/Viewer/CI/Support
// are all allowed (ReasonAllowedByRole). The case names mirror PRD
// BE-0276 ("owner, admin, developer, viewer, ci, support"). The
// verdict is pinned alongside the reason so a catalog or
// builtinRoleCaps regression that upgraded job.read to CapDeploy
// would fail here (silently denying every Viewer/Support that
// fetches a provisioning job by id) and a regression that stripped
// CapRead from a built-in role would also fail here (denying a role
// that should retain read access).
func TestJobReadByIDPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadByIDOrgResource(orgA)

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

// TestJobReadByIDPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal —
// is denied action job.read on the bare-{job_id} fetch, even when
// the underlying role would have allowed it. The underlying role is
// Owner so a working credential WOULD allow job.read; Disabled is
// the only thing in the way and must be load-bearing. The case
// names mirror PRD BE-0276 ("revoked key, expired key"). The deny
// reason is ReasonDeniedPrincipalDisabled — the engine's first-line
// check fires before the catalog lookup, so an action that is not
// even catalogued would still surface this exact reason for a
// disabled principal. The auth layer's reject-before-policy posture
// for revoked keys (the API layer 401s before policy ever runs)
// remains the load-bearing first guard at the wire; this engine
// pin is the defence-in-depth.
func TestJobReadByIDPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadByIDOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_job_read_byid_revoked"},
		{"expired key", "sa_job_read_byid_expired"},
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

// TestJobReadByIDPolicyWrongOrganizationPrincipal pins the cross-
// tenant boundary for the bare-{job_id} fetch. Five of the six
// built-in roles must be denied with ReasonDeniedCrossTenant when
// the resource's organization id differs from the principal's home
// organization id. Support is the singular exception: the engine's
// clause
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)` allows Support to read across tenants and returns
// ReasonAllowedBySupport. This is the load-bearing distinction from
// the cross-tenant matrix for job.cancel / job.retry (CapDeploy —
// Support also denied at cross-tenant): one row flips from deny to
// allow at the cross-tenant boundary, and the engine-level pin
// prevents a future catalog change that downgraded job.read out of
// the CapRead+CapSupport exception (silently denying privileged
// Yalla support's ability to inspect provisioning jobs across
// tenants for incident response) or upgraded it past the exception
// (silently leaking cross-tenant job rows to a non-Support role).
//
// At the wire, a cross-tenant {job_id} that names a row in a
// foreign tenant will additionally be hidden by the row's
// org-scoped repository lookup — the resolver must not leak the
// existence of foreign rows to a non-Support principal. This engine
// pin is the policy-only guard; the wire 404-vs-403 distinction
// (treat foreign rows as not-found for non-Support roles) lives in
// the contract test for BE-0275 and is not in scope for this
// engine-level file.
func TestJobReadByIDPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := jobReadByIDOrgResource(orgB)

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

// TestJobReadByIDPolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for, and pins BOTH directions of the project-grant containment for
// the bare-{job_id} fetch:
//
//   - A project-level Viewer grant naming THIS project CAN authorize
//     job.read against a job owned by THIS project
//     (Kind=KindJob, Scope={org, project}). This is the shape the
//     bare-{job_id} resolver will construct when the looked-up job
//     row is owned by THIS project, and it proves a project-scoped
//     automation key can fetch by id any provisioning job under its
//     own project. The verdict is ReasonAllowedByGrant.
//   - The same project-level Viewer grant CANNOT reach a job owned
//     at the org root (Kind=KindJob, Scope={org} only — no project
//     narrowing). covers() is one-way: a deeper grant scope cannot
//     reach a shallower resource scope. The denial is
//     ReasonDeniedOutOfScope. This is what stops a project-scoped
//     key from fetching by id every job that lives at the
//     organization root.
//   - A project-level Viewer grant naming the SIBLING project
//     CANNOT authorize the fetch against a job owned by THIS
//     project — covers() is one-way and the grant's project does not
//     match the resource's project. The denial is
//     ReasonDeniedOutOfScope. This is the load-bearing AC "project-
//     level grants do not imply access to sibling projects".
//   - A project-level Support grant naming THIS project also
//     authorizes job.read at a THIS-project-owned job row — Support
//     holds CapRead, so the read path is allowed via the role's
//     capability set (the cross-tenant Support exception is a
//     separate, more-specific guard that applies only when
//     home_org != resource_org; here both are orgA, so the grant
//     path resolves through capability matching).
//   - A project-level CI grant naming THIS project also authorizes
//     job.read at a THIS-project-owned job row — CI holds CapRead,
//     so reading provisioning jobs from a pipeline is allowed.
//
// The deny-no-capability case (a role that lacks CapRead) is
// omitted here on purpose because all six built-in roles hold
// CapRead, so there is no first-class role to anchor it against.
// Custom roles can construct such a principal; the unknown/custom-
// role behavior is already pinned by policy_test.go
// TestDecideCustomRole.
func TestJobReadByIDPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetProjectScope := Scope{OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID}
	targetProjectJobResource := jobReadByIDProjectResource(orgA, canonicalJobReadByIDProjectID)
	siblingProjectJobResource := jobReadByIDProjectResource(orgA, canonicalJobReadByIDSiblingID)
	orgRootJobResource := jobReadByIDOrgResource(orgA)

	viewerGrant := Grant{Role: RoleViewer, Scope: targetProjectScope}
	supportGrant := Grant{Role: RoleSupport, Scope: targetProjectScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetProjectScope}

	t.Run("viewer on target project allows project owned job fetch", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies org rooted job fetch", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, orgRootJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("viewer on target project denies sibling project owned job fetch", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, siblingProjectJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("support on target project allows project owned job fetch", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_support_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{supportGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("ci on target project allows project owned job fetch", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRead, targetProjectJobResource), true, ReasonAllowedByGrant)
	})
}

// TestJobReadByIDPolicyEnvironmentGrantContainment proves environment-
// level grants do not imply access to production unless production
// is explicitly granted, and do not reach the shallower org-root or
// parent-project owned job rows at all. A staging-environment grant
// cannot escalate to fetching by id any provisioning job under the
// parent project or the parent organization — that would let a
// staging-scoped key enumerate jobs against sibling environments
// alongside staging, the precise leak the engine forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. So:
//
//   - env-staging grant denies job.read against an org-rooted job
//     row (Scope={org} only). ReasonDeniedOutOfScope.
//   - env-staging grant denies job.read against a parent-project-
//     owned job row (Scope={org, project}). ReasonDeniedOutOfScope.
//   - env-staging grant ALLOWS job.read against a staging-env-owned
//     job row (Scope={org, project, env_staging}) — covers() matches
//     because the grant scope equals the resource scope. This is
//     what the bare-{job_id} resolver will construct when the
//     looked-up row is owned by the staging env, and it proves the
//     env-scoped automation key path.
//   - env-staging grant denies job.read against a PRODUCTION-env-
//     owned job row (Scope={org, project, env_prod}). This is the
//     load-bearing AC "environment-level grants do not imply access
//     to production unless production is explicitly granted" — a
//     staging-scoped key cannot fetch by id any provisioning job
//     scoped to production.
//
// As a defence-in-depth pin, an env-scoped staging grant authorizing
// env.read against the production environment of the same project is
// also denied — staging never widens to production by accident, and
// the same containment underpins the job-read deny: a staging grant
// cannot inspect production jobs at any depth.
func TestJobReadByIDPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobReadByIDProjectResource(orgA, canonicalJobReadByIDProjectID)
	orgRootJobResource := jobReadByIDOrgResource(orgA)
	stagingJobResource := jobReadByIDEnvResource(orgA, canonicalJobReadByIDProjectID, "env_staging")
	productionJobResource := jobReadByIDEnvResource(orgA, canonicalJobReadByIDProjectID, "env_prod")

	envViewerGrantee := Principal{
		ID: "sa_env_viewer_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies org rooted job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant denies parent project owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant allows staging env owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, stagingJobResource),
			true, ReasonAllowedByGrant)
	})

	t.Run("staging grant denies production env owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envViewerGrantee, ActionJobRead, productionJobResource),
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

// TestJobReadByIDPolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources via the bare-{job_id}
// fetch. A service-scoped Viewer grant on svc_a:
//
//   - cannot authorize job.read on an org-rooted job row — that
//     would let a service-scoped key fetch by id every job in the
//     tenant, the exact "service grant exposes parent-level secrets
//     or unrelated services" escalation the acceptance criterion
//     forbids. ReasonDeniedOutOfScope.
//   - cannot authorize job.read on a parent-project-owned job row —
//     pinning the parent-project exposure boundary independently of
//     the org-root pin. ReasonDeniedOutOfScope.
//   - cannot authorize job.read on a parent-environment-owned job
//     row — pinning the parent-environment exposure boundary
//     independently of the parent-project pin, so a job that lives
//     at the env layer is invisible to a service-scoped key.
//     ReasonDeniedOutOfScope.
//   - cannot authorize env.read on the parent environment — pinning
//     the parent-environment exposure boundary independently of
//     job.read, so a future endpoint that authorized parent env.read
//     through a service grant would fail here before it could regress
//     a real customer.
//   - cannot authorize service.read on a sibling service in the same
//     parent environment — pinning the sibling-service boundary
//     independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
//   - cannot authorize job.read on a SIBLING-service-owned job row
//     in the same parent environment — the destructive-by-omission
//     case: a job owned by svc_b is fetched by id by a key scoped to
//     svc_a only, and the engine must refuse even though both
//     services share an env and a project. ReasonDeniedOutOfScope.
//   - CAN authorize job.read on a job owned by its own service
//     ({org, project, env, svc_a}) — covers() matches because the
//     grant scope equals the resource scope. This is what the bare-
//     {job_id} resolver will construct when the looked-up row is
//     owned by svc_a, and proves the service-scoped automation key
//     path stays usable inside its own service.
func TestJobReadByIDPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobReadByIDProjectResource(orgA, canonicalJobReadByIDProjectID)
	orgRootJobResource := jobReadByIDOrgResource(orgA)
	parentEnvJobResource := jobReadByIDEnvResource(orgA, canonicalJobReadByIDProjectID, "env_prod")
	svcAJobResource := jobReadByIDServiceResource(orgA, canonicalJobReadByIDProjectID, "env_prod", "svc_a")
	svcBJobResource := jobReadByIDServiceResource(orgA, canonicalJobReadByIDProjectID, "env_prod", "svc_b")

	svcGrantee := Principal{
		ID: "sa_svc_viewer_byid", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleViewer, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies org rooted job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent project owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent env owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, parentEnvJobResource),
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

	t.Run("service scoped grant denies sibling service owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, svcBJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant allows own service owned job fetch", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRead, svcAJobResource),
			true, ReasonAllowedByGrant)
	})
}

// TestJobReadByIDPolicyOrgGrantCapabilityMatrix pins the capability
// admission for organization-level grants against job.read on the
// bare-{job_id} fetch. An organization-level grant covers any
// resource within the same org by construction (covers() with an
// empty ProjectID matches any project; equally so for the empty
// environment and service fields), so this case isolates the role
// capability from the grant scope: the scope is sufficient at every
// depth, the role's capability set is what decides.
//
// Every built-in role holds CapRead, so org-level grants for any of
// the six roles allow job.read at the canonical org-rooted bare-id
// resource. This is the load-bearing distinction from the org-grant
// capability matrix for job.cancel / job.retry (Viewer and Support
// denied via ReasonDeniedNoCapability): for job.read, the Viewer and
// Support rows flip to allow, and the engine-level pin would catch a
// future catalog change that upgraded job.read to CapDeploy
// (silently denying every org-level Viewer/Support grantee that
// fetches a provisioning job by id) before it could regress a real
// customer. CI and Developer are pinned alongside Viewer and Support
// so the matrix proves the entire CapRead set, not just the load-
// bearing rows.
func TestJobReadByIDPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadByIDOrgResource(orgA)
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
				ID: "sa_org_byid_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionJobRead, resource), true, ReasonAllowedByGrant)
		})
	}
}

// TestJobReadByIDPolicyForeignHomeOrgGrant pins the cross-tenant
// guard on the grant path for the bare-{job_id} fetch. A project-
// scoped Viewer grant for canonicalJobReadByIDProjectID inside orgA,
// carried by a principal whose home org is orgB, cannot be used to
// authorize job.read against a resource in orgB. The resource here
// is in orgB and the principal home is orgB, so the cross-tenant
// guard does NOT fire. Then the grant path is consulted, but the
// grant's Scope.OrganizationID is orgA while the principal's home
// org is orgB, so the engine's grant filter
// `g.Scope.OrganizationID != principal.OrganizationID` skips the
// grant entirely. With no usable grant and no organization role
// (the principal is a ServiceAccount with grants only), the verdict
// is ReasonDeniedNoCapability.
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
func TestJobReadByIDPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobReadByIDProjectResource(orgB, canonicalJobReadByIDProjectID)
	foreignGrant := Grant{
		Role:  RoleViewer,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalJobReadByIDProjectID},
	}
	p := Principal{
		ID: "sa_stolen_read_byid", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionJobRead, resource), false, ReasonDeniedNoCapability)
}
