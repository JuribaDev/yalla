package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action job.cancel (BE-0282).
// The wire endpoint POST /v1/jobs/{job_id}/cancel and its contract
// tests have not landed yet; this file pins the authorization
// contract job.cancel must satisfy regardless of which endpoint
// surfaces it, mirroring the engine-only precedent BE-0273
// established for the GET /v1/jobs list variant, BE-0276 for the
// GET /v1/jobs/{job_id} bare-id fetch variant, and BE-0279 for the
// POST /v1/jobs/{job_id}/retry sibling deploy-class verb. The same
// engine-only pin precedent that holds for previews and the two
// job-read variants holds here.
//
// job.cancel is catalogued as CapDeploy (catalog.go: ActionJobCancel
// -> CapDeploy), the same capability class as job.retry,
// deployment.create, deployment.cancel, deployment.rollback,
// backup.run, service.restart, service.start, service.stop,
// preview.create, and preview.delete. The role matrix for a
// principal acting on its own organization therefore splits along
// the deploy capability class: Owner/Admin/Developer/CI hold
// CapDeploy and are allowed (ReasonAllowedByRole); Viewer/Support do
// not hold CapDeploy and are denied (ReasonDeniedNoCapability). This
// is the load-bearing distinction from job.read (CapRead — six-row
// allow including Viewer and Support) and from environment.create
// (CapWrite — three-role split without CI): CI cancels a stuck
// provisioning job from a pipeline (e.g. when the pipeline itself is
// being aborted) but does not write desired state; Support reads
// provisioning history widely but never aborts a mutating Dokploy
// call in flight. Crucially, the engine's cross-tenant support
// exception is gated on `required == CapRead || required ==
// CapSupport`, so CapDeploy is OUTSIDE that exception — privileged
// Yalla support that needs to cancel a customer's stuck provisioning
// job must go through explicit break-glass admin tooling, never
// this customer-facing action. Pinning the support cross-tenant
// DENY here is what keeps a future cross-tenant variant safe by
// default and prevents a misused support token from aborting
// in-flight provisioning work against the wrong tenant.
//
// The route the wire endpoint will register is bare-{job_id} under
// the organization (POST /v1/jobs/{job_id}/cancel has no parent
// project, environment, or service in the path). The {job_id} path
// segment is a routing artefact — which row to cancel — not the
// policy boundary. The policy boundary is the JOB ROW'S OWNING
// SCOPE, which the resolver looks up before deciding: a job owned
// by the org root resolves into Resource{Kind=KindJob, Scope={org}};
// a job owned by a project resolves into Resource{Kind=KindJob,
// Scope={org, project}}; a job owned by an environment resolves
// into Resource{Kind=KindJob, Scope={org, project, env}}; a job
// owned by a service resolves into Resource{Kind=KindJob, Scope=
// {org, project, env, svc}}. The grant-containment cases below pin
// every one of these owning-scope shapes so a future endpoint
// regression that collapsed every job's owning scope to the org
// root (silently allowing every project-, env-, or service-scoped
// CI key to cancel any job in the tenant) or that lifted the owning
// scope to the {job_id} segment alone (a shape Scope cannot
// represent and which would bypass project/env/svc containment)
// fails one of the cases here. For a mutating verb that aborts a
// Dokploy provisioning call in flight, this containment matrix is
// even more load-bearing than for the read variants: a misrouted
// cancel can leave the wrong tenant's desired-state partially
// applied at Dokploy or terminate a healthy production deploy by
// accident, and the engine-level pin is the only thing that holds
// when a future wire-level resolver regression silently collapses
// the owning scope.

// canonicalJobCancelProjectID and canonicalJobCancelSiblingID are
// the canonical project ids the job-cancel containment matrix
// evaluates against. The ids are deliberately recognisable so a
// future leak guard in a wire-level test for the endpoint can needle
// for them, and deliberately distinct from canonicalJobReadProjectID
// / canonicalJobReadByIDProjectID / canonicalJobRetryProjectID
// (used by the three sibling job engine files) so the read, retry,
// and cancel matrices cannot accidentally share state through a
// future shared helper.
const (
	canonicalJobCancelProjectID = "prj_jobs_cancel_matrix_alpha"
	canonicalJobCancelSiblingID = "prj_jobs_cancel_matrix_beta"
)

// jobCancelOrgResource builds the policy resource the bare-{job_id}
// cancel resolver would construct for a POST /v1/jobs/{job_id}/cancel
// call whose principal home organization is org and whose target row
// is owned at the org root (no parent project, environment, or
// service). The Kind is KindJob and only OrganizationID is pinned:
// the resolver reflects the job row's actual owning scope, and an
// org-rooted job row has no narrower owning scope to reflect.
func jobCancelOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org},
	}
}

// jobCancelProjectResource builds the policy resource the bare-
// {job_id} cancel resolver would construct for a job row owned by a
// project. A project-scoped grant naming that project can satisfy
// it; an org-level role (or org-level grant) for the same tenant
// can also satisfy it via covers() because the grant scope leaves
// the project field empty.
func jobCancelProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// jobCancelEnvResource builds the policy resource the bare-{job_id}
// cancel resolver would construct for a job row owned by an
// environment. An env-scoped grant naming that env can satisfy it;
// a project-scoped grant naming the parent project also satisfies
// it via covers() because the grant scope leaves the env field
// empty.
func jobCancelEnvResource(org, projectID, envID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID},
	}
}

// jobCancelServiceResource builds the policy resource the bare-
// {job_id} cancel resolver would construct for a job row owned by a
// service. A service-scoped grant naming that service can satisfy
// it; an env- or project-scoped grant naming a parent of the
// service also satisfies it via covers() because the grant scope
// leaves the deeper fields empty.
func jobCancelServiceResource(org, projectID, envID, svcID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID, ServiceID: svcID},
	}
}

// TestJobCancelPolicyMatrixRoles drives every built-in role through
// the engine against the canonical bare-{job_id} cancel resource
// owned at the org root in the principal's own organization.
// CapDeploy splits the matrix: Owner/Admin/Developer/CI hold
// CapDeploy and are allowed (ReasonAllowedByRole); Viewer/Support do
// not hold CapDeploy and are denied (ReasonDeniedNoCapability). The
// case names mirror PRD BE-0282 ("owner, admin, developer, viewer,
// ci, support"). The verdict is pinned alongside the reason so a
// catalog or builtinRoleCaps regression that downgraded job.cancel
// to CapRead would fail here (silently allowing every Viewer/Support
// to abort in-flight provisioning work — a mutating Dokploy side
// effect dressed up as a "lifecycle" verb) and an upgrade to
// CapWrite would also fail here (silently denying CI, which is the
// canonical principal for cancelling a transient provisioning job
// from a pipeline that is itself being aborted).
func TestJobCancelPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobCancelOrgResource(orgA)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobCancel, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestJobCancelPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal —
// is denied action job.cancel, even when the underlying role would
// have allowed it. The underlying role is Owner so a working
// credential WOULD allow job.cancel; Disabled is the only thing in
// the way and must be load-bearing. The case names mirror PRD
// BE-0282 ("revoked key, expired key"). The deny reason is
// ReasonDeniedPrincipalDisabled — the engine's first-line check
// fires before the catalog lookup, so an action that is not even
// catalogued would still surface this exact reason for a disabled
// principal. The auth layer's reject-before-policy posture for
// revoked keys (the API layer 401s before policy ever runs) remains
// the load-bearing first guard at the wire; this engine pin is the
// defence-in-depth. The mutating verb makes this pin especially
// load-bearing: a stale CI key whose lease has expired must never
// be able to abort an in-flight provisioning call enqueued by a
// later, healthy CI run — the same defence-in-depth that
// preview.delete required for the destructive teardown verb and
// job.retry required for the destructive re-issue verb applies
// here for the destructive abort verb.
func TestJobCancelPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobCancelOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_job_cancel_revoked"},
		{"expired key", "sa_job_cancel_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionJobCancel, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestJobCancelPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for job.cancel. Every built-in role —
// including Support — must be denied with ReasonDeniedCrossTenant
// when the resource's organization id differs from the principal's
// home organization id. CapDeploy is OUTSIDE the engine's support
// cross-tenant exception (the clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`), so a Support principal of org_yalla authorizing
// job.cancel against an org_victim resource is DENIED — privileged
// Yalla support that needs to cancel a customer's stuck
// provisioning job must go through explicit break-glass admin
// tooling, never this customer-facing action.
//
// This is the load-bearing distinction from the cross-tenant matrix
// for job.read (CapRead — Support is allowed via
// ReasonAllowedBySupport): one row flips from allow to deny at the
// cross-tenant boundary, and the engine-level pin prevents a future
// endpoint that constructed a resource with a foreign-org scope
// from silently leaking deploy authority across tenants. For a
// mutating verb that aborts a Dokploy provisioning call in flight,
// the cross-tenant guard is even more load-bearing than for read: a
// misrouted cancel can interrupt a healthy production deploy in the
// wrong tenant midway through its rollout, an upstream side-effect
// that no in-Yalla rollback can cleanly undo without resubmitting
// the partially-applied desired-state change.
//
// At the wire, a cross-tenant {job_id} that names a row in a
// foreign tenant will additionally be hidden by the row's
// org-scoped repository lookup — the resolver must not leak the
// existence of foreign rows. This engine pin is the policy-only
// guard; the wire 404-vs-403 distinction (treat foreign rows as
// not-found for every non-Support role, and even for Support keep
// it not-found at this customer-facing endpoint because Support
// must use admin break-glass to mutate cross-tenant) lives in the
// contract test for the wire endpoint and is not in scope for this
// engine-level file.
func TestJobCancelPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := jobCancelOrgResource(orgB)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobCancel, foreign)
			assertDecision(t, got, false, ReasonDeniedCrossTenant)
		})
	}
}

// TestJobCancelPolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for, and pins BOTH directions of the project-grant containment
// for the bare-{job_id} cancel:
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     job.cancel against a job owned by THIS project
//     (Kind=KindJob, Scope={org, project}). This is the shape the
//     bare-{job_id} cancel resolver will construct when the looked-
//     up job row is owned by THIS project, and it proves a project-
//     scoped automation key can cancel any provisioning job under
//     its own project. The verdict is ReasonAllowedByGrant.
//   - The same project-level Admin grant CANNOT reach a job owned
//     at the org root (Kind=KindJob, Scope={org} only — no project
//     narrowing). covers() is one-way: a deeper grant scope cannot
//     reach a shallower resource scope. The denial is
//     ReasonDeniedOutOfScope. This is what stops a project-scoped
//     key from cancelling every job that lives at the organization
//     root.
//   - A project-level Admin grant naming the SIBLING project
//     CANNOT authorize the cancel against a job owned by THIS
//     project — covers() is one-way and the grant's project does
//     not match the resource's project. The denial is
//     ReasonDeniedOutOfScope. This is the load-bearing AC "project-
//     level grants do not imply access to sibling projects". For a
//     mutating verb this pin is especially load-bearing: a key
//     scoped to prj_alpha must never be able to cancel a job that
//     belongs to prj_beta just because the wire endpoint happens to
//     accept the sibling's {job_id} on the path.
//   - A project-level CI grant naming THIS project also authorizes
//     job.cancel — CI is the canonical principal for aborting an
//     in-flight provisioning call from a pipeline that is itself
//     being cancelled, so the CI-grants-by-project case is pinned
//     explicitly.
//   - A project-level Viewer grant naming THIS project is denied
//     ReasonDeniedNoCapability — Viewer does NOT hold CapDeploy.
//     The grant's scope covers the resource; the grant role's
//     capability set does not. This pins the CapDeploy requirement
//     against the project-grant path so a future catalog change
//     that downgraded job.cancel to CapRead would fail here
//     (silently allowing every project-scoped Viewer grantee to
//     abort provisioning calls) before it could regress a real
//     customer.
func TestJobCancelPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID}
	targetProjectJobResource := jobCancelProjectResource(orgA, canonicalJobCancelProjectID)
	siblingProjectJobResource := jobCancelProjectResource(orgA, canonicalJobCancelSiblingID)
	orgRootJobResource := jobCancelOrgResource(orgA)

	adminGrant := Grant{Role: RoleAdmin, Scope: targetScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetScope}
	viewerGrant := Grant{Role: RoleViewer, Scope: targetScope}

	t.Run("admin on target project allows project owned job cancel", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobCancel, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("admin on target project denies org rooted job cancel", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobCancel, orgRootJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("admin on target project denies sibling project owned job cancel", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobCancel, siblingProjectJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("ci on target project allows project owned job cancel", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobCancel, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobCancel, targetProjectJobResource), false, ReasonDeniedNoCapability)
	})
}

// TestJobCancelPolicyEnvironmentGrantContainment proves environment-
// level grants do not imply access to production unless production
// is explicitly granted, and do not reach the shallower org-root or
// parent-project owned job rows at all. A staging-environment grant
// cannot escalate to cancelling any provisioning job under the
// parent project or the parent organization — that would let a
// staging-scoped key abort mutating Dokploy work against sibling
// environments alongside staging, the precise leak the engine
// forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. So:
//
//   - env-staging Admin grant denies job.cancel against an org-rooted
//     job row (Scope={org} only). ReasonDeniedOutOfScope.
//   - env-staging Admin grant denies job.cancel against a parent-
//     project-owned job row (Scope={org, project}).
//     ReasonDeniedOutOfScope.
//   - env-staging Admin grant ALLOWS job.cancel against a staging-
//     env-owned job row (Scope={org, project, env_staging}) —
//     covers() matches because the grant scope equals the resource
//     scope. This is what the bare-{job_id} cancel resolver will
//     construct when the looked-up row is owned by the staging env,
//     and it proves the env-scoped automation key path. Admin holds
//     CapDeploy so the verdict is ReasonAllowedByGrant.
//   - env-staging Admin grant DENIES job.cancel against a PRODUCTION-
//     env-owned job row (Scope={org, project, env_prod}). This is
//     the load-bearing AC "environment-level grants do not imply
//     access to production unless production is explicitly granted"
//     — a staging-scoped key cannot cancel any provisioning job
//     scoped to production, the precise side-effect leak the
//     destructive-verb framing forbids.
//
// As a defence-in-depth pin, an env-scoped staging grant authorizing
// env.write against the production environment of the same project
// is also denied — staging never widens to production by accident,
// and the same containment underpins the job-cancel deny: a staging
// grant cannot abort production at any depth.
func TestJobCancelPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobCancelProjectResource(orgA, canonicalJobCancelProjectID)
	orgRootJobResource := jobCancelOrgResource(orgA)
	stagingJobResource := jobCancelEnvResource(orgA, canonicalJobCancelProjectID, "env_staging")
	productionJobResource := jobCancelEnvResource(orgA, canonicalJobCancelProjectID, "env_prod")

	envAdminGrantee := Principal{
		ID: "sa_env_admin_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies org rooted job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobCancel, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant denies parent project owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobCancel, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant allows staging env owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobCancel, stagingJobResource),
			true, ReasonAllowedByGrant)
	})

	t.Run("staging grant denies production env owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobCancel, productionJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("staging grant denies production env write", func(t *testing.T) {
		t.Parallel()
		productionResource := Resource{Kind: domain.KindEnvironment, Scope: productionScope}
		got := e.Decide(envAdminGrantee, ActionEnvWrite, productionResource)
		if got.Allow {
			t.Fatalf("decision = %+v, want deny — a staging env grant must not widen to production write", got)
		}
	})
}

// TestJobCancelPolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources via the bare-{job_id}
// cancel. A service-scoped Admin grant on svc_a:
//
//   - cannot authorize job.cancel on an org-rooted job row — that
//     would let a service-scoped key cancel every job in the tenant,
//     the exact "service grant exposes parent-level secrets or
//     unrelated services" escalation the acceptance criterion
//     forbids. ReasonDeniedOutOfScope.
//   - cannot authorize job.cancel on a parent-project-owned job row —
//     pinning the parent-project exposure boundary independently of
//     the org-root pin. ReasonDeniedOutOfScope.
//   - cannot authorize job.cancel on a parent-environment-owned job
//     row — pinning the parent-environment exposure boundary
//     independently of the parent-project pin, so a job that lives
//     at the env layer is invisible to a service-scoped key.
//     ReasonDeniedOutOfScope.
//   - cannot authorize env.write on the parent environment —
//     pinning the parent-environment exposure boundary independently
//     of job.cancel, so a future endpoint that authorized parent
//     env.write through a service grant would fail here before it
//     could regress a real customer.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service boundary
//     independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
//   - cannot authorize job.cancel on a SIBLING-service-owned job row
//     in the same parent environment — the destructive-by-omission
//     case: a job owned by svc_b is cancelled by a key scoped to
//     svc_a only, and the engine must refuse even though both
//     services share an env and a project. ReasonDeniedOutOfScope.
//   - CAN authorize job.cancel on a job owned by its own service
//     ({org, project, env, svc_a}) — covers() matches because the
//     grant scope equals the resource scope. This is what the bare-
//     {job_id} cancel resolver will construct when the looked-up row
//     is owned by svc_a, and proves the service-scoped automation
//     key path stays usable inside its own service.
func TestJobCancelPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobCancelProjectResource(orgA, canonicalJobCancelProjectID)
	orgRootJobResource := jobCancelOrgResource(orgA)
	parentEnvJobResource := jobCancelEnvResource(orgA, canonicalJobCancelProjectID, "env_prod")
	svcAJobResource := jobCancelServiceResource(orgA, canonicalJobCancelProjectID, "env_prod", "svc_a")
	svcBJobResource := jobCancelServiceResource(orgA, canonicalJobCancelProjectID, "env_prod", "svc_b")

	svcGrantee := Principal{
		ID: "sa_svc_admin_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies org rooted job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobCancel, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent project owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobCancel, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent env owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobCancel, parentEnvJobResource),
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

	t.Run("service scoped grant denies sibling service owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobCancel, svcBJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant allows own service owned job cancel", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobCancel, svcAJobResource),
			true, ReasonAllowedByGrant)
	})
}

// TestJobCancelPolicyOrgGrantCapabilityMatrix pins the capability
// split for organization-level grants against job.cancel. An
// organization-level grant covers any resource within the same org
// by construction (covers() with an empty ProjectID matches any
// project; equally so for the empty environment and service fields),
// so this case isolates the role capability from the grant scope:
// the scope is sufficient at every depth, the role's capability set
// is what decides.
//
//   - Org-level CI grant: scope OK, CI holds CapDeploy — allowed
//     (ReasonAllowedByGrant). CI is the canonical principal for
//     aborting an in-flight provisioning job from a pipeline at
//     organization scope.
//   - Org-level Developer grant: scope OK, Developer holds CapDeploy
//     — allowed (ReasonAllowedByGrant).
//   - Org-level Viewer grant: scope OK, Viewer does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). This pins the
//     CapDeploy requirement against the org-grant path so a future
//     catalog change that downgraded job.cancel to CapRead would
//     fail here (silently allowing every org-level Viewer grantee
//     to abort mutating provisioning calls) before it could
//     regress a real customer.
//   - Org-level Support grant: scope OK, Support does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). Support reads
//     provisioning history widely but never aborts a mutating
//     Dokploy call in flight; this is the load-bearing distinction
//     between job.read (Support allowed) and job.cancel (Support
//     denied) at the org-grant path, mirroring the role matrix
//     denial above. The mutating verb makes this pin especially
//     load-bearing: a stolen or misused support token must never
//     be able to interrupt a destructive provisioning side-effect
//     against the wrong resource.
func TestJobCancelPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobCancelOrgResource(orgA)
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
				ID: "sa_org_cancel_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionJobCancel, resource), tc.allow, tc.reason)
		})
	}
}

// TestJobCancelPolicyForeignHomeOrgGrant pins the cross-tenant guard
// on the grant path. A project-scoped Admin grant for
// canonicalJobCancelProjectID inside orgA, carried by a principal
// whose home org is orgB, cannot be used to authorize job.cancel
// against a resource in orgB. The cross-tenant resource-vs-home
// guard does NOT fire here because the resource org id (orgB)
// equals the principal home org id (orgB); the grant path is
// consulted instead, but the grant's Scope.OrganizationID is orgA
// while the principal's home org is orgB, so the engine's grant
// filter `g.Scope.OrganizationID != principal.OrganizationID` skips
// the grant entirely. With no usable grant and no organization
// role (the principal is a ServiceAccount with grants only), the
// verdict is ReasonDeniedNoCapability.
//
// This is the engine-level twin of the wire-level "stolen scoped
// key" property: a scoped grant minted for one tenant cannot be
// carried by a principal whose home tenant is another, so theft of
// a key cannot smuggle destructive deploy authority across tenants
// even if the foreign project_id happens to exist on the path. For
// a mutating verb that aborts a Dokploy provisioning call in
// flight, this guard is what stops an exfiltrated grant from being
// used to interrupt desired-state changes in the wrong organization
// — a side-effect incident at the upstream provisioner that would
// otherwise be indistinguishable from a legitimate cancel until the
// customer noticed the unexpected provisioning interruption.
// CapDeploy is OUTSIDE the cross-tenant Support exception, so there
// is no catalog row that could rescue the verdict on this path.
func TestJobCancelPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobCancelProjectResource(orgB, canonicalJobCancelProjectID)
	foreignGrant := Grant{
		Role:  RoleAdmin,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalJobCancelProjectID},
	}
	p := Principal{
		ID: "sa_stolen_cancel", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionJobCancel, resource), false, ReasonDeniedNoCapability)
}
