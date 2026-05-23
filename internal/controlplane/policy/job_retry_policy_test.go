package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Engine-level policy-matrix coverage for action job.retry (BE-0279).
// The wire endpoint POST /v1/jobs/{job_id}/retry (BE-0277) and its
// contract tests (BE-0278) have not landed yet; this file pins the
// authorization contract job.retry must satisfy regardless of which
// endpoint surfaces it, mirroring the engine-only precedent BE-0273
// established for the GET /v1/jobs list variant and BE-0276 for the
// GET /v1/jobs/{job_id} bare-id fetch variant. The same engine-only
// pin precedent that holds for previews (preview_read/create/delete)
// and the two job-read variants holds here.
//
// job.retry is catalogued as CapDeploy (catalog.go: ActionJobRetry ->
// CapDeploy), the same capability class as job.cancel,
// deployment.create, deployment.cancel, deployment.rollback,
// backup.run, service.restart, service.start, service.stop,
// preview.create, and preview.delete. The role matrix for a
// principal acting on its own organization therefore splits along
// the deploy capability class: Owner/Admin/Developer/CI hold
// CapDeploy and are allowed (ReasonAllowedByRole); Viewer/Support do
// not hold CapDeploy and are denied (ReasonDeniedNoCapability). This
// is the load-bearing distinction from job.read (CapRead — six-row
// allow including Viewer and Support) and from environment.create
// (CapWrite — three-role split without CI): CI re-runs a failed
// provisioning job from a pipeline but does not write desired state;
// Support reads provisioning history widely but never re-issues a
// mutating Dokploy call by retrying a job. Crucially, the engine's
// cross-tenant support exception is gated on
// `required == CapRead || required == CapSupport`, so CapDeploy is
// OUTSIDE that exception — privileged Yalla support that needs to
// retry a customer's stuck provisioning job must go through explicit
// break-glass admin tooling, never this customer-facing action.
// Pinning the support cross-tenant DENY here is what keeps a future
// cross-tenant variant safe by default and prevents a misused
// support token from re-issuing mutating Dokploy work against the
// wrong tenant.
//
// The route the wire endpoint will register is bare-{job_id} under
// the organization (POST /v1/jobs/{job_id}/retry has no parent
// project, environment, or service in the path). The {job_id} path
// segment is a routing artefact — which row to retry — not the
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
// CI key to retry any job in the tenant) or that lifted the owning
// scope to the {job_id} segment alone (a shape Scope cannot
// represent and which would bypass project/env/svc containment)
// fails one of the cases here. For a mutating verb that re-issues
// a Dokploy provisioning call, this containment matrix is even
// more load-bearing than for the read variants: a misrouted retry
// can replay a destructive desired-state change against the wrong
// tenant, project, environment, or service, and an unintended
// cross-tenant retry is an unrecoverable side-effect at Dokploy,
// not just an unauthorised list/fetch.

// canonicalJobRetryProjectID and canonicalJobRetrySiblingID are the
// canonical project ids the job-retry containment matrix evaluates
// against. The ids are deliberately recognisable so a future leak
// guard in a wire-level test for the endpoint can needle for them,
// and deliberately distinct from canonicalJobReadProjectID /
// canonicalJobReadByIDProjectID (used by the two job-read engine
// files) so the read and retry matrices cannot accidentally share
// state through a future shared helper.
const (
	canonicalJobRetryProjectID = "prj_jobs_retry_matrix_alpha"
	canonicalJobRetrySiblingID = "prj_jobs_retry_matrix_beta"
)

// jobRetryOrgResource builds the policy resource the bare-{job_id}
// retry resolver would construct for a POST /v1/jobs/{job_id}/retry
// call whose principal home organization is org and whose target row
// is owned at the org root (no parent project, environment, or
// service). The Kind is KindJob and only OrganizationID is pinned:
// the resolver reflects the job row's actual owning scope, and an
// org-rooted job row has no narrower owning scope to reflect.
func jobRetryOrgResource(org string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org},
	}
}

// jobRetryProjectResource builds the policy resource the bare-
// {job_id} retry resolver would construct for a job row owned by a
// project. A project-scoped grant naming that project can satisfy
// it; an org-level role (or org-level grant) for the same tenant
// can also satisfy it via covers() because the grant scope leaves
// the project field empty.
func jobRetryProjectResource(org, projectID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID},
	}
}

// jobRetryEnvResource builds the policy resource the bare-{job_id}
// retry resolver would construct for a job row owned by an
// environment. An env-scoped grant naming that env can satisfy it;
// a project-scoped grant naming the parent project also satisfies
// it via covers() because the grant scope leaves the env field
// empty.
func jobRetryEnvResource(org, projectID, envID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID},
	}
}

// jobRetryServiceResource builds the policy resource the bare-
// {job_id} retry resolver would construct for a job row owned by a
// service. A service-scoped grant naming that service can satisfy
// it; an env- or project-scoped grant naming a parent of the
// service also satisfies it via covers() because the grant scope
// leaves the deeper fields empty.
func jobRetryServiceResource(org, projectID, envID, svcID string) Resource {
	return Resource{
		Kind:  domain.KindJob,
		Scope: Scope{OrganizationID: org, ProjectID: projectID, EnvironmentID: envID, ServiceID: svcID},
	}
}

// TestJobRetryPolicyMatrixRoles drives every built-in role through
// the engine against the canonical bare-{job_id} retry resource
// owned at the org root in the principal's own organization.
// CapDeploy splits the matrix: Owner/Admin/Developer/CI hold
// CapDeploy and are allowed (ReasonAllowedByRole); Viewer/Support do
// not hold CapDeploy and are denied (ReasonDeniedNoCapability). The
// case names mirror PRD BE-0279 ("owner, admin, developer, viewer,
// ci, support"). The verdict is pinned alongside the reason so a
// catalog or builtinRoleCaps regression that downgraded job.retry to
// CapRead would fail here (silently allowing every Viewer/Support to
// re-issue a failed provisioning job — a mutating Dokploy side
// effect dressed up as a "lifecycle" verb) and an upgrade to
// CapWrite would also fail here (silently denying CI, which is the
// canonical principal for automatically retrying a transient
// provisioning failure from a pipeline).
func TestJobRetryPolicyMatrixRoles(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobRetryOrgResource(orgA)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobRetry, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

// TestJobRetryPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal —
// is denied action job.retry, even when the underlying role would
// have allowed it. The underlying role is Owner so a working
// credential WOULD allow job.retry; Disabled is the only thing in
// the way and must be load-bearing. The case names mirror PRD
// BE-0279 ("revoked key, expired key"). The deny reason is
// ReasonDeniedPrincipalDisabled — the engine's first-line check
// fires before the catalog lookup, so an action that is not even
// catalogued would still surface this exact reason for a disabled
// principal. The auth layer's reject-before-policy posture for
// revoked keys (the API layer 401s before policy ever runs) remains
// the load-bearing first guard at the wire; this engine pin is the
// defence-in-depth. The mutating verb makes this pin especially
// load-bearing: a stale CI key whose lease has expired must never
// be able to re-issue a mutating Dokploy provisioning call by
// retrying a job a later, healthy CI run already enqueued — the
// same defence-in-depth that preview.delete required for the
// destructive teardown verb applies here for the destructive
// re-issue verb.
func TestJobRetryPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobRetryOrgResource(orgA)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_job_retry_revoked"},
		{"expired key", "sa_job_retry_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := principalIn(orgA, RoleOwner)
			p.ID = tc.id
			p.Kind = domain.KindServiceAccount
			p.Disabled = true
			got := e.Decide(p, ActionJobRetry, resource)
			assertDecision(t, got, false, ReasonDeniedPrincipalDisabled)
		})
	}
}

// TestJobRetryPolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for job.retry. Every built-in role — including Support —
// must be denied with ReasonDeniedCrossTenant when the resource's
// organization id differs from the principal's home organization id.
// CapDeploy is OUTSIDE the engine's support cross-tenant exception
// (the clause is `roleCaps.has(CapSupport) && (required == CapRead
// || required == CapSupport)`), so a Support principal of
// org_yalla authorizing job.retry against an org_victim resource is
// DENIED — privileged Yalla support that needs to re-run a customer's
// stuck provisioning job must go through explicit break-glass admin
// tooling, never this customer-facing action.
//
// This is the load-bearing distinction from the cross-tenant matrix
// for job.read (CapRead — Support is allowed via
// ReasonAllowedBySupport): one row flips from allow to deny at the
// cross-tenant boundary, and the engine-level pin prevents a future
// endpoint that constructed a resource with a foreign-org scope
// from silently leaking deploy authority across tenants. For a
// mutating verb that re-issues a Dokploy provisioning call, the
// cross-tenant guard is even more load-bearing than for read: a
// misrouted retry can replay a destructive desired-state change
// against the wrong tenant, an unrecoverable side-effect at the
// upstream provisioner that no in-Yalla rollback can undo.
//
// At the wire, a cross-tenant {job_id} that names a row in a
// foreign tenant will additionally be hidden by the row's
// org-scoped repository lookup — the resolver must not leak the
// existence of foreign rows. This engine pin is the policy-only
// guard; the wire 404-vs-403 distinction (treat foreign rows as
// not-found for every non-Support role, and even for Support keep
// it not-found at this customer-facing endpoint because Support
// must use admin break-glass to mutate cross-tenant) lives in the
// contract test for BE-0278 and is not in scope for this engine-
// level file.
func TestJobRetryPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	foreign := jobRetryOrgResource(orgB)

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
			got := e.Decide(principalIn(orgA, tc.role), ActionJobRetry, foreign)
			assertDecision(t, got, false, ReasonDeniedCrossTenant)
		})
	}
}

// TestJobRetryPolicyProjectGrantContainment proves project-level
// grants cannot be widened past the project scope they were issued
// for, and pins BOTH directions of the project-grant containment
// for the bare-{job_id} retry:
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     job.retry against a job owned by THIS project
//     (Kind=KindJob, Scope={org, project}). This is the shape the
//     bare-{job_id} retry resolver will construct when the looked-
//     up job row is owned by THIS project, and it proves a project-
//     scoped automation key can retry any provisioning job under
//     its own project. The verdict is ReasonAllowedByGrant.
//   - The same project-level Admin grant CANNOT reach a job owned
//     at the org root (Kind=KindJob, Scope={org} only — no project
//     narrowing). covers() is one-way: a deeper grant scope cannot
//     reach a shallower resource scope. The denial is
//     ReasonDeniedOutOfScope. This is what stops a project-scoped
//     key from retrying every job that lives at the organization
//     root.
//   - A project-level Admin grant naming the SIBLING project
//     CANNOT authorize the retry against a job owned by THIS
//     project — covers() is one-way and the grant's project does
//     not match the resource's project. The denial is
//     ReasonDeniedOutOfScope. This is the load-bearing AC "project-
//     level grants do not imply access to sibling projects". For a
//     mutating verb this pin is especially load-bearing: a key
//     scoped to prj_alpha must never be able to retry a job that
//     belongs to prj_beta just because the wire endpoint happens to
//     accept the sibling's {job_id} on the path.
//   - A project-level CI grant naming THIS project also authorizes
//     job.retry — CI is the canonical principal for automating
//     retries of transient provisioning failures from a pipeline,
//     so the CI-grants-by-project case is pinned explicitly.
//   - A project-level Viewer grant naming THIS project is denied
//     ReasonDeniedNoCapability — Viewer does NOT hold CapDeploy.
//     The grant's scope covers the resource; the grant role's
//     capability set does not. This pins the CapDeploy requirement
//     against the project-grant path so a future catalog change
//     that downgraded job.retry to CapRead would fail here
//     (silently allowing every project-scoped Viewer grantee to
//     re-issue provisioning calls) before it could regress a real
//     customer.
func TestJobRetryPolicyProjectGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	targetScope := Scope{OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID}
	targetProjectJobResource := jobRetryProjectResource(orgA, canonicalJobRetryProjectID)
	siblingProjectJobResource := jobRetryProjectResource(orgA, canonicalJobRetrySiblingID)
	orgRootJobResource := jobRetryOrgResource(orgA)

	adminGrant := Grant{Role: RoleAdmin, Scope: targetScope}
	ciGrant := Grant{Role: RoleCI, Scope: targetScope}
	viewerGrant := Grant{Role: RoleViewer, Scope: targetScope}

	t.Run("admin on target project allows project owned job retry", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRetry, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("admin on target project denies org rooted job retry", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRetry, orgRootJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("admin on target project denies sibling project owned job retry", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_admin_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{adminGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRetry, siblingProjectJobResource), false, ReasonDeniedOutOfScope)
	})

	t.Run("ci on target project allows project owned job retry", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_ci_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{ciGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRetry, targetProjectJobResource), true, ReasonAllowedByGrant)
	})

	t.Run("viewer on target project denies no capability", func(t *testing.T) {
		t.Parallel()
		p := Principal{
			ID: "sa_proj_viewer_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
			Grants: []Grant{viewerGrant},
		}
		assertDecision(t, e.Decide(p, ActionJobRetry, targetProjectJobResource), false, ReasonDeniedNoCapability)
	})
}

// TestJobRetryPolicyEnvironmentGrantContainment proves environment-
// level grants do not imply access to production unless production
// is explicitly granted, and do not reach the shallower org-root or
// parent-project owned job rows at all. A staging-environment grant
// cannot escalate to retrying any provisioning job under the parent
// project or the parent organization — that would let a staging-
// scoped key replay mutating Dokploy work against sibling
// environments alongside staging, the precise leak the engine
// forbids.
//
// covers() is one-way: a deeper-scope grant cannot reach a shallower
// resource. So:
//
//   - env-staging Admin grant denies job.retry against an org-rooted
//     job row (Scope={org} only). ReasonDeniedOutOfScope.
//   - env-staging Admin grant denies job.retry against a parent-
//     project-owned job row (Scope={org, project}).
//     ReasonDeniedOutOfScope.
//   - env-staging Admin grant ALLOWS job.retry against a staging-
//     env-owned job row (Scope={org, project, env_staging}) —
//     covers() matches because the grant scope equals the resource
//     scope. This is what the bare-{job_id} retry resolver will
//     construct when the looked-up row is owned by the staging env,
//     and it proves the env-scoped automation key path. Admin holds
//     CapDeploy so the verdict is ReasonAllowedByGrant.
//   - env-staging Admin grant DENIES job.retry against a PRODUCTION-
//     env-owned job row (Scope={org, project, env_prod}). This is
//     the load-bearing AC "environment-level grants do not imply
//     access to production unless production is explicitly granted"
//     — a staging-scoped key cannot retry any provisioning job
//     scoped to production, the precise side-effect leak the
//     destructive-verb framing forbids.
//
// As a defence-in-depth pin, an env-scoped staging grant authorizing
// env.write against the production environment of the same project
// is also denied — staging never widens to production by accident,
// and the same containment underpins the job-retry deny: a staging
// grant cannot mutate production at any depth.
func TestJobRetryPolicyEnvironmentGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	stagingScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID, EnvironmentID: "env_staging",
	}
	productionScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobRetryProjectResource(orgA, canonicalJobRetryProjectID)
	orgRootJobResource := jobRetryOrgResource(orgA)
	stagingJobResource := jobRetryEnvResource(orgA, canonicalJobRetryProjectID, "env_staging")
	productionJobResource := jobRetryEnvResource(orgA, canonicalJobRetryProjectID, "env_prod")

	envAdminGrantee := Principal{
		ID: "sa_env_admin_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: stagingScope}},
	}

	t.Run("env scoped grant denies org rooted job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobRetry, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant denies parent project owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobRetry, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("env scoped grant allows staging env owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobRetry, stagingJobResource),
			true, ReasonAllowedByGrant)
	})

	t.Run("staging grant denies production env owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(envAdminGrantee, ActionJobRetry, productionJobResource),
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

// TestJobRetryPolicyServiceGrantContainment proves service-level
// grants do not expose parent-level resources via the bare-{job_id}
// retry. A service-scoped Admin grant on svc_a:
//
//   - cannot authorize job.retry on an org-rooted job row — that
//     would let a service-scoped key retry every job in the tenant,
//     the exact "service grant exposes parent-level secrets or
//     unrelated services" escalation the acceptance criterion
//     forbids. ReasonDeniedOutOfScope.
//   - cannot authorize job.retry on a parent-project-owned job row —
//     pinning the parent-project exposure boundary independently of
//     the org-root pin. ReasonDeniedOutOfScope.
//   - cannot authorize job.retry on a parent-environment-owned job
//     row — pinning the parent-environment exposure boundary
//     independently of the parent-project pin, so a job that lives
//     at the env layer is invisible to a service-scoped key.
//     ReasonDeniedOutOfScope.
//   - cannot authorize env.write on the parent environment —
//     pinning the parent-environment exposure boundary independently
//     of job.retry, so a future endpoint that authorized parent
//     env.write through a service grant would fail here before it
//     could regress a real customer.
//   - cannot authorize service.update on a sibling service in the
//     same parent environment — pinning the sibling-service boundary
//     independently of the parent-project boundary, so the
//     containment matrix proves both directions, not just one.
//   - cannot authorize job.retry on a SIBLING-service-owned job row
//     in the same parent environment — the destructive-by-omission
//     case: a job owned by svc_b is retried by a key scoped to
//     svc_a only, and the engine must refuse even though both
//     services share an env and a project. ReasonDeniedOutOfScope.
//   - CAN authorize job.retry on a job owned by its own service
//     ({org, project, env, svc_a}) — covers() matches because the
//     grant scope equals the resource scope. This is what the bare-
//     {job_id} retry resolver will construct when the looked-up row
//     is owned by svc_a, and proves the service-scoped automation
//     key path stays usable inside its own service.
func TestJobRetryPolicyServiceGrantContainment(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	svcAScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_a",
	}
	svcBScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID,
		EnvironmentID: "env_prod", ServiceID: "svc_b",
	}
	parentEnvScope := Scope{
		OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID, EnvironmentID: "env_prod",
	}
	parentProjectJobResource := jobRetryProjectResource(orgA, canonicalJobRetryProjectID)
	orgRootJobResource := jobRetryOrgResource(orgA)
	parentEnvJobResource := jobRetryEnvResource(orgA, canonicalJobRetryProjectID, "env_prod")
	svcAJobResource := jobRetryServiceResource(orgA, canonicalJobRetryProjectID, "env_prod", "svc_a")
	svcBJobResource := jobRetryServiceResource(orgA, canonicalJobRetryProjectID, "env_prod", "svc_b")

	svcGrantee := Principal{
		ID: "sa_svc_admin_retry", Kind: domain.KindServiceAccount, OrganizationID: orgA,
		Grants: []Grant{{Role: RoleAdmin, Scope: svcAScope}},
	}

	t.Run("service scoped grant denies org rooted job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRetry, orgRootJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent project owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRetry, parentProjectJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant denies parent env owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRetry, parentEnvJobResource),
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

	t.Run("service scoped grant denies sibling service owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRetry, svcBJobResource),
			false, ReasonDeniedOutOfScope)
	})

	t.Run("service scoped grant allows own service owned job retry", func(t *testing.T) {
		t.Parallel()
		assertDecision(t,
			e.Decide(svcGrantee, ActionJobRetry, svcAJobResource),
			true, ReasonAllowedByGrant)
	})
}

// TestJobRetryPolicyOrgGrantCapabilityMatrix pins the capability
// split for organization-level grants against job.retry. An
// organization-level grant covers any resource within the same org
// by construction (covers() with an empty ProjectID matches any
// project; equally so for the empty environment and service fields),
// so this case isolates the role capability from the grant scope:
// the scope is sufficient at every depth, the role's capability set
// is what decides.
//
//   - Org-level CI grant: scope OK, CI holds CapDeploy — allowed
//     (ReasonAllowedByGrant). CI is the canonical principal for
//     automating job retry from a pipeline at organization scope.
//   - Org-level Developer grant: scope OK, Developer holds CapDeploy
//     — allowed (ReasonAllowedByGrant).
//   - Org-level Viewer grant: scope OK, Viewer does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). This pins the
//     CapDeploy requirement against the org-grant path so a future
//     catalog change that downgraded job.retry to CapRead would
//     fail here (silently allowing every org-level Viewer grantee
//     to re-issue mutating provisioning calls) before it could
//     regress a real customer.
//   - Org-level Support grant: scope OK, Support does NOT hold
//     CapDeploy — denied (ReasonDeniedNoCapability). Support reads
//     provisioning history widely but never re-issues a mutating
//     Dokploy call; this is the load-bearing distinction between
//     job.read (Support allowed) and job.retry (Support denied) at
//     the org-grant path, mirroring the role matrix denial above.
//     The mutating verb makes this pin especially load-bearing: a
//     stolen or misused support token must never be able to replay
//     a destructive provisioning side-effect against the wrong
//     resource.
func TestJobRetryPolicyOrgGrantCapabilityMatrix(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobRetryOrgResource(orgA)
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
				ID: "sa_org_retry_" + tc.name, Kind: domain.KindServiceAccount, OrganizationID: orgA,
				Grants: []Grant{{Role: tc.role, Scope: orgScope}},
			}
			assertDecision(t, e.Decide(p, ActionJobRetry, resource), tc.allow, tc.reason)
		})
	}
}

// TestJobRetryPolicyForeignHomeOrgGrant pins the cross-tenant guard
// on the grant path. A project-scoped Admin grant for
// canonicalJobRetryProjectID inside orgA, carried by a principal
// whose home org is orgB, cannot be used to authorize job.retry
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
// a mutating verb that re-issues a Dokploy provisioning call, this
// guard is what stops an exfiltrated grant from being used to
// replay desired-state changes in the wrong organization — a
// side-effect incident at the upstream provisioner that would
// otherwise be indistinguishable from a legitimate retry until the
// customer noticed the unexpected provisioning activity. CapDeploy
// is OUTSIDE the cross-tenant Support exception, so there is no
// catalog row that could rescue the verdict on this path.
func TestJobRetryPolicyForeignHomeOrgGrant(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	resource := jobRetryProjectResource(orgB, canonicalJobRetryProjectID)
	foreignGrant := Grant{
		Role:  RoleAdmin,
		Scope: Scope{OrganizationID: orgA, ProjectID: canonicalJobRetryProjectID},
	}
	p := Principal{
		ID: "sa_stolen_retry", Kind: domain.KindServiceAccount, OrganizationID: orgB,
		Grants: []Grant{foreignGrant},
	}
	assertDecision(t, e.Decide(p, ActionJobRetry, resource), false, ReasonDeniedNoCapability)
}
