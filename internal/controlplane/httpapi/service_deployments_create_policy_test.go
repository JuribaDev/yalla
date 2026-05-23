package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for POST /v1/services/{service_id}/deployments
// (BE-0207). Where service_deployments_create_test.go proves the
// endpoint's wire contract (BE-0206), this file proves its
// authorization contract: that action deployment.create cannot be
// bypassed by — or persist a mutation because of — the principal's
// role, revoked credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the other bare-id /v1/services/{service_id}/... routes carry. The
// authorization contract here is the structural twin of
// service_variables_put_policy_test.go (BE-0204) but with a critical
// difference at the role-matrix axis: deployment.create requires
// CapDeploy (catalog.go: ActionDeploymentCreate -> CapDeploy), which
// CI holds — so CI is allowed here, while it denies for env.write.
// The role matrix therefore splits:
//   - Owner / Admin / Developer / CI hold CapDeploy and are allowed
//     (ReasonAllowedByRole).
//   - Viewer holds only CapRead and is denied (ReasonDeniedNoCapability).
//   - Support holds CapRead + CapSupport but NOT CapDeploy and is
//     denied (ReasonDeniedNoCapability).
//
// Cross-tenant: deployment.create is CapDeploy, which is OUTSIDE the
// engine's cross-tenant exception (`CapSupport && (CapRead ||
// CapSupport)`) — so EVERY role, INCLUDING Support, is denied
// cross-tenant via ReasonDeniedCrossTenant. Privileged Yalla support
// that needs to deploy on behalf of a customer must use explicit
// break-glass admin tooling, not this customer-facing route.
//
// Grant containment: serviceIDResolver pins NO ProjectID leg on the
// resource scope (the bare path carries only the service_id), and the
// engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not), so ALL
// project-, environment-, and service-scoped grants are denied at the
// boundary via ReasonDeniedOutOfScope — even a service-scoped Admin
// grant naming THIS service's id. Principals whose only access is a
// scoped grant must use a parent-scoped route family.

// canonicalDeploymentForMatrix is the row every test in this file
// would receive back from the creator on an allow path. Its ids are
// deliberately distinct from other suites so the matrices cannot
// accidentally share fixture state, and they are deliberately
// recognisable so deny-path leak guards can needle for them.
func canonicalDeploymentForMatrix(orgID, svcID, principalID string) store.Deployment {
	created := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	return seedDeploymentWire(
		"dep_matrix_create",
		orgID,
		"prj_matrix_parent",
		"env_matrix_parent",
		svcID,
		store.DeploymentSourceGit,
		"main-matrix",
		"queued",
		principalID,
		"matrix-idem-key-001",
		1,
		created,
		created,
	)
}

const (
	canonicalDeploymentBody              = `{"source":"git","source_ref":"main-matrix","idempotency_key":"matrix-idem-key-001"}`
	canonicalDeploymentMatrixServiceID   = "svc_matrix_deployment_create"
	canonicalDeploymentMatrixIdemKey     = "matrix-idem-key-001"
	canonicalDeploymentMatrixSourceRef   = "main-matrix"
	canonicalDeploymentMatrixProject     = "prj_matrix_parent"
	canonicalDeploymentMatrixEnvironment = "env_matrix_parent"
)

// deploymentDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical deployment, the
// canonical service, or the caller-supplied request-body fields. A
// denied response that accidentally rendered any of these fails the
// test — a denied request-body field would mean the handler echoed
// the request after policy denial (a tenant-boundary smell), and a
// denied canonical-row field would mean the creator ran and the
// response leaked its output even though the wire said 403.
func deploymentDenyBodyLeak(body string) bool {
	needles := []string{
		"dep_matrix_create",
		canonicalDeploymentMatrixIdemKey,
		canonicalDeploymentMatrixSourceRef,
		canonicalDeploymentMatrixProject,
		canonicalDeploymentMatrixEnvironment,
		`"source_ref"`,
		`"idempotency_key"`,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestCreateServiceDeploymentPolicyMatrixRoles drives every built-in
// role through the production request path. CapDeploy splits the
// matrix: Owner / Admin / Developer / CI (own org) are allowed;
// Viewer / Support (own org) are denied. CI's CapDeploy is the
// load-bearing distinction from env.write — automation keys CAN
// trigger deployments but CANNOT mutate variables. The assertions
// that matter for allow rows are that the verdict is reached through
// the role (ReasonAllowedByRole), the creator is reached with the
// principal's own home organization id, the {service_id} path
// parameter, and the principal id (so the audit record names the
// actor verbatim). For deny rows: 403 yalla.error.v1, the stable
// reason on the wire, the creator MUST NEVER run, and the denied
// body must not echo the canonical deployment, the request body, or
// the principal-controlled values.
func TestCreateServiceDeploymentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDeploymentMatrixServiceID
	)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	cases := []struct {
		name   string
		role   policy.Role
		kind   domain.Kind
		allow  bool
		reason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"ci", policy.RoleCI, domain.KindServiceAccount, true, policy.ReasonAllowedByRole},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. CI is
			// allowed because CapDeploy is the deploy capability and
			// CI's role grants it — the load-bearing distinction from
			// env.write.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionDeploymentCreate, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(deployment.create) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(deployment.create) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			canonical := canonicalDeploymentForMatrix(org, svcID, principal.ID)
			var captured store.CreateDeploymentInput
			callCount := 0
			creator := fakeDeploymentCreator{
				deployment: canonical,
				gotInput:   &captured,
				callCount:  &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := createServiceDeploymentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, creator)
			rec := postServiceDeployment(handler, svcID, canonicalDeploymentBody, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("creator call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("creator received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svcID {
					t.Errorf("creator received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("creator received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.Source != store.DeploymentSourceGit || captured.SourceRef != canonicalDeploymentMatrixSourceRef || captured.IdempotencyKey != canonicalDeploymentMatrixIdemKey {
					t.Errorf("creator intent fields = (source=%q, ref=%q, key=%q), want (git, %s, %s)",
						captured.Source, captured.SourceRef, captured.IdempotencyKey,
						canonicalDeploymentMatrixSourceRef, canonicalDeploymentMatrixIdemKey)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(tc.reason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, tc.reason)
			}
			if callCount != 0 {
				t.Errorf("creator was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("creator captured org=%q svc=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID)
			}
			if body := rec.Body.String(); deploymentDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical deployment or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestCreateServiceDeploymentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action deployment.create with a
// stable 403 E_FORBIDDEN, even when the underlying role would have
// allowed it. A revoked or expired CI key must never be able to
// trigger deployments for the organization it once had access to,
// the creator must never run, and the denied body must never echo
// the principal id, the organization id, or any seeded deployment
// data.
//
// Underlying role is CI so a working credential WOULD allow
// deployment.create; Disabled is the only thing in the way and must
// be load-bearing.
func TestCreateServiceDeploymentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDeploymentMatrixServiceID
	)

	cases := []struct {
		name string
		id   string
	}{
		{"revoked key", "sa_revoked"},
		{"expired key", "sa_expired"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal(tc.id, org, policy.RoleCI)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			canonical := canonicalDeploymentForMatrix(org, svcID, principal.ID)
			var captured store.CreateDeploymentInput
			callCount := 0
			creator := fakeDeploymentCreator{
				deployment: canonical,
				gotInput:   &captured,
				callCount:  &callCount,
			}
			handler := createServiceDeploymentHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)
			rec := postServiceDeployment(handler, svcID, canonicalDeploymentBody, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("creator was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				deploymentDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded deployment data", body)
			}
		})
	}
}

// TestCreateServiceDeploymentPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for deployment.create on the service-id
// route. As with env.write on the same route, the resource org id
// is taken from the PRINCIPAL'S home org — the {service_id} path
// parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer:
//
//   - A principal in org_attacker hitting POST /v1/services/
//     {svc_victim}/deployments with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, svc_victim})
//     — allowed by the role at CapDeploy — and then reaches the
//     tenant-scoped repository query with the principal's home org id
//     and the foreign service id. A production *store.
//     DeploymentService cannot match a service row that belongs to
//     another tenant, so the request surfaces as a deterministic 404
//     E_NOT_FOUND, never disguised as a 202 with foreign data and
//     never as a 403 that would confirm existence.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapDeploy
//     actions (the exception covers only CapRead and CapSupport).
//     Pinning that engine verdict here means a future endpoint that
//     resolves the resource into a foreign-org scope inherits a
//     working cross-tenant deny for deployment.create across every
//     role.
func TestCreateServiceDeploymentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_deployment"
		victimOrgNeedle = "org_victim"
	)

	var captured store.CreateDeploymentInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	creator := fakeDeploymentCreator{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := createServiceDeploymentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)
	rec := postServiceDeployment(handler, foreignSvcID, canonicalDeploymentBody, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant service_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("creator received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID {
		t.Errorf("creator received service id %q, want the path parameter %q",
			captured.ServiceID, foreignSvcID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. deployment.create
	// is CapDeploy, which is OUTSIDE the engine clause `CapSupport &&
	// (CapRead || CapSupport)` — so EVERY role, INCLUDING Support,
	// is denied cross-tenant.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: victimOrg, ServiceID: foreignSvcID},
	}
	crossTenantDeny := []struct {
		role policy.Role
		name string
	}{
		{policy.RoleOwner, "owner"},
		{policy.RoleAdmin, "admin"},
		{policy.RoleDeveloper, "developer"},
		{policy.RoleViewer, "viewer"},
		{policy.RoleCI, "ci"},
		{policy.RoleSupport, "support"},
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionDeploymentCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(deployment.create, foreign org) for %s = %+v, want deny via %q — CapDeploy is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCreateServiceDeploymentPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes, then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (even when the grant names the target
// service's own project, its own environment, or its own id), while
// an organization-level Admin grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed
// end-to-end.
func TestCreateServiceDeploymentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_dep_matrix_parent"
		env     = "env_dep_matrix_parent"
		svcID   = "svc_matrix_deployment_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: developer on the parent project. Developer
	// confers CapDeploy at the project scope, which IS enough for
	// deployment.create on a service resource inside that project —
	// and the engine confirms that at a service resource nested
	// inside the parent project.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_dep_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.create) at the parent project's service for the target-project developer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_dep_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Sibling-project containment at the project resource — pins the
	// "project-level grants do not imply sibling projects" criterion.
	if got := e.Decide(projectDevGrantee, policy.ActionDeploymentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine.
	if got := e.Decide(projectDevGrantee, policy.ActionDeploymentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapDeploy. Even at a service resource inside the parent
	// project (which a parent-scoped deploy route would target),
	// deployment.create must fail with ReasonDeniedNoCapability.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(deployment.create) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: developer on the staging environment.
	// "env grant does not imply access to production unless production
	// is explicitly granted" — pinned at env / service resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("deployment.create on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("deployment.create on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	// Env-to-env containment at the env resource too.
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCreate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope, the env-scoped grant is
	// denied at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on THIS service. The grant scope
	// pins ProjectID + EnvironmentID + ServiceID, so the engine's
	// covers() rule denies the bare-id resource scope. At a fully
	// scoped service resource the grant DOES authorize, but a
	// service-level grant does not widen to parent-level resources
	// or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("deployment.create on the granted service (full scope) = %+v, want allow",
			got)
	}
	// Service grant does not authorize a parent environment-level
	// action.
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("environment.update on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to the parent env",
			got)
	}
	// Service grant does not authorize an unrelated sibling service.
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("deployment.create on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	// And on THIS endpoint's bare-id resource scope, the
	// service-scoped grant is denied at the engine — the load-bearing
	// distinction that forces scoped-grant-only principals onto the
	// parent-scoped route.
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.create) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds
	// CapDeploy, so deployment.create is allowed via
	// ReasonAllowedByGrant on the bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionDeploymentCreate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.create) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: confers CapRead at the org but
	// no CapDeploy. deployment.create is denied via
	// ReasonDeniedNoCapability — the load-bearing distinction from
	// the read-side grant matrix (where an org-level Viewer is
	// allowed).
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionDeploymentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(deployment.create) at the service-id route for an org-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// creator must never run.
	var capturedProj store.CreateDeploymentInput
	projCallCount := 0
	projCreator := fakeDeploymentCreator{
		gotInput:  &capturedProj,
		callCount: &projCallCount,
	}
	projHandler := createServiceDeploymentHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projCreator)
	projRec := postServiceDeployment(projHandler, svcID, canonicalDeploymentBody, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("creator was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); deploymentDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical deployment or caller-supplied request body: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an org-level admin grant principal passes the
	// engine and reaches the creator with the principal's home org
	// id.
	var capturedOrg store.CreateDeploymentInput
	orgCallCount := 0
	orgCreator := fakeDeploymentCreator{
		deployment: canonicalDeploymentForMatrix(org, svcID, orgAdminGrantee.ID),
		gotInput:   &capturedOrg,
		callCount:  &orgCallCount,
	}
	orgHandler := createServiceDeploymentHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgCreator)
	orgRec := postServiceDeployment(orgHandler, svcID, canonicalDeploymentBody, "a-valid-token")
	if orgRec.Code != http.StatusAccepted {
		t.Fatalf("org-admin grant wire status = %d, want 202; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("creator call count = %d, want 1 for an org-level admin grant", orgCallCount)
	}
	if capturedOrg.OrganizationID != org || capturedOrg.ServiceID != svcID {
		t.Errorf("creator captured (org=%q, svc=%q), want (%q, %q) for the org-admin allow path",
			capturedOrg.OrganizationID, capturedOrg.ServiceID, org, svcID)
	}
}
