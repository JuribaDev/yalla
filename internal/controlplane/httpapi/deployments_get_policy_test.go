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

// Policy-matrix coverage for GET /v1/deployments/{deployment_id}
// (BE-0213). Where deployments_get_test.go proves the endpoint's
// wire contract (BE-0211 + BE-0212), this file proves its
// authorization contract: that action deployment.read cannot be
// bypassed by — or render data because of — the principal's role,
// revoked credentials, home organization, or scoped grants.
//
// The route carries deploymentIDResolver (routes.go), which pins ONLY
// the OrganizationID leg of the resource scope to the principal's
// home organization. The policy.Scope hierarchy stops at ServiceID,
// so the deployment_id itself is NOT a scope leg — the resource
// carries no ProjectID, EnvironmentID, or ServiceID. The
// authorization contract on this bare-id route is the structural twin
// of services_get_policy_test.go (services-get) but for the
// deployment-read action, with one structural simplification: the
// resource has even fewer pinned scope legs than the services-get
// resource, so the grant-containment posture is even stricter.
//
//   - Owner / Admin / Developer / Viewer / CI hold CapRead and are
//     allowed (ReasonAllowedByRole).
//   - Support holds CapRead + CapSupport — but because
//     deploymentIDResolver pins the resource to the principal's OWN
//     home organization (never the path deployment's tenant),
//     Support's deliberate cross-tenant CapRead exception does NOT
//     apply to this resolver: same-org Support is still allowed via
//     ReasonAllowedByRole.
//
// Cross-tenant: the resolver pins the resource org to the principal's
// home org, so a cross-tenant {deployment_id} reaches the persistence
// layer with the principal's own org id and is rejected as a 404 by
// the tenant-scoped repository's deployment existence check — never as
// a 200 with foreign data, never as a 403 that would confirm
// existence. The engine-level cross-tenant matrix (a hypothetical
// resource pinned to a foreign org) is also asserted — every role
// except Support is denied via ReasonDeniedCrossTenant, and Support
// is allowed via ReasonAllowedBySupport because CapRead is INSIDE the
// engine's `CapSupport && (CapRead || CapSupport)` exception.
//
// Grant containment: deploymentIDResolver pins NO ProjectID,
// EnvironmentID, or ServiceID leg on the resource scope (the
// policy.Scope hierarchy stops at ServiceID, and the deployment_id
// itself is not a leg), and the engine's covers() rule is one-way (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not), so ALL project-, environment-, and service-scoped grants
// are denied at the boundary via ReasonDeniedOutOfScope — even a
// service-scoped Admin grant naming the deployment's actual parent
// service. The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes (a service / environment /
// project resource), then tied back to the wire by proving that ALL
// three scoped key types are denied OutOfScope against THIS endpoint,
// while an organization-level Viewer grant — which pins no ProjectID
// and covers any resource scope in the same org — is allowed
// end-to-end. (Org-level Viewer suffices here because deployment.read
// is CapRead, not CapDeploy — the load-bearing distinction from the
// create-side grant matrix where Viewer denies.)

// canonicalDeploymentForGetMatrix is the row every test in this file
// would receive back from the getter on an allow path. The ids and
// source ref are deliberately recognisable so deny-path leak guards
// can needle for them.
func canonicalDeploymentForGetMatrix(orgID, depID string) store.Deployment {
	created := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	return seedDeploymentWire(
		depID,
		orgID,
		canonicalDeploymentGetMatrixProject,
		canonicalDeploymentGetMatrixEnv,
		canonicalDeploymentGetMatrixService,
		store.DeploymentSourceGit,
		canonicalDeploymentGetMatrixSourceRef,
		"queued",
		"usr_matrix_actor",
		canonicalDeploymentGetMatrixIdemKey,
		1,
		created,
		created,
	)
}

const (
	canonicalDeploymentGetMatrixID        = "dep_matrix_get_a"
	canonicalDeploymentGetMatrixSourceRef = "main-matrix-get"
	canonicalDeploymentGetMatrixIdemKey   = "matrix-get-idem-a"
	canonicalDeploymentGetMatrixProject   = "prj_matrix_get_parent"
	canonicalDeploymentGetMatrixEnv       = "env_matrix_get_parent"
	canonicalDeploymentGetMatrixService   = "svc_matrix_get_parent"
)

// getDeploymentDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical deployment the
// getter would have returned on the allow path. A denied response
// that contains any of these fails the test — proof that the getter
// ran (which it must not on a deny) or that the deny envelope echoed
// canonical-row data.
func getDeploymentDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalDeploymentGetMatrixID,
		canonicalDeploymentGetMatrixSourceRef,
		canonicalDeploymentGetMatrixIdemKey,
		canonicalDeploymentGetMatrixProject,
		canonicalDeploymentGetMatrixEnv,
		canonicalDeploymentGetMatrixService,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestGetServiceDeploymentPolicyMatrixRoles drives every built-in
// role through the production request path. CapRead admits Owner /
// Admin / Developer / Viewer / CI / Support (own-org) — the same
// posture every other CapRead bare-id route uses. The assertions for
// allow rows: 200, getter called once with the principal's own home
// org id and the path deployment id (never a caller-controlled org),
// and the canonical row reaches the wire.
//
// The Support own-org allow is the load-bearing structural property
// for CapRead: same-org Support holds CapRead via the role and the
// resolver pins the resource to Support's own org, so the verdict is
// ReasonAllowedByRole — NOT the cross-tenant exception, which would
// require the resource org to differ from the principal's home org.
func TestGetServiceDeploymentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = canonicalDeploymentGetMatrixID
	)
	// deploymentIDResolver pins ONLY OrganizationID; the engine sees
	// a resource scope with no deeper leg, so the role matrix is
	// asserted against that exact scope.
	depResource := policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: policy.Scope{OrganizationID: org},
	}

	cases := []struct {
		name   string
		role   policy.Role
		kind   domain.Kind
		reason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, policy.ReasonAllowedByRole},
		{"viewer", policy.RoleViewer, domain.KindUser, policy.ReasonAllowedByRole},
		{"ci", policy.RoleCI, domain.KindServiceAccount, policy.ReasonAllowedByRole},
		{"support", policy.RoleSupport, domain.KindUser, policy.ReasonAllowedByRole},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. Every
			// same-org role holds CapRead so all six are allowed via
			// ReasonAllowedByRole; Support's cross-tenant exception is
			// NOT used because the resolver pins the resource to the
			// principal's own home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionDeploymentRead, depResource)
			if !got.Allow || got.Reason != tc.reason {
				t.Errorf("Decide(deployment.read) for %s = %+v, want allow via %q",
					tc.name, got, tc.reason)
			}

			canonical := canonicalDeploymentForGetMatrix(org, depID)
			var gotOrg, gotDep string
			callCount := 0
			getter := fakeDeploymentGetter{
				deployment:      canonical,
				gotOrgID:        &gotOrg,
				gotDeploymentID: &gotDep,
				callCount:       &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := getServiceDeploymentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, getter)
			rec := getServiceDeployment(handler, depID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 1 {
				t.Errorf("getter call count = %d, want 1 on the allow path", callCount)
			}
			if gotOrg != org {
				t.Errorf("getter received organization id %q, want the principal's home org %q",
					gotOrg, org)
			}
			if gotDep != depID {
				t.Errorf("getter received deployment id %q, want the path parameter %q",
					gotDep, depID)
			}
			env := decodeGetServiceDeployment(t, rec)
			if env.Data.Deployment.ID != canonicalDeploymentGetMatrixID {
				t.Errorf("envelope deployment id = %q, want the canonical row %q",
					env.Data.Deployment.ID, canonicalDeploymentGetMatrixID)
			}
		})
	}
}

// TestGetServiceDeploymentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces as Unauthenticated — never reaches
// the getter and never receives canonical row data.
func TestGetServiceDeploymentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = canonicalDeploymentGetMatrixID
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

			callCount := 0
			getter := fakeDeploymentGetter{
				deployment: canonicalDeploymentForGetMatrix(org, depID),
				callCount:  &callCount,
			}
			handler := getServiceDeploymentHandlerFor(
				auth.Identity{}, apierr.Unauthenticated("api key revoked"), getter)
			rec := getServiceDeployment(handler, depID, "yk_no_longer_valid")

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 0 {
				t.Errorf("getter was reached (calls=%d) for a revoked/expired credential; it must never run",
					callCount)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				getDeploymentDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or canonical deployment data", body)
			}
		})
	}
}

// TestGetServiceDeploymentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for deployment.read on the bare-id route. The
// resource org id is taken from the PRINCIPAL'S home org — the
// {deployment_id} path parameter alone never widens the resource to
// another tenant, and so Support's cross-tenant CapRead exception
// does NOT apply through this resolver. Tenant isolation on the wire
// is therefore structural at the persistence layer:
//
//   - A principal in org_attacker hitting GET /v1/deployments/
//     {dep_victim} with a valid Owner token reaches the engine with a
//     same-tenant resource ({org_attacker, KindDeployment}) — allowed
//     by the role at CapRead — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the
//     foreign deployment id. A production *store.DeploymentReader
//     cannot match a deployment row that belongs to another tenant,
//     so the request surfaces as a deterministic 404 E_NOT_FOUND,
//     never disguised as a 200 with foreign data and never as a 403
//     that would confirm existence.
//
//   - Engine defence-in-depth: at a hypothetical foreign-org resource
//     scope, every role except Support is denied via
//     ReasonDeniedCrossTenant, and Support is allowed via
//     ReasonAllowedBySupport — because CapRead IS INSIDE the engine's
//     `CapSupport && (CapRead || CapSupport)` exception. This is the
//     load-bearing distinction from deployment.create (CapDeploy is
//     OUTSIDE the exception, so support is denied cross-tenant for
//     deploy actions).
func TestGetServiceDeploymentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignDepID    = "dep_victim_target"
		victimOrgNeedle = "org_victim"
	)

	var gotOrg string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	getter := fakeDeploymentGetter{
		err:       apierr.NotFound("deployment", foreignDepID),
		gotOrgID:  &gotOrg,
		callCount: &callCount,
	}
	handler := getServiceDeploymentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, getter)
	rec := getServiceDeployment(handler, foreignDepID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant deployment_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("getter call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("getter received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			gotOrg, ownOrg)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary at a foreign-org resource
	// scope: pin the verdict directly so a future endpoint that
	// resolves the resource into a foreign-org scope inherits a
	// working cross-tenant deny for non-Support roles AND a working
	// Support cross-tenant ALLOW.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: policy.Scope{OrganizationID: victimOrg},
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
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionDeploymentRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(deployment.read, foreign org) for %s = %+v, want deny via %q — only Support is excepted for CapRead",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	t.Run("engine_cross_tenant_allow_support", func(t *testing.T) {
		t.Parallel()
		p := orgPrincipal("usr_support", ownOrg, policy.RoleSupport)
		got := e.Decide(p, policy.ActionDeploymentRead, foreign)
		if !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
			t.Errorf("Decide(deployment.read, foreign org) for support = %+v, want allow via %q — CapRead IS INSIDE the support cross-tenant exception",
				got, policy.ReasonAllowedBySupport)
		}
	})
}

// TestGetServiceDeploymentPolicyGrantContainment proves scoped grants
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because deploymentIDResolver pins NO
// ProjectID / EnvironmentID / ServiceID leg on the resource scope and
// the engine's covers() rule is one-way.
//
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes, then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (even when the grant names the deployment's
// actual parent project, its own environment, or its parent service),
// while an organization-level Viewer grant — which pins no ProjectID
// and covers any resource scope in the same org — is allowed
// end-to-end. (Org-level Viewer suffices here because deployment.read
// is CapRead, not CapDeploy — the load-bearing distinction from the
// create-side grant matrix where Viewer denies.)
func TestGetServiceDeploymentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalDeploymentGetMatrixProject
		env     = canonicalDeploymentGetMatrixEnv
		svcID   = canonicalDeploymentGetMatrixService
		depID   = canonicalDeploymentGetMatrixID
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: policy.Scope{OrganizationID: org},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, so deployment.read on a
	// service resource INSIDE that project IS allowed at the engine.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_dep_get_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.read) at the parent project's service for the target-project viewer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	// Sibling-project containment: a service in a sibling project is
	// denied at the engine.
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_dep_get_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the
	// project-scoped grant is denied at the engine.
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at the deployment-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: viewer on the staging environment.
	// "env grant does not imply access to production unless production
	// is explicitly granted" — pinned at env / service resources for
	// the read action.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("deployment.read on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("deployment.read on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentRead, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope, the env-scoped grant is
	// denied at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at the deployment-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: viewer on the deployment's parent service.
	// The grant scope pins ProjectID + EnvironmentID + ServiceID, so
	// the engine's covers() rule denies the bare-id deployment
	// resource scope. At a fully scoped service resource the grant
	// DOES authorize, but a service-level grant does not widen to
	// parent-level resources or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("deployment.read on the granted service (full scope) = %+v, want allow",
			got)
	}
	// A service grant does not widen to the parent environment's
	// variables (a parent secret-bearing resource).
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("env.read on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to parent secrets",
			got)
	}
	// Service grant does not authorize an unrelated sibling service.
	if got := e.Decide(svcGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("deployment.read on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	// And on THIS endpoint's bare-id resource scope, the
	// service-scoped grant is denied at the engine — the load-bearing
	// distinction that forces scoped-grant-only principals onto the
	// parent-scoped route.
	if got := e.Decide(svcGrantee, policy.ActionDeploymentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.read) at the deployment-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Viewer grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Viewer holds CapRead
	// (deployment.read is CapRead — load-bearing distinction from the
	// create-side matrix where Viewer denies), so deployment.read is
	// allowed via ReasonAllowedByGrant on the bare-id route, AND on
	// the wire.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionDeploymentRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.read) at the deployment-id route for an org-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// getter must never run.
	var gotProjOrg string
	projCallCount := 0
	projGetter := fakeDeploymentGetter{
		deployment: canonicalDeploymentForGetMatrix(org, depID),
		gotOrgID:   &gotProjOrg,
		callCount:  &projCallCount,
	}
	projHandler := getServiceDeploymentHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projGetter)
	projRec := getServiceDeployment(projHandler, depID, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("getter was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); getDeploymentDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical deployment data: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: a service-scoped grant principal — even one
	// naming the deployment's actual parent service — is also denied
	// at the boundary on the bare-id route. The grant scope pins a
	// ServiceID the resource leaves empty, so covers() denies.
	var gotSvcOrg string
	svcCallCount := 0
	svcGetter := fakeDeploymentGetter{
		deployment: canonicalDeploymentForGetMatrix(org, depID),
		gotOrgID:   &gotSvcOrg,
		callCount:  &svcCallCount,
	}
	svcHandler := getServiceDeploymentHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcGetter)
	svcRec := getServiceDeployment(svcHandler, depID, "a-valid-token")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCallCount != 0 {
		t.Errorf("getter was reached (calls=%d) for a service-scoped grant principal", svcCallCount)
	}
	if body := svcRec.Body.String(); getDeploymentDenyBodyLeak(body) {
		t.Errorf("service-scoped grant deny response leaked the canonical deployment data: %s", body)
	}

	// Wire-level proof: an org-level viewer grant principal passes the
	// engine and reaches the getter with the principal's home org id.
	var gotOrgID, gotDep string
	orgCallCount := 0
	orgGetter := fakeDeploymentGetter{
		deployment:      canonicalDeploymentForGetMatrix(org, depID),
		gotOrgID:        &gotOrgID,
		gotDeploymentID: &gotDep,
		callCount:       &orgCallCount,
	}
	orgHandler := getServiceDeploymentHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgGetter)
	orgRec := getServiceDeployment(orgHandler, depID, "a-valid-token")
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-viewer grant wire status = %d, want 200; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("getter call count = %d, want 1 for an org-level viewer grant", orgCallCount)
	}
	if gotOrgID != org || gotDep != depID {
		t.Errorf("getter captured (org=%q, dep=%q), want (%q, %q) for the org-viewer allow path",
			gotOrgID, gotDep, org, depID)
	}
}
