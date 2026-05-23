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

// Policy-matrix coverage for GET /v1/services/{service_id}/deployments
// (BE-0210). Where service_deployments_list_test.go proves the
// endpoint's wire contract (BE-0208 + BE-0209), this file proves its
// authorization contract: that action deployment.read cannot be
// bypassed by — or render data because of — the principal's role,
// revoked credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// every other bare-id /v1/services/{service_id}/... route carries.
// The authorization contract here is the structural twin of
// service_variables_policy_test.go (BE-0201) but for the
// deployment-read action. deployment.read is a CapRead action, so:
//   - Owner / Admin / Developer / Viewer / CI hold CapRead and are
//     allowed (ReasonAllowedByRole).
//   - Support holds CapRead + CapSupport — but because
//     serviceIDResolver pins the resource to the principal's OWN home
//     organization (never the path service's tenant), Support's
//     deliberate cross-tenant CapRead exception does NOT apply to
//     this resolver: same-org Support is still allowed via
//     ReasonAllowedByRole.
//
// Cross-tenant: the resolver pins the resource org to the principal's
// home org, so a cross-tenant {service_id} reaches the persistence
// layer with the principal's own org id and is rejected as a 404 by
// the tenant-scoped repository's service existence check — never as
// a 200 with foreign data, never as a 403 that would confirm
// existence. The engine-level cross-tenant matrix (a hypothetical
// resource pinned to a foreign org) is also asserted — every role
// except Support is denied via ReasonDeniedCrossTenant, and Support
// is allowed via ReasonAllowedByRoleAcrossTenants because CapRead is
// INSIDE the engine's `CapSupport && (CapRead || CapSupport)`
// exception.
//
// Grant containment: serviceIDResolver pins NO ProjectID leg on the
// resource scope (the bare path carries only the service_id), and
// the engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not), so ALL
// project-, environment-, and service-scoped grants are denied at
// the boundary via ReasonDeniedOutOfScope — even a service-scoped
// Admin grant naming THIS service's id. Principals whose only access
// is a scoped grant must use a parent-scoped route family.

// canonicalDeploymentsForListMatrix is the slice every test in this
// file would receive back from the lister on an allow path. The ids
// and source refs are deliberately recognisable so deny-path leak
// guards can needle for them.
func canonicalDeploymentsForListMatrix(orgID, svcID string) []store.Deployment {
	created := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	return []store.Deployment{
		seedDeploymentWire(
			"dep_matrix_list_a",
			orgID,
			"prj_matrix_list_parent",
			"env_matrix_list_parent",
			svcID,
			store.DeploymentSourceGit,
			"main-matrix-list",
			"queued",
			"usr_matrix_actor",
			"matrix-list-idem-a",
			1,
			created,
			created,
		),
	}
}

const (
	canonicalDeploymentsListMatrixServiceID = "svc_matrix_deployment_list"
	canonicalDeploymentsListMatrixID        = "dep_matrix_list_a"
	canonicalDeploymentsListMatrixSourceRef = "main-matrix-list"
	canonicalDeploymentsListMatrixIdemKey   = "matrix-list-idem-a"
	canonicalDeploymentsListMatrixProject   = "prj_matrix_list_parent"
	canonicalDeploymentsListMatrixEnv       = "env_matrix_list_parent"
)

// listDeploymentsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical deployment slice
// the lister would have returned on the allow path. A denied response
// that contains any of these fails the test — proof that the lister
// ran (which it must not on a deny) or that the deny envelope echoed
// canonical-row data.
func listDeploymentsDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalDeploymentsListMatrixID,
		canonicalDeploymentsListMatrixSourceRef,
		canonicalDeploymentsListMatrixIdemKey,
		canonicalDeploymentsListMatrixProject,
		canonicalDeploymentsListMatrixEnv,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListServiceDeploymentsPolicyMatrixRoles drives every built-in
// role through the production request path. CapRead admits Owner /
// Admin / Developer / Viewer / CI / Support (own-org) — the same
// posture every other CapRead service-id route uses. The assertions
// for allow rows: 200, lister called once with the principal's own
// home org id and the path service id (never a caller-controlled
// org), and the canonical row reaches the wire. For deny rows: not
// applicable on this matrix — every same-org role can READ
// deployments.
//
// The Support own-org allow is the load-bearing structural property
// for CapRead: same-org Support holds CapRead via the role and the
// resolver pins the resource to Support's own org, so the verdict is
// ReasonAllowedByRole — NOT the cross-tenant exception, which would
// require the resource org to differ from the principal's home org.
func TestListServiceDeploymentsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDeploymentsListMatrixServiceID
	)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
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
			got := e.Decide(principal, policy.ActionDeploymentRead, svcResource)
			if !got.Allow || got.Reason != tc.reason {
				t.Errorf("Decide(deployment.read) for %s = %+v, want allow via %q",
					tc.name, got, tc.reason)
			}

			canonical := canonicalDeploymentsForListMatrix(org, svcID)
			var gotOrg, gotSvc string
			callCount := 0
			lister := fakeDeploymentLister{
				deployments:  canonical,
				gotOrgID:     &gotOrg,
				gotServiceID: &gotSvc,
				callCount:    &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listServiceDeploymentsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, lister)
			rec := getServiceDeployments(handler, svcID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 1 {
				t.Errorf("lister call count = %d, want 1 on the allow path", callCount)
			}
			if gotOrg != org {
				t.Errorf("lister received organization id %q, want the principal's home org %q",
					gotOrg, org)
			}
			if gotSvc != svcID {
				t.Errorf("lister received service id %q, want the path parameter %q",
					gotSvc, svcID)
			}
			env := decodeListServiceDeployments(t, rec)
			if len(env.Data.Deployments) != 1 || env.Data.Deployments[0].ID != canonicalDeploymentsListMatrixID {
				t.Errorf("envelope deployments = %+v, want exactly the canonical row", env.Data.Deployments)
			}
		})
	}
}

// TestListServiceDeploymentsPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces as Unauthenticated — never
// reaches the lister and never receives canonical row data.
func TestListServiceDeploymentsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDeploymentsListMatrixServiceID
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
			lister := fakeDeploymentLister{
				deployments: canonicalDeploymentsForListMatrix(org, svcID),
				callCount:   &callCount,
			}
			handler := listServiceDeploymentsHandlerFor(
				auth.Identity{}, apierr.Unauthenticated("api key revoked"), lister)
			rec := getServiceDeployments(handler, svcID, "yk_no_longer_valid")

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 0 {
				t.Errorf("lister was reached (calls=%d) for a revoked/expired credential; it must never run",
					callCount)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				listDeploymentsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or canonical deployment data", body)
			}
		})
	}
}

// TestListServiceDeploymentsPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for deployment.read on the bare-id route.
// As with env.read on the same route, the resource org id is taken
// from the PRINCIPAL'S home org — the {service_id} path parameter
// alone never widens the resource to another tenant, and so Support's
// cross-tenant CapRead exception does NOT apply through this
// resolver. Tenant isolation on the wire is therefore structural at
// the persistence layer:
//
//   - A principal in org_attacker hitting GET /v1/services/
//     {svc_victim}/deployments with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, svc_victim})
//     — allowed by the role at CapRead — and then reaches the
//     tenant-scoped repository query with the principal's home org id
//     and the foreign service id. A production *store.
//     DeploymentReader cannot match a service row that belongs to
//     another tenant, so the request surfaces as a deterministic 404
//     E_NOT_FOUND, never disguised as a 200 with foreign data and
//     never as a 403 that would confirm existence.
//
//   - Engine defence-in-depth: at a hypothetical foreign-org resource
//     scope, every role except Support is denied via
//     ReasonDeniedCrossTenant, and Support is allowed via
//     ReasonAllowedBySupport — because CapRead IS INSIDE the
//     engine's `CapSupport && (CapRead || CapSupport)` exception.
//     This is the load-bearing distinction from deployment.create
//     (CapDeploy is OUTSIDE the exception, so support is denied
//     cross-tenant for deploy actions).
func TestListServiceDeploymentsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_deployment"
		victimOrgNeedle = "org_victim"
	)

	var gotOrg string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	lister := fakeDeploymentLister{
		err:       apierr.NotFound("service", foreignSvcID),
		gotOrgID:  &gotOrg,
		callCount: &callCount,
	}
	handler := listServiceDeploymentsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, lister)
	rec := getServiceDeployments(handler, foreignSvcID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant service_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("lister call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("lister received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
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

// TestListServiceDeploymentsPolicyGrantContainment proves scoped
// grants cannot reach this endpoint at all — every project-,
// environment-, and service-scoped grant is denied at the boundary
// by ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way.
//
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes, then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (even when the grant names the target
// service's own project, its own environment, or its own id), while
// an organization-level Viewer grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed end-to-end.
// (Org-level Viewer suffices here because deployment.read is
// CapRead, not CapDeploy — the load-bearing distinction from the
// create-side grant matrix where Viewer denies.)
func TestListServiceDeploymentsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_dep_list_matrix_parent"
		env     = "env_dep_list_matrix_parent"
		svcID   = "svc_matrix_deployment_list_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, so deployment.read on a
	// service resource INSIDE that project IS allowed at the engine.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_dep_list_matrix_sibling"}
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
	if got := e.Decide(projectViewerGrantee, policy.ActionDeploymentRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_dep_list_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
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
		t.Errorf("Decide(deployment.read) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
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
		t.Errorf("Decide(deployment.read) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: viewer on THIS service. The grant scope
	// pins ProjectID + EnvironmentID + ServiceID, so the engine's
	// covers() rule denies the bare-id resource scope. At a fully
	// scoped service resource the grant DOES authorize, but a
	// service-level grant does not widen to parent-level resources
	// or unrelated sibling services.
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
		t.Errorf("Decide(deployment.read) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
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
		t.Errorf("Decide(deployment.read) at the service-id route for an org-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// lister must never run.
	var gotProjOrg string
	projCallCount := 0
	projLister := fakeDeploymentLister{
		deployments: canonicalDeploymentsForListMatrix(org, svcID),
		gotOrgID:    &gotProjOrg,
		callCount:   &projCallCount,
	}
	projHandler := listServiceDeploymentsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projLister)
	projRec := getServiceDeployments(projHandler, svcID, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("lister was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); listDeploymentsDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical deployment data: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an org-level viewer grant principal passes the
	// engine and reaches the lister with the principal's home org id.
	var gotOrgID, gotSvc string
	orgCallCount := 0
	orgLister := fakeDeploymentLister{
		deployments:  canonicalDeploymentsForListMatrix(org, svcID),
		gotOrgID:     &gotOrgID,
		gotServiceID: &gotSvc,
		callCount:    &orgCallCount,
	}
	orgHandler := listServiceDeploymentsHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgLister)
	orgRec := getServiceDeployments(orgHandler, svcID, "a-valid-token")
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-viewer grant wire status = %d, want 200; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("lister call count = %d, want 1 for an org-level viewer grant", orgCallCount)
	}
	if gotOrgID != org || gotSvc != svcID {
		t.Errorf("lister captured (org=%q, svc=%q), want (%q, %q) for the org-viewer allow path",
			gotOrgID, gotSvc, org, svcID)
	}
}
