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

// Policy-matrix coverage for POST
// /v1/deployments/{deployment_id}/cancel (BE-0216). Where
// deployments_cancel_test.go proves the endpoint's wire contract
// (BE-0214 + BE-0215), this file proves its authorization contract:
// that action deployment.cancel cannot be bypassed by — or render a
// mutation because of — the principal's role, revoked credentials,
// home organization, or scoped grants.
//
// The route carries deploymentIDResolver (routes.go), which pins ONLY
// the OrganizationID leg of the resource scope to the principal's
// home organization. The policy.Scope hierarchy stops at ServiceID,
// so the deployment_id itself is NOT a scope leg — the resource
// carries no ProjectID, EnvironmentID, or ServiceID. The
// authorization contract on this bare-id route is the structural twin
// of deployments_get_policy_test.go (deployments-get) but for the
// CapDeploy deployment-cancel action, with two load-bearing
// distinctions:
//
//   - CapDeploy splits the role matrix differently from CapRead:
//     Owner / Admin / Developer / CI are allowed; Viewer (CapRead
//     only) and Support (CapRead + CapSupport, but NOT CapDeploy) are
//     denied. CI's CapDeploy is the load-bearing distinction from
//     CapWrite, where CI is also allowed — both gate write paths.
//   - Cross-tenant: deployment.cancel is CapDeploy, which is OUTSIDE
//     the engine's `CapSupport && (CapRead || CapSupport)` exception,
//     so every role — including Support — is denied cross-tenant. The
//     bare-id resolver pins the resource to the principal's OWN home
//     org anyway, so a cross-tenant deployment_id reaches the
//     persistence layer with the principal's org and surfaces as a
//     404 at the tenant-scoped row lookup; the engine-level
//     foreign-org matrix is also asserted as defence-in-depth.
//
// Grant containment: deploymentIDResolver pins NO ProjectID,
// EnvironmentID, or ServiceID leg on the resource scope, and the
// engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not), so ALL
// project-, environment-, and service-scoped grants are denied at the
// boundary via ReasonDeniedOutOfScope — even a service-scoped Admin
// grant naming the deployment's actual parent service. The PRD's
// three containment properties — sibling project, environment grant
// not implying production, service grant shielding parent-level
// resources and unrelated services — are pinned against the engine at
// their natural scopes (a service / environment / project resource),
// then tied back to the wire by proving that ALL three scoped key
// types are denied OutOfScope against THIS endpoint. An organization-
// level Admin grant — which pins no ProjectID and covers any resource
// scope in the same org — is allowed end-to-end (Admin holds
// CapDeploy through the role catalog). An organization-level Viewer
// grant is DENIED at this endpoint because Viewer holds only CapRead,
// not CapDeploy — the load-bearing distinction from the read-side
// grant matrix where org-level Viewer is allowed.

// canonicalDeploymentForCancelMatrix is the row every test in this
// file would receive back from the canceler on an allow path. The ids
// are deliberately recognisable so deny-path leak guards can needle
// for them — a denied response that contains any of them fails the
// test.
func canonicalDeploymentForCancelMatrix(orgID, depID string) store.Deployment {
	created := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 5, 16, 14, 5, 0, 0, time.UTC)
	return store.Deployment{
		ID:             depID,
		OrganizationID: orgID,
		ProjectID:      canonicalDeploymentCancelMatrixProject,
		EnvironmentID:  canonicalDeploymentCancelMatrixEnv,
		ServiceID:      canonicalDeploymentCancelMatrixService,
		Source:         store.DeploymentSourceGit,
		SourceRef:      canonicalDeploymentCancelMatrixSourceRef,
		Status:         store.DeploymentStatusCancelled,
		RequestedBy:    "usr_matrix_actor",
		IdempotencyKey: canonicalDeploymentCancelMatrixIdemKey,
		Version:        2,
		CreatedAt:      created,
		UpdatedAt:      finished,
		FinishedAt:     &finished,
	}
}

const (
	canonicalDeploymentCancelMatrixID        = "dep_matrix_cancel_a"
	canonicalDeploymentCancelMatrixSourceRef = "main-matrix-cancel"
	canonicalDeploymentCancelMatrixIdemKey   = "matrix-cancel-idem-a"
	canonicalDeploymentCancelMatrixProject   = "prj_matrix_cancel_parent"
	canonicalDeploymentCancelMatrixEnv       = "env_matrix_cancel_parent"
	canonicalDeploymentCancelMatrixService   = "svc_matrix_cancel_parent"
)

// cancelDeploymentDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical deployment the
// canceler would have returned on the allow path. A denied response
// that contains any of these fails the test — proof that the canceler
// ran (which it must not on a deny) or that the deny envelope echoed
// row data into the response body.
func cancelDeploymentDenyBodyLeak(body string) bool {
	for _, needle := range []string{
		canonicalDeploymentCancelMatrixID,
		canonicalDeploymentCancelMatrixSourceRef,
		canonicalDeploymentCancelMatrixProject,
		canonicalDeploymentCancelMatrixEnv,
		canonicalDeploymentCancelMatrixService,
		canonicalDeploymentCancelMatrixIdemKey,
	} {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

// TestCancelServiceDeploymentPolicyMatrixRoles drives every built-in
// role through the production request path. CapDeploy splits the role
// matrix: Owner / Admin / Developer / CI hold CapDeploy and the
// canceler is reached on the allow path with the principal's home org
// and the path deployment id; Viewer / Support hold CapRead +
// (CapSupport) but NOT CapDeploy and are denied at the policy
// boundary before the canceler runs.
func TestCancelServiceDeploymentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = canonicalDeploymentCancelMatrixID
	)
	depResource := policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: policy.Scope{OrganizationID: org},
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
			// catalog or builtinRoleCaps regression fails here.
			// Owner/Admin/Developer/CI hold CapDeploy and are allowed;
			// Viewer (CapRead only) and Support (CapRead+CapSupport,
			// no CapDeploy) are denied via ReasonDeniedNoCapability.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionDeploymentCancel, depResource)
			if got.Allow != tc.allow || got.Reason != tc.reason {
				t.Errorf("Decide(deployment.cancel) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.allow, tc.reason)
			}

			canonical := canonicalDeploymentForCancelMatrix(org, depID)
			var captured store.CancelDeploymentInput
			canceler := fakeDeploymentCanceler{
				dep: canonical,
				got: &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := cancelServiceDeploymentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, canceler)
			rec := cancelServiceDeployment(handler, depID, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("canceler received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.DeploymentID != depID {
					t.Errorf("canceler received deployment id %q, want the path parameter %q",
						captured.DeploymentID, depID)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (deny); body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != "" || captured.DeploymentID != "" {
				t.Errorf("canceler was reached for a denied %s; got %+v — engine must reject before the handler runs",
					tc.name, captured)
			}
			if body := rec.Body.String(); cancelDeploymentDenyBodyLeak(body) {
				t.Errorf("%s deny response leaked canonical deployment data: %s", tc.name, body)
			}
		})
	}
}

// TestCancelServiceDeploymentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces as Unauthenticated — never reaches
// the canceler and never receives canonical row data.
func TestCancelServiceDeploymentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		depID = canonicalDeploymentCancelMatrixID
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

			var captured store.CancelDeploymentInput
			canceler := fakeDeploymentCanceler{
				dep: canonicalDeploymentForCancelMatrix(org, depID),
				got: &captured,
			}
			handler := cancelServiceDeploymentHandlerFor(
				auth.Identity{}, apierr.Unauthenticated("api key revoked"), canceler)
			rec := cancelServiceDeployment(handler, depID, "yk_no_longer_valid")

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != "" || captured.DeploymentID != "" {
				t.Errorf("canceler was reached for a revoked/expired credential; got %+v — it must never run",
					captured)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				cancelDeploymentDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or canonical deployment data", body)
			}
		})
	}
}

// TestCancelServiceDeploymentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for deployment.cancel on the bare-id route.
// The resource org id is taken from the PRINCIPAL'S home org — the
// {deployment_id} path parameter alone never widens the resource to
// another tenant. CapDeploy is OUTSIDE the engine's
// `CapSupport && (CapRead || CapSupport)` exception, so every role —
// including Support — is denied cross-tenant at the engine
// (defence-in-depth alongside the persistence-layer 404).
//
//   - A principal in org_attacker hitting POST /v1/deployments/
//     {dep_victim}/cancel with a valid Owner token reaches the engine
//     with a same-tenant resource ({org_attacker, KindDeployment}) —
//     allowed by the role at CapDeploy — and then reaches the tenant-
//     scoped persistence layer with the principal's home org id and
//     the foreign deployment id. A production *store.DeploymentService
//     cannot match a deployment row that belongs to another tenant,
//     so the request surfaces as a deterministic 404 E_NOT_FOUND,
//     never disguised as a 200 with foreign data and never as a 403
//     that would confirm existence.
//
//   - Engine defence-in-depth: at a hypothetical foreign-org resource
//     scope, every role including Support is denied via
//     ReasonDeniedCrossTenant — CapDeploy is OUTSIDE the support
//     cross-tenant exception. This is the load-bearing distinction
//     from deployment.read (CapRead is INSIDE the exception, so
//     support is allowed cross-tenant for read actions).
func TestCancelServiceDeploymentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignDepID    = "dep_victim_target"
		victimOrgNeedle = "org_victim"
	)

	var captured store.CancelDeploymentInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	canceler := fakeDeploymentCanceler{
		err: apierr.NotFound("deployment", foreignDepID),
		got: &captured,
	}
	handler := cancelServiceDeploymentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, canceler)
	rec := cancelServiceDeployment(handler, foreignDepID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant deployment_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("canceler received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
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
	// scope. CapDeploy is OUTSIDE the support cross-tenant exception,
	// so EVERY role — including Support — is denied via
	// ReasonDeniedCrossTenant.
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
		{policy.RoleSupport, "support"},
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionDeploymentCancel, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(deployment.cancel, foreign org) for %s = %+v, want deny via %q — CapDeploy is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCancelServiceDeploymentPolicyGrantContainment proves scoped
// grants cannot reach this endpoint at all — every project-,
// environment-, and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because deploymentIDResolver pins NO
// ProjectID / EnvironmentID / ServiceID on the resource scope (the
// deployment_id itself is not a scope leg). The PRD containment
// properties are pinned at their natural scopes (a service /
// environment / project resource), then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (the canceler must never run on a deny), and
// that an organization-level Admin grant is allowed end-to-end.
// Crucially — and load-bearing against the read-side matrix — an
// organization-level Viewer grant is DENIED here because Viewer holds
// only CapRead, not CapDeploy.
func TestCancelServiceDeploymentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalDeploymentCancelMatrixProject
		env     = canonicalDeploymentCancelMatrixEnv
		svcID   = canonicalDeploymentCancelMatrixService
		depID   = canonicalDeploymentCancelMatrixID
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: policy.Scope{OrganizationID: org},
	}

	// Project-level grant: Admin on the parent project (Admin holds
	// CapDeploy — a project-scoped Developer grant would behave the
	// same, but Admin keeps the role symmetric with the cross-deny
	// load-bearing check below). At a fully scoped service resource
	// INSIDE the granted project the engine allows; at a sibling
	// project the engine denies; and at THIS endpoint's bare-id
	// scope, the project-scoped grant is denied at the boundary.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_dep_cancel_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.cancel) at the parent project's service for the target-project admin grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_dep_cancel_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.cancel) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionDeploymentCancel, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.cancel) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionDeploymentCancel, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.cancel) at the deployment-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: Developer on the staging environment.
	// "env grant does not imply access to production unless production
	// is explicitly granted" — pinned at env / service resources for
	// the cancel action.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("deployment.cancel on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("deployment.cancel on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDeploymentCancel, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.cancel) at the deployment-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: Developer on the deployment's parent
	// service. The grant scope pins ProjectID + EnvironmentID +
	// ServiceID, so the engine's covers() rule denies the bare-id
	// deployment resource scope. At a fully scoped service resource
	// the grant DOES authorize, but the service-level grant does not
	// widen to parent-level resources or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("deployment.cancel on the granted service (full scope) = %+v, want allow",
			got)
	}
	// A service grant does not widen to the parent environment (a
	// secret-bearing parent resource).
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("env.read on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to parent secrets",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCancel, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("deployment.cancel on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionDeploymentCancel, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(deployment.cancel) at the deployment-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds CapDeploy
	// through the role catalog, so deployment.cancel is allowed via
	// ReasonAllowedByGrant on the bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionDeploymentCancel, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(deployment.cancel) at the deployment-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org — BUT Viewer holds
	// only CapRead, not CapDeploy, so deployment.cancel is denied via
	// ReasonDeniedNoCapability. Load-bearing distinction from the
	// read-side grant matrix where org-level Viewer is allowed for
	// CapRead actions; a future catalog change that downgraded
	// deployment.cancel from CapDeploy to CapRead would silently let
	// every viewer key cancel any deployment in the org, and this
	// assertion blocks that regression.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionDeploymentCancel, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(deployment.cancel) at the deployment-id route for an org-level viewer grant = %+v, want deny via %q — Viewer holds CapRead only",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// canceler must never run.
	var projCaptured store.CancelDeploymentInput
	projCanceler := fakeDeploymentCanceler{
		dep: canonicalDeploymentForCancelMatrix(org, depID),
		got: &projCaptured,
	}
	projHandler := cancelServiceDeploymentHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projCanceler)
	projRec := cancelServiceDeployment(projHandler, depID, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCaptured.OrganizationID != "" || projCaptured.DeploymentID != "" {
		t.Errorf("canceler was reached for a project-scoped grant principal; got %+v — the engine must reject before the handler runs",
			projCaptured)
	}
	if body := projRec.Body.String(); cancelDeploymentDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical deployment data: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: a service-scoped grant principal — even one
	// naming the deployment's actual parent service — is also denied
	// at the boundary on the bare-id route.
	var svcCaptured store.CancelDeploymentInput
	svcCanceler := fakeDeploymentCanceler{
		dep: canonicalDeploymentForCancelMatrix(org, depID),
		got: &svcCaptured,
	}
	svcHandler := cancelServiceDeploymentHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcCanceler)
	svcRec := cancelServiceDeployment(svcHandler, depID, "a-valid-token")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.DeploymentID != "" {
		t.Errorf("canceler was reached for a service-scoped grant principal; got %+v",
			svcCaptured)
	}
	if body := svcRec.Body.String(); cancelDeploymentDenyBodyLeak(body) {
		t.Errorf("service-scoped grant deny response leaked the canonical deployment data: %s", body)
	}

	// Wire-level proof: an org-level Viewer grant principal is denied
	// at the boundary — CapRead does not authorize CapDeploy on this
	// endpoint, the load-bearing distinction from the read-side
	// matrix where the same grant is allowed end-to-end.
	var orgViewerCaptured store.CancelDeploymentInput
	orgViewerCanceler := fakeDeploymentCanceler{
		dep: canonicalDeploymentForCancelMatrix(org, depID),
		got: &orgViewerCaptured,
	}
	orgViewerHandler := cancelServiceDeploymentHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgViewerCanceler)
	orgViewerRec := cancelServiceDeployment(orgViewerHandler, depID, "a-valid-token")
	if orgViewerRec.Code != http.StatusForbidden {
		t.Fatalf("org-viewer grant wire status = %d, want 403 (CapRead does not authorize CapDeploy); body %s",
			orgViewerRec.Code, orgViewerRec.Body.String())
	}
	if orgViewerCaptured.OrganizationID != "" || orgViewerCaptured.DeploymentID != "" {
		t.Errorf("canceler was reached for an org-level viewer grant principal; got %+v",
			orgViewerCaptured)
	}

	// Wire-level proof: an org-level Admin grant principal passes the
	// engine and reaches the canceler with the principal's home org id.
	var orgCaptured store.CancelDeploymentInput
	orgCanceler := fakeDeploymentCanceler{
		dep: canonicalDeploymentForCancelMatrix(org, depID),
		got: &orgCaptured,
	}
	orgHandler := cancelServiceDeploymentHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgCanceler)
	orgRec := cancelServiceDeployment(orgHandler, depID, "a-valid-token")
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-admin grant wire status = %d, want 200; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCaptured.OrganizationID != org || orgCaptured.DeploymentID != depID {
		t.Errorf("canceler captured (org=%q, dep=%q), want (%q, %q) for the org-admin allow path",
			orgCaptured.OrganizationID, orgCaptured.DeploymentID, org, depID)
	}
}
