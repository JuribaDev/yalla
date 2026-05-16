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

// Policy-matrix coverage for POST /v1/services/{service_id}/stop
// (BE-0225). Where services_stop_test.go proves the endpoint's wire
// contract (BE-0223 + BE-0224), this file proves its authorization
// contract: that action service.stop cannot be bypassed by — or
// render a mutation because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), which pins ONLY the
// OrganizationID and ServiceID legs of the resource scope to the
// principal's home organization and the path service id. The bare
// service-id path carries NO ProjectID leg, so the resource scope
// leaves ProjectID empty. The authorization contract on this route is
// the structural twin of services_restart_policy_test.go (the
// restart sibling on the same resolver) — same CapDeploy capability,
// same cross-tenant posture, same one-way covers() containment — but
// for the service-stop action.
//
//   - CapDeploy splits the role matrix: Owner / Admin / Developer /
//     CI are allowed; Viewer (CapRead only) and Support (CapRead +
//     CapSupport, but NOT CapDeploy) are denied.
//   - Cross-tenant: service.stop is CapDeploy, which is OUTSIDE
//     the engine's `CapSupport && (CapRead || CapSupport)` exception,
//     so every role — including Support — is denied cross-tenant.
//     serviceIDResolver pins the resource to the principal's OWN home
//     org anyway, so a cross-tenant service_id reaches the
//     persistence layer with the principal's org and surfaces as a
//     404 at the tenant-scoped row lookup; the engine-level
//     foreign-org matrix is also asserted as defence-in-depth.
//
// Grant containment: serviceIDResolver pins NO ProjectID leg on the
// resource scope, and the engine's covers() rule is one-way (a grant
// scope that pins ProjectID cannot cover a resource scope that does
// not), so ALL project-, environment-, and service-scoped grants are
// denied at the boundary via ReasonDeniedOutOfScope — even a
// service-scoped Admin grant naming the SAME service id. The PRD's
// three containment properties — sibling project, environment grant
// not implying production, service grant shielding parent-level
// resources and unrelated services — are pinned against the engine
// at their natural scopes, then tied back to the wire by proving that
// ALL three scoped key types are denied OutOfScope against THIS
// endpoint. An organization-level Admin grant — which pins no
// ProjectID and covers any resource scope in the same org — is
// allowed end-to-end (Admin holds CapDeploy through the role
// catalog). An organization-level Viewer grant is DENIED at this
// endpoint because Viewer holds only CapRead, not CapDeploy — the
// load-bearing distinction from the read-side grant matrix where
// org-level Viewer is allowed.

// canonicalServiceForStopMatrix is the row every test in this file
// would receive back from the stopper on an allow path. The ids are
// deliberately recognisable so deny-path leak guards can needle for
// them — a denied response that contains any of them fails the test.
func canonicalServiceForStopMatrix(orgID string) store.Service {
	created := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	return store.Service{
		ID:             canonicalStopMatrixService,
		OrganizationID: orgID,
		ProjectID:      canonicalStopMatrixProject,
		EnvironmentID:  canonicalStopMatrixEnv,
		Slug:           canonicalStopMatrixSlug,
		DisplayName:    "API",
		Kind:           store.ServiceKindApplication,
		Version:        9,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
}

const (
	canonicalStopMatrixSlug    = "matrix-stop-api"
	canonicalStopMatrixProject = "prj_matrix_stop_parent"
	canonicalStopMatrixEnv     = "env_matrix_stop_parent"
	canonicalStopMatrixService = "svc_matrix_stop_parent"
)

// stopServiceDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical stop service. A
// denied response that contains any of these fails the test — proof
// that the stopper ran (which it must not on a deny) or that the
// deny envelope echoed row data into the response body.
func stopServiceDenyBodyLeak(body string) bool {
	for _, needle := range []string{
		canonicalStopMatrixSlug,
		canonicalStopMatrixProject,
		canonicalStopMatrixEnv,
	} {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

// TestStopServicePolicyMatrixRoles drives every built-in role through
// the production request path. CapDeploy splits the role matrix:
// Owner / Admin / Developer / CI hold CapDeploy and the stopper is
// reached on the allow path with the principal's home org and the
// path service id; Viewer / Support hold CapRead + (CapSupport) but
// NOT CapDeploy and are denied at the policy boundary before the
// stopper runs.
func TestStopServicePolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalStopMatrixService
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
			// catalog or builtinRoleCaps regression fails here.
			// Owner/Admin/Developer/CI hold CapDeploy and are allowed;
			// Viewer (CapRead only) and Support (CapRead+CapSupport,
			// no CapDeploy) are denied via ReasonDeniedNoCapability.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionServiceStop, svcResource)
			if got.Allow != tc.allow || got.Reason != tc.reason {
				t.Errorf("Decide(service.stop) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.allow, tc.reason)
			}

			canonical := canonicalServiceForStopMatrix(org)
			var captured store.StopServiceInput
			stopper := fakeServiceStopper{
				svc: canonical,
				got: &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := stopServiceHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, stopper)
			rec := stopService(handler, svcID, "a-valid-token", nil)

			if tc.allow {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("stopper received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svcID {
					t.Errorf("stopper received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (deny); body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("stopper was reached for a denied %s; got %+v — engine must reject before the handler runs",
					tc.name, captured)
			}
			if body := rec.Body.String(); stopServiceDenyBodyLeak(body) {
				t.Errorf("%s deny response leaked canonical service data: %s", tc.name, body)
			}
		})
	}
}

// TestStopServicePolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces as Unauthenticated — never reaches the stopper and
// never receives canonical row data.
func TestStopServicePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalStopMatrixService
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

			var captured store.StopServiceInput
			stopper := fakeServiceStopper{
				svc: canonicalServiceForStopMatrix(org),
				got: &captured,
			}
			handler := stopServiceHandlerFor(
				auth.Identity{}, apierr.Unauthenticated("api key revoked"), stopper)
			rec := stopService(handler, svcID, "yk_no_longer_valid", nil)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("stopper was reached for a revoked/expired credential; got %+v — it must never run",
					captured)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				stopServiceDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or canonical service data", body)
			}
		})
	}
}

// TestStopServicePolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for service.stop on the bare service-id
// route. The resource org id is taken from the PRINCIPAL'S home org —
// the {service_id} path parameter alone never widens the resource to
// another tenant. CapDeploy is OUTSIDE the engine's `CapSupport &&
// (CapRead || CapSupport)` exception, so every role — including
// Support — is denied cross-tenant at the engine (defence-in-depth
// alongside the persistence-layer 404).
//
//   - A principal in org_attacker hitting POST /v1/services/
//     {svc_victim}/stop with a valid Owner token reaches the engine
//     with a same-tenant resource ({org_attacker, KindService,
//     svc_victim}) — allowed by the role at CapDeploy — and then
//     reaches the tenant-scoped persistence layer with the principal's
//     home org id and the foreign service id. A production
//     *store.ServiceService cannot match a service row that belongs
//     to another tenant, so the request surfaces as a deterministic
//     404 E_NOT_FOUND, never disguised as a 202 with foreign data and
//     never as a 403 that would confirm existence.
//
//   - Engine defence-in-depth: at a hypothetical foreign-org resource
//     scope, every role including Support is denied via
//     ReasonDeniedCrossTenant — CapDeploy is OUTSIDE the support
//     cross-tenant exception. This is the load-bearing distinction
//     from service.read (CapRead is INSIDE the exception, so support
//     is allowed cross-tenant for read actions).
func TestStopServicePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_target"
		victimOrgNeedle = "org_victim"
	)

	var captured store.StopServiceInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	stopper := fakeServiceStopper{
		err: apierr.NotFound("service", foreignSvcID),
		got: &captured,
	}
	handler := stopServiceHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, stopper)
	rec := stopService(handler, foreignSvcID, "a-valid-token", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant service_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("stopper received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
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
			got := e.Decide(p, policy.ActionServiceStop, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(service.stop, foreign org) for %s = %+v, want deny via %q — CapDeploy is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestStopServicePolicyGrantContainment proves scoped grants cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO ProjectID
// leg on the resource scope (the bare service-id path carries no
// parent project_id). The PRD containment properties are pinned at
// their natural scopes (a service / environment / project resource),
// then tied back to the wire by proving that ALL three scoped key
// types are denied OutOfScope against THIS endpoint (the stopper
// must never run on a deny), and that an organization-level Admin
// grant is allowed end-to-end. Crucially — and load-bearing against
// the read-side matrix — an organization-level Viewer grant is
// DENIED here because Viewer holds only CapRead, not CapDeploy.
func TestStopServicePolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalStopMatrixProject
		env     = canonicalStopMatrixEnv
		svcID   = canonicalStopMatrixService
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: Admin on the parent project. At a fully
	// scoped service resource INSIDE the granted project the engine
	// allows; at a sibling project the engine denies; and at THIS
	// endpoint's bare-service-id scope (no ProjectID leg), the
	// project-scoped grant is denied at the boundary.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_stop_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.stop) at the parent project's service for the target-project admin grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_svc_stop_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.stop) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceStop, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.stop) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceStop, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.stop) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: Developer on the staging environment.
	// "env grant does not imply access to production unless production
	// is explicitly granted" — pinned at env / service resources for
	// the stop action.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("service.stop on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("service.stop on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceStop, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.stop) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: Developer on the stop target's service.
	// The grant scope pins ProjectID + EnvironmentID + ServiceID, so
	// the engine's covers() rule denies the bare-service-id resource
	// scope. At a fully scoped service resource the grant DOES
	// authorize, but the service-level grant does not widen to
	// parent-level resources or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("service.stop on the granted service (full scope) = %+v, want allow",
			got)
	}
	// A service grant does not widen to the parent environment (a
	// secret-bearing parent resource).
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("env.read on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to parent secrets",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceStop, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("service.stop on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceStop, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.stop) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds CapDeploy
	// through the role catalog, so service.stop is allowed via
	// ReasonAllowedByGrant on the bare-service-id route, AND on the
	// wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionServiceStop, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.stop) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org — BUT Viewer holds
	// only CapRead, not CapDeploy, so service.stop is denied via
	// ReasonDeniedNoCapability. Load-bearing distinction from the
	// read-side grant matrix where org-level Viewer is allowed for
	// CapRead actions; a future catalog change that downgraded
	// service.stop from CapDeploy to CapRead would silently let every
	// viewer key stop any service in the org, and this assertion
	// blocks that regression.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionServiceStop, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(service.stop) at the service-id route for an org-level viewer grant = %+v, want deny via %q — Viewer holds CapRead only",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-service-id route is denied at the boundary by the engine —
	// the stopper must never run.
	var projCaptured store.StopServiceInput
	projStopper := fakeServiceStopper{
		svc: canonicalServiceForStopMatrix(org),
		got: &projCaptured,
	}
	projHandler := stopServiceHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projStopper)
	projRec := stopService(projHandler, svcID, "a-valid-token", nil)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCaptured.OrganizationID != "" || projCaptured.ServiceID != "" {
		t.Errorf("stopper was reached for a project-scoped grant principal; got %+v — the engine must reject before the handler runs",
			projCaptured)
	}
	if body := projRec.Body.String(); stopServiceDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical service data: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: a service-scoped grant principal — even one
	// naming THIS service's id directly — is also denied at the
	// boundary on the bare-service-id route, because the grant scope
	// pins ProjectID + EnvironmentID + ServiceID while the resource
	// scope leaves ProjectID empty.
	var svcCaptured store.StopServiceInput
	svcStopper := fakeServiceStopper{
		svc: canonicalServiceForStopMatrix(org),
		got: &svcCaptured,
	}
	svcHandler := stopServiceHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcStopper)
	svcRec := stopService(svcHandler, svcID, "a-valid-token", nil)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.ServiceID != "" {
		t.Errorf("stopper was reached for a service-scoped grant principal; got %+v",
			svcCaptured)
	}
	if body := svcRec.Body.String(); stopServiceDenyBodyLeak(body) {
		t.Errorf("service-scoped grant deny response leaked the canonical service data: %s", body)
	}

	// Wire-level proof: an org-level Viewer grant principal is denied
	// at the boundary — CapRead does not authorize CapDeploy on this
	// endpoint, the load-bearing distinction from the read-side matrix
	// where the same grant is allowed end-to-end.
	var orgViewerCaptured store.StopServiceInput
	orgViewerStopper := fakeServiceStopper{
		svc: canonicalServiceForStopMatrix(org),
		got: &orgViewerCaptured,
	}
	orgViewerHandler := stopServiceHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgViewerStopper)
	orgViewerRec := stopService(orgViewerHandler, svcID, "a-valid-token", nil)
	if orgViewerRec.Code != http.StatusForbidden {
		t.Fatalf("org-viewer grant wire status = %d, want 403 (CapRead does not authorize CapDeploy); body %s",
			orgViewerRec.Code, orgViewerRec.Body.String())
	}
	if orgViewerCaptured.OrganizationID != "" || orgViewerCaptured.ServiceID != "" {
		t.Errorf("stopper was reached for an org-level viewer grant principal; got %+v",
			orgViewerCaptured)
	}

	// Wire-level proof: an org-level Admin grant principal passes the
	// engine and reaches the stopper with the principal's home org id
	// and the path service_id.
	var orgCaptured store.StopServiceInput
	orgStopper := fakeServiceStopper{
		svc: canonicalServiceForStopMatrix(org),
		got: &orgCaptured,
	}
	orgHandler := stopServiceHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgStopper)
	orgRec := stopService(orgHandler, svcID, "a-valid-token", nil)
	if orgRec.Code != http.StatusAccepted {
		t.Fatalf("org-admin grant wire status = %d, want 202; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCaptured.OrganizationID != org || orgCaptured.ServiceID != svcID {
		t.Errorf("stopper captured (org=%q, svc=%q), want (%q, %q) for the org-admin allow path",
			orgCaptured.OrganizationID, orgCaptured.ServiceID, org, svcID)
	}
}
