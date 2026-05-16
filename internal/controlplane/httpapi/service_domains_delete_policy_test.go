package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for DELETE
// /v1/services/{service_id}/domains/{domain_id} (BE-0246). Where
// service_domains_delete_test.go proves the endpoint's wire contract
// (BE-0244 + BE-0245), this file proves its authorization contract:
// that action domain.delete cannot be bypassed by — or remove a
// domain row because of — the principal's role, revoked credentials,
// home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the other bare-id /v1/services/{service_id}/... routes carry. The
// authorization contract here is the structural twin of
// service_domains_update_policy_test.go (BE-0243, same CapWrite tier,
// same resolver) — same scoped-grant denial pattern, same support-
// cross-tenant suppression at the resolver, same engine cross-tenant
// deny for CapWrite. The path carries no parent project_id, so the
// resource scope leaves ProjectID empty and the engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not): ALL project-, environment-, and
// service-scoped grants are denied at the boundary via
// ReasonDeniedOutOfScope — even a service-scoped Admin grant naming
// THIS service's id, because the bare-id resource scope has no
// ProjectID for the grant to cover.
//
// domain.delete requires CapWrite (catalog.go: ActionDomainDelete ->
// CapWrite). The role matrix for a principal acting on its own
// organization therefore splits along the write capability class:
//   - Owner / Admin / Developer hold CapWrite and are allowed
//     (ReasonAllowedByRole).
//   - CI is CapSelf+CapRead+CapDeploy (no CapWrite) — denied
//     (ReasonDeniedNoCapability). Automation keys CAN trigger
//     deployments but CANNOT mutate domain rows.
//   - Viewer is CapSelf+CapRead — denied (ReasonDeniedNoCapability).
//   - Support is CapSelf+CapRead+CapSupport (no CapWrite) — denied
//     (ReasonDeniedNoCapability). Support is a deliberate cross-
//     tenant READ exception, never a write one.
//
// Cross-tenant: domain.delete is CapWrite, OUTSIDE the engine's
// cross-tenant exception — so EVERY role, INCLUDING Support, is
// denied cross-tenant via ReasonDeniedCrossTenant.
//
// The service_domains table carries no credential material — the
// certificate_type column names the issuance behavior only. The
// load-bearing deny-leak needles are therefore the path domain_id
// and the canned deleter output. Tenant-leakage and no-write
// invariants apply: a denied response never echoes the canonical
// domain id / hostname / path, the foreign tenant's id, or the path
// service id; and the deleter MUST never run on any deny path — a
// scoped key denied on the wire cannot have committed a destructive
// domain row removal in the background. The "no destructive op on
// deny" invariant is structurally more load-bearing for DELETE than
// for any other mutation because the row's removal is irreversible
// at the application layer (the audit trail outlives it, but the
// desired-state row does not).

const (
	canonicalDomainDeleteMatrixServiceID   = "svc_matrix_domain_delete"
	canonicalDomainDeleteMatrixDomainID    = "sdom_matrix_delete"
	canonicalDomainDeleteMatrixHostname    = "domain-delete-matrix-recognisable-needle.example"
	canonicalDomainDeleteMatrixPath        = "/matrix-delete-recognisable-needle"
	canonicalDomainDeleteMatrixProject     = "prj_domain_delete_matrix_parent"
	canonicalDomainDeleteMatrixEnvironment = "env_domain_delete_matrix_parent"
)

// canonicalDeletedMatrixServiceDomain is the row a deny-path fake
// deleter would return if it were (incorrectly) reached. The
// body-leak guard needles for these recognisable values, so an
// accidental on-deny render of the "deleted" domain fails the test
// even before the deleter-not-reached assertion.
func canonicalDeletedMatrixServiceDomain(orgID, serviceID string) store.ServiceDomain {
	return store.ServiceDomain{
		ID:              canonicalDomainDeleteMatrixDomainID,
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		Hostname:        canonicalDomainDeleteMatrixHostname,
		Path:            canonicalDomainDeleteMatrixPath,
		Port:            443,
		HTTPS:           true,
		CertificateType: store.ServiceDomainCertificateLetsEncrypt,
		Version:         2,
	}
}

// deleteServiceDomainDenyBodyLeak reports whether body contains any
// of the canned deleted-domain fields, the canned parent project /
// environment ids, or other caller-recognisable identifiers. A
// denied response that accidentally rendered any of these fails the
// test: a denied deleted-domain field would mean the deleter ran and
// the response leaked its output even though the wire said 403 (or
// worse, a row was destroyed in the background while the agent saw
// a denial).
func deleteServiceDomainDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalDomainDeleteMatrixDomainID,
		canonicalDomainDeleteMatrixHostname,
		canonicalDomainDeleteMatrixPath,
		canonicalDomainDeleteMatrixProject,
		canonicalDomainDeleteMatrixEnvironment,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestDeleteServiceDomainPolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner / Admin / Developer (own org) are allowed; CI /
// Viewer / Support (own org) are denied at the role boundary.
func TestDeleteServiceDomainPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDomainDeleteMatrixServiceID
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
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionDomainDelete, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(domain.delete) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(domain.delete) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			canonical := canonicalDeletedMatrixServiceDomain(org, svcID)
			var captured store.DeleteServiceDomainInput
			callCount := 0
			deleter := fakeServiceDomainDeleter{
				domain:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := deleteServiceDomainHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, deleter)
			rec := deleteServiceDomain(handler, svcID, canonicalDomainDeleteMatrixDomainID, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("deleter call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("deleter received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svcID {
					t.Errorf("deleter received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				if captured.DomainID != canonicalDomainDeleteMatrixDomainID {
					t.Errorf("deleter received domain id %q, want the path parameter %q",
						captured.DomainID, canonicalDomainDeleteMatrixDomainID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("deleter received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
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
				t.Errorf("deleter was reached (calls=%d) for a denied principal; it must never run — a destructive op on a deny path is the worst possible failure mode",
					callCount)
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" || captured.DomainID != "" {
				t.Errorf("deleter captured (org=%q svc=%q dom=%q) for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID, captured.DomainID)
			}
			if body := rec.Body.String(); deleteServiceDomainDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical domain identifiers: %s", body)
			}
		})
	}
}

// TestDeleteServiceDomainPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired is
// denied action domain.delete with a stable 403 E_FORBIDDEN, even
// when the underlying role would have allowed it. The no-run
// assertion is load-bearing here: a destructive op committed in the
// background while the wire reports 403 would be the worst possible
// failure mode for a credential that the operator has just revoked.
func TestDeleteServiceDomainPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDomainDeleteMatrixServiceID
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

			principal := orgPrincipal(tc.id, org, policy.RoleDeveloper)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			canonical := canonicalDeletedMatrixServiceDomain(org, svcID)
			var captured store.DeleteServiceDomainInput
			callCount := 0
			deleter := fakeServiceDomainDeleter{
				domain:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := deleteServiceDomainHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, deleter)
			rec := deleteServiceDomain(handler, svcID, canonicalDomainDeleteMatrixDomainID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("deleter was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				deleteServiceDomainDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded domain data", body)
			}
		})
	}
}

// TestDeleteServiceDomainPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for domain.delete on the service-id route.
// As with the update twin, the resource org id is taken from the
// PRINCIPAL'S home org — the {service_id} path parameter alone never
// widens the resource to another tenant. Tenant isolation on the
// wire is therefore structural at the persistence layer: a production
// store cannot match a service-domain row that belongs to another
// tenant, so the request surfaces as a deterministic 404 E_NOT_FOUND.
func TestDeleteServiceDomainPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_domain_delete"
		foreignDomainID = "sdom_victim_delete"
		victimOrgNeedle = "org_victim"
	)

	var captured store.DeleteServiceDomainInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	deleter := fakeServiceDomainDeleter{
		err:       apierr.NotFound("service domain", foreignDomainID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, deleter)
	rec := deleteServiceDomain(handler, foreignSvcID, foreignDomainID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("deleter call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("deleter received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID {
		t.Errorf("deleter received service id %q, want the path parameter %q",
			captured.ServiceID, foreignSvcID)
	}
	if captured.DomainID != foreignDomainID {
		t.Errorf("deleter received domain id %q, want the path parameter %q",
			captured.DomainID, foreignDomainID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary: domain.delete is CapWrite,
	// OUTSIDE the engine clause `CapSupport && (CapRead || CapSupport)`
	// — so EVERY role, INCLUDING Support, is denied cross-tenant.
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
			got := e.Decide(p, policy.ActionDomainDelete, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(domain.delete, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestDeleteServiceDomainPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope on the bare-id route.
func TestDeleteServiceDomainPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalDomainDeleteMatrixProject
		env     = canonicalDomainDeleteMatrixEnvironment
		svcID   = "svc_matrix_domain_delete_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level developer grant.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_domain_delete_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(domain.delete) at the parent project's service for the target-project developer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_domain_delete_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Sibling-project containment at the project resource.
	if got := e.Decide(projectDevGrantee, policy.ActionDomainDelete, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine.
	if got := e.Decide(projectDevGrantee, policy.ActionDomainDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a service resource inside the parent
	// project, domain.delete must fail with ReasonDeniedNoCapability.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.delete) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Project-level CI grant: confers CapRead+CapDeploy at the project
	// but not CapWrite. Even at a service resource inside the parent
	// project, domain.delete must fail with ReasonDeniedNoCapability —
	// automation keys are explicitly disallowed from destroying
	// domains.
	projectCIGrantee := policy.Principal{
		ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleCI, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectCIGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.delete) at a service resource inside the parent project for a project-scoped CI grant = %+v, want deny via %q — CI grants do NOT confer CapWrite",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: developer on the staging environment.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("domain.delete on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("domain.delete on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDomainDelete, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDomainDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on THIS service.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("domain.delete on the granted service (full scope) = %+v, want allow",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("environment.update on the parent environment for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionDomainDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("domain.delete on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionDomainDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.delete) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds CapWrite,
	// so domain.delete is allowed via ReasonAllowedByGrant on the
	// bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionDomainDelete, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(domain.delete) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: confers CapRead at the org but
	// no CapWrite. domain.delete is denied via ReasonDeniedNoCapability.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionDomainDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.delete) at the service-id route for an org-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// deleter must never run. The no-run assertion is structurally
	// load-bearing for DELETE: a destructive op committed on a deny
	// path is the worst possible failure mode.
	var capturedProj store.DeleteServiceDomainInput
	projCallCount := 0
	projDeleter := fakeServiceDomainDeleter{
		gotInput:  &capturedProj,
		callCount: &projCallCount,
	}
	projHandler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projDeleter)
	projRec := deleteServiceDomain(projHandler, svcID, canonicalDomainDeleteMatrixDomainID, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("deleter was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); deleteServiceDomainDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical domain identifiers: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an env-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedEnv store.DeleteServiceDomainInput
	envCallCount := 0
	envDeleter := fakeServiceDomainDeleter{
		gotInput:  &capturedEnv,
		callCount: &envCallCount,
	}
	envHandler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: envStagingGrantee, Method: auth.MethodAPIKey}, nil, envDeleter)
	envRec := deleteServiceDomain(envHandler, svcID, canonicalDomainDeleteMatrixDomainID, "a-valid-token")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("env-scoped grant wire status = %d, want 403; body %s", envRec.Code, envRec.Body.String())
	}
	if envCallCount != 0 {
		t.Errorf("deleter was reached (calls=%d) for an env-scoped grant principal; the engine must reject before the handler runs",
			envCallCount)
	}

	// Wire-level proof: a service-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedSvc store.DeleteServiceDomainInput
	svcCallCount := 0
	svcDeleter := fakeServiceDomainDeleter{
		gotInput:  &capturedSvc,
		callCount: &svcCallCount,
	}
	svcHandler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcDeleter)
	svcRec := deleteServiceDomain(svcHandler, svcID, canonicalDomainDeleteMatrixDomainID, "a-valid-token")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCallCount != 0 {
		t.Errorf("deleter was reached (calls=%d) for a service-scoped grant principal; the engine must reject before the handler runs",
			svcCallCount)
	}

	// Wire-level proof: an org-level admin grant principal passes the
	// engine and reaches the deleter with the principal's home org id.
	var capturedOrg store.DeleteServiceDomainInput
	orgCallCount := 0
	orgDeleter := fakeServiceDomainDeleter{
		domain:    canonicalDeletedMatrixServiceDomain(org, svcID),
		gotInput:  &capturedOrg,
		callCount: &orgCallCount,
	}
	orgHandler := deleteServiceDomainHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgDeleter)
	orgRec := deleteServiceDomain(orgHandler, svcID, canonicalDomainDeleteMatrixDomainID, "a-valid-token")
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-admin grant wire status = %d, want 200; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("deleter call count = %d, want 1 for an org-level admin grant", orgCallCount)
	}
	if capturedOrg.OrganizationID != org || capturedOrg.ServiceID != svcID || capturedOrg.DomainID != canonicalDomainDeleteMatrixDomainID {
		t.Errorf("deleter captured (org=%q, svc=%q, dom=%q), want (%q, %q, %q) for the org-admin allow path",
			capturedOrg.OrganizationID, capturedOrg.ServiceID, capturedOrg.DomainID, org, svcID, canonicalDomainDeleteMatrixDomainID)
	}
}
