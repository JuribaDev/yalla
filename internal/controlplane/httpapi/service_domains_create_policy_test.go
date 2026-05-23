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

// Policy-matrix coverage for POST /v1/services/{service_id}/domains
// (BE-0240). Where service_domains_create_test.go proves the
// endpoint's wire contract (BE-0238 + BE-0239), this file proves its
// authorization contract: that action domain.create cannot be
// bypassed by — or commit a domain row because of — the principal's
// role, revoked credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the other bare-id /v1/services/{service_id}/... routes carry. The
// authorization contract here is the structural twin of
// environment_services_create_policy_test.go (BE-0183, same CapWrite
// tier) AND services_metrics_policy_test.go / service_domains_policy_test.go
// (same resolver, same one-way covers() rule) — same scoped-grant
// denial pattern, same support-cross-tenant suppression at the
// resolver, same engine cross-tenant deny for CapWrite. The path
// carries no parent project_id, so the resource scope leaves
// ProjectID empty and the engine's covers() rule is one-way (a grant
// scope that pins ProjectID cannot cover a resource scope that does
// not): ALL project-, environment-, and service-scoped grants are
// denied at the boundary via ReasonDeniedOutOfScope — even a service-
// scoped Admin grant naming THIS service's id, because the bare-id
// resource scope has no ProjectID for the grant to cover.
//
// domain.create requires CapWrite (catalog.go: ActionDomainCreate ->
// CapWrite). The role matrix for a principal acting on its own
// organization therefore splits along the write capability class:
//   - Owner / Admin / Developer hold CapWrite and are allowed
//     (ReasonAllowedByRole).
//   - CI is CapSelf+CapRead+CapDeploy (no CapWrite) — denied
//     (ReasonDeniedNoCapability). This is the load-bearing
//     distinction from POST /v1/services/{service_id}/deployments
//     (BE-0207, deployment.create -> CapDeploy), where CI is allowed.
//     Automation keys CAN trigger deployments but CANNOT mutate
//     domain rows.
//   - Viewer is CapSelf+CapRead — denied (ReasonDeniedNoCapability).
//   - Support is CapSelf+CapRead+CapSupport (no CapWrite) — denied
//     (ReasonDeniedNoCapability). Support is a deliberate cross-
//     tenant READ exception, never a write one; the engine's
//     cross-tenant clause is gated on `required == CapRead ||
//     required == CapSupport`, so CapWrite is OUTSIDE that
//     exception. Privileged Yalla support that needs to add a domain
//     on a customer's behalf must go through explicit break-glass
//     admin tooling, not this customer-facing route.
//
// Cross-tenant: domain.create is CapWrite, OUTSIDE the engine's
// cross-tenant exception — so EVERY role, INCLUDING Support, is
// denied cross-tenant via ReasonDeniedCrossTenant. The customer-
// facing route cannot reach the engine's cross-tenant branch by
// construction (serviceIDResolver pins the resource scope to the
// PRINCIPAL'S home org, not the path service's tenant — the cross-
// tenant deny does NOT apply through this endpoint), but pinning the
// engine verdict here means a future endpoint that resolves the
// resource into a foreign-org scope inherits a working cross-tenant
// deny across every role, and a future catalog change that
// downgraded domain.create to CapRead would fail here (silently
// allowing every support cross-tenant domain create) before it could
// regress a real customer.
//
// The service_domains table carries no credential material — the
// certificate_type column names the issuance behavior (lets-encrypt,
// custom, none) but the actual certificate material is held by the
// worker / Dokploy layer and never round-trips through this table.
// The load-bearing deny-leak needles are therefore the caller-
// supplied request-body fields (a domain id, a hostname, a path a
// denied principal must not see echoed back) and the canned creator
// output (the row a deny-path fake creator WOULD have returned).
// Tenant-leakage and no-write invariants apply: a denied response
// never echoes the canonical request-body fields, the canned domain
// id / hostname / path, the foreign tenant's id, or the path service
// id; and the creator MUST never run on any deny path — a scoped
// key denied on the wire cannot have committed a domain row in the
// background.

const (
	canonicalDomainMatrixServiceID   = "svc_matrix_domain_create"
	canonicalDomainMatrixDomainID    = "sdom_matrix_create"
	canonicalDomainMatrixHostname    = "domain-matrix-recognisable-needle.example"
	canonicalDomainMatrixPath        = "/matrix-recognisable-needle"
	canonicalDomainMatrixProject     = "prj_domain_create_matrix_parent"
	canonicalDomainMatrixEnvironment = "env_domain_create_matrix_parent"
)

// canonicalCreateServiceDomainBody is the canonical JSON request
// body every test in this file shares. The body intentionally exposes
// no organization_id, project_id, environment_id, or service_id field
// — the production handler derives the organization id from the
// principal's home org and the service id from the path parameter,
// never from the body — and the strict JSON decoder rejects an
// unknown field smuggled into the body before the creator ever runs.
const canonicalCreateServiceDomainBody = `{"id":"sdom_matrix_create","hostname":"domain-matrix-recognisable-needle.example","path":"/matrix-recognisable-needle","port":443,"https":true,"certificate_type":"lets-encrypt"}`

// canonicalCreatedServiceDomain is the row a deny-path fake creator
// would return if it were (incorrectly) reached. The body-leak guard
// needles for these recognisable values, so an accidental on-deny
// render of the "created" domain fails the test even before the
// creator-not-reached assertion. The version is deliberately non-
// zero so a wire response that surfaced this row would be
// distinguishable from a zero-value envelope.
func canonicalCreatedServiceDomain(orgID, serviceID string) store.ServiceDomain {
	return store.ServiceDomain{
		ID:              canonicalDomainMatrixDomainID,
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		Hostname:        canonicalDomainMatrixHostname,
		Path:            canonicalDomainMatrixPath,
		Port:            443,
		HTTPS:           true,
		CertificateType: store.ServiceDomainCertificateLetsEncrypt,
		Version:         1,
	}
}

// createServiceDomainDenyBodyLeak reports whether body contains any
// of the caller-supplied request-body fields, the canned created-
// domain fields, the canned parent project / environment ids, or
// other caller-recognisable identifiers. A denied response that
// accidentally rendered any of these fails the test: a denied
// request-body field would mean the handler echoed the request after
// policy denial (a tenant boundary smell), and a denied created-
// domain field would mean the creator ran and the response leaked
// its output even though the wire said 403. There is no secret
// plaintext to anchor on — the service_domains table carries no
// credential material at all.
func createServiceDomainDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalDomainMatrixDomainID,
		canonicalDomainMatrixHostname,
		canonicalDomainMatrixPath,
		canonicalDomainMatrixProject,
		canonicalDomainMatrixEnvironment,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestCreateServiceDomainPolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner / Admin / Developer (own org) are allowed; CI /
// Viewer / Support (own org) are denied at the role boundary —
// builtinRoleCaps[RoleCI] is CapSelf+CapRead+CapDeploy (no CapWrite),
// builtinRoleCaps[RoleSupport] is CapSelf+CapRead+CapSupport (no
// CapWrite). The assertions that matter for allow rows are that the
// verdict is reached through the role (ReasonAllowedByRole), the
// creator is reached with the principal's own home organization id,
// the path {service_id}, and the principal id (so the audit record
// names the actor verbatim). For deny rows: 403 yalla.error.v1, the
// stable reason on the wire, the creator MUST NEVER run, and the
// denied body must not echo the canonical domain, the request body,
// or the principal-controlled values.
func TestCreateServiceDomainPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDomainMatrixServiceID
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

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionDomainCreate, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(domain.create) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(domain.create) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			canonical := canonicalCreatedServiceDomain(org, svcID)
			var captured store.CreateServiceDomainInput
			callCount := 0
			creator := fakeServiceDomainCreator{
				domain:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := createServiceDomainHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, creator)
			rec := postServiceDomain(handler, svcID, canonicalCreateServiceDomainBody, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
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
				if captured.DomainID != canonicalDomainMatrixDomainID || captured.Hostname != canonicalDomainMatrixHostname || captured.Path != canonicalDomainMatrixPath {
					t.Errorf("creator intent fields = (id=%q, host=%q, path=%q), want (%q, %q, %q)",
						captured.DomainID, captured.Hostname, captured.Path,
						canonicalDomainMatrixDomainID, canonicalDomainMatrixHostname, canonicalDomainMatrixPath)
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
			if body := rec.Body.String(); createServiceDomainDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical domain or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestCreateServiceDomainPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action domain.create with a stable
// 403 E_FORBIDDEN, even when the underlying role would have allowed
// it. A revoked or expired Developer key must never be able to add a
// domain to the organization it once had access to; the creator
// must never run; and the denied body must never echo the principal
// id, the organization id, or any seeded domain data.
//
// Underlying role is Developer so a working credential WOULD allow
// domain.create; Disabled is the only thing in the way and must be
// load-bearing.
func TestCreateServiceDomainPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalDomainMatrixServiceID
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

			canonical := canonicalCreatedServiceDomain(org, svcID)
			var captured store.CreateServiceDomainInput
			callCount := 0
			creator := fakeServiceDomainCreator{
				domain:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := createServiceDomainHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)
			rec := postServiceDomain(handler, svcID, canonicalCreateServiceDomainBody, "yk_no_longer_valid")

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
				createServiceDomainDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded domain data", body)
			}
		})
	}
}

// TestCreateServiceDomainPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for domain.create on the service-id route.
// As with service.create on the same route, the resource org id is
// taken from the PRINCIPAL'S home org — the {service_id} path
// parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer:
//
//   - A principal in org_attacker hitting POST
//     /v1/services/{svc_victim}/domains with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     svc_victim}) — allowed by the role at CapWrite — and then
//     reaches the tenant-scoped repository query with the principal's
//     home org id and the foreign service id. A production
//     *store.ServiceDomainService cannot match a service row that
//     belongs to another tenant, so the request surfaces as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 201 with
//     foreign data and never as a 403 that would confirm existence.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (the exception covers only CapRead and CapSupport).
func TestCreateServiceDomainPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_domain"
		victimOrgNeedle = "org_victim"
	)

	var captured store.CreateServiceDomainInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	creator := fakeServiceDomainCreator{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := createServiceDomainHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)
	rec := postServiceDomain(handler, foreignSvcID, canonicalCreateServiceDomainBody, "a-valid-token")

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
	// scope inherits a working cross-tenant deny. domain.create is
	// CapWrite, which is OUTSIDE the engine clause `CapSupport &&
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
			got := e.Decide(p, policy.ActionDomainCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(domain.create, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCreateServiceDomainPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO ProjectID
// leg on the resource scope and the engine's covers() rule is
// one-way (a grant scope that pins ProjectID cannot cover a resource
// scope that does not).
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
func TestCreateServiceDomainPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalDomainMatrixProject
		env     = canonicalDomainMatrixEnvironment
		svcID   = "svc_matrix_domain_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: developer on the parent project. Developer
	// confers CapWrite at the project scope, which IS enough for
	// domain.create on a service resource inside that project — the
	// engine confirms that at a service resource nested inside the
	// parent project.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_domain_create_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(domain.create) at the parent project's service for the target-project developer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_domain_create_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Sibling-project containment at the project resource — pins the
	// "project-level grants do not imply sibling projects" criterion.
	if got := e.Decide(projectDevGrantee, policy.ActionDomainCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine.
	if got := e.Decide(projectDevGrantee, policy.ActionDomainCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a service resource inside the parent
	// project (which a parent-scoped write route would target),
	// domain.create must fail with ReasonDeniedNoCapability.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.create) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Project-level CI grant: confers CapRead+CapDeploy at the project
	// but not CapWrite. Even at a service resource inside the parent
	// project, domain.create must fail with ReasonDeniedNoCapability
	// — automation keys are explicitly disallowed from mutating
	// domains. This is the load-bearing distinction from
	// deployment.create where a project-level CI grant IS allowed.
	projectCIGrantee := policy.Principal{
		ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleCI, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectCIGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.create) at a service resource inside the parent project for a project-scoped CI grant = %+v, want deny via %q — CI grants do NOT confer CapWrite, even though CI is allowed on deployment.create at the same scope",
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
	if got := e.Decide(envStagingGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("domain.create on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("domain.create on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	// Env-to-env containment at the env resource too.
	if got := e.Decide(envStagingGrantee, policy.ActionDomainCreate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope, the env-scoped grant is
	// denied at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionDomainCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on THIS service. The grant scope
	// pins ProjectID + EnvironmentID + ServiceID, so the engine's
	// covers() rule denies the bare-id resource scope. At a fully
	// scoped service resource the grant DOES authorize, but a
	// service-level grant does not widen to parent-level resources or
	// unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("domain.create on the granted service (full scope) = %+v, want allow",
			got)
	}
	// Service grant does not authorize a parent environment-level
	// action.
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("environment.update on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to the parent env",
			got)
	}
	// Service grant does not authorize an unrelated sibling service.
	if got := e.Decide(svcGrantee, policy.ActionDomainCreate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("domain.create on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	// And on THIS endpoint's bare-id resource scope, the
	// service-scoped grant is denied at the engine — the load-bearing
	// distinction that forces scoped-grant-only principals onto the
	// parent-scoped route.
	if got := e.Decide(svcGrantee, policy.ActionDomainCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(domain.create) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds
	// CapWrite, so domain.create is allowed via ReasonAllowedByGrant
	// on the bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionDomainCreate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(domain.create) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: confers CapRead at the org but
	// no CapWrite. domain.create is denied via
	// ReasonDeniedNoCapability — the load-bearing distinction from
	// the read-side grant matrix (where an org-level Viewer is
	// allowed).
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionDomainCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(domain.create) at the service-id route for an org-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// creator must never run.
	var capturedProj store.CreateServiceDomainInput
	projCallCount := 0
	projCreator := fakeServiceDomainCreator{
		gotInput:  &capturedProj,
		callCount: &projCallCount,
	}
	projHandler := createServiceDomainHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projCreator)
	projRec := postServiceDomain(projHandler, svcID, canonicalCreateServiceDomainBody, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("creator was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); createServiceDomainDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical domain or caller-supplied request body: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an env-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedEnv store.CreateServiceDomainInput
	envCallCount := 0
	envCreator := fakeServiceDomainCreator{
		gotInput:  &capturedEnv,
		callCount: &envCallCount,
	}
	envHandler := createServiceDomainHandlerFor(
		auth.Identity{Principal: envStagingGrantee, Method: auth.MethodAPIKey}, nil, envCreator)
	envRec := postServiceDomain(envHandler, svcID, canonicalCreateServiceDomainBody, "a-valid-token")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("env-scoped grant wire status = %d, want 403; body %s", envRec.Code, envRec.Body.String())
	}
	if envCallCount != 0 {
		t.Errorf("creator was reached (calls=%d) for an env-scoped grant principal; the engine must reject before the handler runs",
			envCallCount)
	}

	// Wire-level proof: a service-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedSvc store.CreateServiceDomainInput
	svcCallCount := 0
	svcCreator := fakeServiceDomainCreator{
		gotInput:  &capturedSvc,
		callCount: &svcCallCount,
	}
	svcHandler := createServiceDomainHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcCreator)
	svcRec := postServiceDomain(svcHandler, svcID, canonicalCreateServiceDomainBody, "a-valid-token")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCallCount != 0 {
		t.Errorf("creator was reached (calls=%d) for a service-scoped grant principal; the engine must reject before the handler runs",
			svcCallCount)
	}

	// Wire-level proof: an org-level admin grant principal passes the
	// engine and reaches the creator with the principal's home org
	// id.
	var capturedOrg store.CreateServiceDomainInput
	orgCallCount := 0
	orgCreator := fakeServiceDomainCreator{
		domain:    canonicalCreatedServiceDomain(org, svcID),
		gotInput:  &capturedOrg,
		callCount: &orgCallCount,
	}
	orgHandler := createServiceDomainHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgCreator)
	orgRec := postServiceDomain(orgHandler, svcID, canonicalCreateServiceDomainBody, "a-valid-token")
	if orgRec.Code != http.StatusCreated {
		t.Fatalf("org-admin grant wire status = %d, want 201; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("creator call count = %d, want 1 for an org-level admin grant", orgCallCount)
	}
	if capturedOrg.OrganizationID != org || capturedOrg.ServiceID != svcID {
		t.Errorf("creator captured (org=%q, svc=%q), want (%q, %q) for the org-admin allow path",
			capturedOrg.OrganizationID, capturedOrg.ServiceID, org, svcID)
	}
}
