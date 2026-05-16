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
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for GET /v1/services/{service_id} (BE-0186).
// Where services_test.go proves the endpoint's wire contract
// (BE-0184), this file proves its authorization contract: that action
// service.read cannot be bypassed by — or leak a services row because
// of — the principal's role, revoked credentials, home organization,
// or scoped grants.
//
// The route carries serviceIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {service_id} PATH parameter — and CRUCIALLY pins NO ProjectID leg,
// because the bare top-level path carries no parent project_id. That
// is the structural twin of environments_get_policy_test.go (BE-0156)
// against environmentIDResolver and the load-bearing distinction from
// the parent-scoped GET /v1/environments/{environment_id}/services
// route: every scoped grant in the engine pins a ProjectID, and the
// engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not). The
// consequence is that ALL project-, environment-, and service-scoped
// grants are denied at the boundary by ReasonDeniedOutOfScope — even
// a service-scoped Admin grant naming THIS service's id, because the
// grant scope pins a ProjectID the resource scope does not.
// Principals whose only access is a scoped grant must use a parent-
// scoped route to address a service by its (project, environment,
// service) tuple; this route is reserved for org-wide read roles
// (owner, admin, developer, viewer, ci) and org-wide grants.
//
// service.read requires CapRead (catalog.go: ActionServiceRead ->
// CapRead), the same capability class as environment.read,
// project.read, project.grants.read, environment.grants.read,
// limits.read, usage.read, and env.read. All six built-in roles hold
// CapRead, so the role matrix for a principal reading a service in
// its own organization is "all allow"; the assertions that matter are
// that the verdict is reached through the role (ReasonAllowedByRole),
// the reader is called with the principal's own home organization id
// AND the {service_id} path parameter (so the tenant-scoped GetByID
// query cannot match a service in another tenant), and the response
// carries the canonical service row in a stable yalla.output.v1
// envelope.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing service.read against a foreign-tenant
// resource IS allowed via ReasonAllowedBySupport — the same property
// environment.read / project.read / limits.read / usage.read carry.
// Every non-support role is denied with ReasonDeniedCrossTenant. The
// customer-facing route under test cannot reach that engine branch by
// construction (serviceIDResolver pins the resource scope to the
// PRINCIPAL'S home org, not the path's tenant — the support cross-
// tenant exception specifically does NOT apply through this endpoint,
// as the resolver doc and route description make explicit), but
// pinning the engine verdict here means a future endpoint that
// resolves the resource into a foreign-org scope (a hypothetical
// admin tool) inherits a working cross-tenant deny and the documented
// support exception, and a future catalog change that upgraded
// service.read above CapRead would fail here (silently denying every
// support cross-tenant service read) before it could regress a real
// customer.
//
// Unlike project_variables or environment_variables rows (which
// carry secret values), the services table carries NO credential
// material — only structural identifiers, a slug, a display name, a
// kind taxonomy, an optimistic-concurrency version, and lifecycle
// timestamps. The environmentServiceOf projection has no value-
// redaction chokepoint to anchor a deny-path leak guard on; the
// load-bearing needle is the existence of the service row itself
// (and the id / slug / display name a denied principal must not
// learn, plus the parent project_id and environment_id it would
// reveal). Tenant-leakage and no-read invariants apply: a denied
// response never echoes the seeded service id / slug / display name,
// the foreign tenant's id, or the canonical parent project_id /
// environment_id; and the reader MUST never run on any deny path —
// a scoped key denied on the wire cannot have surfaced a service row
// in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, serviceIDResolver, or the engine fails here.
// getService, decodeGetServiceBody, fakeServiceReader,
// seedServiceWire, orgPrincipal, and decodeError are shared with the
// get-service contract suite (services_test.go) and the wider httpapi
// test fixtures; this file adds a small identity-injected handler
// helper (getServiceHandlerForIdentity) so per-test principals can be
// threaded through the production request path — the contract-test
// helper (getServiceHandlerFor) bakes in a single canonical principal
// and authenticator and is unsuitable for a matrix.

// canonicalGetSvcForMatrix is the row every test in this file reads.
// Its ids / slug / display name are deliberately distinct from
// canonicalServiceForGet (used by services_test.go) so the matrices
// cannot accidentally share fixture state through a future shared
// fake, and they are deliberately recognisable so deny-path leak
// guards can needle for them; allow-path assertions compare against
// the same canonical values.
func canonicalGetSvcForMatrix(orgID, projectID, environmentID string) store.Service {
	created := time.Date(2026, 2, 18, 9, 10, 11, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 12, 13, 14, 0, time.UTC)
	return seedServiceWire("svc_matrix_byid", orgID, projectID, environmentID, "byid-svc", "ByID Service Matrix", "application", 7, created, updated)
}

// getSvcDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical service or its
// parent project / environment. A denied response that accidentally
// rendered any of these fails the test: the service row's existence
// (and the slug / display name it names, and the parent project_id /
// environment_id it would reveal) is itself information a denied
// principal must not receive. The quoted forms catch a case-collapsing
// renderer regression. The services table carries no credential
// material at all, so unlike the project_variables matrix there is
// no secret plaintext to anchor.
func getSvcDenyBodyLeak(body string) bool {
	needles := []string{
		"svc_matrix_byid",
		"\"byid-svc\"",
		"\"ByID Service Matrix\"",
		"prj_svc_matrix_parent",
		"env_svc_matrix_parent",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// getServiceHandlerForIdentity wraps the production NewHandler with a
// fakeAuthenticator parameterised on (id, authErr) and the supplied
// ServiceReader. It is the per-test identity-injected sibling of the
// contract suite's getServiceHandlerFor (which bakes in a single
// canonical principal and authenticator and is unsuitable for a
// matrix). Every other port is a no-op fake; the test exercises only
// the GET /v1/services/{service_id} vertical, and the route table is
// wired identically to production. The trailing nil is the optional
// logger, matching every other handler factory in this package.
func getServiceHandlerForIdentity(id auth.Identity, authErr error, reader ServiceReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// TestGetServicePolicyMatrixRoles drives every built-in role through
// the production request path. All six built-in roles hold CapRead,
// so the matrix is "all allow" for a principal reading a service in
// its own organization; the assertions that matter are that the
// verdict is reached through the role (ReasonAllowedByRole), the
// reader is called with the principal's own home org id AND the
// {service_id} path parameter (so a tenant-scoped store query cannot
// match a foreign row), and the response is a stable 200
// yalla.output.v1 envelope carrying the canonical service.
func TestGetServicePolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_parent"
		env     = "env_svc_matrix_parent"
	)
	svc := canonicalGetSvcForMatrix(org, project, env)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svc.ID},
	}

	cases := []struct {
		name string
		role policy.Role
		kind domain.Kind
	}{
		{"owner", policy.RoleOwner, domain.KindUser},
		{"admin", policy.RoleAdmin, domain.KindUser},
		{"developer", policy.RoleDeveloper, domain.KindUser},
		{"viewer", policy.RoleViewer, domain.KindUser},
		{"ci", policy.RoleCI, domain.KindServiceAccount},
		{"support", policy.RoleSupport, domain.KindUser},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. Support
			// reading a service in ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the cross-
			// tenant clause); the Support cross-tenant exception is
			// exercised at the engine in
			// TestGetServicePolicyWrongOrganizationPrincipal — it
			// cannot be exercised at the wire through this route
			// because serviceIDResolver pins the resource scope to the
			// principal's home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionServiceRead, svcResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(service.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotSvc string
			callCount := 0
			reader := fakeServiceReader{
				svc:       svc,
				gotOrgID:  &gotOrg,
				gotSvcID:  &gotSvc,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := getServiceHandlerForIdentity(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getService(handler, svc.ID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 1 {
				t.Errorf("reader call count = %d, want 1 on the allow path", callCount)
			}
			if gotOrg != org {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					gotOrg, org)
			}
			if gotSvc != svc.ID {
				t.Errorf("reader received service id %q, want the path parameter %q",
					gotSvc, svc.ID)
			}
			projection := decodeGetServiceBody(t, rec)
			if projection.ID != svc.ID ||
				projection.Slug != svc.Slug ||
				projection.DisplayName != svc.DisplayName ||
				projection.Kind != svc.Kind ||
				projection.OrganizationID != svc.OrganizationID ||
				projection.ProjectID != svc.ProjectID ||
				projection.EnvironmentID != svc.EnvironmentID ||
				projection.Version != svc.Version {
				t.Errorf("service = %+v, want (%s, %s, %s, kind=%s, org=%s, project=%s, env=%s, v=%d)",
					projection, svc.ID, svc.Slug, svc.DisplayName, svc.Kind,
					svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.Version)
			}
		})
	}
}

// TestGetServicePolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action service.read with a stable 403 E_FORBIDDEN, even when
// the underlying role would have allowed it. A revoked or expired
// credential must never be able to read a service of the organization
// it once had access to, the reader must never run, and the denied
// body must never echo the principal id, the organization id, the
// path-supplied service id, or any seeded service data.
//
// Underlying role is Owner so a working credential WOULD allow
// service.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0186 ("revoked key,
// expired key").
func TestGetServicePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_parent"
		env     = "env_svc_matrix_parent"
	)
	svc := canonicalGetSvcForMatrix(org, project, env)

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

			principal := orgPrincipal(tc.id, org, policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var gotOrg, gotSvc string
			callCount := 0
			reader := fakeServiceReader{
				svc:       svc,
				gotOrgID:  &gotOrg,
				gotSvcID:  &gotSvc,
				callCount: &callCount,
			}
			handler := getServiceHandlerForIdentity(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getService(handler, svc.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotOrg != "" || gotSvc != "" {
				t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, gotOrg, gotSvc)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				getSvcDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded service data", body)
			}
		})
	}
}

// TestGetServicePolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for service.read on the service-id route. Unlike GET
// /v1/organizations/{org_id}, which takes the org id from the PATH
// (and so fires the engine's cross-tenant clause for a foreign
// {org_id}), this route takes the resource org id from the
// PRINCIPAL'S home org — the {service_id} path parameter alone never
// widens the resource to another tenant. Tenant isolation on the wire
// is therefore structural at the persistence layer, not the policy
// boundary:
//
//   - A principal in org_attacker hitting GET /v1/services/{svc_victim}
//     with a valid Owner token reaches the engine with a same-tenant
//     resource ({org_attacker, svc_victim}) — allowed by the role at
//     CapRead — and then reaches the tenant-scoped GetByID query with
//     the principal's home org id and the foreign service id. A
//     production *store.ServiceReader (which combines organization_id
//     and service_id in its WHERE clause) cannot match a row that
//     belongs to another tenant, so the request surfaces as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 200 with
//     foreign data and never as a 403 that would confirm existence.
//     The body must never echo the foreign org id even though no wire
//     input could place it there, because the persistence layer must
//     not leak foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY non-support role MUST
//     be denied via ReasonDeniedCrossTenant, and a Support principal
//     MUST be allowed via ReasonAllowedBySupport (CapRead is inside
//     the engine clause `roleCaps.has(CapSupport) && (required ==
//     CapRead || required == CapSupport)`). The customer-facing route
//     under test cannot reach this engine branch by construction —
//     serviceIDResolver pins the resource scope to the principal's
//     own home org — but the engine verdict is the authoritative
//     source of the documented support exception, and a future
//     catalog change that upgraded service.read above CapRead would
//     fail here (silently denying every support cross-tenant service
//     read) before it could regress a real customer.
func TestGetServicePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_byid"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/services/{svc_victim} with a valid Owner token. The fake
	// mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, serviceID) pair does not match a
	// row, so a principal whose home org is org_attacker reading a
	// service that belongs to org_victim hits the fake with
	// (org_attacker, svc_victim_byid) and gets NotFound. The
	// assertions that matter are structural: the reader is ALWAYS
	// called with the principal's home org id — never with a caller-
	// controlled value — so a production tenant-scoped ServiceReader
	// could not have surfaced the victim's service regardless of
	// database state. The denied body must never echo the victim's
	// org id.
	var gotOrg, gotSvc string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeServiceReader{
		err:       apierr.NotFound("service", foreignSvcID),
		gotOrgID:  &gotOrg,
		gotSvcID:  &gotSvc,
		callCount: &callCount,
	}
	handler := getServiceHandlerForIdentity(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getService(handler, foreignSvcID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant service_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1 — the reader runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign service id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			gotOrg, ownOrg)
	}
	if gotSvc != foreignSvcID {
		t.Errorf("reader received service id %q, want the path parameter %q",
			gotSvc, foreignSvcID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. service.read is
	// CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
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
			got := e.Decide(p, policy.ActionServiceRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(service.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches service.read because the
	// catalog maps it to CapRead. This locks the CapRead requirement
	// against the support cross-tenant path so a future catalog change
	// that upgraded service.read above CapRead would fail here
	// (silently denying every support cross-tenant service read)
	// before it could regress a real customer. The customer-facing
	// route under test cannot reach this engine branch by construction
	// — serviceIDResolver pins the resource scope to the principal's
	// own home org, so a foreign {service_id} is admitted same-tenant
	// and rejected at the persistence layer — but the engine verdict
	// is the authoritative source of the documented support
	// exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionServiceRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(service.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestGetServicePolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for AND cannot reach this
// endpoint at all — every project-, environment-, and service-scoped
// grant is denied at the boundary by ReasonDeniedOutOfScope, because
// serviceIDResolver pins NO ProjectID leg on the resource scope and
// the engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes (a project resource, an env
// resource, a service resource), then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (even when the grant names the target
// service's own project, the target service's own environment, or
// the target service's own id), while an organization-level Viewer
// grant — which pins no ProjectID and covers any resource scope in
// the same org — is allowed end-to-end.
//
//   - A project-level Viewer grant naming THIS service's parent
//     project CANNOT authorize the read through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     service.read at a service resource in that project — the
//     parent-scoped route's job — and that property is pinned at the
//     engine here so the load-bearing distinction between the two
//     routes' authorization surfaces is explicit.)
//   - A project-level Viewer grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a service resource in the sibling
//     project.
//   - An environment-level Admin grant on a staging environment
//     CANNOT authorize the read either: the grant scope pins
//     ProjectID and the resource scope does not. (The grant DOES
//     authorize service.update at a service inside the staging env —
//     pinned at the engine — but a staging-scoped grant does not
//     reach production unless production is explicitly granted, also
//     pinned at the engine.)
//   - A service-level Admin grant naming THIS service's id CANNOT
//     authorize the read through this route either, because the grant
//     scope pins ProjectID and the resource scope does not. At the
//     engine a service grant does not reach an unrelated sibling
//     service nor expose env.write on the parent environment — the
//     "service grant does not expose parent-level secrets or
//     unrelated services" criterion.
//   - An organization-level Viewer grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because service.read is CapRead and
//     Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the reader is never reached (so a production
// store could not have surfaced the canonical service in the
// background), and the body never echoes the canonical service's
// identifiers or its parent project / environment ids.
func TestGetServicePolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_parent"
		env     = "env_svc_matrix_parent"
	)
	svc := canonicalGetSvcForMatrix(org, project, env)
	e := policy.NewEngine()

	// Resource the service-id route resolves to: OrganizationID from
	// the principal's home org, ServiceID from the path, NO ProjectID
	// and NO EnvironmentID. Every covers() check below against this
	// resource is the engine-level twin of the wire-level deny on
	// this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svc.ID},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, which would normally be
	// enough for service.read on a service resource inside that
	// project — and the engine confirms that at a service resource
	// nested inside the parent project, so the load-bearing
	// distinction between the two routes is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.read) at a service inside the parent project for the target-project viewer grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at a sibling project's service for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Pin the sibling-project containment at the project resource
	// too, to lock the "project-level grants do not imply access to
	// sibling projects" acceptance criterion against a project resource
	// regardless of which child resource a future endpoint might
	// resolve.
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at a sibling project for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from the parent-scoped route.
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env / service resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("service.update on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("service.update on a service inside production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// Pin the env-to-env containment at the env resource too, so the
	// acceptance criterion is locked regardless of which child the
	// engine sees.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// env-staging grant is denied OutOfScope at the engine. Even an
	// env grant on the very environment the target service belongs to
	// would be denied for the same reason — the next fixture pins
	// that directly so a future relaxation of covers() (e.g. allowing
	// a grant on env_X to cover a resource scope with EnvID=env_X
	// and no ProjectID) cannot land without failing this test.
	if got := e.Decide(envStagingGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a grant on the SAME parent env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service. The "service
	// grant does not expose parent-level secrets or unrelated services"
	// property is pinned at the engine against service / env
	// resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	// And the service grant naming THIS service's own id is still
	// denied OutOfScope at this route's resource scope, because the
	// grant scope pins ProjectID and the resource scope does not — a
	// service grant alone cannot authorize the bare service-id route.
	scopeTargetSvc := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID}
	svcTargetGrantee := policy.Principal{
		ID: "sa_svc_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetSvc}},
	}
	if got := e.Decide(svcTargetGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a grant on the SAME service id = %+v, want deny via %q — covers() is one-way, the service_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// service grant on a sibling service is also denied OutOfScope.
	if got := e.Decide(svcGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// target service via THIS route is a 403 with the stable
	// out-of-scope reason, the reader is never reached (so a
	// production store could never have surfaced the canonical
	// service in the background), and the body never echoes the
	// canonical service's identifiers or the parent project /
	// environment ids. This is the property that confines a project-
	// scoped key to the parent-scoped route only.
	var projGotOrg, projGotSvc string
	projCallCount := 0
	projReader := fakeServiceReader{
		svc:       svc, // would be returned if reader ran — leak guard catches it
		gotOrgID:  &projGotOrg,
		gotSvcID:  &projGotSvc,
		callCount: &projCallCount,
	}
	projHandler := getServiceHandlerForIdentity(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projReader)
	projRec := getService(projHandler, svc.ID, "yk_proj_viewer_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the service-id route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projGotOrg != "" || projGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a project-scoped grantee; it must never run",
			projCallCount, projGotOrg, projGotSvc)
	}
	if body := projRec.Body.String(); getSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME environment
	// id the target service belongs to — hitting the service-id route
	// is a 403, the reader is never reached, and the body never
	// echoes the canonical service. This is the load-bearing property
	// that locks down the service-id route: an environment grant
	// alone does not authorize reads through it.
	var envGotOrg, envGotSvc string
	envCallCount := 0
	envReader := fakeServiceReader{
		svc:       svc,
		gotOrgID:  &envGotOrg,
		gotSvcID:  &envGotSvc,
		callCount: &envCallCount,
	}
	envHandler := getServiceHandlerForIdentity(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getService(envHandler, svc.ID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the service-id route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotOrg != "" || envGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for an env-scoped grantee; it must never run",
			envCallCount, envGotOrg, envGotSvc)
	}
	if body := envRec.Body.String(); getSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee — on the SAME service
	// id the path names — hitting the service-id route is a 403, the
	// reader is never reached, and the body never echoes the canonical
	// service. This is the load-bearing property that confines a
	// service grant to a parent-scoped route: even a key that names
	// THIS exact service cannot authorize a top-level service read
	// through this endpoint.
	var svcGotOrg, svcGotSvc string
	svcCallCount := 0
	svcReader := fakeServiceReader{
		svc:       svc,
		gotOrgID:  &svcGotOrg,
		gotSvcID:  &svcGotSvc,
		callCount: &svcCallCount,
	}
	svcHandler := getServiceHandlerForIdentity(
		auth.Identity{Principal: svcTargetGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getService(svcHandler, svc.ID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the service-id route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotOrg != "" || svcGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotOrg, svcGotSvc)
	}
	if body := svcRec.Body.String(); getSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// An organization-level Viewer grant DOES cover any resource scope
	// in the same org (its grant scope pins nothing past
	// OrganizationID) and — because service.read is CapRead and
	// Viewer holds CapRead — is allowed via ReasonAllowedByGrant. The
	// same key is end-to-end allowed at the wire, with the reader
	// reached on the principal's home org id and the path service id.
	// This locks the CapRead requirement against the grant path so a
	// future catalog change that upgraded service.read above CapRead
	// would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionServiceRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotSvc string
	orgCallCount := 0
	orgReader := fakeServiceReader{
		svc:       svc,
		gotOrgID:  &orgGotOrg,
		gotSvcID:  &orgGotSvc,
		callCount: &orgCallCount,
	}
	orgHandler := getServiceHandlerForIdentity(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getService(orgHandler, svc.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedProjection := decodeGetServiceBody(t, allowedRec)
	if allowedProjection.ID != svc.ID ||
		allowedProjection.Slug != svc.Slug ||
		allowedProjection.OrganizationID != svc.OrganizationID ||
		allowedProjection.ProjectID != svc.ProjectID ||
		allowedProjection.EnvironmentID != svc.EnvironmentID {
		t.Errorf("service = %+v, want (%s, %s, org=%s, project=%s, env=%s)",
			allowedProjection, svc.ID, svc.Slug, svc.OrganizationID, svc.ProjectID, svc.EnvironmentID)
	}
	if orgCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, org)
	}
	if orgGotSvc != svc.ID {
		t.Errorf("reader received service id %q, want the path parameter %q",
			orgGotSvc, svc.ID)
	}

	// And the same project-scoped viewer grantee whose home org id is
	// foreign is denied at the engine: a grant for the parent project
	// inside org_acme, carried by a principal whose home org id is
	// org_sibling, cannot be used to read a service in org_sibling —
	// the cross-tenant guard fires first because the principal's home
	// org no longer matches the grant's scope. This is the engine-
	// level twin of the wire-level "wrong organization" property in
	// TestGetServicePolicyWrongOrganizationPrincipal, applied to a
	// scoped key: stealing a key cannot smuggle it across tenants.
	// (service.read IS inside the support cross-tenant exception, but
	// the principal here is a service account with no CapSupport
	// role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionServiceRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(service.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
