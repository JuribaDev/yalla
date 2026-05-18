package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for GET /v1/services/{service_id}/rendered
// (BE-0198). Where services_rendered_test.go proves the endpoint's
// wire contract (BE-0196), this file proves its authorization
// contract: that action service.read cannot be bypassed by — or leak
// a services row (or its rendered projection) because of — the
// principal's role, revoked credentials, home organization, or scoped
// grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the bare-id GET /v1/services/{service_id} route carries, so the
// authorization contract here is the structural twin of
// services_get_policy_test.go (BE-0186): the policy resource is built
// from the principal's HOME organization id and the {service_id} PATH
// parameter, with NO ProjectID leg — the bare top-level path carries
// no parent project_id. The engine's covers() rule is one-way (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not), so ALL project-, environment-, and service-scoped grants
// are denied at the boundary by ReasonDeniedOutOfScope — even a
// service-scoped Admin grant naming THIS service's id, because the
// grant scope pins a ProjectID the resource scope does not.
// Principals whose only access is a scoped grant must use a parent-
// scoped route to address a service by its (project, environment,
// service) tuple; this route is reserved for org-wide read roles
// (owner, admin, developer, viewer, ci) and org-wide grants.
//
// service.read requires CapRead (catalog.go: ActionServiceRead ->
// CapRead). All six built-in roles hold CapRead, so the role matrix
// for a principal reading a service in its own organization is "all
// allow"; the assertions that matter are that the verdict is reached
// through the role (ReasonAllowedByRole), the reader is called with
// the principal's own home organization id AND the {service_id} path
// parameter (so the tenant-scoped GetByID query cannot match a
// service in another tenant), and the response carries the canonical
// rendered projection in a stable yalla.output.v1 envelope — both
// the underlying service row AND the deterministic identity
// projection (Dokploy-safe name, Dokploy service type, structural
// attribution labels). The rendered.* sub-object carries NO
// credential material today (variables, build, resources, and
// domains are deliberately out of the BE-0196 projection), so on the
// allow path the labels carry only canonical hierarchy ids; on the
// deny path the leak guard catches them by their canonical ids
// regardless.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing service.read against a foreign-tenant
// resource IS allowed via ReasonAllowedBySupport — the same property
// services_get_policy_test.go pins against the bare-id route. The
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
// support cross-tenant rendered read) before it could regress a real
// customer.
//
// The services table carries NO credential material — only structural
// identifiers, a slug, a display name, a kind taxonomy, an
// optimistic-concurrency version, and lifecycle timestamps. The
// rendered projection adds the deterministic identity layer
// (Dokploy-safe canonical name, Dokploy service type, structural
// attribution labels carrying yalla.organization_id /
// yalla.project_id / yalla.environment_id / yalla.service_id) — also
// non-secret. The load-bearing needle is the existence of the
// service row itself (and the id / slug / display name a denied
// principal must not learn, plus the parent project_id and
// environment_id it would reveal); on the deny path the reader MUST
// never run, so the rendered projection is never even computed.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, serviceIDResolver, or the engine fails here.
// getServiceRendered, decodeRenderedServiceBody, fakeServiceReader,
// orgPrincipal, decodeError, and getServiceHandlerForIdentity are
// shared with the rendered contract suite (services_rendered_test.go)
// and the bare-id matrix (services_get_policy_test.go) so this file
// is a focused matrix overlay only — adding distinct canonical
// fixtures and a per-leak-guard so the two service-resource matrices
// cannot accidentally share fixture state through a future shared
// fake.

// canonicalRenderedSvcForMatrix is the row every test in this file
// reads. Its ids / slug / display name are deliberately distinct
// from canonicalServiceForGet (services_test.go),
// canonicalGetSvcForMatrix (services_get_policy_test.go),
// canonicalUpdateSvcForMatrix (services_update_policy_test.go),
// canonicalDeletedSvc (services_delete_test.go), and
// canonicalDeleteSvcForMatrix (services_delete_policy_test.go), so
// no matrix can accidentally share fixture state through a future
// shared fake and the deny-path leak guards can needle for each
// matrix's fixture without false-positive overlap.
//
// IDs MUST be canonical (kind prefix + 26-char Crockford base32
// suffix from domain.MustNewID) because the allow path computes
// domain.DokployName(svc.DisplayName, svc.ID), which runs
// domain.ParseID on the supplied service id; a non-canonical id
// would panic that helper. Production rows always carry canonical
// ids — the store layer enforces this — so the fixture mirrors
// production data.
func canonicalRenderedSvcForMatrix() (orgID, projectID, environmentID string, svc store.Service) {
	orgID = "org_acme"
	projectID = "prj_svc_matrix_rendered_parent"
	environmentID = "env_svc_matrix_rendered_parent"
	created := time.Date(2026, 3, 9, 14, 15, 16, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 18, 19, 20, 0, time.UTC)
	svc = store.Service{
		ID:             domain.MustNewID(domain.KindService).String(),
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
		Slug:           "rendered-svc",
		DisplayName:    "Rendered Service Matrix v2",
		Kind:           "application",
		Version:        9,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	return
}

// renderedSvcDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical service or its
// parent project / environment. A denied response that accidentally
// rendered any of these fails the test: the service row's existence
// (and the slug / display name it names, and the parent project_id /
// environment_id it would reveal) is itself information a denied
// principal must not receive — and the rendered projection's
// Dokploy-safe canonical name and structural labels would carry the
// same ids if a deny path mistakenly invoked the renderer. The
// quoted forms catch a case-collapsing renderer regression. The
// services table carries no credential material at all, and the
// rendered.* projection today carries no variable values / build
// settings / domain hostnames / resource limits, so there is no
// secret plaintext to anchor — only structural identifiers.
//
// The canonical service id is allocated per-test (domain.MustNewID),
// so the needle is supplied at call time rather than encoded as a
// constant.
func renderedSvcDenyBodyLeak(svcID, projectID, environmentID, body string) bool {
	needles := []string{
		svcID,
		"\"rendered-svc\"",
		"\"Rendered Service Matrix v2\"",
		projectID,
		environmentID,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// assertRenderedAllowPath pins the entire allow-path projection: the
// success envelope schema, the service block (id / slug / display
// name / kind / org / project / env / version match the canonical
// row), and the rendered block (Dokploy-safe canonical name,
// Dokploy service type mapped from the row's kind, and the four
// structural attribution labels in deterministic order). It is the
// single chokepoint every allow-path test in this file calls so a
// future change to the rendered envelope shape fails in one place
// rather than scattering across the matrix.
func assertRenderedAllowPath(t *testing.T, rec *httptest.ResponseRecorder, svc store.Service) {
	t.Helper()
	env := decodeRenderedServiceBody(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, "yalla.output.v1")
	}
	s := env.Data.Service
	if s.ID != svc.ID ||
		s.Slug != svc.Slug ||
		s.DisplayName != svc.DisplayName ||
		s.Kind != svc.Kind ||
		s.OrganizationID != svc.OrganizationID ||
		s.ProjectID != svc.ProjectID ||
		s.EnvironmentID != svc.EnvironmentID ||
		s.Version != svc.Version {
		t.Errorf("data.service = %+v, want (%s, %s, %s, kind=%s, org=%s, project=%s, env=%s, v=%d)",
			s, svc.ID, svc.Slug, svc.DisplayName, svc.Kind,
			svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.Version)
	}
	wantName, err := domain.DokployName(svc.DisplayName, domain.ID(svc.ID))
	if err != nil {
		t.Fatalf("DokployName(%q,%q) returned err %v — the canonical fixture id must be parseable",
			svc.DisplayName, svc.ID, err)
	}
	if env.Data.Rendered.Name != wantName {
		t.Errorf("data.rendered.name = %q, want %q (domain.DokployName projection)", env.Data.Rendered.Name, wantName)
	}
	if env.Data.Rendered.Type != string(dokploy.ServiceApplication) {
		t.Errorf("data.rendered.type = %q, want %q (kind %q maps to dokploy.ServiceApplication)",
			env.Data.Rendered.Type, string(dokploy.ServiceApplication), svc.Kind)
	}
	wantLabels := []struct {
		Key   string
		Value string
	}{
		{"yalla.organization_id", svc.OrganizationID},
		{"yalla.project_id", svc.ProjectID},
		{"yalla.environment_id", svc.EnvironmentID},
		{"yalla.service_id", svc.ID},
	}
	if len(env.Data.Rendered.Labels) != len(wantLabels) {
		t.Fatalf("data.rendered.labels count = %d, want %d (deterministic 4-label projection)",
			len(env.Data.Rendered.Labels), len(wantLabels))
	}
	for i, w := range wantLabels {
		got := env.Data.Rendered.Labels[i]
		if got.Key != w.Key || got.Value != w.Value {
			t.Errorf("data.rendered.labels[%d] = {%q,%q}, want {%q,%q} (deterministic identity-attribution projection)",
				i, got.Key, got.Value, w.Key, w.Value)
		}
	}
}

// TestGetServiceRenderedPolicyMatrixRoles drives every built-in role
// through the production request path. All six built-in roles hold
// CapRead, so the matrix is "all allow" for a principal reading a
// service in its own organization; the assertions that matter are
// that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {service_id} path parameter (so a tenant-
// scoped store query cannot match a foreign row), and the response
// is a stable 200 yalla.output.v1 envelope carrying both the
// canonical service AND the rendered identity projection.
func TestGetServiceRenderedPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	org, _, _, svc := canonicalRenderedSvcForMatrix()
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
			// TestGetServiceRenderedPolicyWrongOrganizationPrincipal — it
			// cannot be exercised at the wire through this route because
			// serviceIDResolver pins the resource scope to the
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
			rec := getServiceRendered(handler, svc.ID, "a-valid-token")

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
			assertRenderedAllowPath(t, rec, svc)
		})
	}
}

// TestGetServiceRenderedPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action service.read with a stable
// 403 E_FORBIDDEN, even when the underlying role would have allowed
// it. A revoked or expired credential must never be able to read a
// service of the organization it once had access to, the reader must
// never run (so the rendered projection is never even computed), and
// the denied body must never echo the principal id, the organization
// id, the path-supplied service id, or any seeded service data.
//
// Underlying role is Owner so a working credential WOULD allow
// service.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0198 ("revoked key,
// expired key").
func TestGetServiceRenderedPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	org, project, env, svc := canonicalRenderedSvcForMatrix()

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
			rec := getServiceRendered(handler, svc.ID, "yk_no_longer_valid")

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
				renderedSvcDenyBodyLeak(svc.ID, project, env, body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded service data", body)
			}
		})
	}
}

// TestGetServiceRenderedPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for service.read on the rendered route.
// Unlike GET /v1/organizations/{org_id}, which takes the org id from
// the PATH (and so fires the engine's cross-tenant clause for a
// foreign {org_id}), this route takes the resource org id from the
// PRINCIPAL'S home org — the {service_id} path parameter alone never
// widens the resource to another tenant. Tenant isolation on the
// wire is therefore structural at the persistence layer, not the
// policy boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/services/{svc_victim}/rendered with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     svc_victim}) — allowed by the role at CapRead — and then
//     reaches the tenant-scoped GetByID query with the principal's
//     home org id and the foreign service id. A production
//     *store.ServiceReader (which combines organization_id and
//     service_id in its WHERE clause) cannot match a row that belongs
//     to another tenant, so the request surfaces as a deterministic
//     404 E_NOT_FOUND, never disguised as a 200 with foreign data and
//     never as a 403 that would confirm existence. The body must
//     never echo the foreign org id even though no wire input could
//     place it there, because the persistence layer must not leak
//     foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). The
//     customer-facing route under test cannot reach this engine
//     branch by construction — serviceIDResolver pins the resource
//     scope to the principal's own home org — but the engine verdict
//     is the authoritative source of the documented support
//     exception, and a future catalog change that upgraded
//     service.read above CapRead would fail here (silently denying
//     every support cross-tenant rendered read) before it could
//     regress a real customer.
func TestGetServiceRenderedPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		victimOrgNeedle = "org_victim"
	)
	foreignSvcID := domain.MustNewID(domain.KindService).String()

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
	rec := getServiceRendered(handler, foreignSvcID, "a-valid-token")

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
	// against the support cross-tenant path so a future catalog
	// change that upgraded service.read above CapRead would fail here
	// (silently denying every support cross-tenant rendered read)
	// before it could regress a real customer. The customer-facing
	// route under test cannot reach this engine branch by
	// construction — serviceIDResolver pins the resource scope to the
	// principal's own home org, so a foreign {service_id} is admitted
	// same-tenant and rejected at the persistence layer — but the
	// engine verdict is the authoritative source of the documented
	// support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionServiceRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(service.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestGetServiceRenderedPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO ProjectID
// leg on the resource scope and the engine's covers() rule is one-way
// (a grant scope that pins ProjectID cannot cover a resource scope
// that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant
// shielding parent-level resources and unrelated services — are
// pinned against the engine at their natural scopes (a project
// resource, an env resource, a service resource), then tied back to
// the wire by proving that ALL three scoped key types are denied
// OutOfScope against THIS endpoint (even when the grant names the
// target service's own project, the target service's own
// environment, or the target service's own id), while an
// organization-level Viewer grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed end-to-end.
//
//   - A project-level Viewer grant naming THIS service's parent
//     project CANNOT authorize the rendered read through this route
//     — the grant scope pins ProjectID and the resource scope does
//     not, so covers() returns false. (The same key DOES authorize
//     service.read at a service resource in that project — the
//     parent-scoped route's job — and that property is pinned at the
//     engine here so the load-bearing distinction between the two
//     routes' authorization surfaces is explicit.)
//   - A project-level Viewer grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a service resource in the sibling
//     project.
//   - An environment-level Admin grant on a staging environment
//     CANNOT authorize the rendered read either: the grant scope
//     pins ProjectID and the resource scope does not. (The grant
//     DOES authorize service.update at a service inside the staging
//     env — pinned at the engine — but a staging-scoped grant does
//     not reach production unless production is explicitly granted,
//     also pinned at the engine.)
//   - A service-level Admin grant naming THIS service's id CANNOT
//     authorize the rendered read through this route either, because
//     the grant scope pins ProjectID and the resource scope does
//     not. At the engine a service grant does not reach an unrelated
//     sibling service nor expose env.write on the parent environment
//     — the "service grant does not expose parent-level secrets or
//     unrelated services" criterion.
//   - An organization-level Viewer grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because service.read is CapRead and
//     Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the reader is never reached (so a production
// store could not have surfaced the canonical service in the
// background and the rendered projection is never computed), and the
// body never echoes the canonical service's identifiers or its
// parent project / environment ids.
func TestGetServiceRenderedPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	org, project, env, svc := canonicalRenderedSvcForMatrix()
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
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_rendered_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
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
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_rendered_sibling", EnvironmentID: "env_sibling_rendered", ServiceID: "svc_sibling_rendered"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at a sibling project's service for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at a sibling project for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env / service resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging_rendered"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod_rendered"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging_rendered", ServiceID: "svc_in_staging_rendered"},
	}); !got.Allow {
		t.Errorf("service.update on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod_rendered", ServiceID: "svc_in_prod_rendered"},
	}); got.Allow {
		t.Errorf("service.update on a service inside production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a grant on the SAME parent env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service. The "service
	// grant does not expose parent-level secrets or unrelated
	// services" property is pinned at the engine against service /
	// env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_a_rendered"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_b_rendered"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	svcGrantee := policy.Principal{
		ID: "sa_svc_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b_rendered",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	scopeTargetSvc := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID}
	svcTargetGrantee := policy.Principal{
		ID: "sa_svc_target_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetSvc}},
	}
	if got := e.Decide(svcTargetGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a grant on the SAME service id = %+v, want deny via %q — covers() is one-way, the service_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.read) at the service-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// target service via THIS route is a 403 with the stable
	// out-of-scope reason, the reader is never reached (so a
	// production store could never have surfaced the canonical
	// service in the background and the rendered projection is never
	// computed), and the body never echoes the canonical service's
	// identifiers or the parent project / environment ids. This is
	// the property that confines a project-scoped key to the parent-
	// scoped route only.
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
	projRec := getServiceRendered(projHandler, svc.ID, "yk_proj_viewer_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the rendered service-id route; body %s",
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
	if body := projRec.Body.String(); renderedSvcDenyBodyLeak(svc.ID, project, env, body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME environment
	// id the target service belongs to — hitting the rendered route
	// is a 403, the reader is never reached, and the body never
	// echoes the canonical service. This is the load-bearing property
	// that locks down the service-id route: an environment grant
	// alone does not authorize rendered reads through it.
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
	envRec := getServiceRendered(envHandler, svc.ID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the rendered service-id route; body %s",
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
	if body := envRec.Body.String(); renderedSvcDenyBodyLeak(svc.ID, project, env, body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee — on the SAME service
	// id the path names — hitting the rendered route is a 403, the
	// reader is never reached, and the body never echoes the
	// canonical service. This is the load-bearing property that
	// confines a service grant to a parent-scoped route: even a key
	// that names THIS exact service cannot authorize a top-level
	// rendered read through this endpoint.
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
	svcRec := getServiceRendered(svcHandler, svc.ID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the rendered service-id route; body %s",
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
	if body := svcRec.Body.String(); renderedSvcDenyBodyLeak(svc.ID, project, env, body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment data: %s", body)
	}

	// An organization-level Viewer grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because service.read is CapRead and
	// Viewer holds CapRead — is allowed via ReasonAllowedByGrant. The
	// same key is end-to-end allowed at the wire, with the reader
	// reached on the principal's home org id and the path service id,
	// and the rendered projection computed deterministically. This
	// locks the CapRead requirement against the grant path so a
	// future catalog change that upgraded service.read above CapRead
	// would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer_rendered", Kind: domain.KindServiceAccount, OrganizationID: org,
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
	allowedRec := getServiceRendered(orgHandler, svc.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	assertRenderedAllowPath(t, allowedRec, svc)
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
	// TestGetServiceRenderedPolicyWrongOrganizationPrincipal, applied
	// to a scoped key: stealing a key cannot smuggle it across
	// tenants. (service.read IS inside the support cross-tenant
	// exception, but the principal here is a service account with no
	// CapSupport role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling_rendered", ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view_rendered", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling_rendered",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionServiceRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(service.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
