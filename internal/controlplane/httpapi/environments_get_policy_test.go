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

// Policy-matrix coverage for GET /v1/environments/{environment_id}
// (BE-0156). Where environments_test.go proves the endpoint's wire
// contract (BE-0154), this file proves its authorization contract:
// that action environment.read cannot be bypassed by — or leak an
// environment row because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the environmentIDResolver (routes.go), which
// builds the policy resource from the principal's HOME organization
// id and the {environment_id} PATH parameter — and CRUCIALLY pins NO
// ProjectID leg, because the bare top-level path carries no parent
// project_id. That is the load-bearing distinction from the
// projectIDResolver siblings (BE-0126 projects_get_policy_test.go,
// BE-0150 projects_environments_get_policy_test.go): every scoped
// grant in the engine pins a ProjectID, and the engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not). The consequence is that ALL
// project-, environment-, and service-scoped grants are denied at
// the boundary by ReasonDeniedOutOfScope — even a project-scoped
// Viewer grant naming THIS environment's parent project, even an
// environment-scoped Admin grant naming THIS environment's id,
// because neither scope's ProjectID can cover a resource scope
// without one. Principals whose only access is a scoped grant must
// use the parent-scoped GET /v1/projects/{project_id}/environments
// route to address an environment by its (project, environment)
// tuple; this route is reserved for org-wide read roles (owner,
// admin, developer, viewer, ci) and org-wide grants.
//
// environment.read requires CapRead (catalog.go:
// ActionEnvironmentRead -> CapRead), the same capability class as
// project.read, project.grants.read, environment.grants.read,
// service.read, limits.read, usage.read, and env.read. All six
// built-in roles hold CapRead, so the role matrix for a principal
// reading an environment in its own organization is "all allow"; the
// assertions that matter are that the verdict is reached through the
// role (ReasonAllowedByRole), the reader is called with the
// principal's own home organization id AND the {environment_id} path
// parameter (so the tenant-scoped GetByID query cannot match an
// environment in another tenant), and the response carries the
// canonical environment row in a stable yalla.output.v1 envelope.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing environment.read against a foreign-tenant
// resource IS allowed via ReasonAllowedBySupport — the same property
// project.read / environment.read on the project route / limits.read
// / usage.read carry. Every non-support role is denied with
// ReasonDeniedCrossTenant. The customer-facing route under test
// cannot reach that engine branch by construction (environmentIDResolver
// pins the resource scope to the PRINCIPAL'S home org, not the
// path's tenant — the support cross-tenant exception specifically
// does NOT apply through this endpoint, as the resolver doc and
// route description make explicit), but pinning the engine verdict
// here means a future endpoint that resolves the resource into a
// foreign-org scope (a hypothetical admin tool) inherits a working
// cross-tenant deny and the documented support exception, and a
// future catalog change that upgraded environment.read above CapRead
// would fail here (silently denying every support cross-tenant
// environment read) before it could regress a real customer.
//
// Unlike project_variables rows (which carry secret values), the
// environments table carries NO credential material — only structural
// identifiers, a slug, a display name, an optimistic-concurrency
// version, and lifecycle timestamps. The projectEnvironmentOf
// projection has no value-redaction chokepoint to anchor a deny-path
// leak guard on; the load-bearing needle is the existence of the
// environment row itself (and the id / slug / display name a denied
// principal must not learn). Tenant-leakage and no-read invariants
// apply: a denied response never echoes the seeded environment id /
// slug / display name, the foreign tenant's id, or the canonical
// project's id; and the reader MUST never run on any deny path —
// a scoped key denied on the wire cannot have surfaced an environment
// row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, environmentIDResolver, or the engine fails
// here. getEnvironment, decodeGetEnvironmentBody, fakeEnvironmentReader,
// seedEnvironmentWire, orgPrincipal, and decodeError are shared with
// the get-environment contract suite (environments_test.go) and the
// wider httpapi test fixtures; this file adds a small identity-
// injected handler helper (getEnvironmentByIDHandlerForIdentity) so
// per-test principals can be threaded through the production request
// path — the contract-test helper (getEnvironmentHandlerFor) bakes in
// a single canonical principal and is unsuitable for a matrix.

// canonicalGetEnvForMatrix is the row every test in this file reads.
// Its ids / slug / display name are deliberately distinct from
// canonicalEnvForGet (used by environments_test.go) so the matrices
// cannot accidentally share fixture state through a future shared
// fake, and they are deliberately recognisable so deny-path leak
// guards can needle for them; allow-path assertions compare against
// the same canonical values.
func canonicalGetEnvForMatrix(orgID, projectID string) store.Environment {
	created := time.Date(2026, 2, 17, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 11, 12, 13, 0, time.UTC)
	return seedEnvironmentWire("env_matrix_byid", orgID, projectID, "byid-matrix", "ByID Matrix", 11, created, updated)
}

// getEnvDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical environment or its
// parent project. A denied response that accidentally rendered any
// of these fails the test: the environment row's existence (and the
// slug / display name it names, and the parent project's id) is
// itself information a denied principal must not receive. The quoted
// forms catch a case-collapsing renderer regression. The environments
// table carries no credential material at all, so unlike the
// project_variables matrix there is no secret plaintext to anchor.
func getEnvDenyBodyLeak(body string) bool {
	needles := []string{
		"env_matrix_byid",
		"\"byid-matrix\"",
		"\"ByID Matrix\"",
		"prj_byid_matrix_parent",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// getEnvironmentByIDHandlerForIdentity wraps the production NewHandler
// with a fakeAuthenticator parameterised on (id, authErr) and the
// supplied EnvironmentReader. It is the per-test identity-injected
// sibling of the contract suite's getEnvironmentHandlerFor (which
// bakes in a single canonical principal and authenticator and is
// unsuitable for a matrix). Every other port is a no-op fake; the
// test exercises only the GET /v1/environments/{environment_id}
// vertical, and the route table is wired identically to production.
// The trailing nil is the optional logger, matching every other
// handler factory in this package.
func getEnvironmentByIDHandlerForIdentity(id auth.Identity, authErr error, reader EnvironmentReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, reader, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeBreakGlassController{}, nil, nil)
}

// TestGetEnvironmentPolicyMatrixRoles drives every built-in role
// through the production request path. All six built-in roles hold
// CapRead, so the matrix is "all allow" for a principal reading an
// environment in its own organization; the assertions that matter
// are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {environment_id} path parameter (so a
// tenant-scoped store query cannot match a foreign row), and the
// response is a stable 200 yalla.output.v1 envelope carrying the
// canonical environment.
func TestGetEnvironmentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_byid_matrix_parent"
	)
	env := canonicalGetEnvForMatrix(org, project)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: env.ID},
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
			// reading an environment in ITS OWN organization is
			// allowed via ReasonAllowedByRole (same-tenant falls
			// through the cross-tenant clause); the Support cross-
			// tenant exception is exercised at the engine in
			// TestGetEnvironmentPolicyWrongOrganizationPrincipal —
			// it cannot be exercised at the wire through this route
			// because environmentIDResolver pins the resource scope
			// to the principal's home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentRead, envResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(environment.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotEnv string
			callCount := 0
			reader := fakeEnvironmentReader{
				env:       env,
				gotOrgID:  &gotOrg,
				gotEnvID:  &gotEnv,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := getEnvironmentByIDHandlerForIdentity(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getEnvironment(handler, env.ID, "a-valid-token")

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
			if gotEnv != env.ID {
				t.Errorf("reader received environment id %q, want the path parameter %q",
					gotEnv, env.ID)
			}
			projection := decodeGetEnvironmentBody(t, rec)
			if projection.ID != env.ID ||
				projection.Slug != env.Slug ||
				projection.DisplayName != env.DisplayName ||
				projection.OrganizationID != env.OrganizationID ||
				projection.ProjectID != env.ProjectID ||
				projection.Version != env.Version {
				t.Errorf("environment = %+v, want (%s, %s, %s, org=%s, project=%s, v=%d)",
					projection, env.ID, env.Slug, env.DisplayName, env.OrganizationID, env.ProjectID, env.Version)
			}
		})
	}
}

// TestGetEnvironmentPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action environment.read with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to read an
// environment of the organization it once had access to, the reader
// must never run, and the denied body must never echo the principal
// id, the organization id, the path-supplied environment id, or any
// seeded environment data.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.read; Disabled is the only thing in the way and must
// be load-bearing. The case names mirror PRD BE-0156 ("revoked key,
// expired key").
func TestGetEnvironmentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_byid_matrix_parent"
	)
	env := canonicalGetEnvForMatrix(org, project)

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

			var gotOrg, gotEnv string
			callCount := 0
			reader := fakeEnvironmentReader{
				env:       env,
				gotOrgID:  &gotOrg,
				gotEnvID:  &gotEnv,
				callCount: &callCount,
			}
			handler := getEnvironmentByIDHandlerForIdentity(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getEnvironment(handler, env.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotOrg != "" || gotEnv != "" {
				t.Errorf("reader was reached (calls=%d org=%q env=%q) for a disabled principal; it must never run",
					callCount, gotOrg, gotEnv)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				getEnvDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded environment data", body)
			}
		})
	}
}

// TestGetEnvironmentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.read on the env-id route.
// Unlike GET /v1/organizations/{org_id}, which takes the org id from
// the PATH (and so fires the engine's cross-tenant clause for a
// foreign {org_id}), this route takes the resource org id from the
// PRINCIPAL'S home org — the {environment_id} path parameter alone
// never widens the resource to another tenant. Tenant isolation on
// the wire is therefore structural at the persistence layer, not the
// policy boundary:
//
//   - A principal in org_attacker hitting GET /v1/environments/
//     {env_victim} with a valid Owner token reaches the engine with
//     a same-tenant resource ({org_attacker, env_victim}) — allowed
//     by the role at CapRead — and then reaches the tenant-scoped
//     GetByID query with the principal's home org id and the foreign
//     environment id. A production *store.EnvironmentReader (which
//     combines organization_id and environment_id in its WHERE
//     clause) cannot match a row that belongs to another tenant, so
//     the request surfaces as a deterministic 404 E_NOT_FOUND, never
//     disguised as a 200 with foreign data and never as a 403 that
//     would confirm existence. The body must never echo the foreign
//     org id even though no wire input could place it there, because
//     the persistence layer must not leak foreign-tenant identity
//     into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). The
//     customer-facing route under test cannot reach this engine
//     branch by construction — environmentIDResolver pins the
//     resource scope to the principal's own home org — but the
//     engine verdict is the authoritative source of the documented
//     support exception, and a future catalog change that upgraded
//     environment.read above CapRead would fail here (silently
//     denying every support cross-tenant environment read) before
//     it could regress a real customer.
func TestGetEnvironmentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_byid"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET /v1/environments/
	// {env_victim} with a valid Owner token. The fake mirrors the
	// production store contract: it returns NotFound whenever the
	// (organizationID, environmentID) pair does not match a row, so
	// a principal whose home org is org_attacker reading an
	// environment that belongs to org_victim hits the fake with
	// (org_attacker, env_victim_byid) and gets NotFound. The
	// assertions that matter are structural: the reader is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// EnvironmentReader could not have surfaced the victim's
	// environment regardless of database state. The denied body must
	// never echo the victim's org id.
	var gotOrg, gotEnv string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeEnvironmentReader{
		err:       apierr.NotFound("environment", foreignEnvID),
		gotOrgID:  &gotOrg,
		gotEnvID:  &gotEnv,
		callCount: &callCount,
	}
	handler := getEnvironmentByIDHandlerForIdentity(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getEnvironment(handler, foreignEnvID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1 — the reader runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign environment id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			gotOrg, ownOrg)
	}
	if gotEnv != foreignEnvID {
		t.Errorf("reader received environment id %q, want the path parameter %q",
			gotEnv, foreignEnvID)
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
	// scope inherits a working cross-tenant deny. environment.read
	// is CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: victimOrg, EnvironmentID: foreignEnvID},
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
			got := e.Decide(p, policy.ActionEnvironmentRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(environment.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches environment.read because
	// the catalog maps it to CapRead. This locks the CapRead
	// requirement against the support cross-tenant path so a future
	// catalog change that upgraded environment.read above CapRead
	// would fail here (silently denying every support cross-tenant
	// environment read) before it could regress a real customer. The
	// customer-facing route under test cannot reach this engine
	// branch by construction — environmentIDResolver pins the
	// resource scope to the principal's own home org, so a foreign
	// {environment_id} is admitted same-tenant and rejected at the
	// persistence layer — but the engine verdict is the authoritative
	// source of the documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvironmentRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(environment.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestGetEnvironmentPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant
// shielding parent-level resources — are pinned against the engine
// at their natural scopes (a project resource, an env resource, a
// service resource), then tied back to the wire by proving that ALL
// three scoped key types are denied OutOfScope against THIS endpoint
// (even when the grant names the target environment's own project
// or even the target environment's own id), while an organization-
// level Viewer grant — which pins no ProjectID and covers any
// resource scope in the same org — is allowed end-to-end.
//
//   - A project-level Viewer grant naming THIS environment's parent
//     project CANNOT authorize the read through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     environment.read at a project resource — that is the
//     parent-scoped route's job — and that property is pinned at the
//     engine here so the load-bearing distinction between the two
//     routes' authorization surfaces is explicit.)
//   - A project-level Viewer grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a project resource.
//   - An environment-level Admin grant naming THIS environment's id
//     CANNOT authorize the read either, because the grant scope pins
//     ProjectID and the resource scope does not. (The grant DOES
//     authorize env.write at the env resource — pinned at the engine
//     — but not environment.read on this route.) An env grant on
//     staging also does not imply env.write on production at the
//     engine.
//   - A service-level Admin grant CANNOT either, and at the engine a
//     service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level Viewer grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because environment.read is CapRead and
//     Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the reader is never reached (so a production
// store could not have surfaced the canonical environment in the
// background), and the body never echoes the canonical environment's
// identifiers or its parent project's id.
func TestGetEnvironmentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_byid_matrix_parent"
	)
	env := canonicalGetEnvForMatrix(org, project)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO ProjectID.
	// Every covers() check below against this resource is the engine-
	// level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: env.ID},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, which would normally be
	// enough for environment.read on a project resource — and the
	// engine confirms that at a project resource, so the load-bearing
	// distinction between the two routes is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_byid_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.read) at the parent project for the target-project viewer grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at a sibling project for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from the parent-scoped route.
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeStaging}); !got.Allow {
		t.Errorf("env.write on the granted staging environment = %+v, want allow", got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// env-staging grant is denied OutOfScope at the engine — even an
	// env grant on the very environment the path names would be
	// denied for the same reason, which the next fixture pins
	// directly so a future relaxation of covers() (e.g. allowing a
	// grant on env_X to cover a resource scope with just EnvID=env_X
	// and no ProjectID) cannot land without failing this test.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvironmentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (env_matrix_byid itself) is ALSO denied
	// OutOfScope on this route, because the grant scope still pins
	// ProjectID and the resource scope does not — the env_id alone is
	// not enough to authorize a top-level read through this route.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env.ID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvironmentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
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
	// And against THIS route's resource scope (no ProjectID), the
	// service grant is denied OutOfScope at the engine.
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// target environment via THIS route is a 403 with the stable
	// out-of-scope reason, the reader is never reached (so a
	// production store could never have surfaced the canonical
	// environment in the background), and the body never echoes the
	// canonical environment's identifiers or the parent project's
	// id. This is the property that confines a project-scoped key to
	// the parent-scoped route only.
	var projGotOrg, projGotEnv string
	projCallCount := 0
	projReader := fakeEnvironmentReader{
		env:       env, // would be returned if reader ran — leak guard catches it
		gotOrgID:  &projGotOrg,
		gotEnvID:  &projGotEnv,
		callCount: &projCallCount,
	}
	projHandler := getEnvironmentByIDHandlerForIdentity(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projReader)
	projRec := getEnvironment(projHandler, env.ID, "yk_proj_viewer_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-id route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projGotOrg != "" || projGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for a project-scoped grantee; it must never run",
			projCallCount, projGotOrg, projGotEnv)
	}
	if body := projRec.Body.String(); getEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment or parent project data: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME
	// environment id the path names — hitting the env-id route is a
	// 403, the reader is never reached, and the body never echoes
	// the canonical environment. This is the load-bearing property
	// that locks down the env-id route: an environment grant alone
	// does not authorize reads through it.
	var envGotOrg, envGotEnv string
	envCallCount := 0
	envReader := fakeEnvironmentReader{
		env:       env,
		gotOrgID:  &envGotOrg,
		gotEnvID:  &envGotEnv,
		callCount: &envCallCount,
	}
	envHandler := getEnvironmentByIDHandlerForIdentity(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getEnvironment(envHandler, env.ID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-id route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotOrg != "" || envGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for an env-scoped grantee; it must never run",
			envCallCount, envGotOrg, envGotEnv)
	}
	if body := envRec.Body.String(); getEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment or parent project data: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the env-id
	// route is a 403, the reader is never reached, and the body
	// never echoes parent-level identifiers — the "service grant
	// does not expose parent-level secrets or unrelated services"
	// criterion tied to the wire on this route.
	var svcGotOrg, svcGotEnv string
	svcCallCount := 0
	svcReader := fakeEnvironmentReader{
		env:       env,
		gotOrgID:  &svcGotOrg,
		gotEnvID:  &svcGotEnv,
		callCount: &svcCallCount,
	}
	svcHandler := getEnvironmentByIDHandlerForIdentity(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getEnvironment(svcHandler, env.ID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-id route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotOrg != "" || svcGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotOrg, svcGotEnv)
	}
	if body := svcRec.Body.String(); getEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment or parent project data: %s", body)
	}

	// An organization-level Viewer grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because environment.read is CapRead and
	// Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the
	// reader reached on the principal's home org id and the path
	// environment id. This locks the CapRead requirement against the
	// grant path so a future catalog change that upgraded
	// environment.read above CapRead would fail here (silently
	// denying every org-level Viewer grantee) before it could
	// regress a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvironmentRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.read) at the env-id route's resource scope for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotEnv string
	orgCallCount := 0
	orgReader := fakeEnvironmentReader{
		env:       env,
		gotOrgID:  &orgGotOrg,
		gotEnvID:  &orgGotEnv,
		callCount: &orgCallCount,
	}
	orgHandler := getEnvironmentByIDHandlerForIdentity(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getEnvironment(orgHandler, env.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedProjection := decodeGetEnvironmentBody(t, allowedRec)
	if allowedProjection.ID != env.ID || allowedProjection.Slug != env.Slug || allowedProjection.OrganizationID != env.OrganizationID {
		t.Errorf("environment = %+v, want (%s, %s, org=%s)",
			allowedProjection, env.ID, env.Slug, env.OrganizationID)
	}
	if orgCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, org)
	}
	if orgGotEnv != env.ID {
		t.Errorf("reader received environment id %q, want the path parameter %q",
			orgGotEnv, env.ID)
	}

	// And the same project-scoped viewer grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to read an environment in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in TestGetEnvironmentPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (environment.read IS inside the support
	// cross-tenant exception, but the principal here is a service
	// account with no CapSupport role, so the exception does not
	// apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
