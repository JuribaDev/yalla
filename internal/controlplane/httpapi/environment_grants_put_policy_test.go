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

// Policy-matrix coverage for PUT /v1/environments/{environment_id}/grants
// (BE-0171). Where environment_grants_put_test.go proves the endpoint's
// wire contract (BE-0169), this file proves its authorization contract:
// that action environment.grants.write cannot be bypassed by — or replace
// an environment's grants because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the environmentIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and the
// {environment_id} PATH parameter — and CRUCIALLY pins NO ProjectID leg,
// because the bare top-level path carries no parent project_id. That is
// the load-bearing distinction from the projectIDResolver siblings
// (BE-0141 projects_grants_put_policy_test.go is the structural twin for
// the project-scoped grants replace): every scoped grant in the engine
// pins a ProjectID, and the engine's covers() rule is one-way (a grant
// scope that pins ProjectID cannot cover a resource scope that does not).
// The consequence is that ALL project-, environment-, and service-scoped
// grants are denied at the boundary by ReasonDeniedOutOfScope — even an
// environment-scoped Admin grant naming THIS environment's id, because
// the grant scope's ProjectID cannot cover a resource scope without one.
// Principals whose only access is a scoped grant must use a parent-scoped
// route to replace environment grants; this route is reserved for
// org-wide write roles (owner, admin) and org-wide admin grants.
//
// environment.grants.write requires CapAdmin (catalog.go:
// ActionEnvironmentGrantsWrite -> CapAdmin), the same capability class as
// project.grants.write, org.update, member.create, member.update,
// member.delete, and apikey.create — one tier above project.delete /
// project.update / env.write (which are CapWrite). This is the
// load-bearing distinction from the GET-grants policy matrix
// (environment_grants_policy_test.go BE-0168): GET requires CapRead and
// every built-in role allows; here only Owner and Admin allow. The role
// matrix for a principal acting on its own organization therefore splits
// at the admin tier: Owner / Admin hold CapAdmin and are allowed
// (ReasonAllowedByRole); Developer / Viewer / CI / Support do not hold
// CapAdmin and are denied (ReasonDeniedNoCapability). CI holds CapDeploy
// (deploy capability is for service lifecycle and rollouts, not authority
// management), so a CI key cannot replace an environment's grants even
// within its home tenant. Crucially, the engine's cross-tenant support
// exception is gated on `required == CapRead || required == CapSupport`,
// so CapAdmin is OUTSIDE that exception. Privileged Yalla support that
// needs to alter a customer's environment grants must go through explicit
// break-glass admin tooling, not this customer-facing route. Pinning the
// support-cross-tenant DENY at the engine here means a future {org_id}-
// or {project_id}-scoped variant inherits a working cross-tenant deny for
// environment.grants.write across every role.
//
// environment_grants rows store no credential material — only structural
// identifiers and a role enum — so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.write). Tenant-leakage and
// no-write invariants still apply: a denied response never echoes any
// seeded grant id / principal id / role, the foreign tenant's id, or the
// canonical environment's id; and the replacer MUST never run on any
// deny path — a scoped key denied on the wire cannot have replaced a row,
// deleted a row, or appended an audit record in the background. Distinct
// from a read endpoint, the deny-path leak guards must ALSO prove the
// CALLER-SUPPLIED REQUEST BODY (the replacement set the attacker
// submitted) is never echoed back — the policy boundary must not turn
// into an oracle that confirms which principals exist in the foreign
// tenant by reflecting the request shape.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, environmentIDResolver, or the engine fails here.
// replaceEnvironmentGrantsHandlerFor, putEnvironmentGrants,
// decodeReplaceEnvironmentGrants, environmentGrantsAdminIdentity,
// fakeEnvironmentGrantReplacer, canonicalEnvGrantsEnvironmentID,
// canonicalEnvGrantsProjectID, canonicalEnvironmentGrants,
// envGrantsDenyBodyLeak, orgPrincipal, and decodeError are shared with
// the environment-grants put-contract suite (environment_grants_put_test.go),
// the environment-grants list-policy suite
// (environment_grants_policy_test.go), and the wider httpapi test
// fixtures; this file adds no scaffolding beyond the small fixture
// builders below.

// replaceEnvironmentGrantsMatrixBody is the request body every test in
// this file submits on the wire. Its principal_id, role, and service_id
// are deliberately distinctive — distinct from the
// canonicalEnvironmentGrants the replacer would return on an allow
// path — so the deny-path leak guards
// (replaceEnvironmentGrantsRequestBodyLeak + envGrantsDenyBodyLeak)
// cover BOTH directions: the body the caller submitted and the data the
// replacer (a production-shaped fake) would have returned. A denied
// response leaking either is a separate regression direction, kept in
// one guard pair so a future renderer that gained a "render the request
// body back on error" mode (or a "render the would-have-returned data
// on a 403" mode) fails here.
//
// The wire shape carries no environment_id per grant — the environment
// is named by the path parameter, the strict JSON decoder rejects any
// unknown field on a grant, and the body schema names only the four
// legal grant fields (principal_id, principal_kind, role, service_id).
// Compare to the projects_grants_put_policy_test.go body, which DOES
// include environment_id (and service_id) per grant because that
// endpoint replaces grants across multiple environments of one project.
const replaceEnvironmentGrantsMatrixBody = `{"grants":[` +
	`{"principal_id":"usr_egrnt_request_matrix","principal_kind":"usr","role":"developer"},` +
	`{"principal_id":"sa_egrnt_request_matrix","principal_kind":"sa","role":"ci","service_id":"svc_egrnt_request_matrix"}` +
	`]}`

// replaceEnvironmentGrantsRequestBodyLeak reports whether body contains
// any caller-recognisable identifier from the request body the matrix
// submits. A denied response that echoes any of these is leaking
// information about the request the caller made — a policy-boundary
// response should not confirm that the attacker tried to grant role
// "developer" to "usr_egrnt_request_matrix", for example. Combined with
// envGrantsDenyBodyLeak (which catches an echo of the data the replacer
// would have returned on an allow path), this pair pins both directions
// of "what a denied response must not say".
func replaceEnvironmentGrantsRequestBodyLeak(body string) bool {
	needles := []string{
		"usr_egrnt_request_matrix",
		"sa_egrnt_request_matrix",
		"svc_egrnt_request_matrix",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestReplaceEnvironmentGrantsPolicyMatrixRoles drives every built-in
// role through the production request path. CapAdmin splits the matrix
// one tier above the env.write matrix: Owner / Admin (own org) are
// allowed; Developer / Viewer / CI / Support (own org) are denied. The
// load-bearing distinction from the GET-grants matrix
// (environment_grants_policy_test.go) is that every non-admin role
// DENIES here — Developer holds CapWrite, Viewer / Support hold CapRead,
// and CI holds CapDeploy, but none of them hold CapAdmin, so none of
// them can rewrite who is granted authority on the environment. The
// assertions that matter for allow rows are that the verdict is reached
// through the role (ReasonAllowedByRole), the replacer is reached with
// the principal's own home organization id, the {environment_id} path
// parameter, the caller-supplied replacement set, AND the principal id
// (so the audit record names the actor verbatim), and the response is a
// stable 200 yalla.output.v1 carrying the canonical post-replace grants.
// For deny rows, the assertions are 403 yalla.error.v1, the stable
// reason on the wire, the replacer MUST NEVER run (no row's grants
// altered in the background, no audit record filed), and the denied
// body must not echo any caller-supplied request field OR any canonical
// grants/environment identifier.
func TestReplaceEnvironmentGrantsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvGrantsEnvironmentID
	postWriteGrants := canonicalEnvironmentGrants(org, envID)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
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
		{"developer", policy.RoleDeveloper, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. The
			// allow rows resolve via ReasonAllowedByRole on the
			// SAME-tenant environment resource; the deny rows resolve
			// via ReasonDeniedNoCapability because Developer holds
			// CapWrite but not CapAdmin, Viewer / Support hold CapRead
			// but not CapAdmin, and CI holds CapDeploy but not CapAdmin.
			// (The cross-tenant Support deny is pinned separately in
			// TestReplaceEnvironmentGrantsPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentGrantsWrite, envResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.grants.write) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.grants.write) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.ReplaceEnvironmentGrantsInput
			replacer := fakeEnvironmentGrantReplacer{
				grants: postWriteGrants,
				got:    &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := replaceEnvironmentGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, replacer)
			rec := putEnvironmentGrants(handler, envID, "a-valid-token", replaceEnvironmentGrantsMatrixBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("replacer received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.EnvironmentID != envID {
					t.Errorf("replacer received environment id %q, want the path parameter %q",
						captured.EnvironmentID, envID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("replacer received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.ActorOrgID != org {
					t.Errorf("replacer received actor org id %q, want the principal's home org %q",
						captured.ActorOrgID, org)
				}
				if len(captured.Grants) != 2 {
					t.Fatalf("replacer received %d grants, want 2: %+v", len(captured.Grants), captured.Grants)
				}
				if captured.Grants[0].PrincipalID != "usr_egrnt_request_matrix" || captured.Grants[0].Role != "developer" {
					t.Errorf("replacer.Grants[0] = %+v, want usr_egrnt_request_matrix/developer", captured.Grants[0])
				}
				if captured.Grants[1].ServiceID == nil || *captured.Grants[1].ServiceID != "svc_egrnt_request_matrix" {
					t.Errorf("replacer.Grants[1].service_id = %v, want svc_egrnt_request_matrix",
						captured.Grants[1].ServiceID)
				}
				env := decodeReplaceEnvironmentGrants(t, rec)
				if len(env.Data.Grants) != len(postWriteGrants) {
					t.Fatalf("grants len = %d, want %d; body %s",
						len(env.Data.Grants), len(postWriteGrants), rec.Body.String())
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(tc.reason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, tc.reason)
			}
			if captured.OrganizationID != "" || captured.EnvironmentID != "" || len(captured.Grants) != 0 {
				t.Errorf("replacer was reached with org=%q environment=%q grants=%+v for a denied principal; it must never run",
					captured.OrganizationID, captured.EnvironmentID, captured.Grants)
			}
			body := rec.Body.String()
			if envGrantsDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical environment or post-write grants: %s", body)
			}
			if replaceEnvironmentGrantsRequestBodyLeak(body) {
				t.Errorf("denied response leaked the caller-supplied replacement set: %s", body)
			}
		})
	}
}

// TestReplaceEnvironmentGrantsPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both of
// which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action environment.grants.write with a stable
// 403 E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to replace the
// grants of an environment of the organization it once had access to,
// the replacer must never run, and the denied body must never echo the
// principal id, the organization id, the path-supplied environment id,
// the caller-supplied replacement set, or any seeded grant data.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.grants.write; Disabled is the only thing in the way and
// must be load-bearing. The case names mirror PRD BE-0171 ("revoked
// key, expired key").
func TestReplaceEnvironmentGrantsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvGrantsEnvironmentID
	postWriteGrants := canonicalEnvironmentGrants(org, envID)

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

			var captured store.ReplaceEnvironmentGrantsInput
			replacer := fakeEnvironmentGrantReplacer{
				grants: postWriteGrants,
				got:    &captured,
			}
			handler := replaceEnvironmentGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)
			rec := putEnvironmentGrants(handler, envID, "yk_no_longer_valid", replaceEnvironmentGrantsMatrixBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.EnvironmentID != "" || len(captured.Grants) != 0 {
				t.Errorf("replacer was reached with org=%q environment=%q grants=%+v for a disabled principal; it must never run",
					captured.OrganizationID, captured.EnvironmentID, captured.Grants)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				envGrantsDenyBodyLeak(body) ||
				replaceEnvironmentGrantsRequestBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, seeded grant data, or the caller-supplied replacement set",
					body)
			}
		})
	}
}

// TestReplaceEnvironmentGrantsPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.grants.write. As with
// environment.delete and project.grants.write, the resource org id is
// taken from the PRINCIPAL'S home org — the {environment_id} path
// parameter alone never widens the resource to another tenant, and the
// wire shape carries no organization_id field at all (the strict JSON
// decoder rejects an unknown field, and the body schema names only
// "grants"). Tenant isolation on the wire is therefore structural at
// the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PUT
//     /v1/environments/{env_victim}/grants with a valid Owner token and
//     a fully-formed replacement set reaches the engine with a
//     same-tenant resource ({org_attacker, env_victim}) — allowed by
//     the role at CapAdmin — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the foreign
//     environment id. The store-backed replacer Gets the environment
//     under (organization_id, environment_id) before replacing its
//     grants, so a cross-tenant environment_id is rejected as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 200 with
//     foreign data — which would invite an attacker to believe the
//     replacement landed — and never as a 403 that would confirm
//     existence. The body must never echo the foreign org id even
//     though no wire input could place it there, because the
//     persistence layer must not leak foreign-tenant identity into the
//     error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY role MUST be denied via
//     ReasonDeniedCrossTenant — INCLUDING Support, which is OUTSIDE
//     the engine's cross-tenant exception for CapAdmin actions
//     (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the environment.grants.read
//     cross-tenant property (environment_grants_policy_test.go): read
//     admits Support cross-tenant via ReasonAllowedBySupport, but write
//     DOES NOT. Pinning that engine verdict here means the eventual
//     scoped variant inherits a working cross-tenant deny for
//     environment.grants.write across every role, and a future catalog
//     change that downgraded environment.grants.write into the support
//     cross-tenant exception (or widened the exception) would fail here
//     before it could regress a real customer.
func TestReplaceEnvironmentGrantsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_egrnt"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PUT
	// /v1/environments/{env_victim}/grants with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, environmentID) pair does
	// not match a row (the replacer's environment existence check
	// fires first), so a principal whose home org is org_attacker
	// replacing grants of an environment that belongs to org_victim
	// hits the fake with (org_attacker, env_victim_egrnt) and gets
	// NotFound. The assertions that matter are structural: the
	// replacer is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentGrantReplacer could not have replaced
	// the victim's grants regardless of database state. The denied
	// body must never echo the victim's org id, the caller-supplied
	// replacement set, or any seeded grant data.
	var captured store.ReplaceEnvironmentGrantsInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	replacer := fakeEnvironmentGrantReplacer{
		err: apierr.NotFound("environment", foreignEnvID),
		got: &captured,
	}
	handler := replaceEnvironmentGrantsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, replacer)
	rec := putEnvironmentGrants(handler, foreignEnvID, "a-valid-token", replaceEnvironmentGrantsMatrixBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("replacer received org id %q, want the attacker's home org %q — the replacer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.EnvironmentID != foreignEnvID {
		t.Errorf("replacer received environment id %q, want the path parameter %q",
			captured.EnvironmentID, foreignEnvID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			denyEnv.Error.Message)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}
	if replaceEnvironmentGrantsRequestBodyLeak(body) {
		t.Errorf("response body %s echoed the caller-supplied replacement set — a denied write must not turn into a request-reflecting oracle",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// a future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny.
	// environment.grants.write is CapAdmin, which is OUTSIDE the
	// engine clause `CapSupport && (CapRead || CapSupport)` — so
	// EVERY role, including Support, is denied cross-tenant. This is
	// the load-bearing distinction from
	// environment_grants_policy_test.go (BE-0168), where Support IS
	// admitted cross-tenant via ReasonAllowedBySupport because
	// environment.grants.read is CapRead.
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
		{policy.RoleSupport, "support"},
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionEnvironmentGrantsWrite, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(environment.grants.write, foreign org) for %s = %+v, want deny via %q — CapAdmin is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestReplaceEnvironmentGrantsPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule is
// one-way (a grant scope that pins ProjectID cannot cover a resource
// scope that does not).
//
// Crucially for PUT /v1/environments/{environment_id}/grants:
// environment.grants.write is evaluated against an ENVIRONMENT-level
// resource WITHOUT a ProjectID leg (the environmentIDResolver scope is
// {home_org, path_environment_id}) AND requires CapAdmin — one
// capability tier above env.write. This is doubly load-bearing relative
// to the environment-grants list matrix (environment_grants_policy_test.go):
//
//   - All scoped-grant principals are denied at this endpoint, even
//     when the grant names the target environment's own id. The
//     load-bearing property is identical to BE-0168, but at one
//     capability tier higher.
//   - A project-level Admin grant naming THIS environment's parent
//     project CANNOT authorize the replace through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     project.grants.write at a project resource — that is the
//     project-grants route's job — and that property is pinned at the
//     engine here so the load-bearing distinction between the
//     project-grants route and the environment-grants route is
//     explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — covers() is one-way at the wire, and the engine pins
//     the sibling-project deny against a project resource for
//     project.grants.write.
//   - An environment-level Admin grant naming THIS environment's id
//     CANNOT authorize the replace either, because the grant scope
//     pins ProjectID and the resource scope does not. (The grant DOES
//     authorize env.write at the env resource — pinned at the engine —
//     but not environment.grants.write on this route.) An env grant on
//     staging also does not imply env.write on production at the
//     engine.
//   - A service-level Admin grant CANNOT either, and at the engine a
//     service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level Admin grant DOES cover any resource scope
//     in the same org (its grant scope pins nothing past
//     OrganizationID) and — because environment.grants.write is
//     CapAdmin and Admin holds CapAdmin — is allowed via
//     ReasonAllowedByGrant.
//   - An organization-level DEVELOPER grant covers the resource but
//     confers only CapWrite, never CapAdmin; environment.grants.write
//     is denied via ReasonDeniedNoCapability even with org-wide scope.
//     This locks the CapAdmin requirement against the grant path so a
//     future catalog change that downgraded environment.grants.write
//     to CapWrite would still pass the org-admin allow check but fail
//     this org-developer deny check — so the pair of assertions is
//     load-bearing as a unit.
//
// The acceptance criteria's four containment properties — sibling
// project, env grant not implying production, service grant shielding
// parent-level resources, deeper-scope not reaching shallower
// resource — are pinned against the engine at their natural scopes,
// then tied back to the wire by proving that ALL three scoped key
// types are denied OutOfScope against THIS endpoint (even when the
// grant names the target environment's own project or even the target
// environment's own id), while an organization-level Admin grant —
// which pins no ProjectID and covers any resource scope in the same
// org — is allowed end-to-end.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the replacer is never reached (so a production
// store could not have replaced grants in the background), and the
// body never echoes the canonical environment's or grants'
// identifiers, the canonical request body, or the parent project's id.
func TestReplaceEnvironmentGrantsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvGrantsEnvironmentID
	parentProject := canonicalEnvGrantsProjectID
	postWriteGrants := canonicalEnvironmentGrants(org, envID)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO
	// ProjectID. Every covers() check below against this resource is
	// the engine-level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
	}

	// Project-level grant: admin on the parent project. Admin confers
	// CapAdmin at the project scope, which would be enough for
	// project.grants.write on a project resource — and the engine
	// confirms that at a project resource, so the load-bearing
	// distinction between the project-grants route and this route is
	// explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: parentProject}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_egrnt_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.grants.write) at the parent project for the target-project admin grantee = %+v, want allow via %q — the project-grants route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.write) at a sibling project for the target-project admin grantee = %+v, want deny via %q — a project-scoped admin grant must not reach a sibling project",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from the project-grants route.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_egrnt_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_egrnt_prod"}
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
	// env-staging grant is denied OutOfScope at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (the target environment itself) is ALSO
	// denied OutOfScope on this route, because the grant scope still
	// pins ProjectID and the resource scope does not — the env_id
	// alone is not enough to authorize a top-level replace through
	// this route. A future relaxation of covers() (e.g. allowing a
	// grant on env_X to cover a resource scope with just EnvID=env_X
	// and no ProjectID) would land here.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: envID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_egrnt_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_egrnt_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_egrnt_prod"}
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
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// target environment via THIS route is a 403 with the stable
	// out-of-scope reason, the replacer is never reached (so a
	// production store could never have replaced grants in the
	// background), and the body never echoes the canonical
	// environment's identifiers, the canonical grants' or principals'
	// identifiers, the caller-supplied replacement set, or the parent
	// project's id. This is the property that confines a
	// project-scoped key to the project-grants route only.
	var projCaptured store.ReplaceEnvironmentGrantsInput
	projReplacer := fakeEnvironmentGrantReplacer{
		grants: postWriteGrants, // would be returned if replacer ran — leak guard catches it
		got:    &projCaptured,
	}
	projHandler := replaceEnvironmentGrantsHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projReplacer)
	projRec := putEnvironmentGrants(projHandler, envID, "yk_proj_admin_scoped", replaceEnvironmentGrantsMatrixBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-grants route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCaptured.OrganizationID != "" || projCaptured.EnvironmentID != "" || len(projCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q grants=%+v for a project-scoped grantee; it must never run",
			projCaptured.OrganizationID, projCaptured.EnvironmentID, projCaptured.Grants)
	}
	if body := projRec.Body.String(); envGrantsDenyBodyLeak(body) || replaceEnvironmentGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME environment
	// id the path names — hitting the env-grants route is a 403, the
	// replacer is never reached, and the body never echoes the
	// canonical environment, its grants, or the caller-supplied
	// replacement set. This is the load-bearing property that locks
	// down this route: an environment grant alone does not authorize
	// grants replace through it.
	var envCaptured store.ReplaceEnvironmentGrantsInput
	envReplacer := fakeEnvironmentGrantReplacer{
		grants: postWriteGrants,
		got:    &envCaptured,
	}
	envHandler := replaceEnvironmentGrantsHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReplacer)
	envRec := putEnvironmentGrants(envHandler, envID, "yk_env_scoped", replaceEnvironmentGrantsMatrixBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-grants route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCaptured.OrganizationID != "" || envCaptured.EnvironmentID != "" || len(envCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q grants=%+v for an env-scoped grantee; it must never run",
			envCaptured.OrganizationID, envCaptured.EnvironmentID, envCaptured.Grants)
	}
	if body := envRec.Body.String(); envGrantsDenyBodyLeak(body) || replaceEnvironmentGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the env-grants
	// route is a 403, the replacer is never reached, and the body never
	// echoes parent-level identifiers nor the caller-supplied replacement
	// set. This is the "service grant does not expose parent-level
	// secrets or unrelated services" criterion tied to the wire on this
	// route.
	var svcCaptured store.ReplaceEnvironmentGrantsInput
	svcReplacer := fakeEnvironmentGrantReplacer{
		grants: postWriteGrants,
		got:    &svcCaptured,
	}
	svcHandler := replaceEnvironmentGrantsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReplacer)
	svcRec := putEnvironmentGrants(svcHandler, envID, "yk_svc_scoped", replaceEnvironmentGrantsMatrixBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-grants route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.EnvironmentID != "" || len(svcCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q grants=%+v for a service-scoped grantee; it must never run",
			svcCaptured.OrganizationID, svcCaptured.EnvironmentID, svcCaptured.Grants)
	}
	if body := svcRec.Body.String(); envGrantsDenyBodyLeak(body) || replaceEnvironmentGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// An organization-level Admin grant DOES cover any environment
	// resource in the same org (its grant scope pins nothing past
	// OrganizationID) and — because environment.grants.write is
	// CapAdmin and Admin holds CapAdmin — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at the
	// wire, with the replacer reached on the principal's home org id
	// and the path environment id.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.ReplaceEnvironmentGrantsInput
	orgReplacer := fakeEnvironmentGrantReplacer{
		grants: postWriteGrants,
		got:    &orgCaptured,
	}
	orgHandler := replaceEnvironmentGrantsHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putEnvironmentGrants(orgHandler, envID, "yk_org_admin", replaceEnvironmentGrantsMatrixBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeReplaceEnvironmentGrants(t, allowedRec)
	if len(allowedPayload.Data.Grants) != len(postWriteGrants) {
		t.Errorf("grants len = %d, want %d", len(allowedPayload.Data.Grants), len(postWriteGrants))
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.EnvironmentID != envID {
		t.Errorf("replacer received environment id %q, want the path parameter %q",
			orgCaptured.EnvironmentID, envID)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID {
		t.Errorf("replacer received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgAdminGrantee.ID)
	}
	if orgCaptured.ActorOrgID != org {
		t.Errorf("replacer received actor org id %q, want the principal's home org %q",
			orgCaptured.ActorOrgID, org)
	}

	// An organization-level DEVELOPER grant covers the resource but
	// confers no admin capability; environment.grants.write must be
	// denied via ReasonDeniedNoCapability even with org-wide scope.
	// Pairing this deny with the org-admin allow above locks the
	// CapAdmin requirement against the grant path: a future catalog
	// change that downgraded environment.grants.write to CapWrite
	// would still pass the org-admin allow check but fail this
	// org-developer deny check — so the pair of assertions is
	// load-bearing as a unit.
	orgDeveloperGrantee := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloperGrantee, policy.ActionEnvironmentGrantsWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.grants.write) at the env-id route's resource scope for an organization-level developer grant = %+v, want deny via %q — developer holds no admin capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id is
	// foreign is denied at the engine: a grant for the parent project
	// inside org_acme, carried by a principal whose home org id is
	// org_sibling, cannot be used to replace environment grants in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in
	// TestReplaceEnvironmentGrantsPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. environment.grants.write is OUTSIDE the support
	// cross-tenant exception regardless, but the assertion here is
	// structural: a scoped key's home org must match the grant
	// scope's org or the engine refuses to consider the grant at all.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: "org_sibling", EnvironmentID: envID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentGrantsWrite, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.grants.write) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
