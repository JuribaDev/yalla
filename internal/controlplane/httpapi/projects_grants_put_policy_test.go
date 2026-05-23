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

// Policy-matrix coverage for PUT /v1/projects/{project_id}/grants
// (BE-0141). Where project_grants_put_test.go proves the endpoint's wire
// contract (BE-0139), this file proves its authorization contract: that
// action project.grants.write cannot be bypassed by — or replace a
// project's grants because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the projectIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {project_id} PATH parameter. RequireAuth therefore authorizes against
// the project the path names — not merely the principal's home
// organization. That is the load-bearing distinction from the
// create-project matrix (projects_create_policy_test.go), where the
// resource is the organization root and the route uses a nil resolver:
//
//   - The create matrix authorizes against the organization root, so a
//     project-level grant cannot reach it. Here the resource IS
//     project-level, so a project-level Admin grant naming THIS project
//     CAN authorize the replace while a project-level grant naming a
//     SIBLING project cannot.
//   - The handler still derives the organization id on the store input
//     from the PRINCIPAL'S home org (never the caller — the strict JSON
//     decoder rejects an unknown field at the body, and the wire shape
//     has no organization_id at all), so a cross-tenant project_id
//     reaches the tenant-scoped repository query with the principal's
//     home org id and is rejected as a deterministic 404 NotFound at the
//     persistence layer by the replacer's project existence check. A
//     cross-tenant project_id can never replace another organization's
//     grants, and the wire body must never echo the foreign org id even
//     though no wire input could place it there.
//
// project.grants.write requires CapAdmin (catalog.go: ActionProjectGrantsWrite
// -> CapAdmin), one tier above project.create / project.update / project.delete
// (which are CapWrite). This is the load-bearing distinction from the
// project.delete matrix (projects_delete_policy_test.go), which is "Owner
// / Admin / Developer allow"; here Developer ALSO denies because it
// holds CapWrite but not CapAdmin. The role matrix for a principal
// acting on its own organization therefore splits at the admin tier:
// Owner / Admin hold CapAdmin and are allowed (ReasonAllowedByRole);
// Developer / Viewer / CI / Support do not hold CapAdmin and are denied
// (ReasonDeniedNoCapability) — CI holds CapDeploy (the deploy capability
// is for service lifecycle and rollouts, not authority management), so a
// CI key cannot replace a project's grants even within its home tenant.
// Crucially, the engine's cross-tenant support exception is gated on
// `required == CapRead || required == CapSupport`, so CapAdmin is
// OUTSIDE that exception. Privileged Yalla support that needs to alter a
// customer's grants must go through explicit break-glass admin tooling,
// not this customer-facing route. Pinning the support-cross-tenant DENY
// at the engine here means a future {org_id}-scoped variant inherits a
// working cross-tenant deny for project.grants.write across every role.
//
// project_grants rows store no credential material — only structural
// identifiers and a role enum — so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.write). Tenant-leakage and
// no-write invariants still apply: a denied response never echoes any
// seeded grant id / principal id / role, the foreign tenant's id, or
// the canonical project's slug / display name; and the replacer MUST
// never run on any deny path — a scoped key denied on the wire cannot
// have replaced a row, deleted a row, or appended an audit record in
// the background. Distinct from a read endpoint, the deny-path leak
// guards must ALSO prove the CALLER-SUPPLIED REQUEST BODY (the
// replacement set the attacker submitted) is never echoed back — the
// policy boundary must not turn into an oracle that confirms which
// principals exist in the foreign tenant by reflecting the request
// shape.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// replaceProjectGrantsHandlerFor, putProjectGrants,
// decodeReplaceProjectGrants, projectGrantsAdminIdentity,
// fakeProjectGrantReplacer, canonicalGrantsProject,
// canonicalProjectGrants, grantsDenyBodyLeak, orgPrincipal, and
// decodeError are shared with the project-grants put-contract suite
// (project_grants_put_test.go), the project-grants list-policy suite
// (projects_grants_policy_test.go), and the wider httpapi test fixtures;
// this file adds no scaffolding beyond the small fixture builders below.

// replaceGrantsMatrixBody is the request body every test in this file
// submits on the wire. Its principal_id, role, environment_id, and
// service_id are deliberately distinctive — distinct from the
// seededPostWriteGrants the replacer would return on an allow path — so
// the deny-path leak guards (replaceGrantsRequestBodyLeak +
// grantsDenyBodyLeak) cover BOTH directions: the body the caller
// submitted and the data the replacer (a production-shaped fake) would
// have returned. A denied response leaking either is a separate
// regression direction, kept in one guard pair so a future renderer
// that gained a "render the request body back on error" mode (or a
// "render the would-have-returned data on a 403" mode) fails here.
const replaceGrantsMatrixBody = `{"grants":[` +
	`{"principal_id":"usr_request_matrix","principal_kind":"usr","role":"developer"},` +
	`{"principal_id":"sa_request_matrix","principal_kind":"sa","role":"ci","environment_id":"env_request_matrix","service_id":"svc_request_matrix"}` +
	`]}`

// replaceGrantsRequestBodyLeak reports whether body contains any
// caller-recognisable identifier from the request body the matrix
// submits. A denied response that echoes any of these is leaking
// information about the request the caller made — a policy-boundary
// response should not confirm that the attacker tried to grant role
// "developer" to "usr_request_matrix", for example. Combined with
// grantsDenyBodyLeak (which catches an echo of the data the replacer
// would have returned on an allow path), this pair pins both directions
// of "what a denied response must not say".
func replaceGrantsRequestBodyLeak(body string) bool {
	needles := []string{
		"usr_request_matrix",
		"sa_request_matrix",
		"env_request_matrix",
		"svc_request_matrix",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestReplaceProjectGrantsPolicyMatrixRoles drives every built-in role
// through the production request path. CapAdmin splits the matrix one
// tier above the project.delete matrix: Owner / Admin (own org) are
// allowed; Developer / Viewer / CI / Support (own org) are denied. The
// load-bearing distinction from the project.delete matrix
// (projects_delete_policy_test.go) is that Developer DENIES here — it
// holds CapWrite but not CapAdmin, so it can create / update / delete a
// project but cannot alter who is granted authority on it. The
// assertions that matter for allow rows are that the verdict is reached
// through the role (ReasonAllowedByRole), the replacer is reached with
// the principal's own home organization id, the {project_id} path
// parameter, the caller-supplied replacement set, AND the principal id
// (so the audit record names the actor verbatim), and the response is a
// stable 200 yalla.output.v1 carrying the canonical post-replace
// grants. For deny rows, the assertions are 403 yalla.error.v1, the
// stable reason on the wire, the replacer MUST NEVER run (no row's
// grants altered in the background, no audit record filed), and the
// denied body must not echo any caller-supplied request field OR any
// canonical grants/project identifier.
func TestReplaceProjectGrantsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	postWriteGrants := canonicalProjectGrants(org, project.ID)
	projectResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project.ID},
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
			// SAME-tenant project resource; the deny rows resolve via
			// ReasonDeniedNoCapability because Developer holds CapWrite
			// but not CapAdmin, Viewer / Support hold CapRead but not
			// CapAdmin, and CI holds CapDeploy but not CapAdmin. (The
			// cross-tenant Support deny is pinned separately in
			// TestReplaceProjectGrantsPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectGrantsWrite, projectResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.grants.write) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.grants.write) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.ReplaceProjectGrantsInput
			replacer := fakeProjectGrantReplacer{
				grants: postWriteGrants,
				got:    &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := replaceProjectGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, replacer)
			rec := putProjectGrants(handler, project.ID, "a-valid-token", replaceGrantsMatrixBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("replacer received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ProjectID != project.ID {
					t.Errorf("replacer received project id %q, want the path parameter %q",
						captured.ProjectID, project.ID)
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
				if captured.Grants[0].PrincipalID != "usr_request_matrix" || captured.Grants[0].Role != "developer" {
					t.Errorf("replacer.Grants[0] = %+v, want usr_request_matrix/developer", captured.Grants[0])
				}
				if captured.Grants[1].EnvironmentID == nil || *captured.Grants[1].EnvironmentID != "env_request_matrix" {
					t.Errorf("replacer.Grants[1].environment_id = %v, want env_request_matrix",
						captured.Grants[1].EnvironmentID)
				}
				env := decodeReplaceProjectGrants(t, rec)
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
			if captured.OrganizationID != "" || captured.ProjectID != "" || len(captured.Grants) != 0 {
				t.Errorf("replacer was reached with org=%q project=%q grants=%+v for a denied principal; it must never run",
					captured.OrganizationID, captured.ProjectID, captured.Grants)
			}
			body := rec.Body.String()
			if grantsDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical project or post-write grants: %s", body)
			}
			if replaceGrantsRequestBodyLeak(body) {
				t.Errorf("denied response leaked the caller-supplied replacement set: %s", body)
			}
		})
	}
}

// TestReplaceProjectGrantsPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal — is
// denied action project.grants.write with a stable 403 E_FORBIDDEN,
// even when the underlying role would have allowed it. A revoked or
// expired credential must never be able to replace the grants of a
// project of the organization it once had access to, the replacer must
// never run, and the denied body must never echo the principal id, the
// organization id, the path-supplied project id, the caller-supplied
// replacement set, or any seeded grant data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.grants.write; Disabled is the only thing in the way and must
// be load-bearing. The case names mirror PRD BE-0141 ("revoked key,
// expired key").
func TestReplaceProjectGrantsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	postWriteGrants := canonicalProjectGrants(org, project.ID)

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

			var captured store.ReplaceProjectGrantsInput
			replacer := fakeProjectGrantReplacer{
				grants: postWriteGrants,
				got:    &captured,
			}
			handler := replaceProjectGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)
			rec := putProjectGrants(handler, project.ID, "yk_no_longer_valid", replaceGrantsMatrixBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.ProjectID != "" || len(captured.Grants) != 0 {
				t.Errorf("replacer was reached with org=%q project=%q grants=%+v for a disabled principal; it must never run",
					captured.OrganizationID, captured.ProjectID, captured.Grants)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				grantsDenyBodyLeak(body) ||
				replaceGrantsRequestBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, seeded grant data, or the caller-supplied replacement set",
					body)
			}
		})
	}
}

// TestReplaceProjectGrantsPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for project.grants.write. As with
// project.delete, the resource org id is taken from the PRINCIPAL'S
// home org — the {project_id} path parameter alone never widens the
// resource to another tenant, and the wire shape carries no
// organization_id field at all (the strict JSON decoder rejects an
// unknown field, and the body schema names only "grants"). Tenant
// isolation on the wire is therefore structural at the persistence
// layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PUT
//     /v1/projects/{prj_victim}/grants with a valid Owner token and a
//     fully-formed replacement set reaches the engine with a
//     same-tenant resource ({org_attacker, prj_victim}) — allowed by
//     the role at CapAdmin — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the foreign
//     project id. The store-backed replacer Gets the project under
//     (organization_id, project_id) before replacing its grants, so a
//     cross-tenant project_id is rejected as a deterministic 404
//     E_NOT_FOUND, never disguised as a 200 with foreign data — which
//     would invite an attacker to believe the replacement landed — and
//     never as a 403 that would confirm existence. The body must never
//     echo the foreign org id even though no wire input could place it
//     there, because the persistence layer must not leak foreign-tenant
//     identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY role MUST be denied via
//     ReasonDeniedCrossTenant — INCLUDING Support, which is OUTSIDE the
//     engine's cross-tenant exception for CapAdmin actions (`CapSupport
//     && (CapRead || CapSupport)`). This is the load-bearing
//     distinction from the project.grants.read cross-tenant property:
//     read admits Support cross-tenant via ReasonAllowedBySupport, but
//     write DOES NOT. Pinning that engine verdict here means the
//     eventual scoped variant inherits a working cross-tenant deny for
//     project.grants.write across every role, and a future catalog
//     change that downgraded project.grants.write into the support
//     cross-tenant exception (or widened the exception) would fail here
//     before it could regress a real customer.
func TestReplaceProjectGrantsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_alpha"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PUT
	// /v1/projects/{prj_victim}/grants with a valid Owner token. The
	// fake mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, projectID) pair does not match a
	// row (the replacer's project existence check fires first), so a
	// principal whose home org is org_attacker replacing grants of a
	// project that belongs to org_victim hits the fake with
	// (org_attacker, prj_victim_alpha) and gets NotFound. The
	// assertions that matter are structural: the replacer is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectGrantReplacer could not have replaced the victim's grants
	// regardless of database state. The denied body must never echo
	// the victim's org id, the caller-supplied replacement set, or any
	// seeded grant data.
	var captured store.ReplaceProjectGrantsInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	replacer := fakeProjectGrantReplacer{
		err: apierr.NotFound("project", foreignProjID),
		got: &captured,
	}
	handler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, replacer)
	rec := putProjectGrants(handler, foreignProjID, "a-valid-token", replaceGrantsMatrixBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("replacer received org id %q, want the attacker's home org %q — the replacer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ProjectID != foreignProjID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			captured.ProjectID, foreignProjID)
	}
	env := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(env.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			env.Error.Message)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}
	if replaceGrantsRequestBodyLeak(body) {
		t.Errorf("response body %s echoed the caller-supplied replacement set — a denied write must not turn into a request-reflecting oracle",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// a future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. project.grants.write
	// is CapAdmin, which is OUTSIDE the engine clause `CapSupport &&
	// (CapRead || CapSupport)` — so EVERY role, including Support, is
	// denied cross-tenant.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: victimOrg, ProjectID: foreignProjID},
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
			got := e.Decide(p, policy.ActionProjectGrantsWrite, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.grants.write, foreign org) for %s = %+v, want deny via %q — CapAdmin is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestReplaceProjectGrantsPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach the
// parent project, a service grant does not reach the parent
// environment or a sibling service.
//
// Crucially for PUT /v1/projects/{project_id}/grants: project.grants.write
// is evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}) AND requires CapAdmin — one
// capability tier above project.delete. This is doubly load-bearing
// relative to the project.delete grant matrix
// (projects_delete_policy_test.go):
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     the replace (ReasonAllowedByGrant), and at the wire the replacer
//     receives (home_org, target_project_id, principal id,
//     actor_org_id) — the grant scope contains the resource scope and
//     CapAdmin is conferred.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, so the grant scope does not contain the
//     resource scope. The denial is ReasonDeniedOutOfScope (the
//     principal holds the capability somewhere, just not here).
//   - A project-level DEVELOPER grant naming THIS project does not
//     hold CapAdmin and is denied via ReasonDeniedNoCapability — a
//     developer grant confers CapWrite (it can create / update /
//     delete the project) but not CapAdmin (it cannot rewrite who is
//     granted authority on it). This is the load-bearing distinction
//     from the project.delete grant matrix, where the same
//     developer-tier grant WOULD allow project.delete; here it does
//     not. A future "grant role enum re-mapping" regression would
//     catch here.
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope — the "env grant
//     does not imply access to production unless production is
//     explicitly granted" property still applies here: even an env
//     grant on the same project's production environment cannot
//     escalate to replacing the parent project's grants.
//   - A service-level grant likewise does NOT cover a project resource
//     and does not expose the parent environment's secrets through
//     env.write either — the "service grant does not expose
//     parent-level secrets or unrelated services" property.
//   - An organization-level Admin grant DOES cover any project
//     resource within the same org and — because project.grants.write
//     is CapAdmin and Admin holds CapAdmin — is allowed via
//     ReasonAllowedByGrant.
//   - An organization-level DEVELOPER grant covers the resource but
//     confers only CapWrite, never CapAdmin; project.grants.write is
//     denied via ReasonDeniedNoCapability even with org-wide scope.
//     This locks the CapAdmin requirement against the grant path so a
//     future catalog change that downgraded project.grants.write to
//     CapWrite would fail here (silently allowing every developer key
//     to rewrite a project's authority) before it could regress a real
//     customer.
//
// The acceptance criteria's four containment properties — sibling
// project, sibling-env property, deeper-scope reaching shallower
// resource, service-scope shielding parent-level secrets — are pinned
// against the engine, then tied back to the wire by proving the
// replacer is never reached on any deny path (so a production store
// could not have replaced grants in the background) and the denied
// body never echoes the canonical project's identifiers nor the
// caller-supplied replacement set.
func TestReplaceProjectGrantsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	postWriteGrants := canonicalProjectGrants(org, project.ID)
	e := policy.NewEngine()

	// Project-level grant: admin on prj_grants_matrix_alpha only.
	// Admin confers CapAdmin at the project scope, which is exactly
	// what project.grants.write needs. The sibling-project property is
	// pinned for project.grants.write directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_grants_matrix_beta"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.grants.write) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.write) for a sibling project = %+v, want deny via %q — a project-scoped admin grant must not reach prj_grants_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level DEVELOPER grant: confers CapWrite at the project
	// but not CapAdmin. project.grants.write on the same project
	// resource must fail with ReasonDeniedNoCapability — a developer
	// grant does not widen to an admin action even when its scope
	// contains the resource. This is the load-bearing distinction from
	// the project.delete grant matrix, where the same grant WOULD
	// allow project.delete.
	projectDeveloperGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTarget}},
	}
	if got := e.Decide(projectDeveloperGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.grants.write) for a project-scoped developer grant = %+v, want deny via %q — a developer grant confers no admin capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant
	// scope, so covers() does not reach it for project.grants.write.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.write) for an environment-scoped grantee = %+v, want deny via %q — an env grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentDelete, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(environment.delete) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow project.grants.write on the parent
	// project.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.write) for a service-scoped grantee = %+v, want deny via %q — a service grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// TARGET project is a 200 with the canonical post-write grants,
	// the replacer is reached with (home_org, target_project_id,
	// principal id, actor_org_id, the caller-supplied replacement
	// set), and the response carries the post-write grants. A
	// project-scoped Admin grant confers exactly CapAdmin at the
	// project scope.
	var targetCaptured store.ReplaceProjectGrantsInput
	targetReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants,
		got:    &targetCaptured,
	}
	targetHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, targetReplacer)
	targetRec := putProjectGrants(targetHandler, project.ID, "yk_proj_admin_scoped", replaceGrantsMatrixBody)
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped admin key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCaptured.OrganizationID != org {
		t.Errorf("replacer received org id %q, want the principal's home org %q",
			targetCaptured.OrganizationID, org)
	}
	if targetCaptured.ProjectID != project.ID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			targetCaptured.ProjectID, project.ID)
	}
	if targetCaptured.ActorID != projectAdminGrantee.ID {
		t.Errorf("replacer received actor id %q, want the principal id %q",
			targetCaptured.ActorID, projectAdminGrantee.ID)
	}
	if targetCaptured.ActorOrgID != org {
		t.Errorf("replacer received actor org id %q, want the principal's home org %q",
			targetCaptured.ActorOrgID, org)
	}
	if len(targetCaptured.Grants) != 2 {
		t.Errorf("replacer received %d grants, want 2: %+v", len(targetCaptured.Grants), targetCaptured.Grants)
	}
	targetEnv := decodeReplaceProjectGrants(t, targetRec)
	if len(targetEnv.Data.Grants) != len(postWriteGrants) {
		t.Errorf("grants len = %d, want %d", len(targetEnv.Data.Grants), len(postWriteGrants))
	}

	// Wire tie-in #2: the SAME project-scoped admin grantee hitting a
	// SIBLING project is a 403 with the stable out-of-scope reason,
	// the replacer is never reached (so a production store could
	// never have replaced grants in the background), and the body
	// never echoes the canonical project's or grants' identifiers nor
	// the caller-supplied replacement set. This is the property that
	// makes the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied access to a sibling
	// project's grants.
	var siblingCaptured store.ReplaceProjectGrantsInput
	siblingReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants, // would be returned if replacer ran — leak guard catches it
		got:    &siblingCaptured,
	}
	siblingHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, siblingReplacer)
	siblingRec := putProjectGrants(siblingHandler, "prj_grants_matrix_beta", "yk_proj_admin_scoped", replaceGrantsMatrixBody)
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingCaptured.OrganizationID != "" || siblingCaptured.ProjectID != "" || len(siblingCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q project=%q grants=%+v for an out-of-scope grantee; it must never run",
			siblingCaptured.OrganizationID, siblingCaptured.ProjectID, siblingCaptured.Grants)
	}
	if body := siblingRec.Body.String(); grantsDenyBodyLeak(body) || replaceGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// Wire tie-in #3: the project-scoped DEVELOPER grantee hitting
	// the SAME project is a 403 with ReasonDeniedNoCapability (the
	// grant covers the resource, but the role does not hold CapAdmin).
	// The replacer is never reached and the body never echoes any
	// canonical or request-body needle.
	var devCaptured store.ReplaceProjectGrantsInput
	devReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants,
		got:    &devCaptured,
	}
	devHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: projectDeveloperGrantee, Method: auth.MethodAPIKey}, nil, devReplacer)
	devRec := putProjectGrants(devHandler, project.ID, "yk_proj_dev", replaceGrantsMatrixBody)
	if devRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped developer key on its target project; body %s",
			devRec.Code, devRec.Body.String())
	}
	devDenyEnv := decodeError(t, devRec, "E_FORBIDDEN")
	if !strings.Contains(devDenyEnv.Error.Message, string(policy.ReasonDeniedNoCapability)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			devDenyEnv.Error.Message, policy.ReasonDeniedNoCapability)
	}
	if devCaptured.OrganizationID != "" || devCaptured.ProjectID != "" || len(devCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q project=%q grants=%+v for a developer-grant principal; it must never run",
			devCaptured.OrganizationID, devCaptured.ProjectID, devCaptured.Grants)
	}
	if body := devRec.Body.String(); grantsDenyBodyLeak(body) || replaceGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// Wire tie-in #4: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the replacer
	// is never reached. The leak guards catch an accidental render of
	// the canonical grants OR the caller-supplied replacement set
	// even though the env grantee never had project-write coverage at
	// all.
	var envCaptured store.ReplaceProjectGrantsInput
	envReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants,
		got:    &envCaptured,
	}
	envHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReplacer)
	envRec := putProjectGrants(envHandler, project.ID, "yk_env_scoped", replaceGrantsMatrixBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCaptured.OrganizationID != "" || envCaptured.ProjectID != "" || len(envCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q project=%q grants=%+v for an env-scoped grantee; it must never run",
			envCaptured.OrganizationID, envCaptured.ProjectID, envCaptured.Grants)
	}
	if body := envRec.Body.String(); grantsDenyBodyLeak(body) || replaceGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// Wire tie-in #5: the service-scoped grantee hitting the parent
	// project is a 403, the replacer is never reached, and the body
	// never echoes parent-level identifiers nor the caller-supplied
	// replacement set. This is the property that keeps a
	// service-scoped key from escalating to a parent-project grants
	// replace through this endpoint — the "service grant does not
	// expose parent-level secrets or unrelated services" acceptance
	// criterion tied back to the wire.
	var svcCaptured store.ReplaceProjectGrantsInput
	svcReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants,
		got:    &svcCaptured,
	}
	svcHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReplacer)
	svcRec := putProjectGrants(svcHandler, project.ID, "yk_svc_scoped", replaceGrantsMatrixBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.ProjectID != "" || len(svcCaptured.Grants) != 0 {
		t.Errorf("replacer was reached with org=%q project=%q grants=%+v for a service-scoped grantee; it must never run",
			svcCaptured.OrganizationID, svcCaptured.ProjectID, svcCaptured.Grants)
	}
	if body := svcRec.Body.String(); grantsDenyBodyLeak(body) || replaceGrantsRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project / post-write grants or the caller-supplied replacement set: %s", body)
	}

	// An organization-level Admin grant DOES cover any project
	// resource in the same org and — because project.grants.write is
	// CapAdmin and Admin holds CapAdmin — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at the
	// wire, with the replacer reached on the principal's home org id
	// and the path project id. This locks the CapAdmin requirement
	// against the grant path so a future catalog change that
	// downgraded project.grants.write to CapWrite would still pass
	// this allow check but fail the org-developer deny below — so the
	// pair of assertions is load-bearing as a unit.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.grants.write) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.ReplaceProjectGrantsInput
	orgReplacer := fakeProjectGrantReplacer{
		grants: postWriteGrants,
		got:    &orgCaptured,
	}
	orgHandler := replaceProjectGrantsHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putProjectGrants(orgHandler, project.ID, "yk_org_admin", replaceGrantsMatrixBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeReplaceProjectGrants(t, allowedRec)
	if len(allowedPayload.Data.Grants) != len(postWriteGrants) {
		t.Errorf("grants len = %d, want %d", len(allowedPayload.Data.Grants), len(postWriteGrants))
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ProjectID != project.ID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			orgCaptured.ProjectID, project.ID)
	}

	// An organization-level DEVELOPER grant covers the resource but
	// confers no admin capability; project.grants.write must be
	// denied via ReasonDeniedNoCapability even with org-wide scope.
	// This is the load-bearing distinction from the project.delete
	// grant matrix, where an org-level Developer grant would ALLOW
	// the action. Pairing this deny with the org-admin allow above
	// locks the CapAdmin requirement against the grant path: a
	// future catalog change that downgraded project.grants.write to
	// CapWrite would still pass the org-admin allow check but fail
	// this org-developer deny check — so the pair of assertions is
	// load-bearing as a unit.
	orgDeveloperGrantee := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloperGrantee, policy.ActionProjectGrantsWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.grants.write) for an organization-level developer grant = %+v, want deny via %q — developer holds no admin capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id is
	// foreign is denied at the engine: a grant for
	// prj_grants_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to replace
	// grants of prj_grants_matrix_alpha in org_sibling — the
	// cross-tenant guard fires first because the principal's home org
	// no longer matches the grant's scope. This is the engine-level
	// twin of the wire-level "wrong organization" property in
	// TestReplaceProjectGrantsPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. project.grants.write is OUTSIDE the support
	// cross-tenant exception regardless, but the assertion here is
	// structural: a scoped key's home org must match the grant
	// scope's org or the engine refuses to consider the grant at all.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectGrantsWrite, siblingOrgResource); got.Allow {
		t.Errorf("Decide(project.grants.write) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
