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

// Policy-matrix coverage for GET /v1/projects/{project_id}/grants
// (BE-0138). Where project_grants_test.go proves the endpoint's wire
// contract (BE-0136), this file proves its authorization contract: that
// action project.grants.read cannot be bypassed by — or leak grant rows
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries the projectIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {project_id} PATH parameter. RequireAuth therefore authorizes against
// the project the path names — not merely the principal's home
// organization — and the resource Kind is the project, not the grant
// list. That is the load-bearing distinction from the project-create
// matrix (projects_create_policy_test.go), where the resource is the
// organization root and the route uses a nil resolver:
//
//   - The create matrix authorizes against the organization root, so a
//     project-level grant cannot reach it. Here the resource IS
//     project-level, so a project-level grant naming THIS project CAN
//     authorize the read while a project-level grant naming a SIBLING
//     project cannot.
//   - The handler still derives the organization id on the store input
//     from the PRINCIPAL'S home org (never the caller — there is no
//     request body for a list at all), so a cross-tenant project_id
//     reaches the tenant-scoped repository query with the principal's
//     home org id and is rejected as a deterministic 404 NotFound at
//     the persistence layer by the reader's project existence check. A
//     cross-tenant project_id can never reveal another organization's
//     grants, and the wire body must never echo the foreign org id even
//     though no wire input could place it there.
//
// project.grants.read requires CapRead (catalog.go: ActionProjectGrantsRead
// -> CapRead), the same capability class as project.read, env.read,
// service.read, limits.read, and usage.read. All six built-in roles hold
// CapRead, so the role matrix for a principal reading grants in its own
// organization is "all allow"; the assertions that matter are that the
// verdict is reached through the role (ReasonAllowedByRole), the reader
// is called with the principal's own home organization id AND the
// {project_id} path parameter (so the tenant-scoped repository query
// cannot match grants of a project in another tenant), and the response
// carries the canonical grant list in a stable yalla.output.v1 envelope.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support principal
// authorizing project.grants.read against a foreign-tenant resource IS
// allowed via ReasonAllowedBySupport — the same property project.read /
// limits.read / usage.read / env.read carry. Every non-support role is
// denied with ReasonDeniedCrossTenant. The customer-facing route under
// test cannot reach that engine branch by construction (projectIDResolver
// pins the resource scope to the PRINCIPAL'S home org, not the path's
// tenant), but pinning the engine verdict here means a future endpoint
// that resolves the resource into a foreign-org scope (a hypothetical
// admin tool) inherits a working cross-tenant deny and the documented
// support exception, and a future catalog change that upgraded
// project.grants.read above CapRead would fail here (silently denying
// every support cross-tenant read) before it could regress a real
// customer.
//
// project_grants rows store no credential material — only structural
// identifiers and a role enum — so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.read). Tenant-leakage and
// no-read invariants still apply: a denied response never echoes any
// seeded grant id / principal id / role, the foreign tenant's id, or
// the canonical project's slug / display name; and the reader MUST
// never run on any deny path — a scoped key denied on the wire cannot
// have surfaced a grant row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// listProjectGrantsHandlerFor, getProjectGrants, decodeListProjectGrants,
// seedProjectGrantWire, fakeProjectGrantReader, orgPrincipal, seedProject,
// and decodeError are shared with the project-grants contract suite
// (project_grants_test.go) and the wider httpapi test fixtures; this
// file adds no scaffolding beyond the small fixture builders below.

// canonicalGrantsProject is the project every test in this file resolves
// the {project_id} path parameter to. Centralising it lets a future
// regression that reorders, renames, or recategorises a project-grant
// projection field needle for the same identifiers in one place. The
// distinctive id / slug / display name are deliberately recognisable so
// deny-path leak guards can needle for them; allow-path assertions
// compare against the same canonical values.
func canonicalGrantsProject(orgID string) store.Project {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 9, 1, 0, time.UTC)
	return seedProject("prj_grants_matrix_alpha", orgID, "grants-matrix-alpha", "Grants Matrix Alpha", 13, created, updated)
}

// canonicalProjectGrants is the grant list every test in this file would
// receive back from the reader on an allow path. It mixes a
// project-scoped user grant and an env+service-scoped service-account
// grant so the wire projection's nullable EnvironmentID / ServiceID
// pointers and Principal.Kind enum are exercised on the allow side.
// Deny-path leak guards needle for the distinctive grant ids and
// principal ids so an accidental render — even a partial one — fails
// the test.
func canonicalProjectGrants(orgID, projectID string) []store.ProjectGrant {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	envID := "env_prod_matrix"
	svcID := "svc_web_matrix"
	return []store.ProjectGrant{
		seedProjectGrantWire("pgrnt_matrix_one", orgID, projectID, "usr_matrix_one", "usr", "developer", nil, nil, 1, created, updated),
		seedProjectGrantWire("pgrnt_matrix_two", orgID, projectID, "sa_matrix_two", "sa", "ci", &envID, &svcID, 3, created, updated),
	}
}

// grantsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project or its
// grants. A denied response that accidentally rendered any of these
// fails the test — the row's existence (and the principal it grants
// authority to) is itself information a denied principal must not
// receive. The quoted forms catch a case-collapsing renderer
// regression. There is no request body for GET
// /v1/projects/{project_id}/grants, so unlike a write-path leak guard
// there is no caller-supplied request-body field to protect.
func grantsDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_grants_matrix_alpha",
		"\"grants-matrix-alpha\"",
		"\"Grants Matrix Alpha\"",
		"pgrnt_matrix_one",
		"pgrnt_matrix_two",
		"usr_matrix_one",
		"sa_matrix_two",
		"env_prod_matrix",
		"svc_web_matrix",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListProjectGrantsPolicyMatrixRoles drives every built-in role
// through the production request path. All six built-in roles hold
// CapRead, so the matrix is "all allow" for a principal reading grants
// of a project in its own organization; the assertions that matter are
// that the verdict is reached through the role (ReasonAllowedByRole),
// the reader is called with the principal's own home org id AND the
// {project_id} path parameter (so a tenant-scoped store query cannot
// match a foreign row), and the response is a stable 200
// yalla.output.v1 envelope carrying the canonical grant list with
// every nullable field projected correctly.
func TestListProjectGrantsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	grants := canonicalProjectGrants(org, project.ID)
	projectResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project.ID},
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
			// reading grants in ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support cross-tenant exception
			// is exercised in
			// TestListProjectGrantsPolicyWrongOrganizationPrincipal.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectGrantsRead, projectResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(project.grants.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotProj string
			callCount := 0
			reader := fakeProjectGrantReader{
				grants:       grants,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listProjectGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getProjectGrants(handler, project.ID, "a-valid-token")

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
			if gotProj != project.ID {
				t.Errorf("reader received project id %q, want the path parameter %q",
					gotProj, project.ID)
			}
			env := decodeListProjectGrants(t, rec)
			if len(env.Data.Grants) != len(grants) {
				t.Fatalf("grants len = %d, want %d; body %s",
					len(env.Data.Grants), len(grants), rec.Body.String())
			}
			// Spot-check the projection lands the load-bearing fields
			// of both rows — the user grant (project-scoped, env/svc
			// null) and the service-account grant (env+service scoped).
			// A future regression that swapped a nullable pointer for a
			// zero string would fail here.
			got0 := env.Data.Grants[0]
			if got0.GrantID != "pgrnt_matrix_one" || got0.Principal.Kind != "usr" {
				t.Errorf("got[0] = %+v, want pgrnt_matrix_one / usr", got0)
			}
			if got0.EnvironmentID != nil || got0.ServiceID != nil {
				t.Errorf("got[0] env/svc = %v/%v, want both nil", got0.EnvironmentID, got0.ServiceID)
			}
			got1 := env.Data.Grants[1]
			if got1.GrantID != "pgrnt_matrix_two" || got1.Principal.Kind != "sa" {
				t.Errorf("got[1] = %+v, want pgrnt_matrix_two / sa", got1)
			}
			if got1.EnvironmentID == nil || *got1.EnvironmentID != "env_prod_matrix" {
				t.Errorf("got[1].environment_id = %v, want env_prod_matrix", got1.EnvironmentID)
			}
			if got1.ServiceID == nil || *got1.ServiceID != "svc_web_matrix" {
				t.Errorf("got[1].service_id = %v, want svc_web_matrix", got1.ServiceID)
			}
		})
	}
}

// TestListProjectGrantsPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal —
// is denied action project.grants.read with a stable 403 E_FORBIDDEN,
// even when the underlying role would have allowed it. A revoked or
// expired credential must never be able to list grants of a project of
// the organization it once had access to, the reader must never run,
// and the denied body must never echo the principal id, the
// organization id, the path-supplied project id, or any seeded grant
// data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.grants.read; Disabled is the only thing in the way and must
// be load-bearing. The case names mirror PRD BE-0138 ("revoked key,
// expired key").
func TestListProjectGrantsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	grants := canonicalProjectGrants(org, project.ID)

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

			var gotOrg, gotProj string
			callCount := 0
			reader := fakeProjectGrantReader{
				grants:       grants,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			handler := listProjectGrantsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getProjectGrants(handler, project.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotOrg != "" || gotProj != "" {
				t.Errorf("reader was reached (calls=%d org=%q project=%q) for a disabled principal; it must never run",
					callCount, gotOrg, gotProj)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				grantsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded grant data", body)
			}
		})
	}
}

// TestListProjectGrantsPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for project.grants.read. As with project.read,
// the resource org id is taken from the PRINCIPAL'S home org — the
// {project_id} path parameter alone never widens the resource to
// another tenant. Tenant isolation on the wire is therefore structural
// at the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/projects/{prj_victim}/grants with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapRead — and then reaches
//     the tenant-scoped repository query with the principal's home org
//     id and the foreign project id. The store-backed reader Gets the
//     project under (organization_id, project_id) before listing its
//     grants, so a cross-tenant project_id is rejected as a
//     deterministic 404 E_NOT_FOUND, never disguised as an empty
//     success — which would invite an agent to believe the project
//     exists with no grants. The body must never echo the foreign org
//     id even though no wire input could place it there, because the
//     persistence layer must not leak foreign-tenant identity into the
//     error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY non-support role MUST
//     be denied via ReasonDeniedCrossTenant, and a Support principal
//     MUST be allowed via ReasonAllowedBySupport (CapRead is inside
//     the engine clause `roleCaps.has(CapSupport) && (required ==
//     CapRead || required == CapSupport)`). Pinning that engine
//     verdict here means the eventual scoped variant inherits a
//     working cross-tenant deny and the documented support exception,
//     and a future catalog change that upgraded project.grants.read
//     above CapRead would fail here (silently denying every support
//     cross-tenant read) before it could regress a real customer.
func TestListProjectGrantsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_alpha"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/projects/{prj_victim}/grants with a valid Owner token. The
	// fake mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, projectID) pair does not match a
	// row (the reader's project existence check fires first), so a
	// principal whose home org is org_attacker listing grants of a
	// project that belongs to org_victim hits the fake with
	// (org_attacker, prj_victim_alpha) and gets NotFound. The
	// assertions that matter are structural: the reader is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectGrantReader could not have surfaced the victim's grants
	// regardless of database state. The denied body must never echo
	// the victim's org id.
	var gotOrg, gotProj string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeProjectGrantReader{
		err:          apierr.NotFound("project", foreignProjID),
		gotOrgID:     &gotOrg,
		gotProjectID: &gotProj,
		callCount:    &callCount,
	}
	handler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getProjectGrants(handler, foreignProjID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with an empty list and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1 — the reader runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign project id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			gotOrg, ownOrg)
	}
	if gotProj != foreignProjID {
		t.Errorf("reader received project id %q, want the path parameter %q",
			gotProj, foreignProjID)
	}
	env := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(env.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			env.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// a future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. project.grants.read
	// is CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
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
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionProjectGrantsRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.grants.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches project.grants.read because
	// the catalog maps it to CapRead. This locks the CapRead
	// requirement against the support cross-tenant path so a future
	// catalog change that upgraded project.grants.read above CapRead
	// would fail here (silently denying every support cross-tenant
	// read) before it could regress a real customer. The
	// customer-facing route under test cannot reach this engine branch
	// by construction — projectIDResolver pins the resource scope to
	// the principal's own home org — but the engine verdict is the
	// authoritative source of the documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionProjectGrantsRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(project.grants.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListProjectGrantsPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production unless production is explicitly granted, a service grant
// does not reach the parent environment or a sibling service.
//
// Crucially for GET /v1/projects/{project_id}/grants:
// project.grants.read is evaluated against a PROJECT-level resource
// (the projectIDResolver scope is {home_org, path_project_id}). This is
// the load-bearing distinction from the project-create matrix
// (projects_create_policy_test.go), where the resource is the
// ORGANIZATION root and no project-/env-/service-level grant can reach
// it. Here:
//
//   - A project-level Viewer grant naming THIS project CAN authorize
//     the read (ReasonAllowedByGrant), and at the wire the reader
//     receives (home_org, target_project_id) — the grant scope
//     contains the resource scope and CapRead is conferred.
//   - A project-level Viewer grant naming a SIBLING project CANNOT —
//     covers() is one-way, so the grant scope does not contain the
//     resource scope. The denial is ReasonDeniedOutOfScope (the
//     principal holds the capability somewhere, just not here).
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope — the "env grant
//     does not imply access to production unless production is
//     explicitly granted" property still applies here: even an env
//     grant on the same project's production environment cannot
//     escalate to listing the parent project's grants.
//   - A service-level grant likewise does NOT cover a project resource
//     and does not expose the parent environment's secrets through
//     env.write either — the "service grant does not expose
//     parent-level secrets or unrelated services" property.
//   - An organization-level Viewer grant DOES cover any project
//     resource within the same org and — because project.grants.read
//     is CapRead and Viewer holds CapRead — is allowed via
//     ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, service grant
// shielding parent-level secrets — are pinned against the engine, then
// tied back to the wire by proving the reader is never reached on any
// deny path (so a production store could not have surfaced grants in
// the background) and the denied body never echoes the canonical
// project's or grants' identifiers.
func TestListProjectGrantsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGrantsProject(org)
	grants := canonicalProjectGrants(org, project.ID)
	e := policy.NewEngine()

	// Project-level grant: viewer on prj_grants_matrix_alpha only.
	// Viewer confers CapRead at the project scope, which is exactly
	// what project.grants.read needs. The sibling-project property is
	// pinned for project.grants.read directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_grants_matrix_beta"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectGrantsRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.grants.read) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectGrantsRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.read) for a sibling project = %+v, want deny via %q — a project-scoped viewer grant must not reach prj_grants_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant
	// scope, so covers() does not reach it for project.grants.read.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionProjectGrantsRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.read) for an environment-scoped grantee = %+v, want deny via %q — an env grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentDelete, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(environment.delete) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow project.grants.read on the parent
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
	if got := e.Decide(svcGrantee, policy.ActionProjectGrantsRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.grants.read) for a service-scoped grantee = %+v, want deny via %q — a service grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// TARGET project is a 200 with the canonical grant list, the
	// reader is reached with (home_org, target_project_id), and the
	// response carries the grants. A project-scoped Viewer grant
	// confers exactly CapRead at the project scope.
	var targetGotOrg, targetGotProj string
	targetCallCount := 0
	targetReader := fakeProjectGrantReader{
		grants:       grants,
		gotOrgID:     &targetGotOrg,
		gotProjectID: &targetGotProj,
		callCount:    &targetCallCount,
	}
	targetHandler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, targetReader)
	targetRec := getProjectGrants(targetHandler, project.ID, "yk_proj_viewer_scoped")
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped viewer key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", targetCallCount)
	}
	if targetGotOrg != org {
		t.Errorf("reader received org id %q, want the principal's home org %q",
			targetGotOrg, org)
	}
	if targetGotProj != project.ID {
		t.Errorf("reader received project id %q, want the path parameter %q",
			targetGotProj, project.ID)
	}
	targetEnv := decodeListProjectGrants(t, targetRec)
	if len(targetEnv.Data.Grants) != len(grants) {
		t.Errorf("grants len = %d, want %d", len(targetEnv.Data.Grants), len(grants))
	}

	// Wire tie-in #2: the SAME project-scoped Viewer grantee hitting a
	// SIBLING project is a 403 with the stable out-of-scope reason,
	// the reader is never reached (so a production store could never
	// have surfaced sibling grants in the background), and the body
	// never echoes the canonical project's or grants' identifiers.
	// This is the property that makes the policy boundary — not the
	// persistence boundary — the structural place a scoped key is
	// denied access to a sibling project's grants.
	var siblingGotOrg, siblingGotProj string
	siblingCallCount := 0
	siblingReader := fakeProjectGrantReader{
		grants:       grants, // would be returned if reader ran — leak guard catches it
		gotOrgID:     &siblingGotOrg,
		gotProjectID: &siblingGotProj,
		callCount:    &siblingCallCount,
	}
	siblingHandler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, siblingReader)
	siblingRec := getProjectGrants(siblingHandler, "prj_grants_matrix_beta", "yk_proj_viewer_scoped")
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingCallCount != 0 || siblingGotOrg != "" || siblingGotProj != "" {
		t.Errorf("reader was reached (calls=%d org=%q project=%q) for an out-of-scope grantee; it must never run",
			siblingCallCount, siblingGotOrg, siblingGotProj)
	}
	if body := siblingRec.Body.String(); grantsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or grants: %s", body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the reader is
	// never reached. The leak guard catches an accidental render of
	// the canonical grants even though the env grantee never had
	// project-read coverage at all.
	var envGotOrg, envGotProj string
	envCallCount := 0
	envReader := fakeProjectGrantReader{
		grants:       grants,
		gotOrgID:     &envGotOrg,
		gotProjectID: &envGotProj,
		callCount:    &envCallCount,
	}
	envHandler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getProjectGrants(envHandler, project.ID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotOrg != "" || envGotProj != "" {
		t.Errorf("reader was reached (calls=%d org=%q project=%q) for an env-scoped grantee; it must never run",
			envCallCount, envGotOrg, envGotProj)
	}
	if body := envRec.Body.String(); grantsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or grants: %s", body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the reader is never reached, and the body
	// never echoes parent-level identifiers. This is the property that
	// keeps a service-scoped key from escalating to a parent-project
	// grants read through this endpoint — the "service grant does not
	// expose parent-level secrets or unrelated services" acceptance
	// criterion tied back to the wire.
	var svcGotOrg, svcGotProj string
	svcCallCount := 0
	svcReader := fakeProjectGrantReader{
		grants:       grants,
		gotOrgID:     &svcGotOrg,
		gotProjectID: &svcGotProj,
		callCount:    &svcCallCount,
	}
	svcHandler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getProjectGrants(svcHandler, project.ID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotOrg != "" || svcGotProj != "" {
		t.Errorf("reader was reached (calls=%d org=%q project=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotOrg, svcGotProj)
	}
	if body := svcRec.Body.String(); grantsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or grants: %s", body)
	}

	// An organization-level Viewer grant DOES cover any project
	// resource in the same org and — because project.grants.read is
	// CapRead and Viewer holds CapRead — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at the
	// wire, with the reader reached on the principal's home org id
	// and the path project id. This locks the CapRead requirement
	// against the grant path so a future catalog change that upgraded
	// project.grants.read above CapRead would fail here (silently
	// denying every org-level Viewer grantee) before it could regress
	// a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionProjectGrantsRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.grants.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotProj string
	orgCallCount := 0
	orgReader := fakeProjectGrantReader{
		grants:       grants,
		gotOrgID:     &orgGotOrg,
		gotProjectID: &orgGotProj,
		callCount:    &orgCallCount,
	}
	orgHandler := listProjectGrantsHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getProjectGrants(orgHandler, project.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeListProjectGrants(t, allowedRec)
	if len(allowedPayload.Data.Grants) != len(grants) {
		t.Errorf("grants len = %d, want %d", len(allowedPayload.Data.Grants), len(grants))
	}
	if orgCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, org)
	}
	if orgGotProj != project.ID {
		t.Errorf("reader received project id %q, want the path parameter %q",
			orgGotProj, project.ID)
	}

	// And the same project-scoped viewer grantee whose home org id is
	// foreign is denied at the engine: a grant for
	// prj_grants_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to list grants
	// of prj_grants_matrix_alpha in org_sibling — the cross-tenant
	// guard fires first because the principal's home org no longer
	// matches the grant's scope. This is the engine-level twin of the
	// wire-level "wrong organization" property in
	// TestListProjectGrantsPolicyWrongOrganizationPrincipal, applied to
	// a scoped key: stealing a key cannot smuggle it across tenants.
	// (project.grants.read IS inside the support cross-tenant
	// exception, but the principal here is a service account with no
	// CapSupport role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectGrantsRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(project.grants.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
