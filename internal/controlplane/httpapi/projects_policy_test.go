package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for GET /v1/projects (BE-0120). Where
// projects_test.go proves the endpoint's wire contract, this file proves
// its authorization contract: that action project.read cannot be bypassed
// by, or leak data because of, the principal's role, revoked credentials,
// home organization, or scoped grants.
//
// The route carries a NIL ResourceResolver (routes.go). RequireAuth
// therefore authorizes against the principal's own home organization
// scope — there is no caller-supplied path or query parameter that could
// point this read at another tenant. So tenant isolation here is
// structural: the source of authority is the principal's home organization
// id, and the reader is hardcoded to receive that same id. Cross-tenant
// "intrusion" of GET /v1/projects is impossible by construction; the test
// pins that property at the wire AND pins the engine-level cross-tenant
// boundary defence-in-depth (so a future endpoint that exposes an {org_id}
// path parameter inherits a working deny).
//
// project.read requires CapRead (catalog.go: ActionProjectRead -> CapRead).
// All six built-in roles hold CapRead, so the role matrix for a principal
// reading its own organization is "all allow"; the assertions that matter
// are that the verdict is reached through the role (ReasonAllowedByRole)
// and that the reader is reached with the principal's own organization id,
// never a fabricated, escalated, or sibling tenant. This is the same shape
// the limits.read / usage.read / env.read matrices carry — and the
// load-bearing distinction from a CapAdmin endpoint (e.g. audit.read,
// keys.read) where four of six roles deny and a scoped org-level Viewer
// grant would be denied.
//
// projects rows store no secrets, so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.read). Tenant-leakage
// invariants still apply: a denied response never echoes the cross-tenant
// id or seeded resource ids/slugs, and a same-tenant principal can never
// see another tenant's projects through this endpoint regardless of fake
// reader state.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, or the engine fails here. listProjectsHandlerFor, getProjects,
// fakeProjectReader, decodeListProjects, seedProject, orgPrincipal, and
// decodeError are shared with the projects contract suite
// (projects_test.go) and the wider httpapi test fixtures; this file adds
// no scaffolding beyond the small fixture builder below.

// seededProjects builds the canonical two-project fixture every test in
// this file shares. Two rows pin both the empty-array and multi-row
// projections at once — allowed tests prove the wire shape survives every
// principal class, and denied tests prove the ids/slugs/display names
// never leak in an error body. Keeping the fixture in one place lets a
// future regression that reorders, renames, or recategorises a field fail
// in exactly one place.
func seededProjects(orgID string) []store.Project {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	return []store.Project{
		seedProject("prj_alpha", orgID, "alpha", "Alpha", 1, now, now),
		seedProject("prj_beta", orgID, "beta", "Beta", 2, now, now),
	}
}

// projectsBodyLeak reports whether body contains any per-row value seeded
// by seededProjects — ids, slugs, and display names. A denied response
// that accidentally rendered any of these fails the test. Display names
// are intentionally separate from slugs ("Alpha" vs "alpha") so a
// case-collapsing renderer regression is caught too.
func projectsBodyLeak(body string) bool {
	needles := []string{
		"prj_alpha", "prj_beta",
		"\"alpha\"", "\"beta\"",
		"\"Alpha\"", "\"Beta\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListProjectsPolicyMatrixRoles drives every built-in role through
// the production request path. All six built-in roles hold CapRead, so
// the matrix is "all allow"; the assertions that matter are that the
// verdict is reached through the role (ReasonAllowedByRole) and that the
// reader is reached with the principal's own home organization id, never
// a fabricated, escalated, or sibling tenant. The response carries the
// seeded projects in the order the reader returned them, in a stable
// yalla.output.v1 envelope.
func TestListProjectsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
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

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. Support
			// reading ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support exception is exercised
			// in TestListProjectsPolicyWrongOrganizationPrincipal.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectRead, orgRoot)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(project.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var seen string
			reader := fakeProjectReader{projects: seededProjects(org), gotOrgID: &seen}
			handler := listProjectsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getProjects(handler, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if seen != org {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					seen, org)
			}
			env := decodeListProjects(t, rec)
			if env.SchemaVersion != "yalla.output.v1" {
				t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
			}
			if len(env.Data.Projects) != 2 {
				t.Fatalf("projects len = %d, want 2 (got %+v)", len(env.Data.Projects), env.Data.Projects)
			}
			alpha := env.Data.Projects[0]
			if alpha.ProjectID != "prj_alpha" || alpha.Slug != "alpha" ||
				alpha.DisplayName != "Alpha" || alpha.OrganizationID != org || alpha.Version != 1 {
				t.Errorf("[0] = %+v, want (prj_alpha alpha Alpha org=%q v=1)", alpha, org)
			}
			beta := env.Data.Projects[1]
			if beta.ProjectID != "prj_beta" || beta.Slug != "beta" ||
				beta.DisplayName != "Beta" || beta.OrganizationID != org || beta.Version != 2 {
				t.Errorf("[1] = %+v, want (prj_beta beta Beta org=%q v=2)", beta, org)
			}
		})
	}
}

// TestListProjectsPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action project.read with a stable 403 E_FORBIDDEN, even when
// the underlying role would have allowed it. A revoked or expired
// credential must never be able to enumerate projects of the
// organization it once had access to, the reader must never run, and
// the denied body must never echo the principal id, the organization
// id, or any seeded project data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0120 ("revoked key,
// expired key").
func TestListProjectsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

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

			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var seen string
			reader := fakeProjectReader{projects: seededProjects("org_acme"), gotOrgID: &seen}
			handler := listProjectsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getProjects(handler, "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if seen != "" {
				t.Errorf("reader was reached with org=%q for a disabled principal; it must never run", seen)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				projectsBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded project data", body)
			}
		})
	}
}

// TestListProjectsPolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for project.read. The route uses a nil resolver, so RequireAuth
// authorizes against the principal's own home organization — there is no
// path parameter a foreign principal could fabricate to point the read at
// another tenant. Tenant isolation on the wire is therefore structural:
//
//   - A principal in org_attacker hitting GET /v1/projects sees ONLY the
//     projects of org_attacker, regardless of what the fake reader was
//     seeded with for any other tenant. The reader is always called with
//     the principal's own home org id; the attacker can never widen the
//     read to org_victim through this endpoint.
//
//   - Engine defence-in-depth: even if a future endpoint exposed an
//     {org_id} path parameter, a non-support owner of org_attacker
//     authorizing project.read against an org_victim resource MUST be
//     denied with ReasonDeniedCrossTenant. This file pins that engine
//     verdict directly so the cross-tenant clause cannot regress
//     silently while waiting for the {org_id}-scoped endpoint to land.
//
//   - Support IS the documented cross-tenant exception for CapRead
//     actions (engine clause: CapSupport && (CapRead || CapSupport)). A
//     Support principal of org_yalla authorizing project.read against
//     an org_victim resource is allowed via ReasonAllowedBySupport, and
//     would receive the victim's projects on a future {org_id}-scoped
//     endpoint. Pinning this at the engine here means the eventual
//     scoped endpoint inherits the right verdict; it also locks the
//     CapRead requirement so a future catalog change that upgraded
//     project.read above CapRead would fail here (silently denying
//     every support cross-tenant read) before it could regress a real
//     customer.
func TestListProjectsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits /v1/projects with a
	// fake reader seeded with the attacker's own org projects. The
	// assertion that matters is structural: the reader is ALWAYS called
	// with the principal's home org id — never with a caller-controlled
	// or fabricated value — so a production ProjectReader (which only
	// returns projects belonging to the org id it was queried for)
	// could not have surfaced the victim's projects through this
	// endpoint regardless of database state. The body must therefore
	// also never echo the victim's org id, since no input path reaches
	// the response from here.
	var seenAttacker string
	attackerReader := fakeProjectReader{
		gotOrgID: &seenAttacker,
		projects: seededProjects(ownOrg),
	}
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	attackerHandler := listProjectsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, attackerReader)

	rec := getProjects(attackerHandler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a cross-tenant principal still sees its OWN org); body %s",
			rec.Code, rec.Body.String())
	}
	if seenAttacker != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			seenAttacker, ownOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so a
	// future endpoint that resolves an {org_id} path parameter into a
	// foreign org scope inherits a working cross-tenant deny. project.read
	// is CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionProjectRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(project.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches project.read because the
	// catalog maps it to CapRead. This is the same distinguishing
	// property limits.read / usage.read / env.read carry — all four
	// share the action capability class and the exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionProjectRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(project.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListProjectsPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (it carries no organization role); the
// engine confines those grants — a project grant does not reach a sibling
// project, an environment grant does not reach production, a service
// grant does not reach the parent environment or a sibling service.
//
// Crucially for GET /v1/projects: project.read is evaluated against the
// principal's home organization root (the route's nil resolver). A
// project/environment/service-scoped grant — even an Admin grant — does
// not cover that scope (covers() is one-way: a more-specific scope cannot
// reach a broader resource), not even for the key's own organization. So
// a scoped key holding only a project grant is denied the endpoint at
// its own home org with the stable ReasonDeniedOutOfScope, while a key
// holding an organization-level grant — even a Viewer grant, since
// project.read is CapRead — is allowed it (ReasonAllowedByGrant). A
// scoped grant narrows authority within a tenant; it can never be
// escalated to an organization-wide project list.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied back
// to the wire by proving the project grantee is denied the endpoint at
// its own home organization, while an organization-scoped Viewer grantee
// is allowed it.
func TestListProjectsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Sibling-project
	// containment is pinned via the project-update action so the grant
	// has the relevant capability at the relevant scope.
	scopeP := policy.Scope{OrganizationID: org, ProjectID: "proj_p"}
	scopeQ := policy.Scope{OrganizationID: org, ProjectID: "proj_q"}
	projectGrantee := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeP}},
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeP}); !got.Allow {
		t.Errorf("update inside the granted project = %+v, want allow", got)
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeQ}); got.Allow {
		t.Errorf("update a sibling project = %+v, want deny — a project grant must not reach proj_q", got)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_staging"}
	scopeProd := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeStaging}); !got.Allow {
		t.Errorf("update inside the granted environment = %+v, want allow", got)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProd}); got.Allow {
		t.Errorf("update production = %+v, want deny — a staging grant must not reach production unless production is explicitly granted", got)
	}

	// Service-level grant: admin on a single service only. The grant
	// must not expose parent-level secrets (env-write on the parent
	// environment) and must not reach a sibling service.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod"}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets", got)
	}

	// GET /v1/projects reads against the principal's home organization
	// root (the route's nil resolver). A project/environment/service-
	// scoped admin grant does NOT cover that scope — not even for the
	// key's own organization — so each scoped grantee is denied the
	// endpoint with ReasonDeniedOutOfScope: the scoped key cannot be
	// widened to an organization-wide project list, and the reader
	// never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionProjectRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionProjectRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionProjectRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee hitting
	// /v1/projects is a 403 with the stable out-of-scope reason, the
	// reader is never reached, and the body never echoes the seeded
	// project data. This is the property that makes the policy boundary
	// — not the persistence boundary — the structural place a scoped
	// key is denied broader visibility.
	var projectSeen string
	projectReader := fakeProjectReader{projects: seededProjects(org), gotOrgID: &projectSeen}
	projectHandler := listProjectsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getProjects(projectHandler, "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectSeen != "" {
		t.Errorf("reader was reached with org=%q for an out-of-scope grantee; it must never run",
			projectSeen)
	}
	if body := rec.Body.String(); projectsBodyLeak(body) {
		t.Errorf("denied response leaks the seeded project data: %s", body)
	}

	// An organization-level Viewer grant DOES cover the org-root scope
	// and — because project.read is CapRead and Viewer holds CapRead —
	// is allowed via ReasonAllowedByGrant. The same key is end-to-end
	// allowed at the wire, with the reader reached on the principal's
	// home org id. This locks the CapRead requirement against the grant
	// path so a future catalog change that upgraded project.read above
	// CapRead would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionProjectRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgSeen string
	orgReader := fakeProjectReader{projects: seededProjects(org), gotOrgID: &orgSeen}
	orgHandler := listProjectsHandlerFor(
		auth.Identity{Principal: orgViewer, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getProjects(orgHandler, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeListProjects(t, allowedRec)
	if len(allowedPayload.Data.Projects) != 2 ||
		allowedPayload.Data.Projects[0].ProjectID != "prj_alpha" ||
		allowedPayload.Data.Projects[1].ProjectID != "prj_beta" {
		t.Errorf("projects = %+v, want the seeded [prj_alpha, prj_beta] pair",
			allowedPayload.Data.Projects)
	}
	if orgSeen != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgSeen, org)
	}

	// And the same project-scoped grantee whose home org id is foreign
	// is denied at the engine: a grant for proj_p inside org_acme,
	// carried by a principal whose home org id is org_sibling, cannot
	// be used to enumerate projects of org_sibling — the cross-tenant
	// guard fires first because the principal's home org no longer
	// matches the grant's scope. This is the engine-level twin of the
	// wire-level "wrong organization" property in
	// TestListProjectsPolicyWrongOrganizationPrincipal, applied to a
	// scoped key: stealing a key cannot smuggle it across tenants.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeP}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectRead, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(project.read) for a project-scoped key planted in a foreign org = %+v, want deny",
			got)
	}
}
