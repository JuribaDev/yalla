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

// Policy-matrix coverage for GET /v1/projects/{project_id} (BE-0126). Where
// projects_get_test.go proves the endpoint's wire contract (BE-0124), this
// file proves its authorization contract: that action project.read cannot
// be bypassed by — or leak data because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// Unlike GET /v1/projects (nil resolver), this route carries the
// projectIDResolver (routes.go), which builds the policy resource from
// the principal's HOME organization id and the {project_id} PATH
// parameter. That is the load-bearing distinction from the list matrix
// (projects_policy_test.go) and from GET /v1/organizations/{org_id}
// (organizations_get_policy_test.go):
//
//   - The list matrix authorizes against the organization root; a
//     project-level grant cannot reach the org root. Here the resource
//     IS project-level, so a project-level grant naming THIS project
//     CAN authorize the read while a project-level grant naming a
//     SIBLING project cannot.
//
//   - GET /v1/organizations/{org_id} takes the org id from the PATH, so
//     a foreign {org_id} fires the engine's cross-tenant clause and is
//     a 403. Here the resource org id is taken from the PRINCIPAL'S
//     home org (never the caller), so a cross-tenant project_id falls
//     SAME-tenant at the engine and surfaces as a deterministic 404 at
//     the tenant-scoped persistence layer instead. A cross-tenant
//     project_id can never reveal another organization's project, and
//     the wire body must never echo the foreign org id even though no
//     wire input could place it there.
//
// project.read requires CapRead (catalog.go: ActionProjectRead ->
// CapRead). All six built-in roles hold CapRead, so the role matrix for
// a principal reading a project in its own organization is "all allow";
// the assertions that matter are that the verdict is reached through
// the role (ReasonAllowedByRole), the reader is called with the
// principal's own home organization id AND the {project_id} path
// parameter (so the tenant-scoped repository query cannot match a row
// in another tenant), and the response carries the requested project
// in a stable yalla.output.v1 envelope.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing project.read against a foreign-tenant resource
// IS allowed via ReasonAllowedBySupport — the same property limits.read
// / usage.read / env.read carry. Every non-support role is denied with
// ReasonDeniedCrossTenant. Pinning that engine verdict here means a
// future endpoint that constructs a resource with a foreign-org scope
// (e.g. a hypothetical admin tool) inherits a working cross-tenant
// deny and the documented support exception, while the customer-facing
// route under test cannot reach that branch by construction.
//
// projects rows store no secrets, so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.read). Tenant-leakage
// invariants still apply: a denied response never echoes the seeded
// resource id/slug/display name or the foreign tenant's id, and a
// denied principal never reaches the reader — a scoped-key deny on the
// wire cannot have surfaced a row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// listProjectsHandlerFor (which also wires the GET /v1/projects/{project_id}
// route), getProjectByID, decodeGetProject, decodeGetProjectError,
// fakeProjectReader, orgPrincipal, seedProject, projectResource, and
// decodeError are shared with the projects-get contract suite
// (projects_get_test.go) and the wider httpapi test fixtures; this file
// adds no scaffolding beyond the small fixture builders below.

// canonicalGetProject is the row every test in this file reads.
// Centralising it lets a future regression that reorders, renames, or
// recategorises a projectResource field fail in exactly one place. The
// distinctive id/slug/display name are deliberately recognisable so
// deny-path leak guards can needle for them.
func canonicalGetProject(orgID string) store.Project {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return seedProject("prj_matrix_alpha", orgID, "matrix-alpha", "Matrix Alpha", 7, created, updated)
}

// getProjectDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project: id, slug,
// display name. A denied response that accidentally rendered any of
// these fails the test — a deny path must never echo a project row,
// because that row's existence is itself information a denied principal
// must not have. The slug "matrix-alpha" and the display name "Matrix
// Alpha" are intentionally separate so a case-collapsing renderer
// regression is caught too.
func getProjectDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_matrix_alpha",
		"\"matrix-alpha\"",
		"\"Matrix Alpha\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestGetProjectPolicyMatrixRoles drives every built-in role through the
// production request path. All six built-in roles hold CapRead, so the
// matrix is "all allow" for a principal reading a project in its own
// organization; the assertions that matter are that the verdict is
// reached through the role (ReasonAllowedByRole), the reader is called
// with the principal's own home org id AND the {project_id} path
// parameter (so a tenant-scoped store query cannot match a foreign
// row), and the response is a stable 200 yalla.output.v1 envelope
// carrying the requested project.
func TestGetProjectPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGetProject(org)
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
			// reading a project in ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support cross-tenant exception
			// is exercised in
			// TestGetProjectPolicyWrongOrganizationPrincipal.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectRead, projectResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(project.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotProj string
			reader := fakeProjectReader{
				project:         project,
				gotGetOrgID:     &gotOrg,
				gotGetProjectID: &gotProj,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listProjectsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getProjectByID(handler, project.ID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if gotOrg != org {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					gotOrg, org)
			}
			if gotProj != project.ID {
				t.Errorf("reader received project id %q, want the path parameter %q",
					gotProj, project.ID)
			}
			env := decodeGetProject(t, rec)
			if env.Data.Project.ProjectID != project.ID ||
				env.Data.Project.Slug != project.Slug ||
				env.Data.Project.DisplayName != project.DisplayName ||
				env.Data.Project.OrganizationID != org ||
				env.Data.Project.Version != project.Version {
				t.Errorf("project = %+v, want (%s, %s, %s, org=%s, v=%d)",
					env.Data.Project, project.ID, project.Slug, project.DisplayName, org, project.Version)
			}
		})
	}
}

// TestGetProjectPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action project.read with a stable 403 E_FORBIDDEN, even when
// the underlying role would have allowed it. A revoked or expired
// credential must never be able to read a project of the organization
// it once had access to, the reader must never run, and the denied
// body must never echo the principal id, the organization id, the
// path-supplied project id, or any seeded project data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0126 ("revoked key,
// expired key").
func TestGetProjectPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGetProject(org)

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
			reader := fakeProjectReader{
				project:         project,
				gotGetOrgID:     &gotOrg,
				gotGetProjectID: &gotProj,
			}
			handler := listProjectsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getProjectByID(handler, project.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotOrg != "" || gotProj != "" {
				t.Errorf("reader was reached with org=%q project=%q for a disabled principal; it must never run",
					gotOrg, gotProj)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				getProjectDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded project data", body)
			}
		})
	}
}

// TestGetProjectPolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for project.read. Unlike GET /v1/organizations/{org_id},
// which takes the org id from the PATH (and so fires the engine's
// cross-tenant clause for a foreign {org_id}), this route takes the
// resource org id from the PRINCIPAL'S home org — the {project_id}
// path parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting GET /v1/projects/{prj_victim}
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapRead — and then reaches
//     the tenant-scoped repository query with the principal's home org
//     id and the foreign project id. A production reader (which
//     combines organization_id and id in its WHERE clause) cannot
//     match a row that belongs to another tenant, so the request
//     surfaces as a deterministic 404 E_NOT_FOUND. The body must never
//     echo the foreign org id even though no wire input could place it
//     there, because the persistence layer must not leak foreign-tenant
//     identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY non-support role MUST be
//     denied via ReasonDeniedCrossTenant, and a Support principal MUST
//     be allowed via ReasonAllowedBySupport (CapRead is inside the
//     engine clause `roleCaps.has(CapSupport) && (required == CapRead
//     || required == CapSupport)`). Pinning that engine verdict here
//     means the eventual scoped variant inherits a working
//     cross-tenant deny and the documented support exception, and a
//     future catalog change that upgraded project.read above CapRead
//     would fail here (silently denying every support cross-tenant
//     read) before it could regress a real customer.
func TestGetProjectPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_alpha"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/projects/{prj_victim} with a valid token. The fake mirrors
	// the production store contract: it returns NotFound whenever the
	// (organizationID, projectID) pair does not match a row, so a
	// principal whose home org is org_attacker reading a project that
	// belongs to org_victim hits the fake with (org_attacker,
	// prj_victim_alpha) and gets NotFound. The assertions that matter
	// are structural: the reader is ALWAYS called with the principal's
	// home org id — never with a caller-controlled value — so a
	// production tenant-scoped ProjectReader could not have surfaced
	// the victim's project regardless of database state. The denied
	// body must never echo the victim's org id.
	var gotOrg, gotProj string
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeProjectReader{
		getErr:          apierr.NotFound("project", foreignProjID),
		gotGetOrgID:     &gotOrg,
		gotGetProjectID: &gotProj,
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getProjectByID(handler, foreignProjID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
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
	// scope (e.g. a hypothetical admin tool) inherits a working
	// cross-tenant deny. project.read is CapRead, so the engine clause
	// `CapSupport && (CapRead || CapSupport)` admits Support and
	// denies every non-support role.
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
			got := e.Decide(p, policy.ActionProjectRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches project.read because the
	// catalog maps it to CapRead. This locks the CapRead requirement
	// against the support cross-tenant path so a future catalog change
	// that upgraded project.read above CapRead would fail here
	// (silently denying every support cross-tenant read) before it
	// could regress a real customer.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionProjectRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(project.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestGetProjectPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (it carries no organization role); the
// engine confines those grants — a project grant does not reach a
// sibling project, an environment grant does not reach production, a
// service grant does not reach the parent environment or a sibling
// service.
//
// Crucially for GET /v1/projects/{project_id}: project.read is
// evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}). This is the load-bearing
// distinction from the list matrix (projects_policy_test.go), where the
// resource is the ORGANIZATION root and no project-/env-/service-level
// grant can reach it. Here:
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     the read (ReasonAllowedByGrant), and at the wire receives the
//     project — the grant scope contains the resource scope.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, so the grant scope does not contain the
//     resource scope. The denial is ReasonDeniedOutOfScope (the
//     principal holds the capability somewhere, just not here).
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope.
//   - A service-level grant likewise does NOT cover a project resource
//     and does not expose the parent environment's secrets through
//     env.write either.
//   - An organization-level Viewer grant DOES cover any project
//     resource within the same org and — because project.read is
//     CapRead and Viewer holds CapRead — is allowed via
//     ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving:
//
//   - The project grantee on the TARGET project is allowed (reader
//     reached on the principal's home org id + path project id).
//   - The project grantee on a SIBLING project is denied (reader never
//     runs; body never echoes the canonical project).
//   - The env-scoped grantee on the parent project is denied.
//   - The service-scoped grantee on the parent project is denied.
//   - The org-level Viewer grantee is allowed end-to-end.
func TestGetProjectPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalGetProject(org)
	e := policy.NewEngine()

	// Project-level grant: admin on prj_matrix_alpha only.
	// Sibling-project containment is pinned both for project.update
	// (the grant has the relevant write capability at the relevant
	// scope) and for project.read (the action this story authorizes).
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_matrix_beta"}
	projectGrantee := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow {
		t.Errorf("update inside the granted project = %+v, want allow", got)
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow {
		t.Errorf("update a sibling project = %+v, want deny — a project grant must not reach prj_matrix_beta", got)
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.read) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProd := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
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
	// project.read against the PARENT project is out of scope for an
	// env-scoped grantee: covers() is one-way, so a scope that names a
	// deeper environment cannot reach the shallower project resource.
	if got := e.Decide(envGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for an environment-scoped grantee = %+v, want deny via %q — an env grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service only. The grant
	// must not expose parent-level secrets (env.write on the parent
	// environment), must not reach a sibling service, and must not
	// allow project.read on the parent project.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
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
	if got := e.Decide(svcGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) for a service-scoped grantee = %+v, want deny via %q — a service grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped grantee hitting the TARGET
	// project is a 200 with the canonical project, the reader is
	// reached with (home_org, target_project_id), and the response
	// carries every field of the projectResource.
	var targetGotOrg, targetGotProj string
	targetReader := fakeProjectReader{
		project:         project,
		gotGetOrgID:     &targetGotOrg,
		gotGetProjectID: &targetGotProj,
	}
	targetHandler := listProjectsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, targetReader)
	targetRec := getProjectByID(targetHandler, project.ID, "yk_proj_scoped")
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetGotOrg != org {
		t.Errorf("reader received org id %q, want the principal's home org %q",
			targetGotOrg, org)
	}
	if targetGotProj != project.ID {
		t.Errorf("reader received project id %q, want the path parameter %q",
			targetGotProj, project.ID)
	}
	targetEnv := decodeGetProject(t, targetRec)
	if targetEnv.Data.Project.ProjectID != project.ID ||
		targetEnv.Data.Project.Slug != project.Slug ||
		targetEnv.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			targetEnv.Data.Project, project.ID, project.Slug, org)
	}

	// Wire tie-in #2: the SAME project-scoped grantee hitting a SIBLING
	// project is a 403 with the stable out-of-scope reason, the reader
	// is never reached (so a production store could never have
	// surfaced the row in the background), and the body never echoes
	// the canonical project's identifiers. This is the property that
	// makes the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied access to a sibling
	// project.
	var siblingGotOrg, siblingGotProj string
	siblingReader := fakeProjectReader{
		project:         project, // would be returned if reader ran — leak guard catches it
		gotGetOrgID:     &siblingGotOrg,
		gotGetProjectID: &siblingGotProj,
	}
	siblingHandler := listProjectsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, siblingReader)
	siblingRec := getProjectByID(siblingHandler, "prj_matrix_beta", "yk_proj_scoped")
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingGotOrg != "" || siblingGotProj != "" {
		t.Errorf("reader was reached with org=%q project=%q for an out-of-scope grantee; it must never run",
			siblingGotOrg, siblingGotProj)
	}
	if body := siblingRec.Body.String(); getProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project's identifiers: %s", body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the reader is
	// never reached. The leak guard catches an accidental render of
	// the canonical project even though the env grantee never had
	// project-read coverage at all.
	var envGotOrg, envGotProj string
	envReader := fakeProjectReader{
		project:         project,
		gotGetOrgID:     &envGotOrg,
		gotGetProjectID: &envGotProj,
	}
	envHandler := listProjectsHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getProjectByID(envHandler, project.ID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envGotOrg != "" || envGotProj != "" {
		t.Errorf("reader was reached with org=%q project=%q for an env-scoped grantee; it must never run",
			envGotOrg, envGotProj)
	}
	if body := envRec.Body.String(); getProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project's identifiers: %s", body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the reader is never reached, and the body
	// never echoes parent-level identifiers. This is the property that
	// keeps a service-scoped key from escalating to a parent-project
	// read through this endpoint.
	var svcGotOrg, svcGotProj string
	svcReader := fakeProjectReader{
		project:         project,
		gotGetOrgID:     &svcGotOrg,
		gotGetProjectID: &svcGotProj,
	}
	svcHandler := listProjectsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getProjectByID(svcHandler, project.ID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcGotOrg != "" || svcGotProj != "" {
		t.Errorf("reader was reached with org=%q project=%q for a service-scoped grantee; it must never run",
			svcGotOrg, svcGotProj)
	}
	if body := svcRec.Body.String(); getProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project's identifiers: %s", body)
	}

	// An organization-level Viewer grant DOES cover any project
	// resource in the same org and — because project.read is CapRead
	// and Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the reader
	// reached on the principal's home org id and the path project id.
	// This locks the CapRead requirement against the grant path so a
	// future catalog change that upgraded project.read above CapRead
	// would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotProj string
	orgReader := fakeProjectReader{
		project:         project,
		gotGetOrgID:     &orgGotOrg,
		gotGetProjectID: &orgGotProj,
	}
	orgHandler := listProjectsHandlerFor(
		auth.Identity{Principal: orgViewer, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getProjectByID(orgHandler, project.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeGetProject(t, allowedRec)
	if allowedPayload.Data.Project.ProjectID != project.ID ||
		allowedPayload.Data.Project.Slug != project.Slug ||
		allowedPayload.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			allowedPayload.Data.Project, project.ID, project.Slug, org)
	}
	if orgGotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, org)
	}
	if orgGotProj != project.ID {
		t.Errorf("reader received project id %q, want the path parameter %q",
			orgGotProj, project.ID)
	}

	// And the same project-scoped grantee whose home org id is foreign
	// is denied at the engine: a grant for prj_matrix_alpha inside
	// org_acme, carried by a principal whose home org id is
	// org_sibling, cannot be used to read prj_matrix_alpha in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in TestGetProjectPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (project.read IS inside the support cross-tenant
	// exception, but the principal here is a service account with no
	// CapSupport role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(project.read) for a project-scoped key planted in a foreign org = %+v, want deny",
			got)
	}
}
