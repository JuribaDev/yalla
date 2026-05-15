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

// Policy-matrix coverage for GET /v1/projects/{project_id}/environments
// (BE-0150). Where project_environments_test.go proves the endpoint's
// wire contract (BE-0148), this file proves its authorization contract:
// that action environment.read cannot be bypassed by — or leak a
// project's environments because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the projectIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and
// the {project_id} PATH parameter. RequireAuth therefore authorizes
// against the project the path names — not merely the principal's
// home organization — and the resource Kind is the project, not the
// environment list. This is the same projectIDResolver-bound posture
// that BE-0138 (projects_grants_policy_test.go), BE-0141
// (projects_grants_put_policy_test.go), and BE-0144
// (projects_variables_get_policy_test.go) lock in: a scoped grant
// for THIS project authorizes the read while a sibling-project grant
// is rejected at the boundary, and the handler still derives the
// organization id on the store input from the PRINCIPAL'S home org
// (never the caller — there is no request body for a list at all),
// so a cross-tenant project_id reaches the tenant-scoped repository
// query with the principal's home org id and is rejected as a
// deterministic 404 NotFound at the persistence layer by the reader's
// project existence check. A cross-tenant project_id can never reveal
// another organization's environments, and the wire body must never
// echo the foreign org id even though no wire input could place it
// there.
//
// environment.read requires CapRead (catalog.go: ActionEnvironmentRead
// -> CapRead), the same capability class as project.read,
// project.grants.read, environment.grants.read, service.read,
// limits.read, usage.read, and env.read. All six built-in roles hold
// CapRead, so the role matrix for a principal listing environments in
// its own organization is "all allow"; the assertions that matter are
// that the verdict is reached through the role (ReasonAllowedByRole),
// the reader is called with the principal's own home organization id
// AND the {project_id} path parameter (so the tenant-scoped repository
// query cannot match environments of a project in another tenant), and
// the response carries the canonical environment list in a stable
// yalla.output.v1 envelope.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing environment.read against a foreign-tenant
// resource IS allowed via ReasonAllowedBySupport — the same property
// project.read / project.grants.read / env.read / limits.read /
// usage.read carry. Every non-support role is denied with
// ReasonDeniedCrossTenant. The customer-facing route under test cannot
// reach that engine branch by construction (projectIDResolver pins the
// resource scope to the PRINCIPAL'S home org, not the path's tenant),
// but pinning the engine verdict here means a future endpoint that
// resolves the resource into a foreign-org scope (a hypothetical admin
// tool) inherits a working cross-tenant deny and the documented support
// exception, and a future catalog change that upgraded environment.read
// above CapRead would fail here (silently denying every support
// cross-tenant environment read) before it could regress a real
// customer.
//
// Unlike project_variables rows (which carry secret values), the
// environments table carries NO credential material — only structural
// identifiers, a slug, a display name, an optimistic-concurrency
// version, and lifecycle timestamps. The projectEnvironmentOf
// projection has no value-redaction chokepoint to anchor a deny-path
// leak guard on; the load-bearing needle is the existence of the
// environment row itself (and the slug / display name a denied
// principal must not learn). Tenant-leakage and no-read invariants
// apply: a denied response never echoes any seeded environment id /
// slug / display name, the foreign tenant's id, or the canonical
// project's slug / display name; and the reader MUST never run on
// any deny path — a scoped key denied on the wire cannot have
// surfaced an environment row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, projectIDResolver, or the engine fails here.
// listProjectEnvironmentsHandlerFor, getProjectEnvironments,
// decodeListProjectEnvironments, seedEnvironmentWire,
// fakeProjectEnvironmentReader, orgPrincipal, seedProject, and
// decodeError are shared with the project-environments contract suite
// (project_environments_test.go) and the wider httpapi test fixtures;
// this file adds no scaffolding beyond the small fixture builders
// below.

// canonicalEnvironmentsProject is the project every test in this file
// resolves the {project_id} path parameter to. Its id, slug, and
// display name are deliberately distinct from canonicalGrantsProject
// (used by projects_grants_policy_test.go) and canonicalVariablesProject
// (used by projects_variables_get_policy_test.go) so the matrices
// cannot accidentally share fixture state through a future shared
// fake, and they are deliberately recognisable so deny-path leak
// guards can needle for them; allow-path assertions compare against
// the same canonical values.
func canonicalEnvironmentsProject(orgID string) store.Project {
	created := time.Date(2026, 2, 7, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 11, 12, 13, 0, time.UTC)
	return seedProject("prj_envs_matrix_alpha", orgID, "envs-matrix-alpha", "Envs Matrix Alpha", 23, created, updated)
}

// canonicalProjectEnvironments is the environment list every test in
// this file would receive back from the reader on an allow path. It
// carries two environments — production and staging — so the wire
// projection exercises a multi-row response, and the canonical ids /
// slugs / display names are distinctive enough that an accidental
// render on a deny path can be needled by environmentsDenyBodyLeak.
func canonicalProjectEnvironments(orgID, projectID string) []store.Environment {
	created := time.Date(2026, 2, 7, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return []store.Environment{
		seedEnvironmentWire("env_matrix_prod", orgID, projectID, "production-matrix", "Production Matrix", 7, created, updated),
		seedEnvironmentWire("env_matrix_stage", orgID, projectID, "staging-matrix", "Staging Matrix", 2, created, created),
	}
}

// environmentsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project or its
// environments. A denied response that accidentally rendered any of
// these fails the test: the environment row's existence (and the slug
// / display name it names) is itself information a denied principal
// must not receive. The quoted forms catch a case-collapsing renderer
// regression. There is no request body for GET
// /v1/projects/{project_id}/environments, so unlike a write-path leak
// guard there is no caller-supplied request-body field to protect; and
// unlike the project_variables matrix there is no secret plaintext to
// anchor — the environments table carries no credential material at
// all.
func environmentsDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_envs_matrix_alpha",
		"\"envs-matrix-alpha\"",
		"\"Envs Matrix Alpha\"",
		"env_matrix_prod",
		"env_matrix_stage",
		"\"production-matrix\"",
		"\"staging-matrix\"",
		"\"Production Matrix\"",
		"\"Staging Matrix\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListProjectEnvironmentsPolicyMatrixRoles drives every built-in
// role through the production request path. All six built-in roles
// hold CapRead, so the matrix is "all allow" for a principal listing
// environments of a project in its own organization; the assertions
// that matter are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {project_id} path parameter (so a
// tenant-scoped store query cannot match a foreign row), and the
// response is a stable 200 yalla.output.v1 envelope carrying the
// canonical environment list.
func TestListProjectEnvironmentsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envs := canonicalProjectEnvironments(org, project.ID)
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
			// listing environments in ITS OWN organization is allowed
			// via ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support cross-tenant exception
			// is exercised in
			// TestListProjectEnvironmentsPolicyWrongOrganizationPrincipal.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentRead, projectResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(environment.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotProj string
			callCount := 0
			reader := fakeProjectEnvironmentReader{
				envs:         envs,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listProjectEnvironmentsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getProjectEnvironments(handler, project.ID, "a-valid-token")

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
			env := decodeListProjectEnvironments(t, rec)
			if len(env.Data.Environments) != len(envs) {
				t.Fatalf("environments len = %d, want %d; body %s",
					len(env.Data.Environments), len(envs), rec.Body.String())
			}
			// Spot-check the projection lands the load-bearing fields
			// of both rows. The slug, display name, organization id,
			// project id, and version must all project verbatim — a
			// regression in projectEnvironmentOf that dropped or
			// reshuffled a field would fail here.
			got0 := env.Data.Environments[0]
			if got0.ID != "env_matrix_prod" || got0.Slug != "production-matrix" || got0.DisplayName != "Production Matrix" {
				t.Errorf("got[0] = %+v, want (env_matrix_prod, production-matrix, Production Matrix)", got0)
			}
			if got0.OrganizationID != org || got0.ProjectID != project.ID {
				t.Errorf("got[0] org/proj = (%q, %q), want (%q, %q)",
					got0.OrganizationID, got0.ProjectID, org, project.ID)
			}
			if got0.Version != 7 {
				t.Errorf("got[0].Version = %d, want 7", got0.Version)
			}
			got1 := env.Data.Environments[1]
			if got1.ID != "env_matrix_stage" || got1.Slug != "staging-matrix" || got1.DisplayName != "Staging Matrix" {
				t.Errorf("got[1] = %+v, want (env_matrix_stage, staging-matrix, Staging Matrix)", got1)
			}
			if got1.Version != 2 {
				t.Errorf("got[1].Version = %d, want 2", got1.Version)
			}
		})
	}
}

// TestListProjectEnvironmentsPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action environment.read with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to list
// environments of a project of the organization it once had access
// to, the reader must never run, and the denied body must never echo
// the principal id, the organization id, the path-supplied project
// id, or any seeded environment data.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0150 ("revoked key,
// expired key").
func TestListProjectEnvironmentsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envs := canonicalProjectEnvironments(org, project.ID)

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
			reader := fakeProjectEnvironmentReader{
				envs:         envs,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			handler := listProjectEnvironmentsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getProjectEnvironments(handler, project.ID, "yk_no_longer_valid")

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
				environmentsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded environment data", body)
			}
		})
	}
}

// TestListProjectEnvironmentsPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.read on the project
// environments route. As with project.read, project.grants.read, and
// env.read, the resource org id is taken from the PRINCIPAL'S home
// org — the {project_id} path parameter alone never widens the
// resource to another tenant. Tenant isolation on the wire is
// therefore structural at the persistence layer, not the policy
// boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/projects/{prj_victim}/environments with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapRead — and then
//     reaches the tenant-scoped repository query with the principal's
//     home org id and the foreign project id. The store-backed reader
//     Gets the project under (organization_id, project_id) before
//     listing its environments, so a cross-tenant project_id is
//     rejected as a deterministic 404 E_NOT_FOUND, never disguised as
//     an empty success — which would invite an agent to believe the
//     project exists with no environments. The body must never echo
//     the foreign org id even though no wire input could place it
//     there, because the persistence layer must not leak foreign-tenant
//     identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). Pinning
//     that engine verdict here means the eventual scoped variant
//     inherits a working cross-tenant deny and the documented support
//     exception, and a future catalog change that upgraded
//     environment.read above CapRead would fail here (silently denying
//     every support cross-tenant environment read) before it could
//     regress a real customer.
func TestListProjectEnvironmentsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_envs"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/projects/{prj_victim}/environments with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, projectID) pair does not
	// match a row (the reader's project existence check fires first),
	// so a principal whose home org is org_attacker listing
	// environments of a project that belongs to org_victim hits the
	// fake with (org_attacker, prj_victim_envs) and gets NotFound. The
	// assertions that matter are structural: the reader is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectEnvironmentReader could not have surfaced the victim's
	// environments regardless of database state. The denied body must
	// never echo the victim's org id.
	var gotOrg, gotProj string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeProjectEnvironmentReader{
		err:          apierr.NotFound("project", foreignProjID),
		gotOrgID:     &gotOrg,
		gotProjectID: &gotProj,
		callCount:    &callCount,
	}
	handler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getProjectEnvironments(handler, foreignProjID, "a-valid-token")

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
	// scope inherits a working cross-tenant deny. environment.read is
	// CapRead, so the engine clause `CapSupport && (CapRead ||
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
	// customer-facing route under test cannot reach this engine branch
	// by construction — projectIDResolver pins the resource scope to
	// the principal's own home org — but the engine verdict is the
	// authoritative source of the documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvironmentRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(environment.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListProjectEnvironmentsPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for. A
// scoped API key is authorized purely by its grants (it carries no
// organization role); the engine confines those grants — a project
// grant does not reach a sibling project, an environment grant does
// not reach production unless production is explicitly granted, a
// service grant does not reach the parent environment or a sibling
// service.
//
// Crucially for GET /v1/projects/{project_id}/environments:
// environment.read is evaluated against a PROJECT-level resource (the
// projectIDResolver scope is {home_org, path_project_id}). This is
// the load-bearing distinction from a route that resolved into a
// deeper scope (an environment- or service-level route): here a
// project-level Viewer grant naming THIS project authorizes the read,
// but a deeper-scope grant cannot — covers() is one-way, so an env-
// or service-scoped grant does not contain the parent-project
// resource.
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
//     escalate to listing the parent project's environments (which
//     sit at the project layer of the Org → Project → Env → Service
//     hierarchy — a layer the env grantee was never authorized for).
//   - A service-level grant likewise does NOT cover a project
//     resource and does not expose the parent environment either —
//     the "service grant does not expose parent-level secrets or
//     unrelated services" property; here it pins that a
//     service-scoped key cannot escalate to listing the parent
//     project's environments through this endpoint, even if its own
//     service-level action would normally be authorized for the
//     service it names.
//   - An organization-level Viewer grant DOES cover any project
//     resource within the same org and — because environment.read is
//     CapRead and Viewer holds CapRead — is allowed via
//     ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, service grant
// shielding parent-level resources — are pinned against the engine,
// then tied back to the wire by proving the reader is never reached
// on any deny path (so a production store could not have surfaced
// environments in the background) and the denied body never echoes
// the canonical project's or environments' identifiers.
func TestListProjectEnvironmentsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envs := canonicalProjectEnvironments(org, project.ID)
	e := policy.NewEngine()

	// Project-level grant: viewer on prj_envs_matrix_alpha only.
	// Viewer confers CapRead at the project scope, which is exactly
	// what environment.read needs. The sibling-project property is
	// pinned for environment.read directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_envs_matrix_beta"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.read) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) for a sibling project = %+v, want deny via %q — a project-scoped viewer grant must not reach prj_envs_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant
	// scope, so covers() does not reach it for environment.read.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) for an environment-scoped grantee against the parent project = %+v, want deny via %q — an env grant must not reach the parent project's environment list",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(env.write) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow environment.read on the parent
	// project (which would expose the project-scoped environment list
	// this endpoint returns).
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
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) for a service-scoped grantee against the parent project = %+v, want deny via %q — a service grant must not reach the parent project's environment list",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// TARGET project is a 200 with the canonical environment list,
	// the reader is reached with (home_org, target_project_id), and
	// the response carries every environment — the project-scoped
	// Viewer grant confers exactly CapRead at the project scope.
	var targetGotOrg, targetGotProj string
	targetCallCount := 0
	targetReader := fakeProjectEnvironmentReader{
		envs:         envs,
		gotOrgID:     &targetGotOrg,
		gotProjectID: &targetGotProj,
		callCount:    &targetCallCount,
	}
	targetHandler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, targetReader)
	targetRec := getProjectEnvironments(targetHandler, project.ID, "yk_proj_viewer_scoped")
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
	targetEnv := decodeListProjectEnvironments(t, targetRec)
	if len(targetEnv.Data.Environments) != len(envs) {
		t.Errorf("environments len = %d, want %d", len(targetEnv.Data.Environments), len(envs))
	}

	// Wire tie-in #2: the SAME project-scoped Viewer grantee hitting
	// a SIBLING project is a 403 with the stable out-of-scope reason,
	// the reader is never reached (so a production store could never
	// have surfaced sibling environments in the background), and the
	// body never echoes the canonical project's or environments'
	// identifiers. This is the property that makes the policy
	// boundary — not the persistence boundary — the structural place
	// a scoped key is denied access to a sibling project's
	// environments.
	var siblingGotOrg, siblingGotProj string
	siblingCallCount := 0
	siblingReader := fakeProjectEnvironmentReader{
		envs:         envs, // would be returned if reader ran — leak guard catches it
		gotOrgID:     &siblingGotOrg,
		gotProjectID: &siblingGotProj,
		callCount:    &siblingCallCount,
	}
	siblingHandler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, siblingReader)
	siblingRec := getProjectEnvironments(siblingHandler, "prj_envs_matrix_beta", "yk_proj_viewer_scoped")
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
	if body := siblingRec.Body.String(); environmentsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or environment data: %s", body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the reader is
	// never reached. The leak guard catches an accidental render of
	// the canonical environments even though the env grantee never
	// had project-read coverage at all.
	var envGotOrg, envGotProj string
	envCallCount := 0
	envReader := fakeProjectEnvironmentReader{
		envs:         envs,
		gotOrgID:     &envGotOrg,
		gotProjectID: &envGotProj,
		callCount:    &envCallCount,
	}
	envHandler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getProjectEnvironments(envHandler, project.ID, "yk_env_scoped")
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
	if body := envRec.Body.String(); environmentsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or environment data: %s", body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the reader is never reached, and the body
	// never echoes parent-level identifiers. This is the property
	// that keeps a service-scoped key from escalating to a
	// parent-project environment read through this endpoint — the
	// "service grant does not expose parent-level secrets or
	// unrelated services" acceptance criterion tied back to the wire
	// on the environments route.
	var svcGotOrg, svcGotProj string
	svcCallCount := 0
	svcReader := fakeProjectEnvironmentReader{
		envs:         envs,
		gotOrgID:     &svcGotOrg,
		gotProjectID: &svcGotProj,
		callCount:    &svcCallCount,
	}
	svcHandler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getProjectEnvironments(svcHandler, project.ID, "yk_svc_scoped")
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
	if body := svcRec.Body.String(); environmentsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or environment data: %s", body)
	}

	// An organization-level Viewer grant DOES cover any project
	// resource in the same org and — because environment.read is
	// CapRead and Viewer holds CapRead — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at the
	// wire, with the reader reached on the principal's home org id
	// and the path project id. This locks the CapRead requirement
	// against the grant path so a future catalog change that upgraded
	// environment.read above CapRead would fail here (silently
	// denying every org-level Viewer grantee) before it could regress
	// a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotProj string
	orgCallCount := 0
	orgReader := fakeProjectEnvironmentReader{
		envs:         envs,
		gotOrgID:     &orgGotOrg,
		gotProjectID: &orgGotProj,
		callCount:    &orgCallCount,
	}
	orgHandler := listProjectEnvironmentsHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getProjectEnvironments(orgHandler, project.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeListProjectEnvironments(t, allowedRec)
	if len(allowedPayload.Data.Environments) != len(envs) {
		t.Errorf("environments len = %d, want %d", len(allowedPayload.Data.Environments), len(envs))
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
	// prj_envs_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to list
	// environments of prj_envs_matrix_alpha in org_sibling — the
	// cross-tenant guard fires first because the principal's home
	// org no longer matches the grant's scope. This is the
	// engine-level twin of the wire-level "wrong organization"
	// property in TestListProjectEnvironmentsPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (environment.read IS inside the support
	// cross-tenant exception, but the principal here is a service
	// account with no CapSupport role, so the exception does not
	// apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
