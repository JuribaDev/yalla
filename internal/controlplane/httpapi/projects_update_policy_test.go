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

// Policy-matrix coverage for PATCH /v1/projects/{project_id} (BE-0129).
// Where projects_update_test.go proves the endpoint's wire contract
// (BE-0127), this file proves its authorization contract: that action
// project.update cannot be bypassed by — or persist a mutation because
// of — the principal's role, revoked credentials, home organization,
// or scoped grants.
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
//     project-level, so a project-level grant naming THIS project CAN
//     authorize the patch while a project-level grant naming a SIBLING
//     project cannot.
//   - The handler still derives the organization id on the store input
//     from the PRINCIPAL'S home org (never the caller), so a
//     cross-tenant project_id reaches the tenant-scoped repository
//     query with the principal's home org id and is rejected as a
//     deterministic 404 NotFound at the persistence layer. A
//     cross-tenant project_id can never mutate another organization's
//     project, and the wire body must never echo the foreign org id
//     even though no wire input could place it there.
//
// project.update requires CapWrite (catalog.go: ActionProjectUpdate ->
// CapWrite), the same capability class as project.create / env.write /
// environment.create / service.create. The role matrix for a principal
// acting on its own organization therefore splits along the write
// capability class: Owner / Admin / Developer hold CapWrite and are
// allowed (ReasonAllowedByRole); Viewer / CI / Support do not hold
// CapWrite and are denied (ReasonDeniedNoCapability) — CI holds
// CapDeploy (the deploy capability is for service lifecycle and
// rollouts, not desired-state mutation), so a CI key cannot rename a
// project even within its home tenant. This is the load-bearing
// distinction from the project.read matrix
// (projects_get_policy_test.go), which is "all six roles allow":
// three roles deny here at the role boundary, and — crucially — the
// engine's cross-tenant support exception is gated on `required ==
// CapRead || required == CapSupport`, so CapWrite is OUTSIDE that
// exception.
// Privileged Yalla support that needs to mutate a customer's project
// must go through explicit break-glass admin tooling, not this
// customer-facing route. Pinning the support-cross-tenant DENY at the
// engine here means a future {org_id}-scoped variant inherits a
// working cross-tenant deny for project.update.
//
// projects rows store no secrets, so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.write). Tenant-leakage
// and no-write invariants still apply: a denied response never echoes
// the caller-supplied request-body fields, the seeded resource ids /
// slug / display name, or the foreign tenant's id; and the updater
// MUST never run on any deny path — a scoped key denied on the wire
// cannot have mutated a row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// updateProjectHandlerFor, patchProject, decodeUpdateProject,
// fakeProjectUpdater, orgPrincipal, seedProject, projectResource, and
// decodeError are shared with the projects-update contract suite
// (projects_update_test.go) and the wider httpapi test fixtures; this
// file adds no scaffolding beyond the small fixture builders below.

// canonicalUpdateProject is the row every test in this file would
// receive back from the updater on an allow path. Centralising it
// lets a future regression that reorders, renames, or recategorises a
// projectResource field fail in exactly one place. The distinctive
// id / slug / display name are deliberately recognisable so deny-path
// leak guards can needle for them; allow-path assertions compare
// against the same canonical values.
func canonicalUpdateProject(orgID string) store.Project {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return seedProject("prj_matrix_alpha", orgID, "matrix-alpha", "Matrix Alpha v2", 9, created, updated)
}

// canonicalUpdateProjectBody is the canonical PATCH request body every
// test in this file shares. It mutates display_name only (single
// non-nil patch field), which is the minimum input the store layer
// accepts ("a patch that names no field is a 400") and the simplest
// shape to exercise wire-level redaction. The distinctive display
// name "Matrix Alpha Patched" is deliberately recognisable so
// deny-path leak guards can needle for it independently of the
// canonical row.
const (
	canonicalPatchDisplayName = "Matrix Alpha Patched"
	canonicalPatchBody        = `{"display_name":"Matrix Alpha Patched"}`
)

// updateProjectDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project, the
// canonical updated row, or the caller-supplied request-body fields.
// A denied response that accidentally rendered any of these fails the
// test — a denied request_body field would mean the handler echoed
// the request after policy denial (a tenant boundary smell), and a
// denied canonical-row field would mean the updater ran and the
// response leaked its output even though the wire said 403. The
// quoted forms catch a case-collapsing renderer regression.
func updateProjectDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_matrix_alpha",
		"\"matrix-alpha\"",
		"\"Matrix Alpha v2\"",
		"\"" + canonicalPatchDisplayName + "\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestUpdateProjectPolicyMatrixRoles drives every built-in role
// through the production request path. CapWrite splits the matrix:
// Owner / Admin / Developer (own org) are allowed; Viewer / CI /
// Support (own org) are denied. The assertions that matter for allow
// rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the updater is reached with the principal's
// own home organization id, the {project_id} path parameter, AND the
// principal id (so the audit record names the actor verbatim), and
// the response is a stable 200 yalla.output.v1 carrying the canonical
// updated project. For deny rows, the assertions are 403
// yalla.error.v1, the stable reason on the wire, the updater MUST
// NEVER run (no row mutated in the background), and the denied body
// must not echo the canonical project or the caller-supplied
// request-body fields.
func TestUpdateProjectPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalUpdateProject(org)
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
		{"developer", policy.RoleDeveloper, domain.KindUser, true, policy.ReasonAllowedByRole},
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
			// ReasonDeniedNoCapability because Viewer / Support hold
			// CapRead but not CapWrite. (The cross-tenant Support
			// deny is pinned separately in
			// TestUpdateProjectPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectUpdate, projectResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.update) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.update) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.UpdateProjectInput
			updater := fakeProjectUpdater{
				project: project,
				got:     &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := updateProjectHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, updater)
			rec := patchProject(handler, project.ID, "a-valid-token", canonicalPatchBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("updater received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ProjectID != project.ID {
					t.Errorf("updater received project id %q, want the path parameter %q",
						captured.ProjectID, project.ID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("updater received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.DisplayName == nil || *captured.DisplayName != canonicalPatchDisplayName {
					t.Errorf("updater received display_name = %v, want %q",
						captured.DisplayName, canonicalPatchDisplayName)
				}
				env := decodeUpdateProject(t, rec)
				if env.Data.Project.ProjectID != project.ID ||
					env.Data.Project.Slug != project.Slug ||
					env.Data.Project.DisplayName != project.DisplayName ||
					env.Data.Project.OrganizationID != org ||
					env.Data.Project.Version != project.Version {
					t.Errorf("project = %+v, want (%s, %s, %s, org=%s, v=%d)",
						env.Data.Project, project.ID, project.Slug, project.DisplayName, org, project.Version)
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
			if captured.OrganizationID != "" || captured.ProjectID != "" {
				t.Errorf("updater was reached with org=%q project=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ProjectID)
			}
			if body := rec.Body.String(); updateProjectDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical project or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestUpdateProjectPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action project.update with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to mutate a
// project of the organization it once had access to, the updater
// must never run, and the denied body must never echo the principal
// id, the organization id, the path-supplied project id, the
// caller-supplied request-body fields, or any seeded project data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.update; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0129 ("revoked key,
// expired key").
func TestUpdateProjectPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalUpdateProject(org)

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

			var captured store.UpdateProjectInput
			updater := fakeProjectUpdater{
				project: project,
				got:     &captured,
			}
			handler := updateProjectHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, updater)
			rec := patchProject(handler, project.ID, "yk_no_longer_valid", canonicalPatchBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.ProjectID != "" {
				t.Errorf("updater was reached with org=%q project=%q for a disabled principal; it must never run",
					captured.OrganizationID, captured.ProjectID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				updateProjectDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, request body, or seeded project data", body)
			}
		})
	}
}

// TestUpdateProjectPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for project.update. As with project.read,
// the resource org id is taken from the PRINCIPAL'S home org — the
// {project_id} path parameter alone never widens the resource to
// another tenant. Tenant isolation on the wire is therefore
// structural at the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PATCH
//     /v1/projects/{prj_victim} with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, prj_victim})
//     — allowed by the role at CapWrite — and then reaches the
//     tenant-scoped repository query with the principal's home org id
//     and the foreign project id. A production repository (which
//     combines organization_id and id in its WHERE clause) cannot
//     match a row that belongs to another tenant, so the request
//     surfaces as a deterministic 404 E_NOT_FOUND. The body must
//     never echo the foreign org id even though no wire input could
//     place it there, because the persistence layer must not leak
//     foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the project.read cross-tenant
//     property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but update DOES NOT. Pinning that
//     engine verdict here means the eventual scoped variant inherits
//     a working cross-tenant deny for project.update across every
//     role, and a future catalog change that downgraded
//     project.update into the support cross-tenant exception (or
//     widened the exception) would fail here before it could regress
//     a real customer.
func TestUpdateProjectPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_alpha"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PATCH
	// /v1/projects/{prj_victim} with a valid Owner token. The fake
	// mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, projectID) pair does not match a
	// row, so a principal whose home org is org_attacker patching a
	// project that belongs to org_victim hits the fake with
	// (org_attacker, prj_victim_alpha) and gets NotFound. The
	// assertions that matter are structural: the updater is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectUpdater could not have mutated the victim's project
	// regardless of database state. The denied body must never echo
	// the victim's org id.
	var captured store.UpdateProjectInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	updater := fakeProjectUpdater{
		err: apierr.NotFound("project", foreignProjID),
		got: &captured,
	}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, updater)
	rec := patchProject(handler, foreignProjID, "a-valid-token", canonicalPatchBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("updater received org id %q, want the attacker's home org %q — the updater must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ProjectID != foreignProjID {
		t.Errorf("updater received project id %q, want the path parameter %q",
			captured.ProjectID, foreignProjID)
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
	// scope inherits a working cross-tenant deny. project.update is
	// CapWrite, which is OUTSIDE the engine clause `CapSupport &&
	// (CapRead || CapSupport)` — so EVERY role, including Support,
	// is denied cross-tenant.
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
			got := e.Decide(p, policy.ActionProjectUpdate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.update, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestUpdateProjectPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped
// API key is authorized purely by its grants (it carries no
// organization role); the engine confines those grants — a project
// grant does not reach a sibling project, an environment grant does
// not reach the parent project, a service grant does not reach the
// parent environment or a sibling service.
//
// Crucially for PATCH /v1/projects/{project_id}: project.update is
// evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}). This is the load-bearing
// distinction from the project.create matrix
// (projects_create_policy_test.go), where the resource is the
// ORGANIZATION root and no project-/env-/service-level grant can
// reach it. Here:
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     the update (ReasonAllowedByGrant), and at the wire the updater
//     receives (home_org, target_project_id, principal id) — the
//     grant scope contains the resource scope.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, so the grant scope does not contain the
//     resource scope. The denial is ReasonDeniedOutOfScope (the
//     principal holds the capability somewhere, just not here).
//   - A project-level VIEWER grant naming THIS project does not hold
//     CapWrite and is denied via ReasonDeniedNoCapability — a viewer
//     grant confers no write capability even when its scope contains
//     the resource. This is the load-bearing distinction from the
//     project.read grant matrix, where an org-level Viewer grant is
//     allowed.
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope.
//   - A service-level grant likewise does NOT cover a project
//     resource and does not expose the parent environment's secrets
//     through env.write either.
//   - An organization-level Admin grant DOES cover any project
//     resource within the same org and — because project.update is
//     CapWrite and Admin holds CapWrite — is allowed via
//     ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, viewer-grant
// no-capability — are pinned against the engine, then tied back to
// the wire by proving the updater is never reached on any deny path
// (so a production store could not have mutated a row in the
// background) and the denied body never echoes the canonical
// project, the canonical patch body, or the seeded row identifiers.
func TestUpdateProjectPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalUpdateProject(org)
	e := policy.NewEngine()

	// Project-level grant: admin on prj_matrix_alpha only.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_matrix_beta"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.update) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.update) for a sibling project = %+v, want deny via %q — a project-scoped admin grant must not reach prj_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. project.update on the same project resource must
	// fail with ReasonDeniedNoCapability — a viewer grant does not
	// widen to a write action even when its scope contains the
	// resource. This is the property a future "grant role enum
	// re-mapping" regression would catch here.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.update) for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment
	// only; the parent project is shallower than the grant scope, so
	// covers() does not reach it. project.update on the parent
	// project must fail with ReasonDeniedOutOfScope.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.update) for an environment-scoped grantee = %+v, want deny via %q — an env grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow project.update on the parent
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
	if got := e.Decide(svcGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.update) for a service-scoped grantee = %+v, want deny via %q — a service grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// TARGET project is a 200 with the canonical updated project, the
	// updater is reached with (home_org, target_project_id,
	// principal id, decoded display_name patch), and the response
	// carries the canonical row unchanged.
	var targetCaptured store.UpdateProjectInput
	targetUpdater := fakeProjectUpdater{
		project: project,
		got:     &targetCaptured,
	}
	targetHandler := updateProjectHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, targetUpdater)
	targetRec := patchProject(targetHandler, project.ID, "yk_proj_scoped", canonicalPatchBody)
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped admin key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCaptured.OrganizationID != org {
		t.Errorf("updater received org id %q, want the principal's home org %q",
			targetCaptured.OrganizationID, org)
	}
	if targetCaptured.ProjectID != project.ID {
		t.Errorf("updater received project id %q, want the path parameter %q",
			targetCaptured.ProjectID, project.ID)
	}
	if targetCaptured.ActorID != projectAdminGrantee.ID {
		t.Errorf("updater received actor id %q, want the principal id %q",
			targetCaptured.ActorID, projectAdminGrantee.ID)
	}
	targetEnv := decodeUpdateProject(t, targetRec)
	if targetEnv.Data.Project.ProjectID != project.ID ||
		targetEnv.Data.Project.Slug != project.Slug ||
		targetEnv.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			targetEnv.Data.Project, project.ID, project.Slug, org)
	}

	// Wire tie-in #2: the SAME project-scoped admin grantee hitting
	// a SIBLING project is a 403 with the stable out-of-scope
	// reason, the updater is never reached (so a production store
	// could never have mutated a row in the background), and the
	// body never echoes the canonical project's identifiers or the
	// caller-supplied patch body. This is the property that makes
	// the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied access to a sibling
	// project.
	var siblingCaptured store.UpdateProjectInput
	siblingUpdater := fakeProjectUpdater{
		project: project, // would be returned if updater ran — leak guard catches it
		got:     &siblingCaptured,
	}
	siblingHandler := updateProjectHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, siblingUpdater)
	siblingRec := patchProject(siblingHandler, "prj_matrix_beta", "yk_proj_scoped", canonicalPatchBody)
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingCaptured.OrganizationID != "" || siblingCaptured.ProjectID != "" {
		t.Errorf("updater was reached with org=%q project=%q for an out-of-scope grantee; it must never run",
			siblingCaptured.OrganizationID, siblingCaptured.ProjectID)
	}
	if body := siblingRec.Body.String(); updateProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or caller-supplied request body: %s", body)
	}

	// Wire tie-in #3: the project-scoped VIEWER grantee hitting the
	// SAME project is a 403 with ReasonDeniedNoCapability (the grant
	// covers the resource, but the role does not hold CapWrite). The
	// updater is never reached and the body never echoes the
	// canonical project or the caller-supplied patch body.
	var viewerCaptured store.UpdateProjectInput
	viewerUpdater := fakeProjectUpdater{
		project: project,
		got:     &viewerCaptured,
	}
	viewerHandler := updateProjectHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, viewerUpdater)
	viewerRec := patchProject(viewerHandler, project.ID, "yk_proj_viewer", canonicalPatchBody)
	if viewerRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped viewer key on its target project; body %s",
			viewerRec.Code, viewerRec.Body.String())
	}
	viewerDenyEnv := decodeError(t, viewerRec, "E_FORBIDDEN")
	if !strings.Contains(viewerDenyEnv.Error.Message, string(policy.ReasonDeniedNoCapability)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			viewerDenyEnv.Error.Message, policy.ReasonDeniedNoCapability)
	}
	if viewerCaptured.OrganizationID != "" || viewerCaptured.ProjectID != "" {
		t.Errorf("updater was reached with org=%q project=%q for a viewer-grant principal; it must never run",
			viewerCaptured.OrganizationID, viewerCaptured.ProjectID)
	}
	if body := viewerRec.Body.String(); updateProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or caller-supplied request body: %s", body)
	}

	// Wire tie-in #4: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the updater
	// is never reached. The leak guard catches an accidental render
	// of the canonical project even though the env grantee never
	// had project-write coverage at all.
	var envCaptured store.UpdateProjectInput
	envUpdater := fakeProjectUpdater{
		project: project,
		got:     &envCaptured,
	}
	envHandler := updateProjectHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envUpdater)
	envRec := patchProject(envHandler, project.ID, "yk_env_scoped", canonicalPatchBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCaptured.OrganizationID != "" || envCaptured.ProjectID != "" {
		t.Errorf("updater was reached with org=%q project=%q for an env-scoped grantee; it must never run",
			envCaptured.OrganizationID, envCaptured.ProjectID)
	}
	if body := envRec.Body.String(); updateProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or caller-supplied request body: %s", body)
	}

	// Wire tie-in #5: the service-scoped grantee hitting the parent
	// project is a 403, the updater is never reached, and the body
	// never echoes parent-level identifiers. This is the property
	// that keeps a service-scoped key from escalating to a
	// parent-project mutation through this endpoint.
	var svcCaptured store.UpdateProjectInput
	svcUpdater := fakeProjectUpdater{
		project: project,
		got:     &svcCaptured,
	}
	svcHandler := updateProjectHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcUpdater)
	svcRec := patchProject(svcHandler, project.ID, "yk_svc_scoped", canonicalPatchBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.ProjectID != "" {
		t.Errorf("updater was reached with org=%q project=%q for a service-scoped grantee; it must never run",
			svcCaptured.OrganizationID, svcCaptured.ProjectID)
	}
	if body := svcRec.Body.String(); updateProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project or caller-supplied request body: %s", body)
	}

	// An organization-level Admin grant DOES cover any project
	// resource in the same org and — because project.update is
	// CapWrite and Admin holds CapWrite — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at
	// the wire, with the updater reached on the principal's home
	// org id and the path project id. This locks the CapWrite
	// requirement against the grant path so a future catalog change
	// that upgraded project.update above CapWrite would fail here
	// (silently denying every org-level Admin grantee) before it
	// could regress a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.update) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.UpdateProjectInput
	orgUpdater := fakeProjectUpdater{
		project: project,
		got:     &orgCaptured,
	}
	orgHandler := updateProjectHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgUpdater)
	allowedRec := patchProject(orgHandler, project.ID, "yk_org_admin", canonicalPatchBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeUpdateProject(t, allowedRec)
	if allowedPayload.Data.Project.ProjectID != project.ID ||
		allowedPayload.Data.Project.Slug != project.Slug ||
		allowedPayload.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			allowedPayload.Data.Project, project.ID, project.Slug, org)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("updater received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ProjectID != project.ID {
		t.Errorf("updater received project id %q, want the path parameter %q",
			orgCaptured.ProjectID, project.ID)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; project.update must be denied via
	// ReasonDeniedNoCapability even though the grant scope is the
	// whole org. This is the load-bearing distinction from the
	// project.read grant matrix: an org-level Viewer is ALLOWED for
	// read but DENIED for update.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.update) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id
	// is foreign is denied at the engine: a grant for
	// prj_matrix_alpha inside org_acme, carried by a principal whose
	// home org id is org_sibling, cannot be used to update
	// prj_matrix_alpha in org_sibling — the cross-tenant guard fires
	// first because the principal's home org no longer matches the
	// grant's scope. This is the engine-level twin of the wire-level
	// "wrong organization" property in
	// TestUpdateProjectPolicyWrongOrganizationPrincipal, applied to
	// a scoped key: stealing a key cannot smuggle it across tenants.
	// project.update is OUTSIDE the support cross-tenant exception
	// regardless, but the assertion here is structural: a scoped
	// key's home org must match the grant scope's org or the engine
	// refuses to consider the grant at all.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectUpdate, siblingOrgResource); got.Allow {
		t.Errorf("Decide(project.update) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
