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

// Policy-matrix coverage for POST /v1/projects/{project_id}/restore (BE-0135).
// Where projects_restore_test.go proves the endpoint's wire contract
// (BE-0133), this file proves its authorization contract: that action
// project.restore cannot be bypassed by — or revive a soft-deleted
// project because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
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
//     authorize the restore while a project-level grant naming a SIBLING
//     project cannot.
//   - The handler still derives the organization id on the store input
//     from the PRINCIPAL'S home org (never the caller — there is no
//     request body for restore at all), so a cross-tenant project_id
//     reaches the tenant-scoped repository query with the principal's
//     home org id and is rejected as a deterministic 404 NotFound at the
//     persistence layer. A cross-tenant project_id can never revive
//     another organization's soft-deleted project, and the wire body
//     must never echo the foreign org id even though no wire input could
//     place it there.
//
// project.restore requires CapWrite (catalog.go: ActionProjectRestore ->
// CapWrite), the same capability class as project.create, project.update,
// project.delete, environment.create, env.write, and service.create. The
// role matrix for a principal acting on its own organization therefore
// splits along the write capability class: Owner / Admin / Developer hold
// CapWrite and are allowed (ReasonAllowedByRole); Viewer / CI / Support
// do not hold CapWrite and are denied (ReasonDeniedNoCapability) — CI
// holds CapDeploy (the deploy capability is for service lifecycle and
// rollouts, not desired-state mutation), so a CI key cannot revive a
// project even within its home tenant. This is the load-bearing
// distinction from the project.read matrix (projects_get_policy_test.go),
// which is "all six roles allow": three roles deny here at the role
// boundary, and — crucially — the engine's cross-tenant support
// exception is gated on `required == CapRead || required == CapSupport`,
// so CapWrite is OUTSIDE that exception. Privileged Yalla support that
// needs to revive a customer's project must go through explicit
// break-glass admin tooling, not this customer-facing route. The mirror
// case to project.delete: BOTH halves of the project lifecycle are
// equally write-gated, so a Support principal cannot reach EITHER side
// cross-tenant. Pinning the support-cross-tenant DENY at the engine here
// means a future {org_id}-scoped variant inherits a working cross-tenant
// deny for project.restore.
//
// projects rows store no secrets, so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.write). Tenant-leakage
// and no-write invariants still apply: a denied response never echoes
// the seeded resource ids / slug / display name or the foreign tenant's
// id; and the restorer MUST never run on any deny path — a scoped key
// denied on the wire cannot have cleared deletion_scheduled_at on a row
// in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// restoreProjectHandlerFor, restoreProject, decodeRestoreProject,
// fakeProjectRestorer, orgPrincipal, seedProject, projectResource, and
// decodeError are shared with the projects-restore contract suite
// (projects_restore_test.go) and the wider httpapi test fixtures; this
// file adds no scaffolding beyond the small fixture builders below.

// canonicalRestoreProject is the row every test in this file would
// receive back from the restorer on an allow path: a project whose
// deletion_scheduled_at has been cleared, so the wire body carries the
// authoritative restored lifecycle state. Centralising it lets a future
// regression that reorders, renames, or recategorises a projectResource
// field fail in exactly one place. The distinctive id / slug / display
// name are deliberately recognisable so deny-path leak guards can
// needle for them; allow-path assertions compare against the same
// canonical values. The inverse of canonicalDeleteProject: there the
// stamp is set on the wire body, here the stamp is absent — that
// inversion is the lifecycle-state property a future regression that
// returned the row WITHOUT clearing the stamp would fail on.
func canonicalRestoreProject(orgID string) store.Project {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 9, 1, 0, time.UTC)
	p := seedProject("prj_restore_alpha", orgID, "restore-alpha", "Restore Alpha", 11, created, updated)
	// DeletionScheduledAt deliberately left nil — the restore cleared it.
	return p
}

// restoreProjectDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project. A denied
// response that accidentally rendered any of these fails the test —
// the row's existence (and the fact that it was previously soft-deleted)
// is itself information a denied principal must not receive. The quoted
// forms catch a case-collapsing renderer regression. There is no request
// body for POST /v1/projects/{project_id}/restore, so unlike the PATCH
// leak guard there is no caller-supplied request-body field to protect.
func restoreProjectDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_restore_alpha",
		"\"restore-alpha\"",
		"\"Restore Alpha\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestRestoreProjectPolicyMatrixRoles drives every built-in role
// through the production request path. CapWrite splits the matrix:
// Owner / Admin / Developer (own org) are allowed; Viewer / CI /
// Support (own org) are denied. The assertions that matter for allow
// rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the restorer is reached with the principal's
// own home organization id, the {project_id} path parameter, AND the
// principal id (so the audit record names the actor verbatim), and
// the response is a stable 200 yalla.output.v1 carrying the canonical
// restored project with its deletion_scheduled_at stamp ABSENT. For
// deny rows, the assertions are 403 yalla.error.v1, the stable reason
// on the wire, the restorer MUST NEVER run (no row's
// deletion_scheduled_at cleared in the background), and the denied body
// must not echo the canonical project's identifiers.
func TestRestoreProjectPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalRestoreProject(org)
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
			// CapRead but not CapWrite, and CI holds CapDeploy but
			// not CapWrite. (The cross-tenant Support deny is pinned
			// separately in
			// TestRestoreProjectPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectRestore, projectResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.restore) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(project.restore) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.RestoreProjectInput
			restorer := fakeProjectRestorer{
				project: project,
				got:     &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := restoreProjectHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, restorer)
			rec := restoreProject(handler, project.ID, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("restorer received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ProjectID != project.ID {
					t.Errorf("restorer received project id %q, want the path parameter %q",
						captured.ProjectID, project.ID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("restorer received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.ActorOrgID != org {
					t.Errorf("restorer received actor org id %q, want the principal's home org %q",
						captured.ActorOrgID, org)
				}
				env := decodeRestoreProject(t, rec)
				if env.Data.Project.ProjectID != project.ID ||
					env.Data.Project.Slug != project.Slug ||
					env.Data.Project.DisplayName != project.DisplayName ||
					env.Data.Project.OrganizationID != org ||
					env.Data.Project.Version != project.Version {
					t.Errorf("project = %+v, want (%s, %s, %s, org=%s, v=%d)",
						env.Data.Project, project.ID, project.Slug, project.DisplayName, org, project.Version)
				}
				// The inverse of the delete allow-path assertion: the
				// restored row's deletion_scheduled_at MUST be absent.
				// A future handler regression that rendered a stale
				// (still-scheduled) row from the store cache without
				// clearing the stamp would fail here.
				if env.Data.Project.DeletionScheduledAt != nil {
					t.Errorf("deletion_scheduled_at = %v, want nil on the allow path (restored)",
						*env.Data.Project.DeletionScheduledAt)
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
				t.Errorf("restorer was reached with org=%q project=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ProjectID)
			}
			if body := rec.Body.String(); restoreProjectDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical project: %s", body)
			}
		})
	}
}

// TestRestoreProjectPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action project.restore with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to revive a
// soft-deleted project of the organization it once had access to, the
// restorer must never run, and the denied body must never echo the
// principal id, the organization id, the path-supplied project id, or
// any seeded project data.
//
// Underlying role is Owner so a working credential WOULD allow
// project.restore; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0135 ("revoked key,
// expired key").
func TestRestoreProjectPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalRestoreProject(org)

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

			var captured store.RestoreProjectInput
			restorer := fakeProjectRestorer{
				project: project,
				got:     &captured,
			}
			handler := restoreProjectHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, restorer)
			rec := restoreProject(handler, project.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.ProjectID != "" {
				t.Errorf("restorer was reached with org=%q project=%q for a disabled principal; it must never run",
					captured.OrganizationID, captured.ProjectID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				restoreProjectDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded project data", body)
			}
		})
	}
}

// TestRestoreProjectPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for project.restore. As with project.read,
// project.update, and project.delete, the resource org id is taken
// from the PRINCIPAL'S home org — the {project_id} path parameter
// alone never widens the resource to another tenant. Tenant isolation
// on the wire is therefore structural at the persistence layer, not
// the policy boundary:
//
//   - A principal in org_attacker hitting POST
//     /v1/projects/{prj_victim}/restore with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapWrite — and then
//     reaches the tenant-scoped repository query with the principal's
//     home org id and the foreign project id. A production repository
//     (which combines organization_id and id in its WHERE clause)
//     cannot match a row that belongs to another tenant, so the
//     request surfaces as a deterministic 404 E_NOT_FOUND. The body
//     must never echo the foreign org id even though no wire input
//     could place it there, because the persistence layer must not
//     leak foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the project.read cross-tenant
//     property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but restore DOES NOT — the mirror to
//     project.delete (which is also OUTSIDE the support exception).
//     Pinning that engine verdict here means the eventual scoped
//     variant inherits a working cross-tenant deny for
//     project.restore across every role, and a future catalog change
//     that downgraded project.restore into the support cross-tenant
//     exception (or widened the exception) would fail here before it
//     could regress a real customer.
func TestRestoreProjectPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_alpha"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits POST
	// /v1/projects/{prj_victim}/restore with a valid Owner token. The
	// fake mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, projectID) pair does not match a
	// row, so a principal whose home org is org_attacker restoring a
	// project that belongs to org_victim hits the fake with
	// (org_attacker, prj_victim_alpha) and gets NotFound. The
	// assertions that matter are structural: the restorer is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectRestorer could not have cleared the victim's project's
	// deletion_scheduled_at regardless of database state. The denied
	// body must never echo the victim's org id.
	var captured store.RestoreProjectInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	restorer := fakeProjectRestorer{
		err: apierr.NotFound("project", foreignProjID),
		got: &captured,
	}
	handler := restoreProjectHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, restorer)
	rec := restoreProject(handler, foreignProjID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("restorer received org id %q, want the attacker's home org %q — the restorer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ProjectID != foreignProjID {
		t.Errorf("restorer received project id %q, want the path parameter %q",
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
	// scope inherits a working cross-tenant deny. project.restore is
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
			got := e.Decide(p, policy.ActionProjectRestore, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.restore, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestRestoreProjectPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped
// API key is authorized purely by its grants (it carries no
// organization role); the engine confines those grants — a project
// grant does not reach a sibling project, an environment grant does
// not reach the parent project, a service grant does not reach the
// parent environment or a sibling service.
//
// Crucially for POST /v1/projects/{project_id}/restore: project.restore
// is evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}). This is the load-bearing
// distinction from the project.create matrix
// (projects_create_policy_test.go), where the resource is the
// ORGANIZATION root and no project-/env-/service-level grant can
// reach it. Here:
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     the restore (ReasonAllowedByGrant), and at the wire the
//     restorer receives (home_org, target_project_id, principal id) —
//     the grant scope contains the resource scope.
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
//     resource). It is denied ReasonDeniedOutOfScope — the "env grant
//     does not imply access to production unless production is
//     explicitly granted" property still applies here: even an env
//     grant on the same project's production environment cannot
//     escalate to reviving the parent project.
//   - A service-level grant likewise does NOT cover a project
//     resource and does not expose the parent environment's secrets
//     through env.write either — the "service grant does not expose
//     parent-level secrets or unrelated services" property.
//   - An organization-level Admin grant DOES cover any project
//     resource within the same org and — because project.restore is
//     CapWrite and Admin holds CapWrite — is allowed via
//     ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, viewer-grant
// no-capability — are pinned against the engine, then tied back to
// the wire by proving the restorer is never reached on any deny path
// (so a production store could not have cleared a row's
// deletion_scheduled_at in the background) and the denied body never
// echoes the canonical project's identifiers.
func TestRestoreProjectPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalRestoreProject(org)
	e := policy.NewEngine()

	// Project-level grant: admin on prj_restore_alpha only.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_restore_beta"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.restore) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.restore) for a sibling project = %+v, want deny via %q — a project-scoped admin grant must not reach prj_restore_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. project.restore on the same project resource must
	// fail with ReasonDeniedNoCapability — a viewer grant does not
	// widen to a write action even when its scope contains the
	// resource. This is the property a future "grant role enum
	// re-mapping" regression would catch here.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.restore) for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment
	// only; the parent project is shallower than the grant scope, so
	// covers() does not reach it. project.restore on the parent
	// project must fail with ReasonDeniedOutOfScope. The acceptance
	// criterion "environment-level grants do not imply access to
	// production unless production is explicitly granted" is doubly
	// enforced here: the grantee can't escalate from the staging env
	// to the production env (a sibling-env property), and can't
	// escalate from any env to the parent project at all.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.restore) for an environment-scoped grantee = %+v, want deny via %q — an env grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentDelete, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(environment.delete) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow project.restore on the parent
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
	if got := e.Decide(svcGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.restore) for a service-scoped grantee = %+v, want deny via %q — a service grant must not reach the parent project",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// TARGET project is a 200 with the canonical restored project
	// (its deletion_scheduled_at stamp absent), the restorer is
	// reached with (home_org, target_project_id, principal id,
	// actor_org_id), and the response carries the canonical row
	// unchanged.
	var targetCaptured store.RestoreProjectInput
	targetRestorer := fakeProjectRestorer{
		project: project,
		got:     &targetCaptured,
	}
	targetHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, targetRestorer)
	targetRec := restoreProject(targetHandler, project.ID, "yk_proj_scoped")
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped admin key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCaptured.OrganizationID != org {
		t.Errorf("restorer received org id %q, want the principal's home org %q",
			targetCaptured.OrganizationID, org)
	}
	if targetCaptured.ProjectID != project.ID {
		t.Errorf("restorer received project id %q, want the path parameter %q",
			targetCaptured.ProjectID, project.ID)
	}
	if targetCaptured.ActorID != projectAdminGrantee.ID {
		t.Errorf("restorer received actor id %q, want the principal id %q",
			targetCaptured.ActorID, projectAdminGrantee.ID)
	}
	if targetCaptured.ActorOrgID != org {
		t.Errorf("restorer received actor org id %q, want the principal's home org %q",
			targetCaptured.ActorOrgID, org)
	}
	targetEnv := decodeRestoreProject(t, targetRec)
	if targetEnv.Data.Project.ProjectID != project.ID ||
		targetEnv.Data.Project.Slug != project.Slug ||
		targetEnv.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			targetEnv.Data.Project, project.ID, project.Slug, org)
	}
	if targetEnv.Data.Project.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v, want nil on a successful restore",
			*targetEnv.Data.Project.DeletionScheduledAt)
	}

	// Wire tie-in #2: the SAME project-scoped admin grantee hitting
	// a SIBLING project is a 403 with the stable out-of-scope
	// reason, the restorer is never reached (so a production store
	// could never have cleared deletion_scheduled_at on a sibling row
	// in the background), and the body never echoes the canonical
	// project's identifiers. This is the property that makes the
	// policy boundary — not the persistence boundary — the structural
	// place a scoped key is denied access to a sibling project.
	var siblingCaptured store.RestoreProjectInput
	siblingRestorer := fakeProjectRestorer{
		project: project, // would be returned if restorer ran — leak guard catches it
		got:     &siblingCaptured,
	}
	siblingHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, siblingRestorer)
	siblingRec := restoreProject(siblingHandler, "prj_restore_beta", "yk_proj_scoped")
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
		t.Errorf("restorer was reached with org=%q project=%q for an out-of-scope grantee; it must never run",
			siblingCaptured.OrganizationID, siblingCaptured.ProjectID)
	}
	if body := siblingRec.Body.String(); restoreProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project: %s", body)
	}

	// Wire tie-in #3: the project-scoped VIEWER grantee hitting the
	// SAME project is a 403 with ReasonDeniedNoCapability (the grant
	// covers the resource, but the role does not hold CapWrite). The
	// restorer is never reached and the body never echoes the
	// canonical project.
	var viewerCaptured store.RestoreProjectInput
	viewerRestorer := fakeProjectRestorer{
		project: project,
		got:     &viewerCaptured,
	}
	viewerHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, viewerRestorer)
	viewerRec := restoreProject(viewerHandler, project.ID, "yk_proj_viewer")
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
		t.Errorf("restorer was reached with org=%q project=%q for a viewer-grant principal; it must never run",
			viewerCaptured.OrganizationID, viewerCaptured.ProjectID)
	}
	if body := viewerRec.Body.String(); restoreProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project: %s", body)
	}

	// Wire tie-in #4: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the restorer
	// is never reached. The leak guard catches an accidental render
	// of the canonical project even though the env grantee never
	// had project-write coverage at all.
	var envCaptured store.RestoreProjectInput
	envRestorer := fakeProjectRestorer{
		project: project,
		got:     &envCaptured,
	}
	envHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envRestorer)
	envRec := restoreProject(envHandler, project.ID, "yk_env_scoped")
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
		t.Errorf("restorer was reached with org=%q project=%q for an env-scoped grantee; it must never run",
			envCaptured.OrganizationID, envCaptured.ProjectID)
	}
	if body := envRec.Body.String(); restoreProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project: %s", body)
	}

	// Wire tie-in #5: the service-scoped grantee hitting the parent
	// project is a 403, the restorer is never reached, and the body
	// never echoes parent-level identifiers. This is the property
	// that keeps a service-scoped key from escalating to a
	// parent-project restore through this endpoint.
	var svcCaptured store.RestoreProjectInput
	svcRestorer := fakeProjectRestorer{
		project: project,
		got:     &svcCaptured,
	}
	svcHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcRestorer)
	svcRec := restoreProject(svcHandler, project.ID, "yk_svc_scoped")
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
		t.Errorf("restorer was reached with org=%q project=%q for a service-scoped grantee; it must never run",
			svcCaptured.OrganizationID, svcCaptured.ProjectID)
	}
	if body := svcRec.Body.String(); restoreProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project: %s", body)
	}

	// An organization-level Admin grant DOES cover any project
	// resource in the same org and — because project.restore is
	// CapWrite and Admin holds CapWrite — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at
	// the wire, with the restorer reached on the principal's home
	// org id and the path project id. This locks the CapWrite
	// requirement against the grant path so a future catalog change
	// that upgraded project.restore above CapWrite would fail here
	// (silently denying every org-level Admin grantee) before it
	// could regress a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.restore) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.RestoreProjectInput
	orgRestorer := fakeProjectRestorer{
		project: project,
		got:     &orgCaptured,
	}
	orgHandler := restoreProjectHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgRestorer)
	allowedRec := restoreProject(orgHandler, project.ID, "yk_org_admin")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeRestoreProject(t, allowedRec)
	if allowedPayload.Data.Project.ProjectID != project.ID ||
		allowedPayload.Data.Project.Slug != project.Slug ||
		allowedPayload.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, org=%s)",
			allowedPayload.Data.Project, project.ID, project.Slug, org)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("restorer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ProjectID != project.ID {
		t.Errorf("restorer received project id %q, want the path parameter %q",
			orgCaptured.ProjectID, project.ID)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; project.restore must be denied via
	// ReasonDeniedNoCapability even though the grant scope is the
	// whole org. This is the load-bearing distinction from the
	// project.read grant matrix: an org-level Viewer is ALLOWED for
	// read but DENIED for restore.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionProjectRestore, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.restore) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id
	// is foreign is denied at the engine: a grant for
	// prj_restore_alpha inside org_acme, carried by a principal whose
	// home org id is org_sibling, cannot be used to restore
	// prj_restore_alpha in org_sibling — the cross-tenant guard fires
	// first because the principal's home org no longer matches the
	// grant's scope. This is the engine-level twin of the wire-level
	// "wrong organization" property in
	// TestRestoreProjectPolicyWrongOrganizationPrincipal, applied to
	// a scoped key: stealing a key cannot smuggle it across tenants.
	// project.restore is OUTSIDE the support cross-tenant exception
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
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectRestore, siblingOrgResource); got.Allow {
		t.Errorf("Decide(project.restore) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
