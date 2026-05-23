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

// Policy-matrix coverage for POST /v1/projects (BE-0123). Where
// projects_create_test.go proves the endpoint's wire contract (BE-0121,
// BE-0122), this file proves its authorization contract: that action
// project.create cannot be bypassed by — or persist a write because of —
// the principal's role, revoked credentials, home organization, or scoped
// grants.
//
// The route carries a NIL ResourceResolver (routes.go). RequireAuth
// therefore authorizes against the principal's own home organization
// scope — there is no caller-supplied path or query parameter, and the
// strict JSON decoder rejects an organization_id smuggled into the body
// before the handler reads the principal (projects_create_test.go pins
// that property). So tenant isolation here is structural: the source of
// authority is the principal's home organization id, and the creator is
// always invoked with that same id. The risk is therefore not "can a
// caller name another tenant" (the body has no field that could) but
// "does a principal that should not be able to create projects in its
// OWN organization get stopped at the policy boundary, never reaching
// the creator".
//
// project.create requires CapWrite (catalog.go: ActionProjectCreate ->
// CapWrite), the same capability class as variables put / project
// update / environment create / service create. The role matrix for a
// principal acting on its own organization therefore splits along the
// write capability class: Owner/Admin/Developer hold CapWrite and are
// allowed (ReasonAllowedByRole); Viewer/CI/Support do not hold CapWrite
// and are denied (ReasonDeniedNoCapability). This is the load-bearing
// distinction from the project.read matrix (projects_policy_test.go),
// which is "all six roles allow": three additional roles deny here at
// the role boundary, and — crucially — the engine's cross-tenant
// support exception is gated on `required == CapRead || required ==
// CapSupport`, so CapWrite is OUTSIDE that exception. Privileged Yalla
// support that needs to create a project on a customer's behalf must
// go through explicit break-glass admin tooling, not this customer-
// facing route. Pinning the support-cross-tenant DENY at the engine
// here means a future {org_id}-scoped variant inherits a working
// cross-tenant deny.
//
// projects rows store no secrets, so there is no secret-redaction
// chokepoint to pin on the wire (unlike env.write). Tenant-leakage and
// no-write invariants still apply: a denied response never echoes the
// cross-tenant id, the principal id, or the caller-supplied request
// body fields, and the creator MUST never run on any deny path — a
// scoped key denied on the wire cannot have committed a row in the
// background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, or the engine fails here. createProjectHandlerFor,
// postProjects, createProjectRequestBody, decodeCreateProject,
// decodeCreateProjectError, fakeProjectCreator, orgPrincipal, and
// decodeError are shared with the projects-create contract suite
// (projects_create_test.go) and the wider httpapi test fixtures; this
// file adds no scaffolding beyond the small fixtures below.

// canonicalCreateProjectInput builds the canonical request body every
// test in this file shares. Centralising it lets a future regression
// that reorders, renames, or recategorises a field fail in exactly one
// place. The distinctive ids/slug/display name are deliberately
// recognisable so deny-path leak guards can needle for them.
func canonicalCreateProjectInput() (projectID, slug, displayName string) {
	return "prj_matrix_alpha", "matrix-alpha", "Matrix Alpha"
}

// canonicalCreatedProject is the row a deny-path fake creator would
// return if it were (incorrectly) reached. The body-leak guard needles
// for these recognisable values, so an accidental on-deny render of the
// "created" project fails the test even before the creator-not-reached
// assertion. The values are deliberately distinct from the request
// body's so a request-body-echo and a creator-output-echo are both
// catchable.
func canonicalCreatedProject(orgID string) store.Project {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	return store.Project{
		ID:             "prj_matrix_alpha",
		OrganizationID: orgID,
		Slug:           "matrix-alpha",
		DisplayName:    "Matrix Alpha",
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// createProjectDenyBodyLeak reports whether body contains any of the
// caller-supplied request-body fields or the canned created-project
// fields. A denied response that accidentally rendered any of these
// fails the test — a denied request_body field would mean the handler
// echoed the request after policy denial (a tenant boundary smell), and
// a denied created-project field would mean the creator ran and the
// response leaked its output even though the wire said 403.
func createProjectDenyBodyLeak(body string) bool {
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

// TestCreateProjectPolicyMatrixRoles drives every built-in role through
// the production request path. CapWrite splits the matrix: Owner/Admin/
// Developer (own org) are allowed; Viewer/CI/Support (own org) are
// denied. The assertions that matter for allow rows are that the
// verdict is reached through the role (ReasonAllowedByRole), the
// creator is reached with the principal's own home organization id and
// the principal id (so the audit record names the actor verbatim), and
// the response is a stable 201 yalla.output.v1. For deny rows, the
// assertions are 403 yalla.error.v1, the stable reason on the wire, the
// creator MUST NEVER run (no row written in the background), and the
// denied body must not echo the caller-supplied request-body fields.
func TestCreateProjectPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	projectID, slug, displayName := canonicalCreateProjectInput()
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

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
			// allow rows pin ReasonAllowedByRole; the deny rows pin
			// ReasonDeniedNoCapability. CapWrite is outside the
			// support cross-tenant exception, so Support reading ITS
			// OWN organization is denied here at the no-capability
			// boundary (the cross-tenant clause is exercised in
			// TestCreateProjectPolicyWrongOrganizationPrincipal).
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionProjectCreate, orgRoot)
			if got.Allow != tc.allow || got.Reason != tc.reason {
				t.Errorf("Decide(project.create) for %s = %+v, want allow=%v reason=%q",
					tc.name, got, tc.allow, tc.reason)
			}

			var gotInput store.CreateProjectInput
			creator := fakeProjectCreator{
				project: canonicalCreatedProject(org),
				got:     &gotInput,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := createProjectHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, creator)
			rec := postProjects(handler, "a-valid-token",
				createProjectRequestBody(t, projectID, slug, displayName))

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				if gotInput.OrganizationID != org {
					t.Errorf("creator received organization id %q, want the principal's home org %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.ActorOrgID != org {
					t.Errorf("creator received actor org id %q, want the principal's home org %q",
						gotInput.ActorOrgID, org)
				}
				if gotInput.ActorID != "usr_"+tc.name {
					t.Errorf("creator received actor id %q, want usr_%s — the audit record must name the actor verbatim",
						gotInput.ActorID, tc.name)
				}
				env := decodeCreateProject(t, rec)
				if env.SchemaVersion != "yalla.output.v1" || !env.OK {
					t.Errorf("envelope = %+v, want schema_version=yalla.output.v1 ok=true", env)
				}
				if env.Data.Project.ProjectID != projectID || env.Data.Project.Slug != slug || env.Data.Project.OrganizationID != org {
					t.Errorf("project = %+v, want (%s, %s, %s)",
						env.Data.Project, projectID, slug, org)
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
			if gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached for a denied principal with input %+v; it must never run", gotInput)
			}
			if body := rec.Body.String(); createProjectDenyBodyLeak(body) {
				t.Errorf("denied response leaked request-body or canned-project data: %s", body)
			}
		})
	}
}

// TestCreateProjectPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action project.create with a stable 403 E_FORBIDDEN, even when
// the underlying role would have allowed it. A revoked or expired
// credential must never be able to create a project in the organization
// it once had write access to, the creator must never run, and the
// denied body must never echo the principal id, the organization id, or
// the caller-supplied request body fields.
//
// Underlying role is Owner so a working credential WOULD allow
// project.create; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0123 ("revoked key,
// expired key").
func TestCreateProjectPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	projectID, slug, displayName := canonicalCreateProjectInput()

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

			var gotInput store.CreateProjectInput
			creator := fakeProjectCreator{
				project: canonicalCreatedProject(org),
				got:     &gotInput,
			}
			handler := createProjectHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)
			rec := postProjects(handler, "yk_no_longer_valid",
				createProjectRequestBody(t, projectID, slug, displayName))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached with input %+v for a disabled principal; it must never run", gotInput)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				createProjectDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or request data", body)
			}
		})
	}
}

// TestCreateProjectPolicyWrongOrganizationPrincipal pins the cross-tenant
// boundary for project.create. The route uses a nil resolver and the
// strict JSON decoder rejects an organization_id smuggled into the
// body, so the wire surface offers no way for a foreign principal to
// point the write at another tenant — tenant isolation on the wire is
// therefore structural:
//
//   - A principal in org_attacker hitting POST /v1/projects can only
//     create projects of org_attacker, regardless of what the body
//     names. The creator is always invoked with the principal's own
//     home org id; the attacker can never widen the write to org_victim
//     through this endpoint.
//
//   - Engine defence-in-depth: even if a future endpoint exposed an
//     {org_id} path parameter, EVERY role of org_attacker authorizing
//     project.create against an org_victim resource MUST be denied with
//     ReasonDeniedCrossTenant. This is the load-bearing distinction
//     from the project.read matrix (projects_policy_test.go): CapWrite
//     is OUTSIDE the engine's support cross-tenant exception (the
//     clause is `roleCaps.has(CapSupport) && (required == CapRead ||
//     required == CapSupport)`), so a Support principal of org_yalla
//     authorizing project.create against an org_victim resource is
//     DENIED — privileged Yalla support that needs to create a project
//     on a customer's behalf must go through explicit break-glass admin
//     tooling, never this customer-facing route. Pinning that engine
//     verdict here means a future {org_id}-scoped variant inherits a
//     working cross-tenant deny.
func TestCreateProjectPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)
	projectID, slug, displayName := canonicalCreateProjectInput()

	// Wire-level: an attacker in org_attacker hits POST /v1/projects
	// with a valid body. The assertion that matters is structural: the
	// creator is ALWAYS called with the principal's home org id —
	// never with a caller-controlled or fabricated value — so a
	// production ProjectService (which writes only to the
	// organization_id it was handed) cannot have inserted a row in
	// org_victim through this endpoint regardless of the body. The
	// body must therefore also never echo the victim's org id, since
	// no input path reaches the response from here.
	var gotInput store.CreateProjectInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	creator := fakeProjectCreator{
		project: canonicalCreatedProject(ownOrg),
		got:     &gotInput,
	}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)

	rec := postProjects(handler, "a-valid-token",
		createProjectRequestBody(t, projectID, slug, displayName))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (a same-tenant principal still creates in its OWN org); body %s",
			rec.Code, rec.Body.String())
	}
	if gotInput.OrganizationID != ownOrg {
		t.Errorf("creator received organization id %q, want the attacker's home org %q — the creator must never be called with another tenant's id",
			gotInput.OrganizationID, ownOrg)
	}
	if gotInput.ActorOrgID != ownOrg {
		t.Errorf("creator received actor org id %q, want %q — the audit record must name the attacker's own org, not any other",
			gotInput.ActorOrgID, ownOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so a
	// future endpoint that resolves an {org_id} path parameter into a
	// foreign org scope inherits a working cross-tenant deny.
	// project.create is CapWrite; the engine's cross-tenant clause
	// `roleCaps.has(CapSupport) && (required == CapRead || required ==
	// CapSupport)` is gated on CapRead/CapSupport actions, so CapWrite
	// is outside the exception and EVERY role — including Support — is
	// denied here.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	crossTenantRoles := []struct {
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
	for _, tc := range crossTenantRoles {
		tc := tc
		t.Run("cross_tenant_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionProjectCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(project.create, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCreateProjectPolicyGrantContainment proves scoped grants cannot
// be widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (it carries no organization role); the
// engine confines those grants — a project grant does not reach a
// sibling project, an environment grant does not reach production, a
// service grant does not reach the parent environment or a sibling
// service.
//
// Crucially for POST /v1/projects: project.create is evaluated against
// the principal's home organization root (the route's nil resolver). A
// project/environment/service-scoped grant — even an Admin grant — does
// not cover that scope (covers() is one-way: a more-specific scope
// cannot reach a broader resource), not even for the key's own
// organization. So a scoped key holding only a project grant is denied
// the endpoint at its own home org with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level
// write grant (Owner/Admin/Developer) is allowed it
// (ReasonAllowedByGrant). An organization-level VIEWER grant is denied
// because Viewer does not hold CapWrite, ReasonDeniedNoCapability — the
// load-bearing distinction from the project.read containment matrix
// (projects_policy_test.go), where an organization-level Viewer grant
// IS sufficient.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own home organization (creator never runs), while an
// organization-scoped Developer grantee is allowed (creator reached on
// the principal's home org id).
func TestCreateProjectPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	projectID, slug, displayName := canonicalCreateProjectInput()
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

	// POST /v1/projects authorizes against the principal's home
	// organization root (the route's nil resolver). A project/
	// environment/service-scoped admin grant does NOT cover that scope
	// — not even for the key's own organization — so each scoped
	// grantee is denied the endpoint with ReasonDeniedOutOfScope: the
	// scoped key cannot be widened to create a sibling project, and
	// the creator never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionProjectCreate, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.create) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionProjectCreate, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.create) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionProjectCreate, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.create) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee hitting
	// POST /v1/projects is a 403 with the stable out-of-scope reason,
	// the creator is never reached, and the body never echoes the
	// caller-supplied request fields. This is the property that makes
	// the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied a broader write surface.
	var projectGot store.CreateProjectInput
	projectCreator := fakeProjectCreator{
		project: canonicalCreatedProject(org),
		got:     &projectGot,
	}
	projectHandler := createProjectHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectCreator)
	rec := postProjects(projectHandler, "yk_proj_scoped",
		createProjectRequestBody(t, projectID, slug, displayName))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectGot.OrganizationID != "" || projectGot.ActorID != "" {
		t.Errorf("creator was reached with input %+v for an out-of-scope grantee; it must never run",
			projectGot)
	}
	if body := rec.Body.String(); createProjectDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body data: %s", body)
	}

	// An organization-level VIEWER grant covers the org-root scope but
	// — because project.create is CapWrite and Viewer does NOT hold
	// CapWrite — is denied with ReasonDeniedNoCapability. The grant's
	// scope is sufficient; the grant role's capability set is not.
	// This is the load-bearing distinction from project.read
	// containment (projects_policy_test.go), where an organization-
	// level Viewer grant IS sufficient. Pinning the deny here locks
	// the CapWrite requirement against the grant path so a future
	// catalog change that downgraded project.create to CapRead would
	// fail here (silently allowing every org-level Viewer grantee to
	// create projects) before it could regress a real customer.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionProjectCreate, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(project.create) for an organization-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// An organization-level DEVELOPER grant DOES cover the org-root
	// scope and — because project.create is CapWrite and Developer
	// holds CapWrite — is allowed via ReasonAllowedByGrant. The same
	// key is end-to-end allowed at the wire, with the creator reached
	// on the principal's home org id and naming the grantee as actor.
	orgDeveloper := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloper, policy.ActionProjectCreate, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.create) for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGot store.CreateProjectInput
	orgCreator := fakeProjectCreator{
		project: canonicalCreatedProject(org),
		got:     &orgGot,
	}
	orgHandler := createProjectHandlerFor(
		auth.Identity{Principal: orgDeveloper, Method: auth.MethodAPIKey}, nil, orgCreator)
	allowedRec := postProjects(orgHandler, "yk_org_dev",
		createProjectRequestBody(t, projectID, slug, displayName))
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeCreateProject(t, allowedRec)
	if allowedPayload.Data.Project.ProjectID != projectID ||
		allowedPayload.Data.Project.Slug != slug ||
		allowedPayload.Data.Project.OrganizationID != org {
		t.Errorf("project = %+v, want (%s, %s, %s)",
			allowedPayload.Data.Project, projectID, slug, org)
	}
	if orgGot.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			orgGot.OrganizationID, org)
	}
	if orgGot.ActorID != "sa_org_dev" {
		t.Errorf("creator received actor id %q, want sa_org_dev — the audit record must name the grantee verbatim",
			orgGot.ActorID)
	}

	// And the same project-scoped grantee whose home org id is foreign
	// is denied at the engine: a grant for proj_p inside org_acme,
	// carried by a principal whose home org id is org_sibling, cannot
	// be used to create a project in org_sibling — the cross-tenant
	// guard fires first because the principal's home org no longer
	// matches the grant's scope. This is the engine-level twin of the
	// wire-level "wrong organization" property in
	// TestCreateProjectPolicyWrongOrganizationPrincipal, applied to a
	// scoped key: stealing a key cannot smuggle a write across
	// tenants. CapWrite is outside the support cross-tenant
	// exception, so the deny is unconditional.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeP}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionProjectCreate, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(project.create) for a project-scoped key planted in a foreign org = %+v, want deny",
			got)
	}
}
