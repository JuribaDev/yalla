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

// Policy-matrix coverage for POST /v1/projects/{project_id}/environments
// (BE-0153). Where project_environments_create_test.go proves the
// endpoint's wire contract (BE-0151), this file proves its authorization
// contract: that action environment.create cannot be bypassed by — or
// commit an environment because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the projectIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {project_id} PATH parameter. RequireAuth therefore authorizes against
// the project the path names — not merely the principal's home
// organization — and the resource Kind is the project, not the
// environment that would be created under it. This is the same
// projectIDResolver-bound posture that BE-0150
// (projects_environments_get_policy_test.go), BE-0147
// (projects_variables_put_policy_test.go), BE-0144
// (projects_variables_get_policy_test.go), BE-0141
// (projects_grants_put_policy_test.go), and BE-0138
// (projects_grants_policy_test.go) lock in: a scoped grant for THIS
// project authorizes the write while a sibling-project grant is
// rejected at the boundary, and the handler still derives the
// organization id on the store input from the PRINCIPAL'S home org
// (never the caller — the request body has no organization_id field
// and the strict JSON decoder rejects an organization_id smuggled into
// the body before the creator ever runs, project_environments_create_test.go
// pins that property). So a cross-tenant project_id reaches the
// tenant-scoped store create with the principal's home org id and is
// rejected as a deterministic 404 NotFound at the persistence layer by
// the orchestrator's parent-project existence check. A cross-tenant
// project_id can never commit an environment under another
// organization's project, and the wire body must never echo the
// foreign org id even though no wire input could place it there.
//
// environment.create requires CapWrite (catalog.go: ActionEnvironmentCreate
// -> CapWrite), the same capability class as project.create / project.update
// / variables put / service.create. The role matrix for a principal
// acting on its own organization therefore splits along the write
// capability class: Owner/Admin/Developer hold CapWrite and are allowed
// (ReasonAllowedByRole); Viewer/CI/Support do not hold CapWrite and are
// denied (ReasonDeniedNoCapability). This is the load-bearing
// distinction from the environment.read matrix
// (projects_environments_get_policy_test.go), which is "all six roles
// allow": three additional roles deny here at the role boundary, and —
// crucially — the engine's cross-tenant support exception is gated on
// `required == CapRead || required == CapSupport`, so CapWrite is
// OUTSIDE that exception. Privileged Yalla support that needs to create
// an environment on a customer's behalf must go through explicit
// break-glass admin tooling, not this customer-facing route. Pinning
// the support-cross-tenant DENY at the engine here means a future
// {org_id}-scoped variant inherits a working cross-tenant deny.
//
// Unlike project_variables rows (which carry secret values), the
// environments table carries NO credential material — only structural
// identifiers, a slug, a display name, an optimistic-concurrency
// version, and lifecycle timestamps. The projectEnvironmentOf
// projection has no value-redaction chokepoint to anchor a deny-path
// leak guard on; the load-bearing needles are the caller-supplied
// request-body fields (an environment id, a slug, a display name a
// denied principal must not see echoed back) and the canned creator
// output (the row a deny-path fake creator WOULD have returned if it
// had been reached). Tenant-leakage and no-write invariants apply: a
// denied response never echoes the canonical request-body fields, the
// canned environment id / slug / display name, the foreign tenant's
// id, or the canonical project's identifiers; and the creator MUST
// never run on any deny path — a scoped key denied on the wire cannot
// have committed an environment row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// createProjectEnvironmentHandlerFor, postProjectEnvironments,
// createProjectEnvironmentRequestBody, decodeCreateProjectEnvironment,
// decodeCreateProjectEnvironmentError, fakeEnvironmentCreator,
// seedEnvironmentWire, canonicalEnvironmentsProject, orgPrincipal, and
// decodeError are shared with the project-environments contract suite
// (project_environments_test.go, project_environments_create_test.go)
// and the environment-read policy matrix
// (projects_environments_get_policy_test.go); this file adds no
// scaffolding beyond the small fixture builders below.

// canonicalCreateEnvironmentInput builds the canonical request body
// every test in this file shares. Centralising it lets a future
// regression that reorders, renames, or recategorises a field fail in
// exactly one place. The distinctive id / slug / display name are
// deliberately recognisable so deny-path leak guards can needle for
// them, and deliberately distinct from canonicalEnvironmentsProject /
// canonicalProjectEnvironments (used by
// projects_environments_get_policy_test.go) so the matrices cannot
// accidentally share fixture state through a future shared fake.
func canonicalCreateEnvironmentInput() (envID, slug, displayName string) {
	return "env_create_matrix_alpha", "create-matrix-alpha", "Create Matrix Alpha"
}

// canonicalCreatedEnvironment is the row a deny-path fake creator
// would return if it were (incorrectly) reached. The body-leak guard
// needles for these recognisable values, so an accidental on-deny
// render of the "created" environment fails the test even before the
// creator-not-reached assertion. The id mirrors the canonical request
// body so a request-body echo and a creator-output echo are both
// catchable through the same needles, and the version is deliberately
// non-zero so a wire response that surfaced this row would be
// distinguishable from an empty environment.
func canonicalCreatedEnvironment(orgID, projectID string) store.Environment {
	envID, slug, displayName := canonicalCreateEnvironmentInput()
	return store.Environment{
		ID:             envID,
		OrganizationID: orgID,
		ProjectID:      projectID,
		Slug:           slug,
		DisplayName:    displayName,
		Version:        1,
	}
}

// createEnvironmentDenyBodyLeak reports whether body contains any of
// the caller-supplied request-body fields or the canned created-
// environment fields. A denied response that accidentally rendered any
// of these fails the test: a denied request-body field would mean the
// handler echoed the request after policy denial (a tenant boundary
// smell), and a denied created-environment field would mean the creator
// ran and the response leaked its output even though the wire said
// 403. The quoted forms catch a case-collapsing renderer regression.
// There is no secret plaintext to anchor on — the environments table
// carries no credential material at all.
func createEnvironmentDenyBodyLeak(body string) bool {
	needles := []string{
		"env_create_matrix_alpha",
		"\"create-matrix-alpha\"",
		"\"Create Matrix Alpha\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestCreateProjectEnvironmentPolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner/Admin/Developer (own org) are allowed; Viewer/CI/
// Support (own org) are denied. The assertions that matter for allow
// rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the creator is reached with the principal's
// own home organization id, the path {project_id}, and the principal
// id (so the audit record names the actor verbatim), and the response
// is a stable 201 yalla.output.v1 envelope carrying the created
// environment. For deny rows, the assertions are 403 yalla.error.v1,
// the stable reason on the wire, the creator MUST NEVER run (no row
// written in the background), and the denied body must not echo the
// caller-supplied request-body fields.
func TestCreateProjectEnvironmentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envID, slug, displayName := canonicalCreateEnvironmentInput()
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
			// allow rows pin ReasonAllowedByRole; the deny rows pin
			// ReasonDeniedNoCapability. CapWrite is outside the
			// support cross-tenant exception, so Support acting on
			// ITS OWN organization's project is denied here at the
			// no-capability boundary (the cross-tenant clause is
			// exercised in
			// TestCreateProjectEnvironmentPolicyWrongOrganizationPrincipal).
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentCreate, projectResource)
			if got.Allow != tc.allow || got.Reason != tc.reason {
				t.Errorf("Decide(environment.create) for %s = %+v, want allow=%v reason=%q",
					tc.name, got, tc.allow, tc.reason)
			}

			var gotInput store.CreateEnvironmentInput
			callCount := 0
			creator := fakeEnvironmentCreator{
				env:       canonicalCreatedEnvironment(org, project.ID),
				gotInput:  &gotInput,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := createProjectEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, creator)
			rec := postProjectEnvironments(handler, project.ID, "a-valid-token",
				createProjectEnvironmentRequestBody(t, envID, slug, displayName))

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("creator call count = %d, want 1 on the allow path", callCount)
				}
				if gotInput.OrganizationID != org {
					t.Errorf("creator received organization id %q, want the principal's home org %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.ProjectID != project.ID {
					t.Errorf("creator received project id %q, want the path parameter %q",
						gotInput.ProjectID, project.ID)
				}
				if gotInput.ActorOrgID != org {
					t.Errorf("creator received actor org id %q, want the principal's home org %q",
						gotInput.ActorOrgID, org)
				}
				if gotInput.ActorID != "usr_"+tc.name {
					t.Errorf("creator received actor id %q, want usr_%s — the audit record must name the actor verbatim",
						gotInput.ActorID, tc.name)
				}
				env := decodeCreateProjectEnvironment(t, rec)
				if env.SchemaVersion != "yalla.output.v1" || !env.OK {
					t.Errorf("envelope = %+v, want schema_version=yalla.output.v1 ok=true", env)
				}
				if env.Data.Environment.ID != envID ||
					env.Data.Environment.Slug != slug ||
					env.Data.Environment.OrganizationID != org ||
					env.Data.Environment.ProjectID != project.ID {
					t.Errorf("environment = %+v, want (%s, %s, %s, %s)",
						env.Data.Environment, envID, slug, org, project.ID)
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
			if callCount != 0 || gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached (calls=%d input=%+v) for a denied principal; it must never run",
					callCount, gotInput)
			}
			if body := rec.Body.String(); createEnvironmentDenyBodyLeak(body) {
				t.Errorf("denied response leaked request-body or canned-environment data: %s", body)
			}
		})
	}
}

// TestCreateProjectEnvironmentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both of
// which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action environment.create with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it. A
// revoked or expired credential must never be able to create an
// environment under a project of the organization it once had write
// access to, the creator must never run, and the denied body must
// never echo the principal id, the organization id, the path-supplied
// project id, or the caller-supplied request body fields.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.create; Disabled is the only thing in the way and must
// be load-bearing. The case names mirror PRD BE-0153 ("revoked key,
// expired key").
func TestCreateProjectEnvironmentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envID, slug, displayName := canonicalCreateEnvironmentInput()

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

			var gotInput store.CreateEnvironmentInput
			callCount := 0
			creator := fakeEnvironmentCreator{
				env:       canonicalCreatedEnvironment(org, project.ID),
				gotInput:  &gotInput,
				callCount: &callCount,
			}
			handler := createProjectEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)
			rec := postProjectEnvironments(handler, project.ID, "yk_no_longer_valid",
				createProjectEnvironmentRequestBody(t, envID, slug, displayName))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached (calls=%d input=%+v) for a disabled principal; it must never run",
					callCount, gotInput)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				strings.Contains(body, project.ID) ||
				createEnvironmentDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, path project id, or request data",
					body)
			}
		})
	}
}

// TestCreateProjectEnvironmentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.create on the project
// environments route. As with environment.read, project.read,
// project.grants.read, and env.read, the resource org id is taken from
// the PRINCIPAL'S home org — the {project_id} path parameter alone
// never widens the resource to another tenant. Tenant isolation on the
// wire is therefore structural at the persistence layer, not the
// policy boundary:
//
//   - A principal in org_attacker hitting POST
//     /v1/projects/{prj_victim}/environments with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapWrite — and then
//     reaches the store-layer orchestrator with the principal's home
//     org id and the foreign project id. The orchestrator Gets the
//     project under (organization_id, project_id) before creating its
//     environment, so a cross-tenant project_id is rejected as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 200 (which
//     would mean an environment was committed under the foreign
//     project) and never as a 403 that would confirm the project's
//     existence. The body must never echo the foreign org id even
//     though no wire input could place it there, because the
//     persistence layer must not leak foreign-tenant identity into the
//     error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY role — including
//     Support — MUST be denied via ReasonDeniedCrossTenant. This is
//     the load-bearing distinction from the environment.read matrix
//     (projects_environments_get_policy_test.go): CapWrite is OUTSIDE
//     the engine's support cross-tenant exception (the clause is
//     `roleCaps.has(CapSupport) && (required == CapRead || required ==
//     CapSupport)`), so a Support principal of org_yalla authorizing
//     environment.create against an org_victim resource is DENIED —
//     privileged Yalla support that needs to create an environment on
//     a customer's behalf must go through explicit break-glass admin
//     tooling, never this customer-facing route. Pinning that engine
//     verdict here means a future {org_id}-scoped variant inherits a
//     working cross-tenant deny.
func TestCreateProjectEnvironmentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_envs"
		victimOrgNeedle = "org_victim"
	)
	envID, slug, displayName := canonicalCreateEnvironmentInput()

	// Wire-level: an attacker in org_attacker hits POST
	// /v1/projects/{prj_victim}/environments with a valid Owner token.
	// The fake mirrors the production orchestrator contract: it returns
	// NotFound whenever the (organizationID, projectID) pair does not
	// match a row (the orchestrator's parent-project existence check
	// fires first), so a principal whose home org is org_attacker
	// creating an environment under a project that belongs to
	// org_victim hits the fake with (org_attacker, prj_victim_envs)
	// and gets NotFound. The assertions that matter are structural:
	// the creator is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentService could not have committed a row
	// in the victim's project regardless of database state. The
	// denied body must never echo the victim's org id.
	var gotInput store.CreateEnvironmentInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	creator := fakeEnvironmentCreator{
		err:       apierr.NotFound("project", foreignProjID),
		gotInput:  &gotInput,
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)
	rec := postProjectEnvironments(handler, foreignProjID, "a-valid-token",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 201 which would mean a foreign-project commit and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — the creator runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign project id",
			callCount)
	}
	if gotInput.OrganizationID != ownOrg {
		t.Errorf("creator received org id %q, want the attacker's home org %q — the creator must never be called with another tenant's id",
			gotInput.OrganizationID, ownOrg)
	}
	if gotInput.ProjectID != foreignProjID {
		t.Errorf("creator received project id %q, want the path parameter %q",
			gotInput.ProjectID, foreignProjID)
	}
	if gotInput.ActorOrgID != ownOrg {
		t.Errorf("creator received actor org id %q, want %q — the audit record must name the attacker's own org, not the victim's",
			gotInput.ActorOrgID, ownOrg)
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
	// scope inherits a working cross-tenant deny. environment.create
	// is CapWrite; the engine's cross-tenant clause
	// `roleCaps.has(CapSupport) && (required == CapRead || required ==
	// CapSupport)` is gated on CapRead/CapSupport actions, so CapWrite
	// is outside the exception and EVERY role — including Support —
	// is denied here.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: victimOrg, ProjectID: foreignProjID},
	}
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
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionEnvironmentCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(environment.create, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCreateProjectEnvironmentPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for. A
// scoped API key is authorized purely by its grants (it carries no
// organization role); the engine confines those grants — a project
// grant does not reach a sibling project, an environment grant does
// not reach the parent project's environment list (and a staging grant
// does not reach production), a service grant does not reach the
// parent environment or a sibling service.
//
// Crucially for POST /v1/projects/{project_id}/environments:
// environment.create is evaluated against a PROJECT-level resource
// (the projectIDResolver scope is {home_org, path_project_id}). This
// is the load-bearing distinction from a route that resolved into a
// deeper scope (an environment- or service-level route): here a
// project-level Admin grant naming THIS project authorizes the create,
// but a deeper-scope grant cannot — covers() is one-way, so an env-
// or service-scoped grant does not contain the parent-project
// resource.
//
//   - A project-level Admin grant naming THIS project CAN authorize
//     the create (ReasonAllowedByGrant), and at the wire the creator
//     receives (home_org, target_project_id) — the grant scope
//     contains the resource scope and CapWrite is conferred.
//   - A project-level Admin grant naming a SIBLING project CANNOT —
//     covers() is one-way, so the grant scope does not contain the
//     resource scope. The denial is ReasonDeniedOutOfScope.
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope — the "env grant
//     does not imply access to production unless production is
//     explicitly granted" property still applies here: even an env
//     grant on the same project's production environment cannot
//     escalate to creating environments under the parent project
//     (which would let a staging-scoped key mint a production
//     environment, the precise escalation the engine forbids).
//   - A service-level grant likewise does NOT cover a project
//     resource and does not expose the parent environment either —
//     the "service grant does not expose parent-level secrets or
//     unrelated services" property; here it pins that a service-
//     scoped key cannot escalate to creating environments under the
//     parent project through this endpoint, even if its own service-
//     level action would normally be authorized for the service it
//     names.
//   - An organization-level VIEWER grant DOES cover any project
//     resource within the same org but — because environment.create
//     is CapWrite and Viewer does NOT hold CapWrite — is denied via
//     ReasonDeniedNoCapability. The grant's scope is sufficient; the
//     grant role's capability set is not. This is the load-bearing
//     distinction from environment.read containment
//     (projects_environments_get_policy_test.go), where an
//     organization-level Viewer grant IS sufficient.
//   - An organization-level DEVELOPER grant DOES cover any project
//     resource and — because environment.create is CapWrite and
//     Developer holds CapWrite — is allowed via ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, service grant
// shielding parent-level resources — are pinned against the engine,
// then tied back to the wire by proving the creator is never reached
// on any deny path (so a production store could not have committed an
// environment in the background) and the denied body never echoes the
// canonical request-body fields.
func TestCreateProjectEnvironmentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalEnvironmentsProject(org)
	envID, slug, displayName := canonicalCreateEnvironmentInput()
	e := policy.NewEngine()

	// Project-level grant: admin on prj_envs_matrix_alpha only. Admin
	// confers CapWrite at the project scope, which is exactly what
	// environment.create needs. The sibling-project property is
	// pinned for environment.create directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_envs_matrix_beta"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.create) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) for a sibling project = %+v, want deny via %q — a project-scoped admin grant must not reach prj_envs_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project
	// scope, which is NOT enough for environment.create (CapWrite).
	// The grant's scope covers the resource; the grant role's
	// capability set does not. This pins the CapWrite requirement
	// against the project-grant path so a future catalog change that
	// downgraded environment.create to CapRead would fail here
	// (silently allowing every project-scoped Viewer grantee to mint
	// environments) before it could regress a real customer.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.create) for a project-scoped viewer grant = %+v, want deny via %q — Viewer does not hold CapWrite",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant
	// scope, so covers() does not reach it for environment.create.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) for an environment-scoped grantee against the parent project = %+v, want deny via %q — an env grant must not reach the parent project's environment creation",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(env.write) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow environment.create on the parent
	// project (which would let a service-scoped key mint a new
	// environment alongside the one it lives in — the precise
	// escalation the policy engine forbids).
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
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) for a service-scoped grantee against the parent project = %+v, want deny via %q — a service grant must not reach the parent project's environment creation",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// TARGET project is a 201 with the canonical created-environment
	// payload, the creator is reached with (home_org, target_project_id),
	// and the response carries the created environment — the project-
	// scoped Admin grant confers exactly CapWrite at the project scope.
	var targetGotInput store.CreateEnvironmentInput
	targetCallCount := 0
	targetCreator := fakeEnvironmentCreator{
		env:       canonicalCreatedEnvironment(org, project.ID),
		gotInput:  &targetGotInput,
		callCount: &targetCallCount,
	}
	targetHandler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, targetCreator)
	targetRec := postProjectEnvironments(targetHandler, project.ID, "yk_proj_admin_scoped",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))
	if targetRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for a project-scoped admin key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCallCount != 1 {
		t.Errorf("creator call count = %d, want 1 on the allow path", targetCallCount)
	}
	if targetGotInput.OrganizationID != org {
		t.Errorf("creator received org id %q, want the principal's home org %q",
			targetGotInput.OrganizationID, org)
	}
	if targetGotInput.ProjectID != project.ID {
		t.Errorf("creator received project id %q, want the path parameter %q",
			targetGotInput.ProjectID, project.ID)
	}
	if targetGotInput.ActorID != "sa_proj_admin" {
		t.Errorf("creator received actor id %q, want sa_proj_admin — the audit record must name the grantee verbatim",
			targetGotInput.ActorID)
	}
	targetEnv := decodeCreateProjectEnvironment(t, targetRec)
	if targetEnv.Data.Environment.ID != envID ||
		targetEnv.Data.Environment.Slug != slug ||
		targetEnv.Data.Environment.OrganizationID != org ||
		targetEnv.Data.Environment.ProjectID != project.ID {
		t.Errorf("environment = %+v, want (%s, %s, %s, %s)",
			targetEnv.Data.Environment, envID, slug, org, project.ID)
	}

	// Wire tie-in #2: the SAME project-scoped Admin grantee hitting a
	// SIBLING project is a 403 with the stable out-of-scope reason,
	// the creator is never reached (so a production store could never
	// have committed a sibling environment in the background), and
	// the body never echoes the caller-supplied request-body fields.
	// This is the property that makes the policy boundary — not the
	// persistence boundary — the structural place a scoped key is
	// denied access to mint environments under a sibling project.
	var siblingGotInput store.CreateEnvironmentInput
	siblingCallCount := 0
	siblingCreator := fakeEnvironmentCreator{
		env:       canonicalCreatedEnvironment(org, "prj_envs_matrix_beta"),
		gotInput:  &siblingGotInput,
		callCount: &siblingCallCount,
	}
	siblingHandler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, siblingCreator)
	siblingRec := postProjectEnvironments(siblingHandler, "prj_envs_matrix_beta", "yk_proj_admin_scoped",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingCallCount != 0 || siblingGotInput.OrganizationID != "" || siblingGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for an out-of-scope grantee; it must never run",
			siblingCallCount, siblingGotInput)
	}
	if body := siblingRec.Body.String(); createEnvironmentDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-environment data: %s", body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the creator is
	// never reached. The leak guard catches an accidental render of
	// the canned created environment even though the env grantee
	// never had project-write coverage at all.
	var envGotInput store.CreateEnvironmentInput
	envCallCount := 0
	envCreator := fakeEnvironmentCreator{
		env:       canonicalCreatedEnvironment(org, project.ID),
		gotInput:  &envGotInput,
		callCount: &envCallCount,
	}
	envHandler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envCreator)
	envRec := postProjectEnvironments(envHandler, project.ID, "yk_env_scoped",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotInput.OrganizationID != "" || envGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for an env-scoped grantee; it must never run",
			envCallCount, envGotInput)
	}
	if body := envRec.Body.String(); createEnvironmentDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-environment data: %s", body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the creator is never reached, and the body
	// never echoes parent-level identifiers. This is the property that
	// keeps a service-scoped key from escalating to a parent-project
	// environment write through this endpoint — the "service grant
	// does not expose parent-level secrets or unrelated services"
	// acceptance criterion tied back to the wire on the
	// environment-create route.
	var svcGotInput store.CreateEnvironmentInput
	svcCallCount := 0
	svcCreator := fakeEnvironmentCreator{
		env:       canonicalCreatedEnvironment(org, project.ID),
		gotInput:  &svcGotInput,
		callCount: &svcCallCount,
	}
	svcHandler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcCreator)
	svcRec := postProjectEnvironments(svcHandler, project.ID, "yk_svc_scoped",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotInput.OrganizationID != "" || svcGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotInput)
	}
	if body := svcRec.Body.String(); createEnvironmentDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-environment data: %s", body)
	}

	// An organization-level VIEWER grant covers any project resource
	// in the same org but — because environment.create is CapWrite
	// and Viewer does NOT hold CapWrite — is denied with
	// ReasonDeniedNoCapability. The grant's scope is sufficient; the
	// grant role's capability set is not. This is the load-bearing
	// distinction from environment.read containment
	// (projects_environments_get_policy_test.go), where an
	// organization-level Viewer grant IS sufficient. Pinning the deny
	// here locks the CapWrite requirement against the grant path so a
	// future catalog change that downgraded environment.create to
	// CapRead would fail here (silently allowing every org-level
	// Viewer grantee to mint environments) before it could regress a
	// real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.create) for an organization-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// An organization-level DEVELOPER grant DOES cover any project
	// resource in the same org and — because environment.create is
	// CapWrite and Developer holds CapWrite — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at the
	// wire, with the creator reached on the principal's home org id
	// and the path project id, and naming the grantee as actor.
	orgDeveloperGrantee := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloperGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.create) for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotInput store.CreateEnvironmentInput
	orgCallCount := 0
	orgCreator := fakeEnvironmentCreator{
		env:       canonicalCreatedEnvironment(org, project.ID),
		gotInput:  &orgGotInput,
		callCount: &orgCallCount,
	}
	orgHandler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgDeveloperGrantee, Method: auth.MethodAPIKey}, nil, orgCreator)
	allowedRec := postProjectEnvironments(orgHandler, project.ID, "yk_org_dev",
		createProjectEnvironmentRequestBody(t, envID, slug, displayName))
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeCreateProjectEnvironment(t, allowedRec)
	if allowedPayload.Data.Environment.ID != envID ||
		allowedPayload.Data.Environment.Slug != slug ||
		allowedPayload.Data.Environment.OrganizationID != org ||
		allowedPayload.Data.Environment.ProjectID != project.ID {
		t.Errorf("environment = %+v, want (%s, %s, %s, %s)",
			allowedPayload.Data.Environment, envID, slug, org, project.ID)
	}
	if orgCallCount != 1 {
		t.Errorf("creator call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotInput.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			orgGotInput.OrganizationID, org)
	}
	if orgGotInput.ProjectID != project.ID {
		t.Errorf("creator received project id %q, want the path parameter %q",
			orgGotInput.ProjectID, project.ID)
	}
	if orgGotInput.ActorID != "sa_org_dev" {
		t.Errorf("creator received actor id %q, want sa_org_dev — the audit record must name the grantee verbatim",
			orgGotInput.ActorID)
	}

	// And the same project-scoped Admin grantee whose home org id is
	// foreign is denied at the engine: a grant for
	// prj_envs_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to create an
	// environment under prj_envs_matrix_alpha in org_sibling — the
	// cross-tenant guard fires first because the principal's home org
	// no longer matches the grant's scope. This is the engine-level
	// twin of the wire-level "wrong organization" property in
	// TestCreateProjectEnvironmentPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle a write
	// across tenants. CapWrite is outside the support cross-tenant
	// exception, so the deny is unconditional.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentCreate, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.create) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
