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
	"github.com/JuribaDev/yalla/internal/output"
)

// Policy-matrix coverage for GET /v1/projects/{project_id}/variables
// (BE-0144). Where project_variables_test.go proves the endpoint's
// wire contract (BE-0142), this file proves its authorization
// contract: that action env.read cannot be bypassed by — or leak a
// project's variables (and especially secret-variable plaintext)
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries the projectIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and
// the {project_id} PATH parameter. RequireAuth therefore authorizes
// against the project the path names — not merely the principal's
// home organization — and the resource Kind is the project, not the
// variable list. This is the same projectIDResolver-bound posture
// that BE-0138 (projects_grants_policy_test.go) and BE-0141
// (projects_grants_put_policy_test.go) lock in: a scoped grant for
// THIS project authorizes the read while a sibling-project grant is
// rejected at the boundary, and the handler still derives the
// organization id on the store input from the PRINCIPAL'S home org
// (never the caller — there is no request body for a list at all),
// so a cross-tenant project_id reaches the tenant-scoped repository
// query with the principal's home org id and is rejected as a
// deterministic 404 NotFound at the persistence layer by the
// reader's project existence check. A cross-tenant project_id can
// never reveal another organization's variables, and the wire body
// must never echo the foreign org id even though no wire input could
// place it there.
//
// env.read requires CapRead (catalog.go: ActionEnvRead -> CapRead),
// the same capability class as project.read, project.grants.read,
// service.read, limits.read, and usage.read. All six built-in roles
// hold CapRead, so the role matrix for a principal reading variables
// in its own organization is "all allow"; the assertions that matter
// are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home organization id AND the {project_id} path parameter (so
// the tenant-scoped repository query cannot match variables of a
// project in another tenant), the response carries the canonical
// variable list in a stable yalla.output.v1 envelope, and — the
// load-bearing wire distinction from the project-grants matrix —
// secret variable values project as output.Sentinel, never as their
// seeded plaintext.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing env.read against a foreign-tenant resource
// IS allowed via ReasonAllowedBySupport — the same property
// project.read / project.grants.read / limits.read / usage.read
// carry. Every non-support role is denied with ReasonDeniedCrossTenant.
// The customer-facing route under test cannot reach that engine
// branch by construction (projectIDResolver pins the resource scope
// to the PRINCIPAL'S home org, not the path's tenant), but pinning
// the engine verdict here means a future endpoint that resolves the
// resource into a foreign-org scope (a hypothetical admin tool)
// inherits a working cross-tenant deny and the documented support
// exception, and a future catalog change that upgraded env.read above
// CapRead would fail here (silently denying every support cross-tenant
// variable read) before it could regress a real customer.
//
// Unlike project_grants rows (which carry no credential material —
// only structural identifiers and a role enum), project_variables
// rows DO carry credential material in the form of secret values.
// The wire-level redaction chokepoint is projectVariableOf in
// project_variables.go: a row with IsSecret=true projects its Value
// as output.Sentinel rather than the seeded plaintext. The deny-path
// leak guard (variablesDenyBodyLeak) is therefore anchored on the
// SECRET PLAINTEXT (in addition to the canonical variable ids and
// keys), so a future regression that returned the canned reader
// output despite policy denial fails here — the reader's seeded
// plaintext never even reaches the wire because the reader never
// runs on a deny path, but the leak guard catches a renderer that
// would have surfaced it. Tenant-leakage and no-read invariants
// still apply: a denied response never echoes any seeded variable
// id / key / non-secret value, the foreign tenant's id, or the
// canonical project's slug / display name; and the reader MUST
// never run on any deny path — a scoped key denied on the wire
// cannot have surfaced a variable row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, projectIDResolver, or the engine fails here.
// listProjectVariablesHandlerFor, getProjectVariables,
// decodeListProjectVariables, seedProjectVariableWire,
// fakeProjectVariableReader, orgPrincipal, seedProject, and
// decodeError are shared with the project-variables contract suite
// (project_variables_test.go) and the wider httpapi test fixtures;
// this file adds no scaffolding beyond the small fixture builders
// below.

// canonicalVariablesProject is the project every test in this file
// resolves the {project_id} path parameter to. Its id, slug, and
// display name are deliberately distinct from canonicalGrantsProject
// (used by projects_grants_policy_test.go) so the two matrices
// cannot accidentally share fixture state through a future shared
// fake, and they are deliberately recognisable so deny-path leak
// guards can needle for them; allow-path assertions compare against
// the same canonical values.
func canonicalVariablesProject(orgID string) store.Project {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 7, 8, 9, 0, time.UTC)
	return seedProject("prj_vars_matrix_alpha", orgID, "vars-matrix-alpha", "Vars Matrix Alpha", 17, created, updated)
}

// canonicalVariablesSecretPlaintext is the seeded plaintext of the
// secret variable canonicalProjectVariables returns. It MUST never
// appear on the wire — projectVariableOf replaces IsSecret=true
// values with output.Sentinel — and it is the load-bearing needle
// variablesDenyBodyLeak watches for. A regression in the redaction
// chokepoint or a denied response that accidentally surfaced the
// reader's row would render this plaintext, and the leak guard
// would catch it.
const canonicalVariablesSecretPlaintext = "postgres://user:hunter2@db.internal/vars-matrix"

// canonicalProjectVariables is the variable list every test in this
// file would receive back from the reader on an allow path. It mixes
// a secret DATABASE_URL with a non-secret REGION so the wire
// projection exercises the redaction chokepoint on the secret row
// and the verbatim pass-through on the non-secret row. Deny-path
// leak guards needle for the distinctive variable ids, keys, the
// non-secret value, AND the secret plaintext so an accidental render
// — even a partial one — fails the test.
func canonicalProjectVariables(orgID, projectID string) []store.ProjectVariable {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return []store.ProjectVariable{
		seedProjectVariableWire("pvar_matrix_db", orgID, projectID, "DATABASE_URL", canonicalVariablesSecretPlaintext, true, 5, created, updated),
		seedProjectVariableWire("pvar_matrix_region", orgID, projectID, "REGION", "us-matrix-1", false, 2, created, created),
	}
}

// variablesDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical project or its
// variables, OR — the load-bearing addition over grantsDenyBodyLeak
// — the secret variable's plaintext. A denied response that
// accidentally rendered any of these fails the test:
//   - the variable row's existence (and the key it names) is itself
//     information a denied principal must not receive, and
//   - a denied response that surfaced the secret PLAINTEXT would
//     blow the env.read redaction contract — even though
//     projectVariableOf is the chokepoint and the reader never runs
//     on a deny path, the leak guard anchors the contract against
//     any future regression that bypassed both invariants.
//
// The quoted forms catch a case-collapsing renderer regression.
// There is no request body for GET /v1/projects/{project_id}/variables,
// so unlike a write-path leak guard there is no caller-supplied
// request-body field to protect.
func variablesDenyBodyLeak(body string) bool {
	needles := []string{
		"prj_vars_matrix_alpha",
		"\"vars-matrix-alpha\"",
		"\"Vars Matrix Alpha\"",
		"pvar_matrix_db",
		"pvar_matrix_region",
		"\"DATABASE_URL\"",
		"\"REGION\"",
		"\"us-matrix-1\"",
		canonicalVariablesSecretPlaintext,
		"hunter2",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListProjectVariablesPolicyMatrixRoles drives every built-in
// role through the production request path. All six built-in roles
// hold CapRead, so the matrix is "all allow" for a principal reading
// variables of a project in its own organization; the assertions
// that matter are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {project_id} path parameter (so a
// tenant-scoped store query cannot match a foreign row), the
// response is a stable 200 yalla.output.v1 envelope carrying the
// canonical variable list, and — the load-bearing wire distinction
// from the project-grants matrix — secret variable values project
// as output.Sentinel rather than the seeded plaintext. A regression
// in projectVariableOf that forgot to redact would fail here even
// before any deny-path leak guard fires.
func TestListProjectVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	vars := canonicalProjectVariables(org, project.ID)
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
			// reading variables in ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support cross-tenant exception
			// is exercised in
			// TestListProjectVariablesPolicyWrongOrganizationPrincipal.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvRead, projectResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(env.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotProj string
			callCount := 0
			reader := fakeProjectVariableReader{
				vars:         vars,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listProjectVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getProjectVariables(handler, project.ID, "a-valid-token")

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
			env := decodeListProjectVariables(t, rec)
			if len(env.Data.Variables) != len(vars) {
				t.Fatalf("variables len = %d, want %d; body %s",
					len(env.Data.Variables), len(vars), rec.Body.String())
			}
			// Spot-check the projection lands the load-bearing fields
			// of both rows: the secret row's Value MUST be the
			// Sentinel (a redaction regression in projectVariableOf
			// fails here) and its plaintext MUST NOT appear anywhere
			// in the response body (a renderer regression that
			// double-emitted the row in a non-canonical field fails
			// here too). The non-secret row's Value MUST be the
			// seeded plaintext (over-redaction must not silently
			// erase non-secret values).
			got0 := env.Data.Variables[0]
			if got0.ID != "pvar_matrix_db" || got0.Key != "DATABASE_URL" || !got0.IsSecret {
				t.Errorf("got[0] = %+v, want pvar_matrix_db / DATABASE_URL / IsSecret=true", got0)
			}
			if got0.Value != output.Sentinel {
				t.Errorf("got[0].value = %q, want the redaction sentinel %q — projectVariableOf must redact secret values on the wire",
					got0.Value, output.Sentinel)
			}
			got1 := env.Data.Variables[1]
			if got1.ID != "pvar_matrix_region" || got1.Key != "REGION" || got1.IsSecret {
				t.Errorf("got[1] = %+v, want pvar_matrix_region / REGION / IsSecret=false", got1)
			}
			if got1.Value != "us-matrix-1" {
				t.Errorf("got[1].value = %q, want the seeded non-secret plaintext %q — non-secret values must project verbatim",
					got1.Value, "us-matrix-1")
			}
			if body := rec.Body.String(); strings.Contains(body, canonicalVariablesSecretPlaintext) || strings.Contains(body, "hunter2") {
				t.Errorf("response body %s leaked the secret plaintext — the redaction chokepoint must hold on every allow path too",
					body)
			}
		})
	}
}

// TestListProjectVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action env.read with a stable 403 E_FORBIDDEN,
// even when the underlying role would have allowed it. A revoked or
// expired credential must never be able to list variables of a
// project of the organization it once had access to, the reader must
// never run, and the denied body must never echo the principal id,
// the organization id, the path-supplied project id, any seeded
// variable data, or — the load-bearing redaction-contract anchor —
// the secret plaintext.
//
// Underlying role is Owner so a working credential WOULD allow
// env.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0144 ("revoked key,
// expired key").
func TestListProjectVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	vars := canonicalProjectVariables(org, project.ID)

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
			reader := fakeProjectVariableReader{
				vars:         vars,
				gotOrgID:     &gotOrg,
				gotProjectID: &gotProj,
				callCount:    &callCount,
			}
			handler := listProjectVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getProjectVariables(handler, project.ID, "yk_no_longer_valid")

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
				variablesDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, seeded variable data, or the secret plaintext", body)
			}
		})
	}
}

// TestListProjectVariablesPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for env.read on the project variables route.
// As with project.read and project.grants.read, the resource org id
// is taken from the PRINCIPAL'S home org — the {project_id} path
// parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/projects/{prj_victim}/variables with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapRead — and then
//     reaches the tenant-scoped repository query with the principal's
//     home org id and the foreign project id. The store-backed reader
//     Gets the project under (organization_id, project_id) before
//     listing its variables, so a cross-tenant project_id is rejected
//     as a deterministic 404 E_NOT_FOUND, never disguised as an empty
//     success — which would invite an agent to believe the project
//     exists with no variables. The body must never echo the foreign
//     org id even though no wire input could place it there, because
//     the persistence layer must not leak foreign-tenant identity
//     into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). Pinning
//     that engine verdict here means the eventual scoped variant
//     inherits a working cross-tenant deny and the documented
//     support exception, and a future catalog change that upgraded
//     env.read above CapRead would fail here (silently denying every
//     support cross-tenant variable read) before it could regress a
//     real customer.
func TestListProjectVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_vars"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/projects/{prj_victim}/variables with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, projectID) pair does
	// not match a row (the reader's project existence check fires
	// first), so a principal whose home org is org_attacker listing
	// variables of a project that belongs to org_victim hits the
	// fake with (org_attacker, prj_victim_vars) and gets NotFound.
	// The assertions that matter are structural: the reader is
	// ALWAYS called with the principal's home org id — never with
	// a caller-controlled value — so a production tenant-scoped
	// ProjectVariableReader could not have surfaced the victim's
	// variables regardless of database state. The denied body must
	// never echo the victim's org id.
	var gotOrg, gotProj string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeProjectVariableReader{
		err:          apierr.NotFound("project", foreignProjID),
		gotOrgID:     &gotOrg,
		gotProjectID: &gotProj,
		callCount:    &callCount,
	}
	handler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getProjectVariables(handler, foreignProjID, "a-valid-token")

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
	// scope inherits a working cross-tenant deny. env.read is CapRead,
	// so the engine clause `CapSupport && (CapRead || CapSupport)`
	// admits Support and denies every non-support role.
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
			got := e.Decide(p, policy.ActionEnvRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(env.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches env.read because the
	// catalog maps it to CapRead. This locks the CapRead requirement
	// against the support cross-tenant path so a future catalog
	// change that upgraded env.read above CapRead would fail here
	// (silently denying every support cross-tenant variable read)
	// before it could regress a real customer. The customer-facing
	// route under test cannot reach this engine branch by
	// construction — projectIDResolver pins the resource scope to
	// the principal's own home org — but the engine verdict is the
	// authoritative source of the documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(env.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListProjectVariablesPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production unless production is explicitly granted, a service grant
// does not reach the parent environment or a sibling service.
//
// Crucially for GET /v1/projects/{project_id}/variables: env.read is
// evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}). This is the load-bearing
// distinction from a route that resolved into a deeper scope (an
// environment- or service-level variable route): here a project-
// level Viewer grant naming THIS project authorizes the read, but a
// deeper-scope grant cannot — covers() is one-way, so an env- or
// service-scoped grant does not contain the parent-project resource.
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
//     escalate to listing the parent project's variables (which sit
//     at the project layer of the Org → Project → Env → Service
//     variable hierarchy and are therefore the second-from-lowest
//     precedence layer the Dokploy renderer composes — a layer the
//     env grantee was never authorized for).
//   - A service-level grant likewise does NOT cover a project
//     resource and does not expose the parent environment's secrets
//     through env.write either — the "service grant does not expose
//     parent-level secrets or unrelated services" property; here it
//     pins that a service-scoped key cannot escalate to listing the
//     parent project's secret variables through this endpoint, even
//     if its own service-level env.write would normally be authorized
//     for the service it names.
//   - An organization-level Viewer grant DOES cover any project
//     resource within the same org and — because env.read is CapRead
//     and Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, service grant
// shielding parent-level secrets — are pinned against the engine,
// then tied back to the wire by proving the reader is never reached
// on any deny path (so a production store could not have surfaced
// variables in the background and the secret plaintext never reached
// the wire) and the denied body never echoes the canonical project's
// or variables' identifiers — including the secret plaintext, the
// load-bearing redaction anchor.
func TestListProjectVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	vars := canonicalProjectVariables(org, project.ID)
	e := policy.NewEngine()

	// Project-level grant: viewer on prj_vars_matrix_alpha only.
	// Viewer confers CapRead at the project scope, which is exactly
	// what env.read needs. The sibling-project property is pinned
	// for env.read directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_vars_matrix_beta"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for a sibling project = %+v, want deny via %q — a project-scoped viewer grant must not reach prj_vars_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant
	// scope, so covers() does not reach it for env.read.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for an environment-scoped grantee against the parent project = %+v, want deny via %q — an env grant must not reach the parent project's variable list",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(env.write) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not expose parent-level
	// env.write, and must not allow env.read on the parent project
	// (which would expose the project-scoped secret variables this
	// endpoint redacts on the wire).
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
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for a service-scoped grantee against the parent project = %+v, want deny via %q — a service grant must not reach the parent project's variable list (where secrets live one layer up)",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// TARGET project is a 200 with the canonical variable list, the
	// reader is reached with (home_org, target_project_id), the
	// response carries the variables, and the secret row's value is
	// the redaction sentinel — the project-scoped Viewer grant
	// confers exactly CapRead at the project scope, but the wire
	// redaction chokepoint still hides the secret plaintext.
	var targetGotOrg, targetGotProj string
	targetCallCount := 0
	targetReader := fakeProjectVariableReader{
		vars:         vars,
		gotOrgID:     &targetGotOrg,
		gotProjectID: &targetGotProj,
		callCount:    &targetCallCount,
	}
	targetHandler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, targetReader)
	targetRec := getProjectVariables(targetHandler, project.ID, "yk_proj_viewer_scoped")
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
	targetEnv := decodeListProjectVariables(t, targetRec)
	if len(targetEnv.Data.Variables) != len(vars) {
		t.Errorf("variables len = %d, want %d", len(targetEnv.Data.Variables), len(vars))
	}
	if v0 := targetEnv.Data.Variables[0]; v0.Value != output.Sentinel {
		t.Errorf("got[0].value = %q, want the redaction sentinel %q on the project-scoped viewer allow path too",
			v0.Value, output.Sentinel)
	}
	if body := targetRec.Body.String(); strings.Contains(body, canonicalVariablesSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("allow-path response body %s leaked the secret plaintext — the redaction chokepoint must hold for scoped grantees too",
			body)
	}

	// Wire tie-in #2: the SAME project-scoped Viewer grantee hitting
	// a SIBLING project is a 403 with the stable out-of-scope reason,
	// the reader is never reached (so a production store could never
	// have surfaced sibling variables — or secret plaintext — in the
	// background), and the body never echoes the canonical project's
	// or variables' identifiers. This is the property that makes the
	// policy boundary — not the persistence boundary — the structural
	// place a scoped key is denied access to a sibling project's
	// variables.
	var siblingGotOrg, siblingGotProj string
	siblingCallCount := 0
	siblingReader := fakeProjectVariableReader{
		vars:         vars, // would be returned if reader ran — leak guard catches it
		gotOrgID:     &siblingGotOrg,
		gotProjectID: &siblingGotProj,
		callCount:    &siblingCallCount,
	}
	siblingHandler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, siblingReader)
	siblingRec := getProjectVariables(siblingHandler, "prj_vars_matrix_beta", "yk_proj_viewer_scoped")
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
	if body := siblingRec.Body.String(); variablesDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, variables, or secret plaintext: %s", body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent
	// project is a 403 with ReasonDeniedOutOfScope and the reader is
	// never reached. The leak guard catches an accidental render of
	// the canonical variables — including the secret plaintext — even
	// though the env grantee never had project-read coverage at all.
	var envGotOrg, envGotProj string
	envCallCount := 0
	envReader := fakeProjectVariableReader{
		vars:         vars,
		gotOrgID:     &envGotOrg,
		gotProjectID: &envGotProj,
		callCount:    &envCallCount,
	}
	envHandler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getProjectVariables(envHandler, project.ID, "yk_env_scoped")
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
	if body := envRec.Body.String(); variablesDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, variables, or secret plaintext: %s", body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the reader is never reached, and the body
	// never echoes parent-level identifiers — including the secret
	// plaintext that sits one layer up from the service the grant
	// names. This is the property that keeps a service-scoped key
	// from escalating to a parent-project variable read through this
	// endpoint — the "service grant does not expose parent-level
	// secrets or unrelated services" acceptance criterion tied back
	// to the wire on the variables route, where parent-level secrets
	// are exactly the data the policy boundary is protecting.
	var svcGotOrg, svcGotProj string
	svcCallCount := 0
	svcReader := fakeProjectVariableReader{
		vars:         vars,
		gotOrgID:     &svcGotOrg,
		gotProjectID: &svcGotProj,
		callCount:    &svcCallCount,
	}
	svcHandler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getProjectVariables(svcHandler, project.ID, "yk_svc_scoped")
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
	if body := svcRec.Body.String(); variablesDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, variables, or secret plaintext: %s", body)
	}

	// An organization-level Viewer grant DOES cover any project
	// resource in the same org and — because env.read is CapRead and
	// Viewer holds CapRead — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the reader
	// reached on the principal's home org id and the path project id,
	// AND the secret row still projects as output.Sentinel. This
	// locks the CapRead requirement against the grant path so a
	// future catalog change that upgraded env.read above CapRead
	// would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer, and pins
	// that the wire redaction chokepoint is independent of how the
	// principal earned authority (role vs. org-level grant vs.
	// project-level grant).
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotProj string
	orgCallCount := 0
	orgReader := fakeProjectVariableReader{
		vars:         vars,
		gotOrgID:     &orgGotOrg,
		gotProjectID: &orgGotProj,
		callCount:    &orgCallCount,
	}
	orgHandler := listProjectVariablesHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getProjectVariables(orgHandler, project.ID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeListProjectVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != len(vars) {
		t.Errorf("variables len = %d, want %d", len(allowedPayload.Data.Variables), len(vars))
	}
	if v0 := allowedPayload.Data.Variables[0]; v0.Value != output.Sentinel {
		t.Errorf("got[0].value = %q, want the redaction sentinel %q on the org-level viewer grant allow path too",
			v0.Value, output.Sentinel)
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
	if body := allowedRec.Body.String(); strings.Contains(body, canonicalVariablesSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("org-level viewer allow-path response body %s leaked the secret plaintext — the redaction chokepoint must hold independent of how authority was earned",
			body)
	}

	// And the same project-scoped viewer grantee whose home org id
	// is foreign is denied at the engine: a grant for
	// prj_vars_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to list
	// variables of prj_vars_matrix_alpha in org_sibling — the
	// cross-tenant guard fires first because the principal's home
	// org no longer matches the grant's scope. This is the
	// engine-level twin of the wire-level "wrong organization"
	// property in TestListProjectVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (env.read IS inside the support cross-tenant
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
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
