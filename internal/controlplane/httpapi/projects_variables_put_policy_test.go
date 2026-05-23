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

// Policy-matrix coverage for PUT /v1/projects/{project_id}/variables
// (BE-0147). Where project_variables_test.go proves the endpoint's
// wire contract (BE-0145/0146) and projects_variables_get_policy_test.go
// proves the reader-side authorization contract (BE-0144), this file
// proves the writer-side authorization contract: that action env.write
// cannot be bypassed by — or leak (a) the project's existing variables
// (and especially secret-variable plaintext from a post-write re-read),
// or (b) the caller-supplied replacement set, because of — the
// principal's role, revoked credentials, home organization, or scoped
// grants.
//
// The route carries the projectIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {project_id} PATH parameter. RequireAuth therefore authorizes against
// the project the path names — not merely the principal's home
// organization — and the resource Kind is the project, not the variable
// list. A scoped grant for THIS project authorizes the write while a
// sibling-project grant is rejected at the boundary, and the handler
// still derives the OrganizationID on the store input from the
// PRINCIPAL'S home org (never the caller — the request body carries no
// organization id at all), so a cross-tenant {project_id} reaches the
// tenant-scoped repository query with the principal's home org id and
// is rejected as a deterministic 404 NotFound at the persistence layer
// by the project existence check inside the replacer transaction. A
// cross-tenant {project_id} can never overwrite another organization's
// variables, and the wire body must never echo the foreign org id, the
// caller-supplied replacement set, or the seeded post-write rows even
// though the engine has admitted the same-tenant resource scope by
// construction.
//
// env.write requires CapWrite (catalog.go: ActionEnvWrite -> CapWrite),
// the same capability class as project.delete, project.update, and the
// org-level PUT /v1/organizations/{org_id}/variables surface. Owner,
// Admin, and Developer hold CapWrite at the role layer; Viewer, CI,
// and Support do NOT (CI holds CapSelf/CapRead/CapDeploy — deploys are
// CapDeploy actions; variable replacement is a CapWrite action). The
// role matrix for a principal in its own organization is therefore
// "owner/admin/developer allow, viewer/ci/support deny": the
// load-bearing difference from env.read (CapRead, all six allow) — and
// from project.grants.write (CapAdmin, only owner/admin allow) — is
// that Developer JOINS the allow set at the role boundary (it holds
// CapWrite, not CapAdmin) while CI DOES NOT (CI does not hold
// CapWrite). A regression that downgraded env.write below CapWrite
// would silently let viewers and CI keys overwrite variables and would
// fail this test on Viewer/CI/Support; one that upgraded it above
// CapWrite would silently lock developers out and would fail on
// Developer.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapWrite is OUTSIDE that exception, so EVERY role —
// including Support — is denied cross-tenant for env.write via
// ReasonDeniedCrossTenant. This is the same posture as
// project.grants.write (CapAdmin, also outside the exception) and the
// org-level env.write (BE-0111): the documented support cross-tenant
// READ exception explicitly does NOT extend to writes. The
// customer-facing route under test cannot reach the engine's
// cross-tenant branch by construction (projectIDResolver pins the
// resource scope to the PRINCIPAL'S home org, not the path's tenant),
// but pinning the engine verdict here means a future endpoint that
// resolves the resource into a foreign-org scope (a hypothetical admin
// tool) inherits a working cross-tenant deny for support too, and a
// future catalog change that downgraded env.write to CapRead would
// fail here (silently letting support cross-tenant variable writes
// through) before it could regress a real customer.
//
// Like project_variables on the read side, project_variables rows on
// the write side carry credential material. The endpoint re-reads the
// committed variables in the same transaction and renders them through
// the same projectVariableOf chokepoint, so an allow path STILL
// redacts secret values to output.Sentinel on the wire — a customer
// cannot read back a secret value they just submitted. The deny-path
// leak guards anchor on three orthogonal needles: (a) the caller-
// supplied request body's distinctive key/value (envWriteProjectPutBody),
// so a denied write does not echo what the caller submitted; (b) the
// canonical project's id / slug / display name and the per-row ids /
// keys of the seeded post-write fixture, so a denied write does not
// surface the data the replacer would have returned; and (c) the
// recognisable fragments of the seeded post-write SECRET PLAINTEXT, so
// a denied write does not leak a secret plaintext through this
// endpoint even if a future regression bypassed projectVariableOf. The
// replacer MUST never run on any deny path — a denied caller cannot
// have caused any database mutation, audit row, or post-write read in
// the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, projectIDResolver, or the engine fails here.
// replaceProjectVariablesHandlerFor, putProjectVariables,
// decodeReplaceProjectVariables, fakeProjectVariableReplacer,
// orgPrincipal, seedProject, canonicalVariablesProject, and decodeError
// are shared with the project-variables contract suite
// (project_variables_test.go) and the GET policy matrix
// (projects_variables_get_policy_test.go); this file adds no
// scaffolding beyond the small fixture builders below.

// envWriteProjectPutBody is the minimal valid request body the matrix
// tests send: a single non-secret variable. The distinctive key
// (MATRIX_KEY) and value (matrix_value) are deliberately recognisable
// so deny-path leak checks can prove the submitted payload is not
// echoed back, and they intentionally do NOT collide with
// seededPostWriteProjectVariables' returned rows — only the seeded
// post-write fixture is the "data" the replacer would have returned,
// so deny paths must never echo that fixture either.
const envWriteProjectPutBody = `{"variables":[{"key":"MATRIX_KEY","value":"matrix_value"}]}`

// seededPostWriteProjectVariables is the rows the fake
// ProjectVariableReplacer returns on the allow paths — the post-write
// re-read result the production unit of work would produce. It mixes a
// non-secret REGION row with a secret DATABASE_URL row whose plaintext
// is distinctive (post-write-plaintext-correcthorsebatterystaple), so
// the allow-path wire test exercises the redaction chokepoint on the
// secret row and the verbatim pass-through on the non-secret row, and
// the deny-path leak guards needle for each row id and key — plus the
// secret plaintext — so a regression that surfaced the replacer's
// fixture would trip the guard. The fixture is intentionally distinct
// from canonicalProjectVariables (used by the GET matrix) so the two
// matrices cannot accidentally share fixture state through a future
// shared fake; the long secret plaintext is split into recognisable
// fragments so a partial leak that drops only one piece still fails.
func seededPostWriteProjectVariables(orgID, projectID string) []store.ProjectVariable {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return []store.ProjectVariable{
		seedProjectVariableWire("pvar_post_region", orgID, projectID, "POST_WRITE_REGION", "eu-west-3", false, 2, created, updated),
		seedProjectVariableWire("pvar_post_secret", orgID, projectID, "POST_WRITE_SECRET", "post-write-plaintext-correcthorsebatterystaple", true, 2, created, updated),
	}
}

// postWriteProjectVariablesBodyLeak reports whether body contains any
// non-public value from seededPostWriteProjectVariables — the per-row
// ids, the variable keys, the non-secret value, and crucially every
// recognisable fragment of the secret value — OR the canonical
// variables project's id / slug / display name. A denied response that
// accidentally rendered any of these fails the test; the policy
// boundary is the only place a write is gated, so a denied caller
// seeing the seeded post-write data would itself be a contract
// violation. The secret-value needles split the long string into
// distinct substrings so a partial leak that drops only one piece still
// trips the guard. The literal "true" is deliberately NOT in this list
// because it is the JSON encoding of every boolean field.
func postWriteProjectVariablesBodyLeak(body string) bool {
	needles := []string{
		"prj_vars_matrix_alpha",
		"\"vars-matrix-alpha\"",
		"\"Vars Matrix Alpha\"",
		"pvar_post_region", "pvar_post_secret",
		"POST_WRITE_REGION", "POST_WRITE_SECRET",
		"eu-west-3",
		"post-write-plaintext-correcthorsebatterystaple",
		"correcthorsebatterystaple", "post-write-plaintext",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestReplaceProjectVariablesPolicyMatrixRoles drives every built-in
// role through the production request path against a {project_id} that
// names a project in the principal's own home organization. Owner,
// Admin, and Developer hold CapWrite and allow env.write via
// ReasonAllowedByRole — the replacer is reached with (home_org,
// path_project_id, actor.id) and the response carries the seeded
// post-write rows. Viewer, CI, and Support all lack CapWrite (CI holds
// CapDeploy, not CapWrite — deploys are a distinct capability from
// variable mutation) and are denied with a stable 403 E_FORBIDDEN
// carrying ReasonDeniedNoCapability — and in every deny path the
// replacer is never reached, so the policy boundary is the only place
// a project-scoped variable mutation can be authorized for a non-
// CapWrite caller. The allow-path wire assertions also pin the
// redaction chokepoint: the secret post-write row projects as
// output.Sentinel, not its seeded plaintext — a regression in
// projectVariableOf that forgot to redact would fail here even before
// any deny-path leak guard fires.
//
// This is the load-bearing difference from env.read (CapRead, all
// roles allow) and from project.grants.write (CapAdmin, only
// owner/admin allow): Developer JOINS the allow set at the role
// boundary while CI joins the deny set (CI carries CapDeploy but not
// CapWrite — a deliberate split that keeps a deploy-only key from
// reaching into variable replacement). A regression that downgraded
// env.write below CapWrite would silently let viewers and CI keys
// overwrite variables and would fail this test on Viewer/CI/Support;
// one that upgraded it above CapWrite would silently lock developers
// out and would fail on Developer.
func TestReplaceProjectVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	postWrite := seededPostWriteProjectVariables(org, project.ID)
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
			// same-tenant project resource carries the principal's home
			// org id, so the cross-tenant clause does not fire; the
			// allow/deny verdict is determined purely by whether the
			// role's capability set contains CapWrite.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvWrite, projectResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(env.write) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(env.write) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.ReplaceProjectVariablesInput
			callCount := 0
			replacer := fakeProjectVariableReplacer{
				vars:      postWrite,
				got:       &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := replaceProjectVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, replacer)
			rec := putProjectVariables(handler, project.ID, "a-valid-token", envWriteProjectPutBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200 for %s; body %s",
						rec.Code, tc.name, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("replacer call count = %d, want 1 on the allow path for %s",
						callCount, tc.name)
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
				if len(captured.Variables) != 1 || captured.Variables[0].Key != "MATRIX_KEY" || captured.Variables[0].Value != "matrix_value" {
					t.Errorf("replacer received variables = %+v, want one MATRIX_KEY=matrix_value",
						captured.Variables)
				}
				env := decodeReplaceProjectVariables(t, rec)
				if len(env.Data.Variables) != len(postWrite) {
					t.Fatalf("variables len = %d, want %d; body %s",
						len(env.Data.Variables), len(postWrite), rec.Body.String())
				}
				got0 := env.Data.Variables[0]
				if got0.ID != "pvar_post_region" || got0.Key != "POST_WRITE_REGION" || got0.IsSecret {
					t.Errorf("got[0] = %+v, want pvar_post_region / POST_WRITE_REGION / IsSecret=false",
						got0)
				}
				if got0.Value != "eu-west-3" {
					t.Errorf("got[0].value = %q, want the seeded non-secret plaintext %q — non-secret values must project verbatim",
						got0.Value, "eu-west-3")
				}
				got1 := env.Data.Variables[1]
				if got1.ID != "pvar_post_secret" || got1.Key != "POST_WRITE_SECRET" || !got1.IsSecret {
					t.Errorf("got[1] = %+v, want pvar_post_secret / POST_WRITE_SECRET / IsSecret=true",
						got1)
				}
				if got1.Value != output.Sentinel {
					t.Errorf("got[1].value = %q, want the redaction sentinel %q — projectVariableOf must redact secret values on the wire even on PUT",
						got1.Value, output.Sentinel)
				}
				if body := rec.Body.String(); strings.Contains(body, "post-write-plaintext") ||
					strings.Contains(body, "correcthorsebatterystaple") {
					t.Errorf("allow-path response body %s leaked the secret plaintext for role %s — the redaction chokepoint must hold on every allow path",
						body, tc.name)
				}
			} else {
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 for %s; body %s",
						rec.Code, tc.name, rec.Body.String())
				}
				errEnv := decodeError(t, rec, "E_FORBIDDEN")
				if !strings.Contains(errEnv.Error.Message, string(tc.reason)) {
					t.Errorf("message = %q, want it to carry the stable reason %q",
						errEnv.Error.Message, tc.reason)
				}
				if callCount != 0 || captured.OrganizationID != "" || captured.ProjectID != "" {
					t.Errorf("replacer was reached (calls=%d org=%q project=%q) for a non-CapWrite principal; it must never run",
						callCount, captured.OrganizationID, captured.ProjectID)
				}
				if body := rec.Body.String(); strings.Contains(body, "MATRIX_KEY") ||
					strings.Contains(body, "matrix_value") ||
					postWriteProjectVariablesBodyLeak(body) {
					t.Errorf("denied response for %s leaked the submitted payload, the canonical project, the seeded post-write rows, or the secret plaintext: %s",
						tc.name, body)
				}
			}
		})
	}
}

// TestReplaceProjectVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both of
// which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action env.write with a stable 403 E_FORBIDDEN,
// even when the underlying role would have allowed it. A revoked or
// expired credential must never be able to overwrite variables of a
// project of the organization it once had access to, the replacer must
// never run, and the denied body must never echo the principal id, the
// organization id, the path-supplied project id, the caller-supplied
// replacement set, the seeded post-write fixture, or — the load-bearing
// redaction-contract anchor — the secret plaintext.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0147 ("revoked key,
// expired key").
func TestReplaceProjectVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	postWrite := seededPostWriteProjectVariables(org, project.ID)

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

			var captured store.ReplaceProjectVariablesInput
			callCount := 0
			replacer := fakeProjectVariableReplacer{
				vars:      postWrite,
				got:       &captured,
				callCount: &callCount,
			}
			handler := replaceProjectVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)
			rec := putProjectVariables(handler, project.ID, "yk_no_longer_valid", envWriteProjectPutBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ProjectID != "" {
				t.Errorf("replacer was reached (calls=%d org=%q project=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ProjectID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				strings.Contains(body, "MATRIX_KEY") ||
				strings.Contains(body, "matrix_value") ||
				postWriteProjectVariablesBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, submitted payload, canonical project, seeded post-write rows, or the secret plaintext",
					body)
			}
		})
	}
}

// TestReplaceProjectVariablesPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for env.write on the project variables route.
// As with project.delete, project.update, and project.grants.write, the
// resource org id is taken from the PRINCIPAL'S home org — the
// {project_id} path parameter alone never widens the resource to
// another tenant. Tenant isolation on the wire is therefore structural
// at the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PUT
//     /v1/projects/{prj_victim}/variables with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     prj_victim}) — allowed by the role at CapWrite — and then reaches
//     the tenant-scoped repository query with the principal's home org
//     id and the foreign project id. The store-backed replacer Gets
//     the project under (organization_id, project_id) before upserting
//     and re-reading variables, so a cross-tenant project_id is
//     rejected as a deterministic 404 E_NOT_FOUND, never disguised as
//     a 200 with foreign data — which would let an attacker discover a
//     project's existence cross-tenant — and never as a 403 that would
//     itself confirm existence. The body must never echo the foreign
//     org id, the caller-supplied replacement set, or the seeded
//     post-write rows even though no wire input could place them
//     there: the persistence layer must not leak foreign-tenant
//     identity or fixture data into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY role — INCLUDING Support
//     — MUST be denied via ReasonDeniedCrossTenant. env.write is
//     CapWrite, which is OUTSIDE the engine clause `CapSupport &&
//     (CapRead || CapSupport)`. This is the load-bearing distinction
//     from env.read (which IS inside the support exception): a support
//     principal can list another tenant's variables but cannot replace
//     them. Pinning that engine verdict here means a future endpoint
//     that resolves the resource into a foreign-org scope inherits a
//     working cross-tenant deny for support too, and a future catalog
//     change that downgraded env.write to CapRead would fail here
//     (silently letting support cross-tenant variable writes through)
//     before it could regress a real customer.
func TestReplaceProjectVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignProjID   = "prj_victim_vars"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PUT
	// /v1/projects/{prj_victim}/variables with a valid Owner token. The
	// fake mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, projectID) pair does not match a
	// row (the replacer's project existence check fires first), so a
	// principal whose home org is org_attacker replacing variables of a
	// project that belongs to org_victim hits the fake with
	// (org_attacker, prj_victim_vars) and gets NotFound. The
	// assertions that matter are structural: the replacer is ALWAYS
	// called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ProjectVariableReplacer could not have replaced the victim's
	// variables regardless of database state. The denied body must
	// never echo the victim's org id, the caller-supplied replacement
	// set, or the seeded post-write rows.
	var captured store.ReplaceProjectVariablesInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	replacer := fakeProjectVariableReplacer{
		err:       apierr.NotFound("project", foreignProjID),
		got:       &captured,
		callCount: &callCount,
	}
	handler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, replacer)
	rec := putProjectVariables(handler, foreignProjID, "a-valid-token", envWriteProjectPutBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant project_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("replacer call count = %d, want 1 — the replacer runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign project id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("replacer received org id %q, want the attacker's home org %q — the replacer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ProjectID != foreignProjID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			captured.ProjectID, foreignProjID)
	}
	if captured.ActorOrgID != ownOrg {
		t.Errorf("replacer received actor org id %q, want the attacker's home org %q — actor identity must derive from the principal, never the path",
			captured.ActorOrgID, ownOrg)
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
	if strings.Contains(body, "MATRIX_KEY") || strings.Contains(body, "matrix_value") {
		t.Errorf("response body %s echoed the caller-supplied replacement set — a denied write must not turn into a request-reflecting oracle",
			body)
	}
	if postWriteProjectVariablesBodyLeak(body) {
		t.Errorf("response body %s leaked the canonical project, seeded post-write rows, or secret plaintext", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. env.write is CapWrite,
	// which is OUTSIDE the engine clause `CapSupport && (CapRead ||
	// CapSupport)` — so EVERY role, INCLUDING Support, is denied
	// cross-tenant. This is the load-bearing distinction from
	// env.read (CapRead, support IS allowed cross-tenant): a support
	// principal can list another tenant's variables but cannot replace
	// them.
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
			got := e.Decide(p, policy.ActionEnvWrite, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(env.write, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestReplaceProjectVariablesPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for. A
// scoped API key is authorized purely by its grants (it carries no
// organization role); the engine confines those grants — a project
// grant does not reach a sibling project, an environment grant does
// not reach production unless production is explicitly granted, a
// service grant does not reach the parent environment or a sibling
// service.
//
// Crucially for PUT /v1/projects/{project_id}/variables: env.write is
// evaluated against a PROJECT-level resource (the projectIDResolver
// scope is {home_org, path_project_id}). This is the load-bearing
// distinction from a route that resolved into a deeper scope (an
// environment- or service-level variable route): here a project-level
// Developer (or higher) grant naming THIS project authorizes the
// write, but a deeper-scope grant cannot — covers() is one-way, so an
// env- or service-scoped grant does not contain the parent-project
// resource.
//
//   - A project-level Developer grant naming THIS project CAN authorize
//     the write (ReasonAllowedByGrant), and at the wire the replacer
//     receives (home_org, target_project_id, principal_id) — the grant
//     scope contains the resource scope and CapWrite is conferred. A
//     project-level Viewer grant at the same scope CANNOT — Viewer
//     holds CapRead, not CapWrite — even for the key's own project.
//   - A project-level grant naming a SIBLING project CANNOT — covers()
//     is one-way, so the grant scope does not contain the resource
//     scope. The denial is ReasonDeniedOutOfScope (the principal holds
//     the capability somewhere, just not here).
//   - An environment-level grant does NOT cover a project resource
//     (covers() is one-way: a deeper scope cannot reach a shallower
//     resource). It is denied ReasonDeniedOutOfScope — the "env grant
//     does not imply access to production unless production is
//     explicitly granted" property still applies here: even an env
//     grant on the same project's production environment cannot
//     escalate to replacing the parent project's variables (which sit
//     at the project layer of the Org → Project → Env → Service
//     variable hierarchy).
//   - A service-level grant likewise does NOT cover a project resource
//     and does not allow env.write on the parent environment — the
//     "service grant does not expose parent-level secrets or unrelated
//     services" property; here it pins that a service-scoped key
//     cannot escalate to overwriting the parent project's variables
//     through this endpoint, even if its own service-level env.write
//     would normally be authorized for the service it names.
//   - An organization-level Developer grant DOES cover any project
//     resource within the same org and — because env.write is CapWrite
//     and Developer holds CapWrite — is allowed via
//     ReasonAllowedByGrant. An organization-level Viewer grant at the
//     same scope is intentionally NOT enough: Viewer holds CapRead,
//     not CapWrite. This locks the CapWrite requirement against the
//     grant path so a future catalog change that downgraded env.write
//     below CapWrite would fail the Viewer-deny assertion here, and
//     one that upgraded it above CapWrite would fail the Developer-
//     allow assertion.
//
// The acceptance criteria's three containment properties — sibling
// project, deeper-scope reaching shallower resource, service grant
// shielding parent-level secrets — are pinned against the engine, then
// tied back to the wire by proving the replacer is never reached on
// any deny path (so a production store could not have surfaced a
// post-write re-read — or secret plaintext — in the background, and
// the caller's submitted payload was never persisted) and the denied
// body never echoes the canonical project's identifiers, the
// caller-supplied replacement set, or the seeded post-write rows —
// including the secret plaintext, the load-bearing redaction anchor.
func TestReplaceProjectVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	project := canonicalVariablesProject(org)
	postWrite := seededPostWriteProjectVariables(org, project.ID)
	e := policy.NewEngine()

	// Project-level grant: developer on prj_vars_matrix_alpha only.
	// Developer confers CapWrite at the project scope, which is exactly
	// what env.write needs. The sibling-project property is pinned for
	// env.write directly.
	scopeTarget := policy.Scope{OrganizationID: org, ProjectID: project.ID}
	scopeSibling := policy.Scope{OrganizationID: org, ProjectID: "prj_vars_matrix_beta"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTarget}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) for the target project = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeSibling}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for a sibling project = %+v, want deny via %q — a project-scoped developer grant must not reach prj_vars_matrix_beta",
			got, policy.ReasonDeniedOutOfScope)
	}

	// A project-level Viewer grant at the same target scope is
	// intentionally NOT enough: Viewer holds CapRead, not CapWrite.
	// This locks the CapWrite requirement against the grant path so a
	// catalog change downgrading env.write to CapRead would fail here.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTarget}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow {
		t.Errorf("Decide(env.write) for a project-scoped viewer grant on the target project = %+v, want deny — Viewer holds CapRead, not CapWrite",
			got)
	}

	// Environment-level grant: admin on the staging environment only;
	// production is NOT covered. A production grant must be issued
	// explicitly — the policy engine never widens a staging grant to
	// production. The parent project is shallower than the grant scope,
	// so covers() does not reach it for env.write.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project.ID, EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for an environment-scoped grantee against the parent project = %+v, want deny via %q — an env grant must not reach the parent project's variable list",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("Decide(env.write) for an env-scoped staging grantee against production = %+v, want deny — an env grant on staging must not imply access to production",
			got)
	}

	// Service-level grant: admin on a single service. The grant must
	// not reach a sibling service, must not allow env.write on the
	// parent environment (which would expose parent-level secrets), and
	// must not allow env.write on the parent project (which would
	// overwrite the project-scoped variables this endpoint replaces).
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
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for a service-scoped grantee against the parent project = %+v, want deny via %q — a service grant must not reach the parent project's variable list (where secrets live one layer up)",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Developer grantee hitting the
	// TARGET project is a 200 with the seeded post-write rows, the
	// replacer is reached with (home_org, target_project_id), the
	// caller-supplied payload is forwarded verbatim, AND the secret
	// post-write row's value is the redaction sentinel — the project-
	// scoped Developer grant confers exactly CapWrite at the project
	// scope, but the wire redaction chokepoint still hides the secret
	// plaintext.
	var targetCaptured store.ReplaceProjectVariablesInput
	targetCallCount := 0
	targetReplacer := fakeProjectVariableReplacer{
		vars:      postWrite,
		got:       &targetCaptured,
		callCount: &targetCallCount,
	}
	targetHandler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, targetReplacer)
	targetRec := putProjectVariables(targetHandler, project.ID, "yk_proj_dev_scoped", envWriteProjectPutBody)
	if targetRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a project-scoped developer key on its target project; body %s",
			targetRec.Code, targetRec.Body.String())
	}
	if targetCallCount != 1 {
		t.Errorf("replacer call count = %d, want 1 on the allow path", targetCallCount)
	}
	if targetCaptured.OrganizationID != org {
		t.Errorf("replacer received org id %q, want the principal's home org %q",
			targetCaptured.OrganizationID, org)
	}
	if targetCaptured.ProjectID != project.ID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			targetCaptured.ProjectID, project.ID)
	}
	if len(targetCaptured.Variables) != 1 || targetCaptured.Variables[0].Key != "MATRIX_KEY" || targetCaptured.Variables[0].Value != "matrix_value" {
		t.Errorf("replacer received variables = %+v, want one MATRIX_KEY=matrix_value",
			targetCaptured.Variables)
	}
	targetEnv := decodeReplaceProjectVariables(t, targetRec)
	if len(targetEnv.Data.Variables) != len(postWrite) {
		t.Errorf("variables len = %d, want %d", len(targetEnv.Data.Variables), len(postWrite))
	}
	if v1 := targetEnv.Data.Variables[1]; v1.Value != output.Sentinel {
		t.Errorf("got[1].value = %q, want the redaction sentinel %q on the project-scoped developer allow path too",
			v1.Value, output.Sentinel)
	}
	if body := targetRec.Body.String(); strings.Contains(body, "post-write-plaintext") ||
		strings.Contains(body, "correcthorsebatterystaple") {
		t.Errorf("allow-path response body %s leaked the secret plaintext — the redaction chokepoint must hold for scoped grantees too",
			body)
	}

	// Wire tie-in #2: the SAME project-scoped Developer grantee hitting
	// a SIBLING project is a 403 with the stable out-of-scope reason,
	// the replacer is never reached (so a production store could never
	// have replaced sibling variables — or surfaced sibling secret
	// plaintext — in the background), and the body never echoes the
	// canonical project's identifiers, the caller-supplied payload, or
	// the seeded post-write rows. This is the property that makes the
	// policy boundary — not the persistence boundary — the structural
	// place a scoped key is denied access to a sibling project's
	// variables.
	var siblingCaptured store.ReplaceProjectVariablesInput
	siblingCallCount := 0
	siblingReplacer := fakeProjectVariableReplacer{
		vars:      postWrite, // would be returned if replacer ran — leak guard catches it
		got:       &siblingCaptured,
		callCount: &siblingCallCount,
	}
	siblingHandler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, siblingReplacer)
	siblingRec := putProjectVariables(siblingHandler, "prj_vars_matrix_beta", "yk_proj_dev_scoped", envWriteProjectPutBody)
	if siblingRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on a sibling project; body %s",
			siblingRec.Code, siblingRec.Body.String())
	}
	siblingDenyEnv := decodeError(t, siblingRec, "E_FORBIDDEN")
	if !strings.Contains(siblingDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			siblingDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if siblingCallCount != 0 || siblingCaptured.OrganizationID != "" || siblingCaptured.ProjectID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q project=%q) for an out-of-scope grantee; it must never run",
			siblingCallCount, siblingCaptured.OrganizationID, siblingCaptured.ProjectID)
	}
	if body := siblingRec.Body.String(); strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") ||
		postWriteProjectVariablesBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, submitted payload, seeded post-write rows, or secret plaintext: %s",
			body)
	}

	// Wire tie-in #3: the env-scoped grantee hitting the parent project
	// is a 403 with ReasonDeniedOutOfScope and the replacer is never
	// reached. The leak guard catches an accidental render of the
	// canonical variables — including the secret plaintext — even
	// though the env grantee never had project-write coverage at all.
	var envCaptured store.ReplaceProjectVariablesInput
	envCallCount := 0
	envReplacer := fakeProjectVariableReplacer{
		vars:      postWrite,
		got:       &envCaptured,
		callCount: &envCallCount,
	}
	envHandler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: envGrantee, Method: auth.MethodAPIKey}, nil, envReplacer)
	envRec := putProjectVariables(envHandler, project.ID, "yk_env_scoped", envWriteProjectPutBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the parent project; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envCaptured.OrganizationID != "" || envCaptured.ProjectID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q project=%q) for an env-scoped grantee; it must never run",
			envCallCount, envCaptured.OrganizationID, envCaptured.ProjectID)
	}
	if body := envRec.Body.String(); strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") ||
		postWriteProjectVariablesBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, submitted payload, seeded post-write rows, or secret plaintext: %s",
			body)
	}

	// Wire tie-in #4: the service-scoped grantee hitting the parent
	// project is a 403, the replacer is never reached, and the body
	// never echoes parent-level identifiers — including the secret
	// plaintext that sits one layer up from the service the grant
	// names. This is the property that keeps a service-scoped key from
	// escalating to a parent-project variable write through this
	// endpoint — the "service grant does not expose parent-level
	// secrets or unrelated services" acceptance criterion tied back to
	// the wire on the variables write route, where parent-level secrets
	// are exactly the data the policy boundary is protecting.
	var svcCaptured store.ReplaceProjectVariablesInput
	svcCallCount := 0
	svcReplacer := fakeProjectVariableReplacer{
		vars:      postWrite,
		got:       &svcCaptured,
		callCount: &svcCallCount,
	}
	svcHandler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReplacer)
	svcRec := putProjectVariables(svcHandler, project.ID, "yk_svc_scoped", envWriteProjectPutBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the parent project; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcCaptured.OrganizationID != "" || svcCaptured.ProjectID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q project=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcCaptured.OrganizationID, svcCaptured.ProjectID)
	}
	if body := svcRec.Body.String(); strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") ||
		postWriteProjectVariablesBodyLeak(body) {
		t.Errorf("denied response leaked the canonical project, submitted payload, seeded post-write rows, or secret plaintext: %s",
			body)
	}

	// An organization-level Developer grant DOES cover any project
	// resource in the same org and — because env.write is CapWrite and
	// Developer holds CapWrite — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the replacer
	// reached on the principal's home org id and the path project id,
	// AND the secret post-write row still projects as output.Sentinel.
	// This locks the CapWrite requirement against the grant path so a
	// future catalog change that downgraded env.write below CapWrite
	// would fail here (silently denying every org-level Developer
	// grantee) before it could regress a real customer, and pins that
	// the wire redaction chokepoint is independent of how the principal
	// earned authority (role vs. org-level grant vs. project-level
	// grant).
	orgDeveloperGrantee := policy.Principal{
		ID: "sa_org_developer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloperGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// An organization-level Viewer grant at the same scope is
	// intentionally NOT enough: Viewer holds CapRead, not CapWrite. The
	// engine denial pairs with the org-level Developer allow above to
	// lock the CapWrite requirement against the grant path against both
	// directions of catalog drift.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeTarget}); got.Allow {
		t.Errorf("Decide(env.write) for an organization-level viewer grant = %+v, want deny — env.write requires CapWrite, Viewer holds only CapRead",
			got)
	}

	var orgCaptured store.ReplaceProjectVariablesInput
	orgCallCount := 0
	orgReplacer := fakeProjectVariableReplacer{
		vars:      postWrite,
		got:       &orgCaptured,
		callCount: &orgCallCount,
	}
	orgHandler := replaceProjectVariablesHandlerFor(
		auth.Identity{Principal: orgDeveloperGrantee, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putProjectVariables(orgHandler, project.ID, "yk_org_developer", envWriteProjectPutBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("replacer call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ProjectID != project.ID {
		t.Errorf("replacer received project id %q, want the path parameter %q",
			orgCaptured.ProjectID, project.ID)
	}
	allowedPayload := decodeReplaceProjectVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != len(postWrite) {
		t.Errorf("variables len = %d, want %d", len(allowedPayload.Data.Variables), len(postWrite))
	}
	if v1 := allowedPayload.Data.Variables[1]; v1.Value != output.Sentinel {
		t.Errorf("got[1].value = %q, want the redaction sentinel %q on the org-level developer grant allow path too",
			v1.Value, output.Sentinel)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, "post-write-plaintext") ||
		strings.Contains(body, "correcthorsebatterystaple") {
		t.Errorf("org-level developer allow-path response body %s leaked the secret plaintext — the redaction chokepoint must hold independent of how authority was earned",
			body)
	}

	// And the same project-scoped developer grantee whose home org id
	// is foreign is denied at the engine: a grant for
	// prj_vars_matrix_alpha inside org_acme, carried by a principal
	// whose home org id is org_sibling, cannot be used to overwrite
	// variables of prj_vars_matrix_alpha in org_sibling — the
	// cross-tenant guard fires first because the principal's home org
	// no longer matches the grant's scope. This is the engine-level
	// twin of the wire-level "wrong organization" property in
	// TestReplaceProjectVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it across
	// tenants. (env.write is OUTSIDE the support cross-tenant
	// exception, so even if the principal had been a support service
	// account, the engine still denies.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTarget}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvWrite, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.write) for a project-scoped developer key planted in a foreign org = %+v, want deny",
			got)
	}
}
