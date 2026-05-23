package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// Policy-matrix coverage for GET /v1/organizations/{org_id}/variables
// (BE-0108). Where variables_test.go proves the endpoint's wire contract,
// this file proves its authorization contract: that action env.read
// cannot be bypassed by, or leak data because of, the principal's role,
// revoked credentials, home organization, or scoped grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes
// against the organization the {org_id} path NAMES — not merely the
// principal's home organization. So a cross-tenant {org_id} must be a
// deterministic 403 before the handler runs (with the documented Support
// exception), while an {org_id} naming the caller's own organization is
// allowed by any built-in role or by a grant whose scope covers the
// organization root — never by a deeper-scoped grant.
//
// env.read requires CapRead (catalog.go: ActionEnvRead -> CapRead). All
// six built-in roles hold CapRead, so the role matrix for a principal
// reading its own organization is "all allow", and the engine's
// cross-tenant clause permits `required == CapRead || required ==
// CapSupport` through the Support exception, so a Support principal
// reading another tenant's variables is allowed via
// ReasonAllowedBySupport. This is the same shape the limits.read /
// usage.read matrices carry — and the load-bearing distinction from a
// CapAdmin endpoint (e.g. audit.read, keys.read) where the Support
// exception does not fire, four of six built-in roles deny, and a
// scoped org-level Viewer grant is denied.
//
// One property unique to GET /v1/organizations/{org_id}/variables is the
// secret-value redaction chokepoint: organization-scoped variables can
// be is_secret=true, and the handler projects every secret value as
// output.Sentinel. Every denied test in this file pins the negative
// invariant against secret values too — a denied response can never
// echo a secret value (nor the seeded ids, keys, or non-secret value),
// because the reader is never reached. An allowed test pins the
// positive invariant — the secret value is the sentinel on the wire,
// not the seeded plaintext — so the redaction layer cannot drift out of
// the policy-allowed path either.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the organizationIDResolver, or the engine fails here.
// listOrgVariablesHandlerFor, orgVariableActorIdentity, getOrgVariables,
// fakeOrgVariableReader, decodeOrgVariables, orgPrincipal, and
// decodeError are shared with the sibling variables contract suite
// (variables_test.go) and the wider httpapi test fixtures; this file
// adds no scaffolding beyond the small fixture builder below.

// seededOrgVariables builds the canonical "REGION non-secret +
// DATABASE_URL secret" fixture every test in this file shares. Two rows
// pin both projections at once — allowed tests prove the secret value
// projects as output.Sentinel (not the seeded plaintext), and denied
// tests prove the secret value, its prefix, and the seeded ids/keys
// never leak in an error body. Keeping the fixture in one place keeps
// the matrix-mode assertions concise and lets a future regression that
// reorders, renames, or recategorises a field fail in exactly one
// place.
func seededOrgVariables(orgID string) []store.OrganizationVariable {
	return []store.OrganizationVariable{
		{
			ID:             "ovar_region",
			OrganizationID: orgID,
			Key:            "REGION",
			Value:          "us-east-1",
			IsSecret:       false,
			Version:        1,
		},
		{
			ID:             "ovar_db",
			OrganizationID: orgID,
			Key:            "DATABASE_URL",
			Value:          "postgres://user:hunter2@db.internal/yalla",
			IsSecret:       true,
			Version:        1,
		},
	}
}

// orgVariablesBodyLeak reports whether body contains any non-public
// value seeded by seededOrgVariables — the per-row ids, the variable
// keys, the non-secret value, and crucially every recognisable fragment
// of the secret value. A denied response that accidentally rendered any
// of these fails the test. The secret-value needles are split into
// distinct substrings (the full URL, the password "hunter2", the
// "postgres://" prefix, and the "db.internal" host) so a partial leak
// that drops only one piece still trips the guard. The literal "true"
// is deliberately NOT in this list because it is the JSON encoding of
// every boolean field across the API; pinning it would create a false
// signal.
func orgVariablesBodyLeak(body string) bool {
	needles := []string{
		"ovar_region", "ovar_db",
		"REGION", "DATABASE_URL",
		"us-east-1",
		"postgres://user:hunter2@db.internal/yalla",
		"hunter2", "postgres://", "db.internal",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListOrgVariablesPolicyMatrixRoles drives every built-in role
// through the production request path against an {org_id} that names
// its own home organization. All six built-in roles hold CapRead, so
// the matrix is "all allow"; the assertions that matter are that the
// verdict is reached through the role (ReasonAllowedByRole) and that
// the reader is reached with the {org_id} the path named, never a
// fabricated, escalated, or sibling tenant. The response carries the
// seeded variables in the order the reader returned them, and — the
// property unique to this endpoint — the secret variable's value is
// the sentinel on the wire, not the seeded plaintext, so the
// redaction chokepoint can never drift out of the policy-allowed
// path.
func TestListOrgVariablesPolicyMatrixRoles(t *testing.T) {
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
			// catalog or builtinRoleCaps regression fails here.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvRead, orgRoot)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(env.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var seen string
			reader := fakeOrgVariableReader{vars: seededOrgVariables(org), gotOrgID: &seen}
			handler := listOrgVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getOrgVariables(handler, org, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if seen != org {
				t.Errorf("reader received organization id %q, want the path parameter %q", seen, org)
			}
			env := decodeOrgVariables(t, rec.Body.Bytes())
			if env.SchemaVersion != "yalla.output.v1" {
				t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
			}
			if len(env.Data.Variables) != 2 {
				t.Fatalf("variables len = %d, want 2 (got %+v)", len(env.Data.Variables), env.Data.Variables)
			}

			region := env.Data.Variables[0]
			if region.ID != "ovar_region" || region.Key != "REGION" || region.Value != "us-east-1" || region.IsSecret {
				t.Errorf("[0] = %+v, want (ovar_region REGION us-east-1 is_secret=false)", region)
			}
			db := env.Data.Variables[1]
			if db.ID != "ovar_db" || db.Key != "DATABASE_URL" || !db.IsSecret {
				t.Errorf("[1] = %+v, want (ovar_db DATABASE_URL is_secret=true)", db)
			}
			// Allowed-path redaction invariant: the secret variable's
			// value is the sentinel, never the seeded plaintext. This
			// guards the chokepoint inside the role-allowed branch so a
			// future regression that bypassed organizationVariableOf for
			// a particular principal class would fail here too.
			if db.Value != output.Sentinel {
				t.Errorf("[1].value = %q, want sentinel — secret values must be redacted on the wire even for %s", db.Value, tc.name)
			}
			if strings.Contains(rec.Body.String(), "hunter2") ||
				strings.Contains(rec.Body.String(), "postgres://") ||
				strings.Contains(rec.Body.String(), "db.internal") {
				t.Errorf("response body leaked the secret value for role %s: %s", tc.name, rec.Body.String())
			}
		})
	}
}

// TestListOrgVariablesPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal — is
// denied action env.read with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired
// credential must never be able to enumerate variables of the
// organization it once had access to, the reader must never run, and
// the denied body must never echo the principal id, the organization
// id, or any seeded variable data (including any fragment of the
// secret value).
//
// Underlying role is Owner so a working credential WOULD allow
// env.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0108 ("revoked key,
// expired key").
func TestListOrgVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			reader := fakeOrgVariableReader{vars: seededOrgVariables("org_acme"), gotOrgID: &seen}
			handler := listOrgVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getOrgVariables(handler, "org_acme", "yk_no_longer_valid")
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
				orgVariablesBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded variable data", body)
			}
		})
	}
}

// TestListOrgVariablesPolicyWrongOrganizationPrincipal proves env.read
// is confined to the caller's own tenant — except for the documented
// Support exception. The route carries organizationIDResolver, so
// RequireAuth authorizes against the organization the {org_id} path
// names:
//
//   - A non-support owner of org_attacker reading variables of
//     org_victim is a deterministic 403 ReasonDeniedCrossTenant; the
//     reader is never reached, and the denied body never echoes the
//     foreign organization or any of its seeded variable data
//     (including any fragment of the secret value).
//
//   - A Support principal of org_yalla performing the same
//     cross-tenant read IS allowed (engine clause: CapRead within the
//     cross-tenant branch) via ReasonAllowedBySupport, and receives
//     the variables of the organization the path named. This mirrors
//     the limits.read / usage.read matrices exactly because all three
//     map to CapRead and Support is the only role that crosses the
//     tenant boundary for those reads. Crucially, the cross-tenant
//     allowed path STILL redacts secret values to output.Sentinel: a
//     Support read is not a secret-exfiltration channel.
//
// The engine verdict is pinned alongside the wire verdict for both
// principals so a regression in either layer fails here, and a future
// upgrade of env.read to a higher capability would break both the role
// matrix and this exception.
func TestListOrgVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)
	victimVars := seededOrgVariables(victimOrg)

	// Non-support cross-tenant principal: owner of org_attacker reading
	// variables of org_victim is a deterministic 403, the reader never
	// reached, and the body carries no cross-tenant id or variable
	// data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderSeen string
	intruderReader := fakeOrgVariableReader{vars: victimVars, gotOrgID: &intruderSeen}
	intruderHandler := listOrgVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderReader)

	rec := getOrgVariables(intruderHandler, victimOrg, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderSeen != "" {
		t.Errorf("reader was reached with org=%q for a cross-tenant request; it must never run",
			intruderSeen)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) || orgVariablesBodyLeak(body) {
		t.Errorf("error body %s echoed the cross-tenant organization or seeded variable data", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// the resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionEnvRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(env.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches env.read because the catalog
	// maps it to CapRead. So a Support principal reading another
	// tenant's variables is allowed via ReasonAllowedBySupport, and
	// the handler returns 200 with the variables of the organization
	// the path named. This is the same distinguishing property
	// limits.read / usage.read carry — all three share the action
	// capability class and the exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(env.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}

	var supportSeen string
	supportReader := fakeOrgVariableReader{vars: victimVars, gotOrgID: &supportSeen}
	supportHandler := listOrgVariablesHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)
	supportRec := getOrgVariables(supportHandler, victimOrg, "a-valid-support-token")
	if supportRec.Code != http.StatusOK {
		t.Fatalf("support status = %d, want 200 — support is allowed env.read cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportPayload := decodeOrgVariables(t, supportRec.Body.Bytes())
	if len(supportPayload.Data.Variables) != 2 ||
		supportPayload.Data.Variables[0].ID != "ovar_region" ||
		supportPayload.Data.Variables[1].ID != "ovar_db" {
		t.Errorf("support payload variables = %+v, want the seeded [ovar_region, ovar_db]",
			supportPayload.Data.Variables)
	}
	// Cross-tenant allowed path STILL redacts secret values — a
	// Support read is not a secret-exfiltration channel.
	if v := supportPayload.Data.Variables[1].Value; v != output.Sentinel {
		t.Errorf("support payload secret value = %q, want sentinel — cross-tenant support reads must redact secrets too", v)
	}
	if strings.Contains(supportRec.Body.String(), "hunter2") ||
		strings.Contains(supportRec.Body.String(), "postgres://") ||
		strings.Contains(supportRec.Body.String(), "db.internal") {
		t.Errorf("support response leaked the secret value cross-tenant: %s", supportRec.Body.String())
	}
	if supportSeen != victimOrg {
		t.Errorf("support reader received organization id %q, want the path parameter %q",
			supportSeen, victimOrg)
	}
}

// TestListOrgVariablesPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production, a service grant does not reach the parent environment
// or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}/variables: env.read is
// evaluated against the organization-root scope the {org_id} path
// names. A project/environment/service-scoped grant — even an Admin
// grant — does not cover that scope (covers() is one-way: a
// more-specific scope cannot reach a broader resource), not even for
// the key's own organization. So a scoped key holding only a project
// grant is denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level
// grant — even a Viewer grant, since env.read is CapRead — is allowed
// it (ReasonAllowedByGrant). A scoped grant narrows authority within a
// tenant; it can never be escalated to a broader organization-scoped
// variable read.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own {org_id}, while an organization-scoped Viewer
// grantee is allowed it. The allowed wire response is also pinned to
// the sentinel redaction so a future regression that downgraded the
// grant-allowed branch to project the raw plaintext secret would fail
// here, not just in the role-allowed branch.
func TestListOrgVariablesPolicyGrantContainment(t *testing.T) {
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

	// GET /v1/organizations/{org_id}/variables reads against the
	// organization root the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover
	// that scope — not even for the key's own organization — so each
	// scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to an
	// organization-wide variable read, and the reader never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionEnvRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee reading
	// variables of its OWN organization is a 403 with the stable
	// out-of-scope reason, the reader is never reached, and the body
	// never echoes the seeded variable data — including any fragment
	// of the secret value. This is the property that makes the policy
	// boundary — not the persistence boundary — the structural place a
	// scoped key is denied broader visibility.
	var projectSeen string
	projectReader := fakeOrgVariableReader{vars: seededOrgVariables(org), gotOrgID: &projectSeen}
	projectHandler := listOrgVariablesHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getOrgVariables(projectHandler, org, "yk_proj_scoped")
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
	if body := rec.Body.String(); orgVariablesBodyLeak(body) {
		t.Errorf("denied response leaks the seeded variable data: %s", body)
	}

	// An organization-level Viewer grant DOES cover the org-root scope
	// and — because env.read is CapRead and Viewer holds CapRead — is
	// allowed via ReasonAllowedByGrant. The same key is end-to-end
	// allowed at the wire, with the reader reached on the {org_id}
	// parameter. This locks the CapRead requirement against the grant
	// path so a future catalog change that upgraded env.read above
	// CapRead would fail here (silently denying every org-level Viewer
	// grantee) before it could regress a real customer.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionEnvRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgSeen string
	orgReader := fakeOrgVariableReader{vars: seededOrgVariables(org), gotOrgID: &orgSeen}
	orgHandler := listOrgVariablesHandlerFor(
		auth.Identity{Principal: orgViewer, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getOrgVariables(orgHandler, org, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeOrgVariables(t, allowedRec.Body.Bytes())
	if len(allowedPayload.Data.Variables) != 2 ||
		allowedPayload.Data.Variables[0].ID != "ovar_region" ||
		allowedPayload.Data.Variables[1].ID != "ovar_db" {
		t.Errorf("variables = %+v, want the seeded [ovar_region, ovar_db] pair",
			allowedPayload.Data.Variables)
	}
	// Grant-allowed path STILL redacts the secret value. This is the
	// twin of the role-matrix assertion above: redaction is the
	// projection's responsibility, not the policy verdict's, and must
	// hold under both allow-by-role and allow-by-grant.
	if v := allowedPayload.Data.Variables[1].Value; v != output.Sentinel {
		t.Errorf("grant-allowed secret value = %q, want sentinel — the grant path must redact secrets too", v)
	}
	if strings.Contains(allowedRec.Body.String(), "hunter2") ||
		strings.Contains(allowedRec.Body.String(), "postgres://") ||
		strings.Contains(allowedRec.Body.String(), "db.internal") {
		t.Errorf("grant-allowed response leaked the secret value: %s", allowedRec.Body.String())
	}
	if orgSeen != org {
		t.Errorf("reader received organization id %q, want the path parameter %q",
			orgSeen, org)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to enumerate somebody else's
	// variables. The cross-tenant guard fires first, since the scope's
	// organization id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionEnvRead, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(env.read, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := listOrgVariablesHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrgVariableReader{vars: seededOrgVariables(org)})
	foreignRec := getOrgVariables(foreignHandler, "org_sibling", "yk_proj_scoped")
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if body := foreignRec.Body.String(); orgVariablesBodyLeak(body) {
		t.Errorf("foreign denied response leaks the seeded variable data: %s", body)
	}
}
