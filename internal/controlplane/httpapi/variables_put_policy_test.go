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

// Policy-matrix coverage for PUT /v1/organizations/{org_id}/variables
// (BE-0111). Where variables_put_test.go proves the endpoint's wire
// contract (BE-0109/BE-0110), this file proves its authorization
// contract: that action env.write cannot be bypassed by — or persist a
// mutation because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes
// against the organization the {org_id} path NAMES — not merely the
// principal's home organization. So a cross-tenant {org_id} must be a
// deterministic 403 before the handler runs (and unlike CapRead siblings
// there is NO Support exception for CapWrite), while an {org_id} naming
// the caller's own organization is allowed by an organization role that
// holds CapWrite (owner/admin/developer) or by a grant whose scope
// covers the organization root — never by a deeper-scoped grant, never
// by Viewer/CI/Support.
//
// env.write requires CapWrite (catalog.go: ActionEnvWrite -> CapWrite),
// the same capability class as project/environment/service create/update
// /delete. The role matrix therefore allows Owner/Admin/Developer at the
// own organization (each holds CapWrite) and denies Viewer/CI/Support
// (none of which hold CapWrite) — and the engine's cross-tenant clause
// is gated on `required == CapRead || required == CapSupport`, so
// CapWrite is OUTSIDE the support cross-tenant exception. This is the
// load-bearing distinction from the env.read matrix (BE-0108): the same
// resolver and the same {org_id} scoping, but with three additional
// roles denied at the role boundary and with no Support cross-tenant
// allow. Privileged Yalla support that needs to overwrite a tenant's
// variables goes through the explicit break-glass admin tooling, not
// this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the organizationIDResolver, or the engine fails here.
// replaceOrgVariablesHandlerFor, putOrgVariables, decodeUpdateOrgVariables,
// fakeOrgVariableReplacer, orgVariableActorIdentity, orgPrincipal, and
// decodeError are shared with the sibling PUT contract suite
// (variables_put_test.go); seededOrgVariables and orgVariablesBodyLeak
// come from the env.read policy suite (variables_policy_test.go).
// This file adds only the small fixtures below.

// envWritePutBody is the minimal valid request body the matrix tests
// send: a single non-secret variable. The distinctive key (MATRIX_KEY)
// and value (matrix_value) are deliberately recognisable so deny-path
// leak checks can prove the submitted payload is not echoed back, and
// they intentionally do NOT collide with seededPostWriteOrgVariables's
// returned rows — only the seeded post-write fixture is the "data" the
// replacer would have returned, so deny paths must never echo that
// fixture either.
const envWritePutBody = `{"variables":[{"key":"MATRIX_KEY","value":"matrix_value"}]}`

// seededPostWriteOrgVariables builds the distinctive post-write fixture
// the fake replacer returns on success. Two rows pin both projections
// at once — the non-secret row's value (POST_WRITE_REGION=eu-west-3)
// confirms the wire round-trips a non-secret cleanly on allow, and the
// secret row's value confirms allow paths STILL redact secrets to
// output.Sentinel and deny paths NEVER echo the seeded post-write
// secret content. The ids/keys/values are intentionally different from
// the request body and from seededOrgVariables (env.read suite) so a
// leak check that searches for the seeded post-write data can never
// false-positive against unrelated fixtures.
func seededPostWriteOrgVariables(orgID string) []store.OrganizationVariable {
	return []store.OrganizationVariable{
		{
			ID:             "ovar_post_region",
			OrganizationID: orgID,
			Key:            "POST_WRITE_REGION",
			Value:          "eu-west-3",
			IsSecret:       false,
			Version:        2,
		},
		{
			ID:             "ovar_post_secret",
			OrganizationID: orgID,
			Key:            "POST_WRITE_SECRET",
			Value:          "post-write-plaintext-correcthorsebatterystaple",
			IsSecret:       true,
			Version:        2,
		},
	}
}

// postWriteOrgVariablesBodyLeak reports whether body contains any
// non-public value from seededPostWriteOrgVariables — the per-row ids,
// the variable keys, the non-secret value, and crucially every
// recognisable fragment of the secret value. A denied response that
// accidentally rendered any of these fails the test; the policy
// boundary is the only place a write is gated, so a denied caller
// seeing the seeded post-write data would itself be a contract
// violation. The secret-value needles split the long string into
// distinct substrings so a partial leak that drops only one piece
// still trips the guard. The literal "true" is deliberately NOT in
// this list because it is the JSON encoding of every boolean field.
func postWriteOrgVariablesBodyLeak(body string) bool {
	needles := []string{
		"ovar_post_region", "ovar_post_secret",
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

// TestReplaceOrgVariablesPolicyMatrixRoles drives every built-in role
// through the production request path against an {org_id} that names
// its own home organization. Owner, Admin, and Developer hold CapWrite
// and allow env.write via ReasonAllowedByRole — the replacer is reached
// with the path's {org_id} and the response carries the seeded
// post-write rows. Viewer, CI, and Support all lack CapWrite and are
// denied with a stable 403 E_FORBIDDEN carrying ReasonDeniedNoCapability
// — and in every deny path the replacer is never reached, so the policy
// boundary is the only place a variable mutation can be authorized for
// a non-CapWrite caller. This is the load-bearing difference from
// env.read (CapRead, all roles allow): a regression that downgraded the
// catalog's CapWrite for env.write to CapRead would silently let
// viewers and CI keys overwrite variables, and would fail this test on
// every Viewer/CI/Support row.
func TestReplaceOrgVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	cases := []struct {
		name       string
		role       policy.Role
		kind       domain.Kind
		wantAllow  bool
		wantReason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine assertion: the role decision against the
			// organization-root scope the resolver emits is the verdict
			// the matrix names. The {org_id} path parameter is the only
			// input the engine sees for this route.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvWrite, orgRoot)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(env.write) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			var gotInput store.ReplaceOrganizationVariablesInput
			replacer := fakeOrgVariableReplacer{vars: seededPostWriteOrgVariables(org), got: &gotInput}
			handler := replaceOrgVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, replacer)

			rec := putOrgVariables(handler, org, "a-valid-token", envWritePutBody)

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeUpdateOrgVariables(t, rec)
				if env.SchemaVersion != "yalla.output.v1" {
					t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
				}
				if len(env.Data.Variables) != 2 ||
					env.Data.Variables[0].ID != "ovar_post_region" ||
					env.Data.Variables[0].Key != "POST_WRITE_REGION" ||
					env.Data.Variables[0].Value != "eu-west-3" ||
					env.Data.Variables[1].ID != "ovar_post_secret" ||
					env.Data.Variables[1].Key != "POST_WRITE_SECRET" {
					t.Errorf("variables = %+v, want the seeded post-write pair", env.Data.Variables)
				}
				// Allowed-path redaction invariant: the secret variable's
				// value is the sentinel on the wire, not the seeded
				// plaintext. This guards the chokepoint inside the
				// role-allowed branch so a future regression that
				// bypassed organizationVariableOf for a particular
				// principal class would fail here too — even right after
				// a caller submitted a fresh secret.
				if v := env.Data.Variables[1].Value; v != output.Sentinel {
					t.Errorf("[1].value = %q, want sentinel — secret values must be redacted on the wire even for %s", v, tc.name)
				}
				if body := rec.Body.String(); strings.Contains(body, "post-write-plaintext") ||
					strings.Contains(body, "correcthorsebatterystaple") {
					t.Errorf("response body leaked the secret value for role %s: %s", tc.name, body)
				}
				if gotInput.OrganizationID != org {
					t.Errorf("replacer received organization id %q, want the path parameter %q",
						gotInput.OrganizationID, org)
				}
				if len(gotInput.Variables) != 1 ||
					gotInput.Variables[0].Key != "MATRIX_KEY" ||
					gotInput.Variables[0].Value != "matrix_value" {
					t.Errorf("replacer received variables %+v, want exactly one MATRIX_KEY=matrix_value entry",
						gotInput.Variables)
				}
				if gotInput.ActorID != principal.ID || gotInput.ActorOrgID != org {
					t.Errorf("replacer received actor=(%q, %q), want (%q, %q)",
						gotInput.ActorID, gotInput.ActorOrgID, principal.ID, org)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for %s; body %s",
					rec.Code, tc.name, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(tc.wantReason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, tc.wantReason)
			}
			if gotInput.OrganizationID != "" || len(gotInput.Variables) != 0 {
				t.Errorf("replacer was reached with org=%q variables=%+v for a denied %s; it must never run",
					gotInput.OrganizationID, gotInput.Variables, tc.name)
			}
			// A denied response must never leak the seeded post-write
			// variables — the policy boundary is the only place env
			// writes are gated, so a denied caller seeing the seeded
			// post-write data would itself be a contract violation. The
			// submitted MATRIX_KEY/matrix_value request body could
			// echo back trivially, so the deny-leak check pins the data
			// the replacer would have returned, not the data the caller
			// just sent.
			if body := rec.Body.String(); postWriteOrgVariablesBodyLeak(body) {
				t.Errorf("denied response leaks the seeded post-write variable data: %s", body)
			}
		})
	}
}

// TestReplaceOrgVariablesPolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal — is
// denied action env.write with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired
// credential must never be able to overwrite variables of the
// organization it once had access to (a stale CI key clearing
// DATABASE_URL or rotating in a hostile value is precisely the abuse
// this guards), the replacer must never run, and the denied body must
// never echo the principal id, the organization id, or any seeded
// post-write variable data.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0111 ("revoked key,
// expired key").
func TestReplaceOrgVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			var gotInput store.ReplaceOrganizationVariablesInput
			replacer := fakeOrgVariableReplacer{vars: seededPostWriteOrgVariables("org_acme"), got: &gotInput}
			handler := replaceOrgVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)

			rec := putOrgVariables(handler, "org_acme", "yk_no_longer_valid", envWritePutBody)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || len(gotInput.Variables) != 0 {
				t.Errorf("replacer was reached with org=%q variables=%+v for a disabled principal; it must never run",
					gotInput.OrganizationID, gotInput.Variables)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				postWriteOrgVariablesBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded post-write variable data", body)
			}
		})
	}
}

// TestReplaceOrgVariablesPolicyWrongOrganizationPrincipal proves
// env.write is confined to the caller's own tenant — and unlike
// env.read there is NO cross-tenant exception for support. The
// engine's cross-tenant clause only allows CapRead and CapSupport
// actions through the support exception (engine.go: `required ==
// CapRead || required == CapSupport`); CapWrite is excluded by
// construction. So:
//
//   - A non-support owner of org_attacker writing variables in
//     org_victim is a deterministic 403 carrying
//     ReasonDeniedCrossTenant; the replacer is never reached, and the
//     denied body never echoes the victim organization, the submitted
//     key/value, or any seeded post-write variable data.
//
//   - A Support principal of org_yalla — the one that COULD have read
//     another tenant's variables via env.read — cannot mutate them.
//     The engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns
//     403 with no leakage. This is the load-bearing distinction from
//     BE-0108's env.read matrix (CapRead, support allowed
//     cross-tenant) and the property under test here.
//
// Bonus: a support principal cannot mutate variables of its OWN home
// organization either — RoleSupport lacks CapWrite entirely. Pinning
// this verdict locks the support role's read-only-for-config posture
// at the engine level so a future catalog change cannot silently grant
// it variable-mutation authority through the home-tenant path.
//
// Privileged Yalla support that needs to overwrite a tenant's
// variables (e.g. during a customer-authorised key rotation) goes
// through the explicit break-glass admin tooling, not this
// customer-facing endpoint.
func TestReplaceOrgVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)

	// Non-support cross-tenant principal: owner of org_attacker writing
	// variables in org_victim is a deterministic 403, the replacer
	// never reached, and the body carries no cross-tenant id, no
	// submitted key, and no seeded post-write data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderInput store.ReplaceOrganizationVariablesInput
	intruderReplacer := fakeOrgVariableReplacer{
		vars: seededPostWriteOrgVariables(victimOrg), got: &intruderInput,
	}
	intruderHandler := replaceOrgVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderReplacer)

	rec := putOrgVariables(intruderHandler, victimOrg, "a-valid-token", envWritePutBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderInput.OrganizationID != "" || len(intruderInput.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q variables=%+v for a cross-tenant principal; it must never run",
			intruderInput.OrganizationID, intruderInput.Variables)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") ||
		postWriteOrgVariablesBodyLeak(body) {
		t.Errorf("error body %s echoed the cross-tenant organization, the submitted payload, or the seeded post-write variable data",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// the resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionEnvWrite, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(env.write, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for CapWrite. The engine
	// clause `roleCaps.has(CapSupport) && (required == CapRead ||
	// required == CapSupport)` does NOT reach env.write because the
	// catalog maps it to CapWrite. So a Support principal writing
	// another tenant's variables is denied at the engine via
	// ReasonDeniedCrossTenant, and the handler returns 403 with no
	// leakage. This is the load-bearing distinction from BE-0108's
	// env.read matrix where the same support principal IS allowed
	// cross-tenant.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvWrite, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(env.write, foreign org) for support = %+v, want deny via %q (CapWrite is OUTSIDE the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var supportInput store.ReplaceOrganizationVariablesInput
	supportReplacer := fakeOrgVariableReplacer{
		vars: seededPostWriteOrgVariables(victimOrg), got: &supportInput,
	}
	supportHandler := replaceOrgVariablesHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReplacer)
	supportRec := putOrgVariables(supportHandler, victimOrg, "a-valid-support-token", envWritePutBody)
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support is NOT allowed env.write cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportInput.OrganizationID != "" || len(supportInput.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q variables=%+v for a cross-tenant support principal; it must never run",
			supportInput.OrganizationID, supportInput.Variables)
	}
	if body := supportRec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") ||
		postWriteOrgVariablesBodyLeak(body) {
		t.Errorf("support denied response leaked the cross-tenant organization, the submitted payload, or the seeded post-write variable data: %s",
			body)
	}

	// Bonus: a support principal cannot mutate variables of its OWN
	// home organization either — RoleSupport lacks CapWrite entirely.
	// This locks the support role's read-only-for-config posture at
	// the engine level so a future catalog change cannot silently
	// grant it variable-mutation authority.
	supportHome := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: support.OrganizationID}}
	if got := e.Decide(support, policy.ActionEnvWrite, supportHome); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(env.write, own org) for support = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
}

// TestReplaceOrgVariablesPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production, a service grant does not reach the parent environment
// or a sibling service.
//
// Crucially for PUT /v1/organizations/{org_id}/variables: env.write is
// evaluated against the organization-root scope the {org_id} path
// names. A project/environment/service-scoped grant — even an Admin
// grant — does not cover that scope (covers() is one-way: a
// more-specific scope cannot reach a broader resource), not even for
// the key's own organization. So a scoped key holding only a project
// Admin grant is denied the endpoint for its own {org_id} with the
// stable ReasonDeniedOutOfScope, while a key holding an
// organization-level Developer grant — and Developer is enough,
// because env.write is CapWrite and Developer holds CapWrite — is
// allowed it (ReasonAllowedByGrant). A Viewer grant at the same
// organization scope is intentionally NOT enough: Viewer holds
// CapRead, not CapWrite. This locks the CapWrite requirement against
// the grant path so a future catalog change that downgraded env.write
// below CapWrite would fail the Viewer-deny assertion here, and a
// change that upgraded it above CapWrite would fail the
// Developer-allow assertion.
//
// A scoped grant narrows authority within a tenant; it can never be
// escalated to a broader organization-scoped variable write. This is
// the load-bearing property that prevents a leaked project-scoped CI
// key from being weaponised to overwrite the tenant's
// organization-level DATABASE_URL or API tokens — a strict superset
// of the env.read containment property because the abuse here is
// active credential rotation, not enumeration.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own {org_id}, while an organization-scoped
// Developer grantee is allowed it and a Viewer grantee is denied.
func TestReplaceOrgVariablesPolicyGrantContainment(t *testing.T) {
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
	// must not expose parent-level secrets (env.write on the parent
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

	// PUT /v1/organizations/{org_id}/variables mutates against the
	// organization root the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover
	// that scope — not even for the key's own organization — so each
	// scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to
	// overwrite organization-wide variables, and the replacer never
	// runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionEnvWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee writing
	// variables of its OWN organization is a 403 with the stable
	// out-of-scope reason, the replacer is never reached, and the body
	// never echoes the seeded post-write variable data — including any
	// fragment of the secret value. This is the property that makes
	// the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied broader write authority.
	var projectInput store.ReplaceOrganizationVariablesInput
	projectReplacer := fakeOrgVariableReplacer{
		vars: seededPostWriteOrgVariables(org), got: &projectInput,
	}
	projectHandler := replaceOrgVariablesHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReplacer)
	rec := putOrgVariables(projectHandler, org, "yk_proj_scoped", envWritePutBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectInput.OrganizationID != "" || len(projectInput.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q variables=%+v for an out-of-scope grantee; it must never run",
			projectInput.OrganizationID, projectInput.Variables)
	}
	if body := rec.Body.String(); postWriteOrgVariablesBodyLeak(body) {
		t.Errorf("denied response leaks the seeded post-write variable data: %s", body)
	}

	// An organization-level Developer grant DOES cover the org-root
	// scope and — because env.write is CapWrite and Developer holds
	// CapWrite — is allowed via ReasonAllowedByGrant. The same key is
	// end-to-end allowed at the wire, with the replacer reached on the
	// {org_id} parameter and the response carrying the seeded
	// post-write rows. A Viewer grant at the same scope is
	// intentionally NOT enough: env.write requires CapWrite, not
	// CapRead. This locks the CapWrite requirement against the grant
	// path so a future catalog change that downgraded env.write below
	// CapWrite would fail the Viewer-deny assertion here, and one that
	// upgraded it above CapWrite would fail the Developer-allow
	// assertion.
	orgDeveloper := policy.Principal{
		ID: "sa_org_developer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloper, policy.ActionEnvWrite, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionEnvWrite, orgRoot); got.Allow {
		t.Errorf("Decide(env.write) for an organization-level viewer grant = %+v, want deny — viewer holds CapRead, not CapWrite",
			got)
	}

	var orgInput store.ReplaceOrganizationVariablesInput
	orgReplacer := fakeOrgVariableReplacer{
		vars: seededPostWriteOrgVariables(org), got: &orgInput,
	}
	orgHandler := replaceOrgVariablesHandlerFor(
		auth.Identity{Principal: orgDeveloper, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putOrgVariables(orgHandler, org, "yk_org_developer", envWritePutBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeUpdateOrgVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != 2 ||
		allowedPayload.Data.Variables[0].ID != "ovar_post_region" ||
		allowedPayload.Data.Variables[1].ID != "ovar_post_secret" {
		t.Errorf("variables = %+v, want the seeded post-write [ovar_post_region, ovar_post_secret] pair",
			allowedPayload.Data.Variables)
	}
	// Grant-allowed path STILL redacts the secret value. This is the
	// twin of the role-matrix assertion above: redaction is the
	// projection's responsibility, not the policy verdict's, and must
	// hold under both allow-by-role and allow-by-grant.
	if v := allowedPayload.Data.Variables[1].Value; v != output.Sentinel {
		t.Errorf("grant-allowed secret value = %q, want sentinel — the grant path must redact secrets too", v)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, "post-write-plaintext") ||
		strings.Contains(body, "correcthorsebatterystaple") {
		t.Errorf("grant-allowed response leaked the secret value: %s", body)
	}
	if orgInput.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the path parameter %q",
			orgInput.OrganizationID, org)
	}
	if len(orgInput.Variables) != 1 ||
		orgInput.Variables[0].Key != "MATRIX_KEY" ||
		orgInput.Variables[0].Value != "matrix_value" {
		t.Errorf("replacer received variables %+v, want exactly one MATRIX_KEY=matrix_value entry",
			orgInput.Variables)
	}
	if orgInput.ActorID != orgDeveloper.ID || orgInput.ActorOrgID != org {
		t.Errorf("replacer received actor=(%q, %q), want (%q, %q)",
			orgInput.ActorID, orgInput.ActorOrgID, orgDeveloper.ID, org)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to overwrite somebody else's
	// variables. The cross-tenant guard fires first, since the scope's
	// organization id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionEnvWrite, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(env.write, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := replaceOrgVariablesHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrgVariableReplacer{vars: seededPostWriteOrgVariables(org)})
	foreignRec := putOrgVariables(foreignHandler, "org_sibling", "yk_proj_scoped", envWritePutBody)
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if body := foreignRec.Body.String(); postWriteOrgVariablesBodyLeak(body) ||
		strings.Contains(body, "MATRIX_KEY") ||
		strings.Contains(body, "matrix_value") {
		t.Errorf("foreign denied response leaks the seeded post-write variable data or the submitted payload: %s", body)
	}
}
