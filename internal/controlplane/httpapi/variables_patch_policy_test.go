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

// Policy-matrix coverage for PATCH /v1/organizations/{org_id}/variables/{key}
// (BE-0114). Where variables_patch_test.go (BE-0112/BE-0113) proves the
// endpoint's wire contract — the partial-update body decoder, the
// pointer-fidelity forwarding, the projection that redacts secret values,
// the typed not-found and store-outage paths — this file proves its
// authorization contract: that action env.write cannot be bypassed by — or
// persist a mutation because of — the principal's role, revoked or expired
// credentials, home organization, or scoped grants. The PATCH route uses
// exactly the same authorization seam as PUT (organizationIDResolver
// against the {org_id} path parameter for action env.write), so the
// matrix structure mirrors variables_put_policy_test.go (BE-0111) verbatim.
// The two stories remain separate PRD items because the wire surface
// (single-variable {key} sub-resource vs. bulk replacement) is distinct,
// each with its own request shape, redaction chokepoint, and validation
// failure modes — each gets its own authorization proof.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization) — the {key} is a sub-resource within
// the organization-root scope, not a deeper-scoped resource. RequireAuth
// therefore authorizes against the organization the {org_id} path NAMES
// — not merely the principal's home organization, and not against the
// {key}. So a cross-tenant {org_id} must be a deterministic 403 before
// the handler runs (and unlike CapRead siblings there is NO Support
// exception for CapWrite), while an {org_id} naming the caller's own
// organization is allowed by an organization role that holds CapWrite
// (owner/admin/developer) or by a grant whose scope covers the
// organization root — never by a deeper-scoped grant, never by
// Viewer/CI/Support.
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
// allow. Privileged Yalla support that needs to overwrite a single
// tenant variable goes through the explicit break-glass admin tooling,
// not this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the organizationIDResolver, or the engine fails here.
// patchOrgVariableHandlerFor, patchOrgVariable, decodePatchOrgVariable,
// fakeOrgVariablePatcher, orgVariableActorIdentity, orgPrincipal, and
// decodeError are shared with the sibling PATCH contract suite
// (variables_patch_test.go and friends). This file adds only the small
// fixtures below.

// envWritePatchKey is the {key} URL path parameter the matrix tests
// send. It is intentionally distinctive (caller-submitted needle) so
// deny-path leak checks can prove the URL key is not echoed back, and
// it does NOT collide with seededPostPatchOrgVariable's returned Key —
// the seeded post-patch fixture is the "data" the patcher would have
// returned, so deny paths must never echo that fixture either.
const envWritePatchKey = "MATRIX_KEY_PATCH"

// envWritePatchBody is the minimal valid request body the matrix tests
// send: a partial update that names BOTH mutable fields. The
// distinctive value (matrix_value_patch) is deliberately recognisable
// so deny-path leak checks can prove the submitted payload is not
// echoed back, and it intentionally does NOT collide with
// seededPostPatchOrgVariable's returned value — only the seeded
// post-patch fixture is the "data" the patcher would have returned,
// so deny paths must never echo that fixture either. Naming both
// fields exercises the realistic write path (a customer rotating a
// secret while flipping is_secret).
const envWritePatchBody = `{"value":"matrix_value_patch","is_secret":true}`

// seededPostPatchOrgVariable builds the distinctive post-patch fixture
// the fake patcher returns on success. The variable is intentionally a
// SECRET so allow paths can prove the projection STILL redacts secret
// values to output.Sentinel even immediately after the customer
// submitted the value, and so deny paths can prove no fragment of the
// seeded plaintext (or the variable id/key) ever reaches the wire. The
// id/key/value are intentionally different from the matrix request
// body (envWritePatchKey/envWritePatchBody), from seededOrgVariables
// (env.read suite), and from seededPostWriteOrgVariables (PUT matrix
// suite) so a leak check that searches for the seeded post-patch data
// can never false-positive against unrelated fixtures.
func seededPostPatchOrgVariable(orgID string) store.OrganizationVariable {
	return store.OrganizationVariable{
		ID:             "ovar_post_patch",
		OrganizationID: orgID,
		Key:            "POST_PATCH_KEY",
		Value:          "post-patch-plaintext-tokenrotated-supercalifragilistic",
		IsSecret:       true,
		Version:        2,
	}
}

// postPatchOrgVariableBodyLeak reports whether body contains any
// non-public value from seededPostPatchOrgVariable — the row id, the
// variable key, and crucially every recognisable fragment of the
// secret value. A denied response that accidentally rendered any of
// these fails the test; the policy boundary is the only place a write
// is gated, so a denied caller seeing the seeded post-patch data
// would itself be a contract violation. The secret-value needles
// split the long string into distinct substrings so a partial leak
// that drops only one piece still trips the guard. The literal "true"
// is deliberately NOT in this list because it is the JSON encoding of
// every boolean field.
func postPatchOrgVariableBodyLeak(body string) bool {
	needles := []string{
		"ovar_post_patch",
		"POST_PATCH_KEY",
		"post-patch-plaintext-tokenrotated-supercalifragilistic",
		"post-patch-plaintext", "tokenrotated", "supercalifragilistic",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestPatchOrgVariablePolicyMatrixRoles drives every built-in role
// through the production request path against an {org_id} that names
// its own home organization. Owner, Admin, and Developer hold CapWrite
// and allow env.write via ReasonAllowedByRole — the patcher is reached
// with the path's {org_id} and {key} and the response carries the
// seeded post-patch row. Viewer, CI, and Support all lack CapWrite and
// are denied with a stable 403 E_FORBIDDEN carrying
// ReasonDeniedNoCapability — and in every deny path the patcher is
// never reached, so the policy boundary is the only place a single-
// variable mutation can be authorized for a non-CapWrite caller. This
// is the load-bearing difference from env.read (CapRead, all roles
// allow): a regression that downgraded the catalog's CapWrite for
// env.write to CapRead would silently let viewers and CI keys patch
// variables, and would fail this test on every Viewer/CI/Support row.
func TestPatchOrgVariablePolicyMatrixRoles(t *testing.T) {
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
			// scope input the engine sees for this route — the {key} is
			// a sub-resource within that scope.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvWrite, orgRoot)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(env.write) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			var gotInput store.PatchOrganizationVariableInput
			patcher := fakeOrgVariablePatcher{v: seededPostPatchOrgVariable(org), got: &gotInput}
			handler := patchOrgVariableHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, patcher)

			rec := patchOrgVariable(handler, org, envWritePatchKey, "a-valid-token", envWritePatchBody)

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodePatchOrgVariable(t, rec)
				if env.SchemaVersion != "yalla.output.v1" {
					t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
				}
				if env.Data.Variable.ID != "ovar_post_patch" ||
					env.Data.Variable.Key != "POST_PATCH_KEY" ||
					!env.Data.Variable.IsSecret ||
					env.Data.Variable.Version != 2 {
					t.Errorf("variable = %+v, want the seeded post-patch row (ovar_post_patch / POST_PATCH_KEY / secret / v2)",
						env.Data.Variable)
				}
				// Allowed-path redaction invariant: the secret variable's
				// value is the sentinel on the wire, not the seeded
				// plaintext. This guards the chokepoint inside the
				// role-allowed branch so a future regression that
				// bypassed organizationVariableOf for a particular
				// principal class would fail here too — even right after
				// a caller submitted a fresh secret.
				if v := env.Data.Variable.Value; v != output.Sentinel {
					t.Errorf("variable.value = %q, want sentinel — secret values must be redacted on the wire even for %s", v, tc.name)
				}
				if body := rec.Body.String(); strings.Contains(body, "post-patch-plaintext") ||
					strings.Contains(body, "tokenrotated") ||
					strings.Contains(body, "supercalifragilistic") {
					t.Errorf("response body leaked the secret value for role %s: %s", tc.name, body)
				}
				// Forwarding fidelity: the patcher receives the {org_id}
				// AND {key} path parameters AND the principal/correlation
				// fields the audit record needs. A regression that
				// dropped the {key} forwarding would silently patch the
				// wrong row; the deny-path tests cannot catch that
				// because they never reach the patcher.
				if gotInput.OrganizationID != org {
					t.Errorf("patcher received organization id %q, want the path parameter %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.Key != envWritePatchKey {
					t.Errorf("patcher received key %q, want the path parameter %q",
						gotInput.Key, envWritePatchKey)
				}
				if gotInput.Value == nil || *gotInput.Value != "matrix_value_patch" {
					t.Errorf("patcher Value pointer = %+v, want pointer to %q",
						gotInput.Value, "matrix_value_patch")
				}
				if gotInput.IsSecret == nil || !*gotInput.IsSecret {
					t.Errorf("patcher IsSecret pointer = %+v, want pointer to true", gotInput.IsSecret)
				}
				if gotInput.ActorID != principal.ID || gotInput.ActorOrgID != org {
					t.Errorf("patcher received actor=(%q, %q), want (%q, %q)",
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
			if gotInput.OrganizationID != "" || gotInput.Key != "" || gotInput.Value != nil || gotInput.IsSecret != nil {
				t.Errorf("patcher was reached with org=%q key=%q value=%+v is_secret=%+v for a denied %s; it must never run",
					gotInput.OrganizationID, gotInput.Key, gotInput.Value, gotInput.IsSecret, tc.name)
			}
			// A denied response must never leak the seeded post-patch
			// variable — the policy boundary is the only place env
			// writes are gated, so a denied caller seeing the seeded
			// post-patch data would itself be a contract violation. The
			// submitted MATRIX_KEY_PATCH/matrix_value_patch request
			// could echo back trivially in some failure modes, so the
			// deny-leak check pins the data the patcher would have
			// returned, not the data the caller just sent.
			if body := rec.Body.String(); postPatchOrgVariableBodyLeak(body) {
				t.Errorf("denied response leaks the seeded post-patch variable data: %s", body)
			}
		})
	}
}

// TestPatchOrgVariablePolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal — is
// denied action env.write with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired
// credential must never be able to patch variables of the organization
// it once had access to (a stale CI key rotating in a hostile
// DATABASE_URL value through PATCH is precisely the abuse this guards),
// the patcher must never run, and the denied body must never echo the
// principal id, the organization id, the URL {key}, or any seeded
// post-patch variable data.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0114 ("revoked key,
// expired key").
func TestPatchOrgVariablePolicyRevokedAndExpiredKeys(t *testing.T) {
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

			var gotInput store.PatchOrganizationVariableInput
			patcher := fakeOrgVariablePatcher{v: seededPostPatchOrgVariable("org_acme"), got: &gotInput}
			handler := patchOrgVariableHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, patcher)

			rec := patchOrgVariable(handler, "org_acme", envWritePatchKey, "yk_no_longer_valid", envWritePatchBody)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || gotInput.Key != "" || gotInput.Value != nil || gotInput.IsSecret != nil {
				t.Errorf("patcher was reached with org=%q key=%q value=%+v is_secret=%+v for a disabled principal; it must never run",
					gotInput.OrganizationID, gotInput.Key, gotInput.Value, gotInput.IsSecret)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, envWritePatchKey) ||
				postPatchOrgVariableBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, URL key, or seeded post-patch variable data", body)
			}
		})
	}
}

// TestPatchOrgVariablePolicyWrongOrganizationPrincipal proves env.write
// is confined to the caller's own tenant — and unlike env.read there
// is NO cross-tenant exception for support. The engine's cross-tenant
// clause only allows CapRead and CapSupport actions through the
// support exception (engine.go: `required == CapRead || required ==
// CapSupport`); CapWrite is excluded by construction. So:
//
//   - A non-support owner of org_attacker patching a variable in
//     org_victim is a deterministic 403 carrying
//     ReasonDeniedCrossTenant; the patcher is never reached, and the
//     denied body never echoes the victim organization, the URL {key},
//     the submitted value, or any seeded post-patch variable data.
//
//   - A Support principal of org_yalla — the one that COULD have read
//     another tenant's variables via env.read — cannot patch them.
//     The engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns
//     403 with no leakage. This is the load-bearing distinction from
//     BE-0108's env.read matrix (CapRead, support allowed
//     cross-tenant) and the property under test here.
//
// Bonus: a support principal cannot patch variables of its OWN home
// organization either — RoleSupport lacks CapWrite entirely. Pinning
// this verdict locks the support role's read-only-for-config posture
// at the engine level so a future catalog change cannot silently grant
// it variable-mutation authority through the home-tenant path.
//
// Privileged Yalla support that needs to patch a tenant's variable
// (e.g. during a customer-authorised secret rotation) goes through
// the explicit break-glass admin tooling, not this customer-facing
// endpoint.
func TestPatchOrgVariablePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)

	// Non-support cross-tenant principal: owner of org_attacker
	// patching a variable in org_victim is a deterministic 403, the
	// patcher never reached, and the body carries no cross-tenant id,
	// no submitted key, and no seeded post-patch data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderInput store.PatchOrganizationVariableInput
	intruderPatcher := fakeOrgVariablePatcher{
		v: seededPostPatchOrgVariable(victimOrg), got: &intruderInput,
	}
	intruderHandler := patchOrgVariableHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderPatcher)

	rec := patchOrgVariable(intruderHandler, victimOrg, envWritePatchKey, "a-valid-token", envWritePatchBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderInput.OrganizationID != "" || intruderInput.Key != "" ||
		intruderInput.Value != nil || intruderInput.IsSecret != nil {
		t.Errorf("patcher was reached with org=%q key=%q value=%+v is_secret=%+v for a cross-tenant principal; it must never run",
			intruderInput.OrganizationID, intruderInput.Key, intruderInput.Value, intruderInput.IsSecret)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, envWritePatchKey) ||
		strings.Contains(body, "matrix_value_patch") ||
		postPatchOrgVariableBodyLeak(body) {
		t.Errorf("error body %s echoed the cross-tenant organization, the URL key, the submitted payload, or the seeded post-patch variable data",
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
	// catalog maps it to CapWrite. So a Support principal patching
	// another tenant's variable is denied at the engine via
	// ReasonDeniedCrossTenant, and the handler returns 403 with no
	// leakage. This is the load-bearing distinction from BE-0108's
	// env.read matrix where the same support principal IS allowed
	// cross-tenant.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvWrite, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(env.write, foreign org) for support = %+v, want deny via %q (CapWrite is OUTSIDE the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var supportInput store.PatchOrganizationVariableInput
	supportPatcher := fakeOrgVariablePatcher{
		v: seededPostPatchOrgVariable(victimOrg), got: &supportInput,
	}
	supportHandler := patchOrgVariableHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportPatcher)
	supportRec := patchOrgVariable(supportHandler, victimOrg, envWritePatchKey, "a-valid-support-token", envWritePatchBody)
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support is NOT allowed env.write cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportInput.OrganizationID != "" || supportInput.Key != "" ||
		supportInput.Value != nil || supportInput.IsSecret != nil {
		t.Errorf("patcher was reached with org=%q key=%q value=%+v is_secret=%+v for a cross-tenant support principal; it must never run",
			supportInput.OrganizationID, supportInput.Key, supportInput.Value, supportInput.IsSecret)
	}
	if body := supportRec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, envWritePatchKey) ||
		strings.Contains(body, "matrix_value_patch") ||
		postPatchOrgVariableBodyLeak(body) {
		t.Errorf("support denied response leaked the cross-tenant organization, the URL key, the submitted payload, or the seeded post-patch variable data: %s",
			body)
	}

	// Bonus: a support principal cannot patch variables of its OWN
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

// TestPatchOrgVariablePolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production, a service grant does not reach the parent environment
// or a sibling service.
//
// Crucially for PATCH /v1/organizations/{org_id}/variables/{key}:
// env.write is evaluated against the organization-root scope the
// {org_id} path names — the {key} is a sub-resource within that
// scope, NOT a deeper-scoped resource. A
// project/environment/service-scoped grant — even an Admin grant —
// does not cover the organization root (covers() is one-way: a
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
// escalated to a single-variable mutation through the {key} sub-
// resource path. This is the load-bearing property that prevents a
// leaked project-scoped CI key from being weaponised to rotate the
// tenant's organization-level DATABASE_URL or any other single
// org-scoped variable through PATCH — a strict superset of the
// env.read containment property because the abuse here is active
// credential rotation, not enumeration, and a strict equivalent of
// the PUT containment property because the {key} sub-resource path
// does not narrow the engine's required scope.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own {org_id}, while an organization-scoped
// Developer grantee is allowed it and a Viewer grantee is denied.
func TestPatchOrgVariablePolicyGrantContainment(t *testing.T) {
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

	// PATCH /v1/organizations/{org_id}/variables/{key} mutates against
	// the organization root the {org_id} path names; the {key} is a
	// sub-resource within that scope, not a deeper-scoped resource. A
	// project/environment/service-scoped admin grant does NOT cover
	// the organization root — not even for the key's own organization
	// — so each scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to
	// patch organization-wide variables, and the patcher never runs.
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

	// Tie back at the wire: the project-scoped grantee patching a
	// variable of its OWN organization is a 403 with the stable
	// out-of-scope reason, the patcher is never reached, and the body
	// never echoes the seeded post-patch variable data — including any
	// fragment of the secret value. This is the property that makes
	// the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied broader write authority,
	// even through the {key} sub-resource path.
	var projectInput store.PatchOrganizationVariableInput
	projectPatcher := fakeOrgVariablePatcher{
		v: seededPostPatchOrgVariable(org), got: &projectInput,
	}
	projectHandler := patchOrgVariableHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectPatcher)
	rec := patchOrgVariable(projectHandler, org, envWritePatchKey, "yk_proj_scoped", envWritePatchBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectInput.OrganizationID != "" || projectInput.Key != "" ||
		projectInput.Value != nil || projectInput.IsSecret != nil {
		t.Errorf("patcher was reached with org=%q key=%q value=%+v is_secret=%+v for an out-of-scope grantee; it must never run",
			projectInput.OrganizationID, projectInput.Key, projectInput.Value, projectInput.IsSecret)
	}
	if body := rec.Body.String(); postPatchOrgVariableBodyLeak(body) {
		t.Errorf("denied response leaks the seeded post-patch variable data: %s", body)
	}

	// An organization-level Developer grant DOES cover the org-root
	// scope and — because env.write is CapWrite and Developer holds
	// CapWrite — is allowed via ReasonAllowedByGrant. The same key is
	// end-to-end allowed at the wire, with the patcher reached on the
	// {org_id} AND {key} path parameters and the response carrying the
	// seeded post-patch row. A Viewer grant at the same scope is
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

	var orgInput store.PatchOrganizationVariableInput
	orgPatcher := fakeOrgVariablePatcher{
		v: seededPostPatchOrgVariable(org), got: &orgInput,
	}
	orgHandler := patchOrgVariableHandlerFor(
		auth.Identity{Principal: orgDeveloper, Method: auth.MethodAPIKey}, nil, orgPatcher)
	allowedRec := patchOrgVariable(orgHandler, org, envWritePatchKey, "yk_org_developer", envWritePatchBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodePatchOrgVariable(t, allowedRec)
	if allowedPayload.Data.Variable.ID != "ovar_post_patch" ||
		allowedPayload.Data.Variable.Key != "POST_PATCH_KEY" {
		t.Errorf("variable = %+v, want the seeded post-patch row (ovar_post_patch / POST_PATCH_KEY)",
			allowedPayload.Data.Variable)
	}
	// Grant-allowed path STILL redacts the secret value. This is the
	// twin of the role-matrix assertion above: redaction is the
	// projection's responsibility, not the policy verdict's, and must
	// hold under both allow-by-role and allow-by-grant.
	if v := allowedPayload.Data.Variable.Value; v != output.Sentinel {
		t.Errorf("grant-allowed secret value = %q, want sentinel — the grant path must redact secrets too", v)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, "post-patch-plaintext") ||
		strings.Contains(body, "tokenrotated") ||
		strings.Contains(body, "supercalifragilistic") {
		t.Errorf("grant-allowed response leaked the secret value: %s", body)
	}
	if orgInput.OrganizationID != org {
		t.Errorf("patcher received organization id %q, want the path parameter %q",
			orgInput.OrganizationID, org)
	}
	if orgInput.Key != envWritePatchKey {
		t.Errorf("patcher received key %q, want the path parameter %q",
			orgInput.Key, envWritePatchKey)
	}
	if orgInput.Value == nil || *orgInput.Value != "matrix_value_patch" {
		t.Errorf("patcher Value = %+v, want pointer to %q", orgInput.Value, "matrix_value_patch")
	}
	if orgInput.IsSecret == nil || !*orgInput.IsSecret {
		t.Errorf("patcher IsSecret = %+v, want pointer to true", orgInput.IsSecret)
	}
	if orgInput.ActorID != orgDeveloper.ID || orgInput.ActorOrgID != org {
		t.Errorf("patcher received actor=(%q, %q), want (%q, %q)",
			orgInput.ActorID, orgInput.ActorOrgID, orgDeveloper.ID, org)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to patch somebody else's
	// variable. The cross-tenant guard fires first, since the scope's
	// organization id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionEnvWrite, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(env.write, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := patchOrgVariableHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrgVariablePatcher{v: seededPostPatchOrgVariable(org)})
	foreignRec := patchOrgVariable(foreignHandler, "org_sibling", envWritePatchKey, "yk_proj_scoped", envWritePatchBody)
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if body := foreignRec.Body.String(); postPatchOrgVariableBodyLeak(body) ||
		strings.Contains(body, envWritePatchKey) ||
		strings.Contains(body, "matrix_value_patch") {
		t.Errorf("foreign denied response leaks the seeded post-patch variable data, the URL key, or the submitted payload: %s", body)
	}
}
