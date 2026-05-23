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

// Policy-matrix coverage for DELETE /v1/organizations/{org_id}/variables/{key}
// (BE-0117). Where variables_delete_test.go (BE-0115) proves the
// endpoint's wire contract — the URL-parameter forwarding, the
// projection that redacts secret values in the deletion snapshot, the
// typed not-found and store-outage paths — this file proves its
// authorization contract: that action env.write cannot be bypassed by —
// or persist a mutation because of — the principal's role, revoked or
// expired credentials, home organization, or scoped grants. The DELETE
// route uses exactly the same authorization seam as PUT and PATCH
// (organizationIDResolver against the {org_id} path parameter for
// action env.write), so the matrix structure mirrors
// variables_patch_policy_test.go (BE-0114) and
// variables_put_policy_test.go (BE-0111) verbatim. The three stories
// remain separate PRD items because the wire surface (bulk replacement
// vs. single-variable PATCH vs. single-variable DELETE) is distinct,
// each with its own request shape, redaction chokepoint, and failure
// modes — and a deletion is the strictly irreversible class of write,
// the most consequential mutation any customer-facing variable
// endpoint accepts, so its authorization proof is independently
// pinned.
//
// The route carries organizationIDResolver (routes.go), which scopes
// the policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization) — the {key} is a sub-resource within
// the organization-root scope, not a deeper-scoped resource. RequireAuth
// therefore authorizes against the organization the {org_id} path
// NAMES — not merely the principal's home organization, and not
// against the {key}. So a cross-tenant {org_id} must be a deterministic
// 403 before the handler runs (and unlike CapRead siblings there is NO
// Support exception for CapWrite), while an {org_id} naming the
// caller's own organization is allowed by an organization role that
// holds CapWrite (owner/admin/developer) or by a grant whose scope
// covers the organization root — never by a deeper-scoped grant,
// never by Viewer/CI/Support.
//
// env.write requires CapWrite (catalog.go: ActionEnvWrite -> CapWrite),
// the same capability class as project/environment/service create/
// update/delete. The role matrix therefore allows Owner/Admin/Developer
// at the own organization (each holds CapWrite) and denies
// Viewer/CI/Support (none of which hold CapWrite) — and the engine's
// cross-tenant clause is gated on `required == CapRead || required ==
// CapSupport`, so CapWrite is OUTSIDE the support cross-tenant
// exception. This is the load-bearing distinction from the env.read
// matrix (BE-0108): the same resolver and the same {org_id} scoping,
// but with three additional roles denied at the role boundary and with
// no Support cross-tenant allow. Privileged Yalla support that needs
// to delete a single tenant variable goes through the explicit break-
// glass admin tooling, not this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the organizationIDResolver, or the engine fails here.
// deleteOrgVariableHandlerFor, deleteOrgVariable, decodeDeleteOrgVariable,
// fakeOrgVariableDeleter, orgVariableActorIdentity, orgPrincipal, and
// decodeError are shared with the sibling DELETE contract suite
// (variables_delete_test.go) and the env.read/PATCH/PUT policy
// suites. This file adds only the small fixtures below.

// envWriteDeleteKey is the {key} URL path parameter the matrix tests
// send. It is intentionally distinctive (caller-submitted needle) so
// deny-path leak checks can prove the URL key is not echoed back, and
// it does NOT collide with seededDeletedOrgVariable's returned Key —
// the seeded deletion snapshot is the "data" the deleter would have
// returned, so deny paths must never echo that fixture either. The
// value is deliberately not a real variable name a tenant would have
// configured, so any echo in a deny body is a contract failure rather
// than a coincidental collision with production fixtures.
const envWriteDeleteKey = "MATRIX_KEY_DELETE"

// seededDeletedOrgVariable builds the distinctive deletion snapshot
// the fake deleter returns on success — the variable exactly as it
// stood at the moment of removal, which the endpoint projects onto the
// wire (mirroring every other organization-variables endpoint). The
// variable is intentionally a SECRET so allow paths can prove the
// projection STILL redacts secret values to output.Sentinel even at
// the moment of deletion (a customer can never read a secret value
// back through the DELETE response), and so deny paths can prove no
// fragment of the seeded plaintext (or the variable id/key) ever
// reaches the wire. The id/key/value are intentionally different from
// envWriteDeleteKey, from seededOrgVariables (env.read suite),
// seededPostWriteOrgVariables (PUT matrix suite), and
// seededPostPatchOrgVariable (PATCH matrix suite) so a leak check
// that searches for the deletion snapshot can never false-positive
// against unrelated fixtures.
func seededDeletedOrgVariable(orgID string) store.OrganizationVariable {
	return store.OrganizationVariable{
		ID:             "ovar_deleted",
		OrganizationID: orgID,
		Key:            "DELETED_KEY",
		Value:          "deletion-snapshot-plaintext-tokenburned-antidisestablishmentarianism",
		IsSecret:       true,
		Version:        4,
	}
}

// deletedOrgVariableBodyLeak reports whether body contains any
// non-public value from seededDeletedOrgVariable — the row id, the
// variable key, and crucially every recognisable fragment of the
// secret value. A denied response that accidentally rendered any of
// these fails the test; the policy boundary is the only place a
// delete is gated, so a denied caller seeing the deletion snapshot
// would itself be a contract violation. The secret-value needles
// split the long string into distinct substrings so a partial leak
// that drops only one piece still trips the guard. The literal "true"
// is deliberately NOT in this list because it is the JSON encoding of
// every boolean field.
func deletedOrgVariableBodyLeak(body string) bool {
	needles := []string{
		"ovar_deleted",
		"DELETED_KEY",
		"deletion-snapshot-plaintext-tokenburned-antidisestablishmentarianism",
		"deletion-snapshot-plaintext", "tokenburned", "antidisestablishmentarianism",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestDeleteOrgVariablePolicyMatrixRoles drives every built-in role
// through the production request path against an {org_id} that names
// its own home organization. Owner, Admin, and Developer hold CapWrite
// and allow env.write via ReasonAllowedByRole — the deleter is reached
// with the path's {org_id} and {key} and the response carries the
// seeded deletion snapshot. Viewer, CI, and Support all lack CapWrite
// and are denied with a stable 403 E_FORBIDDEN carrying
// ReasonDeniedNoCapability — and in every deny path the deleter is
// never reached, so the policy boundary is the only place a single-
// variable removal can be authorized for a non-CapWrite caller. This
// is the load-bearing difference from env.read (CapRead, all roles
// allow): a regression that downgraded the catalog's CapWrite for
// env.write to CapRead would silently let viewers and CI keys delete
// variables, and would fail this test on every Viewer/CI/Support row.
// A delete is irreversible at the customer surface (the row is gone
// from the variables table once the transaction commits; only an
// audit-log replay can reconstruct what was there), so the authorization
// boundary is the load-bearing place to pin this.
func TestDeleteOrgVariablePolicyMatrixRoles(t *testing.T) {
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

			var gotInput store.DeleteOrganizationVariableInput
			deleter := fakeOrgVariableDeleter{v: seededDeletedOrgVariable(org), got: &gotInput}
			handler := deleteOrgVariableHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, deleter)

			rec := deleteOrgVariable(handler, org, envWriteDeleteKey, "a-valid-token")

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeDeleteOrgVariable(t, rec)
				if env.SchemaVersion != "yalla.output.v1" {
					t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
				}
				if env.Data.Variable.ID != "ovar_deleted" ||
					env.Data.Variable.Key != "DELETED_KEY" ||
					!env.Data.Variable.IsSecret ||
					env.Data.Variable.Version != 4 {
					t.Errorf("variable = %+v, want the seeded deletion snapshot (ovar_deleted / DELETED_KEY / secret / v4)",
						env.Data.Variable)
				}
				// Allowed-path redaction invariant: the secret variable's
				// value is the sentinel on the wire, not the seeded
				// plaintext. This guards the chokepoint inside the
				// role-allowed branch so a future regression that
				// bypassed organizationVariableOf for a particular
				// principal class would fail here too — even on the
				// moment-of-deletion snapshot a caller never previously
				// read.
				if v := env.Data.Variable.Value; v != output.Sentinel {
					t.Errorf("variable.value = %q, want sentinel — secret values must be redacted on the wire even at deletion for %s", v, tc.name)
				}
				if body := rec.Body.String(); strings.Contains(body, "deletion-snapshot-plaintext") ||
					strings.Contains(body, "tokenburned") ||
					strings.Contains(body, "antidisestablishmentarianism") {
					t.Errorf("response body leaked the secret value for role %s: %s", tc.name, body)
				}
				// Forwarding fidelity: the deleter receives the {org_id}
				// AND {key} path parameters AND the principal/correlation
				// fields the audit record needs. A regression that
				// dropped the {key} forwarding would silently delete the
				// wrong row; the deny-path tests cannot catch that
				// because they never reach the deleter.
				if gotInput.OrganizationID != org {
					t.Errorf("deleter received organization id %q, want the path parameter %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.Key != envWriteDeleteKey {
					t.Errorf("deleter received key %q, want the path parameter %q",
						gotInput.Key, envWriteDeleteKey)
				}
				if gotInput.ActorID != principal.ID || gotInput.ActorOrgID != org {
					t.Errorf("deleter received actor=(%q, %q), want (%q, %q)",
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
			if gotInput.OrganizationID != "" || gotInput.Key != "" {
				t.Errorf("deleter was reached with org=%q key=%q for a denied %s; it must never run",
					gotInput.OrganizationID, gotInput.Key, tc.name)
			}
			// A denied response must never leak the seeded deletion
			// snapshot — the policy boundary is the only place env
			// writes are gated, so a denied caller seeing the deleted
			// variable data would itself be a contract violation. The
			// submitted MATRIX_KEY_DELETE URL parameter could echo back
			// trivially in some failure modes, so the deny-leak check
			// pins the data the deleter would have returned, not the
			// URL the caller just sent.
			if body := rec.Body.String(); deletedOrgVariableBodyLeak(body) {
				t.Errorf("denied response leaks the seeded deletion snapshot: %s", body)
			}
		})
	}
}

// TestDeleteOrgVariablePolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which the
// auth layer surfaces to the policy engine as a Disabled principal — is
// denied action env.write with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired
// credential must never be able to delete variables of the organization
// it once had access to (a stale CI key wiping a tenant's
// DATABASE_URL through DELETE is precisely the abuse this guards — and
// a delete is the irreversible class of write, the worst form of this
// abuse), the deleter must never run, and the denied body must never
// echo the principal id, the organization id, the URL {key}, or any
// seeded deletion-snapshot data.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0117 ("revoked key,
// expired key").
func TestDeleteOrgVariablePolicyRevokedAndExpiredKeys(t *testing.T) {
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

			var gotInput store.DeleteOrganizationVariableInput
			deleter := fakeOrgVariableDeleter{v: seededDeletedOrgVariable("org_acme"), got: &gotInput}
			handler := deleteOrgVariableHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, deleter)

			rec := deleteOrgVariable(handler, "org_acme", envWriteDeleteKey, "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || gotInput.Key != "" {
				t.Errorf("deleter was reached with org=%q key=%q for a disabled principal; it must never run",
					gotInput.OrganizationID, gotInput.Key)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, envWriteDeleteKey) ||
				deletedOrgVariableBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, URL key, or seeded deletion-snapshot data", body)
			}
		})
	}
}

// TestDeleteOrgVariablePolicyWrongOrganizationPrincipal proves env.write
// is confined to the caller's own tenant — and unlike env.read there
// is NO cross-tenant exception for support. The engine's cross-tenant
// clause only allows CapRead and CapSupport actions through the
// support exception (engine.go: `required == CapRead || required ==
// CapSupport`); CapWrite is excluded by construction. So:
//
//   - A non-support owner of org_attacker deleting a variable in
//     org_victim is a deterministic 403 carrying
//     ReasonDeniedCrossTenant; the deleter is never reached, and the
//     denied body never echoes the victim organization, the URL {key},
//     or any seeded deletion-snapshot data.
//
//   - A Support principal of org_yalla — the one that COULD have read
//     another tenant's variables via env.read — cannot delete them.
//     The engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns
//     403 with no leakage. This is the load-bearing distinction from
//     BE-0108's env.read matrix (CapRead, support allowed
//     cross-tenant) and the property under test here. Delete is the
//     irreversible class of write, so this gap is especially load-
//     bearing: a privileged-support cross-tenant DELETE would be a
//     silent data-loss vector across the customer base.
//
// Bonus: a support principal cannot delete variables of its OWN home
// organization either — RoleSupport lacks CapWrite entirely. Pinning
// this verdict locks the support role's read-only-for-config posture
// at the engine level so a future catalog change cannot silently grant
// it variable-mutation authority through the home-tenant path.
//
// Privileged Yalla support that needs to delete a tenant's variable
// (e.g. during a customer-authorised secret rotation) goes through
// the explicit break-glass admin tooling, not this customer-facing
// endpoint.
func TestDeleteOrgVariablePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)

	// Non-support cross-tenant principal: owner of org_attacker
	// deleting a variable in org_victim is a deterministic 403, the
	// deleter never reached, and the body carries no cross-tenant id,
	// no submitted key, and no deletion-snapshot data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderInput store.DeleteOrganizationVariableInput
	intruderDeleter := fakeOrgVariableDeleter{
		v: seededDeletedOrgVariable(victimOrg), got: &intruderInput,
	}
	intruderHandler := deleteOrgVariableHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderDeleter)

	rec := deleteOrgVariable(intruderHandler, victimOrg, envWriteDeleteKey, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderInput.OrganizationID != "" || intruderInput.Key != "" {
		t.Errorf("deleter was reached with org=%q key=%q for a cross-tenant principal; it must never run",
			intruderInput.OrganizationID, intruderInput.Key)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, envWriteDeleteKey) ||
		deletedOrgVariableBodyLeak(body) {
		t.Errorf("error body %s echoed the cross-tenant organization, the URL key, or the seeded deletion-snapshot data",
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
	// catalog maps it to CapWrite. So a Support principal deleting
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

	var supportInput store.DeleteOrganizationVariableInput
	supportDeleter := fakeOrgVariableDeleter{
		v: seededDeletedOrgVariable(victimOrg), got: &supportInput,
	}
	supportHandler := deleteOrgVariableHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportDeleter)
	supportRec := deleteOrgVariable(supportHandler, victimOrg, envWriteDeleteKey, "a-valid-support-token")
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support is NOT allowed env.write cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportInput.OrganizationID != "" || supportInput.Key != "" {
		t.Errorf("deleter was reached with org=%q key=%q for a cross-tenant support principal; it must never run",
			supportInput.OrganizationID, supportInput.Key)
	}
	if body := supportRec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, envWriteDeleteKey) ||
		deletedOrgVariableBodyLeak(body) {
		t.Errorf("support denied response leaked the cross-tenant organization, the URL key, or the seeded deletion-snapshot data: %s",
			body)
	}

	// Bonus: a support principal cannot delete variables of its OWN
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

// TestDeleteOrgVariablePolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production, a service grant does not reach the parent environment
// or a sibling service.
//
// Crucially for DELETE /v1/organizations/{org_id}/variables/{key}:
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
// escalated to a single-variable deletion through the {key} sub-
// resource path. This is the load-bearing property that prevents a
// leaked project-scoped CI key from being weaponised to wipe the
// tenant's organization-level DATABASE_URL or any other single
// org-scoped variable through DELETE — a strict superset of the
// env.read containment property because the abuse here is irreversible
// data loss, not enumeration, and a strict equivalent of the PUT and
// PATCH containment properties because the {key} sub-resource path
// does not narrow the engine's required scope.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own {org_id}, while an organization-scoped
// Developer grantee is allowed it and a Viewer grantee is denied.
func TestDeleteOrgVariablePolicyGrantContainment(t *testing.T) {
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

	// DELETE /v1/organizations/{org_id}/variables/{key} mutates against
	// the organization root the {org_id} path names; the {key} is a
	// sub-resource within that scope, not a deeper-scoped resource. A
	// project/environment/service-scoped admin grant does NOT cover
	// the organization root — not even for the key's own organization
	// — so each scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to
	// delete organization-wide variables, and the deleter never runs.
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

	// Tie back at the wire: the project-scoped grantee deleting a
	// variable of its OWN organization is a 403 with the stable
	// out-of-scope reason, the deleter is never reached, and the body
	// never echoes the seeded deletion-snapshot data — including any
	// fragment of the secret value. This is the property that makes
	// the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied broader write authority,
	// even through the {key} sub-resource path.
	var projectInput store.DeleteOrganizationVariableInput
	projectDeleter := fakeOrgVariableDeleter{
		v: seededDeletedOrgVariable(org), got: &projectInput,
	}
	projectHandler := deleteOrgVariableHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectDeleter)
	rec := deleteOrgVariable(projectHandler, org, envWriteDeleteKey, "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectInput.OrganizationID != "" || projectInput.Key != "" {
		t.Errorf("deleter was reached with org=%q key=%q for an out-of-scope grantee; it must never run",
			projectInput.OrganizationID, projectInput.Key)
	}
	if body := rec.Body.String(); deletedOrgVariableBodyLeak(body) {
		t.Errorf("denied response leaks the seeded deletion-snapshot data: %s", body)
	}

	// An organization-level Developer grant DOES cover the org-root
	// scope and — because env.write is CapWrite and Developer holds
	// CapWrite — is allowed via ReasonAllowedByGrant. The same key is
	// end-to-end allowed at the wire, with the deleter reached on the
	// {org_id} AND {key} path parameters and the response carrying the
	// seeded deletion snapshot. A Viewer grant at the same scope is
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

	var orgInput store.DeleteOrganizationVariableInput
	orgDeleter := fakeOrgVariableDeleter{
		v: seededDeletedOrgVariable(org), got: &orgInput,
	}
	orgHandler := deleteOrgVariableHandlerFor(
		auth.Identity{Principal: orgDeveloper, Method: auth.MethodAPIKey}, nil, orgDeleter)
	allowedRec := deleteOrgVariable(orgHandler, org, envWriteDeleteKey, "yk_org_developer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeDeleteOrgVariable(t, allowedRec)
	if allowedPayload.Data.Variable.ID != "ovar_deleted" ||
		allowedPayload.Data.Variable.Key != "DELETED_KEY" {
		t.Errorf("variable = %+v, want the seeded deletion snapshot (ovar_deleted / DELETED_KEY)",
			allowedPayload.Data.Variable)
	}
	// Grant-allowed path STILL redacts the secret value. This is the
	// twin of the role-matrix assertion above: redaction is the
	// projection's responsibility, not the policy verdict's, and must
	// hold under both allow-by-role and allow-by-grant — even on the
	// moment-of-deletion snapshot.
	if v := allowedPayload.Data.Variable.Value; v != output.Sentinel {
		t.Errorf("grant-allowed secret value = %q, want sentinel — the grant path must redact secrets too", v)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, "deletion-snapshot-plaintext") ||
		strings.Contains(body, "tokenburned") ||
		strings.Contains(body, "antidisestablishmentarianism") {
		t.Errorf("grant-allowed response leaked the secret value: %s", body)
	}
	if orgInput.OrganizationID != org {
		t.Errorf("deleter received organization id %q, want the path parameter %q",
			orgInput.OrganizationID, org)
	}
	if orgInput.Key != envWriteDeleteKey {
		t.Errorf("deleter received key %q, want the path parameter %q",
			orgInput.Key, envWriteDeleteKey)
	}
	if orgInput.ActorID != orgDeveloper.ID || orgInput.ActorOrgID != org {
		t.Errorf("deleter received actor=(%q, %q), want (%q, %q)",
			orgInput.ActorID, orgInput.ActorOrgID, orgDeveloper.ID, org)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to wipe somebody else's
	// variable. The cross-tenant guard fires first, since the scope's
	// organization id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionEnvWrite, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(env.write, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := deleteOrgVariableHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrgVariableDeleter{v: seededDeletedOrgVariable(org)})
	foreignRec := deleteOrgVariable(foreignHandler, "org_sibling", envWriteDeleteKey, "yk_proj_scoped")
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if body := foreignRec.Body.String(); deletedOrgVariableBodyLeak(body) ||
		strings.Contains(body, envWriteDeleteKey) {
		t.Errorf("foreign denied response leaks the seeded deletion-snapshot data or the URL key: %s", body)
	}
}
