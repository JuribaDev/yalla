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

// Policy-matrix coverage for DELETE /v1/organizations/{org_id}/api-keys/{key_id}
// (BE-0090). Where api_keys_delete_test.go proves the endpoint's wire
// contract, this file proves its authorization contract: that action
// keys.manage against a single key cannot be bypassed by — or leak data
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries apiKeyIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter (Kind=domain.KindAPIKey,
// Scope.OrganizationID set from the path). The {key_id} path parameter is
// NOT part of the authorization decision; it only selects which row the
// revoker stamps once the request is authorized. So a cross-tenant
// {org_id} must be a deterministic 403 before the handler runs regardless
// of the {key_id} value, while an {org_id} naming the caller's own
// organization is allowed only by an organization role that holds
// CapAdmin (owner / admin) or by a grant whose scope covers the
// organization root — never by a deeper-scoped grant, never by
// Developer/Viewer/CI, and — like the GET sibling at BE-0084 and the
// PATCH sibling at BE-0087 — never by Support's cross-tenant read
// exception.
//
// keys.manage requires CapAdmin (catalog.go: ActionKeysManage -> CapAdmin),
// because revoking an API key is a one-way credential operation that
// permanently destroys an agent principal's ability to authenticate
// against the tenant — a viewer or developer triggering it could lock
// the tenant out of CI or break-glass paths it depends on. The role
// matrix therefore matches the keys.read and keys.manage-PATCH
// siblings exactly: only Owner and Admin allow within the own
// organization; Developer, Viewer, CI, and Support all deny
// (ReasonDeniedNoCapability — they each lack CapAdmin). The engine's
// cross-tenant exception is gated on `required == CapRead || required
// == CapSupport`, so CapAdmin is OUTSIDE the support cross-tenant
// exception. A Support principal cannot revoke another tenant's keys —
// and cannot revoke its own home tenant's keys either — so a Support
// credential is structurally incapable of revoking API key metadata
// through this endpoint. Privileged Yalla support that needs key
// revocation goes through the explicit break-glass admin tooling, not
// this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the apiKeyIDResolver, or the engine fails here.
// revokeAPIKeyHandlerFor, deleteAPIKey, decodeRevokeAPIKey, orgPrincipal,
// fakeAPIKeyRevoker, seedAPIKey, and decodeError are shared with the
// sibling DELETE /v1/organizations/{org_id}/api-keys/{key_id} contract
// suite in api_keys_delete_test.go; this file adds no scaffolding.
//
// DELETE has no request body and no query parameters — the policy
// boundary fires purely off the {org_id} path parameter the resolver
// reads, so unlike the PATCH sibling there is no body shape to keep
// "structurally valid" alongside the deny verdict. A denied DELETE is a
// rejected DELETE before the revoker is touched, full stop.

// TestRevokeAPIKeyPolicyMatrixRoles drives every built-in role through the
// production request path against an ({org_id}, {key_id}) pair naming a
// key inside the principal's own home organization. Owner and Admin hold
// CapAdmin and allow keys.manage via ReasonAllowedByRole — the revoker is
// reached with both the path's {org_id} and {key_id} and the response
// carries the revoked key snapshot. Developer, Viewer, CI, and Support
// all lack CapAdmin and are denied with a stable 403 E_FORBIDDEN
// carrying ReasonDeniedNoCapability — and in every deny path the
// revoker is never reached, so the policy boundary is the only place an
// api-key row can be revoked for a non-CapAdmin caller.
func TestRevokeAPIKeyPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		keyID = "key_ada"
		pfx   = "yk_pf_ada"
	)
	cases := []struct {
		name      string
		role      policy.Role
		kind      domain.Kind
		wantAllow bool
		// wantReason is the engine Reason expected on either verdict.
		wantReason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	apiKeyScope := policy.Resource{
		Kind:  domain.KindAPIKey,
		Scope: policy.Scope{OrganizationID: org},
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	revokedAt := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine assertion: the role decision against the
			// api-key scope the resolver emits is the verdict the matrix
			// names. The {org_id} path parameter is the only input the
			// engine sees for this route — {key_id} is not consulted.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionKeysManage, apiKeyScope)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(keys.manage) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			persisted := seedAPIKey(org, keyID, pfx, "Ada CLI",
				[]string{"projects:read"}, "usr_ada", "", now, now)
			persisted.RevokedAt = &revokedAt
			var gotInput store.RevokeAPIKeyInput
			revoker := fakeAPIKeyRevoker{key: persisted, got: &gotInput}
			handler := revokeAPIKeyHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession},
				nil, revoker)

			rec := deleteAPIKey(handler, org, keyID, "a-valid-token")

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeRevokeAPIKey(t, rec)
				if env.Data.APIKey.KeyID != keyID {
					t.Errorf("api_key.key_id = %q, want %q", env.Data.APIKey.KeyID, keyID)
				}
				if gotInput.OrganizationID != org {
					t.Errorf("revoker received organization id %q, want the path parameter %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.KeyID != keyID {
					t.Errorf("revoker received key id %q, want the path parameter %q",
						gotInput.KeyID, keyID)
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
			if gotInput.OrganizationID != "" || gotInput.KeyID != "" {
				t.Errorf("revoker was reached with org=%q key=%q for a denied %s; it must never run",
					gotInput.OrganizationID, gotInput.KeyID, tc.name)
			}
			// A denied response must never leak the seeded key's identifying
			// material — the policy boundary is the only place keys are
			// gated, so a denied caller seeing a prefix or key id would
			// itself be a contract violation.
			body := rec.Body.String()
			if strings.Contains(body, keyID) || strings.Contains(body, pfx) {
				t.Errorf("denied response leaks the seeded key's id or prefix: %s", body)
			}
		})
	}
}

// TestRevokeAPIKeyPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is
// denied action keys.manage with a stable 403 E_FORBIDDEN, even when
// the underlying role would have allowed it. A revoked or expired
// credential must never be able to revoke API keys of the organization
// it once had access to (using a stale credential to scorched-earth a
// tenant's CI keys is precisely the abuse this guards), the revoker
// must never run, and the denied body must never echo the principal id,
// the organization id, or any seeded key data.
func TestRevokeAPIKeyPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			// Underlying role is Owner so a working credential WOULD allow
			// keys.manage; the disabled flag is the only thing in the way
			// and must be load-bearing.
			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var gotInput store.RevokeAPIKeyInput
			revoker := fakeAPIKeyRevoker{
				key: seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
					[]string{"projects:read"}, "usr_ada", "",
					time.Now().UTC(), time.Now().UTC()),
				got: &gotInput,
			}
			handler := revokeAPIKeyHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey},
				nil, revoker)

			rec := deleteAPIKey(handler, "org_acme", "key_ada", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || gotInput.KeyID != "" {
				t.Errorf("revoker was reached with org=%q key=%q for a disabled principal; it must never run",
					gotInput.OrganizationID, gotInput.KeyID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, "key_ada") ||
				strings.Contains(body, "yk_pf_ada") {
				t.Errorf("error body %s leaked the principal id, organization, or seeded key data", body)
			}
		})
	}
}

// TestRevokeAPIKeyPolicyWrongOrganizationPrincipal proves keys.manage is
// confined to the caller's own tenant — and like the keys.read and
// keys.manage-PATCH siblings there is NO cross-tenant exception for
// support. The engine's cross-tenant clause only allows CapRead and
// CapSupport actions through the support exception (engine.go:
// `required == CapRead || required == CapSupport`); CapAdmin is excluded
// by construction. So:
//
//   - A non-support owner of org_attacker revoking a key of org_victim
//     is a deterministic 403 carrying ReasonDeniedCrossTenant; the
//     revoker is never reached, and the denied body never echoes the
//     victim organization or any of its keys.
//   - A support principal of org_yalla — the one that COULD have read a
//     member or organization cross-tenant — cannot revoke keys. The
//     engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns 403
//     with no leakage.
//
// Privileged Yalla support that needs to revoke a tenant's keys (e.g.
// during a credential-leak incident) goes through the explicit
// break-glass admin tooling, not this customer-facing endpoint.
func TestRevokeAPIKeyPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
		victimKey = "key_victim"
		victimPfx = "yk_pf_victim"
	)

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	// Non-support cross-tenant principal: owner of org_attacker revoking
	// a key of org_victim is a deterministic 403, the revoker never
	// reached, and the body carries no cross-tenant id.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var gotIntruderInput store.RevokeAPIKeyInput
	intruderRevoker := fakeAPIKeyRevoker{
		key: seedAPIKey(victimOrg, victimKey, victimPfx, "victim",
			[]string{"projects:read"}, "usr_v", "", now, now),
		got: &gotIntruderInput,
	}
	intruderHandler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession},
		nil, intruderRevoker)

	rec := deleteAPIKey(intruderHandler, victimOrg, victimKey, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotIntruderInput.OrganizationID != "" || gotIntruderInput.KeyID != "" {
		t.Errorf("revoker was reached with org=%q key=%q for a cross-tenant request; it must never run",
			gotIntruderInput.OrganizationID, gotIntruderInput.KeyID)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) ||
		strings.Contains(body, victimKey) ||
		strings.Contains(body, victimPfx) {
		t.Errorf("error body %s echoed the cross-tenant organization or seeded key data", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so the
	// resolver-shape (api-key scope of the {org_id} path parameter) is
	// exactly what the engine sees. The {key_id} path is not consulted by
	// the engine for this action.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindAPIKey, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionKeysManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(keys.manage, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for keys.manage. Pin both
	// the engine verdict and the handler outcome — CapAdmin is excluded
	// from the support cross-tenant exception, so a Yalla support
	// principal cannot revoke another tenant's keys.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionKeysManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(keys.manage, foreign org) for support = %+v, want deny via %q (CapAdmin is excluded from the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var gotSupportInput store.RevokeAPIKeyInput
	supportRevoker := fakeAPIKeyRevoker{
		key: seedAPIKey(victimOrg, victimKey, victimPfx, "victim",
			[]string{"projects:read"}, "usr_v", "", now, now),
		got: &gotSupportInput,
	}
	supportHandler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession},
		nil, supportRevoker)
	supportRec := deleteAPIKey(supportHandler, victimOrg, victimKey,
		"a-valid-support-token")
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support cannot revoke keys cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotSupportInput.OrganizationID != "" || gotSupportInput.KeyID != "" {
		t.Errorf("revoker was reached with org=%q key=%q for a support cross-tenant revoke; it must never run",
			gotSupportInput.OrganizationID, gotSupportInput.KeyID)
	}
	supportBody := supportRec.Body.String()
	if strings.Contains(supportBody, victimOrg) ||
		strings.Contains(supportBody, victimKey) ||
		strings.Contains(supportBody, victimPfx) {
		t.Errorf("support error body %s echoed the cross-tenant organization or seeded key data", supportBody)
	}

	// Bonus: a support principal cannot revoke keys of its OWN home
	// organization either — RoleSupport lacks CapAdmin entirely, so
	// within the home tenant the verdict is ReasonDeniedNoCapability,
	// not the cross-tenant denial. This locks the support role's
	// read-only-for-non-key-data posture at the engine level so a future
	// catalog change cannot silently grant it key-revocation authority.
	supportHome := policy.Resource{Kind: domain.KindAPIKey, Scope: policy.Scope{OrganizationID: support.OrganizationID}}
	if got := e.Decide(support, policy.ActionKeysManage, supportHome); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(keys.manage, own org) for support = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
}

// TestRevokeAPIKeyPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (no organization role); the engine
// confines those grants — a project grant does not reach a sibling
// project, an environment grant does not reach production, a service
// grant does not reach the parent environment or a sibling service.
//
// Crucially for DELETE /v1/organizations/{org_id}/api-keys/{key_id}:
// keys.manage is evaluated against the api-key scope the {org_id} path
// names. A project/environment/service grant — even an Admin grant —
// does not cover that scope (covers() is one-way: a more-specific scope
// cannot reach a broader resource), not even for the key's own
// organization. So a scoped key holding only a project Admin grant is
// denied the endpoint for its own ({org_id},{key_id}) with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level
// Admin grant is allowed it (ReasonAllowedByGrant). A scoped grant
// narrows authority within a tenant; it can never be escalated to an
// organization-wide revocation of arbitrary key credentials. This is
// the load-bearing property that prevents a leaked project-scoped CI
// key from being weaponised to revoke the tenant's owner keys and lock
// the customer out of their own organization.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own ({org_id},{key_id}).
func TestRevokeAPIKeyPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		keyID = "key_ada"
		pfx   = "yk_pf_ada"
	)
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Sibling-project
	// containment is pinned via the project-write action so the grant
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

	// DELETE /v1/organizations/{org_id}/api-keys/{key_id} revokes against
	// the api-key scope the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover that
	// scope — not even for the key's own organization — so each scoped
	// grantee is denied the endpoint with ReasonDeniedOutOfScope: the
	// scoped key cannot be widened to revoke arbitrary organization-wide
	// credentials, and the revoker never runs.
	apiKeyScope := policy.Resource{Kind: domain.KindAPIKey, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionKeysManage, apiKeyScope); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionKeysManage, apiKeyScope); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionKeysManage, apiKeyScope); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee revoking a key of
	// its OWN organization is a 403 with the stable out-of-scope reason,
	// the revoker is never reached, and the body never echoes the seeded
	// key's id or prefix. This is the property that makes the policy
	// boundary — not the persistence boundary — the structural place a
	// scoped key is denied broader revocation authority.
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	var gotProjectInput store.RevokeAPIKeyInput
	projectRevoker := fakeAPIKeyRevoker{
		key: seedAPIKey(org, keyID, pfx, "Ada CLI",
			[]string{"projects:read"}, "usr_ada", "", now, now),
		got: &gotProjectInput,
	}
	projectHandler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, projectRevoker)
	rec := deleteAPIKey(projectHandler, org, keyID, "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if gotProjectInput.OrganizationID != "" || gotProjectInput.KeyID != "" {
		t.Errorf("revoker was reached with org=%q key=%q for an out-of-scope grantee; it must never run",
			gotProjectInput.OrganizationID, gotProjectInput.KeyID)
	}
	body := rec.Body.String()
	if strings.Contains(body, keyID) || strings.Contains(body, pfx) {
		t.Errorf("denied response leaks the seeded key's id or prefix: %s", body)
	}

	// An organization-level Admin grant DOES cover the api-key scope and
	// is allowed via ReasonAllowedByGrant — and the same key is
	// end-to-end allowed at the wire, with the revoker reached on both
	// the {org_id} AND {key_id} parameters. A Viewer grant is
	// intentionally NOT enough: keys.manage requires CapAdmin, not
	// CapRead. This locks the CapAdmin requirement against the grant
	// path so a future catalog change cannot silently downgrade
	// keys.manage to a read-level capability.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionKeysManage, apiKeyScope); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(keys.manage) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionKeysManage, apiKeyScope); got.Allow {
		t.Errorf("Decide(keys.manage) for an organization-level viewer grant = %+v, want deny — viewer holds CapRead, not CapAdmin",
			got)
	}

	revokedAt := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(org, keyID, pfx, "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", now, now)
	persisted.RevokedAt = &revokedAt
	var gotOrgGranteeInput store.RevokeAPIKeyInput
	orgRevoker := fakeAPIKeyRevoker{key: persisted, got: &gotOrgGranteeInput}
	orgHandler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey},
		nil, orgRevoker)
	allowedRec := deleteAPIKey(orgHandler, org, keyID, "yk_org_admin")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedEnv := decodeRevokeAPIKey(t, allowedRec)
	if allowedEnv.Data.APIKey.KeyID != keyID {
		t.Errorf("api_key.key_id = %q, want %q", allowedEnv.Data.APIKey.KeyID, keyID)
	}
	if gotOrgGranteeInput.OrganizationID != org {
		t.Errorf("revoker received organization id %q, want the path parameter %q",
			gotOrgGranteeInput.OrganizationID, org)
	}
	if gotOrgGranteeInput.KeyID != keyID {
		t.Errorf("revoker received key id %q, want the path parameter %q",
			gotOrgGranteeInput.KeyID, keyID)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to revoke somebody else's API key.
	// The cross-tenant guard fires first, since the scope's organization
	// id no longer matches the principal's own.
	siblingScope := policy.Resource{Kind: domain.KindAPIKey, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionKeysManage, siblingScope); got.Allow {
		t.Errorf("Decide(keys.manage, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, fakeAPIKeyRevoker{
			key: seedAPIKey("org_sibling", "key_x", "yk_pf_x", "x",
				[]string{}, "usr_x", "", now, now),
		})
	foreignRec := deleteAPIKey(foreignHandler, "org_sibling", "key_x", "yk_proj_scoped")
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
}
