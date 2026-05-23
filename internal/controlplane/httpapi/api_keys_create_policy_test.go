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

// Policy-matrix coverage for POST /v1/organizations/{org_id}/api-keys
// (BE-0081). Where api_keys_create_test.go proves the endpoint's wire
// contract (BE-0079), this file proves its authorization contract: that
// action keys.manage cannot be bypassed by — or persist a credential
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes against
// the organization the {org_id} path NAMES — not merely the principal's
// home organization. So a cross-tenant {org_id} must be a deterministic 403
// before the handler runs, while an {org_id} naming the caller's own
// organization is allowed only by an organization role that holds CapAdmin
// (owner/admin) or by a grant whose scope covers the organization root —
// never by a deeper-scoped grant, never by Developer/Viewer/CI, and — the
// load-bearing distinction from members.read — never by Support's
// cross-tenant read exception.
//
// keys.manage requires CapAdmin (catalog.go: ActionKeysManage->CapAdmin),
// because minting an API key creates a long-lived credential that can act
// across the organization until rotated or revoked: it is strictly more
// privileged than enumerating keys, and accidentally widening the role
// matrix would let a Developer or Viewer fabricate a credential it could
// never have been granted directly. The role matrix therefore matches its
// keys.read sibling (BE-0078) exactly — Owner/Admin allow,
// Developer/Viewer/CI/Support all deny — and is independently locked here:
// keys.read and keys.manage share a capability today, but the engine
// catalog can change, and a regression that downgraded keys.manage to a
// non-Admin capability would be a credential-minting escalation.
//
// Support is the load-bearing distinction from the read sibling story: the
// engine's cross-tenant exception is gated on
// `required == CapRead || required == CapSupport`, so CapAdmin is OUTSIDE
// the support cross-tenant exception. A Support principal cannot mint a
// key in another tenant — and cannot mint a key in its own home tenant
// either — so a Support credential is structurally incapable of creating
// API keys through this endpoint. Privileged Yalla support that needs to
// mint a key on a customer's behalf goes through the explicit break-glass
// admin tooling, not this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// createAPIKeyHandlerFor, postAPIKey, decodeCreateAPIKey, orgPrincipal,
// fakeAPIKeyCreator, seedAPIKey, and decodeError are shared with the
// sibling POST /v1/organizations/{org_id}/api-keys contract suite in
// api_keys_create_test.go; this file adds no scaffolding.

// validCreateAPIKeyBody is the minimal accepted request body for the POST
// endpoint. The name is intentionally short and free of identifying
// material that the test then asserts is NOT echoed back on a denial: the
// authentication / authorization layer rejects before the body is parsed,
// so no field of the request must leak into the 403 envelope.
const validCreateAPIKeyBody = `{"name":"matrix"}`

// TestCreateAPIKeyPolicyMatrixRoles drives every built-in role through the
// production request path against an {org_id} that names its own home
// organization. Owner and Admin hold CapAdmin and allow keys.manage via
// ReasonAllowedByRole — the creator is reached with the path's {org_id}
// and the response carries the persisted projection plus the one-time
// plaintext token. Developer, Viewer, CI, and Support all lack CapAdmin
// and are denied with a stable 403 E_FORBIDDEN carrying
// ReasonDeniedNoCapability — and in every deny path the creator is never
// reached, so the policy boundary is the only place a key can be minted
// for a non-CapAdmin caller.
func TestCreateAPIKeyPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		keyID = "key_ada"
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

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine assertion: the role decision against the
			// organization-root scope the resolver emits is the verdict the
			// matrix names. The {org_id} path parameter is the only input
			// the engine sees for this route.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionKeysManage, orgRoot)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(keys.manage) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			// Capture the input the creator saw, so a denied caller's
			// creator-never-reached invariant is structural — a 403 alone
			// is not enough, because the creator could in principle have
			// run and still produced a 403 via a downstream error.
			var captured store.CreateAPIKeyInput
			creator := fakeAPIKeyCreator{
				key: seedAPIKey(org, keyID, "yk_pf_ada", "Ada's CLI key",
					[]string{"projects:read"}, "usr_ada", "", now, now),
				got: &captured,
			}
			handler := createAPIKeyHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession},
				nil, creator)

			rec := postAPIKey(handler, org, "a-valid-token", validCreateAPIKeyBody)

			if tc.wantAllow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				env := decodeCreateAPIKey(t, rec)
				if env.Data.APIKey.KeyID != keyID {
					t.Errorf("key_id = %q, want the seeded key %q", env.Data.APIKey.KeyID, keyID)
				}
				if env.Data.Token == "" {
					t.Errorf("token is empty, want the one-time plaintext credential")
				}
				if captured.OrganizationID != org {
					t.Errorf("creator received organization id %q, want the path parameter %q",
						captured.OrganizationID, org)
				}
				// The seedAPIKey sentinel must never reach the wire: the
				// success projection omits secret_hash by construction.
				body := rec.Body.String()
				if strings.Contains(body, "must-not-leak-secret-hash-sentinel") {
					t.Errorf("success response leaks the seeded secret_hash sentinel: %s", body)
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
			if captured.OrganizationID != "" {
				t.Errorf("creator was reached with org=%q for a denied %s; it must never run",
					captured.OrganizationID, tc.name)
			}
			// A denied response must never echo the principal id, the
			// supplied request name, or fabricate the seeded key's
			// identifying material — the policy boundary is the only place
			// the mint is gated, and a denied caller seeing any of that
			// would itself be a contract violation.
			body := rec.Body.String()
			if strings.Contains(body, "usr_"+tc.name) ||
				strings.Contains(body, `"matrix"`) ||
				strings.Contains(body, keyID) ||
				strings.Contains(body, "yk_pf_ada") {
				t.Errorf("denied response leaks principal id, request name, or fabricated key data: %s", body)
			}
		})
	}
}

// TestCreateAPIKeyPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is denied
// action keys.manage with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired credential
// must never be able to mint a fresh credential in the organization it
// once had access to (otherwise revocation is meaningless), the creator
// must never run, and the denied body must never echo the principal id,
// the organization id, or the request name.
func TestCreateAPIKeyPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			var captured store.CreateAPIKeyInput
			creator := fakeAPIKeyCreator{got: &captured}
			handler := createAPIKeyHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey},
				nil, creator)

			rec := postAPIKey(handler, "org_acme", "yk_no_longer_valid", validCreateAPIKeyBody)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" {
				t.Errorf("creator was reached with org=%q for a disabled principal; it must never run",
					captured.OrganizationID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, `"matrix"`) {
				t.Errorf("error body %s leaked the principal id, organization, or request name", body)
			}
		})
	}
}

// TestCreateAPIKeyPolicyWrongOrganizationPrincipal proves keys.manage is
// confined to the caller's own tenant — and unlike CapRead actions there
// is NO cross-tenant exception for support. The engine's cross-tenant
// clause only allows CapRead and CapSupport actions through the support
// exception (engine.go: `required == CapRead || required == CapSupport`);
// CapAdmin is excluded by construction. So:
//
//   - A non-support owner of org_attacker minting a key in org_victim is a
//     deterministic 403 carrying ReasonDeniedCrossTenant; the creator is
//     never reached, and the denied body never echoes the victim
//     organization or the request name.
//   - A support principal of org_yalla — the one that COULD have read a
//     member or organization cross-tenant — cannot mint a key in another
//     tenant. The engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns 403
//     with no leakage.
//
// This is the load-bearing distinction from BE-0042 / BE-0069 and the
// reason this story exists separately. Privileged Yalla support that
// needs to mint a key on a customer's behalf goes through the explicit
// break-glass admin tooling, not this customer-facing endpoint.
func TestCreateAPIKeyPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)

	// Non-support cross-tenant principal: owner of org_attacker minting a
	// key in org_victim is a deterministic 403, the creator never reached,
	// and the body carries no cross-tenant id or request name.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderCaptured store.CreateAPIKeyInput
	intruderCreator := fakeAPIKeyCreator{got: &intruderCaptured}
	intruderHandler := createAPIKeyHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession},
		nil, intruderCreator)

	rec := postAPIKey(intruderHandler, victimOrg, "a-valid-token", validCreateAPIKeyBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with org=%q for a cross-tenant request; it must never run",
			intruderCaptured.OrganizationID)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) ||
		strings.Contains(body, `"matrix"`) {
		t.Errorf("error body %s echoed the cross-tenant organization or request name", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so the
	// resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionKeysManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(keys.manage, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for keys.manage. Pin both
	// the engine verdict and the handler outcome, since support IS the
	// exception for the members.read / org.read sibling stories. This is
	// the load-bearing assertion that distinguishes this matrix from any
	// CapRead/CapSupport one.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionKeysManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(keys.manage, foreign org) for support = %+v, want deny via %q (CapAdmin is excluded from the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var supportCaptured store.CreateAPIKeyInput
	supportCreator := fakeAPIKeyCreator{got: &supportCaptured}
	supportHandler := createAPIKeyHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession},
		nil, supportCreator)
	supportRec := postAPIKey(supportHandler, victimOrg, "a-valid-support-token", validCreateAPIKeyBody)
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support cannot mint keys cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with org=%q for a support cross-tenant mint; it must never run",
			supportCaptured.OrganizationID)
	}
	supportBody := supportRec.Body.String()
	if strings.Contains(supportBody, victimOrg) ||
		strings.Contains(supportBody, `"matrix"`) {
		t.Errorf("support error body %s echoed the cross-tenant organization or request name", supportBody)
	}

	// Bonus: a support principal cannot mint keys in its OWN home
	// organization either — RoleSupport lacks CapAdmin entirely, so within
	// the home tenant the verdict is ReasonDeniedNoCapability, not the
	// cross-tenant denial. This locks the support role's read-only-for-
	// non-key-data posture at the engine level so a future catalog change
	// cannot silently grant it key-minting authority.
	supportHome := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: support.OrganizationID}}
	if got := e.Decide(support, policy.ActionKeysManage, supportHome); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(keys.manage, own org) for support = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
}

// TestCreateAPIKeyPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (no organization role); the engine
// confines those grants — a project grant does not reach a sibling
// project, an environment grant does not reach production, a service
// grant does not reach the parent environment or a sibling service.
//
// Crucially for POST /v1/organizations/{org_id}/api-keys: keys.manage is
// evaluated against the organization-root scope the {org_id} path names.
// A project/environment/service grant — even an Admin grant — does not
// cover that scope (covers() is one-way: a more-specific scope cannot
// reach a broader resource), not even for the key's own organization. So
// a scoped key holding only a project Admin grant is denied the endpoint
// for its own {org_id} with the stable ReasonDeniedOutOfScope, while a
// key holding an organization-level Admin grant is allowed it
// (ReasonAllowedByGrant). A scoped grant narrows authority within a
// tenant; it can never be escalated to organization-wide credential
// minting.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied back
// to the wire by proving the project grantee is denied the endpoint at
// its own {org_id}. The CapAdmin requirement is also locked against the
// grant path: an organization-level Viewer grant does NOT mint a key, so
// keys.manage cannot be silently downgraded to a read-level capability.
func TestCreateAPIKeyPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		keyID = "key_ada"
	)
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Sibling-project
	// containment is pinned via the project-write action so the grant has
	// the relevant capability at the relevant scope.
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

	// Service-level grant: admin on a single service only. The grant must
	// not expose parent-level secrets (env-write on the parent
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

	// POST /v1/organizations/{org_id}/api-keys mints against the
	// organization root the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover that
	// scope — not even for the key's own organization — so each scoped
	// grantee is denied the endpoint with ReasonDeniedOutOfScope: the
	// scoped key cannot be widened to mint an organization-wide
	// credential, and the creator never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionKeysManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionKeysManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionKeysManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(keys.manage) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee minting a key in
	// its OWN organization is a 403 with the stable out-of-scope reason,
	// the creator is never reached, and the body never echoes the
	// request name. This is the property that makes the policy boundary —
	// not the persistence boundary — the structural place a scoped key
	// is denied broader minting authority.
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	var projectCaptured store.CreateAPIKeyInput
	projectCreator := fakeAPIKeyCreator{
		key: seedAPIKey(org, keyID, "yk_pf_ada", "Ada's CLI key",
			[]string{"projects:read"}, "usr_ada", "", now, now),
		got: &projectCaptured,
	}
	projectHandler := createAPIKeyHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, projectCreator)
	rec := postAPIKey(projectHandler, org, "yk_proj_scoped", validCreateAPIKeyBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with org=%q for an out-of-scope grantee; it must never run",
			projectCaptured.OrganizationID)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"matrix"`) ||
		strings.Contains(body, keyID) ||
		strings.Contains(body, "yk_pf_ada") {
		t.Errorf("denied response leaks the request name or fabricated key data: %s", body)
	}

	// An organization-level Admin grant DOES cover the org-root scope and
	// is allowed via ReasonAllowedByGrant — and the same key is end-to-end
	// allowed at the wire, with the creator reached on the {org_id}
	// parameter. A Viewer grant is intentionally NOT enough: keys.manage
	// requires CapAdmin, not CapRead. This locks the CapAdmin requirement
	// against the grant path so a future catalog change cannot silently
	// downgrade keys.manage to a read-level capability.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionKeysManage, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(keys.manage) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionKeysManage, orgRoot); got.Allow {
		t.Errorf("Decide(keys.manage) for an organization-level viewer grant = %+v, want deny — viewer holds CapRead, not CapAdmin",
			got)
	}

	var orgGranteeCaptured store.CreateAPIKeyInput
	orgCreator := fakeAPIKeyCreator{
		key: seedAPIKey(org, keyID, "yk_pf_ada", "Ada's CLI key",
			[]string{"projects:read"}, "usr_ada", "", now, now),
		got: &orgGranteeCaptured,
	}
	orgHandler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey},
		nil, orgCreator)
	allowedRec := postAPIKey(orgHandler, org, "yk_org_admin", validCreateAPIKeyBody)
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedEnv := decodeCreateAPIKey(t, allowedRec)
	if allowedEnv.Data.APIKey.KeyID != keyID {
		t.Errorf("key_id = %q, want the seeded key %q", allowedEnv.Data.APIKey.KeyID, keyID)
	}
	if allowedEnv.Data.Token == "" {
		t.Errorf("token is empty, want the one-time plaintext credential")
	}
	if orgGranteeCaptured.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the path parameter %q",
			orgGranteeCaptured.OrganizationID, org)
	}

	// And the same project-scoped grantee against a foreign {org_id} is
	// still denied — a scoped key cannot be smuggled across tenants by
	// fabricating a path parameter to mint somebody else's API key. The
	// cross-tenant guard fires first, since the scope's organization id
	// no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionKeysManage, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(keys.manage, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	var foreignCaptured store.CreateAPIKeyInput
	foreignCreator := fakeAPIKeyCreator{got: &foreignCaptured}
	foreignHandler := createAPIKeyHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, foreignCreator)
	foreignRec := postAPIKey(foreignHandler, "org_sibling", "yk_proj_scoped", validCreateAPIKeyBody)
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-tenant {org_id} on a scoped key; body %s",
			foreignRec.Code, foreignRec.Body.String())
	}
	foreignEnv := decodeError(t, foreignRec, "E_FORBIDDEN")
	if !strings.Contains(foreignEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("foreign message = %q, want it to carry the stable reason %q",
			foreignEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if foreignCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with org=%q for a cross-tenant scoped-grant mint; it must never run",
			foreignCaptured.OrganizationID)
	}
}
