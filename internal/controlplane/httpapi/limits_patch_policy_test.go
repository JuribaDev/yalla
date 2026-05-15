package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for PATCH /v1/organizations/{org_id}/limits
// (BE-0099). Where limits_patch_test.go proves the endpoint's wire
// contract, this file proves its authorization contract: that action
// limits.write cannot be bypassed by — or leak data because of — the
// principal's role, revoked credentials, home organization, or scoped
// grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes against
// the organization the {org_id} path NAMES — not merely the principal's
// home organization. So a cross-tenant {org_id} must be a deterministic
// 403 before the handler runs, while an {org_id} naming the caller's own
// organization is allowed only by an organization role that holds CapAdmin
// (owner / admin) or by a grant whose scope covers the organization root —
// never by a deeper-scoped grant, never by Developer/Viewer/CI, and —
// unlike CapRead siblings — never by Support's cross-tenant read
// exception.
//
// limits.write requires CapAdmin (catalog.go: ActionLimitsWrite->CapAdmin),
// because mutating quota policies can immediately enable or block
// allocations across the whole tenant — a viewer or developer flipping a
// hard limit to zero could lock production out of provisioning, and an
// adversary with read-only access escalating to a write could starve the
// tenant or hide an exfiltration spike behind a metered ceiling. The role
// matrix therefore matches the keys.manage matrix exactly: only Owner and
// Admin allow within the own organization; Developer, Viewer, CI, and
// Support all deny (ReasonDeniedNoCapability — they each lack CapAdmin).
// The engine's cross-tenant exception is gated on `required == CapRead ||
// required == CapSupport`, so CapAdmin is OUTSIDE the support cross-tenant
// exception — a Support principal cannot mutate another tenant's limits,
// and cannot mutate its own home tenant's limits either, so the support
// role is structurally incapable of reaching this endpoint. Privileged
// Yalla support that needs limit overrides goes through the explicit
// break-glass admin tooling, not this customer-facing route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// updateLimitsHandlerFor, patchLimits, decodeUpdateLimits, fakeLimitsUpdater,
// orgPrincipal, and decodeError are shared with the sibling PATCH
// /v1/organizations/{org_id}/limits contract suite (limits_patch_test.go)
// and the wider httpapi test fixtures; this file adds no scaffolding.

// limitsWritePatchBody is the minimal valid request body the matrix tests
// send: a single organization-scoped projects=42 override. The
// distinctive limit_value (42) is also used as a redaction probe in deny
// paths — the seeded fakeLimitsUpdater returns its own (different) value
// so the body's request payload doesn't false-positively look like the
// seeded data, and the deny-path body checks search for the seeded value,
// not the request value.
const limitsWritePatchBody = `{"limits":[{"resource":"projects","limit_value":42}]}`

// TestUpdateLimitsPolicyMatrixRoles drives every built-in role through the
// production request path against an {org_id} that names its own home
// organization. Owner and Admin hold CapAdmin and allow limits.write via
// ReasonAllowedByRole — the updater is reached with the path's {org_id}
// and the response carries the seeded post-write effective limits.
// Developer, Viewer, CI, and Support all lack CapAdmin and are denied with
// a stable 403 E_FORBIDDEN carrying ReasonDeniedNoCapability — and in
// every deny path the updater is never reached, so the policy boundary is
// the only place a quota mutation can be authorized for a non-CapAdmin
// caller. This is the load-bearing difference from limits.read (CapRead,
// all roles allow): a regression that downgraded the catalog's CapAdmin
// for limits.write to CapRead would silently let viewers mutate limits,
// and would fail this test on every non-Owner/Admin row.
func TestUpdateLimitsPolicyMatrixRoles(t *testing.T) {
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
		{"developer", policy.RoleDeveloper, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	// Distinctive post-write value so deny-path leak checks can search for
	// the seeded data without false-matching the request body.
	seeded := []store.EffectiveQuotaLimit{
		{
			Resource:        store.QuotaResourceProjects,
			LimitValue:      99,
			EnforcementMode: store.EnforcementModeHard,
			Scope:           store.QuotaScopeOrganization,
		},
	}

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
			got := e.Decide(principal, policy.ActionLimitsWrite, orgRoot)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(limits.write) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			var gotInput store.UpdateLimitsInput
			updater := fakeLimitsUpdater{limits: seeded, got: &gotInput}
			handler := updateLimitsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, updater)

			rec := patchLimits(handler, org, "a-valid-token", limitsWritePatchBody)

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeUpdateLimits(t, rec)
				if len(env.Data.Limits) != 1 ||
					env.Data.Limits[0].Resource != "projects" ||
					env.Data.Limits[0].LimitValue != 99 ||
					env.Data.Limits[0].EnforcementMode != "hard" ||
					env.Data.Limits[0].Source != "organization" {
					t.Errorf("limits = %+v, want exactly the seeded organization-scoped projects=99/hard",
						env.Data.Limits)
				}
				if gotInput.OrganizationID != org {
					t.Errorf("updater received organization id %q, want the path parameter %q",
						gotInput.OrganizationID, org)
				}
				if len(gotInput.Items) != 1 ||
					gotInput.Items[0].Resource != store.QuotaResourceProjects ||
					gotInput.Items[0].LimitValue != 42 {
					t.Errorf("updater received items %+v, want exactly one projects=42 entry",
						gotInput.Items)
				}
				if gotInput.ActorID != principal.ID || gotInput.ActorOrgID != org {
					t.Errorf("updater received actor=(%q, %q), want (%q, %q)",
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
			if gotInput.OrganizationID != "" || len(gotInput.Items) != 0 {
				t.Errorf("updater was reached with org=%q items=%+v for a denied %s; it must never run",
					gotInput.OrganizationID, gotInput.Items, tc.name)
			}
			// A denied response must never leak the seeded post-write
			// limits — the policy boundary is the only place limits are
			// gated, so a denied caller seeing the seeded value or the
			// organization id would itself be a contract violation.
			body := rec.Body.String()
			if strings.Contains(body, "\"limit_value\":99") ||
				strings.Contains(body, ":99,") ||
				strings.Contains(body, "\"organization\"") {
				t.Errorf("denied response leaks the seeded post-write limit data: %s", body)
			}
		})
	}
}

// TestUpdateLimitsPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is denied
// action limits.write with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired credential
// must never be able to mutate limits of the organization it once had
// access to (a stale credential rewriting a tenant's ceilings to lock
// allocations or hide spend is precisely the abuse this guards), the
// updater must never run, and the denied body must never echo the
// principal id, the organization id, or any seeded limit data.
func TestUpdateLimitsPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			// limits.write; the disabled flag is the only thing in the way
			// and must be load-bearing.
			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var gotInput store.UpdateLimitsInput
			updater := fakeLimitsUpdater{
				limits: []store.EffectiveQuotaLimit{{
					Resource:        store.QuotaResourceProjects,
					LimitValue:      99,
					EnforcementMode: store.EnforcementModeHard,
					Scope:           store.QuotaScopeOrganization,
				}},
				got: &gotInput,
			}
			handler := updateLimitsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, updater)

			rec := patchLimits(handler, "org_acme", "yk_no_longer_valid", limitsWritePatchBody)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotInput.OrganizationID != "" || len(gotInput.Items) != 0 {
				t.Errorf("updater was reached with org=%q items=%+v for a disabled principal; it must never run",
					gotInput.OrganizationID, gotInput.Items)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, "\"limit_value\":99") ||
				strings.Contains(body, "\"organization\"") {
				t.Errorf("error body %s leaked the principal id, organization, or seeded limit data", body)
			}
		})
	}
}

// TestUpdateLimitsPolicyWrongOrganizationPrincipal proves limits.write is
// confined to the caller's own tenant — and unlike limits.read there is
// NO cross-tenant exception for support. The engine's cross-tenant clause
// only allows CapRead and CapSupport actions through the support
// exception; CapAdmin is excluded by construction. So:
//
//   - A non-support owner of org_attacker patching limits of org_victim is
//     a deterministic 403 carrying ReasonDeniedCrossTenant; the updater is
//     never reached, and the denied body never echoes the victim
//     organization or any of its limits.
//   - A support principal of org_yalla — the one that COULD have read
//     another tenant's limits via limits.read — cannot mutate them. The
//     engine still denies with ReasonDeniedCrossTenant for any
//     organization outside its home tenant, and the handler returns 403
//     with no leakage. This is the load-bearing distinction from BE-0096's
//     limits.read matrix (CapRead, support allowed cross-tenant) and the
//     property under test here.
//
// Privileged Yalla support that needs to override a tenant's limits (e.g.
// during a billing-incident lift) goes through the explicit break-glass
// admin tooling, not this customer-facing endpoint.
func TestUpdateLimitsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)
	victimLimits := []store.EffectiveQuotaLimit{{
		Resource:        store.QuotaResourceProjects,
		LimitValue:      77,
		EnforcementMode: store.EnforcementModeHard,
		Scope:           store.QuotaScopeOrganization,
	}}

	// Non-support cross-tenant principal: owner of org_attacker patching
	// limits of org_victim is a deterministic 403, the updater never
	// reached, and the body carries no cross-tenant id or limit data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var gotIntruderInput store.UpdateLimitsInput
	intruderUpdater := fakeLimitsUpdater{limits: victimLimits, got: &gotIntruderInput}
	intruderHandler := updateLimitsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderUpdater)

	rec := patchLimits(intruderHandler, victimOrg, "a-valid-token", limitsWritePatchBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotIntruderInput.OrganizationID != "" || len(gotIntruderInput.Items) != 0 {
		t.Errorf("updater was reached with org=%q items=%+v for a cross-tenant request; it must never run",
			gotIntruderInput.OrganizationID, gotIntruderInput.Items)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, "\"limit_value\":77") ||
		strings.Contains(body, "\"organization\"") {
		t.Errorf("error body %s echoed the cross-tenant organization or seeded limit data", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so the
	// resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionLimitsWrite, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(limits.write, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for limits.write — CapAdmin
	// is excluded from the engine's support cross-tenant exception. The
	// support principal that CAN read foreign limits (BE-0096) CANNOT
	// mutate them through this endpoint.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionLimitsWrite, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(limits.write, foreign org) for support = %+v, want deny via %q (CapAdmin is excluded from the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var gotSupportInput store.UpdateLimitsInput
	supportUpdater := fakeLimitsUpdater{limits: victimLimits, got: &gotSupportInput}
	supportHandler := updateLimitsHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportUpdater)
	supportRec := patchLimits(supportHandler, victimOrg, "a-valid-support-token", limitsWritePatchBody)
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support cannot mutate limits cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotSupportInput.OrganizationID != "" || len(gotSupportInput.Items) != 0 {
		t.Errorf("updater was reached with org=%q items=%+v for a support cross-tenant patch; it must never run",
			gotSupportInput.OrganizationID, gotSupportInput.Items)
	}
	if supportBody := supportRec.Body.String(); strings.Contains(supportBody, victimOrg) ||
		strings.Contains(supportBody, "\"limit_value\":77") ||
		strings.Contains(supportBody, "\"organization\"") {
		t.Errorf("support error body %s echoed the cross-tenant organization or seeded limit data", supportBody)
	}

	// Bonus: a support principal cannot mutate limits of its OWN home
	// organization either — RoleSupport lacks CapAdmin entirely. This
	// locks the support role's read-only-for-quota posture at the engine
	// level so a future catalog change cannot silently grant it
	// limit-mutation authority.
	supportHome := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: support.OrganizationID}}
	if got := e.Decide(support, policy.ActionLimitsWrite, supportHome); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(limits.write, own org) for support = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
}

// TestUpdateLimitsPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (it carries no organization role); the
// engine confines those grants — a project grant does not reach a sibling
// project, an environment grant does not reach production, a service
// grant does not reach the parent environment or a sibling service.
//
// Crucially for PATCH /v1/organizations/{org_id}/limits: limits.write is
// evaluated against the organization-root scope the {org_id} path names.
// A project/environment/service-scoped grant — even an Admin grant — does
// not cover that scope (covers() is one-way: a more-specific scope cannot
// reach a broader resource), not even for the key's own organization. So
// a scoped key holding only a project Admin grant is denied the endpoint
// for its own {org_id} with the stable ReasonDeniedOutOfScope, while a
// key holding an organization-level Admin grant — and only Admin, since
// limits.write is CapAdmin and a Viewer grant is structurally not enough
// even at the organization root — is allowed it (ReasonAllowedByGrant).
// A scoped grant narrows authority within a tenant; it can never be
// escalated to a broader limits mutation. This is the load-bearing
// property that prevents a leaked project-scoped CI key from being
// weaponised to rewrite the tenant's quota policies and lock the customer
// out of allocations.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied back
// to the wire by proving the project grantee is denied the endpoint at
// its own {org_id}, while an organization-scoped Admin grantee is allowed
// it and a Viewer grantee is denied.
func TestUpdateLimitsPolicyGrantContainment(t *testing.T) {
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

	// PATCH /v1/organizations/{org_id}/limits mutates against the
	// organization root the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover that
	// scope — not even for the key's own organization — so each scoped
	// grantee is denied the endpoint with ReasonDeniedOutOfScope: the
	// scoped key cannot be widened to mutate organization-wide quota
	// policies, and the updater never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionLimitsWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.write) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionLimitsWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.write) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionLimitsWrite, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.write) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee patching limits of
	// its OWN organization is a 403 with the stable out-of-scope reason,
	// the updater is never reached, and the body never echoes the seeded
	// post-write limit data. This is the property that makes the policy
	// boundary — not the persistence boundary — the structural place a
	// scoped key is denied broader authority.
	seeded := []store.EffectiveQuotaLimit{{
		Resource:        store.QuotaResourceProjects,
		LimitValue:      99,
		EnforcementMode: store.EnforcementModeHard,
		Scope:           store.QuotaScopeOrganization,
	}}
	var gotProjectInput store.UpdateLimitsInput
	projectUpdater := fakeLimitsUpdater{limits: seeded, got: &gotProjectInput}
	projectHandler := updateLimitsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectUpdater)
	rec := patchLimits(projectHandler, org, "yk_proj_scoped", limitsWritePatchBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if gotProjectInput.OrganizationID != "" || len(gotProjectInput.Items) != 0 {
		t.Errorf("updater was reached with org=%q items=%+v for an out-of-scope grantee; it must never run",
			gotProjectInput.OrganizationID, gotProjectInput.Items)
	}
	if body := rec.Body.String(); strings.Contains(body, "\"limit_value\":99") ||
		strings.Contains(body, "\"organization\"") {
		t.Errorf("denied response leaks the seeded post-write limit data: %s", body)
	}

	// An organization-level Admin grant DOES cover the org-root scope and
	// is allowed via ReasonAllowedByGrant — and the same key is end-to-end
	// allowed at the wire, with the updater reached on the {org_id}
	// parameter. A Viewer grant at the same scope is intentionally NOT
	// enough: limits.write requires CapAdmin, not CapRead. This locks the
	// CapAdmin requirement against the grant path so a future catalog
	// change that downgraded limits.write below CapAdmin would fail the
	// Viewer-deny assertion here.
	orgAdmin := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdmin, policy.ActionLimitsWrite, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(limits.write) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionLimitsWrite, orgRoot); got.Allow {
		t.Errorf("Decide(limits.write) for an organization-level viewer grant = %+v, want deny — viewer holds CapRead, not CapAdmin",
			got)
	}

	var gotOrgInput store.UpdateLimitsInput
	orgUpdater := fakeLimitsUpdater{limits: seeded, got: &gotOrgInput}
	orgHandler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgAdmin, Method: auth.MethodAPIKey}, nil, orgUpdater)
	allowedRec := patchLimits(orgHandler, org, "yk_org_admin", limitsWritePatchBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedEnv := decodeUpdateLimits(t, allowedRec)
	if len(allowedEnv.Data.Limits) != 1 ||
		allowedEnv.Data.Limits[0].Resource != "projects" ||
		allowedEnv.Data.Limits[0].LimitValue != 99 {
		t.Errorf("limits = %+v, want the seeded projects=99 limit", allowedEnv.Data.Limits)
	}
	if gotOrgInput.OrganizationID != org {
		t.Errorf("updater received organization id %q, want the path parameter %q",
			gotOrgInput.OrganizationID, org)
	}
	if gotOrgInput.ActorID != orgAdmin.ID || gotOrgInput.ActorOrgID != org {
		t.Errorf("updater received actor=(%q, %q), want (%q, %q)",
			gotOrgInput.ActorID, gotOrgInput.ActorOrgID, orgAdmin.ID, org)
	}

	// And the same project-scoped grantee against a foreign {org_id}
	// is still denied — a scoped key cannot be smuggled across tenants
	// by fabricating a path parameter to mutate somebody else's quota.
	// The cross-tenant guard fires first, since the scope's organization
	// id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionLimitsWrite, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(limits.write, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := updateLimitsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeLimitsUpdater{limits: []store.EffectiveQuotaLimit{{
			Resource:        store.QuotaResourceProjects,
			LimitValue:      99,
			EnforcementMode: store.EnforcementModeHard,
			Scope:           store.QuotaScopeOrganization,
		}}})
	foreignRec := patchLimits(foreignHandler, "org_sibling", "yk_proj_scoped", limitsWritePatchBody)
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
