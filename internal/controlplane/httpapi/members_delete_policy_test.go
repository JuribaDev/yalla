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

// Policy-matrix coverage for DELETE /v1/organizations/{org_id}/members/{member_id}
// (BE-0075). Where members_delete_test.go proves the endpoint's wire contract,
// this file proves its authorization contract: that action members.manage —
// the destructive removal that deletes the membership row and severs every
// outstanding session for the named member — cannot be bypassed by, or leak
// data because of, the principal's role, revoked credentials, home
// organization, or scoped grants. The DELETE story carries the same action as
// PATCH (members.manage->CapAdmin) because role-change and removal are both
// org-root membership mutations; the matrix is intentionally identical to
// the PATCH companion (members_update_policy_test.go) so a regression that
// silently downgrades members.manage on one verb but not the other still
// fails here.
//
// The route carries memberIDResolver, which scopes the policy.Resource to the
// {org_id} path parameter (Kind=domain.KindUser); the {member_id} path
// parameter is not part of the authorization decision — it only selects which
// row the remover deletes once authorization succeeds. So a cross-tenant
// {org_id} must be a deterministic 403 BEFORE the handler runs regardless of
// the {member_id} value, while an {org_id} naming the caller's own
// organization is allowed only by an organization role that holds CapAdmin
// (owner/admin) or by a grant whose scope covers the organization root —
// never by a deeper-scoped grant, never by Developer/Viewer/CI, and never by
// the Support cross-tenant read exception.
//
// members.manage requires CapAdmin (catalog.go: ActionMembersManage->CapAdmin),
// so the role matrix splits sharply from members.read: only Owner and Admin
// allow within the own organization; Developer, Viewer, CI, and Support all
// deny (ReasonDeniedNoCapability — they each lack CapAdmin). Support is the
// load-bearing distinction from the read story: the engine's cross-tenant
// exception is gated on `required == CapRead || required == CapSupport`, so
// CapAdmin is OUTSIDE the support cross-tenant read exception. A Support
// principal cannot remove members of another tenant — and cannot remove
// members of its own home tenant either — so a Support credential is
// structurally incapable of mutating membership.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the memberIDResolver, or the engine fails here.
// removeMemberHandlerFor, deleteMember, decodeRemoveMember, orgPrincipal,
// fakeMembershipRemover, seedMember, and decodeError are shared with the
// contract-test files; this file adds no scaffolding.

// TestRemoveMemberPolicyMatrixRoles drives every built-in role through the
// production request path against an {org_id} that names its own home
// organization. Owner and Admin hold CapAdmin and allow members.manage via
// ReasonAllowedByRole — the remover is reached with both path parameters in
// the expected positions and the response carries the removed member.
// Developer, Viewer, CI, and Support all lack CapAdmin and are denied with a
// stable 403 E_FORBIDDEN carrying ReasonDeniedNoCapability — and in every
// deny path the remover's Remove is never reached, so a probed {member_id}
// can never confirm whether that user belongs to the organization (and, more
// importantly for DELETE, can never silently destroy that membership row).
func TestRemoveMemberPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org      = "org_acme"
		memberID = "usr_grace"
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

	orgRoot := policy.Resource{Kind: domain.KindUser, Scope: policy.Scope{OrganizationID: org}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine assertion: the role decision against the
			// organization-root scope the resolver emits is the verdict the
			// matrix names. The {member_id} path parameter is not part of
			// the engine's input.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionMembersManage, orgRoot)
			if got.Allow != tc.wantAllow || got.Reason != tc.wantReason {
				t.Errorf("Decide(members.manage) for %s = %+v, want allow=%v via %q",
					tc.name, got, tc.wantAllow, tc.wantReason)
			}

			var captured store.RemoveMembershipInput
			remover := fakeMembershipRemover{
				member: seedMember(org, memberID, "grace@acme.example",
					"Grace Hopper", "admin", 4, now, now.Add(time.Hour)),
				got: &captured,
			}
			handler := removeMemberHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession},
				nil, remover)

			rec := deleteMember(handler, org, memberID, "a-valid-token")

			if tc.wantAllow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeRemoveMember(t, rec)
				if env.Data.Member.UserID != memberID {
					t.Errorf("response member.user_id = %q, want %q",
						env.Data.Member.UserID, memberID)
				}
				if env.Data.Member.Role != "admin" {
					t.Errorf("response member.role = %q, want %q — the row at the moment of removal must reach the wire",
						env.Data.Member.Role, "admin")
				}
				if captured.OrganizationID != org {
					t.Errorf("remover received organization_id = %q, want the path parameter %q",
						captured.OrganizationID, org)
				}
				if captured.UserID != memberID {
					t.Errorf("remover received user_id = %q, want the path parameter %q",
						captured.UserID, memberID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("remover received actor_id = %q, want the authenticated principal %q",
						captured.ActorID, principal.ID)
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
			if captured.OrganizationID != "" || captured.UserID != "" {
				t.Errorf("remover was reached with org=%q user=%q for a denied %s; it must never run",
					captured.OrganizationID, captured.UserID, tc.name)
			}
		})
	}
}

// TestRemoveMemberPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// members.manage with a stable 403 E_FORBIDDEN, even when the underlying
// role would have allowed it. A revoked or expired credential must never be
// able to mutate (or destroy) a member of the organization it once had
// access to, the remover must never run, and the denied body must never
// echo the principal id, the organization id, or the targeted member id.
func TestRemoveMemberPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			// members.manage; the disabled flag is the only thing in the
			// way and must be load-bearing.
			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var captured store.RemoveMembershipInput
			remover := fakeMembershipRemover{
				member: seedMember("org_acme", "usr_grace", "g@acme.example",
					"Grace", "admin", 1, time.Now().UTC(), time.Now().UTC()),
				got: &captured,
			}
			handler := removeMemberHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey},
				nil, remover)

			rec := deleteMember(handler, "org_acme", "usr_grace",
				"yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.UserID != "" {
				t.Errorf("remover was reached with org=%q user=%q for a disabled principal; it must never run",
					captured.OrganizationID, captured.UserID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, "usr_grace") {
				t.Errorf("error body %s leaked the principal id, organization, or member id", body)
			}
		})
	}
}

// TestRemoveMemberPolicyWrongOrganizationPrincipal proves members.manage is
// confined to the caller's own tenant — and unlike members.read there is NO
// cross-tenant exception for support. The engine's cross-tenant clause only
// allows CapRead and CapSupport actions through the support exception
// (engine.go: `required == CapRead || required == CapSupport`); CapAdmin is
// excluded by construction. So:
//
//   - A non-support owner of org_attacker deleting a member of org_victim is
//     a deterministic 403 carrying ReasonDeniedCrossTenant; the remover is
//     never reached, and the denied body never echoes the victim
//     organization or member id.
//   - A support principal of org_yalla — the one that COULD have read a
//     member cross-tenant — cannot remove one. The engine still denies with
//     ReasonDeniedCrossTenant for any member outside its home org, and the
//     handler returns 403 with no leakage.
//
// This is the load-bearing distinction from the read policy matrix and the
// reason this story exists separately from BE-0069. For DELETE specifically
// the stake is higher than for PATCH: a cross-tenant read leaks data, a
// cross-tenant DELETE destroys it.
func TestRemoveMemberPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
		victimID  = "usr_v"
	)

	// Non-support cross-tenant principal: owner of org_attacker deleting
	// a member of org_victim is a deterministic 403, the remover never
	// reached, and the body carries no cross-tenant id.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var capturedIntruder store.RemoveMembershipInput
	intruderRemover := fakeMembershipRemover{
		member: seedMember(victimOrg, victimID, "v@victim.example", "Victor",
			"owner", 1, time.Now().UTC(), time.Now().UTC()),
		got: &capturedIntruder,
	}
	intruderHandler := removeMemberHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession},
		nil, intruderRemover)

	rec := deleteMember(intruderHandler, victimOrg, victimID, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if capturedIntruder.OrganizationID != "" || capturedIntruder.UserID != "" {
		t.Errorf("remover was reached with org=%q user=%q for a cross-tenant request; it must never run",
			capturedIntruder.OrganizationID, capturedIntruder.UserID)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) || strings.Contains(body, victimID) {
		t.Errorf("error body %s echoed the cross-tenant organization or member id", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so the
	// resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindUser, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionMembersManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.manage, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for members.manage. Pin both
	// the engine verdict and the handler outcome, since support IS the
	// exception for the read sibling story (BE-0069).
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionMembersManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.manage, foreign org) for support = %+v, want deny via %q (CapAdmin is excluded from the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var capturedSupport store.RemoveMembershipInput
	supportRemover := fakeMembershipRemover{
		member: seedMember(victimOrg, victimID, "v@victim.example", "Victor",
			"owner", 1, time.Now().UTC(), time.Now().UTC()),
		got: &capturedSupport,
	}
	supportHandler := removeMemberHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession},
		nil, supportRemover)
	supportRec := deleteMember(supportHandler, victimOrg, victimID,
		"a-valid-support-token")
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — support cannot remove members cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if capturedSupport.OrganizationID != "" || capturedSupport.UserID != "" {
		t.Errorf("remover was reached with org=%q user=%q for a support cross-tenant delete; it must never run",
			capturedSupport.OrganizationID, capturedSupport.UserID)
	}
	supportBody := supportRec.Body.String()
	if strings.Contains(supportBody, victimOrg) || strings.Contains(supportBody, victimID) {
		t.Errorf("support error body %s echoed the cross-tenant organization or member id", supportBody)
	}

	// Bonus: a support principal cannot remove members of its OWN home
	// organization either — RoleSupport lacks CapAdmin entirely, so within
	// the home tenant the verdict is ReasonDeniedNoCapability, not the
	// cross-tenant denial. This locks the support role's read-only posture
	// at the engine level so a future catalog change cannot silently
	// grant it write authority.
	supportHome := policy.Resource{Kind: domain.KindUser, Scope: policy.Scope{OrganizationID: support.OrganizationID}}
	if got := e.Decide(support, policy.ActionMembersManage, supportHome); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(members.manage, own org) for support = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
}

// TestRemoveMemberPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (no organization role); the engine
// confines those grants — a project grant does not reach a sibling project,
// an environment grant does not reach production, a service grant does not
// reach the parent environment or a sibling service.
//
// Crucially for DELETE /v1/organizations/{org_id}/members/{member_id}:
// members.manage is evaluated against the organization-root scope the
// {org_id} path names. A project/environment/service grant — even an Admin
// grant — does not cover that scope (covers() is one-way: a more-specific
// scope cannot reach a broader resource), not even for the key's own
// organization. So a scoped key holding only a project Admin grant is
// denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level Admin
// grant is allowed it (ReasonAllowedByGrant). A scoped grant narrows
// authority within a tenant; it can never be escalated to an
// organization-wide membership removal.
func TestRemoveMemberPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org      = "org_acme"
		memberID = "usr_grace"
	)
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Cross-resource sibling-
	// project containment is asserted via the project-write action so the
	// grant has the relevant capability at the relevant scope.
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

	// DELETE /v1/organizations/{org_id}/members/{member_id} mutates the
	// organization root the {org_id} path names. A project-scoped admin
	// grant does NOT cover that scope — not even for the key's own
	// organization — so the project grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to an
	// organization-wide membership removal, and the remover never runs.
	orgRoot := policy.Resource{Kind: domain.KindUser, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionMembersManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.manage) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionMembersManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.manage) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionMembersManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.manage) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee deleting a member
	// of its OWN organization is a 403 with the stable out-of-scope
	// reason, the remover is never reached (so a probed {member_id}
	// cannot leak whether that user belongs to the organization, nor —
	// the sharper DELETE-specific failure mode — destroy that membership
	// row), and the body never echoes the scoped key id, the org id, or
	// the member id.
	var captured store.RemoveMembershipInput
	remover := fakeMembershipRemover{
		member: seedMember(org, memberID, "g@acme.example", "Grace",
			"admin", 1, time.Now().UTC(), time.Now().UTC()),
		got: &captured,
	}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, remover)
	rec := deleteMember(handler, org, memberID, "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if captured.OrganizationID != "" || captured.UserID != "" {
		t.Errorf("remover was reached with org=%q user=%q for an out-of-scope grantee; it must never run",
			captured.OrganizationID, captured.UserID)
	}
	body := rec.Body.String()
	if strings.Contains(body, projectGrantee.ID) ||
		strings.Contains(body, org) ||
		strings.Contains(body, memberID) {
		t.Errorf("error body %s leaked the principal id, organization, or member id", body)
	}

	// An organization-level Admin grant DOES cover the org-root scope and
	// is allowed via ReasonAllowedByGrant — and the same key is end-to-end
	// allowed at the wire, with the remover reached on both path
	// parameters. (Viewer is intentionally not enough: members.manage
	// requires CapAdmin, not CapRead.)
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionMembersManage, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(members.manage) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	// And an organization-level Viewer grant is NOT enough — locking in
	// the CapAdmin requirement so a future catalog change cannot silently
	// downgrade members.manage to a read-level capability.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionMembersManage, orgRoot); got.Allow {
		t.Errorf("Decide(members.manage) for an organization-level viewer grant = %+v, want deny — viewer holds CapRead, not CapAdmin",
			got)
	}

	var capturedAllowed store.RemoveMembershipInput
	allowedRemover := fakeMembershipRemover{
		member: seedMember(org, memberID, "g@acme.example", "Grace",
			"admin", 7, time.Now().UTC(), time.Now().UTC()),
		got: &capturedAllowed,
	}
	allowedHandler := removeMemberHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey},
		nil, allowedRemover)
	allowedRec := deleteMember(allowedHandler, org, memberID, "yk_org_admin")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedEnv := decodeRemoveMember(t, allowedRec)
	if allowedEnv.Data.Member.UserID != memberID {
		t.Errorf("response member.user_id = %q, want the path-named member %q",
			allowedEnv.Data.Member.UserID, memberID)
	}
	if capturedAllowed.OrganizationID != org {
		t.Errorf("remover received organization_id = %q, want the path parameter %q",
			capturedAllowed.OrganizationID, org)
	}
	if capturedAllowed.UserID != memberID {
		t.Errorf("remover received user_id = %q, want the path parameter %q",
			capturedAllowed.UserID, memberID)
	}
	if capturedAllowed.ActorID != orgGrantee.ID {
		t.Errorf("remover received actor_id = %q, want the authenticated principal %q",
			capturedAllowed.ActorID, orgGrantee.ID)
	}

	// And the same project-scoped grantee against a foreign {org_id} is
	// still denied — a scoped key cannot be smuggled across tenants by
	// fabricating a path parameter to delete somebody else's membership.
	foreignHandler := removeMemberHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey},
		nil, fakeMembershipRemover{member: seedMember("org_other", "usr_x",
			"x@other.example", "X", "admin", 1, time.Now().UTC(), time.Now().UTC())})
	foreignRec := deleteMember(foreignHandler, "org_other", "usr_x", "yk_proj_scoped")
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
