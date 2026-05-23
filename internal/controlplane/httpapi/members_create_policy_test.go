package httpapi

import (
	stderrors "errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for POST /v1/organizations/{org_id}/members (BE-0066).
// Where members_create_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action members.manage cannot be
// bypassed by — or made to act for the wrong tenant because of — the
// principal's role, revoked credentials, home organization, or scoped grants.
//
// This route carries the organizationIDResolver, so RequireAuth authorizes
// action members.manage against the organization the {org_id} PATH names —
// not merely the principal's home organization. That is the property under
// test here: a cross-tenant {org_id} must be a deterministic 403 before the
// handler runs, and a same-tenant {org_id} is allowed only when the
// principal's role (or an organization-level grant) confers CapAdmin.
//
// members.manage is a CapAdmin action: of the six built-in roles only owner
// and admin hold CapAdmin, so the role matrix is split — owner/admin allow,
// developer/viewer/ci/support deny with ReasonDeniedNoCapability. Support is
// not a cross-tenant exception here either: the support escape hatch covers
// CapRead and CapSupport only, never CapAdmin, so a support principal calling
// a foreign-tenant POST members is denied with ReasonDeniedCrossTenant — and
// support calling the endpoint for its own home org is denied for capability,
// not tenant.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// addMemberHandlerFor, postMember, decodeAddMember, orgPrincipal,
// fakeMembershipCreator, seedMember, and decodeError are shared with the
// sibling POST /v1/organizations/{org_id}/members contract suite.

// TestAddMemberPolicyMatrixRoles tables every built-in organization role
// against POST /v1/organizations/{org_id}/members for an {org_id} naming the
// principal's home organization. The split matrix is the property under test:
// owner and admin hold CapAdmin and create the membership through
// ReasonAllowedByRole, with the forwarded audit actor being exactly the
// caller's own principal; developer, viewer, ci, and support each lack
// CapAdmin and are denied with a stable 403 carrying ReasonDeniedNoCapability,
// the creator never running for them. The denied body must not echo the
// principal id or the path's organization back.
func TestAddMemberPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

	cases := []struct {
		name       string
		role       policy.Role
		kind       domain.Kind
		allow      bool
		wantReason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, false, policy.ReasonDeniedNoCapability},
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

			// Pin the engine-level verdict directly: the role confers (or
			// fails to confer) CapAdmin within the principal's own org, so the
			// verdict is stable and the reason code is the contract.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionMembersManage, orgRoot)
			if got.Allow != tc.allow || got.Reason != tc.wantReason {
				t.Fatalf("Decide(members.manage) = %+v, want allow=%v via %q",
					got, tc.allow, tc.wantReason)
			}

			var captured store.AddMembershipInput
			creator := fakeMembershipCreator{
				member: seedMember(org, "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 1, created, created),
				got:    &captured,
			}
			handler := addMemberHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, creator)

			rec := postMember(handler, org, "a-valid-session-token",
				`{"user_id":"usr_grace","role":"admin"}`)

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				env := decodeAddMember(t, rec)
				if env.Data.Member.UserID != "usr_grace" || env.Data.Member.Role != "admin" {
					t.Errorf("member = %+v, want user usr_grace with role admin", env.Data.Member)
				}
				// The forwarded audit actor is the authenticated principal,
				// never a caller-controlled or escalated identity.
				if captured.ActorID != principal.ID || captured.ActorOrgID != org {
					t.Errorf("forwarded actor = %q/%q, want the caller's own principal %q/%q",
						captured.ActorID, captured.ActorOrgID, principal.ID, org)
				}
				if captured.OrganizationID != org {
					t.Errorf("forwarded organization_id = %q, want the path parameter %q",
						captured.OrganizationID, org)
				}
				return
			}

			// Deny path: 403 E_FORBIDDEN carrying the stable reason; the
			// creator must never run; the denied body must not leak the
			// principal id or the path's organization.
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for role %q; body %s",
					rec.Code, tc.role, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(tc.wantReason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, tc.wantReason)
			}
			if captured.OrganizationID != "" || captured.UserID != "" || captured.ActorID != "" {
				t.Errorf("creator was reached for a denied role %q with %+v; it must never run",
					tc.role, captured)
			}
			if body := rec.Body.String(); strings.Contains(body, principal.ID) || strings.Contains(body, org) {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestAddMemberPolicyRevokedAndExpiredKeys proves a principal whose credential
// has been revoked or has expired — both of which the auth layer surfaces to
// the policy engine as a Disabled principal — is denied action members.manage
// with a stable 403 E_FORBIDDEN, even though an active owner role would be
// allowed it. A revoked or expired key must never be able to mutate the
// membership graph of the organization it once had access to, the creator
// must never run, and the denied body must not echo the principal id or the
// organization id back.
func TestAddMemberPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			var captured store.AddMembershipInput
			creator := fakeMembershipCreator{
				err: stderrors.New("creator must not be called"),
				got: &captured,
			}
			handler := addMemberHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)

			rec := postMember(handler, "org_acme", "yk_no_longer_valid",
				`{"user_id":"usr_grace","role":"admin"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.UserID != "" {
				t.Errorf("creator was reached with %+v for a disabled principal; it must never run", captured)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestAddMemberPolicyWrongOrganizationPrincipal proves members.manage is
// confined to the caller's own tenant — with no support exception. This route
// carries the organizationIDResolver, so RequireAuth authorizes against the
// organization the {org_id} path names: a non-support principal whose home
// organization is org_intruder calling POST against org_victim's members is a
// deterministic 403 ReasonDeniedCrossTenant, the creator is never reached,
// and the denied body never echoes the foreign id. Crucially, support is NOT
// an exception for this action — the engine's support escape hatch covers
// CapRead and CapSupport only, and members.manage is CapAdmin — so a support
// principal targeting another tenant's members is denied with the same
// cross-tenant reason as any other role.
func TestAddMemberPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	// A non-support owner cannot mutate another organization's memberships:
	// the resolver scopes authorization to org_victim and the engine denies
	// the cross-tenant write before the handler runs.
	intruder := orgPrincipal("usr_intruder", ownOrg, policy.RoleOwner)
	var captured store.AddMembershipInput
	creator := fakeMembershipCreator{
		err: stderrors.New("creator must not be called"),
		got: &captured,
	}
	handler := addMemberHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)

	rec := postMember(handler, victimOrg, "a-valid-session-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if captured.OrganizationID != "" {
		t.Errorf("creator was reached with %+v for a cross-tenant request; it must never run", captured)
	}
	if strings.Contains(rec.Body.String(), victimOrg) {
		t.Errorf("error body %s echoed the cross-tenant organization id", rec.Body.String())
	}

	// At the engine level the cross-tenant boundary is pinned directly.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionMembersManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.manage, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for members.manage: CapAdmin is
	// not CapRead or CapSupport. A support principal from org_yalla calling
	// POST /v1/organizations/org_victim/members is denied with the SAME
	// cross-tenant reason as any other role — no escalation through the
	// support escape hatch.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionMembersManage, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.manage, foreign org) for support = %+v, want deny via %q — the support escape hatch must not cover CapAdmin",
			got, policy.ReasonDeniedCrossTenant)
	}

	var supportCaptured store.AddMembershipInput
	supportCreator := fakeMembershipCreator{
		err: stderrors.New("creator must not be called"),
		got: &supportCaptured,
	}
	supportHandler := addMemberHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportCreator)
	supportRec := postMember(supportHandler, victimOrg, "a-valid-support-token",
		`{"user_id":"usr_grace","role":"admin"}`)
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403; body %s", supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry the stable reason %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with %+v for a support cross-tenant request; it must never run", supportCaptured)
	}
}

// TestAddMemberPolicyGrantContainment proves scoped grants cannot be widened
// past the scope they were issued for. A scoped API key is authorized purely
// by its grants (it carries no organization role); the engine confines those
// grants — a project grant does not reach a sibling project, an environment
// grant does not reach production, a service grant does not reach the parent
// environment or a sibling service.
//
// Crucially for POST /v1/organizations/{org_id}/members: members.manage is
// evaluated against the organization-root scope the {org_id} path names,
// which a project/environment/service grant does not cover — not even for the
// key's own organization. So a scoped key holding only a project grant is
// denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level admin
// grant is allowed it (ReasonAllowedByGrant). A scoped grant narrows
// authority within a tenant; it can never be escalated to an organization-
// wide membership mutation. A viewer grant at the organization root holds
// only CapRead, never CapAdmin, so it is denied with ReasonDeniedNoCapability
// — even at the matching scope, the wrong role does not confer the action.
func TestAddMemberPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	// Project-level grant: developer on proj_p only.
	scopeP := policy.Scope{OrganizationID: org, ProjectID: "proj_p"}
	scopeQ := policy.Scope{OrganizationID: org, ProjectID: "proj_q"}
	projectGrantee := policy.Principal{
		ID: "sa_proj", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeP}},
	}
	if got := e.Decide(projectGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindService, Scope: scopeP}); !got.Allow {
		t.Errorf("write inside the granted project = %+v, want allow", got)
	}
	if got := e.Decide(projectGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindService, Scope: scopeQ}); got.Allow {
		t.Errorf("write in a sibling project = %+v, want deny — a project grant must not reach proj_q", got)
	}

	// Environment-level grant: developer on the staging environment only.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_staging"}
	scopeProd := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod"}
	envGrantee := policy.Principal{
		ID: "sa_env", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeStaging}); !got.Allow {
		t.Errorf("write inside the granted environment = %+v, want allow", got)
	}
	if got := e.Decide(envGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProd}); got.Allow {
		t.Errorf("write in production = %+v, want deny — a staging grant must not reach production unless production is explicitly granted", got)
	}

	// Service-level grant: developer on a single service only.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod"}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeSvcA}},
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

	// POST /v1/organizations/{org_id}/members mutates memberships of the
	// organization root the path names. A project-scoped grant does not cover
	// that scope — not even for the key's own organization — so the project
	// grantee is denied the endpoint for its own {org_id} with a stable 403
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to an
	// organization-wide membership write.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeP}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionMembersManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.manage) for a project-scoped admin grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectCaptured store.AddMembershipInput
	projectCreator := fakeMembershipCreator{
		err: stderrors.New("creator must not be called"),
		got: &projectCaptured,
	}
	projectKeyHandler := addMemberHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projectCreator)
	rec := postMember(projectKeyHandler, org, "yk_project_scoped",
		`{"user_id":"usr_grace","role":"admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectCaptured.OrganizationID != "" {
		t.Errorf("creator was reached with %+v for an out-of-scope key; it must never run", projectCaptured)
	}

	// A viewer grant at the organization root covers the scope but does not
	// confer CapAdmin — members.manage is denied with ReasonDeniedNoCapability,
	// not ReasonDeniedOutOfScope. The right role at the wrong scope is
	// out_of_scope; the wrong role at the right scope is no_capability.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionMembersManage, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(members.manage) for an organization-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// An organization-level admin grant DOES cover the organization root with
	// CapAdmin, so a key scoped to the whole organization with the admin role
	// is allowed members.manage for its own {org_id} (ReasonAllowedByGrant)
	// and the creator runs with the caller's principal as the audit actor.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionMembersManage, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(members.manage) for an organization-scoped admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	var orgCaptured store.AddMembershipInput
	orgCreator := fakeMembershipCreator{
		member: seedMember(org, "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 1, now, now),
		got:    &orgCaptured,
	}
	orgKeyHandler := addMemberHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgCreator)
	okRec := postMember(orgKeyHandler, org, "yk_org_scoped",
		`{"user_id":"usr_grace","role":"admin"}`)
	if okRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an organization-scoped admin grant; body %s",
			okRec.Code, okRec.Body.String())
	}
	okEnv := decodeAddMember(t, okRec)
	if okEnv.Data.Member.UserID != "usr_grace" || okEnv.Data.Member.Role != "admin" {
		t.Errorf("member = %+v, want the seeded membership of the key's own org", okEnv.Data.Member)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID || orgCaptured.ActorOrgID != org {
		t.Errorf("forwarded actor = %q/%q, want the caller's own principal %q/%q — a grant must not widen the actor",
			orgCaptured.ActorID, orgCaptured.ActorOrgID, orgAdminGrantee.ID, org)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("forwarded organization_id = %q, want the path parameter %q",
			orgCaptured.OrganizationID, org)
	}

	// A project-scoped grant must not be widened to a sibling-organization
	// {org_id} either: an out-of-scope organization write is denied regardless
	// of which organization the path names — the cross-tenant guard and the
	// out-of-scope guard both hold.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectAdminGrantee, policy.ActionMembersManage, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(members.manage, foreign org) for a project-scoped admin grant = %+v, want deny", got)
	}
}
