package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// Policy-matrix coverage for GET /v1/organizations/{org_id}/members/{member_id}
// (BE-0069). Where members_test.go proves the endpoint's wire contract, this
// file proves its authorization contract: that action members.read cannot be
// bypassed by — or leak data because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// Like its sibling GET /v1/organizations/{org_id}/members route, this route
// carries the organizationIDResolver, so RequireAuth authorizes action
// members.read against the organization the {org_id} PATH names — not the
// principal's home organization. The {member_id} path parameter is not part
// of the authorization decision; it only selects which row the reader returns
// once the request is authorized. That is the property under test here: a
// cross-tenant {org_id} must be a deterministic 403 before the handler runs
// regardless of the {member_id} value, while a {org_id} naming the caller's
// own organization is allowed by the role (or an organization-scoped grant)
// and never by a deeper-scoped grant.
//
// members.read is a CapRead action: all six built-in roles hold CapRead, so
// the role matrix for a principal reading a member of its own organization is
// "all allow", but a disabled principal, a cross-tenant {org_id} for a
// non-support principal, or a grant whose scope does not cover the
// organization root are all denied — and in every deny path the reader's
// GetMember is never reached (gotMemberOrgID and gotMemberUserID both stay
// empty), so a cross-tenant {member_id} cannot reveal whether that user is
// part of the victim organization.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// listMembersHandlerFor, getMember, decodeGetMember, orgPrincipal,
// fakeMembershipReader, seedMember, and decodeError are shared with the
// sibling GET /v1/organizations/{org_id}/members/{member_id} contract suite
// in members_test.go.

// TestGetMemberPolicyMatrixRoles proves every built-in organization role is
// allowed action members.read for an {org_id} that names its own home
// organization, and the reader is reached with both path parameters in the
// expected order. All six built-in roles hold CapRead, so the matrix is "all
// allow"; the assertions that matter are that the verdict is reached through
// the role (ReasonAllowedByRole), that the reader is invoked with the path's
// (org_id, member_id) — never a fabricated, escalated, or sibling tenant —
// and that the response renders the single addressed member.
func TestGetMemberPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org      = "org_acme"
		memberID = "usr_ada"
	)
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
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// At the engine level the role — not a grant, not the self
			// shortcut — is what confers members.read against the principal's
			// own organization. The {member_id} path parameter is not part of
			// this decision; the engine sees only the organization-root scope
			// resolved from the {org_id} path parameter.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionMembersRead, orgRoot)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(members.read) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
			}

			var gotOrgID, gotUserID string
			reader := fakeMembershipReader{
				member: seedMember(org, memberID, "ada@acme.example", "Ada Lovelace",
					"owner", 1, now, now),
				gotMemberOrgID:  &gotOrgID,
				gotMemberUserID: &gotUserID,
			}
			handler := listMembersHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getMember(handler, org, memberID, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeGetMember(t, rec)
			if env.Data.Member.UserID != memberID {
				t.Errorf("member.user_id = %q, want %q", env.Data.Member.UserID, memberID)
			}
			if gotOrgID != org {
				t.Errorf("reader received organization id %q, want the path parameter %q", gotOrgID, org)
			}
			if gotUserID != memberID {
				t.Errorf("reader received member id %q, want the path parameter %q", gotUserID, memberID)
			}
		})
	}
}

// TestGetMemberPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// members.read with a stable 403 E_FORBIDDEN, even though every active role
// is allowed it. A revoked or expired key must never be able to read a member
// of the organization it once had access to, the reader must never run, and
// the denied body must not echo the principal id, the organization id, or
// the requested member id back.
func TestGetMemberPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			// The reader must never be reached — authorization fails first.
			var gotOrgID, gotUserID string
			reader := fakeMembershipReader{
				member: seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada",
					"owner", 1, time.Now().UTC(), time.Now().UTC()),
				gotMemberOrgID:  &gotOrgID,
				gotMemberUserID: &gotUserID,
			}
			handler := listMembersHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getMember(handler, "org_acme", "usr_ada", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotOrgID != "" || gotUserID != "" {
				t.Errorf("reader was reached with org=%q user=%q for a disabled principal; it must never run",
					gotOrgID, gotUserID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") || strings.Contains(body, "usr_ada") {
				t.Errorf("error body %s leaked the principal id, organization, or member id", body)
			}
		})
	}
}

// TestGetMemberPolicyWrongOrganizationPrincipal proves members.read is
// confined to the caller's own tenant — except for the documented support
// exception. This route carries the organizationIDResolver, so RequireAuth
// authorizes against the organization the {org_id} path names: a non-support
// principal whose home organization is org_intruder reading any member of
// org_victim is a deterministic 403 ReasonDeniedCrossTenant, the reader is
// never reached (so the {member_id} can never reveal whether that user belongs
// to the victim organization), and the denied body never echoes the foreign
// id. A support principal performing a read is the one allowed cross-tenant
// exception (ReasonAllowedBySupport) and receives the member the path named.
func TestGetMemberPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
		victimID  = "usr_v"
	)

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	// A non-support principal cannot read another organization's member
	// through the path parameter: the resolver scopes authorization to
	// org_victim and the engine denies the cross-tenant read before the
	// handler runs.
	intruder := orgPrincipal("usr_intruder", ownOrg, policy.RoleOwner)
	var gotOrgID, gotUserID string
	reader := fakeMembershipReader{
		member: seedMember(victimOrg, victimID, "v@victim.example", "Victor",
			"owner", 1, now, now),
		gotMemberOrgID:  &gotOrgID,
		gotMemberUserID: &gotUserID,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)

	rec := getMember(handler, victimOrg, victimID, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotOrgID != "" || gotUserID != "" {
		t.Errorf("reader was reached with org=%q user=%q for a cross-tenant request; it must never run",
			gotOrgID, gotUserID)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) || strings.Contains(body, victimID) {
		t.Errorf("error body %s echoed the cross-tenant organization or member id", body)
	}

	// At the engine level the cross-tenant boundary is pinned directly. The
	// resolver targets the organization-root scope of the {org_id} path
	// parameter, exactly as the route registers it.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionMembersRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is the documented cross-tenant read exception — and, because
	// this route resolves the resource from the path, that exception IS
	// reachable here: a support principal reading another tenant's member is
	// allowed (ReasonAllowedBySupport) and receives the named member.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionMembersRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(members.read, foreign org) for support = %+v, want allow via %q",
			got, policy.ReasonAllowedBySupport)
	}

	var supportGotOrgID, supportGotUserID string
	supportReader := fakeMembershipReader{
		member: seedMember(victimOrg, victimID, "v@victim.example", "Victor",
			"owner", 1, now, now),
		gotMemberOrgID:  &supportGotOrgID,
		gotMemberUserID: &supportGotUserID,
	}
	supportHandler := listMembersHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)

	supportRec := getMember(supportHandler, victimOrg, victimID, "a-valid-support-token")
	if supportRec.Code != http.StatusOK {
		t.Fatalf("support status = %d, want 200; body %s", supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeGetMember(t, supportRec)
	if supportEnv.Data.Member.UserID != victimID {
		t.Errorf("support member.user_id = %q, want the path-named member %q",
			supportEnv.Data.Member.UserID, victimID)
	}
	if supportGotOrgID != victimOrg {
		t.Errorf("support read reached the reader with organization id %q, want the path parameter %q",
			supportGotOrgID, victimOrg)
	}
	if supportGotUserID != victimID {
		t.Errorf("support read reached the reader with member id %q, want the path parameter %q",
			supportGotUserID, victimID)
	}
}

// TestGetMemberPolicyGrantContainment proves scoped grants cannot be widened
// past the scope they were issued for. A scoped API key is authorized purely
// by its grants (it carries no organization role); the engine confines those
// grants — a project grant does not reach a sibling project, an environment
// grant does not reach production, a service grant does not reach the parent
// environment or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}/members/{member_id}:
// members.read is evaluated against the organization-root scope the {org_id}
// path names, which a project/environment/service grant does not cover — not
// even for the key's own organization. So a scoped key holding only a project
// grant is denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope (and the reader never runs, so the {member_id}
// cannot leak which users are members), while a key holding an
// organization-level viewer grant is allowed it (ReasonAllowedByGrant). A
// scoped grant narrows authority within a tenant; it can never be escalated
// to a broader read than it covers.
func TestGetMemberPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org      = "org_acme"
		memberID = "usr_ada"
	)
	e := policy.NewEngine()

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

	// GET /v1/organizations/{org_id}/members/{member_id} reads a single
	// membership of the organization root the path names. A project-scoped
	// grant does not cover that scope — not even for the key's own
	// organization — so the project grantee is denied the endpoint with a
	// stable 403: the scoped key cannot be widened to an organization-wide
	// membership read, and the reader never runs so a probed {member_id}
	// cannot leak whether that user belongs to the organization.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionMembersRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectGotOrgID, projectGotUserID string
	projectReader := fakeMembershipReader{
		member: seedMember(org, memberID, "ada@acme.example", "Ada",
			"owner", 1, time.Now().UTC(), time.Now().UTC()),
		gotMemberOrgID:  &projectGotOrgID,
		gotMemberUserID: &projectGotUserID,
	}
	projectKeyHandler := listMembersHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getMember(projectKeyHandler, org, memberID, "yk_project_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectGotOrgID != "" || projectGotUserID != "" {
		t.Errorf("reader was reached with org=%q user=%q for an out-of-scope key; it must never run",
			projectGotOrgID, projectGotUserID)
	}

	// An organization-level grant does cover the organization root, so a key
	// scoped to the whole organization is allowed the endpoint for its own
	// {org_id}. members.read is a CapRead action, so even a Viewer grant at
	// the organization root is sufficient — but only at the organization
	// root, and the response carries exactly the addressed member.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionMembersRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(members.read) for an organization-scoped key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	var orgGotOrgID, orgGotUserID string
	orgReader := fakeMembershipReader{
		member: seedMember(org, memberID, "ada@acme.example", "Ada Lovelace",
			"owner", 1, now, now),
		gotMemberOrgID:  &orgGotOrgID,
		gotMemberUserID: &orgGotUserID,
	}
	orgKeyHandler := listMembersHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	okRec := getMember(orgKeyHandler, org, memberID, "yk_org_scoped")
	if okRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an organization-scoped key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeGetMember(t, okRec)
	if okEnv.Data.Member.UserID != memberID {
		t.Errorf("member.user_id = %q, want the path-named member %q of the key's own org",
			okEnv.Data.Member.UserID, memberID)
	}
	if orgGotOrgID != org {
		t.Errorf("reader received organization id %q, want the key's own org %q", orgGotOrgID, org)
	}
	if orgGotUserID != memberID {
		t.Errorf("reader received member id %q, want the path parameter %q", orgGotUserID, memberID)
	}

	// A project-scoped grant must not be widened to a sibling-organization
	// {org_id} either: an out-of-scope organization read is denied regardless
	// of which organization the path names — the cross-tenant guard and the
	// out-of-scope guard both hold.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionMembersRead, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(members.read, foreign org) for a project-scoped key = %+v, want deny", got)
	}
}
