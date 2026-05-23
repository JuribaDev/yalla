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

// Policy-matrix coverage for GET /v1/organizations/{org_id}/members (BE-0063).
// Where members_test.go proves the endpoint's wire contract, this file proves
// its authorization contract: that action members.read cannot be bypassed by —
// or leak data because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// This route carries the organizationIDResolver, so RequireAuth authorizes
// action members.read against the organization the {org_id} PATH names — not
// merely the principal's home organization. That is the property under test
// here: a cross-tenant {org_id} must be a deterministic 403 before the handler
// runs, while a {org_id} naming the caller's own organization is allowed by
// the role (or an organization-scoped grant) and never by a deeper-scoped
// grant.
//
// members.read is a CapRead action: all six built-in roles hold CapRead, so
// the role matrix for a principal listing its own organization's members is
// "all allow", but a disabled principal, a cross-tenant {org_id} for a
// non-support principal, or a grant whose scope does not cover the
// organization root are all denied.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// listMembersHandlerFor, getMembers, decodeListMembers, orgPrincipal,
// fakeMembershipReader, seedMember, and decodeError are shared with the
// sibling GET /v1/organizations/{org_id}/members contract suite.

// TestListMembersPolicyMatrixRoles proves every built-in organization role is
// allowed action members.read for an {org_id} that names its own home
// organization, and receives exactly the members of that organization. All
// six built-in roles hold CapRead, so the matrix is "all allow"; the
// assertions that matter are that the verdict is reached through the role
// (ReasonAllowedByRole) and that the reader is invoked with the path's
// organization id — never a fabricated, escalated, or sibling tenant.
func TestListMembersPolicyMatrixRoles(t *testing.T) {
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
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// At the engine level the role — not a grant, not the self
			// shortcut — is what confers members.read against the principal's
			// own organization.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionMembersRead, orgRoot)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(members.read) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
			}

			var gotOrgID string
			reader := fakeMembershipReader{
				members: []store.OrganizationMember{
					seedMember(org, "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 1, now, now),
				},
				gotOrgID: &gotOrgID,
			}
			handler := listMembersHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getMembers(handler, org, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeListMembers(t, rec)
			if len(env.Data.Members) != 1 || env.Data.Members[0].UserID != "usr_ada" {
				t.Errorf("members = %+v, want exactly the seeded member", env.Data.Members)
			}
			if gotOrgID != org {
				t.Errorf("reader received organization id %q, want the path parameter %q", gotOrgID, org)
			}
		})
	}
}

// TestListMembersPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// members.read with a stable 403 E_FORBIDDEN, even though every active role
// is allowed it. A revoked or expired key must never be able to list the
// members of the organization it once had access to, the reader must never
// run, and the denied body must not echo the principal id or the organization
// id back.
func TestListMembersPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			var gotOrgID string
			reader := fakeMembershipReader{
				members:  []store.OrganizationMember{seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada", "owner", 1, time.Now().UTC(), time.Now().UTC())},
				gotOrgID: &gotOrgID,
			}
			handler := listMembersHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getMembers(handler, "org_acme", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotOrgID != "" {
				t.Errorf("reader was reached with id %q for a disabled principal; it must never run", gotOrgID)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestListMembersPolicyWrongOrganizationPrincipal proves members.read is
// confined to the caller's own tenant — except for the documented support
// exception. This route carries the organizationIDResolver, so RequireAuth
// authorizes against the organization the {org_id} path names: a non-support
// principal whose home organization is org_intruder listing org_victim's
// members is a deterministic 403 ReasonDeniedCrossTenant, the reader is never
// reached, and the denied body never echoes the foreign id. A support
// principal performing a read is the one allowed cross-tenant exception
// (ReasonAllowedBySupport) and receives the members the path named.
func TestListMembersPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	// A non-support principal cannot read another organization's members
	// through the path parameter: the resolver scopes authorization to
	// org_victim and the engine denies the cross-tenant read before the
	// handler runs.
	intruder := orgPrincipal("usr_intruder", ownOrg, policy.RoleOwner)
	var gotOrgID string
	reader := fakeMembershipReader{
		members: []store.OrganizationMember{
			seedMember(victimOrg, "usr_v", "v@victim.example", "Victor", "owner", 1, now, now),
		},
		gotOrgID: &gotOrgID,
	}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)

	rec := getMembers(handler, victimOrg, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotOrgID != "" {
		t.Errorf("reader was reached with id %q for a cross-tenant request; it must never run", gotOrgID)
	}
	if strings.Contains(rec.Body.String(), victimOrg) {
		t.Errorf("error body %s echoed the cross-tenant organization id", rec.Body.String())
	}

	// At the engine level the cross-tenant boundary is pinned directly.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionMembersRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(members.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is the documented cross-tenant read exception — and, because this
	// route resolves the resource from the path, that exception IS reachable
	// here: a support principal listing another tenant's members is allowed
	// (ReasonAllowedBySupport) and receives the named organization's members.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionMembersRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(members.read, foreign org) for support = %+v, want allow via %q",
			got, policy.ReasonAllowedBySupport)
	}

	var supportGotOrgID string
	supportReader := fakeMembershipReader{
		members: []store.OrganizationMember{
			seedMember(victimOrg, "usr_v", "v@victim.example", "Victor", "owner", 1, now, now),
		},
		gotOrgID: &supportGotOrgID,
	}
	supportHandler := listMembersHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)

	supportRec := getMembers(supportHandler, victimOrg, "a-valid-support-token")
	if supportRec.Code != http.StatusOK {
		t.Fatalf("support status = %d, want 200; body %s", supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeListMembers(t, supportRec)
	if len(supportEnv.Data.Members) != 1 || supportEnv.Data.Members[0].UserID != "usr_v" {
		t.Errorf("support members = %+v, want exactly the victim's member", supportEnv.Data.Members)
	}
	if supportGotOrgID != victimOrg {
		t.Errorf("support read reached the reader with id %q, want the path parameter %q", supportGotOrgID, victimOrg)
	}
}

// TestListMembersPolicyGrantContainment proves scoped grants cannot be widened
// past the scope they were issued for. A scoped API key is authorized purely
// by its grants (it carries no organization role); the engine confines those
// grants — a project grant does not reach a sibling project, an environment
// grant does not reach production, a service grant does not reach the parent
// environment or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}/members: members.read is
// evaluated against the organization-root scope the {org_id} path names,
// which a project/environment/service grant does not cover — not even for the
// key's own organization. So a scoped key holding only a project grant is
// denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope, while a key holding an organization-level viewer
// grant is allowed it (ReasonAllowedByGrant). A scoped grant narrows
// authority within a tenant; it can never be escalated to a broader read
// than it covers.
func TestListMembersPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
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

	// GET /v1/organizations/{org_id}/members lists the memberships of the
	// organization root the path names. A project-scoped grant does not cover
	// that scope — not even for the key's own organization — so the project
	// grantee is denied the endpoint with a stable 403: the scoped key cannot
	// be widened to an organization-wide membership read.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionMembersRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(members.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectGotOrgID string
	projectReader := fakeMembershipReader{
		members:  []store.OrganizationMember{seedMember(org, "usr_ada", "ada@acme.example", "Ada", "owner", 1, time.Now().UTC(), time.Now().UTC())},
		gotOrgID: &projectGotOrgID,
	}
	projectKeyHandler := listMembersHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getMembers(projectKeyHandler, org, "yk_project_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectGotOrgID != "" {
		t.Errorf("reader was reached with id %q for an out-of-scope key; it must never run", projectGotOrgID)
	}

	// An organization-level grant does cover the organization root, so a key
	// scoped to the whole organization is allowed the endpoint for its own
	// {org_id}. members.read is a CapRead action, so even a Viewer grant at
	// the organization root is sufficient — but only at the organization root.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionMembersRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(members.read) for an organization-scoped key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	var orgGotOrgID string
	orgReader := fakeMembershipReader{
		members: []store.OrganizationMember{
			seedMember(org, "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 1, now, now),
		},
		gotOrgID: &orgGotOrgID,
	}
	orgKeyHandler := listMembersHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	okRec := getMembers(orgKeyHandler, org, "yk_org_scoped")
	if okRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an organization-scoped key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeListMembers(t, okRec)
	if len(okEnv.Data.Members) != 1 || okEnv.Data.Members[0].UserID != "usr_ada" {
		t.Errorf("members = %+v, want exactly the seeded member of the key's own org", okEnv.Data.Members)
	}
	if orgGotOrgID != org {
		t.Errorf("reader received organization id %q, want the key's own org %q", orgGotOrgID, org)
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
