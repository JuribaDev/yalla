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

// Policy-matrix coverage for PATCH /v1/organizations/{org_id} (BE-0057). Where
// organizations_patch_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action organization.update cannot be
// bypassed by — or leak data because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// This route carries the organizationIDResolver, so RequireAuth authorizes
// action organization.update against the organization the {org_id} PATH names —
// not merely the principal's home organization. That is the property under
// test: a cross-tenant {org_id} must be a deterministic 403 before the handler
// runs, while a {org_id} naming the caller's own organization is allowed only
// by an admin-capable role (or an organization-scoped admin grant) and never by
// a deeper-scoped grant.
//
// organization.update requires CapAdmin — unlike organization.read's CapRead.
// Only RoleOwner and RoleAdmin hold CapAdmin, so the role matrix for a principal
// updating its own organization is "owner/admin allow, everyone else deny", and
// — crucially — support is NOT a cross-tenant exception here, because the
// support carve-out only covers CapRead and CapSupport actions. A disabled
// principal, a cross-tenant {org_id} for any role, or a grant whose scope does
// not cover the organization root are all denied.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// updateOrganizationHandlerFor, patchOrganization, decodeUpdateOrganization,
// fakeOrganizationUpdater, orgPrincipal, and decodeError are shared with the
// sibling PATCH /v1/organizations/{org_id} contract suite.

// TestUpdateOrganizationPolicyMatrixRoles proves the role contract for action
// organization.update: RoleOwner and RoleAdmin hold CapAdmin and are allowed it
// for an {org_id} naming their own home organization (ReasonAllowedByRole),
// while RoleDeveloper, RoleViewer, RoleCI, and RoleSupport lack CapAdmin and are
// denied with a stable 403 ReasonDeniedNoCapability — even though they
// authenticate cleanly and target their own tenant. For the denied roles the
// updater is never reached, so an under-privileged principal can never mutate
// the organization.
func TestUpdateOrganizationPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	cases := []struct {
		name  string
		role  policy.Role
		kind  domain.Kind
		allow bool
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true},
		{"admin", policy.RoleAdmin, domain.KindUser, true},
		{"developer", policy.RoleDeveloper, domain.KindUser, false},
		{"viewer", policy.RoleViewer, domain.KindUser, false},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false},
		{"support", policy.RoleSupport, domain.KindUser, false},
	}

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// At the engine level the role — not a grant, not the self
			// shortcut — is what does or does not confer organization.update
			// against the principal's own organization.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionOrganizationUpdate, orgRoot)
			if tc.allow {
				if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
					t.Fatalf("Decide(organization.update) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
				}
			} else {
				if got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
					t.Fatalf("Decide(organization.update) = %+v, want deny via %q", got, policy.ReasonDeniedNoCapability)
				}
			}

			var captured store.UpdateOrganizationInput
			updater := fakeOrganizationUpdater{
				org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme Worldwide"},
				got: &captured,
			}
			handler := updateOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, updater)

			rec := patchOrganization(handler, org, "a-valid-token", `{"display_name":"Acme Worldwide"}`)
			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				env := decodeUpdateOrganization(t, rec)
				if id := env.Data.Organization.OrganizationID; id != org {
					t.Errorf("organization_id = %q, want the {org_id} the path named %q", id, org)
				}
				if captured.OrganizationID != org {
					t.Errorf("updater received organization id %q, want the path parameter %q", captured.OrganizationID, org)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			errEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(errEnv.Error.Message, string(policy.ReasonDeniedNoCapability)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					errEnv.Error.Message, policy.ReasonDeniedNoCapability)
			}
			if captured.OrganizationID != "" {
				t.Errorf("updater was reached with id %q for an under-privileged role; it must never run", captured.OrganizationID)
			}
		})
	}
}

// TestUpdateOrganizationPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// organization.update with a stable 403 E_FORBIDDEN, even when the principal
// otherwise holds an admin-capable role. A revoked or expired key must never be
// able to mutate the organization it once administered, the updater must never
// run, and the denied body must not echo the principal id or the organization
// id back.
func TestUpdateOrganizationPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			// The updater must never be reached — authorization fails first.
			var captured store.UpdateOrganizationInput
			updater := fakeOrganizationUpdater{
				org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
				got: &captured,
			}
			handler := updateOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, updater)

			rec := patchOrganization(handler, "org_acme", "yk_no_longer_valid", `{"display_name":"Acme"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" {
				t.Errorf("updater was reached with id %q for a disabled principal; it must never run", captured.OrganizationID)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestUpdateOrganizationPolicyWrongOrganizationPrincipal proves organization.update
// is confined to the caller's own tenant with no exception. This route carries
// the organizationIDResolver, so RequireAuth authorizes against the organization
// the {org_id} path names: a principal whose home organization is org_intruder
// patching org_victim is a deterministic 403 ReasonDeniedCrossTenant, the
// updater is never reached, and the denied body never echoes the foreign id.
//
// Unlike GET /v1/organizations/{org_id}, support is NOT a cross-tenant exception
// here: the support carve-out only covers CapRead and CapSupport actions, and
// organization.update requires CapAdmin — so a support principal reaching for
// another tenant's organization is denied exactly like any other role.
func TestUpdateOrganizationPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}

	cases := []struct {
		name string
		role policy.Role
		kind domain.Kind
	}{
		{"owner", policy.RoleOwner, domain.KindUser},
		{"admin", policy.RoleAdmin, domain.KindUser},
		// Support can read across tenants, but organization.update needs
		// CapAdmin — so even support is denied cross-tenant here.
		{"support", policy.RoleSupport, domain.KindUser},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			principal.Kind = tc.kind

			// At the engine level the cross-tenant boundary is pinned directly:
			// no role — not even support — may update another tenant.
			if got := e.Decide(principal, policy.ActionOrganizationUpdate, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(organization.update, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}

			var captured store.UpdateOrganizationInput
			updater := fakeOrganizationUpdater{
				org: store.Organization{ID: victimOrg, Slug: "victim", DisplayName: "Victim"},
				got: &captured,
			}
			handler := updateOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, updater)

			rec := patchOrganization(handler, victimOrg, "a-valid-token", `{"display_name":"Pwned"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedCrossTenant)
			}
			if captured.OrganizationID != "" {
				t.Errorf("updater was reached with id %q for a cross-tenant request; it must never run", captured.OrganizationID)
			}
			if strings.Contains(rec.Body.String(), victimOrg) {
				t.Errorf("error body %s echoed the cross-tenant organization id", rec.Body.String())
			}
		})
	}
}

// TestUpdateOrganizationPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is authorized
// purely by its grants (it carries no organization role); the engine confines
// those grants — a project grant does not reach a sibling project, an
// environment grant does not reach production, a service grant does not reach
// the parent environment or a sibling service.
//
// Crucially for PATCH /v1/organizations/{org_id}: organization.update is
// evaluated against the organization-root scope the {org_id} path names. A
// project/environment/service grant does not cover that scope — not even for
// the key's own organization, and not even when the grant's role is admin-
// capable — so such a key is denied the endpoint with the stable
// ReasonDeniedOutOfScope. Only a grant scoped to the organization root and
// carrying an admin-capable role is allowed it (ReasonAllowedByGrant). A scoped
// grant narrows authority within a tenant; it can never be escalated to a
// broader write than it covers.
func TestUpdateOrganizationPolicyGrantContainment(t *testing.T) {
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

	// PATCH /v1/organizations/{org_id} updates the organization root the path
	// names. A project-scoped grant does not cover that scope — not even when
	// the grant carries an admin-capable role, and not even for the key's own
	// organization — so the project grantee is denied the endpoint with a
	// stable 403: the scoped key cannot be widened to an organization update.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeP}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionOrganizationUpdate, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(organization.update) for a project-scoped admin key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectCaptured store.UpdateOrganizationInput
	projectKeyHandler := updateOrganizationHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrganizationUpdater{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"}, got: &projectCaptured})
	rec := patchOrganization(projectKeyHandler, org, "yk_project_scoped", `{"display_name":"Acme"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectCaptured.OrganizationID != "" {
		t.Errorf("updater was reached with id %q for an out-of-scope key; it must never run", projectCaptured.OrganizationID)
	}

	// An organization-level grant carrying an admin-capable role does cover the
	// organization root, so a key scoped to the whole organization is allowed
	// the endpoint for its own {org_id}.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionOrganizationUpdate, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(organization.update) for an organization-scoped admin key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// A viewer-scoped organization grant carries no admin capability, so even an
	// organization-root grant does not confer organization.update.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionOrganizationUpdate, orgRoot); got.Allow {
		t.Errorf("Decide(organization.update) for an organization-scoped viewer key = %+v, want deny — a viewer grant confers no admin capability", got)
	}

	var orgCaptured store.UpdateOrganizationInput
	orgKeyHandler := updateOrganizationHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrganizationUpdater{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"}, got: &orgCaptured})
	okRec := patchOrganization(orgKeyHandler, org, "yk_org_scoped", `{"display_name":"Acme"}`)
	if okRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an organization-scoped admin key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeUpdateOrganization(t, okRec)
	if id := okEnv.Data.Organization.OrganizationID; id != org {
		t.Errorf("organization_id = %q, want the key's own org %q", id, org)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("updater received organization id %q, want the path parameter %q", orgCaptured.OrganizationID, org)
	}

	// A project-scoped grant must not be widened to a sibling-organization
	// {org_id} either: an out-of-scope organization update is denied as a
	// cross-tenant request regardless of which organization the path names.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectAdminGrantee, policy.ActionOrganizationUpdate, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(organization.update, foreign org) for a project-scoped key = %+v, want deny", got)
	}
}
