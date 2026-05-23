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

// Policy-matrix coverage for DELETE /v1/organizations/{org_id} (BE-0060). Where
// organizations_delete_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action organization.delete cannot be
// bypassed by — or leak data because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// This route carries the organizationIDResolver, so RequireAuth authorizes
// action organization.delete against the organization the {org_id} PATH names —
// not merely the principal's home organization. That is the property under
// test: a cross-tenant {org_id} must be a deterministic 403 before the handler
// runs, while a {org_id} naming the caller's own organization is allowed only
// by an owner-capable role (or an organization-scoped owner grant) and never by
// an admin-capable-but-not-owner role or a deeper-scoped grant.
//
// organization.delete requires CapOwner — stricter than organization.update's
// CapAdmin. Only RoleOwner holds CapOwner, so the role matrix for a principal
// deleting its own organization is "owner allow, everyone else deny" — admin
// included — and support is NOT a cross-tenant exception here, because the
// support carve-out only covers CapRead and CapSupport actions. A disabled
// principal, a cross-tenant {org_id} for any role, or a grant whose scope does
// not cover the organization root are all denied.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// deleteOrganizationHandlerFor, deleteOrganization, decodeDeleteOrganization,
// fakeOrganizationDeleter, orgPrincipal, and decodeError are shared with the
// sibling DELETE /v1/organizations/{org_id} contract suite.

// TestDeleteOrganizationPolicyMatrixRoles proves the role contract for action
// organization.delete: RoleOwner holds CapOwner and is allowed it for an
// {org_id} naming its own home organization (ReasonAllowedByRole), while
// RoleAdmin, RoleDeveloper, RoleViewer, RoleCI, and RoleSupport lack CapOwner
// and are denied with a stable 403 ReasonDeniedNoCapability — even though they
// authenticate cleanly and target their own tenant. Crucially RoleAdmin, which
// can update the organization, still cannot delete it. For the denied roles the
// deleter is never reached, so an under-privileged principal can never schedule
// the organization for deletion.
func TestDeleteOrganizationPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	cases := []struct {
		name  string
		role  policy.Role
		kind  domain.Kind
		allow bool
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true},
		{"admin", policy.RoleAdmin, domain.KindUser, false},
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
			// shortcut — is what does or does not confer organization.delete
			// against the principal's own organization.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionOrganizationDelete, orgRoot)
			if tc.allow {
				if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
					t.Fatalf("Decide(organization.delete) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
				}
			} else {
				if got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
					t.Fatalf("Decide(organization.delete) = %+v, want deny via %q", got, policy.ReasonDeniedNoCapability)
				}
			}

			var captured store.DeleteOrganizationInput
			deleter := fakeOrganizationDeleter{
				org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"},
				got: &captured,
			}
			handler := deleteOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, deleter)

			rec := deleteOrganization(handler, org, "a-valid-token")
			if tc.allow {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
				}
				env := decodeDeleteOrganization(t, rec)
				if id := env.Data.Organization.OrganizationID; id != org {
					t.Errorf("organization_id = %q, want the {org_id} the path named %q", id, org)
				}
				if captured.OrganizationID != org {
					t.Errorf("deleter received organization id %q, want the path parameter %q", captured.OrganizationID, org)
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
				t.Errorf("deleter was reached with id %q for an under-privileged role; it must never run", captured.OrganizationID)
			}
		})
	}
}

// TestDeleteOrganizationPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// organization.delete with a stable 403 E_FORBIDDEN, even when the principal
// otherwise holds the owner role. A revoked or expired key must never be able
// to delete the organization it once owned, the deleter must never run, and the
// denied body must not echo the principal id or the organization id back.
func TestDeleteOrganizationPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			// The deleter must never be reached — authorization fails first.
			var captured store.DeleteOrganizationInput
			deleter := fakeOrganizationDeleter{
				org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
				got: &captured,
			}
			handler := deleteOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, deleter)

			rec := deleteOrganization(handler, "org_acme", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" {
				t.Errorf("deleter was reached with id %q for a disabled principal; it must never run", captured.OrganizationID)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestDeleteOrganizationPolicyWrongOrganizationPrincipal proves organization.delete
// is confined to the caller's own tenant with no exception. This route carries
// the organizationIDResolver, so RequireAuth authorizes against the organization
// the {org_id} path names: a principal whose home organization is org_intruder
// deleting org_victim is a deterministic 403 ReasonDeniedCrossTenant, the
// deleter is never reached, and the denied body never echoes the foreign id.
//
// Unlike GET /v1/organizations/{org_id}, support is NOT a cross-tenant exception
// here: the support carve-out only covers CapRead and CapSupport actions, and
// organization.delete requires CapOwner — so a support principal reaching for
// another tenant's organization is denied exactly like any other role.
func TestDeleteOrganizationPolicyWrongOrganizationPrincipal(t *testing.T) {
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
		// Support can read across tenants, but organization.delete needs
		// CapOwner — so even support is denied cross-tenant here.
		{"support", policy.RoleSupport, domain.KindUser},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			principal.Kind = tc.kind

			// At the engine level the cross-tenant boundary is pinned directly:
			// no role — not even support — may delete another tenant.
			if got := e.Decide(principal, policy.ActionOrganizationDelete, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(organization.delete, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}

			var captured store.DeleteOrganizationInput
			deleter := fakeOrganizationDeleter{
				org: store.Organization{ID: victimOrg, Slug: "victim", DisplayName: "Victim"},
				got: &captured,
			}
			handler := deleteOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, deleter)

			rec := deleteOrganization(handler, victimOrg, "a-valid-token")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedCrossTenant)
			}
			if captured.OrganizationID != "" {
				t.Errorf("deleter was reached with id %q for a cross-tenant request; it must never run", captured.OrganizationID)
			}
			if strings.Contains(rec.Body.String(), victimOrg) {
				t.Errorf("error body %s echoed the cross-tenant organization id", rec.Body.String())
			}
		})
	}
}

// TestDeleteOrganizationPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is authorized
// purely by its grants (it carries no organization role); the engine confines
// those grants — a project grant does not reach a sibling project, an
// environment grant does not reach production, a service grant does not reach
// the parent environment or a sibling service.
//
// Crucially for DELETE /v1/organizations/{org_id}: organization.delete is
// evaluated against the organization-root scope the {org_id} path names. A
// project/environment/service grant does not cover that scope — not even for
// the key's own organization, and not even when the grant's role is owner-
// capable — so such a key is denied the endpoint with the stable
// ReasonDeniedOutOfScope. Only a grant scoped to the organization root and
// carrying an owner-capable role is allowed it (ReasonAllowedByGrant); an
// organization-root grant carrying only an admin-capable role is still denied,
// because organization.delete requires CapOwner. A scoped grant narrows
// authority within a tenant; it can never be escalated to a broader write than
// it covers.
func TestDeleteOrganizationPolicyGrantContainment(t *testing.T) {
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

	// DELETE /v1/organizations/{org_id} deletes the organization root the path
	// names. A project-scoped grant does not cover that scope — not even when
	// the grant carries an owner-capable role, and not even for the key's own
	// organization — so the project grantee is denied the endpoint with a
	// stable 403: the scoped key cannot be widened to an organization delete.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	projectOwnerGrantee := policy.Principal{
		ID: "sa_proj_owner", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleOwner, Scope: scopeP}},
	}
	if got := e.Decide(projectOwnerGrantee, policy.ActionOrganizationDelete, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(organization.delete) for a project-scoped owner key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectCaptured store.DeleteOrganizationInput
	projectKeyHandler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: projectOwnerGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrganizationDeleter{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"}, got: &projectCaptured})
	rec := deleteOrganization(projectKeyHandler, org, "yk_project_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectCaptured.OrganizationID != "" {
		t.Errorf("deleter was reached with id %q for an out-of-scope key; it must never run", projectCaptured.OrganizationID)
	}

	// An organization-level grant carrying an admin-capable role does NOT confer
	// organization.delete: the action requires CapOwner, which RoleAdmin lacks.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionOrganizationDelete, orgRoot); got.Allow {
		t.Errorf("Decide(organization.delete) for an organization-scoped admin key = %+v, want deny — an admin grant confers no owner capability", got)
	}

	// An organization-level grant carrying an owner-capable role does cover the
	// organization root, so a key scoped to the whole organization with the
	// owner role is allowed the endpoint for its own {org_id}.
	orgOwnerGrantee := policy.Principal{
		ID: "sa_org_owner", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleOwner, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgOwnerGrantee, policy.ActionOrganizationDelete, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(organization.delete) for an organization-scoped owner key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.DeleteOrganizationInput
	orgKeyHandler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgOwnerGrantee, Method: auth.MethodAPIKey}, nil,
		fakeOrganizationDeleter{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"}, got: &orgCaptured})
	okRec := deleteOrganization(orgKeyHandler, org, "yk_org_scoped")
	if okRec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 for an organization-scoped owner key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeDeleteOrganization(t, okRec)
	if id := okEnv.Data.Organization.OrganizationID; id != org {
		t.Errorf("organization_id = %q, want the key's own org %q", id, org)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("deleter received organization id %q, want the path parameter %q", orgCaptured.OrganizationID, org)
	}

	// A project-scoped grant must not be widened to a sibling-organization
	// {org_id} either: an out-of-scope organization delete is denied as a
	// cross-tenant request regardless of which organization the path names.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectOwnerGrantee, policy.ActionOrganizationDelete, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(organization.delete, foreign org) for a project-scoped key = %+v, want deny", got)
	}
}
