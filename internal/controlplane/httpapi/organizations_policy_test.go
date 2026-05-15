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

// Policy-matrix coverage for GET /v1/organizations (BE-0048). Where
// organizations_test.go proves the endpoint's wire contract, this file proves
// its authorization contract: that action organization.read cannot be bypassed
// by — or leak data because of — the principal's role, revoked credentials,
// home organization, or scoped grants.
//
// organization.read is a CapRead action, not a CapSelf one. Unlike auth.orgs
// (every authenticated principal holds it), organization.read requires the
// read capability: all six built-in roles hold CapRead, so the role matrix is
// "all allow", but a disabled principal, a cross-tenant resource, or a grant
// whose scope does not cover the organization root are all denied. The
// /v1/organizations route carries no ResourceResolver, so RequireAuth
// authorizes against the principal's own organization scope — a request can
// never be pointed at another tenant through this route.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, or the engine fails here. organizationsHandlerFor, getOrganizations,
// decodeOrganizations, orgPrincipal, fakeOrganizationReader, and decodeError
// are shared with the sibling /v1/organizations contract suite.

// TestOrganizationsPolicyMatrixRoles proves every built-in organization role is
// allowed action organization.read and receives exactly its own home
// organization. All six built-in roles hold CapRead, so the matrix is "all
// allow"; the assertions that matter are that the verdict is reached through
// the role (ReasonAllowedByRole) and that the listed organization is the
// caller's, never a fabricated, escalated, or sibling tenant.
func TestOrganizationsPolicyMatrixRoles(t *testing.T) {
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

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := policy.Principal{ID: "usr_" + tc.name, Kind: tc.kind, OrganizationID: org, Role: tc.role}

			// At the engine level the role — not a grant, not the self
			// shortcut — is what confers organization.read.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionOrganizationRead,
				policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}})
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(organization.read) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
			}

			reader := fakeOrganizationReader{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme, Inc."}}
			handler := organizationsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getOrganizations(handler, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeOrganizations(t, rec)
			if len(env.Data.Organizations) != 1 {
				t.Fatalf("organizations = %+v, want exactly the caller's home org", env.Data.Organizations)
			}
			if id := env.Data.Organizations[0].OrganizationID; id != org {
				t.Errorf("organization_id = %q, want the caller's own org %q", id, org)
			}
		})
	}
}

// TestOrganizationsPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// organization.read with a stable 403 E_FORBIDDEN, even though every active
// role is allowed it. A revoked or expired key must never be able to read the
// organization it once had access to, and the denied body must not echo the
// principal id or its organization back.
func TestOrganizationsPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			principal := policy.Principal{
				ID:             tc.id,
				Kind:           domain.KindServiceAccount,
				OrganizationID: "org_acme",
				Role:           policy.RoleOwner,
				Disabled:       true,
			}
			// The reader must never be reached — authorization fails first.
			reader := fakeOrganizationReader{org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"}}
			handler := organizationsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getOrganizations(handler, "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestOrganizationsPolicyWrongOrganizationPrincipal proves organization.read is
// confined to the caller's own tenant. The /v1/organizations route carries no
// path parameter and no ResourceResolver, so RequireAuth authorizes against —
// and the handler reads — the principal's own organization: a principal whose
// home organization is org_intruder receives org_intruder's organization and
// nothing else.
//
// At the engine level the cross-tenant boundary is pinned directly: a non-
// support role is denied organization.read on a foreign organization with the
// stable ReasonDeniedCrossTenant. The support role is the documented exception
// — it may read across tenants (ReasonAllowedBySupport) — but that exception
// can never reach customers through this route, because the nil resolver gives
// the engine the principal's own organization, never a foreign one.
func TestOrganizationsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	principal := policy.Principal{ID: "usr_intruder", Kind: domain.KindUser, OrganizationID: ownOrg, Role: policy.RoleOwner}
	reader := fakeOrganizationReader{org: store.Organization{ID: ownOrg, Slug: "intruder", DisplayName: "Intruder"}}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

	rec := getOrganizations(handler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the caller's own org", env.Data.Organizations)
	}
	if id := env.Data.Organizations[0].OrganizationID; id != ownOrg {
		t.Errorf("organization_id = %q, want the caller's own org %q", id, ownOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response %s leaked another tenant's identifiers", body)
	}

	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}

	// A non-support role cannot read another organization at all.
	if got := e.Decide(principal, policy.ActionOrganizationRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(organization.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is the documented cross-tenant read exception — but it is an
	// engine-level capability for internal tooling, never reachable through
	// this route's own-organization resolver.
	support := policy.Principal{ID: "usr_support", Kind: domain.KindUser, OrganizationID: ownOrg, Role: policy.RoleSupport}
	if got := e.Decide(support, policy.ActionOrganizationRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(organization.read, foreign org) for support = %+v, want allow via %q",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestOrganizationsPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is authorized
// purely by its grants (it carries no organization role); the engine confines
// those grants — a project grant does not reach a sibling project, an
// environment grant does not reach production, a service grant does not reach
// the parent environment or a sibling service.
//
// Crucially for GET /v1/organizations: organization.read is evaluated against
// the organization-root scope, which a project/environment/service grant does
// not cover. So a scoped key holding only a project grant is denied the
// endpoint with the stable ReasonDeniedOutOfScope, while a key holding an
// organization-level grant is allowed it (ReasonAllowedByGrant). A scoped grant
// narrows authority within a tenant; it can never be escalated to a broader
// read than it covers.
func TestOrganizationsPolicyGrantContainment(t *testing.T) {
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

	// GET /v1/organizations reads the organization root. A project-scoped grant
	// does not cover that scope, so the project grantee is denied the endpoint
	// with a stable 403 — the scoped key cannot be widened to an organization
	// read.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionOrganizationRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(organization.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	reader := fakeOrganizationReader{org: store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"}}
	projectKeyHandler := organizationsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, reader)
	rec := getOrganizations(projectKeyHandler, "yk_project_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// An organization-level grant does cover the organization root, so a key
	// scoped to the whole organization is allowed the endpoint.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionOrganizationRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(organization.read) for an organization-scoped key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	orgKeyHandler := organizationsHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey}, nil, reader)
	okRec := getOrganizations(orgKeyHandler, "yk_org_scoped")
	if okRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an organization-scoped key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeOrganizations(t, okRec)
	if len(okEnv.Data.Organizations) != 1 || okEnv.Data.Organizations[0].OrganizationID != org {
		t.Errorf("organizations = %+v, want exactly the key's own org %q", okEnv.Data.Organizations, org)
	}
}
