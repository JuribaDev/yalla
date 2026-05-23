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

// Policy-matrix coverage for GET /v1/organizations/{org_id} (BE-0054). Where
// organizations_get_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action organization.read cannot be
// bypassed by — or leak data because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// Unlike GET /v1/organizations, this route carries the organizationIDResolver,
// so RequireAuth authorizes action organization.read against the organization
// the {org_id} PATH names — not merely the principal's home organization. That
// is the property under test here: a cross-tenant {org_id} must be a
// deterministic 403 before the handler runs, while a {org_id} naming the
// caller's own organization is allowed by the role (or an organization-scoped
// grant) and never by a deeper-scoped grant.
//
// organization.read is a CapRead action: all six built-in roles hold CapRead,
// so the role matrix for a principal reading its own organization is "all
// allow", but a disabled principal, a cross-tenant {org_id} for a non-support
// principal, or a grant whose scope does not cover the organization root are
// all denied.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// organizationsHandlerFor, getOrganizationByID, decodeGetOrganization,
// orgPrincipal, fakeOrganizationReader, and decodeError are shared with the
// sibling GET /v1/organizations/{org_id} contract suite.

// TestGetOrganizationPolicyMatrixRoles proves every built-in organization role
// is allowed action organization.read for an {org_id} that names its own home
// organization, and receives exactly that organization. All six built-in roles
// hold CapRead, so the matrix is "all allow"; the assertions that matter are
// that the verdict is reached through the role (ReasonAllowedByRole) and that
// the returned organization is the one the path named, never a fabricated,
// escalated, or sibling tenant.
func TestGetOrganizationPolicyMatrixRoles(t *testing.T) {
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
			// shortcut — is what confers organization.read against the
			// principal's own organization.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionOrganizationRead,
				policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}})
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(organization.read) = %+v, want allow via %q", got, policy.ReasonAllowedByRole)
			}

			var gotID string
			reader := fakeOrganizationReader{
				org:   store.Organization{ID: org, Slug: "acme", DisplayName: "Acme, Inc."},
				gotID: &gotID,
			}
			handler := organizationsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getOrganizationByID(handler, org, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeGetOrganization(t, rec)
			if id := env.Data.Organization.OrganizationID; id != org {
				t.Errorf("organization_id = %q, want the {org_id} the path named %q", id, org)
			}
			if gotID != org {
				t.Errorf("reader received organization id %q, want the path parameter %q", gotID, org)
			}
		})
	}
}

// TestGetOrganizationPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// organization.read with a stable 403 E_FORBIDDEN, even though every active
// role is allowed it. A revoked or expired key must never be able to read the
// organization it once had access to, and the denied body must not echo the
// principal id or the organization id back.
func TestGetOrganizationPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			var gotID string
			reader := fakeOrganizationReader{
				org:   store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
				gotID: &gotID,
			}
			handler := organizationsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getOrganizationByID(handler, "org_acme", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if gotID != "" {
				t.Errorf("reader was reached with id %q for a disabled principal; it must never run", gotID)
			}
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestGetOrganizationPolicyWrongOrganizationPrincipal proves organization.read
// is confined to the caller's own tenant — except for the documented support
// exception. This route carries the organizationIDResolver, so RequireAuth
// authorizes against the organization the {org_id} path names: a non-support
// principal whose home organization is org_intruder requesting org_victim is a
// deterministic 403 ReasonDeniedCrossTenant, the reader is never reached, and
// the denied body never echoes the foreign id. A support principal performing
// a read is the one allowed cross-tenant exception (ReasonAllowedBySupport) and
// receives the organization the path named.
func TestGetOrganizationPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	// A non-support principal cannot read another organization through the
	// path parameter: the resolver scopes authorization to org_victim and the
	// engine denies the cross-tenant read before the handler runs.
	intruder := policy.Principal{ID: "usr_intruder", Kind: domain.KindUser, OrganizationID: ownOrg, Role: policy.RoleOwner}
	var gotID string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: victimOrg, Slug: "victim", DisplayName: "Victim"},
		gotID: &gotID,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)

	rec := getOrganizationByID(handler, victimOrg, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotID != "" {
		t.Errorf("reader was reached with id %q for a cross-tenant request; it must never run", gotID)
	}
	if strings.Contains(rec.Body.String(), victimOrg) {
		t.Errorf("error body %s echoed the cross-tenant organization id", rec.Body.String())
	}

	// At the engine level the cross-tenant boundary is pinned directly.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionOrganizationRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(organization.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is the documented cross-tenant read exception — and, because this
	// route resolves the resource from the path, that exception IS reachable
	// here: a support principal reading another tenant's organization is
	// allowed (ReasonAllowedBySupport) and receives the named organization.
	support := policy.Principal{ID: "usr_support", Kind: domain.KindUser, OrganizationID: "org_yalla", Role: policy.RoleSupport}
	if got := e.Decide(support, policy.ActionOrganizationRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(organization.read, foreign org) for support = %+v, want allow via %q",
			got, policy.ReasonAllowedBySupport)
	}

	var supportGotID string
	supportReader := fakeOrganizationReader{
		org:   store.Organization{ID: victimOrg, Slug: "victim", DisplayName: "Victim"},
		gotID: &supportGotID,
	}
	supportHandler := organizationsHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)

	supportRec := getOrganizationByID(supportHandler, victimOrg, "a-valid-support-token")
	if supportRec.Code != http.StatusOK {
		t.Fatalf("support status = %d, want 200; body %s", supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeGetOrganization(t, supportRec)
	if id := supportEnv.Data.Organization.OrganizationID; id != victimOrg {
		t.Errorf("support organization_id = %q, want the {org_id} the path named %q", id, victimOrg)
	}
	if supportGotID != victimOrg {
		t.Errorf("support read reached the reader with id %q, want the path parameter %q", supportGotID, victimOrg)
	}
}

// TestGetOrganizationPolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is authorized
// purely by its grants (it carries no organization role); the engine confines
// those grants — a project grant does not reach a sibling project, an
// environment grant does not reach production, a service grant does not reach
// the parent environment or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}: organization.read is evaluated
// against the organization-root scope the {org_id} path names, which a
// project/environment/service grant does not cover — not even for the key's
// own organization. So a scoped key holding only a project grant is denied the
// endpoint for its own {org_id} with the stable ReasonDeniedOutOfScope, while a
// key holding an organization-level grant is allowed it (ReasonAllowedByGrant).
// A scoped grant narrows authority within a tenant; it can never be escalated
// to a broader read than it covers.
func TestGetOrganizationPolicyGrantContainment(t *testing.T) {
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

	// GET /v1/organizations/{org_id} reads the organization root the path
	// names. A project-scoped grant does not cover that scope — not even for
	// the key's own organization — so the project grantee is denied the
	// endpoint with a stable 403: the scoped key cannot be widened to an
	// organization read.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionOrganizationRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(organization.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	var projectGotID string
	reader := fakeOrganizationReader{
		org:   store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"},
		gotID: &projectGotID,
	}
	projectKeyHandler := organizationsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, reader)
	rec := getOrganizationByID(projectKeyHandler, org, "yk_project_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectGotID != "" {
		t.Errorf("reader was reached with id %q for an out-of-scope key; it must never run", projectGotID)
	}

	// An organization-level grant does cover the organization root, so a key
	// scoped to the whole organization is allowed the endpoint for its own
	// {org_id}.
	orgGrantee := policy.Principal{
		ID: "sa_org", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgGrantee, policy.ActionOrganizationRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(organization.read) for an organization-scoped key = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	var orgGotID string
	orgReader := fakeOrganizationReader{
		org:   store.Organization{ID: org, Slug: "acme", DisplayName: "Acme"},
		gotID: &orgGotID,
	}
	orgKeyHandler := organizationsHandlerFor(
		auth.Identity{Principal: orgGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	okRec := getOrganizationByID(orgKeyHandler, org, "yk_org_scoped")
	if okRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an organization-scoped key; body %s", okRec.Code, okRec.Body.String())
	}
	okEnv := decodeGetOrganization(t, okRec)
	if id := okEnv.Data.Organization.OrganizationID; id != org {
		t.Errorf("organization_id = %q, want the key's own org %q", id, org)
	}
	if orgGotID != org {
		t.Errorf("reader received organization id %q, want the path parameter %q", orgGotID, org)
	}

	// A project-scoped grant must not be widened to a sibling-project {org_id}
	// either: an out-of-scope organization read is denied regardless of which
	// organization the path names — the cross-tenant guard and the
	// out-of-scope guard both hold.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionOrganizationRead, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(organization.read, foreign org) for a project-scoped key = %+v, want deny", got)
	}
}
