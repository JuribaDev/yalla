package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// Policy-matrix coverage for GET /v1/me/organizations (BE-0045). Where
// me_organizations_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action auth.orgs cannot be bypassed
// by, or leak data because of, the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// auth.orgs is a CapSelf action — every authenticated, enabled principal holds
// it, regardless of role or scope, and the /v1/me/organizations route carries
// no ResourceResolver, so authorization is evaluated against the principal's
// own organization. The risk is therefore not "can a viewer call it" (every
// role can) but "does the endpoint ever list an organization the caller cannot
// actually see". Each test drives the real NewHandler + real policy.NewEngine()
// — the production request path — so a regression in the middleware, the
// catalog, or the engine fails here. mePrincipal, getMeOrganizations,
// decodeMeOrganizations, decodeError, and meHandlerFor are shared with the
// sibling /v1/me policy and contract suites.

// TestMeOrganizationsPolicyMatrixRoles proves every built-in organization role
// — and a role-less principal authorized purely by grants — is allowed action
// auth.orgs and receives exactly its own home organization. auth.orgs is a
// self action no role can be denied, so the matrix is "all allow"; the
// assertion that matters is that the listed organization is the caller's,
// never a fabricated, escalated, or sibling tenant.
func TestMeOrganizationsPolicyMatrixRoles(t *testing.T) {
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
		// A principal with no organization role at all, authorized purely by a
		// scoped grant: auth.orgs does not depend on a role, so it is still
		// allowed, and the role is omitted from the listed organization.
		{"grant-only", policy.Role(""), domain.KindServiceAccount},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := mePrincipal("usr_"+tc.name, tc.kind, org, tc.role)
			handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

			rec := getMeOrganizations(handler, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeMeOrganizations(t, rec)
			if len(env.Data.Organizations) != 1 {
				t.Fatalf("organizations = %+v, want exactly the caller's home org", env.Data.Organizations)
			}
			got := env.Data.Organizations[0]
			if got.OrganizationID != org {
				t.Errorf("organization_id = %q, want the caller's own org %q", got.OrganizationID, org)
			}
			if got.Role != string(tc.role) {
				t.Errorf("role = %q, want %q", got.Role, tc.role)
			}
			if got.Grants == nil {
				t.Errorf("grants decoded as nil, want a non-nil empty slice")
			}
		})
	}
}

// TestMeOrganizationsPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// auth.orgs with a stable 403 E_FORBIDDEN, even though every active role is
// allowed it. A revoked or expired key must never be able to enumerate the
// organizations it once had access to.
func TestMeOrganizationsPolicyRevokedAndExpiredKeys(t *testing.T) {
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

			principal := mePrincipal(tc.id, domain.KindServiceAccount, "org_acme", policy.RoleCI)
			principal.Disabled = true
			handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil)

			rec := getMeOrganizations(handler, "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			// The denied response must not echo the principal id or its
			// organization back.
			if body := rec.Body.String(); strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") {
				t.Errorf("error body %s leaked the principal id or organization", body)
			}
		})
	}
}

// TestMeOrganizationsPolicyWrongOrganizationPrincipal proves auth.orgs is
// organization-independent in the only safe way: a principal whose home
// organization is org_intruder receives org_intruder's organization and
// nothing else. The endpoint carries no path parameter and reads no database,
// so it cannot be pointed at another tenant — but this pins that property so a
// future resolver change cannot silently turn /v1/me/organizations into a
// cross-tenant probe.
func TestMeOrganizationsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	principal := mePrincipal("usr_intruder", domain.KindUser, ownOrg, policy.RoleOwner,
		policy.Grant{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: ownOrg, ProjectID: "proj_own"}})
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMeOrganizations(handler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the caller's own org", env.Data.Organizations)
	}
	if env.Data.Organizations[0].OrganizationID != ownOrg {
		t.Errorf("organization_id = %q, want the caller's own org %q",
			env.Data.Organizations[0].OrganizationID, ownOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response %s leaked another tenant's identifiers", body)
	}

	// At the engine level, auth.orgs is allowed regardless of the resource's
	// organization precisely because it is a self action that never reads the
	// resource — the resource org is irrelevant, so it can never be a leak.
	e := policy.NewEngine()
	got := e.Decide(principal, policy.ActionAuthOrgs,
		policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}})
	if !got.Allow || got.Reason != policy.ReasonAllowedSelf {
		t.Errorf("Decide(auth.orgs, foreign-org resource) = %+v, want allow via %q", got, policy.ReasonAllowedSelf)
	}
}

// TestMeOrganizationsPolicyGrantContainment proves the scoped grants a
// /v1/me/organizations principal carries are confined by the policy engine — a
// project grant does not reach a sibling project, an environment grant does not
// reach production, a service grant does not reach the parent environment or a
// sibling service — and that GET /v1/me/organizations echoes those grants
// verbatim inside the home organization without widening them or surfacing a
// second tenant. The endpoint reports the principal's authority; it must never
// report more than the engine would actually honour.
func TestMeOrganizationsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()

	// Project-level grant: developer on proj_p only.
	scopeP := policy.Scope{OrganizationID: org, ProjectID: "proj_p"}
	scopeQ := policy.Scope{OrganizationID: org, ProjectID: "proj_q"}
	projectGrantee := mePrincipal("usr_proj", domain.KindUser, org, policy.RoleViewer,
		policy.Grant{Role: policy.RoleDeveloper, Scope: scopeP})

	if got := e.Decide(projectGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindService, Scope: scopeP}); !got.Allow {
		t.Errorf("write inside the granted project = %+v, want allow", got)
	}
	if got := e.Decide(projectGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindService, Scope: scopeQ}); got.Allow {
		t.Errorf("write in a sibling project = %+v, want deny — a project grant must not reach proj_q", got)
	}

	// Environment-level grant: developer on the staging environment only.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_staging"}
	scopeProd := policy.Scope{OrganizationID: org, ProjectID: "proj_p", EnvironmentID: "env_prod"}
	envGrantee := mePrincipal("usr_env", domain.KindUser, org, policy.RoleViewer,
		policy.Grant{Role: policy.RoleDeveloper, Scope: scopeStaging})

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
	svcGrantee := mePrincipal("usr_svc", domain.KindUser, org, policy.RoleViewer,
		policy.Grant{Role: policy.RoleDeveloper, Scope: scopeSvcA})

	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets", got)
	}

	// GET /v1/me/organizations echoes the project grant exactly: same scope, no
	// widening to a sibling project and no deeper ids invented, all confined to
	// the single home organization.
	handler := meHandlerFor(auth.Identity{Principal: projectGrantee, Method: auth.MethodSession}, nil)
	rec := getMeOrganizations(handler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the home org", env.Data.Organizations)
	}
	home := env.Data.Organizations[0]
	if home.OrganizationID != org {
		t.Errorf("organization_id = %q, want %q", home.OrganizationID, org)
	}
	if len(home.Grants) != 1 {
		t.Fatalf("grants = %+v, want exactly the one granted scope", home.Grants)
	}
	g := home.Grants[0]
	if g.Role != string(policy.RoleDeveloper) || g.OrganizationID != org || g.ProjectID != "proj_p" {
		t.Errorf("grant = %+v, want developer @ %s/proj_p", g, org)
	}
	if g.EnvironmentID != "" || g.ServiceID != "" {
		t.Errorf("grant carries invented deeper scope ids %+v, want them empty", g)
	}
	if strings.Contains(rec.Body.String(), "proj_q") {
		t.Errorf("response %s mentions a sibling project the principal was never granted", rec.Body.String())
	}
}

// TestMeOrganizationsPolicyForeignGrantIsNeverASecondTenant proves a grant that
// references an organization other than the principal's home org — whether set
// defensively or through a future bug — is dropped by the payload builder and
// never surfaces as a second visible organization. A scoped grant narrows or
// widens authority *within* a tenant; it can never manufacture access to
// another one.
func TestMeOrganizationsPolicyForeignGrantIsNeverASecondTenant(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_acme"
		victimOrg = "org_victim"
	)

	principal := mePrincipal("usr_ada", domain.KindUser, ownOrg, policy.RoleOwner,
		policy.Grant{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: ownOrg, ProjectID: "proj_own"}},
		policy.Grant{Role: policy.RoleOwner, Scope: policy.Scope{OrganizationID: victimOrg, ProjectID: "proj_victim"}},
	)
	handler := meHandlerFor(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil)

	rec := getMeOrganizations(handler, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeMeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the caller's own org", env.Data.Organizations)
	}
	home := env.Data.Organizations[0]
	if home.OrganizationID != ownOrg {
		t.Errorf("organization_id = %q, want %q", home.OrganizationID, ownOrg)
	}
	if len(home.Grants) != 1 {
		t.Fatalf("grants = %+v, want only the home-org grant (the foreign grant dropped)", home.Grants)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) || strings.Contains(body, "proj_victim") {
		t.Errorf("response %s leaked another tenant's identifiers", body)
	}
}
