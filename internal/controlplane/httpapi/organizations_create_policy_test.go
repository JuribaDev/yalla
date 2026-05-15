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

// Policy-matrix coverage for POST /v1/organizations (BE-0051). Where
// organizations_create_test.go proves the endpoint's wire contract, this file
// proves its authorization contract: that action organization.create cannot be
// bypassed by — or made to act for the wrong tenant because of — the
// principal's role, revoked credentials, home organization, or scoped grants.
//
// organization.create is a CapSelf action — every authenticated, enabled
// principal holds it, regardless of role or scope, and the POST
// /v1/organizations route carries no ResourceResolver, so authorization is
// evaluated against the principal's own organization. The risk is therefore
// not "can a viewer call it" (every role can) but "does the endpoint ever
// create an organization for an actor that is not exactly the caller's own".
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, or the engine fails here. createOrganizationHandlerFor,
// postOrganizations, decodeCreateOrganization, fakeOrganizationCreator,
// orgPrincipal, and decodeError are shared with the sibling POST
// /v1/organizations contract suite.

// TestCreateOrganizationPolicyMatrixRoles proves every built-in organization
// role — and a role-less principal authorized purely by a scoped grant — is
// allowed action organization.create and creates an organization whose audit
// actor is exactly the caller's own principal. organization.create is a self
// action no role can be denied, so the matrix is "all allow"; the assertion
// that matters is that the forwarded actor is the caller's own identity, never
// a fabricated, escalated, or cross-tenant one.
func TestCreateOrganizationPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	cases := []struct {
		name   string
		role   policy.Role
		kind   domain.Kind
		grants []policy.Grant
	}{
		{"owner", policy.RoleOwner, domain.KindUser, nil},
		{"admin", policy.RoleAdmin, domain.KindUser, nil},
		{"developer", policy.RoleDeveloper, domain.KindUser, nil},
		{"viewer", policy.RoleViewer, domain.KindUser, nil},
		{"ci", policy.RoleCI, domain.KindServiceAccount, nil},
		{"support", policy.RoleSupport, domain.KindUser, nil},
		// A principal with no organization role at all, authorized purely by a
		// scoped grant: organization.create does not depend on a role, so it is
		// still allowed.
		{"grant-only", policy.Role(""), domain.KindServiceAccount, []policy.Grant{
			{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org, ProjectID: "proj_own"}},
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := policy.Principal{
				ID:             "usr_" + tc.name,
				Kind:           tc.kind,
				OrganizationID: org,
				Role:           tc.role,
				Grants:         tc.grants,
			}

			// At the engine level the action is conferred by the self
			// shortcut — not a role, not a grant — so the resource's
			// organization is irrelevant and can never be a leak.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionOrganizationCreate,
				policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}})
			if !got.Allow || got.Reason != policy.ReasonAllowedSelf {
				t.Errorf("Decide(organization.create) = %+v, want allow via %q", got, policy.ReasonAllowedSelf)
			}

			var captured store.CreateOrganizationInput
			creator := fakeOrganizationCreator{
				org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme, Inc."},
				got: &captured,
			}
			handler := createOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, creator)

			rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme, Inc."}`)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
			}
			env := decodeCreateOrganization(t, rec)
			if env.Data.Organization.OrganizationID != "org_new" {
				t.Errorf("organization_id = %q, want the created row org_new", env.Data.Organization.OrganizationID)
			}
			// The audit actor is the authenticated principal, never a
			// caller-controlled or escalated identity.
			if captured.ActorID != principal.ID || captured.ActorOrgID != org {
				t.Errorf("forwarded actor = %q/%q, want the caller's own principal %q/%q",
					captured.ActorID, captured.ActorOrgID, principal.ID, org)
			}
			if captured.ActorKind == "" {
				t.Errorf("forwarded actor kind is empty, want the authenticated principal's kind")
			}
		})
	}
}

// TestCreateOrganizationPolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth layer
// surfaces to the policy engine as a Disabled principal — is denied action
// organization.create with a stable 403 E_FORBIDDEN, even though every active
// role is allowed it. A revoked or expired key must never be able to create a
// new organization, and the denied body must not echo the principal id or its
// organization back.
func TestCreateOrganizationPolicyRevokedAndExpiredKeys(t *testing.T) {
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
			// The creator must never be reached — authorization fails first.
			creator := fakeOrganizationCreator{
				org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme"},
				got: &store.CreateOrganizationInput{},
			}
			handler := createOrganizationHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)

			rec := postOrganizations(handler, "yk_no_longer_valid", `{"slug":"acme","display_name":"Acme"}`)
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

// TestCreateOrganizationPolicyWrongOrganizationPrincipal proves
// organization.create can never act for another tenant. The POST
// /v1/organizations route carries no path parameter and no ResourceResolver,
// so RequireAuth authorizes against — and the handler forwards as the audit
// actor — the principal's own organization: a principal whose home
// organization is org_intruder creates an organization stamped with
// org_intruder as the actor and never org_victim.
//
// At the engine level the property is pinned directly: organization.create is
// a self action that never reads the resource, so it is allowed regardless of
// the resource's organization (ReasonAllowedSelf) precisely because the
// resource org is irrelevant — it can never become a cross-tenant write.
func TestCreateOrganizationPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_intruder"
		victimOrg = "org_victim"
	)

	principal := policy.Principal{
		ID:             "usr_intruder",
		Kind:           domain.KindUser,
		OrganizationID: ownOrg,
		Role:           policy.RoleOwner,
		Grants: []policy.Grant{
			{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: ownOrg, ProjectID: "proj_own"}},
		},
	}

	var captured store.CreateOrganizationInput
	creator := fakeOrganizationCreator{
		org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme"},
		got: &captured,
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if captured.ActorOrgID != ownOrg || captured.ActorID != "usr_intruder" {
		t.Errorf("forwarded actor = %q/%q, want the caller's own principal usr_intruder/%q",
			captured.ActorID, captured.ActorOrgID, ownOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response %s leaked another tenant's identifiers", body)
	}

	// At the engine level, organization.create is allowed regardless of the
	// resource's organization precisely because it is a self action that never
	// reads the resource — the resource org is irrelevant, so it can never be a
	// cross-tenant write.
	e := policy.NewEngine()
	got := e.Decide(principal, policy.ActionOrganizationCreate,
		policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}})
	if !got.Allow || got.Reason != policy.ReasonAllowedSelf {
		t.Errorf("Decide(organization.create, foreign-org resource) = %+v, want allow via %q", got, policy.ReasonAllowedSelf)
	}
}

// TestCreateOrganizationPolicyGrantContainment proves the scoped grants a POST
// /v1/organizations principal carries are confined by the policy engine — a
// project grant does not reach a sibling project, an environment grant does not
// reach production, a service grant does not reach the parent environment or a
// sibling service — and that those grants neither block nor widen
// organization.create: the action is conferred by the self shortcut, and the
// forwarded audit actor is always exactly the caller's own principal, never
// the deeper or sibling scope a grant references.
func TestCreateOrganizationPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()

	// Project-level grant: developer on proj_p only.
	scopeP := policy.Scope{OrganizationID: org, ProjectID: "proj_p"}
	scopeQ := policy.Scope{OrganizationID: org, ProjectID: "proj_q"}
	projectGrantee := policy.Principal{
		ID: "usr_proj", Kind: domain.KindUser, OrganizationID: org, Role: policy.RoleViewer,
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
		ID: "usr_env", Kind: domain.KindUser, OrganizationID: org, Role: policy.RoleViewer,
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
		ID: "usr_svc", Kind: domain.KindUser, OrganizationID: org, Role: policy.RoleViewer,
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

	// The project-scoped principal can still create an organization — the
	// action is conferred by the self shortcut, not the grant — and the
	// forwarded audit actor is exactly the caller's own principal: a grant
	// referencing proj_p never widens the actor to that deeper scope, and a
	// sibling project the principal was never granted never appears.
	var captured store.CreateOrganizationInput
	creator := fakeOrganizationCreator{
		org: store.Organization{ID: "org_new", Slug: "acme", DisplayName: "Acme"},
		got: &captured,
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodSession}, nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", `{"slug":"acme","display_name":"Acme"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if captured.ActorID != "usr_proj" || captured.ActorOrgID != org {
		t.Errorf("forwarded actor = %q/%q, want the caller's own principal usr_proj/%q — a grant must not widen the actor",
			captured.ActorID, captured.ActorOrgID, org)
	}
	if body := rec.Body.String(); strings.Contains(body, "proj_p") || strings.Contains(body, "proj_q") {
		t.Errorf("response %s mentions a project scope organization.create never acts on", body)
	}
}
