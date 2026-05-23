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

// Policy-matrix coverage for GET /v1/organizations/{org_id}/usage
// (BE-0102). Where usage_test.go proves the endpoint's wire contract, this
// file proves its authorization contract: that action limits.read — the
// same action that gates GET /v1/organizations/{org_id}/limits — cannot
// be bypassed by, or leak data because of, the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes against
// the organization the {org_id} path NAMES — not merely the principal's
// home organization. So a cross-tenant {org_id} must be a deterministic 403
// before the handler runs (with the documented support exception), while
// an {org_id} naming the caller's own organization is allowed by any role
// or by a grant whose scope covers the organization root — never by a
// deeper-scoped grant.
//
// limits.read requires CapRead (catalog.go: ActionLimitsRead->CapRead).
// All six built-in roles hold CapRead, so the role matrix for a principal
// reading its own organization is "all allow". The engine's cross-tenant
// clause permits `required == CapRead || required == CapSupport` through
// the Support exception, so a Support principal reading another tenant's
// usage is allowed via ReasonAllowedBySupport — this is the load-bearing
// difference from a CapAdmin endpoint (e.g. keys.read) where the Support
// exception does not fire, and the matrix mirrors limits.read because both
// endpoints map to the same action.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the action
// catalog, the organizationIDResolver, or the engine fails here.
// listUsageHandlerFor, usageActorIdentity, getUsage, fakeUsageReader,
// decodeUsageList, orgPrincipal, and decodeError are shared with the
// sibling GET /v1/organizations/{org_id}/usage contract suite
// (usage_test.go) and the wider httpapi test fixtures; this file adds no
// scaffolding beyond the small fixture builder below.

// seededUsage builds the canonical "projects=3/10 hard organization,
// domains=5 unconstrained" fixture this file uses throughout. Keeping the
// fixture in one place keeps the matrix-mode assertions concise (every
// allowed test exercises the same projection — including the optional
// nested limit object — and every denied test pins the same redaction
// invariants against the same data).
func seededUsage() []store.OrganizationResourceUsage {
	mode := store.EnforcementModeHard
	scope := store.QuotaScopeOrganization
	limit := int64(10)
	return []store.OrganizationResourceUsage{
		{
			Resource:        store.QuotaResourceProjects,
			UsedValue:       3,
			LimitValue:      &limit,
			EnforcementMode: &mode,
			Scope:           &scope,
		},
		{
			Resource:  store.QuotaResourceDomains,
			UsedValue: 5,
		},
	}
}

// TestListUsagePolicyMatrixRoles drives every built-in role through the
// production request path against an {org_id} that names its own home
// organization. All six built-in roles hold CapRead, so the matrix is "all
// allow"; the assertions that matter are that the verdict is reached
// through the role (ReasonAllowedByRole) and that the reader is reached
// with the {org_id} the path named, never a fabricated, escalated, or
// sibling tenant. The response carries the seeded usage rows unchanged,
// in the order the reader returned them — including the nullable limit
// projection, which is the load-bearing wire-shape difference from the
// limits endpoint.
func TestListUsagePolicyMatrixRoles(t *testing.T) {
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

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine assertion: the role decision against the
			// organization-root scope the resolver emits is the verdict the
			// matrix names. The {org_id} path parameter is the only input
			// the engine sees for this route.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionLimitsRead, orgRoot)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(limits.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var seen string
			reader := fakeUsageReader{usage: seededUsage(), got: &seen}
			handler := listUsageHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getUsage(handler, org, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeUsageList(t, rec.Body.Bytes())
			if len(env.Data.Usage) != 2 {
				t.Fatalf("usage len = %d, want 2 (got %+v)", len(env.Data.Usage), env.Data.Usage)
			}
			projects := env.Data.Usage[0]
			if projects.Resource != "projects" || projects.UsedValue != 3 {
				t.Errorf("[0] = %+v, want projects used_value=3", projects)
			}
			if projects.Limit == nil ||
				projects.Limit.LimitValue != 10 ||
				projects.Limit.EnforcementMode != "hard" ||
				projects.Limit.Source != "organization" {
				t.Errorf("[0].limit = %+v, want {10, hard, organization}", projects.Limit)
			}
			domains := env.Data.Usage[1]
			if domains.Resource != "domains" || domains.UsedValue != 5 {
				t.Errorf("[1] = %+v, want domains used_value=5", domains)
			}
			if domains.Limit != nil {
				t.Errorf("[1].limit = %+v, want nil for an unconstrained resource", domains.Limit)
			}
			if seen != org {
				t.Errorf("reader received organization id %q, want the path parameter %q",
					seen, org)
			}
		})
	}
}

// TestListUsagePolicyRevokedAndExpiredKeys proves a principal whose
// credential has been revoked or has expired — both of which the auth
// layer surfaces to the policy engine as a Disabled principal — is denied
// action limits.read with a stable 403 E_FORBIDDEN, even when the
// underlying role would have allowed it. A revoked or expired credential
// must never be able to enumerate usage of the organization it once had
// access to, the reader must never run, and the denied body must never
// echo the principal id, the organization id, or any seeded usage data.
func TestListUsagePolicyRevokedAndExpiredKeys(t *testing.T) {
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
			// limits.read; Disabled is the only thing in the way and must
			// be load-bearing.
			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var seen string
			reader := fakeUsageReader{usage: seededUsage(), got: &seen}
			handler := listUsageHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getUsage(handler, "org_acme", "yk_no_longer_valid")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if seen != "" {
				t.Errorf("reader was reached with org=%q for a disabled principal; it must never run", seen)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, "org_acme") ||
				strings.Contains(body, "projects") ||
				strings.Contains(body, "domains") ||
				strings.Contains(body, "\"hard\"") ||
				strings.Contains(body, "\"organization\"") {
				t.Errorf("error body %s leaked the principal id, organization, or seeded usage data", body)
			}
		})
	}
}

// TestListUsagePolicyWrongOrganizationPrincipal proves limits.read is
// confined to the caller's own tenant — except for the documented Support
// exception. This route carries the organizationIDResolver, so RequireAuth
// authorizes against the organization the {org_id} path names:
//
//   - A non-support owner of org_attacker reading usage of org_victim is
//     a deterministic 403 ReasonDeniedCrossTenant; the reader is never
//     reached, and the denied body never echoes the foreign organization
//     or any of its usage rows.
//   - A Support principal of org_yalla performing the same cross-tenant
//     read IS allowed (engine clause: CapRead within the cross-tenant
//     branch) via ReasonAllowedBySupport, and receives the usage of the
//     organization the path named. This mirrors the limits.read matrix
//     exactly because both endpoints map to the same action and Support
//     is the only role that crosses the tenant boundary for a CapRead
//     read.
//
// The engine verdict is pinned alongside the wire verdict for both
// principals so a regression in either layer fails here, and a downgrade
// of the catalog's `CapRead` to a higher capability would break both the
// role matrix and this exception.
func TestListUsagePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)
	mode := store.EnforcementModeHard
	scope := store.QuotaScopeOrganization
	limit := int64(42)
	victimUsage := []store.OrganizationResourceUsage{{
		Resource:        store.QuotaResourceProjects,
		UsedValue:       7,
		LimitValue:      &limit,
		EnforcementMode: &mode,
		Scope:           &scope,
	}}

	// Non-support cross-tenant principal: owner of org_attacker reading
	// usage of org_victim is a deterministic 403, the reader never
	// reached, and the body carries no cross-tenant id or usage data.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderSeen string
	intruderReader := fakeUsageReader{usage: victimUsage, got: &intruderSeen}
	intruderHandler := listUsageHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderReader)

	rec := getUsage(intruderHandler, victimOrg, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderSeen != "" {
		t.Errorf("reader was reached with org=%q for a cross-tenant request; it must never run",
			intruderSeen)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) ||
		strings.Contains(body, "\"42\"") || strings.Contains(body, ":42") ||
		strings.Contains(body, "used_value") {
		t.Errorf("error body %s echoed the cross-tenant organization or seeded usage data", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so the
	// resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionLimitsRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(limits.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support IS a cross-tenant exception for CapRead actions: the engine
	// clause `roleCaps.has(CapSupport) && (required == CapRead || required
	// == CapSupport)` reaches limits.read because the catalog maps it to
	// CapRead. So a Support principal reading another tenant's usage is
	// allowed via ReasonAllowedBySupport, and the handler returns 200 with
	// the usage of the organization the path named. This is the same
	// distinguishing property limits.read carries — both endpoints share
	// the action and the exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionLimitsRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(limits.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}

	var supportSeen string
	supportReader := fakeUsageReader{usage: victimUsage, got: &supportSeen}
	supportHandler := listUsageHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)
	supportRec := getUsage(supportHandler, victimOrg, "a-valid-support-token")
	if supportRec.Code != http.StatusOK {
		t.Fatalf("support status = %d, want 200 — support is allowed limits.read cross-tenant; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportPayload := decodeUsageList(t, supportRec.Body.Bytes())
	if len(supportPayload.Data.Usage) != 1 ||
		supportPayload.Data.Usage[0].Resource != "projects" ||
		supportPayload.Data.Usage[0].UsedValue != 7 {
		t.Errorf("support payload = %+v, want exactly the victim org's seeded projects used_value=7",
			supportPayload.Data.Usage)
	}
	if supportPayload.Data.Usage[0].Limit == nil ||
		supportPayload.Data.Usage[0].Limit.LimitValue != 42 {
		t.Errorf("support payload limit = %+v, want limit_value=42", supportPayload.Data.Usage[0].Limit)
	}
	if supportSeen != victimOrg {
		t.Errorf("support reader received organization id %q, want the path parameter %q",
			supportSeen, victimOrg)
	}
}

// TestListUsagePolicyGrantContainment proves scoped grants cannot be
// widened past the scope they were issued for. A scoped API key is
// authorized purely by its grants (it carries no organization role); the
// engine confines those grants — a project grant does not reach a sibling
// project, an environment grant does not reach production, a service grant
// does not reach the parent environment or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}/usage: limits.read is
// evaluated against the organization-root scope the {org_id} path names.
// A project/environment/service-scoped grant — even an Admin grant — does
// not cover that scope (covers() is one-way: a more-specific scope cannot
// reach a broader resource), not even for the key's own organization. So
// a scoped key holding only a project grant is denied the endpoint for
// its own {org_id} with the stable ReasonDeniedOutOfScope, while a key
// holding an organization-level grant — even a Viewer grant, since
// limits.read is CapRead — is allowed it (ReasonAllowedByGrant). A scoped
// grant narrows authority within a tenant; it can never be escalated to a
// broader usage read.
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied back
// to the wire by proving the project grantee is denied the endpoint at
// its own {org_id}, while an organization-scoped Viewer grantee is
// allowed it.
func TestListUsagePolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Sibling-project
	// containment is pinned via the project-update action so the grant has
	// the relevant capability at the relevant scope.
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

	// Service-level grant: admin on a single service only. The grant must
	// not expose parent-level secrets (env-write on the parent
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

	// GET /v1/organizations/{org_id}/usage reads against the organization
	// root the {org_id} path names. A project/environment/service-scoped
	// admin grant does NOT cover that scope — not even for the key's own
	// organization — so each scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to an
	// organization-wide usage read, and the reader never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionLimitsRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionLimitsRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.read) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionLimitsRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(limits.read) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Tie back at the wire: the project-scoped grantee reading usage of
	// its OWN organization is a 403 with the stable out-of-scope reason,
	// the reader is never reached, and the body never echoes the seeded
	// usage data. This is the property that makes the policy boundary —
	// not the persistence boundary — the structural place a scoped key is
	// denied broader visibility.
	var projectSeen string
	projectReader := fakeUsageReader{usage: seededUsage(), got: &projectSeen}
	projectHandler := listUsageHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getUsage(projectHandler, org, "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectSeen != "" {
		t.Errorf("reader was reached with org=%q for an out-of-scope grantee; it must never run",
			projectSeen)
	}
	if body := rec.Body.String(); strings.Contains(body, "projects") ||
		strings.Contains(body, "domains") ||
		strings.Contains(body, "used_value") ||
		strings.Contains(body, "\"hard\"") {
		t.Errorf("denied response leaks the seeded usage data: %s", body)
	}

	// An organization-level Viewer grant DOES cover the org-root scope
	// and — because limits.read is CapRead and Viewer holds CapRead — is
	// allowed via ReasonAllowedByGrant. The same key is end-to-end allowed
	// at the wire, with the reader reached on the {org_id} parameter.
	// This locks the CapRead requirement against the grant path so a
	// future catalog change that downgraded an org-level Viewer below
	// CapRead would fail here.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionLimitsRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(limits.read) for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgSeen string
	orgReader := fakeUsageReader{usage: seededUsage(), got: &orgSeen}
	orgHandler := listUsageHandlerFor(
		auth.Identity{Principal: orgViewer, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getUsage(orgHandler, org, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeUsageList(t, allowedRec.Body.Bytes())
	if len(allowedPayload.Data.Usage) != 2 ||
		allowedPayload.Data.Usage[0].Resource != "projects" ||
		allowedPayload.Data.Usage[0].UsedValue != 3 ||
		allowedPayload.Data.Usage[0].Limit == nil ||
		allowedPayload.Data.Usage[0].Limit.LimitValue != 10 {
		t.Errorf("usage = %+v, want the seeded projects=3/10 + domains=5 unconstrained pair",
			allowedPayload.Data.Usage)
	}
	if orgSeen != org {
		t.Errorf("reader received organization id %q, want the path parameter %q",
			orgSeen, org)
	}

	// And the same project-scoped grantee against a foreign {org_id} is
	// still denied — a scoped key cannot be smuggled across tenants by
	// fabricating a path parameter to enumerate somebody else's usage.
	// The cross-tenant guard fires first, since the scope's organization
	// id no longer matches the principal's own.
	siblingOrgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: "org_sibling"}}
	if got := e.Decide(projectGrantee, policy.ActionLimitsRead, siblingOrgRoot); got.Allow {
		t.Errorf("Decide(limits.read, foreign org) for a project-scoped key = %+v, want deny", got)
	}
	foreignHandler := listUsageHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil,
		fakeUsageReader{usage: seededUsage()})
	foreignRec := getUsage(foreignHandler, "org_sibling", "yk_proj_scoped")
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
