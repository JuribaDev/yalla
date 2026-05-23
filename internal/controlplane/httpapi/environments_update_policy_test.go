package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for PATCH /v1/environments/{environment_id}
// (BE-0159). Where environments_update_test.go proves the endpoint's
// wire contract (BE-0157), this file proves its authorization
// contract: that action environment.update cannot be bypassed by — or
// persist a mutation because of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries the environmentIDResolver (routes.go), which
// builds the policy resource from the principal's HOME organization
// id and the {environment_id} PATH parameter — and CRUCIALLY pins NO
// ProjectID leg, because the bare top-level path carries no parent
// project_id. That is the load-bearing distinction from the
// parent-scoped projects/environments/create matrix
// (projects_environments_create_policy_test.go): every scoped grant
// in the engine pins a ProjectID, and the engine's covers() rule is
// one-way (a grant scope that pins ProjectID cannot cover a resource
// scope that does not). The consequence is that ALL project-,
// environment-, and service-scoped grants are denied at the boundary
// by ReasonDeniedOutOfScope — even an environment-scoped Admin grant
// naming THIS environment's id, because the grant scope's pinned
// ProjectID cannot cover a resource scope without one. Principals
// whose only access is a scoped grant cannot reach this endpoint at
// all; this route is reserved for org-wide write roles and org-wide
// grants.
//
// environment.update requires CapWrite (catalog.go:
// ActionEnvironmentUpdate -> CapWrite), the same capability class as
// project.create / project.update / environment.create / service.create.
// The role matrix for a principal acting on its own organization
// therefore splits along the write capability class: Owner / Admin /
// Developer hold CapWrite and are allowed (ReasonAllowedByRole);
// Viewer / CI / Support do not hold CapWrite and are denied
// (ReasonDeniedNoCapability) — CI holds CapDeploy (the deploy
// capability is for service lifecycle and rollouts, not desired-state
// mutation), so a CI key cannot rename an environment even within
// its home tenant. This is the load-bearing distinction from the
// environment.read matrix (environments_get_policy_test.go), which
// is "all six roles allow": three roles deny here at the role
// boundary, and — crucially — the engine's cross-tenant support
// exception is gated on `required == CapRead || required ==
// CapSupport`, so CapWrite is OUTSIDE that exception. Privileged
// Yalla support that needs to mutate a customer's environment must
// go through explicit break-glass admin tooling, not this
// customer-facing route.
//
// environments rows store no credential material — only structural
// identifiers, a slug, a display name, an optimistic-concurrency
// version, and lifecycle timestamps. The projectEnvironmentOf
// projection has no value-redaction chokepoint to anchor a deny-path
// leak guard on; the load-bearing needle is the existence of the
// environment row itself (and the id / slug / display name a denied
// principal must not learn, plus the caller-supplied request-body
// fields). Tenant-leakage and no-write invariants apply: a denied
// response never echoes the seeded environment id / slug / display
// name, the foreign tenant's id, the canonical project's id, or the
// caller-supplied patch body; and the updater MUST never run on any
// deny path — a scoped key denied on the wire cannot have mutated a
// row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, environmentIDResolver, or the engine fails
// here. updateEnvironmentHandlerFor, patchEnvironment,
// decodeUpdateEnvironment, fakeEnvironmentUpdater, orgPrincipal,
// seedEnvironmentWire, and decodeError are shared with the
// update-environment contract suite (environments_update_test.go)
// and the wider httpapi test fixtures; this file adds no scaffolding
// beyond the small fixture builders below.

// canonicalUpdateEnvForMatrix is the row every test in this file
// would receive back from the updater on an allow path. Its ids /
// slug / display name are deliberately distinct from canonicalEnvForGet
// (used by environments_test.go), canonicalGetEnvForMatrix (used by
// environments_get_policy_test.go), and canonicalUpdatedEnv (used by
// environments_update_test.go) so the matrices cannot accidentally
// share fixture state through a future shared fake, and they are
// deliberately recognisable so deny-path leak guards can needle for
// them; allow-path assertions compare against the same canonical
// values.
func canonicalUpdateEnvForMatrix(orgID, projectID string) store.Environment {
	created := time.Date(2026, 1, 13, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 11, 12, 13, 0, time.UTC)
	return seedEnvironmentWire("env_matrix_patch", orgID, projectID, "patch-matrix", "Patch Matrix v2", 17, created, updated)
}

// The canonical PATCH request body every test in this file shares.
// It mutates display_name only (single non-nil patch field), which
// is the minimum input the store layer accepts ("a patch that names
// no field is a 400") and the simplest shape to exercise wire-level
// redaction. The distinctive display name "Patch Matrix Renamed" is
// deliberately recognisable so deny-path leak guards can needle for
// it independently of the canonical row.
const (
	canonicalUpdateEnvDisplayName = "Patch Matrix Renamed"
	canonicalUpdateEnvBody        = `{"display_name":"Patch Matrix Renamed"}`
)

// updateEnvDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical environment, its
// parent project, or the caller-supplied request-body fields. A
// denied response that accidentally rendered any of these fails the
// test — a denied request-body field would mean the handler echoed
// the request after policy denial (a tenant-boundary smell), and a
// denied canonical-row field would mean the updater ran and the
// response leaked its output even though the wire said 403. The
// quoted forms catch a case-collapsing renderer regression. The
// environments table carries no credential material at all, so
// unlike the project_variables matrix there is no secret plaintext
// to anchor.
func updateEnvDenyBodyLeak(body string) bool {
	needles := []string{
		"env_matrix_patch",
		"\"patch-matrix\"",
		"\"Patch Matrix v2\"",
		"\"" + canonicalUpdateEnvDisplayName + "\"",
		"prj_patch_matrix_parent",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestUpdateEnvironmentPolicyMatrixRoles drives every built-in role
// through the production request path. CapWrite splits the matrix:
// Owner / Admin / Developer (own org) are allowed; Viewer / CI /
// Support (own org) are denied. The assertions that matter for allow
// rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the updater is reached with the principal's
// own home organization id, the {environment_id} path parameter, AND
// the principal id (so the audit record names the actor verbatim),
// the decoded patch body, and the response is a stable 200
// yalla.output.v1 carrying the canonical updated environment. For
// deny rows, the assertions are 403 yalla.error.v1, the stable
// reason on the wire, the updater MUST NEVER run (no row mutated in
// the background), and the denied body must not echo the canonical
// environment, the parent project, or the caller-supplied
// request-body fields.
func TestUpdateEnvironmentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_patch_matrix_parent"
	)
	env := canonicalUpdateEnvForMatrix(org, project)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: env.ID},
	}

	cases := []struct {
		name   string
		role   policy.Role
		kind   domain.Kind
		allow  bool
		reason policy.Reason
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"admin", policy.RoleAdmin, domain.KindUser, true, policy.ReasonAllowedByRole},
		{"developer", policy.RoleDeveloper, domain.KindUser, true, policy.ReasonAllowedByRole},
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

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. The
			// allow rows resolve via ReasonAllowedByRole on the
			// SAME-tenant environment resource; the deny rows
			// resolve via ReasonDeniedNoCapability because Viewer /
			// CI / Support hold CapRead (and CI CapDeploy) but not
			// CapWrite. (The cross-tenant Support deny is pinned
			// separately in TestUpdateEnvironmentPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentUpdate, envResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.update) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.update) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.UpdateEnvironmentInput
			callCount := 0
			updater := fakeEnvironmentUpdater{
				env:       env,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := updateEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, updater)
			rec := patchEnvironment(handler, env.ID, "a-valid-token", canonicalUpdateEnvBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("updater call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("updater received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.EnvironmentID != env.ID {
					t.Errorf("updater received environment id %q, want the path parameter %q",
						captured.EnvironmentID, env.ID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("updater received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.DisplayName == nil || *captured.DisplayName != canonicalUpdateEnvDisplayName {
					t.Errorf("updater received display_name = %v, want pointer to %q",
						captured.DisplayName, canonicalUpdateEnvDisplayName)
				}
				if captured.Slug != nil {
					t.Errorf("updater received slug = %v, want nil (field omitted in body)", captured.Slug)
				}
				payload := decodeUpdateEnvironment(t, rec)
				if payload.Data.Environment.ID != env.ID ||
					payload.Data.Environment.Slug != env.Slug ||
					payload.Data.Environment.DisplayName != env.DisplayName ||
					payload.Data.Environment.OrganizationID != env.OrganizationID ||
					payload.Data.Environment.ProjectID != env.ProjectID ||
					payload.Data.Environment.Version != env.Version {
					t.Errorf("environment = %+v, want (%s, %s, %s, org=%s, project=%s, v=%d)",
						payload.Data.Environment, env.ID, env.Slug, env.DisplayName, env.OrganizationID, env.ProjectID, env.Version)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(tc.reason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, tc.reason)
			}
			if callCount != 0 {
				t.Errorf("updater was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.EnvironmentID != "" {
				t.Errorf("updater captured org=%q env=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.EnvironmentID)
			}
			if body := rec.Body.String(); updateEnvDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical environment, parent project, or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestUpdateEnvironmentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action environment.update with a
// stable 403 E_FORBIDDEN, even when the underlying role would have
// allowed it. A revoked or expired credential must never be able to
// mutate an environment of the organization it once had access to,
// the updater must never run, and the denied body must never echo
// the principal id, the organization id, the path-supplied
// environment id, the caller-supplied request-body fields, or any
// seeded environment data.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.update; Disabled is the only thing in the way and must
// be load-bearing. The case names mirror PRD BE-0159 ("revoked key,
// expired key").
func TestUpdateEnvironmentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_patch_matrix_parent"
	)
	env := canonicalUpdateEnvForMatrix(org, project)

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

			principal := orgPrincipal(tc.id, org, policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var captured store.UpdateEnvironmentInput
			callCount := 0
			updater := fakeEnvironmentUpdater{
				env:       env,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := updateEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, updater)
			rec := patchEnvironment(handler, env.ID, "yk_no_longer_valid", canonicalUpdateEnvBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.EnvironmentID != "" {
				t.Errorf("updater was reached (calls=%d org=%q env=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.EnvironmentID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				updateEnvDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, request body, or seeded environment data", body)
			}
		})
	}
}

// TestUpdateEnvironmentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.update on the env-id route.
// As with environment.read on the same route, the resource org id is
// taken from the PRINCIPAL'S home org — the {environment_id} path
// parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PATCH /v1/environments/
//     {env_victim} with a valid Owner token reaches the engine with
//     a same-tenant resource ({org_attacker, env_victim}) — allowed
//     by the role at CapWrite — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the
//     foreign environment id. A production *store.EnvironmentService
//     (which combines organization_id and environment_id in its
//     WHERE clause) cannot match a row that belongs to another
//     tenant, so the request surfaces as a deterministic 404
//     E_NOT_FOUND, never disguised as a 200 with foreign data and
//     never as a 403 that would confirm existence. The body must
//     never echo the foreign org id even though no wire input could
//     place it there, because the persistence layer must not leak
//     foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the environment.read cross-
//     tenant property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but update DOES NOT. Pinning that
//     engine verdict here means the eventual scoped variant inherits
//     a working cross-tenant deny for environment.update across
//     every role, and a future catalog change that downgraded
//     environment.update into the support cross-tenant exception
//     (or widened the exception) would fail here before it could
//     regress a real customer.
func TestUpdateEnvironmentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_patch"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PATCH
	// /v1/environments/{env_victim} with a valid Owner token. The
	// fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, environmentID) pair
	// does not match a row, so a principal whose home org is
	// org_attacker patching an environment that belongs to org_victim
	// hits the fake with (org_attacker, env_victim_patch) and gets
	// NotFound. The assertions that matter are structural: the
	// updater is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentUpdater could not have mutated the
	// victim's environment regardless of database state. The denied
	// body must never echo the victim's org id.
	var captured store.UpdateEnvironmentInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	updater := fakeEnvironmentUpdater{
		err:       apierr.NotFound("environment", foreignEnvID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, updater)
	rec := patchEnvironment(handler, foreignEnvID, "a-valid-token", canonicalUpdateEnvBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("updater call count = %d, want 1 — the updater runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign environment id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("updater received org id %q, want the attacker's home org %q — the updater must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.EnvironmentID != foreignEnvID {
		t.Errorf("updater received environment id %q, want the path parameter %q",
			captured.EnvironmentID, foreignEnvID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. environment.update
	// is CapWrite, which is OUTSIDE the engine clause `CapSupport &&
	// (CapRead || CapSupport)` — so EVERY role, including Support,
	// is denied cross-tenant.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: victimOrg, EnvironmentID: foreignEnvID},
	}
	crossTenantDeny := []struct {
		role policy.Role
		name string
	}{
		{policy.RoleOwner, "owner"},
		{policy.RoleAdmin, "admin"},
		{policy.RoleDeveloper, "developer"},
		{policy.RoleViewer, "viewer"},
		{policy.RoleCI, "ci"},
		{policy.RoleSupport, "support"},
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionEnvironmentUpdate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(environment.update, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestUpdateEnvironmentPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, environment grant not implying production, service grant
// shielding parent-level resources — are pinned against the engine
// at their natural scopes (a project resource, an env resource, a
// service resource), then tied back to the wire by proving that ALL
// three scoped key types are denied OutOfScope against THIS endpoint
// (even when the grant names the target environment's own project
// or the target environment's own id), while an organization-level
// Admin grant — which pins no ProjectID and covers any resource
// scope in the same org — is allowed end-to-end.
//
//   - A project-level Admin grant naming THIS environment's parent
//     project CANNOT authorize the update through this route — the
//     grant scope pins ProjectID and the resource scope does not,
//     so covers() returns false. (The same key DOES authorize
//     environment.create / environment.update at a project resource
//     — that is the parent-scoped route's job — and the engine pins
//     that property here so the load-bearing distinction between
//     the two routes' authorization surfaces is explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a project resource.
//   - An environment-level Admin grant naming THIS environment's id
//     CANNOT authorize the update either, because the grant scope
//     pins ProjectID and the resource scope does not. (The grant
//     DOES authorize env.write at the env resource — pinned at the
//     engine — but not environment.update on this route.) An env
//     grant on staging also does not imply env.write on production
//     at the engine.
//   - A service-level Admin grant CANNOT either, and at the engine
//     a service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level Admin grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because environment.update is CapWrite
//     and Admin holds CapWrite — is allowed via ReasonAllowedByGrant.
//   - An organization-level VIEWER grant covers the resource but
//     confers no write capability; environment.update is denied via
//     ReasonDeniedNoCapability. This is the load-bearing distinction
//     from the environment.read grant matrix where an org-level
//     Viewer is allowed.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the updater is never reached (so a production
// store could never have mutated a row in the background), and the
// body never echoes the canonical environment's identifiers, the
// parent project's id, or the caller-supplied patch body.
func TestUpdateEnvironmentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_patch_matrix_parent"
	)
	env := canonicalUpdateEnvForMatrix(org, project)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO ProjectID.
	// Every covers() check below against this resource is the engine-
	// level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: env.ID},
	}

	// Project-level grant: admin on the parent project. Admin
	// confers CapWrite at the project scope, which would normally be
	// enough for environment.update on a project resource — and the
	// engine confirms that at a project resource, so the load-bearing
	// distinction between this route and a project-scoped route is
	// explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_patch_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.update) at the parent project for the target-project admin grantee = %+v, want allow via %q — a project-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at a sibling project for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from any parent-scoped route.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a project resource (which the parent-
	// scoped route would target), environment.update must fail with
	// ReasonDeniedNoCapability — a viewer grant does not widen to a
	// write action even when its scope contains the resource.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.update) at a project resource for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property
	// is pinned at the engine against env resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeStaging}); !got.Allow {
		t.Errorf("env.write on the granted staging environment = %+v, want allow", got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// env-staging grant is denied OutOfScope at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (env_matrix_patch itself) is ALSO denied
	// OutOfScope on this route, because the grant scope still pins
	// ProjectID and the resource scope does not — the env_id alone
	// is not enough to authorize a top-level update through this
	// route. This is the load-bearing property that locks down the
	// env-id route: an environment grant alone does not authorize
	// mutations through it.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env.ID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// service grant is denied OutOfScope at the engine.
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// target environment via THIS route is a 403 with the stable
	// out-of-scope reason, the updater is never reached (so a
	// production store could never have mutated a row in the
	// background), and the body never echoes the canonical
	// environment's identifiers or the parent project's id. This is
	// the property that confines a project-scoped key to a
	// parent-scoped route.
	var projCaptured store.UpdateEnvironmentInput
	projCallCount := 0
	projUpdater := fakeEnvironmentUpdater{
		env:       env, // would be returned if updater ran — leak guard catches it
		gotInput:  &projCaptured,
		callCount: &projCallCount,
	}
	projHandler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projUpdater)
	projRec := patchEnvironment(projHandler, env.ID, "yk_proj_admin_scoped", canonicalUpdateEnvBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-id route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projCaptured.OrganizationID != "" || projCaptured.EnvironmentID != "" {
		t.Errorf("updater was reached (calls=%d org=%q env=%q) for a project-scoped grantee; it must never run",
			projCallCount, projCaptured.OrganizationID, projCaptured.EnvironmentID)
	}
	if body := projRec.Body.String(); updateEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, parent project, or caller-supplied request body: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME
	// environment id the path names — hitting the env-id route is a
	// 403, the updater is never reached, and the body never echoes
	// the canonical environment. This is the load-bearing property
	// that locks down the env-id route: an environment grant alone
	// does not authorize mutations through it.
	var envCaptured store.UpdateEnvironmentInput
	envCallCount := 0
	envUpdater := fakeEnvironmentUpdater{
		env:       env,
		gotInput:  &envCaptured,
		callCount: &envCallCount,
	}
	envHandler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envUpdater)
	envRec := patchEnvironment(envHandler, env.ID, "yk_env_scoped", canonicalUpdateEnvBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-id route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envCaptured.OrganizationID != "" || envCaptured.EnvironmentID != "" {
		t.Errorf("updater was reached (calls=%d org=%q env=%q) for an env-scoped grantee; it must never run",
			envCallCount, envCaptured.OrganizationID, envCaptured.EnvironmentID)
	}
	if body := envRec.Body.String(); updateEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, parent project, or caller-supplied request body: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the env-id
	// route is a 403, the updater is never reached, and the body
	// never echoes parent-level identifiers — the "service grant
	// does not expose parent-level secrets or unrelated services"
	// criterion tied to the wire on this route.
	var svcCaptured store.UpdateEnvironmentInput
	svcCallCount := 0
	svcUpdater := fakeEnvironmentUpdater{
		env:       env,
		gotInput:  &svcCaptured,
		callCount: &svcCallCount,
	}
	svcHandler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcUpdater)
	svcRec := patchEnvironment(svcHandler, env.ID, "yk_svc_scoped", canonicalUpdateEnvBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-id route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcCaptured.OrganizationID != "" || svcCaptured.EnvironmentID != "" {
		t.Errorf("updater was reached (calls=%d org=%q env=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcCaptured.OrganizationID, svcCaptured.EnvironmentID)
	}
	if body := svcRec.Body.String(); updateEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, parent project, or caller-supplied request body: %s", body)
	}

	// An organization-level Admin grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because environment.update is CapWrite
	// and Admin holds CapWrite — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the
	// updater reached on the principal's home org id, the path env
	// id, and the principal id. This locks the CapWrite requirement
	// against the grant path so a future catalog change that
	// upgraded environment.update above CapWrite would fail here
	// (silently denying every org-level Admin grantee) before it
	// could regress a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.update) at the env-id route's resource scope for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.UpdateEnvironmentInput
	orgCallCount := 0
	orgUpdater := fakeEnvironmentUpdater{
		env:       env,
		gotInput:  &orgCaptured,
		callCount: &orgCallCount,
	}
	orgHandler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgUpdater)
	allowedRec := patchEnvironment(orgHandler, env.ID, "yk_org_admin", canonicalUpdateEnvBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeUpdateEnvironment(t, allowedRec)
	if allowedPayload.Data.Environment.ID != env.ID ||
		allowedPayload.Data.Environment.Slug != env.Slug ||
		allowedPayload.Data.Environment.OrganizationID != env.OrganizationID ||
		allowedPayload.Data.Environment.ProjectID != env.ProjectID ||
		allowedPayload.Data.Environment.Version != env.Version {
		t.Errorf("environment = %+v, want (%s, %s, org=%s, project=%s, v=%d)",
			allowedPayload.Data.Environment, env.ID, env.Slug, env.OrganizationID, env.ProjectID, env.Version)
	}
	if orgCallCount != 1 {
		t.Errorf("updater call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("updater received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.EnvironmentID != env.ID {
		t.Errorf("updater received environment id %q, want the path parameter %q",
			orgCaptured.EnvironmentID, env.ID)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID {
		t.Errorf("updater received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgAdminGrantee.ID)
	}
	if orgCaptured.DisplayName == nil || *orgCaptured.DisplayName != canonicalUpdateEnvDisplayName {
		t.Errorf("updater received display_name = %v, want pointer to %q",
			orgCaptured.DisplayName, canonicalUpdateEnvDisplayName)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; environment.update must be denied
	// via ReasonDeniedNoCapability even though the grant scope is
	// the whole org. This is the load-bearing distinction from the
	// environment.read grant matrix: an org-level Viewer is
	// ALLOWED for read but DENIED for update.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvironmentUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.update) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to update an environment in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in TestUpdateEnvironmentPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (environment.update is OUTSIDE the support
	// cross-tenant exception regardless, but the assertion here is
	// structural: a scoped key's home org must match the grant
	// scope's org or the engine refuses to consider the grant at
	// all.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentUpdate, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.update) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
