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

// Policy-matrix coverage for POST /v1/environments/{environment_id}/clone
// (BE-0165). Where environments_clone_test.go proves the endpoint's
// wire contract (BE-0163), this file proves its authorization
// contract: that action environment.create cannot be bypassed by — or
// persist a new environment row because of — the principal's role,
// revoked credentials, home organization, or scoped grants.
//
// The route carries the environmentIDResolver (routes.go), which
// builds the policy resource from the principal's HOME organization
// id and the {environment_id} PATH parameter (the SOURCE environment
// the clone reads its project_id from) — and CRUCIALLY pins NO
// ProjectID leg, because the bare top-level path carries no parent
// project_id. That is the load-bearing distinction from a parent-
// scoped create (POST /v1/projects/{project_id}/environments,
// authorized through projectIDResolver against a resource scope that
// DOES pin ProjectID): every scoped grant in the engine pins a
// ProjectID, and the engine's covers() rule is one-way (a grant
// scope that pins ProjectID cannot cover a resource scope that does
// not). The consequence is that ALL project-, environment-, and
// service-scoped grants are denied at the boundary by
// ReasonDeniedOutOfScope on this route — even a project-scoped Admin
// grant naming the source environment's OWN parent project, and even
// an environment-scoped Admin grant naming the source environment's
// OWN id. Principals whose only access is a scoped grant cannot
// clone an environment through this top-level route at all; they
// must use the parent-scoped POST
// /v1/projects/{project_id}/environments route instead. This is the
// same load-bearing property the bare-id GET / PATCH / DELETE
// matrices pin — pinning it for CLONE too means a future env-id
// verb-route added without a project leg inherits a working scoped-
// grant lockdown for the whole family.
//
// environment.create requires CapWrite (catalog.go:
// ActionEnvironmentCreate -> CapWrite), the same capability class as
// project.create / project.update / project.delete /
// environment.update / environment.delete. The role matrix for a
// principal acting on its own organization therefore splits along the
// write capability class: Owner / Admin / Developer hold CapWrite and
// are allowed (ReasonAllowedByRole); Viewer / CI / Support do not
// hold CapWrite and are denied (ReasonDeniedNoCapability) — CI holds
// CapDeploy (the deploy capability is for service lifecycle and
// rollouts, not desired-state mutation), so a CI key cannot stand up
// a cloned environment even within its home tenant. This is the
// load-bearing distinction from the environment.read matrix
// (environments_get_policy_test.go), which is "all six roles allow":
// three roles deny here at the role boundary, and — crucially — the
// engine's cross-tenant support exception is gated on `required ==
// CapRead || required == CapSupport`, so CapWrite is OUTSIDE that
// exception. Privileged Yalla support that needs to clone a
// customer's environment must go through explicit break-glass admin
// tooling, not this customer-facing route.
//
// environments rows store no credential material — only structural
// identifiers, a slug, a display name, an optimistic-concurrency
// version, and lifecycle timestamps. The projectEnvironmentOf
// projection has no value-redaction chokepoint to anchor a deny-path
// leak guard on; the load-bearing needle is the existence of the
// new environment row itself (and the id / slug / display name a
// denied principal must not learn). Tenant-leakage and no-write
// invariants apply: a denied response never echoes the new clone's
// id / slug / display name (which would also be a request-body echo
// — the request body carries the new id, slug, and display name),
// the source environment's id, the foreign tenant's id, the
// inherited project's id; and the cloner MUST never run on any deny
// path — a scoped key denied on the wire cannot have inserted a row
// in the background. Unlike DELETE, POST clone DOES carry a request
// body, so the leak guard also protects against a renderer
// regression that echoed the caller-supplied id / slug / display
// name back to a denied principal.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, environmentIDResolver, or the engine fails
// here. cloneEnvironmentHandlerFor, cloneEnvironment,
// decodeCloneEnvironment, fakeEnvironmentCloner, orgPrincipal,
// seedEnvironmentWire, and decodeError are shared with the clone-
// environment contract suite (environments_clone_test.go) and the
// wider httpapi test fixtures; this file adds no scaffolding beyond
// the small fixture builders below.

// cloneEnvSourcePathID is the {environment_id} PATH parameter for
// every test in this file: the id of the SOURCE environment the
// clone operation reads its project_id from. It is deliberately
// distinct from canonicalCloneEnvForMatrix.ID (the NEW row the
// clone writes), so the assertions can pin which value is the
// path's source id and which is the body's new id without
// ambiguity, and so the deny-path leak guard catches a renderer
// regression that echoed the path parameter back to a denied
// principal.
const cloneEnvSourcePathID = "env_matrix_clone_source"

// canonicalCloneRequestBody is the JSON request body every test in
// this file sends to the clone endpoint. It encodes the new
// environment's id, slug, and display name — the three caller-
// supplied fields the clone schema accepts (project_id is inherited
// from the source row inside the store transaction and is not part
// of the request schema). The body fields intentionally mirror the
// canonicalCloneEnvForMatrix row's slug / display_name, so the
// deny-path leak guard catches an echo of either the request body
// or the allow-path response with the same needles.
const canonicalCloneRequestBody = `{"environment_id":"env_matrix_clone","slug":"clone-matrix","display_name":"Clone Matrix v3"}`

// canonicalCloneEnvForMatrix is the row every test in this file
// would receive back from the cloner on an allow path: the NEW
// environment the clone writes, inheriting the source's project_id
// (the caller cannot supply one), with no deletion_scheduled_at
// stamp (a freshly-cloned row is live). Centralising it lets a
// future regression that reorders, renames, or recategorises a
// projectEnvironment field fail in exactly one place. Its ids /
// slug / display name are deliberately distinct from
// canonicalEnvForGet (used by environments_test.go),
// canonicalGetEnvForMatrix (used by environments_get_policy_test.go),
// canonicalUpdatedEnv (used by environments_update_test.go),
// canonicalUpdateEnvForMatrix (used by
// environments_update_policy_test.go), and
// canonicalDeleteEnvForMatrix (used by
// environments_delete_policy_test.go) so the matrices cannot
// accidentally share fixture state through a future shared fake,
// and they are deliberately recognisable so deny-path leak guards
// can needle for them; allow-path assertions compare against the
// same canonical values.
func canonicalCloneEnvForMatrix(orgID, projectID string) store.Environment {
	created := time.Date(2026, 1, 14, 9, 10, 11, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 12, 13, 14, 0, time.UTC)
	return seedEnvironmentWire("env_matrix_clone", orgID, projectID, "clone-matrix", "Clone Matrix v3", 1, created, updated)
}

// cloneEnvDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the new cloned environment, the
// source environment, the inherited project, or the caller-supplied
// request body fields. A denied response that accidentally rendered
// any of these fails the test — the new row's existence (and the
// caller-supplied slug / display name / id) is itself information a
// denied principal must not receive, and a deny-path leak of the
// canonical clone fields would mean the cloner ran and the response
// rendered its output even though the wire said 403. The quoted
// forms catch a case-collapsing renderer regression. Unlike DELETE,
// the clone request DOES carry a body, so the leak guard also
// protects against a renderer regression that echoed the caller-
// supplied environment_id / slug / display_name back to a denied
// principal — the new env id (env_matrix_clone) and the source
// path id (env_matrix_clone_source) are distinct so the renderer
// regression for "the path parameter" and for "the body's new id"
// are caught independently.
func cloneEnvDenyBodyLeak(body string) bool {
	needles := []string{
		"env_matrix_clone",        // catches both the new id (body) AND echoes of an allow-path response
		"env_matrix_clone_source", // path parameter — the source env id
		"\"clone-matrix\"",        // body slug + allow-path slug (quoted to dodge unrelated substrings)
		"\"Clone Matrix v3\"",     // body display_name + allow-path display_name (quoted)
		"prj_clone_matrix_parent", // inherited project id (would only appear via the cloner's allow-path response)
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestCloneEnvironmentPolicyMatrixRoles drives every built-in role
// through the production request path. CapWrite splits the matrix:
// Owner / Admin / Developer (own org) are allowed; Viewer / CI /
// Support (own org) are denied. The assertions that matter for
// allow rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the cloner is reached with the principal's
// own home organization id, the {environment_id} path parameter as
// the source id, the request body's new id / slug / display name,
// the principal id (so the audit record names the actor verbatim),
// the principal's home org id (so the audit record names the
// actor's tenant verbatim), and the response is a stable 201
// yalla.output.v1 carrying the new environment row with no
// deletion_scheduled_at stamp and its version mirrored into the
// ETag response header. For deny rows, the assertions are 403
// yalla.error.v1, the stable reason on the wire, the cloner MUST
// NEVER run (no row inserted in the background), and the denied
// body must not echo the new clone's id / slug / display name, the
// source env id, the inherited project, or any caller-supplied
// request body field.
func TestCloneEnvironmentPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_clone_matrix_parent"
	)
	env := canonicalCloneEnvForMatrix(org, project)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: cloneEnvSourcePathID},
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
			// separately in TestCloneEnvironmentPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvironmentCreate, envResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.create) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(environment.create) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.CloneEnvironmentInput
			callCount := 0
			cloner := fakeEnvironmentCloner{
				env:       env,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := cloneEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, cloner)
			rec := cloneEnvironment(handler, cloneEnvSourcePathID, "a-valid-token", canonicalCloneRequestBody)

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("cloner call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("cloner received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.SourceEnvironmentID != cloneEnvSourcePathID {
					t.Errorf("cloner received source environment id %q, want the path parameter %q",
						captured.SourceEnvironmentID, cloneEnvSourcePathID)
				}
				if captured.NewEnvironmentID != env.ID {
					t.Errorf("cloner received new environment id %q, want the request body's id %q",
						captured.NewEnvironmentID, env.ID)
				}
				if captured.NewSlug != env.Slug {
					t.Errorf("cloner received new slug %q, want the request body's slug %q",
						captured.NewSlug, env.Slug)
				}
				if captured.NewDisplayName != env.DisplayName {
					t.Errorf("cloner received new display_name %q, want the request body's display_name %q",
						captured.NewDisplayName, env.DisplayName)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("cloner received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.ActorOrgID != org {
					t.Errorf("cloner received actor org id %q, want the principal's home org %q",
						captured.ActorOrgID, org)
				}
				payload := decodeCloneEnvironment(t, rec)
				if payload.Data.Environment.ID != env.ID ||
					payload.Data.Environment.Slug != env.Slug ||
					payload.Data.Environment.DisplayName != env.DisplayName ||
					payload.Data.Environment.OrganizationID != env.OrganizationID ||
					payload.Data.Environment.ProjectID != env.ProjectID ||
					payload.Data.Environment.Version != env.Version {
					t.Errorf("environment = %+v, want (%s, %s, %s, org=%s, project=%s, v=%d)",
						payload.Data.Environment, env.ID, env.Slug, env.DisplayName, env.OrganizationID, env.ProjectID, env.Version)
				}
				if payload.Data.Environment.DeletionScheduledAt != nil {
					t.Errorf("deletion_scheduled_at = %v, want nil — a freshly-cloned row is live",
						payload.Data.Environment.DeletionScheduledAt)
				}
				if got, want := rec.Header().Get("ETag"), `"1"`; got != want {
					t.Errorf("ETag header = %q, want %q", got, want)
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
				t.Errorf("cloner was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.SourceEnvironmentID != "" || captured.NewEnvironmentID != "" {
				t.Errorf("cloner captured org=%q source_env=%q new_env=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.SourceEnvironmentID, captured.NewEnvironmentID)
			}
			if body := rec.Body.String(); cloneEnvDenyBodyLeak(body) {
				t.Errorf("denied response leaked the new clone, source env, inherited project, or caller-supplied body field: %s", body)
			}
		})
	}
}

// TestCloneEnvironmentPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action environment.create with a
// stable 403 E_FORBIDDEN, even when the underlying role would have
// allowed it. A revoked or expired credential must never be able to
// clone an environment of the organization it once had access to,
// the cloner must never run, and the denied body must never echo
// the principal id, the organization id, the path-supplied source
// environment id, the request body fields, or any seeded
// environment data.
//
// Underlying role is Owner so a working credential WOULD allow
// environment.create; Disabled is the only thing in the way and
// must be load-bearing. The case names mirror PRD BE-0165 ("revoked
// key, expired key").
func TestCloneEnvironmentPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_clone_matrix_parent"
	)
	env := canonicalCloneEnvForMatrix(org, project)

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

			var captured store.CloneEnvironmentInput
			callCount := 0
			cloner := fakeEnvironmentCloner{
				env:       env,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := cloneEnvironmentHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, cloner)
			rec := cloneEnvironment(handler, cloneEnvSourcePathID, "yk_no_longer_valid", canonicalCloneRequestBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 ||
				captured.OrganizationID != "" ||
				captured.SourceEnvironmentID != "" ||
				captured.NewEnvironmentID != "" {
				t.Errorf("cloner was reached (calls=%d org=%q source_env=%q new_env=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.SourceEnvironmentID, captured.NewEnvironmentID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				cloneEnvDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded environment data", body)
			}
		})
	}
}

// TestCloneEnvironmentPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for environment.create on the env-id clone
// route. As with environment.read / environment.update /
// environment.delete on the bare-id route family, the resource org
// id is taken from the PRINCIPAL'S home org — the {environment_id}
// path parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting POST /v1/environments/
//     {env_victim}/clone with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, env_victim})
//     — allowed by the role at CapWrite — and then reaches the
//     tenant-scoped repository query with the principal's home org
//     id and the foreign environment id. A production
//     *store.EnvironmentService (which combines organization_id and
//     environment_id in its WHERE clause when reading the source
//     row) cannot match a row that belongs to another tenant, so
//     the request surfaces as a deterministic 404 E_NOT_FOUND,
//     never disguised as a 201 with foreign data and never as a 403
//     that would confirm existence. The body must never echo the
//     foreign org id even though no wire input could place it
//     there, because the persistence layer must not leak
//     foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the environment.read cross-
//     tenant property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but create DOES NOT. Pinning that
//     engine verdict here means the eventual scoped variant inherits
//     a working cross-tenant deny for environment.create across
//     every role, and a future catalog change that downgraded
//     environment.create into the support cross-tenant exception
//     (or widened the exception) would fail here before it could
//     regress a real customer.
func TestCloneEnvironmentPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_clone_source"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits POST
	// /v1/environments/{env_victim}/clone with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, environmentID) pair
	// does not match a row, so a principal whose home org is
	// org_attacker cloning an environment that belongs to org_victim
	// hits the fake with (org_attacker, env_victim_clone_source) and
	// gets NotFound. The assertions that matter are structural: the
	// cloner is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentCloner could not have read the
	// victim's environment regardless of database state, and the
	// new row could never have been inserted. The denied body must
	// never echo the victim's org id.
	var captured store.CloneEnvironmentInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	cloner := fakeEnvironmentCloner{
		err:       apierr.NotFound("environment", foreignEnvID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, cloner)
	rec := cloneEnvironment(handler, foreignEnvID, "a-valid-token", canonicalCloneRequestBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant source environment_id surfaces as NotFound, never 201 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("cloner call count = %d, want 1 — the cloner runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign source environment id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("cloner received org id %q, want the attacker's home org %q — the cloner must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.SourceEnvironmentID != foreignEnvID {
		t.Errorf("cloner received source environment id %q, want the path parameter %q",
			captured.SourceEnvironmentID, foreignEnvID)
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
	// scope inherits a working cross-tenant deny.
	// environment.create is CapWrite, which is OUTSIDE the engine
	// clause `CapSupport && (CapRead || CapSupport)` — so EVERY
	// role, including Support, is denied cross-tenant.
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
			got := e.Decide(p, policy.ActionEnvironmentCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(environment.create, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCloneEnvironmentPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, environment grant not implying production, service grant
// shielding parent-level resources — are pinned against the engine
// at their natural scopes (a project resource, an env resource, a
// service resource), then tied back to the wire by proving that ALL
// three scoped key types are denied OutOfScope against THIS endpoint
// (even when the grant names the source environment's own project
// or the source environment's own id), while an organization-level
// Admin grant — which pins no ProjectID and covers any resource
// scope in the same org — is allowed end-to-end.
//
//   - A project-level Admin grant naming the source environment's
//     parent project CANNOT authorize the clone through this route
//     — the grant scope pins ProjectID and the resource scope does
//     not, so covers() returns false. (The same key DOES authorize
//     environment.create at a project resource at the engine —
//     pinned here so the load-bearing distinction between this
//     route and the parent-scoped POST
//     /v1/projects/{project_id}/environments route is explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a project resource.
//   - An environment-level Admin grant naming the source
//     environment's id CANNOT authorize the clone either, because
//     the grant scope pins ProjectID and the resource scope does
//     not. (The grant DOES authorize env.write at the env resource
//     — pinned at the engine — but not environment.create on this
//     route.) An env grant on staging also does not imply env.write
//     on production at the engine.
//   - A service-level Admin grant CANNOT either, and at the engine
//     a service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level Admin grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because environment.create is CapWrite
//     and Admin holds CapWrite — is allowed via
//     ReasonAllowedByGrant.
//   - An organization-level VIEWER grant covers the resource but
//     confers no write capability; environment.create is denied via
//     ReasonDeniedNoCapability. This is the load-bearing distinction
//     from the environment.read grant matrix where an org-level
//     Viewer is allowed.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the cloner is never reached (so a production
// store could never have inserted a row in the background), and the
// body never echoes the new clone's identifiers, the source
// environment's id, the inherited project's id, or any caller-
// supplied request body field.
func TestCloneEnvironmentPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_clone_matrix_parent"
	)
	env := canonicalCloneEnvForMatrix(org, project)
	e := policy.NewEngine()

	// Resource the env-id clone route resolves to: OrganizationID
	// from the principal's home org, EnvironmentID from the path's
	// source env id, NO ProjectID. Every covers() check below
	// against this resource is the engine-level twin of the wire-
	// level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: cloneEnvSourcePathID},
	}

	// Project-level grant: admin on the source environment's parent
	// project. Admin confers CapWrite at the project scope, which
	// would normally be enough for environment.create on a project
	// resource — and the engine confirms that at a project resource,
	// so the load-bearing distinction between this route and the
	// parent-scoped POST /v1/projects/{project_id}/environments
	// route is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_clone_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.create) at the parent project for the target-project admin grantee = %+v, want allow via %q — a project-scoped resource IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) at a sibling project for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the
	// load-bearing distinction from the parent-scoped route.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) at the env-id clone route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a project resource (which the parent-
	// scoped POST /v1/projects/{project_id}/environments route would
	// target), environment.create must fail with
	// ReasonDeniedNoCapability — a viewer grant does not widen to a
	// write action even when its scope contains the resource.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.create) at a project resource for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
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
	if got := e.Decide(envStagingGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) at the env-id clone route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (the source env id itself) is ALSO
	// denied OutOfScope on this route, because the grant scope
	// still pins ProjectID and the resource scope does not — the
	// env_id alone is not enough to authorize a top-level clone
	// through this route. This is the load-bearing property that
	// locks down the env-id clone route: an environment grant alone
	// does not authorize clones through it.
	scopeSourceEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: cloneEnvSourcePathID}
	envSourceGrantee := policy.Principal{
		ID: "sa_env_source", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSourceEnv}},
	}
	if got := e.Decide(envSourceGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) at the env-id clone route's resource scope for a grant on the SAME source env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the
	// engine against service / env resources.
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
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.create) at the env-id clone route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// source environment via THIS route is a 403 with the stable
	// out-of-scope reason, the cloner is never reached (so a
	// production store could never have inserted a row in the
	// background), and the body never echoes the new clone's
	// identifiers, the source env id, the inherited project's id, or
	// any caller-supplied request body field. This is the property
	// that confines a project-scoped key to the parent-scoped route.
	var projCaptured store.CloneEnvironmentInput
	projCallCount := 0
	projCloner := fakeEnvironmentCloner{
		env:       env, // would be returned if cloner ran — leak guard catches it
		gotInput:  &projCaptured,
		callCount: &projCallCount,
	}
	projHandler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projCloner)
	projRec := cloneEnvironment(projHandler, cloneEnvSourcePathID, "yk_proj_admin_scoped", canonicalCloneRequestBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-id clone route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projCaptured.OrganizationID != "" || projCaptured.SourceEnvironmentID != "" || projCaptured.NewEnvironmentID != "" {
		t.Errorf("cloner was reached (calls=%d org=%q source_env=%q new_env=%q) for a project-scoped grantee; it must never run",
			projCallCount, projCaptured.OrganizationID, projCaptured.SourceEnvironmentID, projCaptured.NewEnvironmentID)
	}
	if body := projRec.Body.String(); cloneEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the new clone, source env, inherited project, or caller-supplied body field: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME source
	// environment id the path names — hitting the env-id clone
	// route is a 403, the cloner is never reached, and the body
	// never echoes the canonical environment or any caller-supplied
	// body field. This is the load-bearing property that locks down
	// the env-id clone route: an environment grant alone does not
	// authorize clones through it.
	var envCaptured store.CloneEnvironmentInput
	envCallCount := 0
	envCloner := fakeEnvironmentCloner{
		env:       env,
		gotInput:  &envCaptured,
		callCount: &envCallCount,
	}
	envHandler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: envSourceGrantee, Method: auth.MethodAPIKey}, nil, envCloner)
	envRec := cloneEnvironment(envHandler, cloneEnvSourcePathID, "yk_env_scoped", canonicalCloneRequestBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-id clone route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envCaptured.OrganizationID != "" || envCaptured.SourceEnvironmentID != "" || envCaptured.NewEnvironmentID != "" {
		t.Errorf("cloner was reached (calls=%d org=%q source_env=%q new_env=%q) for an env-scoped grantee; it must never run",
			envCallCount, envCaptured.OrganizationID, envCaptured.SourceEnvironmentID, envCaptured.NewEnvironmentID)
	}
	if body := envRec.Body.String(); cloneEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the new clone, source env, inherited project, or caller-supplied body field: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the env-id
	// clone route is a 403, the cloner is never reached, and the
	// body never echoes parent-level identifiers — the "service
	// grant does not expose parent-level secrets or unrelated
	// services" criterion tied to the wire on this route.
	var svcCaptured store.CloneEnvironmentInput
	svcCallCount := 0
	svcCloner := fakeEnvironmentCloner{
		env:       env,
		gotInput:  &svcCaptured,
		callCount: &svcCallCount,
	}
	svcHandler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcCloner)
	svcRec := cloneEnvironment(svcHandler, cloneEnvSourcePathID, "yk_svc_scoped", canonicalCloneRequestBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-id clone route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcCaptured.OrganizationID != "" || svcCaptured.SourceEnvironmentID != "" || svcCaptured.NewEnvironmentID != "" {
		t.Errorf("cloner was reached (calls=%d org=%q source_env=%q new_env=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcCaptured.OrganizationID, svcCaptured.SourceEnvironmentID, svcCaptured.NewEnvironmentID)
	}
	if body := svcRec.Body.String(); cloneEnvDenyBodyLeak(body) {
		t.Errorf("denied response leaked the new clone, source env, inherited project, or caller-supplied body field: %s", body)
	}

	// An organization-level Admin grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because environment.create is CapWrite
	// and Admin holds CapWrite — is allowed via
	// ReasonAllowedByGrant. The same key is end-to-end allowed at
	// the wire, with the cloner reached on the principal's home org
	// id, the path source env id, the request body's new id / slug
	// / display name, the principal id, AND the principal's home
	// org id (ActorOrgID — so the audit record names the actor's
	// tenant verbatim). This locks the CapWrite requirement against
	// the grant path so a future catalog change that upgraded
	// environment.create above CapWrite would fail here (silently
	// denying every org-level Admin grantee) before it could regress
	// a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(environment.create) at the env-id clone route's resource scope for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.CloneEnvironmentInput
	orgCallCount := 0
	orgCloner := fakeEnvironmentCloner{
		env:       env,
		gotInput:  &orgCaptured,
		callCount: &orgCallCount,
	}
	orgHandler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgCloner)
	allowedRec := cloneEnvironment(orgHandler, cloneEnvSourcePathID, "yk_org_admin", canonicalCloneRequestBody)
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeCloneEnvironment(t, allowedRec)
	if allowedPayload.Data.Environment.ID != env.ID ||
		allowedPayload.Data.Environment.Slug != env.Slug ||
		allowedPayload.Data.Environment.OrganizationID != env.OrganizationID ||
		allowedPayload.Data.Environment.ProjectID != env.ProjectID ||
		allowedPayload.Data.Environment.Version != env.Version {
		t.Errorf("environment = %+v, want (%s, %s, org=%s, project=%s, v=%d)",
			allowedPayload.Data.Environment, env.ID, env.Slug, env.OrganizationID, env.ProjectID, env.Version)
	}
	if allowedPayload.Data.Environment.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v on the org-admin allow path, want nil — a freshly-cloned row is live",
			allowedPayload.Data.Environment.DeletionScheduledAt)
	}
	if got, want := allowedRec.Header().Get("ETag"), `"1"`; got != want {
		t.Errorf("ETag header = %q, want %q on the org-admin allow path", got, want)
	}
	if orgCallCount != 1 {
		t.Errorf("cloner call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("cloner received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.SourceEnvironmentID != cloneEnvSourcePathID {
		t.Errorf("cloner received source environment id %q, want the path parameter %q",
			orgCaptured.SourceEnvironmentID, cloneEnvSourcePathID)
	}
	if orgCaptured.NewEnvironmentID != env.ID {
		t.Errorf("cloner received new environment id %q, want the request body's id %q",
			orgCaptured.NewEnvironmentID, env.ID)
	}
	if orgCaptured.NewSlug != env.Slug {
		t.Errorf("cloner received new slug %q, want the request body's slug %q",
			orgCaptured.NewSlug, env.Slug)
	}
	if orgCaptured.NewDisplayName != env.DisplayName {
		t.Errorf("cloner received new display_name %q, want the request body's display_name %q",
			orgCaptured.NewDisplayName, env.DisplayName)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID {
		t.Errorf("cloner received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgAdminGrantee.ID)
	}
	if orgCaptured.ActorOrgID != org {
		t.Errorf("cloner received actor org id %q, want the principal's home org %q",
			orgCaptured.ActorOrgID, org)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; environment.create must be denied
	// via ReasonDeniedNoCapability even though the grant scope is
	// the whole org. This is the load-bearing distinction from the
	// environment.read grant matrix: an org-level Viewer is
	// ALLOWED for read but DENIED for create.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvironmentCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(environment.create) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home
	// org id is org_sibling, cannot be used to clone an environment
	// in org_sibling — the cross-tenant guard fires first because
	// the principal's home org no longer matches the grant's scope.
	// This is the engine-level twin of the wire-level "wrong
	// organization" property in
	// TestCloneEnvironmentPolicyWrongOrganizationPrincipal, applied
	// to a scoped key: stealing a key cannot smuggle it across
	// tenants. (environment.create is OUTSIDE the support
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
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvironmentCreate, siblingOrgResource); got.Allow {
		t.Errorf("Decide(environment.create) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
