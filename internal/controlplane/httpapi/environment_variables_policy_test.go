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
	"github.com/JuribaDev/yalla/internal/output"
)

// Policy-matrix coverage for GET /v1/environments/{environment_id}/variables
// (BE-0174). Where environment_variables_test.go proves the endpoint's
// wire contract (BE-0172), this file proves its authorization contract:
// that action env.read cannot be bypassed by — or leak a foreign
// environment's variables (and especially secret-variable plaintext) on
// account of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries environmentIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and
// the {environment_id} PATH parameter — and CRUCIALLY pins NO
// ProjectID leg, because the bare top-level path carries no parent
// project_id. That is the load-bearing distinction from the
// projectIDResolver siblings (BE-0144 projects_variables_get_policy_test.go
// is the structural twin for the project-scoped variables list): every
// scoped grant in the engine pins a ProjectID, and the engine's
// covers() rule is one-way (a grant scope that pins ProjectID cannot
// cover a resource scope that does not). The consequence is that ALL
// project-, environment-, and service-scoped grants are denied at the
// boundary by ReasonDeniedOutOfScope — even a project-scoped Viewer
// grant naming THIS environment's parent project, even an
// environment-scoped Admin grant naming THIS environment's id, because
// neither scope's ProjectID can cover a resource scope without one.
// Principals whose only access is a scoped grant must use a
// parent-scoped route to address environment variables; this route is
// reserved for org-wide read roles (owner, admin, developer, viewer,
// ci) and org-wide grants.
//
// env.read requires CapRead (catalog.go: ActionEnvRead -> CapRead), the
// same capability class as environment.read, project.read, env.read,
// service.read, limits.read, usage.read, and the grants-read actions.
// All six built-in roles hold CapRead, so the role matrix for a
// principal reading variables in its own organization is "all allow";
// the assertions that matter are that the verdict is reached through
// the role (ReasonAllowedByRole), the reader is called with the
// principal's own home organization id AND the {environment_id} path
// parameter (so the tenant-scoped repository query cannot match
// variables of an environment in another tenant), and the response
// carries the canonical variable list in a stable yalla.output.v1
// envelope.
//
// Unlike environment_grants rows, environment_variables rows DO carry
// credential material in the form of secret values. The wire chokepoint
// for that material is environmentVariableOf (environment_variables.go):
// is_secret=true rows project Value as output.Sentinel rather than the
// seeded plaintext. The deny-path leak guard (envVarsDenyBodyLeak) is
// therefore anchored on the SECRET PLAINTEXT (in addition to the
// canonical variable ids and keys), because the strongest possible
// regression — the renderer leaking secret values to a denied principal
// — has no other natural sentinel. The reader is never reached on a
// deny path, but the leak guard catches a renderer that would have
// surfaced it. Tenant-leakage and no-read invariants still apply: a
// denied response never echoes any seeded variable id / key /
// non-secret value, the foreign tenant's id, or the canonical
// environment's id; and the reader MUST never run on any deny path —
// a scoped key denied on the wire cannot have surfaced a variable row
// in the background.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing env.read against a foreign-tenant resource IS
// allowed via ReasonAllowedBySupport — the same property
// environment.read / project.read / project.grants.read /
// environment.grants.read / limits.read / usage.read carry. Every
// non-support role is denied with ReasonDeniedCrossTenant. The
// customer-facing route under test cannot reach that engine branch by
// construction (environmentIDResolver pins the resource scope to the
// PRINCIPAL'S home org, not the path's tenant — the support
// cross-tenant exception specifically does NOT apply through this
// endpoint, as the resolver doc and route description make explicit),
// but pinning the engine verdict here means a future endpoint that
// resolves the resource into a foreign-org scope (a hypothetical admin
// tool) inherits a working cross-tenant deny and the documented
// support exception, and a future catalog change that upgraded
// env.read above CapRead would fail here (silently denying every
// support cross-tenant variables read) before it could regress a real
// customer.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, environmentIDResolver, or the engine fails here.
// listEnvironmentVariablesHandlerFor, getEnvironmentVariables,
// decodeListEnvironmentVariables, seedEnvironmentVariableWire,
// fakeEnvironmentVariableReader, orgPrincipal, and decodeError are
// shared with the environment-variables contract suite
// (environment_variables_test.go) and the wider httpapi test fixtures;
// this file adds no scaffolding beyond the small fixture builders
// below.

// canonicalEnvVarsEnvironmentID is the environment id every test in
// this file resolves the {environment_id} path parameter to.
// Centralising it lets a future regression that reorders, renames, or
// recategorises an environment-variable projection field needle for
// the same identifiers in one place. The distinctive id is
// deliberately recognisable so deny-path leak guards can needle for
// it; allow-path assertions compare against the same canonical value.
const canonicalEnvVarsEnvironmentID = "env_evar_matrix_alpha"

// canonicalEnvVarsProjectID is the parent project id every test in
// this file pins on a scoped grant when the grant scope must carry a
// ProjectID (the load-bearing scope leg that makes a scoped grant
// fail covers() against this route's resource). The id is
// deliberately recognisable so deny-path leak guards can needle for
// it — even though no wire input could place it on the response — to
// catch a future renderer regression that accidentally projected the
// parent project id through.
const canonicalEnvVarsProjectID = "prj_evar_matrix_parent"

// canonicalEnvVarsSecretPlaintext is the seeded plaintext of the
// secret variable canonicalEnvironmentVariables returns. It MUST
// never reach the wire — environmentVariableOf replaces secret values
// with output.Sentinel — and it is the load-bearing needle
// envVarsDenyBodyLeak watches for. A regression in the redaction
// chokepoint, or a renderer that surfaced an unredacted row on a deny
// path, would render this plaintext, and the leak guard catches it.
const canonicalEnvVarsSecretPlaintext = "postgres://user:hunter2@db.internal/evar-matrix"

// canonicalEnvironmentVariables is the variable list every test in
// this file would receive back from the reader on an allow path. It
// mixes a secret DATABASE_URL with a non-secret REGION so the wire
// projection exercises the redaction chokepoint on the secret row and
// the verbatim pass-through on the non-secret row. Deny-path leak
// guards needle for the distinctive variable ids, keys, the
// non-secret value, AND the secret plaintext so an accidental render
// — even a partial one — fails the test.
func canonicalEnvironmentVariables(orgID, envID string) []store.EnvironmentVariable {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	return []store.EnvironmentVariable{
		seedEnvironmentVariableWire("evar_matrix_db", orgID, envID, "DATABASE_URL", canonicalEnvVarsSecretPlaintext, true, 5, created, updated),
		seedEnvironmentVariableWire("evar_matrix_region", orgID, envID, "REGION", "us-east-1", false, 1, created, created),
	}
}

// envVarsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical environment or its
// variables, OR — the load-bearing addition over envGrantsDenyBodyLeak
// — the secret variable's plaintext. A denied response that
// accidentally rendered any of these fails the test:
//
//   - a denied response that surfaced the secret PLAINTEXT would be a
//     critical credential leak, the strongest possible regression this
//     route can carry. The reader never runs on a deny path, but the
//     leak guard anchors the contract against a hypothetical future
//     handler that materialised rows before the policy boundary.
//   - a denied response that surfaced a row's structural identity (id,
//     key, non-secret value) leaks the existence of the row, which is
//     itself information a denied principal must not receive.
//
// There is no request body for GET /v1/environments/{environment_id}/variables,
// so unlike a write-path leak guard there is no caller-supplied
// request-body field to protect. The quoted "hunter2" form catches a
// case-collapsing renderer regression that might project the password
// substring of the connection string.
func envVarsDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalEnvVarsEnvironmentID,
		canonicalEnvVarsProjectID,
		"evar_matrix_db",
		"evar_matrix_region",
		"DATABASE_URL",
		"us-east-1",
		canonicalEnvVarsSecretPlaintext,
		"hunter2",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListEnvironmentVariablesPolicyMatrixRoles drives every built-in
// role through the production request path. All six built-in roles
// hold CapRead, so the matrix is "all allow" for a principal reading
// variables of an environment in its own organization; the assertions
// that matter are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {environment_id} path parameter (so a
// tenant-scoped store query cannot match a foreign row), the response
// is a stable 200 yalla.output.v1 envelope carrying the canonical
// variable list, and — the load-bearing wire distinction from the
// environment-grants matrix — secret variable values project as
// output.Sentinel rather than the seeded plaintext. A regression in
// environmentVariableOf would surface the secret plaintext on every
// allow row here, before any deny-path leak guard fires.
func TestListEnvironmentVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	vars := canonicalEnvironmentVariables(org, envID)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
	}

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

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here. Support
			// reading variables in ITS OWN organization is allowed via
			// ReasonAllowedByRole (same-tenant falls through the
			// cross-tenant clause); the Support cross-tenant exception
			// is exercised at the engine in
			// TestListEnvironmentVariablesPolicyWrongOrganizationPrincipal
			// — it cannot be exercised at the wire through this route
			// because environmentIDResolver pins the resource scope to
			// the principal's home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvRead, envResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(env.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotEnv string
			callCount := 0
			reader := fakeEnvironmentVariableReader{
				vars:             vars,
				gotOrgID:         &gotOrg,
				gotEnvironmentID: &gotEnv,
				callCount:        &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listEnvironmentVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getEnvironmentVariables(handler, envID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 1 {
				t.Errorf("reader call count = %d, want 1 on the allow path", callCount)
			}
			if gotOrg != org {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					gotOrg, org)
			}
			if gotEnv != envID {
				t.Errorf("reader received environment id %q, want the path parameter %q",
					gotEnv, envID)
			}
			env := decodeListEnvironmentVariables(t, rec)
			if len(env.Data.Variables) != len(vars) {
				t.Fatalf("variables len = %d, want %d; body %s",
					len(env.Data.Variables), len(vars), rec.Body.String())
			}
			// Spot-check the projection lands the load-bearing fields
			// of both rows: the secret row's Value MUST be the
			// Sentinel (a redaction regression in environmentVariableOf
			// would surface the plaintext here, before any deny-path
			// leak guard fires; a regression that double-emitted the
			// row in a non-canonical field fails here too). The
			// non-secret row's Value MUST be the seeded plaintext (a
			// regression in the redaction chokepoint that over-redacted
			// non-secret values would fail here).
			got0 := env.Data.Variables[0]
			if got0.ID != "evar_matrix_db" || got0.Key != "DATABASE_URL" || !got0.IsSecret {
				t.Errorf("got[0] = %+v, want evar_matrix_db / DATABASE_URL / is_secret=true", got0)
			}
			if got0.Value != output.Sentinel {
				t.Errorf("got[0].value = %q, want the redaction sentinel %q — environmentVariableOf must redact secret values on the wire",
					got0.Value, output.Sentinel)
			}
			got1 := env.Data.Variables[1]
			if got1.ID != "evar_matrix_region" || got1.Key != "REGION" || got1.IsSecret {
				t.Errorf("got[1] = %+v, want evar_matrix_region / REGION / is_secret=false", got1)
			}
			if got1.Value != "us-east-1" {
				t.Errorf("got[1].value = %q, want the seeded non-secret plaintext %q — non-secret values must project verbatim",
					got1.Value, "us-east-1")
			}
			// The secret plaintext MUST NEVER appear on any allow path
			// either — the wire redaction chokepoint is the contract,
			// and the leak guard pins it on the role matrix so a
			// regression that leaked plaintext to ANY built-in role
			// would fail here, before it could regress a real
			// customer.
			if body := rec.Body.String(); strings.Contains(body, canonicalEnvVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
				t.Errorf("response body %s leaked the secret plaintext — the redaction chokepoint must hold on every allow path too",
					body)
			}
		})
	}
}

// TestListEnvironmentVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action env.read with a stable 403 E_FORBIDDEN,
// even when the underlying role would have allowed it. A revoked or
// expired credential must never be able to list variables of an
// environment of the organization it once had access to, the reader
// must never run, and the denied body must never echo the principal
// id, the organization id, the path-supplied environment id, any
// seeded variable id / key / non-secret value, or — the critical
// addition — the secret variable's plaintext.
//
// Underlying role is Owner so a working credential WOULD allow
// env.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0174 ("revoked key,
// expired key").
func TestListEnvironmentVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	vars := canonicalEnvironmentVariables(org, envID)

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

			var gotOrg, gotEnv string
			callCount := 0
			reader := fakeEnvironmentVariableReader{
				vars:             vars,
				gotOrgID:         &gotOrg,
				gotEnvironmentID: &gotEnv,
				callCount:        &callCount,
			}
			handler := listEnvironmentVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getEnvironmentVariables(handler, envID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotOrg != "" || gotEnv != "" {
				t.Errorf("reader was reached (calls=%d org=%q env=%q) for a disabled principal; it must never run",
					callCount, gotOrg, gotEnv)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				envVarsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded variable data (including the secret plaintext)",
					body)
			}
		})
	}
}

// TestListEnvironmentVariablesPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for env.read on the env-id route. As with
// environment.read, the resource org id is taken from the PRINCIPAL'S
// home org — the {environment_id} path parameter alone never widens
// the resource to another tenant. Tenant isolation on the wire is
// therefore structural at the persistence layer, not the policy
// boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/environments/{env_victim}/variables with a valid Owner
//     token reaches the engine with a same-tenant resource
//     ({org_attacker, env_victim}) — allowed by the role at CapRead —
//     and then reaches the tenant-scoped repository query with the
//     principal's home org id and the foreign environment id. The
//     store-backed reader Gets the environment under (organization_id,
//     environment_id) before listing its variables, so a cross-tenant
//     environment_id is rejected as a deterministic 404 E_NOT_FOUND,
//     never disguised as an empty success — which would invite an
//     agent to believe the environment exists with no variables. The
//     body must never echo the foreign org id (even though no wire
//     input could place it there), nor — the critical addition for
//     this route — the secret plaintext (a renderer that materialised
//     a foreign-tenant row before the persistence guard would land
//     here).
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). Pinning
//     that engine verdict here means the eventual scoped variant
//     inherits a working cross-tenant deny and the documented support
//     exception, and a future catalog change that upgraded env.read
//     above CapRead would fail here (silently denying every support
//     cross-tenant read) before it could regress a real customer.
func TestListEnvironmentVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_evar"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits GET
	// /v1/environments/{env_victim}/variables with a valid Owner
	// token. The fake mirrors the production store contract: it
	// returns NotFound whenever the (organizationID, environmentID)
	// pair does not match a row (the reader's environment existence
	// check fires first), so a principal whose home org is
	// org_attacker listing variables of an environment that belongs to
	// org_victim hits the fake with (org_attacker, env_victim_evar)
	// and gets NotFound. The assertions that matter are structural:
	// the reader is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentVariableReader could not have surfaced
	// the victim's variables regardless of database state. The denied
	// body must never echo the victim's org id, nor the secret
	// plaintext.
	var gotOrg, gotEnv string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeEnvironmentVariableReader{
		err:              apierr.NotFound("environment", foreignEnvID),
		gotOrgID:         &gotOrg,
		gotEnvironmentID: &gotEnv,
		callCount:        &callCount,
	}
	handler := listEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getEnvironmentVariables(handler, foreignEnvID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 200 with an empty list and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1 — the reader runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign environment id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			gotOrg, ownOrg)
	}
	if gotEnv != foreignEnvID {
		t.Errorf("reader received environment id %q, want the path parameter %q",
			gotEnv, foreignEnvID)
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
	// The secret plaintext MUST NEVER appear on a cross-tenant deny
	// either; the reader didn't materialise the canonical rows here
	// (it returned NotFound), but the leak guard pins the invariant
	// against a future regression that surfaced foreign-tenant
	// material in an error envelope.
	if body := rec.Body.String(); strings.Contains(body, canonicalEnvVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("response body %s leaked the secret plaintext on a cross-tenant deny", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. env.read is
	// CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
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
	}
	for _, tc := range crossTenantDeny {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionEnvRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(env.read, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` reaches env.read because the
	// catalog maps it to CapRead. This locks the CapRead requirement
	// against the support cross-tenant path so a future catalog
	// change that upgraded env.read above CapRead would fail here
	// (silently denying every support cross-tenant read) before it
	// could regress a real customer. The customer-facing route under
	// test cannot reach this engine branch by construction —
	// environmentIDResolver pins the resource scope to the
	// principal's own home org, so a foreign {environment_id} is
	// admitted same-tenant and rejected at the persistence layer —
	// but the engine verdict is the authoritative source of the
	// documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(env.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListEnvironmentVariablesPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant shielding
// parent-level resources — are pinned against the engine at their
// natural scopes (a project resource, an env resource, a service
// resource), then tied back to the wire by proving that ALL three
// scoped key types are denied OutOfScope against THIS endpoint (even
// when the grant names the target environment's own project or even
// the target environment's own id), while an organization-level
// Viewer grant — which pins no ProjectID and covers any resource
// scope in the same org — is allowed end-to-end.
//
//   - A project-level Viewer grant naming THIS environment's parent
//     project CANNOT authorize the read through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     project.read at a project resource — that is the
//     project-variables route's job — and that property is pinned at
//     the engine here so the load-bearing distinction between the
//     project-variables route and the environment-variables route is
//     explicit.)
//   - A project-level Viewer grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a project resource.
//   - An environment-level Admin grant naming THIS environment's id
//     CANNOT authorize the read either, because the grant scope pins
//     ProjectID and the resource scope does not. (The grant DOES
//     authorize env.write at the env resource — pinned at the engine
//     — but not env.read on this route.) An env grant on staging
//     also does not imply env.write on production at the engine.
//   - A service-level Admin grant CANNOT either, and at the engine a
//     service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level Viewer grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because env.read is CapRead and Viewer
//     holds CapRead — is allowed via ReasonAllowedByGrant.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the reader is never reached (so a production
// store could not have surfaced the canonical variables — and
// especially the secret plaintext — in the background), and the body
// never echoes the canonical environment's or variables' identifiers,
// nor the parent project's id, nor the secret plaintext.
func TestListEnvironmentVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	parentProject := canonicalEnvVarsProjectID
	vars := canonicalEnvironmentVariables(org, envID)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO
	// ProjectID. Every covers() check below against this resource is
	// the engine-level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, which would normally be
	// enough for project.read on a project resource — and the engine
	// confirms that at a project resource, so the load-bearing
	// distinction between the project-variables route and this route
	// is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: parentProject}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_evar_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.read) at the parent project for the target-project viewer grantee = %+v, want allow via %q — the project-variables route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionProjectRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.read) at a sibling project for the target-project viewer grantee = %+v, want deny via %q — a project-scoped viewer grant must not reach a sibling project",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from the project-variables route.
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod"}
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
	if got := e.Decide(envStagingGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (the target environment itself) is ALSO
	// denied OutOfScope on this route, because the grant scope still
	// pins ProjectID and the resource scope does not — the env_id
	// alone is not enough to authorize a top-level read through this
	// route. A future relaxation of covers() (e.g. allowing a grant
	// on env_X to cover a resource scope with just EnvID=env_X and
	// no ProjectID) would land here.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: envID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod"}
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
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// target environment via THIS route is a 403 with the stable
	// out-of-scope reason, the reader is never reached (so a
	// production store could never have surfaced the canonical
	// variables — and especially the secret plaintext — in the
	// background), and the body never echoes the canonical
	// environment's identifiers, the canonical variables' ids / keys
	// / values, or the parent project's id. This is the property
	// that confines a project-scoped key to the project-variables
	// route only.
	var projGotOrg, projGotEnv string
	projCallCount := 0
	projReader := fakeEnvironmentVariableReader{
		vars:             vars, // would be returned if reader ran — leak guard catches it
		gotOrgID:         &projGotOrg,
		gotEnvironmentID: &projGotEnv,
		callCount:        &projCallCount,
	}
	projHandler := listEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projReader)
	projRec := getEnvironmentVariables(projHandler, envID, "yk_proj_viewer_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-variables route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projGotOrg != "" || projGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for a project-scoped grantee; it must never run",
			projCallCount, projGotOrg, projGotEnv)
	}
	if body := projRec.Body.String(); envVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, variables (including secret plaintext), or parent project data: %s",
			body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME
	// environment id the path names — hitting the env-variables route
	// is a 403, the reader is never reached, and the body never
	// echoes the canonical environment or its variables. This is the
	// load-bearing property that locks down this route: an
	// environment grant alone does not authorize variable reads
	// through it.
	var envGotOrg, envGotEnv string
	envCallCount := 0
	envReader := fakeEnvironmentVariableReader{
		vars:             vars,
		gotOrgID:         &envGotOrg,
		gotEnvironmentID: &envGotEnv,
		callCount:        &envCallCount,
	}
	envHandler := listEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getEnvironmentVariables(envHandler, envID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-variables route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotOrg != "" || envGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for an env-scoped grantee; it must never run",
			envCallCount, envGotOrg, envGotEnv)
	}
	if body := envRec.Body.String(); envVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, variables (including secret plaintext), or parent project data: %s",
			body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the
	// env-variables route is a 403, the reader is never reached, and
	// the body never echoes parent-level identifiers — the "service
	// grant does not expose parent-level secrets or unrelated
	// services" criterion tied to the wire on this route.
	var svcGotOrg, svcGotEnv string
	svcCallCount := 0
	svcReader := fakeEnvironmentVariableReader{
		vars:             vars,
		gotOrgID:         &svcGotOrg,
		gotEnvironmentID: &svcGotEnv,
		callCount:        &svcCallCount,
	}
	svcHandler := listEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getEnvironmentVariables(svcHandler, envID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-variables route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotOrg != "" || svcGotEnv != "" {
		t.Errorf("reader was reached (calls=%d org=%q env=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotOrg, svcGotEnv)
	}
	if body := svcRec.Body.String(); envVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment, variables (including secret plaintext), or parent project data: %s",
			body)
	}

	// An organization-level Viewer grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because env.read is CapRead and Viewer
	// holds CapRead — is allowed via ReasonAllowedByGrant. The same
	// key is end-to-end allowed at the wire, with the reader reached
	// on the principal's home org id and the path environment id,
	// and the secret variable's value redacted to output.Sentinel on
	// the response. This locks the CapRead requirement against the
	// grant path so a future catalog change that upgraded env.read
	// above CapRead would fail here (silently denying every
	// org-level Viewer grantee) before it could regress a real
	// customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) at the env-id route's resource scope for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotEnv string
	orgCallCount := 0
	orgReader := fakeEnvironmentVariableReader{
		vars:             vars,
		gotOrgID:         &orgGotOrg,
		gotEnvironmentID: &orgGotEnv,
		callCount:        &orgCallCount,
	}
	orgHandler := listEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getEnvironmentVariables(orgHandler, envID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeListEnvironmentVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != len(vars) {
		t.Errorf("variables len = %d, want %d", len(allowedPayload.Data.Variables), len(vars))
	}
	if orgCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, org)
	}
	if orgGotEnv != envID {
		t.Errorf("reader received environment id %q, want the path parameter %q",
			orgGotEnv, envID)
	}
	// Even on the org-level grant allow path the secret plaintext
	// MUST be redacted; the wire chokepoint is the contract on every
	// successful read regardless of which authorization path admitted
	// it.
	if body := allowedRec.Body.String(); strings.Contains(body, canonicalEnvVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("org-viewer allow response leaked the secret plaintext: %s", body)
	}
	// And the secret row's projected Value MUST be the redaction
	// sentinel — a positive assertion that locks the redaction
	// chokepoint against an authorization path that bypassed the
	// role matrix.
	if got0 := allowedPayload.Data.Variables[0]; got0.Value != output.Sentinel {
		t.Errorf("org-viewer allow path got[0].value = %q, want the redaction sentinel %q",
			got0.Value, output.Sentinel)
	}

	// And the same project-scoped viewer grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to list environment
	// variables in org_sibling — the cross-tenant guard fires first
	// because the principal's home org no longer matches the grant's
	// scope. This is the engine-level twin of the wire-level "wrong
	// organization" property in
	// TestListEnvironmentVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (env.read IS inside the support cross-tenant
	// exception, but the principal here is a service account with no
	// CapSupport role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: "org_sibling", EnvironmentID: envID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
