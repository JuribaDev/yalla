package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// Policy-matrix coverage for PUT /v1/environments/{environment_id}/variables
// (BE-0177). Where environment_variables_put_test.go proves the endpoint's
// wire contract (BE-0175), this file proves its authorization contract:
// action env.write cannot be bypassed by — or replace an environment's
// variables because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries the environmentIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and the
// {environment_id} PATH parameter — and CRUCIALLY pins NO ProjectID leg,
// because the bare top-level path carries no parent project_id. That is
// the load-bearing distinction from the projectIDResolver siblings
// (BE-0144 project_variables_put_policy_test.go is the structural twin
// for the project-scoped variables replace): every scoped grant in the
// engine pins a ProjectID, and the engine's covers() rule is one-way (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not). The consequence is that ALL project-, environment-, and
// service-scoped grants are denied at the boundary by
// ReasonDeniedOutOfScope — even an environment-scoped Admin grant naming
// THIS environment's id, because the grant scope's ProjectID cannot
// cover a resource scope without one. Principals whose only access is a
// scoped grant must use a parent-scoped route to replace environment
// variables; this route is reserved for org-wide write roles (owner,
// admin, developer) and org-wide write grants.
//
// env.write requires CapWrite (catalog.go: ActionEnvWrite -> CapWrite),
// the same capability class as project.update, project.delete,
// environment.create, environment.update, environment.delete,
// service.create, service.update, service.delete, domain.create, etc.
// The role matrix for a principal acting on its own organization
// therefore splits at the write tier: Owner / Admin / Developer hold
// CapWrite and are allowed (ReasonAllowedByRole); Viewer / CI / Support
// do not hold CapWrite and are denied (ReasonDeniedNoCapability). This
// is the load-bearing distinction from the env-grants put matrix
// (environment_grants_put_policy_test.go BE-0171, env.grants.write =
// CapAdmin): Developer is now in the allow set, and CI — which holds
// CapDeploy but never CapWrite — is now in the deny set even within its
// home tenant. The engine's cross-tenant support exception is gated on
// `required == CapRead || required == CapSupport`, so CapWrite is
// OUTSIDE that exception. Privileged Yalla support that needs to alter
// a customer's environment variables must go through explicit
// break-glass admin tooling, not this customer-facing route. Pinning
// the support-cross-tenant DENY at the engine here means a future
// {org_id}- or {project_id}-scoped variant inherits a working
// cross-tenant deny for env.write across every role.
//
// environment_variables rows store SECRET credential material (the
// `value` column of is_secret=true variables), so the wire-level
// redaction chokepoint is doubly load-bearing on this endpoint:
//
//   - On the ALLOW path, the response is the post-write re-read, and
//     environmentVariableOf renders is_secret=true rows as
//     output.Sentinel rather than the seeded plaintext. A denied
//     principal must never reach this allow path; the wire-level
//     redaction chokepoint pinned in environment_variables_put_test.go
//     (BE-0175) is the load-bearing guard there.
//   - On the DENY path, the response must never echo (a) any seeded
//     plaintext the canonical replacer would have returned — the
//     envVarsDenyBodyLeak guard covers that, including the canonical
//     secret plaintext — AND (b) any caller-supplied request field,
//     because the request body itself carries plaintext secrets the
//     caller is trying to set. A denied PUT must not turn into a
//     request-reflecting oracle that confirms which keys / plaintexts
//     the attacker submitted; the deny-path guards
//     replaceEnvironmentVariablesRequestBodyLeak + envVarsDenyBodyLeak
//     pin BOTH directions.
//
// Tenant-leakage and no-write invariants still apply: a denied response
// never echoes any canonical variable id / key, the foreign tenant's
// id, or the canonical environment's id; and the replacer MUST never
// run on any deny path — a scoped key denied on the wire cannot have
// upserted a row, deleted a row, or appended an audit record in the
// background.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, environmentIDResolver, or the engine fails here.
// replaceEnvironmentVariablesHandlerFor, putEnvironmentVariables,
// decodeReplaceEnvironmentVariables, fakeEnvironmentVariableReplacer,
// canonicalEnvVarsEnvironmentID, canonicalEnvVarsProjectID,
// canonicalEnvironmentVariables, envVarsDenyBodyLeak,
// canonicalEnvVarsSecretPlaintext, orgPrincipal, and decodeError are
// shared with the environment-variables put-contract suite
// (environment_variables_put_test.go), the environment-variables
// list-policy suite (environment_variables_policy_test.go), and the
// wider httpapi test fixtures; this file adds no scaffolding beyond
// the small fixture builders below.

// replaceEnvironmentVariablesMatrixSecretNeedle is a distinctive
// substring embedded in the secret variable value the matrix submits.
// It is engineered to be globally unique to this test file so the
// deny-path leak guard replaceEnvironmentVariablesRequestBodyLeak can
// detect the smallest possible echo of the caller-supplied secret.
// Because env.write is the credential-bearing write endpoint, a denied
// response that echoed even a fragment of the secret plaintext would
// be the single most damaging regression direction the policy boundary
// could open up; pinning a unique needle here means even a partial
// echo (e.g., a future renderer that surfaced the first 32 chars of
// the value in an error message) fails this guard before reaching a
// customer.
const replaceEnvironmentVariablesMatrixSecretNeedle = "evar-put-policy-matrix-secret-needle"

// replaceEnvironmentVariablesMatrixBody is the request body every test
// in this file submits on the wire. Its key names, the is_secret=true
// value (which carries replaceEnvironmentVariablesMatrixSecretNeedle),
// and the is_secret=false value are deliberately distinctive — distinct
// from the canonicalEnvironmentVariables the replacer would return on
// an allow path — so the deny-path leak guards
// (replaceEnvironmentVariablesRequestBodyLeak + envVarsDenyBodyLeak)
// cover BOTH directions: the body the caller submitted (including a
// SECRET value the caller is trying to set, which is the
// credential-bearing direction unique to env.write) and the data the
// replacer (a production-shaped fake) would have returned. A denied
// response leaking either is a separate regression direction, kept in
// one guard pair so a future renderer that gained a "render the request
// body back on error" mode (or a "render the would-have-returned data
// on a 403" mode) fails here.
//
// The wire shape carries no environment_id per variable — the
// environment is named by the path parameter, the strict JSON decoder
// rejects any unknown field on a variable, and the body schema names
// only the three legal variable fields (key, value, is_secret).
const replaceEnvironmentVariablesMatrixBody = `{"variables":[` +
	`{"key":"ATTACKER_DB_URL","value":"postgres://attacker:` + replaceEnvironmentVariablesMatrixSecretNeedle + `@db.attacker/yalla","is_secret":true},` +
	`{"key":"ATTACKER_REGION","value":"evar-put-policy-matrix-region","is_secret":false}` +
	`]}`

// replaceEnvironmentVariablesRequestBodyLeak reports whether body
// contains any caller-recognisable identifier from the request body
// the matrix submits — including the secret plaintext the caller is
// trying to set. A denied response that echoes any of these is leaking
// information about the request the caller made — and in the case of
// the secret value, the credential itself. Combined with
// envVarsDenyBodyLeak (which catches an echo of the data the replacer
// would have returned on an allow path), this pair pins both
// directions of "what a denied response must not say".
func replaceEnvironmentVariablesRequestBodyLeak(body string) bool {
	needles := []string{
		"ATTACKER_DB_URL",
		"ATTACKER_REGION",
		"evar-put-policy-matrix-region",
		replaceEnvironmentVariablesMatrixSecretNeedle,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestReplaceEnvironmentVariablesPolicyMatrixRoles drives every
// built-in role through the production request path. CapWrite splits
// the matrix one tier below the env-grants put matrix: Owner / Admin /
// Developer (own org) are allowed; Viewer / CI / Support (own org) are
// denied. The load-bearing distinctions from the env-grants put matrix
// (environment_grants_put_policy_test.go BE-0171) are that Developer
// holds CapWrite and is ADMITTED here, while CI holds CapDeploy but
// NOT CapWrite and is DENIED here even within its home tenant. The
// load-bearing distinction from the GET-variables matrix
// (environment_variables_policy_test.go BE-0174) is that Viewer and
// Support — which hold CapRead and were admitted there — are DENIED
// here, because CapRead is not CapWrite.
//
// The assertions that matter for allow rows are that the verdict is
// reached through the role (ReasonAllowedByRole), the replacer is
// reached with the principal's own home organization id, the
// {environment_id} path parameter, the caller-supplied variable set,
// AND the principal id (so the audit record names the actor verbatim),
// and the response is a stable 200 yalla.output.v1 carrying the
// canonical post-replace variables with the secret value redacted to
// output.Sentinel on the wire. For deny rows, the assertions are 403
// yalla.error.v1, the stable reason on the wire, the replacer MUST
// NEVER run (no row's value upserted in the background, no audit
// record filed), and the denied body must not echo any caller-supplied
// request field (including the secret plaintext) OR any canonical
// variables/environment identifier.
func TestReplaceEnvironmentVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	postWriteVars := canonicalEnvironmentVariables(org, envID)
	envResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
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
			// SAME-tenant environment resource; the deny rows resolve
			// via ReasonDeniedNoCapability because Viewer holds only
			// CapRead, CI holds CapDeploy but not CapWrite, and Support
			// holds CapRead + CapSupport but not CapWrite. (The
			// cross-tenant Support deny is pinned separately in
			// TestReplaceEnvironmentVariablesPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvWrite, envResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(env.write) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(env.write) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.ReplaceEnvironmentVariablesInput
			replacer := fakeEnvironmentVariableReplacer{
				vars: postWriteVars,
				got:  &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := replaceEnvironmentVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, replacer)
			rec := putEnvironmentVariables(handler, envID, "a-valid-token", replaceEnvironmentVariablesMatrixBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if captured.OrganizationID != org {
					t.Errorf("replacer received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.EnvironmentID != envID {
					t.Errorf("replacer received environment id %q, want the path parameter %q",
						captured.EnvironmentID, envID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("replacer received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.ActorOrgID != org {
					t.Errorf("replacer received actor org id %q, want the principal's home org %q",
						captured.ActorOrgID, org)
				}
				if len(captured.Variables) != 2 {
					t.Fatalf("replacer received %d variables, want 2: %+v",
						len(captured.Variables), captured.Variables)
				}
				if captured.Variables[0].Key != "ATTACKER_DB_URL" ||
					!captured.Variables[0].IsSecret ||
					!strings.Contains(captured.Variables[0].Value, replaceEnvironmentVariablesMatrixSecretNeedle) {
					t.Errorf("replacer.Variables[0] = %+v, want ATTACKER_DB_URL/is_secret=true carrying the secret needle",
						captured.Variables[0])
				}
				if captured.Variables[1].Key != "ATTACKER_REGION" ||
					captured.Variables[1].IsSecret ||
					captured.Variables[1].Value != "evar-put-policy-matrix-region" {
					t.Errorf("replacer.Variables[1] = %+v, want ATTACKER_REGION/is_secret=false/evar-put-policy-matrix-region",
						captured.Variables[1])
				}
				env := decodeReplaceEnvironmentVariables(t, rec)
				if len(env.Data.Variables) != len(postWriteVars) {
					t.Fatalf("variables len = %d, want %d; body %s",
						len(env.Data.Variables), len(postWriteVars), rec.Body.String())
				}
				// Wire-level redaction chokepoint on the allow path:
				// the post-write re-read still renders is_secret=true
				// rows as output.Sentinel rather than the seeded
				// plaintext canonicalEnvVarsSecretPlaintext. A
				// regression in environmentVariableOf that re-projected
				// a secret row's plaintext (or surfaced the canonical
				// plaintext anywhere in the body) fails here.
				got0 := env.Data.Variables[0]
				if got0.Value != output.Sentinel {
					t.Errorf("variables[0].value = %q, want the redaction sentinel %q — environmentVariableOf must redact secret values on the wire",
						got0.Value, output.Sentinel)
				}
				if body := rec.Body.String(); strings.Contains(body, canonicalEnvVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
					t.Errorf("response body %s leaked the canonical secret plaintext on an allow path — the post-write re-read renderer must redact is_secret=true values",
						body)
				}
				// And on the allow path, the caller-supplied secret
				// needle is NOT re-rendered either: the response is the
				// post-write re-read (canonical store data), not the
				// request body. A future implementation that echoed
				// the request body back into the response (instead of
				// re-reading) would land here.
				if body := rec.Body.String(); strings.Contains(body, replaceEnvironmentVariablesMatrixSecretNeedle) {
					t.Errorf("response body %s echoed the caller-supplied secret plaintext on an allow path — the response must be the post-write re-read, not the request body",
						body)
				}
				return
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(tc.reason)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, tc.reason)
			}
			if captured.OrganizationID != "" || captured.EnvironmentID != "" || len(captured.Variables) != 0 {
				t.Errorf("replacer was reached with org=%q environment=%q variables=%+v for a denied principal; it must never run",
					captured.OrganizationID, captured.EnvironmentID, captured.Variables)
			}
			body := rec.Body.String()
			if envVarsDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical environment / post-write variables (including the canonical secret plaintext): %s", body)
			}
			if replaceEnvironmentVariablesRequestBodyLeak(body) {
				t.Errorf("denied response leaked the caller-supplied replacement set (including the caller-submitted secret plaintext): %s", body)
			}
		})
	}
}

// TestReplaceEnvironmentVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both of
// which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action env.write with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it. A
// revoked or expired credential must never be able to replace the
// variables of an environment of the organization it once had access
// to, the replacer must never run, and the denied body must never echo
// the principal id, the organization id, the path-supplied environment
// id, the caller-supplied replacement set (including the secret
// plaintext), or any seeded variable data.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0177 ("revoked key,
// expired key").
func TestReplaceEnvironmentVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	postWriteVars := canonicalEnvironmentVariables(org, envID)

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

			var captured store.ReplaceEnvironmentVariablesInput
			replacer := fakeEnvironmentVariableReplacer{
				vars: postWriteVars,
				got:  &captured,
			}
			handler := replaceEnvironmentVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)
			rec := putEnvironmentVariables(handler, envID, "yk_no_longer_valid", replaceEnvironmentVariablesMatrixBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if captured.OrganizationID != "" || captured.EnvironmentID != "" || len(captured.Variables) != 0 {
				t.Errorf("replacer was reached with org=%q environment=%q variables=%+v for a disabled principal; it must never run",
					captured.OrganizationID, captured.EnvironmentID, captured.Variables)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				envVarsDenyBodyLeak(body) ||
				replaceEnvironmentVariablesRequestBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, seeded variable data (including the canonical secret plaintext), or the caller-supplied replacement set (including the caller-submitted secret plaintext)",
					body)
			}
		})
	}
}

// TestReplaceEnvironmentVariablesPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for env.write. As with env.read and
// env.grants.write, the resource org id is taken from the PRINCIPAL'S
// home org — the {environment_id} path parameter alone never widens
// the resource to another tenant, and the wire shape carries no
// organization_id field at all (the strict JSON decoder rejects an
// unknown field, and the body schema names only "variables"). Tenant
// isolation on the wire is therefore structural at the persistence
// layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PUT
//     /v1/environments/{env_victim}/variables with a valid Owner token
//     and a fully-formed replacement set reaches the engine with a
//     same-tenant resource ({org_attacker, env_victim}) — allowed by
//     the role at CapWrite — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the foreign
//     environment id. The store-backed replacer Gets the environment
//     under (organization_id, environment_id) before replacing its
//     variables, so a cross-tenant environment_id is rejected as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 200 with
//     foreign data — which would invite an attacker to believe the
//     replacement landed — and never as a 403 that would confirm
//     existence. The body must never echo the foreign org id even
//     though no wire input could place it there, because the
//     persistence layer must not leak foreign-tenant identity into the
//     error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed a
//     resource with a foreign-org scope, EVERY role MUST be denied via
//     ReasonDeniedCrossTenant — INCLUDING Support, which is OUTSIDE
//     the engine's cross-tenant exception for CapWrite actions
//     (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the env.read cross-tenant property
//     (environment_variables_policy_test.go BE-0174): read admits
//     Support cross-tenant via ReasonAllowedBySupport, but write DOES
//     NOT. Pinning that engine verdict here means the eventual scoped
//     variant inherits a working cross-tenant deny for env.write
//     across every role, and a future catalog change that downgraded
//     env.write into the support cross-tenant exception (or widened
//     the exception) would fail here before it could regress a real
//     customer.
//
// On the wire, the caller-supplied SECRET plaintext must also never
// leak — a denied cross-tenant attacker must not be able to confirm
// that its credential-bearing request was even reflected back, since
// even an empty echo could be used to probe the response shape. The
// replaceEnvironmentVariablesRequestBodyLeak guard catches the secret
// needle alongside the structural request needles.
func TestReplaceEnvironmentVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_evar"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PUT
	// /v1/environments/{env_victim}/variables with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, environmentID) pair does
	// not match a row (the replacer's environment existence check
	// fires first), so a principal whose home org is org_attacker
	// replacing variables of an environment that belongs to org_victim
	// hits the fake with (org_attacker, env_victim_evar) and gets
	// NotFound. The assertions that matter are structural: the
	// replacer is ALWAYS called with the principal's home org id —
	// never with a caller-controlled value — so a production
	// tenant-scoped EnvironmentVariableReplacer could not have
	// upserted the victim's variables regardless of database state.
	// The denied body must never echo the victim's org id, the
	// caller-supplied replacement set (including the secret
	// plaintext), or any seeded variable data.
	var captured store.ReplaceEnvironmentVariablesInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	replacer := fakeEnvironmentVariableReplacer{
		err: apierr.NotFound("environment", foreignEnvID),
		got: &captured,
	}
	handler := replaceEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, replacer)
	rec := putEnvironmentVariables(handler, foreignEnvID, "a-valid-token", replaceEnvironmentVariablesMatrixBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("replacer received org id %q, want the attacker's home org %q — the replacer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.EnvironmentID != foreignEnvID {
		t.Errorf("replacer received environment id %q, want the path parameter %q",
			captured.EnvironmentID, foreignEnvID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id — the persistence layer must redact the foreign identity",
			denyEnv.Error.Message)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id — the victim's tenant must never reach a foreign principal",
			body)
	}
	if replaceEnvironmentVariablesRequestBodyLeak(body) {
		t.Errorf("response body %s echoed the caller-supplied replacement set (including the caller-submitted secret plaintext) — a denied write must not turn into a request-reflecting oracle",
			body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// a future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. env.write is
	// CapWrite, which is OUTSIDE the engine clause
	// `CapSupport && (CapRead || CapSupport)` — so EVERY role,
	// including Support, is denied cross-tenant. This is the
	// load-bearing distinction from environment_variables_policy_test.go
	// (BE-0174), where Support IS admitted cross-tenant via
	// ReasonAllowedBySupport because env.read is CapRead.
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
			got := e.Decide(p, policy.ActionEnvWrite, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(env.write, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestReplaceEnvironmentVariablesPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// Crucially for PUT /v1/environments/{environment_id}/variables:
// env.write is evaluated against an ENVIRONMENT-level resource WITHOUT
// a ProjectID leg (the environmentIDResolver scope is {home_org,
// path_environment_id}) AND requires CapWrite — one capability tier
// below env.grants.write. This is the structural twin of
// environment_grants_put_policy_test.go (BE-0171) at one capability
// tier lower, with the consequence that the org-level allow / deny
// pair locks CapWrite specifically against the grant path:
//
//   - All scoped-grant principals are denied at this endpoint, even
//     when the grant names the target environment's own id. The
//     load-bearing property is identical to BE-0174 / BE-0171, but
//     pinned here so a future relaxation of covers() (or of
//     environmentIDResolver) would fail at this route's resource
//     scope.
//   - A project-level Developer grant naming THIS environment's parent
//     project CANNOT authorize the replace through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize env.write
//     at the parent project's project resource via the project-scoped
//     variables route — pinned at the engine.)
//   - A project-level Developer grant naming a SIBLING project also
//     CANNOT — covers() is one-way at the wire.
//   - An environment-level Developer grant naming THIS environment's
//     id CANNOT authorize the replace either, because the grant scope
//     pins ProjectID and the resource scope does not. (The grant DOES
//     authorize env.write at the env resource — pinned at the engine —
//     but not through this route's NO-ProjectID resource scope.) An
//     env grant on staging also does not imply env.write on production
//     at the engine.
//   - A service-level Developer grant CANNOT either, and at the engine
//     a service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level DEVELOPER grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because env.write is CapWrite and
//     Developer holds CapWrite — is allowed via ReasonAllowedByGrant.
//     This is the load-bearing distinction from
//     environment_grants_put_policy_test.go: there an org-developer
//     grant was DENIED (env.grants.write = CapAdmin); here an
//     org-developer grant is ALLOWED.
//   - An organization-level VIEWER grant covers the resource but
//     confers only CapRead, never CapWrite; env.write is denied via
//     ReasonDeniedNoCapability even with org-wide scope. This locks
//     the CapWrite requirement against the grant path so a future
//     catalog change that downgraded env.write to CapRead would still
//     pass the org-developer allow check but fail this org-viewer deny
//     check — so the pair of assertions is load-bearing as a unit.
//
// The acceptance criteria's four containment properties — sibling
// project, env grant not implying production, service grant shielding
// parent-level resources, deeper-scope not reaching shallower
// resource — are pinned against the engine at their natural scopes,
// then tied back to the wire by proving that ALL three scoped key
// types are denied OutOfScope against THIS endpoint (even when the
// grant names the target environment's own project or even the target
// environment's own id), while an organization-level Developer grant —
// which pins no ProjectID and covers any resource scope in the same
// org — is allowed end-to-end.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the replacer is never reached (so a production
// store could not have upserted variables in the background), and the
// body never echoes the canonical environment's or variables'
// identifiers, the canonical secret plaintext, the caller-supplied
// request body (including the caller-submitted secret plaintext), or
// the parent project's id.
func TestReplaceEnvironmentVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	envID := canonicalEnvVarsEnvironmentID
	parentProject := canonicalEnvVarsProjectID
	postWriteVars := canonicalEnvironmentVariables(org, envID)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO
	// ProjectID. Every covers() check below against this resource is
	// the engine-level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
	}

	// Project-level grant: developer on the parent project. Developer
	// confers CapWrite at the project scope, which would be enough for
	// env.write on a project-scoped variables route resource — and the
	// engine confirms that at a project resource, so the load-bearing
	// distinction between a parent-scoped route and this top-level
	// route is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: parentProject}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_evar_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(project.update) at the parent project for the target-project developer grantee = %+v, want allow via %q — a project-scoped Developer grant IS authorized for CapWrite at the parent project",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionProjectUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(project.update) at a sibling project for the target-project developer grantee = %+v, want deny via %q — a project-scoped developer grant must not reach a sibling project",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction between a parent-scoped route and this route.
	if got := e.Decide(projectDevGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: developer on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
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
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (the target environment itself) is ALSO
	// denied OutOfScope on this route, because the grant scope still
	// pins ProjectID and the resource scope does not — the env_id
	// alone is not enough to authorize a top-level replace through
	// this route. A future relaxation of covers() (e.g. allowing a
	// grant on env_X to cover a resource scope with just EnvID=env_X
	// and no ProjectID) would land here.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: envID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on a single service of the parent
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources. This is the load-bearing
	// containment criterion for env.write specifically: a service
	// grant must NEVER be widened to replace the parent environment's
	// variables (which carry secrets shared across services).
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod", ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod", ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: parentProject, EnvironmentID: "env_evar_prod"}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeSvcA}},
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
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Developer grantee hitting the
	// target environment via THIS route is a 403 with the stable
	// out-of-scope reason, the replacer is never reached (so a
	// production store could never have upserted variables in the
	// background), and the body never echoes the canonical
	// environment's identifiers, the canonical variables' identifiers
	// (including the seeded secret plaintext), the caller-supplied
	// replacement set (including the caller-submitted secret
	// plaintext), or the parent project's id. This is the property
	// that confines a project-scoped key to the project-scoped
	// variables route only.
	var projCaptured store.ReplaceEnvironmentVariablesInput
	projReplacer := fakeEnvironmentVariableReplacer{
		vars: postWriteVars, // would be returned if replacer ran — leak guard catches it
		got:  &projCaptured,
	}
	projHandler := replaceEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projReplacer)
	projRec := putEnvironmentVariables(projHandler, envID, "yk_proj_dev_scoped", replaceEnvironmentVariablesMatrixBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-variables route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCaptured.OrganizationID != "" || projCaptured.EnvironmentID != "" || len(projCaptured.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q variables=%+v for a project-scoped grantee; it must never run",
			projCaptured.OrganizationID, projCaptured.EnvironmentID, projCaptured.Variables)
	}
	if body := projRec.Body.String(); envVarsDenyBodyLeak(body) || replaceEnvironmentVariablesRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write variables (including the canonical secret plaintext) or the caller-supplied replacement set (including the caller-submitted secret plaintext): %s",
			body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME environment
	// id the path names — hitting the env-variables route is a 403,
	// the replacer is never reached, and the body never echoes the
	// canonical environment, its variables, or the caller-supplied
	// replacement set. This is the load-bearing property that locks
	// down this route: an environment grant alone does not authorize
	// variables replace through it.
	var envCaptured store.ReplaceEnvironmentVariablesInput
	envReplacer := fakeEnvironmentVariableReplacer{
		vars: postWriteVars,
		got:  &envCaptured,
	}
	envHandler := replaceEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReplacer)
	envRec := putEnvironmentVariables(envHandler, envID, "yk_env_scoped", replaceEnvironmentVariablesMatrixBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-variables route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCaptured.OrganizationID != "" || envCaptured.EnvironmentID != "" || len(envCaptured.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q variables=%+v for an env-scoped grantee; it must never run",
			envCaptured.OrganizationID, envCaptured.EnvironmentID, envCaptured.Variables)
	}
	if body := envRec.Body.String(); envVarsDenyBodyLeak(body) || replaceEnvironmentVariablesRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write variables (including the canonical secret plaintext) or the caller-supplied replacement set (including the caller-submitted secret plaintext): %s",
			body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the
	// env-variables route is a 403, the replacer is never reached, and
	// the body never echoes parent-level identifiers nor the
	// caller-supplied replacement set. This is the "service grant does
	// not expose parent-level secrets or unrelated services" criterion
	// tied to the wire on this route — and it is especially
	// load-bearing for env.write, because a service grantee gaining
	// the ability to replace the parent environment's variables would
	// be a service-account privilege escalation into shared secret
	// material.
	var svcCaptured store.ReplaceEnvironmentVariablesInput
	svcReplacer := fakeEnvironmentVariableReplacer{
		vars: postWriteVars,
		got:  &svcCaptured,
	}
	svcHandler := replaceEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReplacer)
	svcRec := putEnvironmentVariables(svcHandler, envID, "yk_svc_scoped", replaceEnvironmentVariablesMatrixBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-variables route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.EnvironmentID != "" || len(svcCaptured.Variables) != 0 {
		t.Errorf("replacer was reached with org=%q environment=%q variables=%+v for a service-scoped grantee; it must never run",
			svcCaptured.OrganizationID, svcCaptured.EnvironmentID, svcCaptured.Variables)
	}
	if body := svcRec.Body.String(); envVarsDenyBodyLeak(body) || replaceEnvironmentVariablesRequestBodyLeak(body) {
		t.Errorf("denied response leaked the canonical environment / post-write variables (including the canonical secret plaintext) or the caller-supplied replacement set (including the caller-submitted secret plaintext): %s",
			body)
	}

	// An organization-level Developer grant DOES cover any environment
	// resource in the same org (its grant scope pins nothing past
	// OrganizationID) and — because env.write is CapWrite and
	// Developer holds CapWrite — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the
	// replacer reached on the principal's home org id and the path
	// environment id, AND the post-write response still redacts the
	// canonical secret value to output.Sentinel — locking the wire
	// chokepoint on the grant-allow path too.
	orgDevGrantee := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDevGrantee, policy.ActionEnvWrite, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.ReplaceEnvironmentVariablesInput
	orgReplacer := fakeEnvironmentVariableReplacer{
		vars: postWriteVars,
		got:  &orgCaptured,
	}
	orgHandler := replaceEnvironmentVariablesHandlerFor(
		auth.Identity{Principal: orgDevGrantee, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putEnvironmentVariables(orgHandler, envID, "yk_org_dev", replaceEnvironmentVariablesMatrixBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeReplaceEnvironmentVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != len(postWriteVars) {
		t.Errorf("variables len = %d, want %d",
			len(allowedPayload.Data.Variables), len(postWriteVars))
	}
	// Wire-level redaction chokepoint on the grant-allow path: the
	// post-write re-read still renders is_secret=true rows as
	// output.Sentinel rather than the seeded plaintext. A regression
	// in environmentVariableOf that re-projected a secret row's
	// plaintext only on the role-allow path (and not on the
	// grant-allow path) would land here.
	if got0 := allowedPayload.Data.Variables[0]; got0.Value != output.Sentinel {
		t.Errorf("variables[0].value = %q on the grant-allow path, want the redaction sentinel %q",
			got0.Value, output.Sentinel)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, canonicalEnvVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("grant-allow response body %s leaked the canonical secret plaintext — the post-write re-read renderer must redact is_secret=true values on every allow path",
			body)
	}
	if body := allowedRec.Body.String(); strings.Contains(body, replaceEnvironmentVariablesMatrixSecretNeedle) {
		t.Errorf("grant-allow response body %s echoed the caller-supplied secret plaintext — the response must be the post-write re-read, not the request body",
			body)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.EnvironmentID != envID {
		t.Errorf("replacer received environment id %q, want the path parameter %q",
			orgCaptured.EnvironmentID, envID)
	}
	if orgCaptured.ActorID != orgDevGrantee.ID {
		t.Errorf("replacer received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgDevGrantee.ID)
	}
	if orgCaptured.ActorOrgID != org {
		t.Errorf("replacer received actor org id %q, want the principal's home org %q",
			orgCaptured.ActorOrgID, org)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; env.write must be denied via
	// ReasonDeniedNoCapability even with org-wide scope. Pairing this
	// deny with the org-developer allow above locks the CapWrite
	// requirement against the grant path: a future catalog change
	// that downgraded env.write to CapRead would still pass the
	// org-developer allow check but fail this org-viewer deny check —
	// so the pair of assertions is load-bearing as a unit.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(env.write) at the env-id route's resource scope for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped developer grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to replace environment
	// variables in org_sibling — the cross-tenant guard fires first
	// because the principal's home org no longer matches the grant's
	// scope. This is the engine-level twin of the wire-level "wrong
	// organization" property in
	// TestReplaceEnvironmentVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. env.write is OUTSIDE the support cross-tenant
	// exception regardless, but the assertion here is structural: a
	// scoped key's home org must match the grant scope's org or the
	// engine refuses to consider the grant at all.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: "org_sibling", EnvironmentID: envID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvWrite, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.write) for a project-scoped developer key planted in a foreign org = %+v, want deny",
			got)
	}
}
