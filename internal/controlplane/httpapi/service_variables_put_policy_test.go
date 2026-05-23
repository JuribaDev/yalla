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

// Policy-matrix coverage for PUT /v1/services/{service_id}/variables
// (BE-0204). Where service_variables_put_test.go proves the endpoint's
// wire contract (BE-0203), this file proves its authorization
// contract: that action env.write cannot be bypassed by — or persist a
// mutation because of — the principal's role, revoked credentials,
// home organization, or scoped grants, and that no deny path ever
// leaks a foreign service's variables (least of all secret-variable
// plaintext the caller just submitted).
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the bare-id GET /v1/services/{service_id}/variables (BE-0201), the
// bare-id GET /v1/services/{service_id}, and the bare-id GET
// /v1/services/{service_id}/rendered routes carry. The authorization
// contract here is the structural twin of services_update_policy_test
// .go (BE-0189) and environment_variables_put_policy_test.go
// (BE-0177): the policy resource is built from the principal's HOME
// organization id and the {service_id} PATH parameter, with NO
// ProjectID leg — the bare top-level path carries no parent
// project_id. The engine's covers() rule is one-way (a grant scope
// that pins ProjectID cannot cover a resource scope that does not),
// so ALL project-, environment-, and service-scoped grants are denied
// at the boundary by ReasonDeniedOutOfScope — even a service-scoped
// Admin grant naming THIS service's id, because the grant scope pins
// a ProjectID the resource scope does not. Principals whose only
// access is a scoped grant must use a parent-scoped route family to
// address a service-scoped variable replace; this route is reserved
// for org-wide write roles (owner, admin, developer) and org-wide
// grants.
//
// env.write requires CapWrite (catalog.go: ActionEnvWrite ->
// CapWrite), the same capability class as service.create /
// service.update / environment.create / project.create. The role
// matrix for a principal acting on its own organization therefore
// splits along the write capability class: Owner / Admin / Developer
// hold CapWrite and are allowed (ReasonAllowedByRole); Viewer / CI /
// Support do not hold CapWrite and are denied
// (ReasonDeniedNoCapability) — CI holds CapDeploy (the deploy
// capability is for service lifecycle and rollouts, not variable
// replacement), so a CI key cannot replace variables even within its
// home tenant. This is the load-bearing distinction
// from the env.read matrix (service_variables_policy_test.go, "all
// six roles allow"): two roles deny here at the role boundary, and —
// crucially — the engine's cross-tenant support exception is gated
// on `required == CapRead || required == CapSupport`, so CapWrite is
// OUTSIDE that exception. Privileged Yalla support that needs to
// mutate a customer's service variables must go through explicit
// break-glass admin tooling, not this customer-facing route.
//
// service_variables rows carry value plaintext on insert, so the
// load-bearing wire distinction this matrix pins (beyond the
// services_update_policy_test.go shape) is the secret-redaction
// chokepoint: a denied response must never reveal the caller's
// just-submitted plaintext, even though the body that arrived at the
// handler carried that plaintext verbatim, and the replacer's canned
// post-write payload also contains that plaintext for the leak guard
// to needle.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, serviceIDResolver, or the engine fails here.
// replaceServiceVariablesHandlerFor, putServiceVariables,
// decodeReplaceServiceVariables, fakeServiceVariableReplacer,
// orgPrincipal, seedServiceVariableWire, and decodeError are shared
// with the replace-service-variables contract suite
// (service_variables_put_test.go) and the wider httpapi test
// fixtures; this file adds no scaffolding beyond the small fixture
// builders below.

// canonicalReplaceSvcVarsForMatrix is the row every test in this file
// would receive back from the replacer on an allow path. Its ids /
// keys / values are deliberately distinct from the canonical fixtures
// the other service-variable suites use so the matrices cannot
// accidentally share fixture state through a future shared fake, and
// they are deliberately recognisable so deny-path leak guards can
// needle for them; allow-path assertions compare against the same
// canonical values. The fixture carries one secret variable
// (svar_db_replace) whose plaintext is the strongest leak needle in
// this suite — a denied 403 that rendered the seeded value would
// expose a secret to a principal the engine just rejected.
func canonicalReplaceSvcVarsForMatrix(orgID, svcID string) []store.ServiceVariable {
	created := time.Date(2026, 1, 18, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 16, 11, 12, 13, 0, time.UTC)
	return []store.ServiceVariable{
		seedServiceVariableWire("svar_db_replace", orgID, svcID, "DATABASE_URL_REPLACE", "postgres://matrix-user:matrix-secret-hunter2@db.matrix.internal/replace", true, 4, created, updated),
		seedServiceVariableWire("svar_region_replace", orgID, svcID, "REGION_REPLACE", "us-matrix-west-1", false, 1, created, created),
	}
}

// The canonical PUT request body every test in this file shares. It
// supplies a fresh replacement set that includes a secret variable so
// the deny-path leak guard has something concrete to needle for. The
// distinctive plaintext fragments are deliberately recognisable so
// the wire's redaction chokepoint must hold even when the caller has
// just handed the plaintext to the handler.
const (
	canonicalReplaceSvcVarsSecretKey      = "DATABASE_URL_REPLACE"
	canonicalReplaceSvcVarsSecretValue    = "postgres://matrix-user:matrix-secret-hunter2@db.matrix.internal/replace"
	canonicalReplaceSvcVarsNonSecretKey   = "REGION_REPLACE"
	canonicalReplaceSvcVarsNonSecretValue = "us-matrix-west-1"
	canonicalReplaceSvcVarsBody           = `{"variables":[{"key":"DATABASE_URL_REPLACE","value":"postgres://matrix-user:matrix-secret-hunter2@db.matrix.internal/replace","is_secret":true},{"key":"REGION_REPLACE","value":"us-matrix-west-1"}]}`
)

// replaceSvcVarsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical replacement set, the
// canonical service, or the caller-supplied request-body fields. A
// denied response that accidentally rendered any of these fails the
// test — a denied request-body field would mean the handler echoed the
// request after policy denial (a tenant-boundary smell), and a denied
// canonical-row field would mean the replacer ran and the response
// leaked its output even though the wire said 403. Most critically,
// the secret plaintext "matrix-secret-hunter2" the caller just
// submitted must NEVER appear on a deny path — the redaction
// chokepoint is non-negotiable, even when the engine denies the
// request after the body decoder accepted it.
func replaceSvcVarsDenyBodyLeak(body string) bool {
	needles := []string{
		"svar_db_replace",
		"svar_region_replace",
		"matrix-secret-hunter2",
		"postgres://matrix-user",
		"db.matrix.internal",
		"matrix-user",
		"\"" + canonicalReplaceSvcVarsSecretKey + "\"",
		"\"" + canonicalReplaceSvcVarsNonSecretKey + "\"",
		"\"" + canonicalReplaceSvcVarsNonSecretValue + "\"",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestReplaceServiceVariablesPolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner / Admin / Developer (own org) are allowed; Viewer /
// CI / Support (own org) are denied. The assertions that matter
// for allow rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the replacer is reached with the principal's
// own home organization id, the {service_id} path parameter, the
// principal id (so the audit record names the actor verbatim), and
// the decoded variables; the response is a stable 200 yalla.output.v1
// carrying the canonical replacement set with secret values
// redacted to output.Sentinel — the redaction chokepoint must hold
// for every allow row even when the caller just submitted the
// plaintext. For deny rows, the assertions are 403 yalla.error.v1,
// the stable reason on the wire, the replacer MUST NEVER run (no row
// mutated in the background), and the denied body must not echo the
// canonical variables, the request body, or — load-bearing — the
// caller's just-submitted secret plaintext.
func TestReplaceServiceVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_matrix_var_replace"
	)
	canonical := canonicalReplaceSvcVarsForMatrix(org, svcID)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
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
			// SAME-tenant service resource; the deny rows resolve via
			// ReasonDeniedNoCapability because Viewer / Support hold
			// CapRead (and Support CapSupport) but not CapWrite. (The
			// cross-tenant Support deny is pinned separately in
			// TestReplaceServiceVariablesPolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvWrite, svcResource)
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

			var captured store.ReplaceServiceVariablesInput
			callCount := 0
			replacer := fakeServiceVariableReplacer{
				vars:      canonical,
				got:       &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := replaceServiceVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, replacer)
			rec := putServiceVariables(handler, svcID, "a-valid-token", canonicalReplaceSvcVarsBody)

			if tc.allow {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("replacer call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("replacer received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svcID {
					t.Errorf("replacer received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("replacer received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if len(captured.Variables) != 2 {
					t.Fatalf("replacer received %d variables, want 2", len(captured.Variables))
				}
				if captured.Variables[0].Key != canonicalReplaceSvcVarsSecretKey ||
					captured.Variables[0].Value != canonicalReplaceSvcVarsSecretValue ||
					!captured.Variables[0].IsSecret {
					t.Errorf("replacer variables[0] = %+v, want %s/%s/is_secret=true",
						captured.Variables[0], canonicalReplaceSvcVarsSecretKey, canonicalReplaceSvcVarsSecretValue)
				}
				env := decodeReplaceServiceVariables(t, rec)
				if len(env.Data.Variables) != 2 {
					t.Fatalf("variables len = %d, want 2 (body %s)", len(env.Data.Variables), rec.Body.String())
				}
				// Wire-level redaction chokepoint: even on the allow
				// path, with the caller having just submitted the
				// plaintext, the secret value renders as the sentinel.
				if env.Data.Variables[0].IsSecret && env.Data.Variables[0].Value != output.Sentinel {
					t.Errorf("variables[0].Value = %q, want output.Sentinel for is_secret=true",
						env.Data.Variables[0].Value)
				}
				// The allow path's response also must not leak the
				// just-submitted secret plaintext — the redaction
				// chokepoint is non-negotiable.
				body := rec.Body.String()
				for _, leak := range []string{"matrix-secret-hunter2", "postgres://matrix-user", "db.matrix.internal"} {
					if strings.Contains(body, leak) {
						t.Errorf("allow path body leaks secret fragment %q: %s", leak, body)
					}
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
				t.Errorf("replacer was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("replacer captured org=%q svc=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID)
			}
			if body := rec.Body.String(); replaceSvcVarsDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical variables, the just-submitted secret plaintext, or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestReplaceServiceVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action env.write with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to replace
// variables of the organization it once had access to, the replacer
// must never run, and the denied body must never echo the principal
// id, the organization id, the path-supplied service id, the
// caller-supplied request-body fields, or any seeded variable data —
// least of all the just-submitted secret plaintext.
//
// Underlying role is Owner so a working credential WOULD allow
// env.write; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0204 ("revoked key,
// expired key").
func TestReplaceServiceVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_matrix_var_replace"
	)
	canonical := canonicalReplaceSvcVarsForMatrix(org, svcID)

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

			var captured store.ReplaceServiceVariablesInput
			callCount := 0
			replacer := fakeServiceVariableReplacer{
				vars:      canonical,
				got:       &captured,
				callCount: &callCount,
			}
			handler := replaceServiceVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, replacer)
			rec := putServiceVariables(handler, svcID, "yk_no_longer_valid", canonicalReplaceSvcVarsBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("replacer was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				replaceSvcVarsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, request body, or seeded variable data", body)
			}
		})
	}
}

// TestReplaceServiceVariablesPolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for env.write on the service-id route.
// As with env.read on the same route, the resource org id is taken
// from the PRINCIPAL'S home org — the {service_id} path parameter
// alone never widens the resource to another tenant. Tenant
// isolation on the wire is therefore structural at the persistence
// layer, not the policy boundary:
//
//   - A principal in org_attacker hitting PUT /v1/services/
//     {svc_victim}/variables with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, svc_victim})
//     — allowed by the role at CapWrite — and then reaches the
//     tenant-scoped repository query with the principal's home org id
//     and the foreign service id. A production *store.
//     ServiceVariableService (which combines organization_id and
//     service_id in its existence check) cannot match a row that
//     belongs to another tenant, so the request surfaces as a
//     deterministic 404 E_NOT_FOUND, never disguised as a 200 with
//     foreign data and never as a 403 that would confirm existence.
//     The body must never echo the foreign org id even though no wire
//     input could place it there, because the persistence layer must
//     not leak foreign-tenant identity into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the env.read cross-tenant
//     property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but env.write DOES NOT. Pinning that
//     engine verdict here means a future endpoint that resolves the
//     resource into a foreign-org scope inherits a working
//     cross-tenant deny for env.write across every role, and a future
//     catalog change that downgraded env.write into the support
//     cross-tenant exception (or widened the exception) would fail
//     here before it could regress a real customer.
func TestReplaceServiceVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_var_replace"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits PUT
	// /v1/services/{svc_victim}/variables with a valid Owner token.
	// The fake mirrors the production store contract: it returns
	// NotFound whenever the (organizationID, serviceID) pair does not
	// match a row, so a principal whose home org is org_attacker
	// targeting a service that belongs to org_victim hits the fake
	// with (org_attacker, svc_victim_var_replace) and gets NotFound.
	// The assertions that matter are structural: the replacer is
	// ALWAYS called with the principal's home org id — never with a
	// caller-controlled value — so a production tenant-scoped
	// ServiceVariableService could not have mutated the victim's
	// variables regardless of database state. The denied body must
	// never echo the victim's org id or the just-submitted secret
	// plaintext.
	var captured store.ReplaceServiceVariablesInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	replacer := fakeServiceVariableReplacer{
		err:       apierr.NotFound("service", foreignSvcID),
		got:       &captured,
		callCount: &callCount,
	}
	handler := replaceServiceVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, replacer)
	rec := putServiceVariables(handler, foreignSvcID, "a-valid-token", canonicalReplaceSvcVarsBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant service_id surfaces as NotFound, never 200 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("replacer call count = %d, want 1 — the replacer runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign service id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("replacer received org id %q, want the attacker's home org %q — the replacer must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID {
		t.Errorf("replacer received service id %q, want the path parameter %q",
			captured.ServiceID, foreignSvcID)
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
	// The 404 path must not echo the caller's just-submitted secret
	// plaintext either — even an error response carries no part of
	// the request body.
	for _, leak := range []string{"matrix-secret-hunter2", "postgres://matrix-user", "db.matrix.internal"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("404 body leaks the just-submitted secret fragment %q: %s", leak, rec.Body.String())
		}
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. env.write is
	// CapWrite, which is OUTSIDE the engine clause `CapSupport &&
	// (CapRead || CapSupport)` — so EVERY role, including Support,
	// is denied cross-tenant.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: victimOrg, ServiceID: foreignSvcID},
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

// TestReplaceServiceVariablesPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO ProjectID
// leg on the resource scope and the engine's covers() rule is one-way
// (a grant scope that pins ProjectID cannot cover a resource scope
// that does not).
//
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant shielding
// parent-level resources and unrelated services — are pinned against
// the engine at their natural scopes (a project resource, an env
// resource, a service resource), then tied back to the wire by
// proving that ALL three scoped key types are denied OutOfScope
// against THIS endpoint (even when the grant names the target
// service's own project, its own environment, or its own id), while
// an organization-level Admin grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed end-to-end.
//
//   - A project-level Admin grant naming THIS service's parent
//     project CANNOT authorize the replace through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize env.write
//     at a service resource in that project — that is the parent-
//     scoped route's job — and the engine pins that property here so
//     the load-bearing distinction between the two routes'
//     authorization surfaces is explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a service resource in the sibling
//     project.
//   - An environment-level Admin grant naming THIS service's parent
//     environment CANNOT authorize the replace either, because the
//     grant scope pins ProjectID and the resource scope does not.
//     (The grant DOES authorize env.write at a service inside the
//     granted env — pinned at the engine — but a staging-scoped
//     grant does not reach production unless production is explicitly
//     granted.)
//   - A service-level Admin grant naming THIS service's id CANNOT
//     either, and at the engine a service grant does not expose
//     env.write on the parent environment nor reach an unrelated
//     sibling service.
//   - An organization-level Admin grant DOES cover any resource
//     scope in the same org and — because env.write is CapWrite and
//     Admin holds CapWrite — is allowed via ReasonAllowedByGrant.
//   - An organization-level VIEWER grant covers the resource but
//     confers no write capability; env.write is denied via
//     ReasonDeniedNoCapability. This is the load-bearing distinction
//     from the env.read grant matrix where an org-level Viewer is
//     allowed.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the replacer is never reached (so a
// production store could never have mutated a row in the
// background), and the body never echoes the canonical replacement
// set, the just-submitted secret plaintext, or the caller-supplied
// request body.
func TestReplaceServiceVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_var_matrix_parent"
		env     = "env_svc_var_matrix_parent"
		svcID   = "svc_matrix_var_replace"
	)
	canonical := canonicalReplaceSvcVarsForMatrix(org, svcID)
	e := policy.NewEngine()

	// Resource the service-id route resolves to: OrganizationID from
	// the principal's home org, ServiceID from the path, NO ProjectID
	// and NO EnvironmentID. Every covers() check below against this
	// resource is the engine-level twin of the wire-level deny on
	// this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: admin on the parent project. Admin
	// confers CapWrite at the project scope, which would normally be
	// enough for env.write on a service resource inside that project
	// — and the engine confirms that at a service resource nested
	// inside the parent project, so the load-bearing distinction
	// between this route and a parent-scoped route is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_var_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvWrite, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) at the parent project's service for the target-project admin grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvWrite, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_svc_var_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at a sibling project's service for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Pin the sibling-project containment at the project resource
	// too, to lock the "project-level grants do not imply access to
	// sibling projects" acceptance criterion regardless of which
	// child resource a future endpoint might resolve.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at a sibling project for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from any parent-scoped route.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a service resource inside the parent
	// project (which the parent-scoped route would target), env.write
	// must fail with ReasonDeniedNoCapability — a viewer grant does
	// not widen to a write action even when its scope contains the
	// resource.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvWrite, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(env.write) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property
	// is pinned at the engine against env / service resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	scopeProduction := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("env.write on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("env.write on a service inside production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// Pin the env-to-env containment at the env resource too, so the
	// acceptance criterion is locked regardless of which child the
	// engine sees.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// env-staging grant is denied OutOfScope at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (env_svc_var_matrix_parent itself) is
	// ALSO denied OutOfScope on this route, because the grant scope
	// still pins ProjectID and the resource scope does not — the
	// env_id alone is not enough to authorize a top-level replace
	// through this route. This is the load-bearing property that
	// locks down the service-id route: an environment grant alone
	// does not authorize mutations through it.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for a grant on the SAME parent env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service. The "service
	// grant does not expose parent-level secrets or unrelated
	// services" property is pinned at the engine against service /
	// env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_a"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_b"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("env.write on the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("env.write on a sibling service = %+v, want deny — a service grant must not reach svc_b",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("env.write on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	// And the service grant naming THIS service's own id is still
	// denied OutOfScope at this route's resource scope, because the
	// grant scope pins ProjectID and the resource scope does not — a
	// service grant alone cannot authorize the bare service-id route.
	scopeTargetSvc := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcTargetGrantee := policy.Principal{
		ID: "sa_svc_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetSvc}},
	}
	if got := e.Decide(svcTargetGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for a grant on the SAME service id = %+v, want deny via %q — covers() is one-way, the service_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// service grant on a sibling service is also denied OutOfScope.
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// target service via THIS route is a 403 with the stable
	// out-of-scope reason, the replacer is never reached (so a
	// production store could never have mutated a row in the
	// background), and the body never echoes the canonical variables
	// or the just-submitted secret plaintext.
	var projCaptured store.ReplaceServiceVariablesInput
	projCallCount := 0
	projReplacer := fakeServiceVariableReplacer{
		vars:      canonical, // would be returned if replacer ran — leak guard catches it
		got:       &projCaptured,
		callCount: &projCallCount,
	}
	projHandler := replaceServiceVariablesHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projReplacer)
	projRec := putServiceVariables(projHandler, svcID, "yk_proj_admin_scoped", canonicalReplaceSvcVarsBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the service-id route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projCaptured.OrganizationID != "" || projCaptured.ServiceID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q svc=%q) for a project-scoped grantee; it must never run",
			projCallCount, projCaptured.OrganizationID, projCaptured.ServiceID)
	}
	if body := projRec.Body.String(); replaceSvcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical variables, the just-submitted secret plaintext, or caller-supplied request body: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME parent
	// environment id — hitting the service-id route is a 403, the
	// replacer is never reached, and the body never echoes the
	// canonical variables or the just-submitted secret plaintext.
	var envCaptured store.ReplaceServiceVariablesInput
	envCallCount := 0
	envReplacer := fakeServiceVariableReplacer{
		vars:      canonical,
		got:       &envCaptured,
		callCount: &envCallCount,
	}
	envHandler := replaceServiceVariablesHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReplacer)
	envRec := putServiceVariables(envHandler, svcID, "yk_env_scoped", canonicalReplaceSvcVarsBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the service-id route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envCaptured.OrganizationID != "" || envCaptured.ServiceID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q svc=%q) for an env-scoped grantee; it must never run",
			envCallCount, envCaptured.OrganizationID, envCaptured.ServiceID)
	}
	if body := envRec.Body.String(); replaceSvcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical variables, the just-submitted secret plaintext, or caller-supplied request body: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee — on the SAME
	// service id the path names — hitting the service-id route is a
	// 403, the replacer is never reached, and the body never echoes
	// parent-level identifiers — the "service grant does not expose
	// parent-level secrets or unrelated services" criterion tied to
	// the wire on this route.
	var svcCaptured store.ReplaceServiceVariablesInput
	svcCallCount := 0
	svcReplacer := fakeServiceVariableReplacer{
		vars:      canonical,
		got:       &svcCaptured,
		callCount: &svcCallCount,
	}
	svcHandler := replaceServiceVariablesHandlerFor(
		auth.Identity{Principal: svcTargetGrantee, Method: auth.MethodAPIKey}, nil, svcReplacer)
	svcRec := putServiceVariables(svcHandler, svcID, "yk_svc_scoped", canonicalReplaceSvcVarsBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the service-id route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcCaptured.OrganizationID != "" || svcCaptured.ServiceID != "" {
		t.Errorf("replacer was reached (calls=%d org=%q svc=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcCaptured.OrganizationID, svcCaptured.ServiceID)
	}
	if body := svcRec.Body.String(); replaceSvcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical variables, the just-submitted secret plaintext, or caller-supplied request body: %s", body)
	}

	// An organization-level Admin grant DOES cover any resource scope
	// in the same org (its grant scope pins nothing past
	// OrganizationID) and — because env.write is CapWrite and Admin
	// holds CapWrite — is allowed via ReasonAllowedByGrant. The same
	// key is end-to-end allowed at the wire, with the replacer
	// reached on the principal's home org id, the path service id,
	// and the principal id. This locks the CapWrite requirement
	// against the grant path so a future catalog change that
	// upgraded env.write above CapWrite would fail here (silently
	// denying every org-level Admin grantee) before it could regress
	// a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionEnvWrite, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.write) at the service-id route's resource scope for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.ReplaceServiceVariablesInput
	orgCallCount := 0
	orgReplacer := fakeServiceVariableReplacer{
		vars:      canonical,
		got:       &orgCaptured,
		callCount: &orgCallCount,
	}
	orgHandler := replaceServiceVariablesHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgReplacer)
	allowedRec := putServiceVariables(orgHandler, svcID, "yk_org_admin", canonicalReplaceSvcVarsBody)
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeReplaceServiceVariables(t, allowedRec)
	if len(allowedPayload.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2 on the allow path; body %s",
			len(allowedPayload.Data.Variables), allowedRec.Body.String())
	}
	// Wire-level redaction chokepoint on the org-grant allow path:
	// the secret value is still the sentinel.
	if allowedPayload.Data.Variables[0].IsSecret && allowedPayload.Data.Variables[0].Value != output.Sentinel {
		t.Errorf("variables[0].Value = %q, want output.Sentinel for is_secret=true",
			allowedPayload.Data.Variables[0].Value)
	}
	if orgCallCount != 1 {
		t.Errorf("replacer call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("replacer received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ServiceID != svcID {
		t.Errorf("replacer received service id %q, want the path parameter %q",
			orgCaptured.ServiceID, svcID)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID {
		t.Errorf("replacer received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgAdminGrantee.ID)
	}
	// Even on the org-grant allow path the secret plaintext must not
	// surface — the redaction chokepoint holds for every authorized
	// principal too.
	for _, leak := range []string{"matrix-secret-hunter2", "postgres://matrix-user", "db.matrix.internal"} {
		if strings.Contains(allowedRec.Body.String(), leak) {
			t.Errorf("org-grant allow body leaks secret fragment %q: %s", leak, allowedRec.Body.String())
		}
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; env.write must be denied via
	// ReasonDeniedNoCapability even though the grant scope is the
	// whole org. This is the load-bearing distinction from the
	// env.read grant matrix: an org-level Viewer is ALLOWED for read
	// but DENIED for write.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvWrite, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(env.write) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id is
	// foreign is denied at the engine: a grant for the parent project
	// inside org_acme, carried by a principal whose home org id is
	// org_sibling, cannot be used to replace variables in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in TestReplaceServiceVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (env.write is OUTSIDE the support cross-tenant
	// exception regardless, but the assertion here is structural: a
	// scoped key's home org must match the grant scope's org or the
	// engine refuses to consider the grant at all.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvWrite, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.write) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
