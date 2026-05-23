package httpapi

import (
	"net/http"
	"net/http/httptest"
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

// Policy-matrix coverage for GET /v1/services/{service_id}/variables
// (BE-0201). Where service_variables_test.go proves the endpoint's
// wire contract (BE-0199), this file proves its authorization
// contract: that action env.read cannot be bypassed by — or leak a
// foreign service's variables (and especially secret-variable
// plaintext) on account of — the principal's role, revoked
// credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the bare-id GET /v1/services/{service_id} and GET
// /v1/services/{service_id}/rendered routes carry, so the
// authorization contract here is the structural twin of
// services_get_policy_test.go (BE-0186) and
// services_rendered_policy_test.go (BE-0198): the policy resource is
// built from the principal's HOME organization id and the
// {service_id} PATH parameter, with NO ProjectID leg — the bare
// top-level path carries no parent project_id. The engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not), so ALL project-, environment-, and
// service-scoped grants are denied at the boundary by
// ReasonDeniedOutOfScope — even a service-scoped Admin grant naming
// THIS service's id, because the grant scope pins a ProjectID the
// resource scope does not. Principals whose only access is a scoped
// grant must use a parent-scoped route family to address a service
// by its (project, environment, service) tuple; this route is
// reserved for org-wide read roles (owner, admin, developer, viewer,
// ci) and org-wide grants.
//
// env.read requires CapRead (catalog.go: ActionEnvRead -> CapRead),
// the same capability class as environment.read, project.read,
// service.read, limits.read, usage.read, and the grants-read
// actions. All six built-in roles hold CapRead, so the role matrix
// for a principal reading variables of a service in its own
// organization is "all allow"; the assertions that matter are that
// the verdict is reached through the role (ReasonAllowedByRole), the
// reader is called with the principal's own home organization id AND
// the {service_id} path parameter (so a tenant-scoped GetByID query
// cannot match a service in another tenant), the response is a
// stable 200 yalla.output.v1 envelope carrying the canonical
// variable list, and — the load-bearing wire distinction from the
// services_rendered matrix — secret variable values project as
// output.Sentinel rather than the seeded plaintext. A regression in
// serviceVariableOf would surface the secret plaintext on every
// allow row here, before any deny-path leak guard fires.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapRead is INSIDE that exception, so a Support
// principal authorizing env.read against a foreign-tenant resource
// IS allowed via ReasonAllowedBySupport — the same property
// environment_variables_policy_test.go (env-id route) and
// services_rendered_policy_test.go (service-id route) pin. Every
// non-support role is denied with ReasonDeniedCrossTenant. The
// customer-facing route under test cannot reach that engine branch
// by construction (serviceIDResolver pins the resource scope to the
// PRINCIPAL'S home org, not the path's tenant — the support
// cross-tenant exception specifically does NOT apply through this
// endpoint, as the resolver doc and route description make
// explicit), but pinning the engine verdict here means a future
// endpoint that resolves the resource into a foreign-org scope (a
// hypothetical admin tool) inherits a working cross-tenant deny and
// the documented support exception, and a future catalog change
// that upgraded env.read above CapRead would fail here (silently
// denying every support cross-tenant service-variables read) before
// it could regress a real customer.
//
// Unlike services / services_rendered rows, service_variables rows
// DO carry credential material in the form of secret values. The
// wire chokepoint for that material is serviceVariableOf
// (service_variables.go): is_secret=true rows project Value as
// output.Sentinel rather than the seeded plaintext. The deny-path
// leak guard (svcVarsDenyBodyLeak) is therefore anchored on the
// SECRET PLAINTEXT (in addition to the canonical variable ids,
// keys, the non-secret value, and the parent service/project/env
// ids), because a denied response that accidentally surfaced the
// secret plaintext would be a critical credential leak — the
// strongest possible regression this route can carry. Tenant-leakage
// and no-read invariants apply: a denied response never echoes any
// seeded variable id / key / non-secret value, the secret plaintext,
// the foreign tenant's id, or the canonical service's id; and the
// reader MUST never run on any deny path — a scoped key denied on
// the wire cannot have surfaced a variable row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, serviceIDResolver, or the engine fails here.
// getServiceVariables, decodeListServiceVariables,
// fakeServiceVariableReader, seedServiceVariableWire, orgPrincipal,
// listServiceVariablesHandlerFor, and decodeError are shared with
// the service-variables contract suite (service_variables_test.go)
// and the wider httpapi test fixtures; this file is a focused matrix
// overlay only — adding distinct canonical fixtures and a per-leak-
// guard so the service-variables matrix cannot accidentally share
// fixture state with the services / services_rendered matrices
// through a future shared fake.

// canonicalSvcVarsServiceID is the {service_id} every test in this
// file targets through the wire. It is deliberately distinct from
// the canonical service ids used by the services / services_rendered
// matrices so the deny-path leak guards can needle for it without
// false-positive overlap with sibling matrices that might be
// rendered into the same JSON body by a future shared response
// helper. The service id is opaque to this endpoint: unlike the
// rendered route, the variables list endpoint does NOT compute
// domain.DokployName on the row, so a non-canonical id like
// "svc_svar_matrix" is safe here (and matches the existing
// service_variables_test.go convention of using simple ids).
const (
	canonicalSvcVarsServiceID = "svc_svar_matrix"
	canonicalSvcVarsOrgID     = "org_acme"
	canonicalSvcVarsProjectID = "prj_svc_svar_matrix_parent"
	canonicalSvcVarsEnvID     = "env_svc_svar_matrix_parent"
)

// canonicalSvcVarsSecretPlaintext is the seeded plaintext of the
// secret variable canonicalServiceVariables returns. It MUST never
// reach the wire — serviceVariableOf replaces secret values with
// output.Sentinel — and it is the load-bearing needle
// svcVarsDenyBodyLeak watches for. A regression in the redaction
// chokepoint, or a renderer that surfaced an unredacted row on a
// deny path, would render this plaintext, and the leak guard
// catches it.
const canonicalSvcVarsSecretPlaintext = "postgres://user:hunter2@db.internal/svar-matrix"

// canonicalServiceVariables is the variable list every test in this
// file would receive back from the reader on an allow path. It
// mixes a secret DATABASE_URL with a non-secret REGION so the wire
// projection exercises the redaction chokepoint on the secret row
// and the verbatim pass-through on the non-secret row. Deny-path
// leak guards needle for the distinctive variable ids, keys, the
// non-secret value, AND the secret plaintext so an accidental
// render — even a partial one — fails the test.
func canonicalServiceVariables() []store.ServiceVariable {
	created := time.Date(2026, 3, 9, 14, 15, 16, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 18, 19, 20, 0, time.UTC)
	return []store.ServiceVariable{
		seedServiceVariableWire("svar_matrix_db", canonicalSvcVarsOrgID, canonicalSvcVarsServiceID, "DATABASE_URL", canonicalSvcVarsSecretPlaintext, true, 5, created, updated),
		seedServiceVariableWire("svar_matrix_region", canonicalSvcVarsOrgID, canonicalSvcVarsServiceID, "REGION", "us-east-1", false, 1, created, created),
	}
}

// svcVarsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical service or its
// variables, OR — the load-bearing addition over the structural
// rendered/services leak guards — the secret variable's plaintext.
// A denied response that accidentally rendered any of these fails
// the test:
//
//   - a denied response that surfaced the secret PLAINTEXT would be
//     a critical credential leak, the strongest possible regression
//     this route can carry. The reader never runs on a deny path,
//     but the leak guard anchors the contract against a hypothetical
//     future handler that materialised rows before the policy
//     boundary.
//   - a denied response that surfaced a row's structural identity
//     (id, key, non-secret value) leaks the existence of the row,
//     which is itself information a denied principal must not
//     receive.
//   - a denied response that surfaced the parent service id, the
//     parent project id, or the parent environment id would leak
//     hierarchy structure to a foreign principal.
//
// There is no request body for GET /v1/services/{service_id}/variables,
// so unlike a write-path leak guard there is no caller-supplied
// request-body field to protect. The quoted "hunter2" form catches
// a case-collapsing renderer regression that might project the
// password substring of the connection string.
func svcVarsDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalSvcVarsServiceID,
		canonicalSvcVarsProjectID,
		canonicalSvcVarsEnvID,
		"svar_matrix_db",
		"svar_matrix_region",
		"DATABASE_URL",
		"us-east-1",
		canonicalSvcVarsSecretPlaintext,
		"hunter2",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// assertSvcVarsAllowPath pins the entire allow-path projection: the
// success envelope schema, the variable count, the secret row's
// redaction chokepoint (Value MUST be output.Sentinel — a redaction
// regression in serviceVariableOf would surface the plaintext here,
// before any deny-path leak guard fires), the non-secret row's
// verbatim Value, and the structural fields that prove the
// reader's home-org pin reached the wire. It is the single
// chokepoint every allow-path test in this file calls so a future
// change to the listServiceVariables envelope shape fails in one
// place rather than scattering across the matrix.
func assertSvcVarsAllowPath(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	env := decodeListServiceVariables(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, "yalla.output.v1")
	}
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2; body %s", len(env.Data.Variables), rec.Body.String())
	}
	got0 := env.Data.Variables[0]
	if got0.ID != "svar_matrix_db" || got0.Key != "DATABASE_URL" || !got0.IsSecret {
		t.Errorf("got[0] = %+v, want svar_matrix_db / DATABASE_URL / is_secret=true", got0)
	}
	if got0.Value != output.Sentinel {
		t.Errorf("got[0].value = %q, want the redaction sentinel %q — serviceVariableOf must redact secret values on the wire",
			got0.Value, output.Sentinel)
	}
	if got0.OrganizationID != canonicalSvcVarsOrgID || got0.ServiceID != canonicalSvcVarsServiceID {
		t.Errorf("got[0] org/svc = (%q, %q), want (%q, %q)",
			got0.OrganizationID, got0.ServiceID, canonicalSvcVarsOrgID, canonicalSvcVarsServiceID)
	}
	if got0.Version != 5 {
		t.Errorf("got[0].version = %d, want 5", got0.Version)
	}
	got1 := env.Data.Variables[1]
	if got1.ID != "svar_matrix_region" || got1.Key != "REGION" || got1.IsSecret {
		t.Errorf("got[1] = %+v, want svar_matrix_region / REGION / is_secret=false", got1)
	}
	if got1.Value != "us-east-1" {
		t.Errorf("got[1].value = %q, want the seeded non-secret plaintext %q — non-secret values must project verbatim",
			got1.Value, "us-east-1")
	}
	// The secret plaintext MUST NEVER appear on any allow path
	// either — the wire redaction chokepoint is the contract, and
	// the leak guard pins it on the allow path so a regression that
	// surfaced the plaintext on a successful read (rather than only
	// on a denied one) fails too.
	if body := rec.Body.String(); strings.Contains(body, canonicalSvcVarsSecretPlaintext) || strings.Contains(body, "hunter2") {
		t.Errorf("allow response leaked the secret plaintext: %s", body)
	}
}

// TestListServiceVariablesPolicyMatrixRoles drives every built-in
// role through the production request path. All six built-in roles
// hold CapRead, so the matrix is "all allow" for a principal reading
// variables of a service in its own organization; the assertions
// that matter are that the verdict is reached through the role
// (ReasonAllowedByRole), the reader is called with the principal's
// own home org id AND the {service_id} path parameter (so a tenant-
// scoped store query cannot match a foreign row), the response is a
// stable 200 yalla.output.v1 envelope carrying the canonical variable
// list, and secret variable values project as output.Sentinel rather
// than the seeded plaintext.
func TestListServiceVariablesPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	vars := canonicalServiceVariables()
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ServiceID: canonicalSvcVarsServiceID},
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

			principal := orgPrincipal("usr_"+tc.name, canonicalSvcVarsOrgID, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so
			// a catalog or builtinRoleCaps regression fails here.
			// Support reading variables of a service in ITS OWN
			// organization is allowed via ReasonAllowedByRole
			// (same-tenant falls through the cross-tenant clause);
			// the Support cross-tenant exception is exercised at the
			// engine in
			// TestListServiceVariablesPolicyWrongOrganizationPrincipal
			// — it cannot be exercised at the wire through this
			// route because serviceIDResolver pins the resource scope
			// to the principal's home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionEnvRead, svcResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(env.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			var gotOrg, gotSvc string
			callCount := 0
			reader := fakeServiceVariableReader{
				vars:         vars,
				gotOrgID:     &gotOrg,
				gotServiceID: &gotSvc,
				callCount:    &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listServiceVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := getServiceVariables(handler, canonicalSvcVarsServiceID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 1 {
				t.Errorf("reader call count = %d, want 1 on the allow path", callCount)
			}
			if gotOrg != canonicalSvcVarsOrgID {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					gotOrg, canonicalSvcVarsOrgID)
			}
			if gotSvc != canonicalSvcVarsServiceID {
				t.Errorf("reader received service id %q, want the path parameter %q",
					gotSvc, canonicalSvcVarsServiceID)
			}
			assertSvcVarsAllowPath(t, rec)
		})
	}
}

// TestListServiceVariablesPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action env.read with a stable
// 403 E_FORBIDDEN, even when the underlying role would have allowed
// it. A revoked or expired credential must never be able to read a
// service's variables of the organization it once had access to,
// the reader must never run (so a canonical secret variable cannot
// have surfaced on a deny path), and the denied body must never
// echo the principal id, the organization id, the path-supplied
// service id, or any seeded variable data (especially the secret
// plaintext).
//
// Underlying role is Owner so a working credential WOULD allow
// env.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0201 ("revoked key,
// expired key").
func TestListServiceVariablesPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	vars := canonicalServiceVariables()

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

			principal := orgPrincipal(tc.id, canonicalSvcVarsOrgID, policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var gotOrg, gotSvc string
			callCount := 0
			reader := fakeServiceVariableReader{
				vars:         vars,
				gotOrgID:     &gotOrg,
				gotServiceID: &gotSvc,
				callCount:    &callCount,
			}
			handler := listServiceVariablesHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)
			rec := getServiceVariables(handler, canonicalSvcVarsServiceID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotOrg != "" || gotSvc != "" {
				t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, gotOrg, gotSvc)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, canonicalSvcVarsOrgID) ||
				svcVarsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded variable data", body)
			}
		})
	}
}

// TestListServiceVariablesPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for env.read on the service-variables list
// route. Unlike GET /v1/organizations/{org_id}, which takes the org
// id from the PATH (and so fires the engine's cross-tenant clause
// for a foreign {org_id}), this route takes the resource org id
// from the PRINCIPAL'S home org — the {service_id} path parameter
// alone never widens the resource to another tenant. Tenant
// isolation on the wire is therefore structural at the persistence
// layer, not the policy boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/services/{svc_victim}/variables with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     svc_victim}) — allowed by the role at CapRead — and then
//     reaches the tenant-scoped service-existence check with the
//     principal's home org id and the foreign service id. A
//     production *store.ServiceVariableRepository.ListByService
//     (which performs the existence check under
//     (organization_id, service_id) before listing) cannot match a
//     service that belongs to another tenant, so the request
//     surfaces as a deterministic 404 E_NOT_FOUND, never disguised
//     as a 200 with foreign variables and never as a 403 that would
//     confirm existence. The body must never echo the foreign org
//     id even though no wire input could place it there, because
//     the persistence layer must not leak foreign-tenant identity
//     into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY non-support role
//     MUST be denied via ReasonDeniedCrossTenant, and a Support
//     principal MUST be allowed via ReasonAllowedBySupport (CapRead
//     is inside the engine clause `roleCaps.has(CapSupport) &&
//     (required == CapRead || required == CapSupport)`). The
//     customer-facing route under test cannot reach this engine
//     branch by construction — serviceIDResolver pins the resource
//     scope to the principal's own home org — but the engine
//     verdict is the authoritative source of the documented support
//     exception, and a future catalog change that upgraded env.read
//     above CapRead would fail here (silently denying every support
//     cross-tenant service-variables read) before it could regress
//     a real customer.
func TestListServiceVariablesPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_svars"
		victimOrgNeedle = "org_victim"
	)

	var gotOrg, gotSvc string
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeServiceVariableReader{
		err:          apierr.NotFound("service", foreignSvcID),
		gotOrgID:     &gotOrg,
		gotServiceID: &gotSvc,
		callCount:    &callCount,
	}
	handler := listServiceVariablesHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := getServiceVariables(handler, foreignSvcID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant service_id surfaces as NotFound, never 200 with foreign variables and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1 — the reader runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign service id",
			callCount)
	}
	if gotOrg != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — the reader must never be called with another tenant's id",
			gotOrg, ownOrg)
	}
	if gotSvc != foreignSvcID {
		t.Errorf("reader received service id %q, want the path parameter %q",
			gotSvc, foreignSvcID)
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
	// scope inherits a working cross-tenant deny. env.read is
	// CapRead, so the engine clause `CapSupport && (CapRead ||
	// CapSupport)` admits Support and denies every non-support role.
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
	// serviceIDResolver pins the resource scope to the principal's
	// own home org, so a foreign {service_id} is admitted same-
	// tenant and rejected at the persistence layer — but the engine
	// verdict is the authoritative source of the documented support
	// exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionEnvRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(env.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListServiceVariablesPolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant
// shielding parent-level resources and unrelated services — are
// pinned against the engine at their natural scopes (a project
// resource, an env resource, a service resource), then tied back to
// the wire by proving that ALL three scoped key types are denied
// OutOfScope against THIS endpoint (even when the grant names the
// target service's own project, the target service's own
// environment, or the target service's own id), while an
// organization-level Viewer grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed end-to-end
// AND its allow-path response carries the secret variable's Value
// as output.Sentinel, locking the CapRead requirement against the
// grant path so a future catalog change that upgraded env.read
// above CapRead would fail here.
//
//   - A project-level Viewer grant naming THIS service's parent
//     project CANNOT authorize the variables read through this
//     route — the grant scope pins ProjectID and the resource scope
//     does not, so covers() returns false. (The same key DOES
//     authorize env.read at a service resource in that project —
//     the parent-scoped route family's job — and that property is
//     pinned at the engine here so the load-bearing distinction
//     between the two routes' authorization surfaces is explicit.)
//   - A project-level Viewer grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a service resource in the
//     sibling project.
//   - An environment-level Admin grant on a staging environment
//     CANNOT authorize the variables read either: the grant scope
//     pins ProjectID and the resource scope does not. (The grant
//     DOES authorize env.write at the staging env — pinned at the
//     engine — but a staging-scoped grant does not reach production
//     unless production is explicitly granted, also pinned at the
//     engine.)
//   - A service-level Admin grant naming THIS service's id CANNOT
//     authorize the variables read through this route either,
//     because the grant scope pins ProjectID and the resource scope
//     does not. At the engine a service grant does not reach an
//     unrelated sibling service nor expose env.write on the parent
//     environment — the "service grant does not expose parent-level
//     secrets or unrelated services" criterion.
//   - An organization-level Viewer grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because env.read is CapRead and Viewer
//     holds CapRead — is allowed via ReasonAllowedByGrant.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the reader is never reached (so a production
// store could not have surfaced the canonical variable list in the
// background and the secret plaintext is never even materialised),
// and the body never echoes any seeded variable data — especially
// not the secret plaintext.
func TestListServiceVariablesPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	vars := canonicalServiceVariables()
	e := policy.NewEngine()

	// Resource the service-id route resolves to: OrganizationID
	// from the principal's home org, ServiceID from the path, NO
	// ProjectID and NO EnvironmentID. Every covers() check below
	// against this resource is the engine-level twin of the
	// wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ServiceID: canonicalSvcVarsServiceID},
	}

	// Project-level grant: viewer on the parent project. Viewer
	// confers CapRead at the project scope, which would normally be
	// enough for env.read on a service resource inside that project
	// — and the engine confirms that at a service resource nested
	// inside the parent project, so the load-bearing distinction
	// between the two routes is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID}
	scopeSiblingProject := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: "prj_svc_svar_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID, ServiceID: canonicalSvcVarsServiceID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) at a service inside the parent project for the target-project viewer grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: "prj_svc_svar_matrix_sibling", EnvironmentID: "env_sibling_svars", ServiceID: "svc_sibling_svars"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at a sibling project's service for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvironmentRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.read) at a sibling project for the target-project viewer grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property
	// is pinned at the engine against env / service resources.
	scopeStaging := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: "env_staging_svars"}
	scopeProduction := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: "env_prod_svars"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeStaging}); !got.Allow {
		t.Errorf("env.write on the granted staging environment = %+v, want allow", got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: scopeProduction}); got.Allow {
		t.Errorf("env.write on production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	scopeTargetEnv := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for a grant on the SAME parent env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service. The "service
	// grant does not expose parent-level secrets or unrelated
	// services" property is pinned at the engine against service /
	// env resources.
	scopeSvcA := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID, ServiceID: "svc_a_svars"}
	scopeSvcB := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID, ServiceID: "svc_b_svars"}
	parentEnv := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_b_svars",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	scopeTargetSvc := policy.Scope{OrganizationID: canonicalSvcVarsOrgID, ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID, ServiceID: canonicalSvcVarsServiceID}
	svcTargetGrantee := policy.Principal{
		ID: "sa_svc_target_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetSvc}},
	}
	if got := e.Decide(svcTargetGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for a grant on the SAME service id = %+v, want deny via %q — covers() is one-way, the service_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Viewer grantee hitting the
	// target service via THIS route is a 403 with the stable
	// out-of-scope reason, the reader is never reached (so a
	// production store could never have surfaced the canonical
	// variable list in the background and the secret plaintext is
	// never even materialised), and the body never echoes any
	// canonical variable data. This is the property that confines a
	// project-scoped key to the parent-scoped route family only.
	var projGotOrg, projGotSvc string
	projCallCount := 0
	projReader := fakeServiceVariableReader{
		vars:         vars, // would be returned if reader ran — leak guard catches it
		gotOrgID:     &projGotOrg,
		gotServiceID: &projGotSvc,
		callCount:    &projCallCount,
	}
	projHandler := listServiceVariablesHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projReader)
	projRec := getServiceVariables(projHandler, canonicalSvcVarsServiceID, "yk_proj_viewer_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the service-variables service-id route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projGotOrg != "" || projGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a project-scoped grantee; it must never run",
			projCallCount, projGotOrg, projGotSvc)
	}
	if body := projRec.Body.String(); svcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service variables or hierarchy data: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME
	// environment id the target service belongs to — hitting the
	// service-variables route is a 403, the reader is never
	// reached, and the body never echoes any canonical variable
	// data. This is the load-bearing property that locks down the
	// service-id route: an environment grant alone does not
	// authorize service-scoped variable reads through it.
	var envGotOrg, envGotSvc string
	envCallCount := 0
	envReader := fakeServiceVariableReader{
		vars:         vars,
		gotOrgID:     &envGotOrg,
		gotServiceID: &envGotSvc,
		callCount:    &envCallCount,
	}
	envHandler := listServiceVariablesHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := getServiceVariables(envHandler, canonicalSvcVarsServiceID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the service-variables service-id route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotOrg != "" || envGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for an env-scoped grantee; it must never run",
			envCallCount, envGotOrg, envGotSvc)
	}
	if body := envRec.Body.String(); svcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service variables or hierarchy data: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee — on the SAME
	// service id the path names — hitting the service-variables
	// route is a 403, the reader is never reached, and the body
	// never echoes any canonical variable data. This is the load-
	// bearing property that confines a service grant to a parent-
	// scoped route family: even a key that names THIS exact service
	// cannot authorize a top-level service-variables read through
	// this endpoint.
	var svcGotOrg, svcGotSvc string
	svcCallCount := 0
	svcReader := fakeServiceVariableReader{
		vars:         vars,
		gotOrgID:     &svcGotOrg,
		gotServiceID: &svcGotSvc,
		callCount:    &svcCallCount,
	}
	svcHandler := listServiceVariablesHandlerFor(
		auth.Identity{Principal: svcTargetGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := getServiceVariables(svcHandler, canonicalSvcVarsServiceID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the service-variables service-id route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotOrg != "" || svcGotSvc != "" {
		t.Errorf("reader was reached (calls=%d org=%q svc=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotOrg, svcGotSvc)
	}
	if body := svcRec.Body.String(); svcVarsDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service variables or hierarchy data: %s", body)
	}

	// An organization-level Viewer grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because env.read is CapRead and Viewer
	// holds CapRead — is allowed via ReasonAllowedByGrant. The same
	// key is end-to-end allowed at the wire, with the reader
	// reached on the principal's home org id and the path service
	// id, and the secret variable's Value redacted to output.Sentinel
	// on the response. This locks the CapRead requirement against
	// the grant path so a future catalog change that upgraded
	// env.read above CapRead would fail here (silently denying every
	// org-level Viewer grantee) before it could regress a real
	// customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer_svars", Kind: domain.KindServiceAccount, OrganizationID: canonicalSvcVarsOrgID,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: canonicalSvcVarsOrgID}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionEnvRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(env.read) at the service-id route's resource scope for an organization-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgGotOrg, orgGotSvc string
	orgCallCount := 0
	orgReader := fakeServiceVariableReader{
		vars:         vars,
		gotOrgID:     &orgGotOrg,
		gotServiceID: &orgGotSvc,
		callCount:    &orgCallCount,
	}
	orgHandler := listServiceVariablesHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getServiceVariables(orgHandler, canonicalSvcVarsServiceID, "yk_org_viewer")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level viewer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	assertSvcVarsAllowPath(t, allowedRec)
	if orgCallCount != 1 {
		t.Errorf("reader call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgGotOrg != canonicalSvcVarsOrgID {
		t.Errorf("reader received organization id %q, want the principal's home org %q",
			orgGotOrg, canonicalSvcVarsOrgID)
	}
	if orgGotSvc != canonicalSvcVarsServiceID {
		t.Errorf("reader received service id %q, want the path parameter %q",
			orgGotSvc, canonicalSvcVarsServiceID)
	}

	// And the same project-scoped viewer grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home
	// org id is org_sibling_svars, cannot be used to read service
	// variables in org_sibling_svars — the cross-tenant guard fires
	// first because the principal's home org no longer matches the
	// grant's scope. This is the engine-level twin of the wire-
	// level "wrong organization" property in
	// TestListServiceVariablesPolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (env.read IS inside the support cross-tenant
	// exception, but the principal here is a service account with
	// no CapSupport role, so the exception does not apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling_svars", ProjectID: canonicalSvcVarsProjectID, EnvironmentID: canonicalSvcVarsEnvID, ServiceID: canonicalSvcVarsServiceID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view_svars", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling_svars",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionEnvRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(env.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}
}
