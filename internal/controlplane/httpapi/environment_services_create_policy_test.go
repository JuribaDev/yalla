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
)

// Policy-matrix coverage for POST /v1/environments/{environment_id}/services
// (BE-0183). Where environment_services_create_test.go proves the
// endpoint's wire contract (BE-0181), this file proves its
// authorization contract: that action service.create cannot be
// bypassed by — or commit a service row because of — the principal's
// role, revoked credentials, home organization, or scoped grants.
//
// The route carries environmentIDResolver (routes.go), which builds
// the policy resource from the principal's HOME organization id and
// the {environment_id} PATH parameter — and CRUCIALLY pins NO
// ProjectID leg, because the bare top-level path carries no parent
// project_id. That is the load-bearing distinction from projectID-
// rooted siblings (e.g. POST /v1/projects/{project_id}/environments,
// BE-0153): every scoped grant in the engine pins a ProjectID, and
// the engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not). The
// consequence is that ALL project-, environment-, and service-scoped
// grants are denied at the boundary by ReasonDeniedOutOfScope — even
// a project-scoped Admin grant naming THIS environment's parent
// project, even an environment-scoped Admin grant naming THIS
// environment's id, because neither scope's ProjectID can cover a
// resource scope without one. Principals whose only access is a
// scoped grant must use a parent-scoped route to address an
// environment by its (project, environment) tuple; this route is
// reserved for org-wide write roles (owner, admin, developer) and
// org-wide grants. This is the structural twin of BE-0180
// (environment_services_policy_test.go): same resolver, same
// scoped-grant denial pattern; it differs at the capability tier
// (CapWrite vs CapRead) and at the engine's cross-tenant clause
// (CapWrite is OUTSIDE the support cross-tenant exception).
//
// service.create requires CapWrite (catalog.go: ActionServiceCreate
// -> CapWrite), the same capability class as project.create /
// environment.create / service.update / service.delete / env.write.
// The role matrix for a principal acting on its own organization
// therefore splits along the write capability class:
// Owner/Admin/Developer hold CapWrite and are allowed
// (ReasonAllowedByRole); Viewer/CI/Support do not hold CapWrite and
// are denied (ReasonDeniedNoCapability) — CI is CapRead+CapDeploy
// only (catalog.go: builtinRoleCaps[RoleCI] = CapSelf | CapRead |
// CapDeploy). This is the load-bearing distinction from the
// service.read matrix (BE-0180), which is "all six roles allow":
// three additional roles deny here at the role boundary, and —
// crucially — the engine's cross-tenant support exception is gated
// on `required == CapRead || required == CapSupport`, so CapWrite is
// OUTSIDE that exception. Privileged Yalla support that needs to
// create a service on a customer's behalf must go through explicit
// break-glass admin tooling, not this customer-facing route. Pinning
// the support-cross-tenant DENY at the engine here means a future
// {org_id}-scoped variant inherits a working cross-tenant deny.
//
// Engine defence-in-depth: the cross-tenant clause is
// `roleCaps.has(CapSupport) && (required == CapRead || required ==
// CapSupport)`. CapWrite is OUTSIDE that clause, so a Support
// principal authorizing service.create against a foreign-tenant
// resource is DENIED via ReasonDeniedCrossTenant — unlike BE-0180,
// where CapRead admits Support cross-tenant via
// ReasonAllowedBySupport. The customer-facing route under test
// cannot reach the engine's cross-tenant branch by construction
// (environmentIDResolver pins the resource scope to the PRINCIPAL'S
// home org, not the path's tenant — the cross-tenant deny does NOT
// apply through this endpoint, as the resolver doc makes explicit),
// but pinning the engine verdict here means a future endpoint that
// resolves the resource into a foreign-org scope inherits a working
// cross-tenant deny across every role, and a future catalog change
// that downgraded service.create to CapRead would fail here
// (silently allowing every support cross-tenant service create)
// before it could regress a real customer.
//
// Unlike project_variables or environment_variables rows (which
// carry secret values), the services table carries NO credential
// material — only structural identifiers, a slug, a display name, a
// kind taxonomy, an optimistic-concurrency version, and lifecycle
// timestamps. The environmentServiceOf projection has no value-
// redaction chokepoint to anchor a deny-path leak guard on; the
// load-bearing needles are the caller-supplied request-body fields
// (a service id, a slug, a display name a denied principal must not
// see echoed back) and the canned creator output (the row a
// deny-path fake creator WOULD have returned if it had been
// reached). Tenant-leakage and no-write invariants apply: a denied
// response never echoes the canonical request-body fields, the
// canned service id / slug / display name, the foreign tenant's id,
// or the path environment id; and the creator MUST never run on any
// deny path — a scoped key denied on the wire cannot have committed
// a service row in the background.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, environmentIDResolver, or the engine fails
// here. createEnvironmentServiceHandlerFor, postEnvironmentService,
// decodeCreateEnvironmentService, fakeEnvironmentServiceCreator,
// seedServiceWire, orgPrincipal, and decodeError are shared with the
// create-service contract suite (environment_services_create_test.go)
// and the wider httpapi test fixtures; this file adds no scaffolding
// beyond the small fixture builders below.

// canonicalCreateServiceInput builds the canonical request body
// every test in this file shares. Centralising it lets a future
// regression that reorders, renames, or recategorises a field fail
// in exactly one place. The distinctive id / slug / display name are
// deliberately recognisable so deny-path leak guards can needle for
// them, and deliberately distinct from canonicalServicesForMatrix
// (used by BE-0180) so the matrices cannot accidentally share
// fixture state through a future shared fake.
func canonicalCreateServiceInput() (svcID, slug, displayName, kind string) {
	return "svc_create_matrix_alpha", "create-matrix-alpha", "Create Matrix Alpha", "application"
}

// canonicalCreatedService is the row a deny-path fake creator would
// return if it were (incorrectly) reached. The body-leak guard
// needles for these recognisable values, so an accidental on-deny
// render of the "created" service fails the test even before the
// creator-not-reached assertion. The id mirrors the canonical
// request body so a request-body echo and a creator-output echo are
// both catchable through the same needles, and the version is
// deliberately non-zero so a wire response that surfaced this row
// would be distinguishable from a zero-value envelope.
func canonicalCreatedService(orgID, projectID, environmentID string) store.Service {
	svcID, slug, displayName, kind := canonicalCreateServiceInput()
	return store.Service{
		ID:             svcID,
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
		Slug:           slug,
		DisplayName:    displayName,
		Kind:           kind,
		Version:        1,
	}
}

// canonicalCreateServiceBody is the canonical JSON request body
// every test in this file shares. The body intentionally exposes no
// organization_id, project_id, or environment_id field — the
// production handler derives the organization id from the principal's
// home org and the environment id from the path parameter, never
// from the body — and the strict JSON decoder rejects an unknown
// field smuggled into the body before the creator ever runs.
func canonicalCreateServiceBody() string {
	svcID, slug, displayName, kind := canonicalCreateServiceInput()
	return `{"service_id":"` + svcID + `","slug":"` + slug +
		`","display_name":"` + displayName + `","kind":"` + kind + `"}`
}

// createServiceDenyBodyLeak reports whether body contains any of the
// caller-supplied request-body fields, the canned created-service
// fields, the canned parent project / environment ids, or other
// caller-recognisable identifiers. A denied response that
// accidentally rendered any of these fails the test: a denied
// request-body field would mean the handler echoed the request
// after policy denial (a tenant boundary smell), and a denied
// created-service field would mean the creator ran and the response
// leaked its output even though the wire said 403. The quoted forms
// catch a case-collapsing renderer regression. There is no secret
// plaintext to anchor on — the services table carries no credential
// material at all.
func createServiceDenyBodyLeak(body string) bool {
	needles := []string{
		"svc_create_matrix_alpha",
		"\"create-matrix-alpha\"",
		"\"Create Matrix Alpha\"",
		"prj_svc_create_matrix_parent",
		"env_svc_create_matrix_target",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestCreateEnvironmentServicePolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner/Admin/Developer (own org) are allowed; Viewer/CI/
// Support (own org) are denied at the role boundary —
// builtinRoleCaps[RoleCI] is CapSelf+CapRead+CapDeploy (no CapWrite),
// builtinRoleCaps[RoleSupport] is CapSelf+CapRead+CapSupport (no
// CapWrite). The assertions that matter for allow rows are that the
// verdict is reached through the role (ReasonAllowedByRole), the
// creator is reached with the principal's own home organization id,
// the path {environment_id}, and the principal id (so the audit
// record names the actor verbatim), and the response is a stable 201
// yalla.output.v1 envelope carrying the created service. For deny
// rows, the assertions are 403 yalla.error.v1, the stable reason on
// the wire, the creator MUST NEVER run (no row written in the
// background), and the denied body must not echo the caller-supplied
// request-body fields.
func TestCreateEnvironmentServicePolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_create_matrix_parent"
		envID   = "env_svc_create_matrix_target"
	)
	svcID, slug, displayName, kind := canonicalCreateServiceInput()
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
			// allow rows pin ReasonAllowedByRole; the deny rows pin
			// ReasonDeniedNoCapability. CapWrite is outside the
			// support cross-tenant exception, so Support acting on
			// ITS OWN organization's environment is denied here at
			// the no-capability boundary (the cross-tenant clause is
			// exercised in
			// TestCreateEnvironmentServicePolicyWrongOrganizationPrincipal).
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionServiceCreate, envResource)
			if got.Allow != tc.allow || got.Reason != tc.reason {
				t.Errorf("Decide(service.create) for %s = %+v, want allow=%v reason=%q",
					tc.name, got, tc.allow, tc.reason)
			}

			var gotInput store.CreateServiceInput
			callCount := 0
			creator := fakeEnvironmentServiceCreator{
				service:   canonicalCreatedService(org, project, envID),
				gotInput:  &gotInput,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := createEnvironmentServiceHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, creator)
			rec := postEnvironmentService(handler, envID, canonicalCreateServiceBody(), "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusCreated {
					t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("creator call count = %d, want 1 on the allow path", callCount)
				}
				if gotInput.OrganizationID != org {
					t.Errorf("creator received organization id %q, want the principal's home org %q",
						gotInput.OrganizationID, org)
				}
				if gotInput.EnvironmentID != envID {
					t.Errorf("creator received environment id %q, want the path parameter %q",
						gotInput.EnvironmentID, envID)
				}
				if gotInput.ServiceID != svcID || gotInput.Slug != slug ||
					gotInput.DisplayName != displayName || gotInput.Kind != kind {
					t.Errorf("creator received resource fields = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
						gotInput.ServiceID, gotInput.Slug, gotInput.DisplayName, gotInput.Kind,
						svcID, slug, displayName, kind)
				}
				if gotInput.ActorOrgID != org {
					t.Errorf("creator received actor org id %q, want the principal's home org %q",
						gotInput.ActorOrgID, org)
				}
				if gotInput.ActorID != "usr_"+tc.name {
					t.Errorf("creator received actor id %q, want usr_%s — the audit record must name the actor verbatim",
						gotInput.ActorID, tc.name)
				}
				envelope := decodeCreateEnvironmentService(t, rec)
				svc := envelope.Data.Service
				if svc.ID != svcID || svc.Slug != slug || svc.DisplayName != displayName ||
					svc.Kind != kind || svc.OrganizationID != org ||
					svc.ProjectID != project || svc.EnvironmentID != envID {
					t.Errorf("service = %+v, want (%s, %s, %s, %s, org=%s, prj=%s, env=%s)",
						svc, svcID, slug, displayName, kind, org, project, envID)
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
			if callCount != 0 || gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached (calls=%d input=%+v) for a denied principal; it must never run",
					callCount, gotInput)
			}
			if body := rec.Body.String(); createServiceDenyBodyLeak(body) {
				t.Errorf("denied response leaked request-body or canned-service data: %s", body)
			}
		})
	}
}

// TestCreateEnvironmentServicePolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired — both
// of which the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action service.create with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to create a
// service under an environment of the organization it once had write
// access to, the creator must never run, and the denied body must
// never echo the principal id, the organization id, the path-supplied
// environment id, or the caller-supplied request body fields.
//
// Underlying role is Owner so a working credential WOULD allow
// service.create; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0183 ("revoked key,
// expired key").
func TestCreateEnvironmentServicePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_create_matrix_parent"
		envID   = "env_svc_create_matrix_target"
	)

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

			var gotInput store.CreateServiceInput
			callCount := 0
			creator := fakeEnvironmentServiceCreator{
				service:   canonicalCreatedService(org, project, envID),
				gotInput:  &gotInput,
				callCount: &callCount,
			}
			handler := createEnvironmentServiceHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, creator)
			rec := postEnvironmentService(handler, envID, canonicalCreateServiceBody(), "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || gotInput.OrganizationID != "" || gotInput.ActorID != "" {
				t.Errorf("creator was reached (calls=%d input=%+v) for a disabled principal; it must never run",
					callCount, gotInput)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				strings.Contains(body, envID) ||
				createServiceDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, path environment id, or request data",
					body)
			}
		})
	}
}

// TestCreateEnvironmentServicePolicyWrongOrganizationPrincipal pins
// the cross-tenant boundary for service.create on the env-id route.
// As with environment.read / project.read / env.read / service.read,
// the resource org id is taken from the PRINCIPAL'S home org — the
// {environment_id} path parameter alone never widens the resource to
// another tenant. Tenant isolation on the wire is therefore
// structural at the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting POST /v1/environments/
//     {env_victim}/services with a valid Owner token reaches the
//     engine with a same-tenant resource ({org_attacker, env_victim})
//     — allowed by the role at CapWrite — and then reaches the
//     store-layer orchestrator with the principal's home org id and
//     the foreign environment id. The orchestrator Gets the
//     environment under (organization_id, environment_id) before
//     creating its service, so a cross-tenant environment_id is
//     rejected as a deterministic 404 E_NOT_FOUND, never disguised
//     as a 201 (which would mean a service was committed under the
//     foreign environment) and never as a 403 that would confirm the
//     environment's existence. The body must never echo the foreign
//     org id even though no wire input could place it there, because
//     the persistence layer must not leak foreign-tenant identity
//     into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role — INCLUDING
//     Support — MUST be denied via ReasonDeniedCrossTenant. This is
//     the load-bearing distinction from the service.read matrix
//     (BE-0180): CapWrite is OUTSIDE the engine's support
//     cross-tenant exception (the clause is `roleCaps.has(CapSupport)
//     && (required == CapRead || required == CapSupport)`), so a
//     Support principal of org_yalla authorizing service.create
//     against an org_victim resource is DENIED — privileged Yalla
//     support that needs to create a service on a customer's behalf
//     must go through explicit break-glass admin tooling, never this
//     customer-facing route. Pinning that engine verdict here means
//     a future {org_id}-scoped variant inherits a working
//     cross-tenant deny across every role.
func TestCreateEnvironmentServicePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignEnvID    = "env_victim_svc_create"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits POST /v1/environments/
	// {env_victim}/services with a valid Owner token. The fake
	// mirrors the production orchestrator contract: it returns
	// NotFound whenever the (organizationID, environmentID) pair
	// does not match a row (the orchestrator's parent-environment
	// existence check fires first), so a principal whose home org is
	// org_attacker creating a service under an environment that
	// belongs to org_victim hits the fake with (org_attacker,
	// env_victim_svc_create) and gets NotFound. The assertions that
	// matter are structural: the creator is ALWAYS called with the
	// principal's home org id — never with a caller-controlled value
	// — so a production tenant-scoped ServiceService could not have
	// committed a row in the victim's environment regardless of
	// database state. The denied body must never echo the victim's
	// org id.
	var gotInput store.CreateServiceInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	creator := fakeEnvironmentServiceCreator{
		err:       apierr.NotFound("environment", foreignEnvID),
		gotInput:  &gotInput,
		callCount: &callCount,
	}
	handler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, creator)
	rec := postEnvironmentService(handler, foreignEnvID, canonicalCreateServiceBody(), "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant environment_id surfaces as NotFound, never 201 which would mean a foreign-environment commit and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — the creator runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign environment id",
			callCount)
	}
	if gotInput.OrganizationID != ownOrg {
		t.Errorf("creator received org id %q, want the attacker's home org %q — the creator must never be called with another tenant's id",
			gotInput.OrganizationID, ownOrg)
	}
	if gotInput.EnvironmentID != foreignEnvID {
		t.Errorf("creator received environment id %q, want the path parameter %q",
			gotInput.EnvironmentID, foreignEnvID)
	}
	if gotInput.ActorOrgID != ownOrg {
		t.Errorf("creator received actor org id %q, want %q — the audit record must name the attacker's own org, not the victim's",
			gotInput.ActorOrgID, ownOrg)
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
	// future endpoint that resolves the resource into a foreign-org
	// scope inherits a working cross-tenant deny. service.create is
	// CapWrite; the engine's cross-tenant clause
	// `roleCaps.has(CapSupport) && (required == CapRead || required ==
	// CapSupport)` is gated on CapRead/CapSupport actions, so
	// CapWrite is outside the exception and EVERY role — INCLUDING
	// Support — is denied here. This is the load-bearing distinction
	// from BE-0180, where Support cross-tenant CapRead is allowed
	// via ReasonAllowedBySupport.
	e := policy.NewEngine()
	foreign := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: victimOrg, EnvironmentID: foreignEnvID},
	}
	crossTenantRoles := []struct {
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
	for _, tc := range crossTenantRoles {
		tc := tc
		t.Run("engine_cross_tenant_deny_"+tc.name, func(t *testing.T) {
			t.Parallel()
			p := orgPrincipal("usr_"+tc.name, ownOrg, tc.role)
			got := e.Decide(p, policy.ActionServiceCreate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(service.create, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestCreateEnvironmentServicePolicyGrantContainment proves scoped
// grants cannot be widened past the scope they were issued for AND
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because environmentIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, env grant not implying production, service grant
// shielding parent-level resources — are pinned against the engine
// at their natural scopes (a project resource for service.create, an
// env resource for env.write, a service resource for
// service.update), then tied back to the wire by proving that ALL
// three scoped key types are denied OutOfScope against THIS endpoint
// (even when the grant names the target environment's own project
// or even the target environment's own id), while an organization-
// level Developer grant — which pins no ProjectID and covers any
// resource scope in the same org and confers CapWrite — is allowed
// end-to-end.
//
//   - A project-level Admin grant naming THIS environment's parent
//     project CANNOT authorize the create through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     service.create at a project resource — a parent-scoped route's
//     job — and that property is pinned at the engine here so the
//     load-bearing distinction between the two routes' authorization
//     surfaces is explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a project resource.
//   - An environment-level Admin grant naming THIS environment's id
//     CANNOT authorize the create either, because the grant scope
//     pins ProjectID and the resource scope does not. (The grant
//     DOES authorize env.write at the env resource — pinned at the
//     engine — but not service.create on this route.) An env grant
//     on staging also does not imply env.write on production at the
//     engine, the production-isolation property of the acceptance
//     criteria.
//   - A service-level Admin grant CANNOT either, and at the engine a
//     service grant does not expose env.write on the parent
//     environment nor reach an unrelated sibling service.
//   - An organization-level VIEWER grant DOES cover any resource
//     scope in the same org but — because service.create is CapWrite
//     and Viewer does NOT hold CapWrite — is denied via
//     ReasonDeniedNoCapability. The grant's scope is sufficient; the
//     grant role's capability set is not. This is the load-bearing
//     distinction from BE-0180's grant containment, where an
//     organization-level Viewer grant IS sufficient for service.read.
//   - An organization-level DEVELOPER grant DOES cover any resource
//     scope in the same org and — because service.create is CapWrite
//     and Developer holds CapWrite — is allowed via
//     ReasonAllowedByGrant. The same key is end-to-end allowed at
//     the wire.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the creator is never reached (so a production
// store could not have committed a service in the background), and
// the body never echoes a caller-supplied request-body field, the
// canned created-service id, or the parent project / environment id.
func TestCreateEnvironmentServicePolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_create_matrix_parent"
		envID   = "env_svc_create_matrix_target"
	)
	e := policy.NewEngine()

	// Resource the env-id route resolves to: OrganizationID from the
	// principal's home org, EnvironmentID from the path, NO ProjectID.
	// Every covers() check below against this resource is the engine-
	// level twin of the wire-level deny on this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: policy.Scope{OrganizationID: org, EnvironmentID: envID},
	}

	// Project-level grant: admin on the parent project. Admin
	// confers CapWrite at the project scope, which would normally be
	// enough for service.create on a project resource — and the
	// engine confirms that at a project resource, so the
	// load-bearing distinction between the two routes is explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_create_matrix_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.create) at the parent project for the target-project admin grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.create) at a sibling project for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from the parent-scoped route.
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project
	// scope, which is NOT enough for service.create (CapWrite). Pin
	// at a project resource to lock down the CapWrite requirement on
	// the project-grant path — a future catalog change that
	// downgraded service.create to CapRead would fail here (silently
	// allowing every project-scoped Viewer grantee to mint services)
	// before it could regress a real customer.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceCreate, policy.Resource{Kind: domain.KindProject, Scope: scopeTargetProject}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(service.create) for a project-scoped viewer grant = %+v, want deny via %q — Viewer does not hold CapWrite",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: admin on the staging environment of
	// the target project. The "env grant does not imply access to
	// production unless production is explicitly granted" property is
	// pinned at the engine against env resources.
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
	// env-staging grant is denied OutOfScope at the engine — even an
	// env grant on the very environment the path names would be
	// denied for the same reason, which the next fixture pins
	// directly so a future relaxation of covers() (e.g. allowing a
	// grant on env_X to cover a resource scope with just EnvID=env_X
	// and no ProjectID) cannot land without failing this test.
	if got := e.Decide(envStagingGrantee, policy.ActionServiceCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (env_svc_create_matrix_target itself) is
	// ALSO denied OutOfScope on this route, because the grant scope
	// still pins ProjectID and the resource scope does not — the
	// env_id alone is not enough to authorize a top-level write
	// through this route.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: envID}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionServiceCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for a grant on the SAME env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: admin on a single service of the target
	// environment. The "service grant does not expose parent-level
	// secrets or unrelated services" property is pinned at the engine
	// against service / env resources.
	scopeSvcA := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: envID, ServiceID: "svc_create_matrix_existing"}
	scopeSvcB := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: envID, ServiceID: "svc_create_matrix_sibling"}
	parentEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: envID}
	svcGrantee := policy.Principal{
		ID: "sa_svc", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeSvcA}},
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("update the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceUpdate, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("update a sibling service = %+v, want deny — a service grant must not reach svc_create_matrix_sibling",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("write env vars on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// service grant is denied OutOfScope at the engine.
	if got := e.Decide(svcGrantee, policy.ActionServiceCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// target environment's services via THIS route is a 403 with the
	// stable out-of-scope reason, the creator is never reached (so a
	// production store could never have committed a service in the
	// background), and the body never echoes the canonical
	// request-body fields, the canned created-service id, or the
	// parent project / environment id. This is the property that
	// confines a project-scoped key to the parent-scoped route only,
	// even when the project-scoped key holds CapWrite at the project
	// scope.
	var projGotInput store.CreateServiceInput
	projCallCount := 0
	projCreator := fakeEnvironmentServiceCreator{
		service:   canonicalCreatedService(org, project, envID),
		gotInput:  &projGotInput,
		callCount: &projCallCount,
	}
	projHandler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projCreator)
	projRec := postEnvironmentService(projHandler, envID, canonicalCreateServiceBody(), "yk_proj_admin_scoped")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key on the env-id services route; body %s",
			projRec.Code, projRec.Body.String())
	}
	projDenyEnv := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(projDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			projDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projCallCount != 0 || projGotInput.OrganizationID != "" || projGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for a project-scoped grantee; it must never run",
			projCallCount, projGotInput)
	}
	if body := projRec.Body.String(); createServiceDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-service data: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME environment
	// id the path names — hitting the env-id services route is a
	// 403, the creator is never reached, and the body never echoes
	// the canonical request-body fields. This is the load-bearing
	// property that locks down the env-id route: an environment
	// grant alone does not authorize service.create through it.
	var envGotInput store.CreateServiceInput
	envCallCount := 0
	envCreator := fakeEnvironmentServiceCreator{
		service:   canonicalCreatedService(org, project, envID),
		gotInput:  &envGotInput,
		callCount: &envCallCount,
	}
	envHandler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envCreator)
	envRec := postEnvironmentService(envHandler, envID, canonicalCreateServiceBody(), "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an env-scoped key on the env-id services route; body %s",
			envRec.Code, envRec.Body.String())
	}
	envDenyEnv := decodeError(t, envRec, "E_FORBIDDEN")
	if !strings.Contains(envDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			envDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if envCallCount != 0 || envGotInput.OrganizationID != "" || envGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for an env-scoped grantee; it must never run",
			envCallCount, envGotInput)
	}
	if body := envRec.Body.String(); createServiceDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-service data: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee hitting the env-id
	// services route is a 403, the creator is never reached, and the
	// body never echoes parent-level identifiers — the "service
	// grant does not expose parent-level secrets or unrelated
	// services" criterion tied to the wire on this route. A
	// hypothetical regression that let a service-scoped key surface
	// its own row through this list route would fail here as well.
	var svcGotInput store.CreateServiceInput
	svcCallCount := 0
	svcCreator := fakeEnvironmentServiceCreator{
		service:   canonicalCreatedService(org, project, envID),
		gotInput:  &svcGotInput,
		callCount: &svcCallCount,
	}
	svcHandler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcCreator)
	svcRec := postEnvironmentService(svcHandler, envID, canonicalCreateServiceBody(), "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a service-scoped key on the env-id services route; body %s",
			svcRec.Code, svcRec.Body.String())
	}
	svcDenyEnv := decodeError(t, svcRec, "E_FORBIDDEN")
	if !strings.Contains(svcDenyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			svcDenyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if svcCallCount != 0 || svcGotInput.OrganizationID != "" || svcGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for a service-scoped grantee; it must never run",
			svcCallCount, svcGotInput)
	}
	if body := svcRec.Body.String(); createServiceDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-service data: %s", body)
	}

	// An organization-level VIEWER grant DOES cover any resource
	// scope in the same org but — because service.create is CapWrite
	// and Viewer does NOT hold CapWrite — is denied via
	// ReasonDeniedNoCapability at the engine, and 403 at the wire.
	// The grant's scope is sufficient; the grant role's capability
	// set is not. This is the load-bearing distinction from BE-0180's
	// containment, where an organization-level Viewer grant IS
	// sufficient for service.read.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionServiceCreate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for an organization-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}
	var orgViewerGotInput store.CreateServiceInput
	orgViewerCallCount := 0
	orgViewerCreator := fakeEnvironmentServiceCreator{
		service:   canonicalCreatedService(org, project, envID),
		gotInput:  &orgViewerGotInput,
		callCount: &orgViewerCallCount,
	}
	orgViewerHandler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgViewerCreator)
	orgViewerRec := postEnvironmentService(orgViewerHandler, envID, canonicalCreateServiceBody(), "yk_org_viewer")
	if orgViewerRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an org-level viewer grant on service.create; body %s",
			orgViewerRec.Code, orgViewerRec.Body.String())
	}
	if orgViewerCallCount != 0 || orgViewerGotInput.OrganizationID != "" || orgViewerGotInput.ActorID != "" {
		t.Errorf("creator was reached (calls=%d input=%+v) for an org-level viewer grantee; it must never run",
			orgViewerCallCount, orgViewerGotInput)
	}
	if body := orgViewerRec.Body.String(); createServiceDenyBodyLeak(body) {
		t.Errorf("denied response leaked request-body or canned-service data: %s", body)
	}

	// An organization-level DEVELOPER grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because service.create is CapWrite and
	// Developer holds CapWrite — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the
	// creator reached on the principal's home org id and the path
	// environment id, the actor id naming the grantee verbatim, and
	// the response carrying the created service. This locks the
	// CapWrite requirement against the grant path so a future
	// catalog change that upgraded service.create above CapWrite
	// would fail here (silently denying every org-level Developer
	// grantee) before it could regress a real customer.
	orgDeveloperGrantee := policy.Principal{
		ID: "sa_org_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgDeveloperGrantee, policy.ActionServiceCreate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.create) at the env-id route's resource scope for an organization-level developer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	var orgDevGotInput store.CreateServiceInput
	orgDevCallCount := 0
	orgDevCreator := fakeEnvironmentServiceCreator{
		service:   canonicalCreatedService(org, project, envID),
		gotInput:  &orgDevGotInput,
		callCount: &orgDevCallCount,
	}
	orgDevHandler := createEnvironmentServiceHandlerFor(
		auth.Identity{Principal: orgDeveloperGrantee, Method: auth.MethodAPIKey}, nil, orgDevCreator)
	allowedRec := postEnvironmentService(orgDevHandler, envID, canonicalCreateServiceBody(), "yk_org_developer")
	if allowedRec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for an org-level developer grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	if orgDevCallCount != 1 {
		t.Errorf("creator call count = %d, want 1 on the allow path", orgDevCallCount)
	}
	if orgDevGotInput.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			orgDevGotInput.OrganizationID, org)
	}
	if orgDevGotInput.EnvironmentID != envID {
		t.Errorf("creator received environment id %q, want the path parameter %q",
			orgDevGotInput.EnvironmentID, envID)
	}
	if orgDevGotInput.ActorID != "sa_org_dev" {
		t.Errorf("creator received actor id %q, want sa_org_dev — the audit record must name the grantee verbatim",
			orgDevGotInput.ActorID)
	}
	allowedEnvelope := decodeCreateEnvironmentService(t, allowedRec)
	svcID, slug, _, _ := canonicalCreateServiceInput()
	if allowedEnvelope.Data.Service.ID != svcID ||
		allowedEnvelope.Data.Service.Slug != slug ||
		allowedEnvelope.Data.Service.OrganizationID != org ||
		allowedEnvelope.Data.Service.EnvironmentID != envID {
		t.Errorf("service = %+v, want (%s, %s, org=%s, env=%s)",
			allowedEnvelope.Data.Service, svcID, slug, org, envID)
	}

	// And the same project-scoped Admin grantee whose home org id is
	// foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to create a service in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in
	// TestCreateEnvironmentServicePolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. service.create is CapWrite, OUTSIDE the
	// support cross-tenant exception, so even a support-style
	// principal would be denied here.
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindProject,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionServiceCreate, siblingOrgResource); got.Allow {
		t.Errorf("Decide(service.create) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
