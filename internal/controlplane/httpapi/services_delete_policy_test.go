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

// Policy-matrix coverage for DELETE /v1/services/{service_id} (BE-0192).
// Where services_delete_test.go proves the endpoint's wire contract
// (BE-0190), this file proves its authorization contract: that action
// service.delete cannot be bypassed by — or persist a soft-deletion
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), which builds the
// policy resource from the principal's HOME organization id and the
// {service_id} PATH parameter — and CRUCIALLY pins NO ProjectID leg,
// because the bare top-level path carries no parent project_id. That
// is the structural twin of services_update_policy_test.go (BE-0189)
// against the same serviceIDResolver, and the load-bearing distinction
// from any parent-scoped DELETE route: every scoped grant in the
// engine pins a ProjectID, and the engine's covers() rule is one-way
// (a grant scope that pins ProjectID cannot cover a resource scope
// that does not). The consequence is that ALL project-, environment-,
// and service-scoped grants are denied at the boundary by
// ReasonDeniedOutOfScope — even a service-scoped Admin grant naming
// THIS service's id, because the grant scope's pinned ProjectID
// cannot cover a resource scope without one. Principals whose only
// access is a scoped grant cannot reach this endpoint at all; this
// route is reserved for org-wide write roles and org-wide grants.
//
// service.delete requires CapWrite (catalog.go: ActionServiceDelete
// -> CapWrite), the same capability class as service.create /
// service.update / project.create / environment.update. The role
// matrix for a principal acting on its own organization therefore
// splits along the write capability class: Owner / Admin / Developer
// hold CapWrite and are allowed (ReasonAllowedByRole); Viewer / CI /
// Support do not hold CapWrite and are denied
// (ReasonDeniedNoCapability) — CI holds CapDeploy (the deploy
// capability is for service lifecycle and rollouts, not desired-state
// teardown), so a CI key cannot soft-delete a service even within
// its home tenant. This is the load-bearing distinction from the
// service.read matrix (services_get_policy_test.go), which is "all
// six roles allow": three roles deny here at the role boundary, and
// — crucially — the engine's cross-tenant support exception is gated
// on `required == CapRead || required == CapSupport`, so CapWrite is
// OUTSIDE that exception. Privileged Yalla support that needs to
// schedule a customer's service for teardown must go through explicit
// break-glass admin tooling, not this customer-facing route.
//
// services rows store no credential material — only structural
// identifiers (org/project/env/service ids), a slug, a display name,
// a kind taxonomy, an optimistic-concurrency version, and lifecycle
// timestamps. The environmentServiceOf projection has no value-
// redaction chokepoint to anchor a deny-path leak guard on; the load-
// bearing needle is the existence of the service row itself (and the
// id / slug / display name / parent project_id / parent
// environment_id a denied principal must not learn). Tenant-leakage
// and no-write invariants apply: a denied response never echoes the
// seeded service id / slug / display name, the foreign tenant's id,
// or the canonical parent project_id / environment_id; and the
// deleter MUST never run on any deny path — a scoped key denied on
// the wire cannot have stamped deletion_scheduled_at on a row in the
// background. DELETE accepts no request body, so unlike the PATCH
// matrix there is no caller-supplied body field to anchor a leak
// guard on.
//
// Each test drives the real NewHandler + real policy.NewEngine() —
// the production request path — so a regression in the middleware,
// the action catalog, serviceIDResolver, or the engine fails here.
// deleteServiceHandlerFor, deleteService, decodeDeleteServiceBody,
// fakeServiceDeleter, orgPrincipal, and decodeError are shared with
// the delete-service contract suite (services_delete_test.go) and
// the wider httpapi test fixtures; this file adds no scaffolding
// beyond the small fixture builders below.

// canonicalDeleteSvcForMatrix is the row every test in this file
// would receive back from the deleter on an allow path. The
// DeletionScheduledAt timestamp is non-nil because the deleter's
// production contract is "return the soft-deleted row with the new
// deletion_scheduled_at stamped". Its ids / slug / display name are
// deliberately distinct from canonicalServiceForGet (used by
// services_test.go), canonicalDeletedSvc (used by
// services_delete_test.go), canonicalGetSvcForMatrix (used by
// services_get_policy_test.go), and canonicalUpdateSvcForMatrix
// (used by services_update_policy_test.go) so the matrices cannot
// accidentally share fixture state through a future shared fake, and
// they are deliberately recognisable so deny-path leak guards can
// needle for them; allow-path assertions compare against the same
// canonical values.
func canonicalDeleteSvcForMatrix(orgID, projectID, environmentID string) store.Service {
	created := time.Date(2026, 1, 14, 8, 9, 10, 0, time.UTC)
	updated := time.Date(2026, 5, 16, 11, 12, 13, 0, time.UTC)
	scheduled := time.Date(2026, 5, 16, 11, 12, 13, 0, time.UTC)
	return store.Service{
		ID:                  "svc_matrix_delete",
		OrganizationID:      orgID,
		ProjectID:           projectID,
		EnvironmentID:       environmentID,
		Slug:                "delete-svc",
		DisplayName:         "Delete Service Matrix v2",
		Kind:                "application",
		Version:             23,
		CreatedAt:           created,
		UpdatedAt:           updated,
		DeletionScheduledAt: &scheduled,
	}
}

// deleteSvcDenyBodyLeak reports whether body contains any caller-
// recognisable identifier of the canonical service or its parent
// project / environment. A denied response that accidentally rendered
// any of these fails the test — a denied canonical-row field would
// mean the deleter ran and the response leaked its output even though
// the wire said 403. The quoted forms catch a case-collapsing
// renderer regression. The services table carries no credential
// material at all, and DELETE accepts no request body, so unlike the
// project_variables matrix there is no secret plaintext to anchor and
// unlike the PATCH matrix there is no caller-supplied body field
// either.
func deleteSvcDenyBodyLeak(body string) bool {
	needles := []string{
		"svc_matrix_delete",
		"\"delete-svc\"",
		"\"Delete Service Matrix v2\"",
		"prj_svc_matrix_del_parent",
		"env_svc_matrix_del_parent",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestDeleteServicePolicyMatrixRoles drives every built-in role
// through the production request path. CapWrite splits the matrix:
// Owner / Admin / Developer (own org) are allowed; Viewer / CI /
// Support (own org) are denied. The assertions that matter for allow
// rows are that the verdict is reached through the role
// (ReasonAllowedByRole), the deleter is reached with the principal's
// own home organization id, the {service_id} path parameter, AND the
// principal id (so the audit record names the actor verbatim), and
// the response is a stable 202 Accepted yalla.output.v1 carrying the
// canonical soft-deleted service. For deny rows, the assertions are
// 403 yalla.error.v1, the stable reason on the wire, the deleter
// MUST NEVER run (no row mutated in the background), and the denied
// body must not echo the canonical service or the parent project /
// environment ids.
func TestDeleteServicePolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_del_parent"
		env     = "env_svc_matrix_del_parent"
	)
	svc := canonicalDeleteSvcForMatrix(org, project, env)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svc.ID},
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
			// ReasonDeniedNoCapability because Viewer / CI / Support
			// hold CapRead (and CI CapDeploy) but not CapWrite. (The
			// cross-tenant Support deny is pinned separately in
			// TestDeleteServicePolicyWrongOrganizationPrincipal.)
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionServiceDelete, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(service.delete) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(service.delete) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			var captured store.DeleteServiceInput
			callCount := 0
			deleter := fakeServiceDeleter{
				svc:       svc,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := deleteServiceHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, deleter)
			rec := deleteService(handler, svc.ID, "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("deleter call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("deleter received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svc.ID {
					t.Errorf("deleter received service id %q, want the path parameter %q",
						captured.ServiceID, svc.ID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("deleter received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.IfMatchVersion != nil {
					t.Errorf("deleter received If-Match version %v, want nil (header omitted)",
						captured.IfMatchVersion)
				}
				payload := decodeDeleteServiceBody(t, rec)
				if payload.Data.Service.ID != svc.ID ||
					payload.Data.Service.Slug != svc.Slug ||
					payload.Data.Service.DisplayName != svc.DisplayName ||
					payload.Data.Service.Kind != svc.Kind ||
					payload.Data.Service.OrganizationID != svc.OrganizationID ||
					payload.Data.Service.ProjectID != svc.ProjectID ||
					payload.Data.Service.EnvironmentID != svc.EnvironmentID ||
					payload.Data.Service.Version != svc.Version {
					t.Errorf("service = %+v, want (%s, %s, %s, kind=%s, org=%s, project=%s, env=%s, v=%d)",
						payload.Data.Service, svc.ID, svc.Slug, svc.DisplayName, svc.Kind,
						svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.Version)
				}
				if payload.Data.Service.DeletionScheduledAt == nil || *payload.Data.Service.DeletionScheduledAt == "" {
					t.Errorf("service.deletion_scheduled_at = %v, want non-empty RFC 3339 string — the deleter stamps this on the allow path",
						payload.Data.Service.DeletionScheduledAt)
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
				t.Errorf("deleter was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("deleter captured org=%q svc=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID)
			}
			if body := rec.Body.String(); deleteSvcDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical service or parent project/environment: %s", body)
			}
		})
	}
}

// TestDeleteServicePolicyRevokedAndExpiredKeys proves a principal
// whose credential has been revoked or has expired — both of which
// the auth layer surfaces to the policy engine as a Disabled
// principal — is denied action service.delete with a stable 403
// E_FORBIDDEN, even when the underlying role would have allowed it.
// A revoked or expired credential must never be able to schedule a
// service of the organization it once had access to for teardown,
// the deleter must never run, and the denied body must never echo
// the principal id, the organization id, the path-supplied service
// id, or any seeded service data.
//
// Underlying role is Owner so a working credential WOULD allow
// service.delete; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0192 ("revoked key,
// expired key").
func TestDeleteServicePolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_del_parent"
		env     = "env_svc_matrix_del_parent"
	)
	svc := canonicalDeleteSvcForMatrix(org, project, env)

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

			var captured store.DeleteServiceInput
			callCount := 0
			deleter := fakeServiceDeleter{
				svc:       svc,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := deleteServiceHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, deleter)
			rec := deleteService(handler, svc.ID, "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("deleter was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				deleteSvcDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded service data", body)
			}
		})
	}
}

// TestDeleteServicePolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for service.delete on the service-id route.
// As with service.read and service.update on the same route, the
// resource org id is taken from the PRINCIPAL'S home org — the
// {service_id} path parameter alone never widens the resource to
// another tenant. Tenant isolation on the wire is therefore
// structural at the persistence layer, not the policy boundary:
//
//   - A principal in org_attacker hitting DELETE /v1/services/
//     {svc_victim} with a valid Owner token reaches the engine with
//     a same-tenant resource ({org_attacker, svc_victim}) — allowed
//     by the role at CapWrite — and then reaches the tenant-scoped
//     repository query with the principal's home org id and the
//     foreign service id. A production *store.ServiceService (which
//     combines organization_id and service_id in its WHERE clause)
//     cannot match a row that belongs to another tenant, so the
//     request surfaces as a deterministic 404 E_NOT_FOUND, never
//     disguised as a 202 with foreign data and never as a 403 that
//     would confirm existence. The body must never echo the foreign
//     org id even though no wire input could place it there, because
//     the persistence layer must not leak foreign-tenant identity
//     into the error message.
//
//   - Engine defence-in-depth: even if a future endpoint constructed
//     a resource with a foreign-org scope, EVERY role MUST be denied
//     via ReasonDeniedCrossTenant — INCLUDING Support, which is
//     OUTSIDE the engine's cross-tenant exception for CapWrite
//     actions (`CapSupport && (CapRead || CapSupport)`). This is the
//     load-bearing distinction from the service.read cross-tenant
//     property: read admits Support cross-tenant via
//     ReasonAllowedBySupport, but delete DOES NOT. Pinning that
//     engine verdict here means the eventual scoped variant inherits
//     a working cross-tenant deny for service.delete across every
//     role, and a future catalog change that downgraded
//     service.delete into the support cross-tenant exception (or
//     widened the exception) would fail here before it could regress
//     a real customer.
func TestDeleteServicePolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_delete"
		victimOrgNeedle = "org_victim"
	)

	// Wire-level: an attacker in org_attacker hits DELETE
	// /v1/services/{svc_victim} with a valid Owner token. The fake
	// mirrors the production store contract: it returns NotFound
	// whenever the (organizationID, serviceID) pair does not match a
	// row, so a principal whose home org is org_attacker deleting a
	// service that belongs to org_victim hits the fake with
	// (org_attacker, svc_victim_delete) and gets NotFound. The
	// assertions that matter are structural: the deleter is ALWAYS
	// called with the principal's home org id — never with a caller-
	// controlled value — so a production tenant-scoped ServiceDeleter
	// could not have stamped deletion_scheduled_at on the victim's
	// service regardless of database state. The denied body must
	// never echo the victim's org id.
	var captured store.DeleteServiceInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	deleter := fakeServiceDeleter{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := deleteServiceHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, deleter)
	rec := deleteService(handler, foreignSvcID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a cross-tenant service_id surfaces as NotFound, never 202 with foreign data and never 403 that would confirm existence); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("deleter call count = %d, want 1 — the deleter runs because the engine admits the same-tenant resource, and the persistence layer rejects the foreign service id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("deleter received org id %q, want the attacker's home org %q — the deleter must never be called with another tenant's id",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID {
		t.Errorf("deleter received service id %q, want the path parameter %q",
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

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. service.delete is
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
			got := e.Decide(p, policy.ActionServiceDelete, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(service.delete, foreign org) for %s = %+v, want deny via %q — CapWrite is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestDeleteServicePolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers() rule
// is one-way (a grant scope that pins ProjectID cannot cover a
// resource scope that does not).
//
// The acceptance criteria's three containment properties — sibling
// project, environment grant not implying production, service grant
// shielding parent-level resources and unrelated services — are
// pinned against the engine at their natural scopes (a project
// resource, an env resource, a service resource), then tied back to
// the wire by proving that ALL three scoped key types are denied
// OutOfScope against THIS endpoint (even when the grant names the
// target service's own project, the target service's own
// environment, or the target service's own id), while an
// organization-level Admin grant — which pins no ProjectID and
// covers any resource scope in the same org — is allowed end-to-end.
//
//   - A project-level Admin grant naming THIS service's parent
//     project CANNOT authorize the deletion through this route — the
//     grant scope pins ProjectID and the resource scope does not, so
//     covers() returns false. (The same key DOES authorize
//     service.delete at a service resource in that project — that is
//     the parent-scoped route's job — and the engine pins that
//     property here so the load-bearing distinction between the two
//     routes' authorization surfaces is explicit.)
//   - A project-level Admin grant naming a SIBLING project also
//     CANNOT — same reason at the wire, and the engine pins the
//     sibling-project deny against a service resource in the sibling
//     project.
//   - An environment-level Admin grant naming THIS service's parent
//     environment CANNOT authorize the deletion either, because the
//     grant scope pins ProjectID and the resource scope does not.
//     (The grant DOES authorize service.delete at a service inside
//     the granted env — pinned at the engine — but a staging-scoped
//     grant does not reach production unless production is explicitly
//     granted.)
//   - A service-level Admin grant naming THIS service's id CANNOT
//     either, and at the engine a service grant does not expose
//     env.write on the parent environment nor reach an unrelated
//     sibling service.
//   - An organization-level Admin grant DOES cover any resource
//     scope in the same org (its grant scope pins nothing past
//     OrganizationID) and — because service.delete is CapWrite and
//     Admin holds CapWrite — is allowed via ReasonAllowedByGrant.
//   - An organization-level VIEWER grant covers the resource but
//     confers no write capability; service.delete is denied via
//     ReasonDeniedNoCapability. This is the load-bearing distinction
//     from the service.read grant matrix where an org-level Viewer
//     is allowed.
//
// On the wire all three scoped-key denies are 403 with the stable
// out-of-scope reason, the deleter is never reached (so a production
// store could never have stamped deletion_scheduled_at on a row in
// the background), and the body never echoes the canonical service's
// identifiers or the parent project / environment ids.
func TestDeleteServicePolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = "prj_svc_matrix_del_parent"
		env     = "env_svc_matrix_del_parent"
	)
	svc := canonicalDeleteSvcForMatrix(org, project, env)
	e := policy.NewEngine()

	// Resource the service-id route resolves to: OrganizationID from
	// the principal's home org, ServiceID from the path, NO ProjectID
	// and NO EnvironmentID. Every covers() check below against this
	// resource is the engine-level twin of the wire-level deny on
	// this route.
	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svc.ID},
	}

	// Project-level grant: admin on the parent project. Admin
	// confers CapWrite at the project scope, which would normally be
	// enough for service.delete on a service resource inside that
	// project — and the engine confirms that at a service resource
	// nested inside the parent project, so the load-bearing
	// distinction between this route and a parent-scoped route is
	// explicit.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_del_sibling"}
	projectAdminGrantee := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.delete) at the parent project's service for the target-project admin grantee = %+v, want allow via %q — the parent-scoped route IS authorized for this grant",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_svc_matrix_del_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at a sibling project's service for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Pin the sibling-project containment at the project resource
	// too, to lock the "project-level grants do not imply access to
	// sibling projects" acceptance criterion regardless of which
	// child resource a future endpoint might resolve.
	if got := e.Decide(projectAdminGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(environment.update) at a sibling project for the target-project admin grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine — the load-bearing
	// distinction from any parent-scoped route.
	if got := e.Decide(projectAdminGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way: a grant that pins ProjectID cannot cover a resource scope that does not",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a service resource inside the parent
	// project (which the parent-scoped route would target),
	// service.delete must fail with ReasonDeniedNoCapability — a
	// viewer grant does not widen to a write action even when its
	// scope contains the resource.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionServiceDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(service.delete) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q — a viewer grant confers no write capability",
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
	if got := e.Decide(envStagingGrantee, policy.ActionServiceDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("service.delete on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionServiceDelete, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("service.delete on a service inside production for a staging-scoped grantee = %+v, want deny — a staging grant must not reach production unless production is explicitly granted",
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
	if got := e.Decide(envStagingGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// The same-id env grant (env_svc_matrix_del_parent itself) is
	// ALSO denied OutOfScope on this route, because the grant scope
	// still pins ProjectID and the resource scope does not — the
	// env_id alone is not enough to authorize a top-level deletion
	// through this route. This is the load-bearing property that
	// locks down the service-id route: an environment grant alone
	// does not authorize mutations through it.
	scopeTargetEnv := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetEnv}},
	}
	if got := e.Decide(envTargetGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for a grant on the SAME parent env id = %+v, want deny via %q — covers() is one-way, the env_id alone cannot authorize this route",
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
	if got := e.Decide(svcGrantee, policy.ActionServiceDelete, policy.Resource{Kind: domain.KindService, Scope: scopeSvcA}); !got.Allow {
		t.Errorf("delete the granted service = %+v, want allow", got)
	}
	if got := e.Decide(svcGrantee, policy.ActionServiceDelete, policy.Resource{Kind: domain.KindService, Scope: scopeSvcB}); got.Allow {
		t.Errorf("delete a sibling service = %+v, want deny — a service grant must not reach svc_b",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvWrite, policy.Resource{Kind: domain.KindEnvironment, Scope: parentEnv}); got.Allow {
		t.Errorf("env.write on the parent environment = %+v, want deny — a service grant must not expose parent-level secrets",
			got)
	}
	// And the service grant naming THIS service's own id is still
	// denied OutOfScope at this route's resource scope, because the
	// grant scope pins ProjectID and the resource scope does not — a
	// service grant alone cannot authorize the bare service-id route.
	scopeTargetSvc := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svc.ID}
	svcTargetGrantee := policy.Principal{
		ID: "sa_svc_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetSvc}},
	}
	if got := e.Decide(svcTargetGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for a grant on the SAME service id = %+v, want deny via %q — covers() is one-way, the service_id alone cannot authorize this route",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And against THIS route's resource scope (no ProjectID), the
	// service grant on a sibling service is also denied OutOfScope.
	if got := e.Decide(svcGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for a service-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Wire tie-in #1: the project-scoped Admin grantee hitting the
	// target service via THIS route is a 403 with the stable
	// out-of-scope reason, the deleter is never reached (so a
	// production store could never have stamped deletion_scheduled_at
	// on a row in the background), and the body never echoes the
	// canonical service's identifiers or the parent project /
	// environment ids. This is the property that confines a project-
	// scoped key to a parent-scoped route only.
	var projCaptured store.DeleteServiceInput
	projCallCount := 0
	projDeleter := fakeServiceDeleter{
		svc:       svc, // would be returned if deleter ran — leak guard catches it
		gotInput:  &projCaptured,
		callCount: &projCallCount,
	}
	projHandler := deleteServiceHandlerFor(
		auth.Identity{Principal: projectAdminGrantee, Method: auth.MethodAPIKey}, nil, projDeleter)
	projRec := deleteService(projHandler, svc.ID, "yk_proj_admin_scoped")
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
		t.Errorf("deleter was reached (calls=%d org=%q svc=%q) for a project-scoped grantee; it must never run",
			projCallCount, projCaptured.OrganizationID, projCaptured.ServiceID)
	}
	if body := projRec.Body.String(); deleteSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment: %s", body)
	}

	// Wire tie-in #2: the env-scoped grantee — on the SAME parent
	// environment id — hitting the service-id route is a 403, the
	// deleter is never reached, and the body never echoes the
	// canonical service. This is the load-bearing property that
	// locks down the service-id route: an environment grant alone
	// does not authorize mutations through it.
	var envCaptured store.DeleteServiceInput
	envCallCount := 0
	envDeleter := fakeServiceDeleter{
		svc:       svc,
		gotInput:  &envCaptured,
		callCount: &envCallCount,
	}
	envHandler := deleteServiceHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envDeleter)
	envRec := deleteService(envHandler, svc.ID, "yk_env_scoped")
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
		t.Errorf("deleter was reached (calls=%d org=%q svc=%q) for an env-scoped grantee; it must never run",
			envCallCount, envCaptured.OrganizationID, envCaptured.ServiceID)
	}
	if body := envRec.Body.String(); deleteSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment: %s", body)
	}

	// Wire tie-in #3: the service-scoped grantee — on the SAME
	// service id the path names — hitting the service-id route is a
	// 403, the deleter is never reached, and the body never echoes
	// parent-level identifiers — the "service grant does not expose
	// parent-level secrets or unrelated services" criterion tied to
	// the wire on this route.
	var svcCaptured store.DeleteServiceInput
	svcCallCount := 0
	svcDeleter := fakeServiceDeleter{
		svc:       svc,
		gotInput:  &svcCaptured,
		callCount: &svcCallCount,
	}
	svcHandler := deleteServiceHandlerFor(
		auth.Identity{Principal: svcTargetGrantee, Method: auth.MethodAPIKey}, nil, svcDeleter)
	svcRec := deleteService(svcHandler, svc.ID, "yk_svc_scoped")
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
		t.Errorf("deleter was reached (calls=%d org=%q svc=%q) for a service-scoped grantee; it must never run",
			svcCallCount, svcCaptured.OrganizationID, svcCaptured.ServiceID)
	}
	if body := svcRec.Body.String(); deleteSvcDenyBodyLeak(body) {
		t.Errorf("denied response leaked the canonical service or parent project/environment: %s", body)
	}

	// An organization-level Admin grant DOES cover any resource
	// scope in the same org (its grant scope pins nothing past
	// OrganizationID) and — because service.delete is CapWrite and
	// Admin holds CapWrite — is allowed via ReasonAllowedByGrant.
	// The same key is end-to-end allowed at the wire, with the
	// deleter reached on the principal's home org id, the path
	// service id, and the principal id. This locks the CapWrite
	// requirement against the grant path so a future catalog change
	// that upgraded service.delete above CapWrite would fail here
	// (silently denying every org-level Admin grantee) before it
	// could regress a real customer.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionServiceDelete, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(service.delete) at the service-id route's resource scope for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgCaptured store.DeleteServiceInput
	orgCallCount := 0
	orgDeleter := fakeServiceDeleter{
		svc:       svc,
		gotInput:  &orgCaptured,
		callCount: &orgCallCount,
	}
	orgHandler := deleteServiceHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgDeleter)
	allowedRec := deleteService(orgHandler, svc.ID, "yk_org_admin")
	if allowedRec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeDeleteServiceBody(t, allowedRec)
	if allowedPayload.Data.Service.ID != svc.ID ||
		allowedPayload.Data.Service.Slug != svc.Slug ||
		allowedPayload.Data.Service.OrganizationID != svc.OrganizationID ||
		allowedPayload.Data.Service.ProjectID != svc.ProjectID ||
		allowedPayload.Data.Service.EnvironmentID != svc.EnvironmentID ||
		allowedPayload.Data.Service.Version != svc.Version {
		t.Errorf("service = %+v, want (%s, %s, org=%s, project=%s, env=%s, v=%d)",
			allowedPayload.Data.Service, svc.ID, svc.Slug, svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.Version)
	}
	if allowedPayload.Data.Service.DeletionScheduledAt == nil || *allowedPayload.Data.Service.DeletionScheduledAt == "" {
		t.Errorf("service.deletion_scheduled_at = %v, want non-empty RFC 3339 string on the allow path",
			allowedPayload.Data.Service.DeletionScheduledAt)
	}
	if orgCallCount != 1 {
		t.Errorf("deleter call count = %d, want 1 on the allow path", orgCallCount)
	}
	if orgCaptured.OrganizationID != org {
		t.Errorf("deleter received organization id %q, want the principal's home org %q",
			orgCaptured.OrganizationID, org)
	}
	if orgCaptured.ServiceID != svc.ID {
		t.Errorf("deleter received service id %q, want the path parameter %q",
			orgCaptured.ServiceID, svc.ID)
	}
	if orgCaptured.ActorID != orgAdminGrantee.ID {
		t.Errorf("deleter received actor id %q, want the principal id %q",
			orgCaptured.ActorID, orgAdminGrantee.ID)
	}
	if orgCaptured.IfMatchVersion != nil {
		t.Errorf("deleter received If-Match version %v, want nil (header omitted)",
			orgCaptured.IfMatchVersion)
	}

	// An organization-level VIEWER grant covers the resource but
	// confers no write capability; service.delete must be denied via
	// ReasonDeniedNoCapability even though the grant scope is the
	// whole org. This is the load-bearing distinction from the
	// service.read grant matrix: an org-level Viewer is ALLOWED for
	// read but DENIED for delete.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionServiceDelete, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(service.delete) for an organization-level viewer grant = %+v, want deny via %q — viewer holds no write capability",
			got, policy.ReasonDeniedNoCapability)
	}

	// And the same project-scoped admin grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home org
	// id is org_sibling, cannot be used to delete a service in
	// org_sibling — the cross-tenant guard fires first because the
	// principal's home org no longer matches the grant's scope. This
	// is the engine-level twin of the wire-level "wrong organization"
	// property in TestDeleteServicePolicyWrongOrganizationPrincipal,
	// applied to a scoped key: stealing a key cannot smuggle it
	// across tenants. (service.delete is OUTSIDE the support
	// cross-tenant exception regardless, but the assertion here is
	// structural: a scoped key's home org must match the grant
	// scope's org or the engine refuses to consider the grant at
	// all.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project, EnvironmentID: env, ServiceID: svc.ID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_admin", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionServiceDelete, siblingOrgResource); got.Allow {
		t.Errorf("Decide(service.delete) for a project-scoped admin key planted in a foreign org = %+v, want deny",
			got)
	}
}
