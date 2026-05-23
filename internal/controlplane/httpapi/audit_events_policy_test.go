package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Policy-matrix coverage for GET /v1/organizations/{org_id}/audit-events
// (BE-0105). Where audit_events_test.go proves the endpoint's wire
// contract, this file proves its authorization contract: that action
// audit.read cannot be bypassed by, or leak data because of, the
// principal's role, revoked credentials, home organization, or scoped
// grants.
//
// The route carries organizationIDResolver (routes.go), which scopes the
// policy.Resource to the {org_id} path parameter
// (Kind=domain.KindOrganization). RequireAuth therefore authorizes
// against the organization the {org_id} path NAMES — not merely the
// principal's home organization. So a cross-tenant {org_id} must be a
// deterministic 403 before the handler runs, while an {org_id} naming
// the caller's own organization is allowed by roles whose capability set
// contains CapAdmin, or by a grant whose scope covers the organization
// root AND whose role contains CapAdmin — never by a deeper-scoped
// grant.
//
// audit.read requires CapAdmin (catalog.go: ActionAuditRead->CapAdmin).
// The role-to-capability matrix (catalog.go) admits CapAdmin only for
// RoleOwner and RoleAdmin: Developer, Viewer, CI, and Support all lack
// it. So the role matrix is "owner+admin allow, the other four
// in-tenant roles deny via ReasonDeniedNoCapability" — already a
// load-bearing difference from CapRead endpoints (limits.read,
// usage.read) where every built-in role allows.
//
// Crucially, the engine's cross-tenant clause permits Support only when
// `required == CapRead || required == CapSupport`. For audit.read
// (CapAdmin) that clause does not fire, so even a Support principal
// reading another tenant's audit log is denied with
// ReasonDeniedCrossTenant. This is the load-bearing distinction from
// the limits.read and usage policy matrices, where Support IS allowed
// cross-tenant. A future drop of audit.read to CapRead would silently
// expose every tenant's audit trail to Support; the cross-tenant test
// here is the structural barrier against that change.
//
// Each test drives the real NewHandler + real policy.NewEngine() — the
// production request path — so a regression in the middleware, the
// action catalog, the organizationIDResolver, or the engine fails here.
// listAuditEventsHandlerFor, auditEventActorIdentity, getAuditEvents,
// decodeAuditEventList, fakeAuditEventReader, orgPrincipal, and
// decodeError are shared with the sibling audit-events contract suite
// (audit_events_test.go) and the wider httpapi test fixtures; this file
// adds no scaffolding beyond the small fixture builder below.

// seededAuditEvents builds the canonical two-event fixture every test
// in this file shares — one allowed event with both actor and resource
// resolved, and one denied event with no resolved principal. Keeping
// the fixture in one place keeps the matrix-mode assertions concise:
// every allowed test exercises the same projection (including the
// nullable actor/resource objects) and every denied test pins the same
// redaction invariants against the same data.
func seededAuditEvents(orgID string) []store.AuditEvent {
	occurred := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	return []store.AuditEvent{
		{
			ID:             "aud_alpha",
			OrganizationID: orgID,
			ActorID:        "usr_admin",
			ActorKind:      domain.KindUser.String(),
			Action:         "limits.write",
			ResourceKind:   "organization",
			ResourceID:     orgID,
			Decision:       store.AuditDecisionAllowed,
			Reason:         "role_capability",
			RequestID:      "req_abc",
			CorrelationID:  "cor_xyz",
			IPAddress:      "203.0.113.7",
			UserAgent:      "yalla-cli/1.0",
			Metadata:       map[string]string{"updated_resources": "projects"},
			OccurredAt:     occurred,
		},
		{
			ID:             "aud_beta",
			OrganizationID: orgID,
			Action:         "organization.read",
			Decision:       store.AuditDecisionDenied,
			Reason:         "no_principal",
			RequestID:      "req_def",
			OccurredAt:     occurred.Add(-time.Hour),
		},
	}
}

// auditEventsBodyLeak reports whether body contains any of the
// non-public values seeded by seededAuditEvents — the per-event ids,
// the actor id, the IP/user-agent, the metadata key/value, and the
// recorded action — so a denied response that accidentally rendered
// any of them fails the test. Decision/Reason strings ("allowed",
// "role_capability") are deliberately NOT in this list because they
// are stable, non-secret enum values shared with other surfaces; a
// denied response that happens to mention "denied" or "denied_*" is
// expected because that IS the policy verdict, and pinning against
// those strings would create a false signal.
func auditEventsBodyLeak(body string) bool {
	needles := []string{
		"aud_alpha", "aud_beta",
		"usr_admin",
		"limits.write", "organization.read",
		"203.0.113.7", "yalla-cli",
		"updated_resources", "projects",
		"req_abc", "cor_xyz", "req_def",
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestListAuditEventsPolicyMatrixRoles drives every built-in role
// through the production request path against an {org_id} that names
// its own home organization. The matrix is split:
//
//   - Owner and Admin hold CapAdmin → ReasonAllowedByRole; the handler
//     returns 200 with the seeded events. Behind the wire we also
//     verify the reader was called on exactly the path parameter.
//
//   - Developer, Viewer, CI, and Support do NOT hold CapAdmin
//     (catalog.go's builtinRoleCaps). Each is denied with
//     ReasonDeniedNoCapability — no grant in scope and no capability
//     supplied by the role. This is the load-bearing distinction from
//     CapRead endpoints (limits.read, usage.read): on those endpoints
//     every built-in role allows; on audit.read four of six in-tenant
//     roles deny.
//
// Denied requests must never invoke the reader and must never echo
// seeded audit data in the error body.
func TestListAuditEventsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	cases := []struct {
		name      string
		role      policy.Role
		kind      domain.Kind
		wantAllow bool
		wantCode  int
	}{
		{"owner", policy.RoleOwner, domain.KindUser, true, http.StatusOK},
		{"admin", policy.RoleAdmin, domain.KindUser, true, http.StatusOK},
		{"developer", policy.RoleDeveloper, domain.KindUser, false, http.StatusForbidden},
		{"viewer", policy.RoleViewer, domain.KindUser, false, http.StatusForbidden},
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, http.StatusForbidden},
		{"support", policy.RoleSupport, domain.KindUser, false, http.StatusForbidden},
	}

	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionAuditRead, orgRoot)
			if got.Allow != tc.wantAllow {
				t.Errorf("Decide(audit.read) for role %q = %+v, want allow=%v", tc.role, got, tc.wantAllow)
			}
			if tc.wantAllow {
				if got.Reason != policy.ReasonAllowedByRole {
					t.Errorf("allow reason for role %q = %q, want %q", tc.role, got.Reason, policy.ReasonAllowedByRole)
				}
			} else {
				if got.Reason != policy.ReasonDeniedNoCapability {
					t.Errorf("deny reason for role %q = %q, want %q (role lacks CapAdmin and no grant supplies it)",
						tc.role, got.Reason, policy.ReasonDeniedNoCapability)
				}
			}

			var seen string
			reader := fakeAuditEventReader{events: seededAuditEvents(org), gotOrgID: &seen}
			handler := listAuditEventsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader)

			rec := getAuditEvents(handler, org, "", "a-valid-token")
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantCode, rec.Body.String())
			}

			if tc.wantAllow {
				if seen != org {
					t.Errorf("reader received organization id %q, want the path parameter %q", seen, org)
				}
				env := decodeAuditEventList(t, rec.Body.Bytes())
				if env.SchemaVersion != "yalla.output.v1" {
					t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
				}
				if len(env.Data.Events) != 2 {
					t.Fatalf("events len = %d, want 2; events=%+v", len(env.Data.Events), env.Data.Events)
				}
				if env.Data.Events[0].ID != "aud_alpha" || env.Data.Events[1].ID != "aud_beta" {
					t.Errorf("event ids = [%s, %s], want [aud_alpha, aud_beta]",
						env.Data.Events[0].ID, env.Data.Events[1].ID)
				}
				return
			}

			env := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedNoCapability)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					env.Error.Message, policy.ReasonDeniedNoCapability)
			}
			if seen != "" {
				t.Errorf("reader was reached with org=%q for a denied role; it must never run", seen)
			}
			if auditEventsBodyLeak(rec.Body.String()) {
				t.Errorf("denied response leaks seeded audit data: %s", rec.Body.String())
			}
		})
	}
}

// TestListAuditEventsPolicyDisabledPrincipal proves a revoked or
// expired API key is rejected at the policy boundary even when the
// underlying role would otherwise allow audit.read. The auth layer
// surfaces a disabled credential as a Principal{Disabled: true};
// policy.Engine.Decide rejects it deterministically with
// ReasonDeniedPrincipalDisabled BEFORE consulting the role matrix, so
// a freshly-revoked owner key cannot read its own organization's
// audit log. The handler is reached through RequireAuth(authenticator,
// engine, ...) so the engine verdict IS the wire verdict here.
//
// Underlying role is Owner so a working credential WOULD allow
// audit.read; Disabled is the only thing in the way and must be
// load-bearing. The case names mirror PRD BE-0105 ("revoked key,
// expired key").
func TestListAuditEventsPolicyDisabledPrincipal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
	}{
		{"revoked-key", "sa_revoked"},
		{"expired-key", "sa_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal(tc.id, "org_acme", policy.RoleOwner)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			var seen string
			reader := fakeAuditEventReader{events: seededAuditEvents("org_acme"), gotOrgID: &seen}
			handler := listAuditEventsHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, reader)

			rec := getAuditEvents(handler, "org_acme", "", "yk_no_longer_valid")
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
			if strings.Contains(body, tc.id) || strings.Contains(body, "org_acme") || auditEventsBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded audit data", body)
			}
		})
	}
}

// TestListAuditEventsPolicyWrongOrganizationPrincipal proves
// audit.read is confined to the caller's own tenant — without the
// Support exception that limits.read and usage.read enjoy.
//
// The route carries organizationIDResolver, so RequireAuth authorizes
// against the organization the {org_id} path names:
//
//   - A non-support owner of org_attacker reading the audit log of
//     org_victim is a deterministic 403 ReasonDeniedCrossTenant; the
//     reader is never reached, and the denied body never echoes the
//     foreign organization or any of its seeded audit data.
//
//   - A Support principal of org_yalla performing the same
//     cross-tenant read is ALSO denied with ReasonDeniedCrossTenant.
//     This is the load-bearing distinction from limits.read/usage,
//     which the policy engine's cross-tenant clause admits via
//     `roleCaps.has(CapSupport) && (required == CapRead || required
//     == CapSupport)` — audit.read is CapAdmin, outside that clause.
//     A future regression that dropped audit.read to CapRead would
//     silently expose every tenant's audit log to Support; this test
//     is the structural barrier against that change.
//
// The engine verdict is pinned alongside the wire verdict for both
// principals so a regression in either layer fails here.
func TestListAuditEventsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg    = "org_attacker"
		victimOrg = "org_victim"
	)
	victimEvents := seededAuditEvents(victimOrg)

	// Non-support owner of org_attacker reading org_victim → 403.
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	var intruderSeen string
	intruderReader := fakeAuditEventReader{events: victimEvents, gotOrgID: &intruderSeen}
	intruderHandler := listAuditEventsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, intruderReader)

	rec := getAuditEvents(intruderHandler, victimOrg, "", "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if intruderSeen != "" {
		t.Errorf("reader was reached with org=%q for a cross-tenant request; it must never run", intruderSeen)
	}
	body := rec.Body.String()
	if strings.Contains(body, victimOrg) || auditEventsBodyLeak(body) {
		t.Errorf("error body %s echoed the cross-tenant organization or seeded audit data", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly so
	// the resolver-shape (organization-root scope of the {org_id} path
	// parameter) is exactly what the engine sees.
	e := policy.NewEngine()
	foreign := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: victimOrg}}
	if got := e.Decide(intruder, policy.ActionAuditRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(audit.read, foreign org) for owner = %+v, want deny via %q",
			got, policy.ReasonDeniedCrossTenant)
	}

	// Support is NOT a cross-tenant exception for CapAdmin actions: the
	// engine clause `roleCaps.has(CapSupport) && (required == CapRead
	// || required == CapSupport)` does NOT cover CapAdmin, so Support
	// is denied cross-tenant here. This is the load-bearing distinction
	// from limits.read/usage.read where Support IS allowed cross-tenant
	// via ReasonAllowedBySupport. Pin the engine verdict AND the wire
	// verdict so a future drop of audit.read to CapRead would fail BOTH
	// (and would not silently expose audit trails to Support).
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionAuditRead, foreign); got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
		t.Errorf("Decide(audit.read, foreign org) for support = %+v, want deny via %q (CapAdmin is OUTSIDE the support cross-tenant exception)",
			got, policy.ReasonDeniedCrossTenant)
	}

	var supportSeen string
	supportReader := fakeAuditEventReader{events: victimEvents, gotOrgID: &supportSeen}
	supportHandler := listAuditEventsHandlerFor(
		auth.Identity{Principal: support, Method: auth.MethodSession}, nil, supportReader)
	supportRec := getAuditEvents(supportHandler, victimOrg, "", "a-valid-support-token")
	if supportRec.Code != http.StatusForbidden {
		t.Fatalf("support status = %d, want 403 — audit.read is CapAdmin, outside the support cross-tenant exception; body %s",
			supportRec.Code, supportRec.Body.String())
	}
	supportEnv := decodeError(t, supportRec, "E_FORBIDDEN")
	if !strings.Contains(supportEnv.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("support message = %q, want it to carry %q",
			supportEnv.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if supportSeen != "" {
		t.Errorf("support reader was reached with org=%q for an out-of-exception cross-tenant request; it must never run",
			supportSeen)
	}
	if supportBody := supportRec.Body.String(); strings.Contains(supportBody, victimOrg) || auditEventsBodyLeak(supportBody) {
		t.Errorf("support error body %s echoed the cross-tenant organization or seeded audit data", supportBody)
	}
}

// TestListAuditEventsPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for. A scoped API
// key is authorized purely by its grants (it carries no organization
// role); the engine confines those grants — a project grant does not
// reach a sibling project, an environment grant does not reach
// production, a service grant does not reach the parent environment
// or a sibling service.
//
// Crucially for GET /v1/organizations/{org_id}/audit-events:
// audit.read is evaluated against the organization-root scope the
// {org_id} path names. A project/environment/service-scoped grant —
// even an Admin grant — does not cover that scope, not even for the
// key's own organization. So a scoped key holding only a project
// grant is denied the endpoint for its own {org_id} with the stable
// ReasonDeniedOutOfScope.
//
// A second load-bearing property unique to audit.read: an
// organization-level Viewer grant — which would suffice for the
// CapRead-gated limits.read/usage endpoints — is denied here because
// Viewer does not hold CapAdmin. Only an organization-level grant
// whose role holds CapAdmin (Admin / Owner) allows the read. So we
// pin both the deny (org-level Viewer grant → ReasonDeniedNoCapability)
// and the allow (org-level Admin grant → ReasonAllowedByGrant).
//
// The acceptance criteria's three containment properties — sibling
// project, production environment, parent-level secrets — are pinned
// against the engine via the project/env/service grants, then tied
// back to the wire by proving the project grantee is denied the
// endpoint at its own {org_id}, while an organization-scoped Admin
// grantee is allowed it.
func TestListAuditEventsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	e := policy.NewEngine()

	// Project-level grant: admin on proj_p only. Sibling-project
	// containment is pinned via the project-update action so the grant
	// has the relevant capability at the relevant scope.
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

	// Service-level grant: admin on a single service only. The grant
	// must not expose parent-level secrets (env-write on the parent
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

	// GET /v1/organizations/{org_id}/audit-events reads against the
	// organization root the {org_id} path names. A
	// project/environment/service-scoped admin grant does NOT cover
	// that scope — not even for the key's own organization — so each
	// scoped grantee is denied the endpoint with
	// ReasonDeniedOutOfScope: the scoped key cannot be widened to an
	// organization-wide audit read, and the reader never runs.
	orgRoot := policy.Resource{Kind: domain.KindOrganization, Scope: policy.Scope{OrganizationID: org}}
	if got := e.Decide(projectGrantee, policy.ActionAuditRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(audit.read) for a project-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envGrantee, policy.ActionAuditRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(audit.read) for an environment-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(svcGrantee, policy.ActionAuditRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(audit.read) for a service-scoped key = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Capability containment unique to audit.read: an organization-level
	// Viewer grant covers the org-root scope, but Viewer does not hold
	// CapAdmin, so the engine denies with ReasonDeniedNoCapability (no
	// grant in scope supplies the required capability, no role on the
	// key supplies it either). This is the LOAD-BEARING distinction
	// from CapRead-gated endpoints — a future regression that dropped
	// audit.read to CapRead would silently let every org-level Viewer
	// grantee read the audit log; this assertion fails first.
	orgViewer := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewer, policy.ActionAuditRead, orgRoot); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(audit.read) for an organization-level viewer grant = %+v, want deny via %q (Viewer lacks CapAdmin)",
			got, policy.ReasonDeniedNoCapability)
	}

	// Tie back at the wire: the project-scoped grantee reading the
	// audit log of its OWN organization is a 403 with the stable
	// out-of-scope reason, the reader is never reached, and the body
	// never echoes the seeded audit data. This is the property that
	// makes the policy boundary — not the persistence boundary — the
	// structural place a scoped key is denied broader visibility.
	var projectSeen string
	projectReader := fakeAuditEventReader{events: seededAuditEvents(org), gotOrgID: &projectSeen}
	projectHandler := listAuditEventsHandlerFor(
		auth.Identity{Principal: projectGrantee, Method: auth.MethodAPIKey}, nil, projectReader)
	rec := getAuditEvents(projectHandler, org, "", "yk_proj_scoped")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a project-scoped key; body %s",
			rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			denyEnv.Error.Message, policy.ReasonDeniedOutOfScope)
	}
	if projectSeen != "" {
		t.Errorf("reader was reached with org=%q for an out-of-scope grantee; it must never run",
			projectSeen)
	}
	if body := rec.Body.String(); auditEventsBodyLeak(body) {
		t.Errorf("denied response leaks seeded audit data: %s", body)
	}

	// An organization-level Admin grant DOES cover the org-root scope
	// AND holds CapAdmin (catalog.go's builtinRoleCaps) — engine
	// permits via ReasonAllowedByGrant; the wire returns 200 with the
	// seeded events, and the reader is reached on the {org_id}
	// parameter. This locks the CapAdmin requirement against the grant
	// path so a future catalog change that downgraded audit.read below
	// CapAdmin would let a weaker grant through and break the matrix.
	orgAdmin := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdmin, policy.ActionAuditRead, orgRoot); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(audit.read) for an organization-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	var orgSeen string
	orgReader := fakeAuditEventReader{events: seededAuditEvents(org), gotOrgID: &orgSeen}
	orgHandler := listAuditEventsHandlerFor(
		auth.Identity{Principal: orgAdmin, Method: auth.MethodAPIKey}, nil, orgReader)
	allowedRec := getAuditEvents(orgHandler, org, "", "yk_org_admin")
	if allowedRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an org-level admin grant; body %s",
			allowedRec.Code, allowedRec.Body.String())
	}
	allowedPayload := decodeAuditEventList(t, allowedRec.Body.Bytes())
	if len(allowedPayload.Data.Events) != 2 ||
		allowedPayload.Data.Events[0].ID != "aud_alpha" ||
		allowedPayload.Data.Events[1].ID != "aud_beta" {
		t.Errorf("allowed payload events = %+v, want the seeded [aud_alpha, aud_beta]",
			allowedPayload.Data.Events)
	}
	if orgSeen != org {
		t.Errorf("org-admin reader received organization id %q, want the path parameter %q",
			orgSeen, org)
	}
}
