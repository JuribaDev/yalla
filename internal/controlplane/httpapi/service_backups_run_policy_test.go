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

// Policy-matrix coverage for POST
// /v1/services/{service_id}/backups/{backup_id}/run (BE-0255). Where
// service_backups_run_test.go proves the endpoint's wire contract
// (BE-0253 + BE-0254), this file proves its authorization contract:
// that action backup.run cannot be bypassed by — or trigger a run
// because of — the principal's role, revoked credentials, home
// organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the other bare-id /v1/services/{service_id}/... routes carry. The
// authorization contract here is the structural twin of
// services_restart_policy_test.go (same CapDeploy tier, same
// resolver, same one-way covers() rule) — same scoped-grant denial
// pattern, same engine cross-tenant deny for CapDeploy, but the
// allow set widens by one principal compared to backup.create
// because CI keys hold CapDeploy.
//
// backup.run requires CapDeploy (catalog.go: ActionBackupRun ->
// CapDeploy). The role matrix for a principal acting on its own
// organization therefore splits along the deploy capability class:
//   - Owner / Admin / Developer hold CapDeploy and are allowed
//     (ReasonAllowedByRole).
//   - CI is CapSelf+CapRead+CapDeploy and is ALSO allowed
//     (ReasonAllowedByRole). This is the load-bearing distinction
//     from POST /v1/services/{service_id}/backups (backup.create ->
//     CapWrite), where CI is denied. Automation keys CAN trigger
//     backup runs but CANNOT create the backup-policy row.
//   - Viewer is CapSelf+CapRead — denied (ReasonDeniedNoCapability).
//   - Support is CapSelf+CapRead+CapSupport (no CapDeploy) — denied
//     (ReasonDeniedNoCapability). Support is a deliberate cross-
//     tenant READ exception, never a deploy one; the engine's
//     cross-tenant clause is gated on `required == CapRead ||
//     required == CapSupport`, so CapDeploy is OUTSIDE that
//     exception. Privileged Yalla support that needs to trigger a
//     backup on a customer's behalf must go through explicit break-
//     glass admin tooling, not this customer-facing route.
//
// Cross-tenant: backup.run is CapDeploy, OUTSIDE the engine's
// cross-tenant exception — so EVERY role, INCLUDING Support, is
// denied cross-tenant via ReasonDeniedCrossTenant. The customer-
// facing route cannot reach the engine's cross-tenant branch by
// construction (serviceIDResolver pins the resource scope to the
// PRINCIPAL'S home org, not the path service's tenant — the cross-
// tenant deny does NOT apply through this endpoint), but pinning
// the engine verdict here means a future endpoint that resolves the
// resource into a foreign-org scope inherits a working cross-tenant
// deny across every role, and a future catalog change that
// downgraded backup.run to CapRead would fail here (silently
// allowing every support cross-tenant backup run) before it could
// regress a real customer.
//
// The service_backups table carries no credential material — the
// schedule column is a cron-style expression and the backup
// artefact bytes themselves live in the worker / Dokploy / object-
// storage layer and never round-trip through this endpoint. The
// load-bearing deny-leak needle is therefore the canned runner
// output (the row a deny-path fake runner WOULD have returned).
// Tenant-leakage and no-write invariants apply: a denied response
// never echoes the canned backup id / display_name / schedule, the
// foreign tenant's id, or the path service id; and the runner MUST
// never run on any deny path — a scoped key denied on the wire
// cannot have triggered a backup in the background.

const (
	canonicalBackupRunMatrixServiceID   = "svc_matrix_backup_run"
	canonicalBackupRunMatrixBackupID    = "sbkp_matrix_run"
	canonicalBackupRunMatrixDisplayName = "backup-run-matrix-recognisable-needle"
	canonicalBackupRunMatrixSchedule    = "11 5 * * 6"
	canonicalBackupRunMatrixProject     = "prj_backup_run_matrix_parent"
	canonicalBackupRunMatrixEnvironment = "env_backup_run_matrix_parent"
)

// canonicalRunServiceBackup is the row a deny-path fake runner
// would return if it were (incorrectly) reached. The body-leak
// guard needles for these recognisable values, so an accidental
// on-deny render of the "triggered" backup fails the test even
// before the runner-not-reached assertion. The status is pending so
// the row mirrors the post-run state a successful flip would have
// returned, and the version is deliberately non-zero so a wire
// response that surfaced this row would be distinguishable from a
// zero-value envelope.
func canonicalRunServiceBackup(orgID, serviceID string) store.ServiceBackup {
	return store.ServiceBackup{
		ID:             canonicalBackupRunMatrixBackupID,
		OrganizationID: orgID,
		ServiceID:      serviceID,
		DisplayName:    canonicalBackupRunMatrixDisplayName,
		Schedule:       canonicalBackupRunMatrixSchedule,
		RetentionCount: 7,
		Enabled:        true,
		Status:         store.ServiceBackupStatusPending,
		Version:        4,
	}
}

// runServiceBackupDenyBodyLeak reports whether body contains any of
// the canned runner-output fields, the canned parent project /
// environment ids, or other caller-recognisable identifiers. A
// denied response that accidentally rendered any of these fails
// the test: a denied field would mean the runner ran and the
// response leaked its output even though the wire said 403. There
// is no secret plaintext to anchor on — the service_backups table
// carries no credential material at all.
func runServiceBackupDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalBackupRunMatrixBackupID,
		canonicalBackupRunMatrixDisplayName,
		canonicalBackupRunMatrixSchedule,
		canonicalBackupRunMatrixProject,
		canonicalBackupRunMatrixEnvironment,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestRunServiceBackupPolicyMatrixRoles drives every built-in role
// through the production request path. CapDeploy splits the
// matrix: Owner / Admin / Developer / CI (own org) are allowed;
// Viewer / Support (own org) are denied at the role boundary —
// builtinRoleCaps[RoleViewer] is CapSelf+CapRead (no CapDeploy),
// builtinRoleCaps[RoleSupport] is CapSelf+CapRead+CapSupport (no
// CapDeploy). The assertions that matter for allow rows are that
// the verdict is reached through the role (ReasonAllowedByRole),
// the runner is reached with the principal's own home organization
// id, the {service_id} and {backup_id} path parameters, and the
// principal id (so the audit record names the actor verbatim). For
// deny rows: 403 yalla.error.v1, the stable reason on the wire,
// the runner MUST NEVER run, and the denied body must not echo
// the canned backup output or the principal-controlled values.
func TestRunServiceBackupPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupRunMatrixServiceID
		bkpID = canonicalBackupRunMatrixBackupID
	)
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
		{"ci", policy.RoleCI, domain.KindServiceAccount, true, policy.ReasonAllowedByRole},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			// Engine verdict — pinned alongside the wire verdict so a
			// catalog or builtinRoleCaps regression fails here.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionBackupRun, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(backup.run) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(backup.run) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			canonical := canonicalRunServiceBackup(org, svcID)
			var captured store.RunServiceBackupInput
			callCount := 0
			runner := fakeServiceBackupRunner{
				backup:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := runServiceBackupHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, runner)
			rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")

			if tc.allow {
				if rec.Code != http.StatusAccepted {
					t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
				}
				if callCount != 1 {
					t.Errorf("runner call count = %d, want 1 on the allow path", callCount)
				}
				if captured.OrganizationID != org {
					t.Errorf("runner received organization id %q, want the principal's home org %q",
						captured.OrganizationID, org)
				}
				if captured.ServiceID != svcID {
					t.Errorf("runner received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				if captured.BackupID != bkpID {
					t.Errorf("runner received backup id %q, want the path parameter %q",
						captured.BackupID, bkpID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("runner received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
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
				t.Errorf("runner was reached (calls=%d) for a denied principal; it must never run",
					callCount)
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" || captured.BackupID != "" {
				t.Errorf("runner captured org=%q svc=%q bkp=%q for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID, captured.BackupID)
			}
			if body := rec.Body.String(); runServiceBackupDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canned backup output: %s", body)
			}
		})
	}
}

// TestRunServiceBackupPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired —
// both of which the auth layer surfaces to the policy engine as a
// Disabled principal — is denied action backup.run with a stable
// 403 E_FORBIDDEN, even when the underlying role would have
// allowed it. A revoked or expired CI key must never be able to
// trigger a backup in the organization it once had access to; the
// runner must never run; and the denied body must never echo the
// principal id, the organization id, or any seeded backup data.
//
// Underlying role is CI so a working credential WOULD allow
// backup.run; Disabled is the only thing in the way and must be
// load-bearing.
func TestRunServiceBackupPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupRunMatrixServiceID
		bkpID = canonicalBackupRunMatrixBackupID
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

			principal := orgPrincipal(tc.id, org, policy.RoleCI)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			canonical := canonicalRunServiceBackup(org, svcID)
			var captured store.RunServiceBackupInput
			callCount := 0
			runner := fakeServiceBackupRunner{
				backup:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := runServiceBackupHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, runner)
			rec := postRunServiceBackup(handler, svcID, bkpID, "", "yk_no_longer_valid")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("runner was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				runServiceBackupDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded backup data", body)
			}
		})
	}
}

// TestRunServiceBackupPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for backup.run on the service-id route. As
// with backup.create on the same route, the resource org id is
// taken from the PRINCIPAL'S home org — the {service_id} path
// parameter alone never widens the resource to another tenant.
// Tenant isolation on the wire is therefore structural at the
// persistence layer:
//
//   - A principal in org_attacker hitting POST
//     /v1/services/{svc_victim}/backups/{bkp_victim}/run with a
//     valid Owner token reaches the engine with a same-tenant
//     resource ({org_attacker, svc_victim}) — allowed by the role
//     at CapDeploy — and then reaches the tenant-scoped repository
//     queries with the principal's home org id and the foreign
//     ids. A production *store.ServiceBackupService cannot match a
//     service row that belongs to another tenant, so the request
//     surfaces as a deterministic 404 E_NOT_FOUND, never disguised
//     as a 202 with foreign data and never as a 403 that would
//     confirm existence.
//
//   - Engine defence-in-depth: even if a future endpoint
//     constructed a resource with a foreign-org scope, EVERY role
//     MUST be denied via ReasonDeniedCrossTenant — INCLUDING
//     Support, which is OUTSIDE the engine's cross-tenant
//     exception for CapDeploy actions (the exception covers only
//     CapRead and CapSupport).
func TestRunServiceBackupPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_backup_run"
		foreignBkpID    = "sbkp_victim_backup_run"
		victimOrgNeedle = "org_victim"
	)

	var captured store.RunServiceBackupInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	runner := fakeServiceBackupRunner{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := runServiceBackupHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, runner)
	rec := postRunServiceBackup(handler, foreignSvcID, foreignBkpID, "", "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant service_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("runner call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("runner received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID || captured.BackupID != foreignBkpID {
		t.Errorf("runner received (service=%q, backup=%q), want the path parameters (%q, %q)",
			captured.ServiceID, captured.BackupID, foreignSvcID, foreignBkpID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary: pin the verdict directly
	// against a Resource that DOES carry the victim's org id, so a
	// future endpoint that resolves the resource into a foreign org
	// scope inherits a working cross-tenant deny. backup.run is
	// CapDeploy, which is OUTSIDE the engine clause
	// `(CapRead || CapSupport)` — so EVERY role, INCLUDING Support,
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
			got := e.Decide(p, policy.ActionBackupRun, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(backup.run, foreign org) for %s = %+v, want deny via %q — CapDeploy is OUTSIDE the support cross-tenant exception",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestRunServiceBackupPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope and the engine's covers()
// rule is one-way (a grant scope that pins ProjectID cannot cover
// a resource scope that does not).
//
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant
// shielding parent-level resources and unrelated services — are
// pinned against the engine at their natural scopes, then tied
// back to the wire by proving that ALL three scoped key types are
// denied OutOfScope against THIS endpoint (even when the grant
// names the target service's own project, its own environment, or
// its own id), while an organization-level Admin grant — which
// pins no ProjectID and covers any resource scope in the same org
// — is allowed end-to-end.
func TestRunServiceBackupPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalBackupRunMatrixProject
		env     = canonicalBackupRunMatrixEnvironment
		svcID   = "svc_matrix_backup_run_grants"
		bkpID   = "sbkp_matrix_run_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level DEVELOPER grant: developer on the parent
	// project. Developer confers CapDeploy at the project scope,
	// which IS enough for backup.run on a service resource inside
	// that project — the engine confirms that at a service resource
	// nested inside the parent project.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_backup_run_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.run) at the parent project's service for the target-project developer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_backup_run_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Sibling-project containment at the project resource — pins
	// the "project-level grants do not imply sibling projects"
	// criterion.
	if got := e.Decide(projectDevGrantee, policy.ActionBackupRun, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine.
	if got := e.Decide(projectDevGrantee, policy.ActionBackupRun, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project
	// but NOT CapDeploy. Even at a service resource inside the
	// parent project, backup.run must fail with
	// ReasonDeniedNoCapability.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(backup.run) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Project-level CI grant: confers CapRead+CapDeploy at the
	// project. backup.run requires CapDeploy, so the project-scoped
	// CI grant IS allowed at a fully scoped service inside the
	// parent project. This is the load-bearing distinction from
	// backup.create where the same grant is denied
	// (ReasonDeniedNoCapability) — automation keys CAN trigger
	// backup runs but CANNOT create the backup-policy row.
	projectCIGrantee := policy.Principal{
		ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleCI, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectCIGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.run) at a service resource inside the parent project for a project-scoped CI grant = %+v, want allow via %q — CI holds CapDeploy and is allowed on backup.run even though denied on backup.create",
			got, policy.ReasonAllowedByGrant)
	}

	// Environment-level grant: developer on the staging
	// environment. "env grant does not imply access to production
	// unless production is explicitly granted" — pinned at env /
	// service resources.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("backup.run on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("backup.run on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	// Env-to-env containment at the env resource too.
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRun, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// And on THIS endpoint's resource scope, the env-scoped grant
	// is denied at the engine.
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRun, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on THIS service. The grant
	// scope pins ProjectID + EnvironmentID + ServiceID, so the
	// engine's covers() rule denies the bare-id resource scope. At
	// a fully scoped service resource the grant DOES authorize,
	// but a service-level grant does not widen to parent-level
	// resources or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("backup.run on the granted service (full scope) = %+v, want allow",
			got)
	}
	// Service grant does not authorize a parent environment-level
	// action.
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("environment.update on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to the parent env",
			got)
	}
	// Service grant does not authorize an unrelated sibling
	// service.
	if got := e.Decide(svcGrantee, policy.ActionBackupRun, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("backup.run on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	// And on THIS endpoint's bare-id resource scope, the service-
	// scoped grant is denied at the engine — the load-bearing
	// distinction that forces scoped-grant-only principals onto
	// the parent-scoped route.
	if got := e.Decide(svcGrantee, policy.ActionBackupRun, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.run) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so
	// covers() admits any resource scope in the same org. Admin
	// holds CapDeploy, so backup.run is allowed via
	// ReasonAllowedByGrant on the bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionBackupRun, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.run) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: confers CapRead at the org
	// but no CapDeploy. backup.run is denied via
	// ReasonDeniedNoCapability — the load-bearing distinction from
	// the read-side grant matrix.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionBackupRun, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(backup.run) at the service-id route for an org-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting
	// the bare-id route is denied at the boundary by the engine —
	// the runner must never run.
	var capturedProj store.RunServiceBackupInput
	projCallCount := 0
	projRunner := fakeServiceBackupRunner{
		gotInput:  &capturedProj,
		callCount: &projCallCount,
	}
	projHandler := runServiceBackupHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projRunner)
	projRec := postRunServiceBackup(projHandler, svcID, bkpID, "", "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("runner was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); runServiceBackupDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canned backup output: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: a project-scoped CI grant principal also
	// hits the bare-id route's covers() denial — even though CI
	// would have been allowed at the fully-scoped resource. The
	// route shape forces the principal onto a parent-scoped route.
	var capturedCI store.RunServiceBackupInput
	ciCallCount := 0
	ciRunner := fakeServiceBackupRunner{
		gotInput:  &capturedCI,
		callCount: &ciCallCount,
	}
	ciHandler := runServiceBackupHandlerFor(
		auth.Identity{Principal: projectCIGrantee, Method: auth.MethodAPIKey}, nil, ciRunner)
	ciRec := postRunServiceBackup(ciHandler, svcID, bkpID, "", "a-valid-token")
	if ciRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped CI grant wire status = %d, want 403 (engine covers() is one-way); body %s",
			ciRec.Code, ciRec.Body.String())
	}
	if ciCallCount != 0 {
		t.Errorf("runner was reached (calls=%d) for a project-scoped CI grant principal on the bare-id route; the engine must reject before the handler runs",
			ciCallCount)
	}
	if body := ciRec.Body.String(); runServiceBackupDenyBodyLeak(body) {
		t.Errorf("project-scoped CI grant deny response leaked the canned backup output: %s", body)
	}

	// Wire-level proof: an env-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedEnv store.RunServiceBackupInput
	envCallCount := 0
	envRunner := fakeServiceBackupRunner{
		gotInput:  &capturedEnv,
		callCount: &envCallCount,
	}
	envHandler := runServiceBackupHandlerFor(
		auth.Identity{Principal: envStagingGrantee, Method: auth.MethodAPIKey}, nil, envRunner)
	envRec := postRunServiceBackup(envHandler, svcID, bkpID, "", "a-valid-token")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("env-scoped grant wire status = %d, want 403; body %s", envRec.Code, envRec.Body.String())
	}
	if envCallCount != 0 {
		t.Errorf("runner was reached (calls=%d) for an env-scoped grant principal; the engine must reject before the handler runs",
			envCallCount)
	}

	// Wire-level proof: a service-scoped grant principal hitting
	// the bare-id route is denied at the boundary too.
	var capturedSvc store.RunServiceBackupInput
	svcCallCount := 0
	svcRunner := fakeServiceBackupRunner{
		gotInput:  &capturedSvc,
		callCount: &svcCallCount,
	}
	svcHandler := runServiceBackupHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcRunner)
	svcRec := postRunServiceBackup(svcHandler, svcID, bkpID, "", "a-valid-token")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCallCount != 0 {
		t.Errorf("runner was reached (calls=%d) for a service-scoped grant principal; the engine must reject before the handler runs",
			svcCallCount)
	}

	// Wire-level proof: an org-level admin grant principal passes
	// the engine and reaches the runner with the principal's home
	// org id and the path parameters.
	var capturedOrg store.RunServiceBackupInput
	orgCallCount := 0
	orgRunner := fakeServiceBackupRunner{
		backup:    canonicalRunServiceBackup(org, svcID),
		gotInput:  &capturedOrg,
		callCount: &orgCallCount,
	}
	orgHandler := runServiceBackupHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgRunner)
	orgRec := postRunServiceBackup(orgHandler, svcID, bkpID, "", "a-valid-token")
	if orgRec.Code != http.StatusAccepted {
		t.Fatalf("org-admin grant wire status = %d, want 202; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("runner call count = %d, want 1 for an org-level admin grant", orgCallCount)
	}
	if capturedOrg.OrganizationID != org || capturedOrg.ServiceID != svcID || capturedOrg.BackupID != bkpID {
		t.Errorf("runner captured (org=%q, svc=%q, bkp=%q), want (%q, %q, %q) for the org-admin allow path",
			capturedOrg.OrganizationID, capturedOrg.ServiceID, capturedOrg.BackupID, org, svcID, bkpID)
	}
}
