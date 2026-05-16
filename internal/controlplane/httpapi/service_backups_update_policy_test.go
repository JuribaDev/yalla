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

// Policy-matrix coverage for PATCH
// /v1/services/{service_id}/backups/{backup_id} (BE-0258). Where
// service_backups_update_test.go proves the endpoint's wire contract
// (BE-0256 + BE-0257), this file proves its authorization contract:
// that action backup.update cannot be bypassed by — or commit a
// backup-policy row mutation because of — the principal's role,
// revoked credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), the same resolver
// the other bare-id /v1/services/{service_id}/... routes carry. The
// authorization contract here is the structural twin of
// service_domains_update_policy_test.go (BE-0243, same CapWrite
// tier, same resolver) — same scoped-grant denial pattern, same
// support-cross-tenant suppression at the resolver, same engine
// cross-tenant deny for CapWrite. The path carries no parent
// project_id, so the resource scope leaves ProjectID empty and the
// engine's covers() rule is one-way (a grant scope that pins
// ProjectID cannot cover a resource scope that does not): ALL
// project-, environment-, and service-scoped grants are denied at
// the boundary via ReasonDeniedOutOfScope — even a service-scoped
// Admin grant naming THIS service's id, because the bare-id resource
// scope has no ProjectID for the grant to cover.
//
// backup.update requires CapWrite (catalog.go: ActionBackupUpdate ->
// CapWrite). The role matrix for a principal acting on its own
// organization therefore splits along the write capability class:
//   - Owner / Admin / Developer hold CapWrite and are allowed
//     (ReasonAllowedByRole).
//   - CI is CapSelf+CapRead+CapDeploy (no CapWrite) — denied
//     (ReasonDeniedNoCapability). Automation keys CAN trigger
//     deployments but CANNOT mutate backup-policy rows.
//   - Viewer is CapSelf+CapRead — denied
//     (ReasonDeniedNoCapability).
//   - Support is CapSelf+CapRead+CapSupport (no CapWrite) — denied
//     (ReasonDeniedNoCapability). Support is a deliberate cross-
//     tenant READ exception, never a write one.
//
// Cross-tenant: backup.update is CapWrite, OUTSIDE the engine's
// cross-tenant exception — so EVERY role, INCLUDING Support, is
// denied cross-tenant via ReasonDeniedCrossTenant.
//
// The service_backups table carries no credential material — the
// backup artefact bytes live in the worker / Dokploy / object-
// storage layer and never round-trip through this endpoint. The
// load-bearing deny-leak needles are therefore the caller-supplied
// request-body fields, the path backup_id, and the canned updater
// output. Tenant-leakage and no-write invariants apply: a denied
// response never echoes the canonical request-body fields, the
// canonical backup id / display_name / schedule, the foreign
// tenant's id, or the path service id; and the updater MUST never
// run on any deny path — a scoped key denied on the wire cannot
// have committed a backup row mutation in the background.

const (
	canonicalBackupUpdateMatrixServiceID   = "svc_matrix_backup_update"
	canonicalBackupUpdateMatrixBackupID    = "bkp_matrix_update"
	canonicalBackupUpdateMatrixDisplayName = "backup-update-matrix-recognisable-needle"
	canonicalBackupUpdateMatrixSchedule    = "0 4 * * matrix-update-recognisable-needle"
	canonicalBackupUpdateMatrixProject     = "prj_backup_update_matrix_parent"
	canonicalBackupUpdateMatrixEnvironment = "env_backup_update_matrix_parent"
)

// canonicalUpdateServiceBackupBody is the canonical JSON request
// body every test in this file shares. The body intentionally
// exposes no organization_id, service_id, or id field — the
// production handler derives the organization id from the
// principal's home org, the service id from the {service_id} path
// parameter, and the backup id from the {backup_id} path parameter,
// never from the body — and the strict JSON decoder rejects an
// unknown field smuggled into the body before the updater ever
// runs.
const canonicalUpdateServiceBackupBody = `{"display_name":"backup-update-matrix-recognisable-needle","schedule":"0 4 * * matrix-update-recognisable-needle","retention_count":21,"enabled":true}`

// canonicalUpdatedMatrixServiceBackup is the row a deny-path fake
// updater would return if it were (incorrectly) reached. The body-
// leak guard needles for these recognisable values, so an
// accidental on-deny render of the "updated" backup fails the test
// even before the updater-not-reached assertion.
func canonicalUpdatedMatrixServiceBackup(orgID, serviceID string) store.ServiceBackup {
	return store.ServiceBackup{
		ID:             canonicalBackupUpdateMatrixBackupID,
		OrganizationID: orgID,
		ServiceID:      serviceID,
		DisplayName:    canonicalBackupUpdateMatrixDisplayName,
		Schedule:       canonicalBackupUpdateMatrixSchedule,
		RetentionCount: 21,
		Enabled:        true,
		Status:         store.ServiceBackupStatusPending,
		Version:        2,
	}
}

// updateServiceBackupDenyBodyLeak reports whether body contains any
// of the caller-supplied request-body fields, the canned updated-
// backup fields, the canned parent project / environment ids, or
// other caller-recognisable identifiers. A denied response that
// accidentally rendered any of these fails the test: a denied
// request-body field would mean the handler echoed the request
// after policy denial (a tenant boundary smell), and a denied
// updated-backup field would mean the updater ran and the response
// leaked its output even though the wire said 403.
func updateServiceBackupDenyBodyLeak(body string) bool {
	needles := []string{
		canonicalBackupUpdateMatrixBackupID,
		canonicalBackupUpdateMatrixDisplayName,
		canonicalBackupUpdateMatrixSchedule,
		canonicalBackupUpdateMatrixProject,
		canonicalBackupUpdateMatrixEnvironment,
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

// TestUpdateServiceBackupPolicyMatrixRoles drives every built-in
// role through the production request path. CapWrite splits the
// matrix: Owner / Admin / Developer (own org) are allowed; CI /
// Viewer / Support (own org) are denied at the role boundary.
func TestUpdateServiceBackupPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupUpdateMatrixServiceID
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
		{"ci", policy.RoleCI, domain.KindServiceAccount, false, policy.ReasonDeniedNoCapability},
		{"viewer", policy.RoleViewer, domain.KindUser, false, policy.ReasonDeniedNoCapability},
		{"support", policy.RoleSupport, domain.KindUser, false, policy.ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			principal := orgPrincipal("usr_"+tc.name, org, tc.role)
			principal.Kind = tc.kind

			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionBackupUpdate, svcResource)
			if tc.allow {
				if !got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(backup.update) for %s = %+v, want allow via %q",
						tc.name, got, tc.reason)
				}
			} else {
				if got.Allow || got.Reason != tc.reason {
					t.Errorf("Decide(backup.update) for %s = %+v, want deny via %q",
						tc.name, got, tc.reason)
				}
			}

			canonical := canonicalUpdatedMatrixServiceBackup(org, svcID)
			var captured store.UpdateServiceBackupInput
			callCount := 0
			updater := fakeServiceBackupUpdater{
				backup:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := updateServiceBackupHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, updater)
			rec := patchServiceBackup(handler, svcID, canonicalBackupUpdateMatrixBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)

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
				if captured.ServiceID != svcID {
					t.Errorf("updater received service id %q, want the path parameter %q",
						captured.ServiceID, svcID)
				}
				if captured.BackupID != canonicalBackupUpdateMatrixBackupID {
					t.Errorf("updater received backup id %q, want the path parameter %q",
						captured.BackupID, canonicalBackupUpdateMatrixBackupID)
				}
				if captured.ActorID != principal.ID {
					t.Errorf("updater received actor id %q, want the principal id %q",
						captured.ActorID, principal.ID)
				}
				if captured.DisplayName == nil || *captured.DisplayName != canonicalBackupUpdateMatrixDisplayName ||
					captured.Schedule == nil || *captured.Schedule != canonicalBackupUpdateMatrixSchedule {
					t.Errorf("updater intent fields wrong (display_name=%v, schedule=%v)",
						captured.DisplayName, captured.Schedule)
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
			if captured.OrganizationID != "" || captured.ServiceID != "" || captured.BackupID != "" {
				t.Errorf("updater captured (org=%q svc=%q bkp=%q) for a denied principal; it must never run",
					captured.OrganizationID, captured.ServiceID, captured.BackupID)
			}
			if body := rec.Body.String(); updateServiceBackupDenyBodyLeak(body) {
				t.Errorf("denied response leaked the canonical backup or caller-supplied request body: %s", body)
			}
		})
	}
}

// TestUpdateServiceBackupPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired is
// denied action backup.update with a stable 403 E_FORBIDDEN, even
// when the underlying role would have allowed it.
func TestUpdateServiceBackupPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupUpdateMatrixServiceID
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

			principal := orgPrincipal(tc.id, org, policy.RoleDeveloper)
			principal.Kind = domain.KindServiceAccount
			principal.Disabled = true

			canonical := canonicalUpdatedMatrixServiceBackup(org, svcID)
			var captured store.UpdateServiceBackupInput
			callCount := 0
			updater := fakeServiceBackupUpdater{
				backup:    canonical,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := updateServiceBackupHandlerFor(
				auth.Identity{Principal: principal, Method: auth.MethodAPIKey}, nil, updater)
			rec := patchServiceBackup(handler, svcID, canonicalBackupUpdateMatrixBackupID, "yk_no_longer_valid", canonicalUpdateServiceBackupBody)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			denyEnv := decodeError(t, rec, "E_FORBIDDEN")
			if !strings.Contains(denyEnv.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
				t.Errorf("message = %q, want it to carry the stable reason %q",
					denyEnv.Error.Message, policy.ReasonDeniedPrincipalDisabled)
			}
			if callCount != 0 || captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("updater was reached (calls=%d org=%q svc=%q) for a disabled principal; it must never run",
					callCount, captured.OrganizationID, captured.ServiceID)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				updateServiceBackupDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or seeded backup data", body)
			}
		})
	}
}

// TestUpdateServiceBackupPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for backup.update on the service-id route.
// As with the create-backup twin, the resource org id is taken from
// the PRINCIPAL'S home org — the {service_id} path parameter alone
// never widens the resource to another tenant. Tenant isolation on
// the wire is therefore structural at the persistence layer: a
// production store cannot match a service-backups row that belongs
// to another tenant, so the request surfaces as a deterministic 404
// E_NOT_FOUND.
func TestUpdateServiceBackupPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_backup_patch"
		foreignBackupID = "bkp_victim_patch"
		victimOrgNeedle = "org_victim"
	)

	var captured store.UpdateServiceBackupInput
	callCount := 0
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	updater := fakeServiceBackupUpdater{
		err:       apierr.NotFound("service backup", foreignBackupID),
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, updater)
	rec := patchServiceBackup(handler, foreignSvcID, foreignBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("updater call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("updater received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
	}
	if captured.ServiceID != foreignSvcID {
		t.Errorf("updater received service id %q, want the path parameter %q",
			captured.ServiceID, foreignSvcID)
	}
	if captured.BackupID != foreignBackupID {
		t.Errorf("updater received backup id %q, want the path parameter %q",
			captured.BackupID, foreignBackupID)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary: backup.update is CapWrite,
	// OUTSIDE the engine clause `CapSupport && (CapRead || CapSupport)`
	// — so EVERY role, INCLUDING Support, is denied cross-tenant.
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
			got := e.Decide(p, policy.ActionBackupUpdate, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(backup.update, foreign org) for %s = %+v, want deny via %q",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}
}

// TestUpdateServiceBackupPolicyGrantContainment proves scoped grants
// cannot be widened past the scope they were issued for AND cannot
// reach this endpoint at all — every project-, environment-, and
// service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope on the bare-id route.
func TestUpdateServiceBackupPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalBackupUpdateMatrixProject
		env     = canonicalBackupUpdateMatrixEnvironment
		svcID   = "svc_matrix_backup_update_grants"
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level developer grant.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_backup_update_matrix_sibling"}
	projectDevGrantee := policy.Principal{
		ID: "sa_proj_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectDevGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.update) at the parent project's service for the target-project developer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectDevGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_backup_update_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// Sibling-project containment at the project resource.
	if got := e.Decide(projectDevGrantee, policy.ActionBackupUpdate, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	// On THIS endpoint's resource scope (no ProjectID), the same
	// target-project grant is denied at the engine.
	if got := e.Decide(projectDevGrantee, policy.ActionBackupUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Project-level VIEWER grant: confers CapRead at the project but
	// not CapWrite. Even at a service resource inside the parent
	// project, backup.update must fail with
	// ReasonDeniedNoCapability.
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(backup.update) at a service resource inside the parent project for a project-scoped viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Project-level CI grant: confers CapRead+CapDeploy at the
	// project but not CapWrite. Even at a service resource inside
	// the parent project, backup.update must fail with
	// ReasonDeniedNoCapability — automation keys are explicitly
	// disallowed from mutating backup policies.
	projectCIGrantee := policy.Principal{
		ID: "sa_proj_ci", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleCI, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectCIGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(backup.update) at a service resource inside the parent project for a project-scoped CI grant = %+v, want deny via %q — CI grants do NOT confer CapWrite",
			got, policy.ReasonDeniedNoCapability)
	}

	// Environment-level grant: developer on the staging environment.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("backup.update on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("backup.update on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod"}}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at the production env for a staging-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: developer on THIS service.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_dev", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleDeveloper, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("backup.update on the granted service (full scope) = %+v, want allow",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionEnvironmentUpdate, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("environment.update on the parent environment for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupUpdate, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("backup.update on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.update) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Admin grant: pins no ProjectID, so covers()
	// admits any resource scope in the same org. Admin holds
	// CapWrite, so backup.update is allowed via ReasonAllowedByGrant
	// on the bare-id route, AND on the wire.
	orgAdminGrantee := policy.Principal{
		ID: "sa_org_admin", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleAdmin, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgAdminGrantee, policy.ActionBackupUpdate, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.update) at the service-id route for an org-level admin grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// Organization-level Viewer grant: confers CapRead at the org
	// but no CapWrite. backup.update is denied via
	// ReasonDeniedNoCapability.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionBackupUpdate, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedNoCapability {
		t.Errorf("Decide(backup.update) at the service-id route for an org-level viewer grant = %+v, want deny via %q",
			got, policy.ReasonDeniedNoCapability)
	}

	// Wire-level proof: a project-scoped grant principal hitting the
	// bare-id route is denied at the boundary by the engine — the
	// updater must never run.
	var capturedProj store.UpdateServiceBackupInput
	projCallCount := 0
	projUpdater := fakeServiceBackupUpdater{
		gotInput:  &capturedProj,
		callCount: &projCallCount,
	}
	projHandler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: projectDevGrantee, Method: auth.MethodAPIKey}, nil, projUpdater)
	projRec := patchServiceBackup(projHandler, svcID, canonicalBackupUpdateMatrixBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCallCount != 0 {
		t.Errorf("updater was reached (calls=%d) for a project-scoped grant principal; the engine must reject before the handler runs",
			projCallCount)
	}
	if body := projRec.Body.String(); updateServiceBackupDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked the canonical backup or caller-supplied request body: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an env-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedEnv store.UpdateServiceBackupInput
	envCallCount := 0
	envUpdater := fakeServiceBackupUpdater{
		gotInput:  &capturedEnv,
		callCount: &envCallCount,
	}
	envHandler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: envStagingGrantee, Method: auth.MethodAPIKey}, nil, envUpdater)
	envRec := patchServiceBackup(envHandler, svcID, canonicalBackupUpdateMatrixBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("env-scoped grant wire status = %d, want 403; body %s", envRec.Code, envRec.Body.String())
	}
	if envCallCount != 0 {
		t.Errorf("updater was reached (calls=%d) for an env-scoped grant principal; the engine must reject before the handler runs",
			envCallCount)
	}

	// Wire-level proof: a service-scoped grant principal hitting the
	// bare-id route is denied at the boundary too.
	var capturedSvc store.UpdateServiceBackupInput
	svcCallCount := 0
	svcUpdater := fakeServiceBackupUpdater{
		gotInput:  &capturedSvc,
		callCount: &svcCallCount,
	}
	svcHandler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcUpdater)
	svcRec := patchServiceBackup(svcHandler, svcID, canonicalBackupUpdateMatrixBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCallCount != 0 {
		t.Errorf("updater was reached (calls=%d) for a service-scoped grant principal; the engine must reject before the handler runs",
			svcCallCount)
	}

	// Wire-level proof: an org-level admin grant principal passes
	// the engine and reaches the updater with the principal's home
	// org id.
	var capturedOrg store.UpdateServiceBackupInput
	orgCallCount := 0
	orgUpdater := fakeServiceBackupUpdater{
		backup:    canonicalUpdatedMatrixServiceBackup(org, svcID),
		gotInput:  &capturedOrg,
		callCount: &orgCallCount,
	}
	orgHandler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgAdminGrantee, Method: auth.MethodAPIKey}, nil, orgUpdater)
	orgRec := patchServiceBackup(orgHandler, svcID, canonicalBackupUpdateMatrixBackupID, "a-valid-token", canonicalUpdateServiceBackupBody)
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-admin grant wire status = %d, want 200; body %s", orgRec.Code, orgRec.Body.String())
	}
	if orgCallCount != 1 {
		t.Errorf("updater call count = %d, want 1 for an org-level admin grant", orgCallCount)
	}
	if capturedOrg.OrganizationID != org || capturedOrg.ServiceID != svcID || capturedOrg.BackupID != canonicalBackupUpdateMatrixBackupID {
		t.Errorf("updater captured (org=%q, svc=%q, bkp=%q), want (%q, %q, %q) for the org-admin allow path",
			capturedOrg.OrganizationID, capturedOrg.ServiceID, capturedOrg.BackupID, org, svcID, canonicalBackupUpdateMatrixBackupID)
	}
}
