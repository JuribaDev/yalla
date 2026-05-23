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

// Policy-matrix coverage for GET /v1/services/{service_id}/backups
// (BE-0249). Where service_backups_test.go proves the endpoint's
// wire contract (BE-0247 + BE-0248), this file proves its
// authorization contract: that action backup.read cannot be
// bypassed by — or render backup rows because of — the principal's
// role, revoked credentials, home organization, or scoped grants.
//
// The route carries serviceIDResolver (routes.go), which pins ONLY
// the OrganizationID and ServiceID legs of the resource scope to
// the principal's home organization and the path service id. The
// bare service-id path carries NO ProjectID leg, so the resource
// scope leaves ProjectID empty. The authorization contract on this
// route is the structural twin of service_domains_policy_test.go
// (BE-0237; same CapRead action shape, same resolver) — same
// support-cross-tenant-exception-by-engine, same one-way covers()
// containment — but for the backup.read action.
//
//   - CapRead does NOT split the role matrix: all six built-in
//     roles (Owner / Admin / Developer / Viewer / CI / Support)
//     hold CapRead and reading the service's backups in the
//     principal's OWN tenant is allowed via ReasonAllowedByRole.
//   - Cross-tenant: backup.read is CapRead, which IS inside the
//     engine's `CapSupport && (CapRead || CapSupport)` exception.
//     Support is therefore allowed cross-tenant at the engine level
//     — the documented cross-tenant read path. But
//     serviceIDResolver pins the resource to the principal's OWN
//     home org by construction, so a cross-tenant service_id
//     reaches the persistence layer with the principal's home org
//     id and surfaces as a 404 at the tenant-scoped existence
//     check; the engine-level cross-tenant verdict is asserted as
//     defence-in-depth.
//
// Grant containment: serviceIDResolver pins NO ProjectID leg on
// the resource scope, and the engine's covers() rule is one-way (a
// grant scope that pins ProjectID cannot cover a resource scope
// that does not), so project-, environment-, and service-scoped
// grants are denied at the boundary via ReasonDeniedOutOfScope —
// even a service-scoped Viewer grant naming the SAME service id.
// The PRD's three containment properties — sibling project,
// environment grant not implying production, service grant
// shielding parent-level resources and unrelated services — are
// pinned against the engine at their natural scopes, then tied
// back to the wire by proving that ALL three scoped key types are
// denied OutOfScope against THIS endpoint. An organization-level
// Viewer grant — which pins no ProjectID and covers any resource
// scope in the same org — is allowed end-to-end (Viewer holds
// CapRead through the role catalog, and backup.read is CapRead).
// This is the load-bearing distinction from
// services_start_policy_test.go where an org-level Viewer grant is
// DENIED because service.start is CapDeploy.

const (
	canonicalBackupsMatrixSlug        = "matrix-backups-api"
	canonicalBackupsMatrixProject     = "prj_matrix_backups_parent"
	canonicalBackupsMatrixEnv         = "env_matrix_backups_parent"
	canonicalBackupsMatrixService     = "svc_matrix_backups_parent"
	canonicalBackupsMatrixDisplayName = "matrix-backups-recognisable-needle-nightly"
	canonicalBackupsMatrixSchedule    = "0 7 * * *"
)

// canonicalBackupsForMatrix is the ServiceBackups every test in
// this file would receive back from the reader on an allow path.
// The service id, display_name, and schedule are deliberately
// recognisable so deny-path leak guards can needle for them — a
// denied response that contains any of them fails the test.
func canonicalBackupsForMatrix() store.ServiceBackups {
	t := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	return store.ServiceBackups{
		ServiceID: canonicalBackupsMatrixService,
		Backups: []store.ServiceBackup{
			{
				ID:              "sbkp_matrix",
				OrganizationID:  "org_acme",
				ServiceID:       canonicalBackupsMatrixService,
				DisplayName:     canonicalBackupsMatrixDisplayName,
				Schedule:        canonicalBackupsMatrixSchedule,
				RetentionCount:  7,
				Enabled:         true,
				Status:          store.ServiceBackupStatusSucceeded,
				LastRunAt:       &t,
				LastSucceededAt: &t,
				Version:         1,
				CreatedAt:       t,
				UpdatedAt:       t,
			},
		},
	}
}

// backupsDenyBodyLeak reports whether body contains any
// caller-recognisable identifier of the canonical backups
// response. A denied response that contains any of these fails the
// test — proof that the reader ran (which it must not on a deny)
// or that the deny envelope echoed backup data into the response
// body.
func backupsDenyBodyLeak(body string) bool {
	for _, needle := range []string{
		canonicalBackupsMatrixDisplayName,
		canonicalBackupsMatrixSchedule,
		canonicalBackupsMatrixProject,
		canonicalBackupsMatrixEnv,
		canonicalBackupsMatrixSlug,
	} {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

// TestListServiceBackupsPolicyMatrixRoles drives every built-in
// role through the production request path. All six built-in roles
// hold CapRead, so the matrix is "all allow" for a principal
// reading backups of a service in its own organization; the
// assertions that matter are that the verdict is reached through
// the role (ReasonAllowedByRole), the reader is called with the
// principal's own home org id AND the {service_id} path parameter
// (so a tenant-scoped store query cannot match a foreign row), and
// the response is a stable 200 yalla.output.v1 envelope carrying
// the canonical row.
func TestListServiceBackupsPolicyMatrixRoles(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupsMatrixService
	)
	svcResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
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

			// Engine verdict — pinned alongside the wire verdict so
			// a catalog or builtinRoleCaps regression fails here.
			// Support reading backups of a service in ITS OWN
			// organization is allowed via ReasonAllowedByRole
			// (same-tenant falls through the cross-tenant clause);
			// the Support cross-tenant exception is exercised at
			// the engine in
			// TestListServiceBackupsPolicyWrongOrganizationPrincipal
			// — it cannot be exercised at the wire through this
			// route because serviceIDResolver pins the resource
			// scope to the principal's home org.
			e := policy.NewEngine()
			got := e.Decide(principal, policy.ActionBackupRead, svcResource)
			if !got.Allow || got.Reason != policy.ReasonAllowedByRole {
				t.Errorf("Decide(backup.read) for %s = %+v, want allow via %q",
					tc.name, got, policy.ReasonAllowedByRole)
			}

			canonical := canonicalBackupsForMatrix()
			var captured store.ListServiceBackupsInput
			reader := fakeServiceBackupReader{
				backups: canonical,
				got:     &captured,
			}
			method := auth.MethodSession
			if tc.kind == domain.KindServiceAccount {
				method = auth.MethodAPIKey
			}
			handler := listServiceBackupsHandlerFor(
				auth.Identity{Principal: principal, Method: method}, nil, reader)
			rec := listServiceBackups(handler, svcID, "a-valid-token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != org {
				t.Errorf("reader received organization id %q, want the principal's home org %q",
					captured.OrganizationID, org)
			}
			if captured.ServiceID != svcID {
				t.Errorf("reader received service id %q, want the path parameter %q",
					captured.ServiceID, svcID)
			}
		})
	}
}

// TestListServiceBackupsPolicyRevokedAndExpiredKeys proves a
// principal whose credential has been revoked or has expired —
// both of which the auth layer surfaces as Unauthenticated — never
// reaches the reader and never receives canonical backup data.
func TestListServiceBackupsPolicyRevokedAndExpiredKeys(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = canonicalBackupsMatrixService
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

			var captured store.ListServiceBackupsInput
			reader := fakeServiceBackupReader{
				backups: canonicalBackupsForMatrix(),
				got:     &captured,
			}
			handler := listServiceBackupsHandlerFor(
				auth.Identity{}, apierr.Unauthenticated("api key revoked"), reader)
			rec := listServiceBackups(handler, svcID, "yk_no_longer_valid")

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
			}
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("reader was reached for a revoked/expired credential; got %+v — it must never run",
					captured)
			}
			body := rec.Body.String()
			if strings.Contains(body, tc.id) ||
				strings.Contains(body, org) ||
				backupsDenyBodyLeak(body) {
				t.Errorf("error body %s leaked the principal id, organization, or canonical backup data", body)
			}
		})
	}
}

// TestListServiceBackupsPolicyWrongOrganizationPrincipal pins the
// cross-tenant boundary for backup.read on the bare service-id
// route. The resource org id is taken from the PRINCIPAL'S home
// org — the {service_id} path parameter alone never widens the
// resource to another tenant. Tenant isolation on the wire is
// therefore structural at the persistence layer, not the policy
// boundary:
//
//   - A principal in org_attacker hitting GET
//     /v1/services/{svc_victim}/backups with a valid Owner token
//     reaches the engine with a same-tenant resource ({org_attacker,
//     svc_victim}) — allowed by the role at CapRead — and then
//     reaches the tenant-scoped existence check with the
//     principal's home org id and the foreign service id. A
//     production *store.ServiceBackupReader (which composes the
//     service existence check under (organization_id, service_id))
//     cannot match a row that belongs to another tenant, so the
//     request surfaces as a deterministic 404 E_NOT_FOUND, never
//     disguised as a 200 with foreign data and never as a 403 that
//     would confirm existence. The body must never echo the
//     foreign org id even though no wire input could place it
//     there.
//
//   - Engine defence-in-depth: even if a future endpoint
//     constructed a resource with a foreign-org scope, EVERY
//     non-support role MUST be denied via ReasonDeniedCrossTenant,
//     and a Support principal MUST be allowed via
//     ReasonAllowedBySupport (CapRead is inside the engine clause
//     `roleCaps.has(CapSupport) && (required == CapRead || required
//     == CapSupport)`). The customer-facing route under test cannot
//     reach this engine branch by construction —
//     serviceIDResolver pins the resource scope to the principal's
//     own home org — but the engine verdict is the authoritative
//     source of the documented support exception, and a future
//     catalog change that upgraded backup.read above CapRead would
//     fail here (silently denying every support cross-tenant
//     backup read) before it could regress a real customer.
func TestListServiceBackupsPolicyWrongOrganizationPrincipal(t *testing.T) {
	t.Parallel()

	const (
		ownOrg          = "org_attacker"
		victimOrg       = "org_victim"
		foreignSvcID    = "svc_victim_backups_target"
		victimOrgNeedle = "org_victim"
	)

	var captured store.ListServiceBackupsInput
	intruder := orgPrincipal("usr_mallory", ownOrg, policy.RoleOwner)
	reader := fakeServiceBackupReader{
		err: apierr.NotFound("service", foreignSvcID),
		got: &captured,
	}
	handler := listServiceBackupsHandlerFor(
		auth.Identity{Principal: intruder, Method: auth.MethodSession}, nil, reader)
	rec := listServiceBackups(handler, foreignSvcID, "a-valid-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (cross-tenant service_id surfaces as NotFound); body %s",
			rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != ownOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q — handler must never trust caller-controlled org ids",
			captured.OrganizationID, ownOrg)
	}
	denyEnv := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(strings.ToLower(denyEnv.Error.Message), strings.ToLower(victimOrgNeedle)) {
		t.Errorf("error.message = %q, must not echo the foreign tenant's organization id",
			denyEnv.Error.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}

	// Engine-level cross-tenant boundary at a foreign-org resource
	// scope. CapRead IS inside the support cross-tenant exception,
	// so every NON-SUPPORT role is denied via
	// ReasonDeniedCrossTenant, and Support is allowed via
	// ReasonAllowedBySupport.
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
			got := e.Decide(p, policy.ActionBackupRead, foreign)
			if got.Allow || got.Reason != policy.ReasonDeniedCrossTenant {
				t.Errorf("Decide(backup.read, foreign org) for %s = %+v, want deny via %q — CapRead is inside the support cross-tenant exception only for support principals",
					tc.name, got, policy.ReasonDeniedCrossTenant)
			}
		})
	}

	// Support IS a cross-tenant exception for CapRead actions: the
	// engine clause `roleCaps.has(CapSupport) && (required ==
	// CapRead || required == CapSupport)` reaches backup.read
	// because the catalog maps it to CapRead. This locks the
	// CapRead requirement against the support cross-tenant path so
	// a future catalog change that upgraded backup.read above
	// CapRead would fail here (silently denying every support
	// cross-tenant backup read) before it could regress a real
	// customer. The customer-facing route under test cannot reach
	// this engine branch by construction — serviceIDResolver pins
	// the resource scope to the principal's own home org, so a
	// foreign {service_id} is admitted same-tenant and rejected at
	// the persistence layer — but the engine verdict is the
	// authoritative source of the documented support exception.
	support := orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)
	if got := e.Decide(support, policy.ActionBackupRead, foreign); !got.Allow || got.Reason != policy.ReasonAllowedBySupport {
		t.Errorf("Decide(backup.read, foreign org) for support = %+v, want allow via %q (CapRead is inside the support cross-tenant exception)",
			got, policy.ReasonAllowedBySupport)
	}
}

// TestListServiceBackupsPolicyGrantContainment proves scoped grants
// cannot reach this endpoint at all — every project-, environment-,
// and service-scoped grant is denied at the boundary by
// ReasonDeniedOutOfScope, because serviceIDResolver pins NO
// ProjectID leg on the resource scope (the bare service-id path
// carries no parent project_id). The PRD containment properties
// are pinned at their natural scopes (a service / environment /
// project resource), then tied back to the wire by proving that
// ALL three scoped key types are denied OutOfScope against THIS
// endpoint (the reader must never run on a deny), and that an
// organization-level Viewer grant is allowed end-to-end — the
// load-bearing distinction from services_start_policy_test.go
// where an org-level Viewer grant is DENIED because service.start
// is CapDeploy.
func TestListServiceBackupsPolicyGrantContainment(t *testing.T) {
	t.Parallel()

	const (
		org     = "org_acme"
		project = canonicalBackupsMatrixProject
		env     = canonicalBackupsMatrixEnv
		svcID   = canonicalBackupsMatrixService
	)
	e := policy.NewEngine()

	resourceOnRoute := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ServiceID: svcID},
	}

	// Project-level grant: Viewer on the parent project. At a fully
	// scoped service resource INSIDE the granted project the engine
	// allows (Viewer holds CapRead, backup.read is CapRead); at a
	// sibling project the engine denies; and at THIS endpoint's
	// bare-service-id scope (no ProjectID leg), the project-scoped
	// grant is denied at the boundary.
	scopeTargetProject := policy.Scope{OrganizationID: org, ProjectID: project}
	scopeSiblingProject := policy.Scope{OrganizationID: org, ProjectID: "prj_backups_matrix_sibling"}
	projectViewerGrantee := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.read) at the parent project's service for the target-project viewer grantee = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: "prj_backups_matrix_sibling", EnvironmentID: "env_sibling", ServiceID: "svc_sibling"},
	}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.read) at a sibling project's service = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupRead, policy.Resource{Kind: domain.KindProject, Scope: scopeSiblingProject}); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.read) at a sibling project = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}
	if got := e.Decide(projectViewerGrantee, policy.ActionBackupRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.read) at the service-id route's resource scope for a project-scoped grantee = %+v, want deny via %q — covers() is one-way",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Environment-level grant: Viewer on the staging environment.
	// "env grant does not imply access to production unless production
	// is explicitly granted" — pinned at env / service resources for
	// the backup.read action.
	scopeStaging := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging"}
	envStagingGrantee := policy.Principal{
		ID: "sa_env_staging", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeStaging}},
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_staging", ServiceID: "svc_in_staging"},
	}); !got.Allow {
		t.Errorf("backup.read on a service inside the granted staging environment = %+v, want allow",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: "env_prod", ServiceID: "svc_in_prod"},
	}); got.Allow {
		t.Errorf("backup.read on a service inside production for a staging-scoped grantee = %+v, want deny — staging grant must not reach production",
			got)
	}
	if got := e.Decide(envStagingGrantee, policy.ActionBackupRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.read) at the service-id route's resource scope for an env-scoped grantee = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Service-level grant: Viewer on the target service. The grant
	// scope pins ProjectID + EnvironmentID + ServiceID, so the
	// engine's covers() rule denies the bare-service-id resource
	// scope. At a fully scoped service resource the grant DOES
	// authorize, but the service-level grant does not widen to
	// parent-level resources or unrelated sibling services.
	scopeTargetService := policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: svcID}
	svcGrantee := policy.Principal{
		ID: "sa_svc_view", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetService}},
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: scopeTargetService,
	}); !got.Allow {
		t.Errorf("backup.read on the granted service (full scope) = %+v, want allow",
			got)
	}
	// A service grant does not widen to the parent environment's
	// secret-bearing resources.
	if got := e.Decide(svcGrantee, policy.ActionEnvRead, policy.Resource{Kind: domain.KindEnvironment, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}); got.Allow {
		t.Errorf("env.read on the parent environment for a service-scoped grant = %+v, want deny — a service grant must not widen to parent secrets",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupRead, policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env, ServiceID: "svc_unrelated"},
	}); got.Allow {
		t.Errorf("backup.read on an unrelated sibling service for a service-scoped grant = %+v, want deny",
			got)
	}
	if got := e.Decide(svcGrantee, policy.ActionBackupRead, resourceOnRoute); got.Allow || got.Reason != policy.ReasonDeniedOutOfScope {
		t.Errorf("Decide(backup.read) at the service-id route's resource scope for a service-scoped grant = %+v, want deny via %q",
			got, policy.ReasonDeniedOutOfScope)
	}

	// Organization-level Viewer grant: pins no ProjectID, so
	// covers() admits any resource scope in the same org. Viewer
	// holds CapRead through the role catalog and backup.read is
	// CapRead, so the route is allowed via ReasonAllowedByGrant —
	// the load-bearing distinction from
	// services_start_policy_test.go where the same grant is DENIED
	// because service.start is CapDeploy. This locks the CapRead
	// requirement against the grant path so a future catalog change
	// that upgraded backup.read above CapRead would fail here
	// (silently denying every org-level Viewer grantee) before it
	// could regress a real customer.
	orgViewerGrantee := policy.Principal{
		ID: "sa_org_viewer", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org}}},
	}
	if got := e.Decide(orgViewerGrantee, policy.ActionBackupRead, resourceOnRoute); !got.Allow || got.Reason != policy.ReasonAllowedByGrant {
		t.Errorf("Decide(backup.read) at the service-id route for an org-level viewer grant = %+v, want allow via %q",
			got, policy.ReasonAllowedByGrant)
	}

	// And the same project-scoped viewer grantee whose home org id
	// is foreign is denied at the engine: a grant for the parent
	// project inside org_acme, carried by a principal whose home
	// org id is org_sibling, cannot be used to read backups of a
	// service in org_sibling — the cross-tenant guard fires first
	// because the principal's home org no longer matches the
	// grant's scope. (backup.read IS inside the support
	// cross-tenant exception, but the principal here is a service
	// account with no CapSupport role, so the exception does not
	// apply.)
	siblingOrgResource := policy.Resource{
		Kind:  domain.KindService,
		Scope: policy.Scope{OrganizationID: "org_sibling", ProjectID: project, EnvironmentID: env, ServiceID: svcID},
	}
	siblingHomePrincipal := policy.Principal{
		ID: "sa_proj_view", Kind: domain.KindServiceAccount, OrganizationID: "org_sibling",
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: scopeTargetProject}},
	}
	if got := e.Decide(siblingHomePrincipal, policy.ActionBackupRead, siblingOrgResource); got.Allow {
		t.Errorf("Decide(backup.read) for a project-scoped viewer key planted in a foreign org = %+v, want deny",
			got)
	}

	// Wire-level proof: a project-scoped grant principal hitting
	// the bare-service-id route is denied at the boundary by the
	// engine — the reader must never run.
	var projCaptured store.ListServiceBackupsInput
	projReader := fakeServiceBackupReader{
		backups: canonicalBackupsForMatrix(),
		got:     &projCaptured,
	}
	projHandler := listServiceBackupsHandlerFor(
		auth.Identity{Principal: projectViewerGrantee, Method: auth.MethodAPIKey}, nil, projReader)
	projRec := listServiceBackups(projHandler, svcID, "a-valid-token")
	if projRec.Code != http.StatusForbidden {
		t.Fatalf("project-scoped grant wire status = %d, want 403; body %s", projRec.Code, projRec.Body.String())
	}
	if projCaptured.OrganizationID != "" || projCaptured.ServiceID != "" {
		t.Errorf("reader was reached for a project-scoped grant principal; got %+v — the engine must reject before the handler runs",
			projCaptured)
	}
	if body := projRec.Body.String(); backupsDenyBodyLeak(body) {
		t.Errorf("project-scoped grant deny response leaked canonical backup data: %s", body)
	}
	denyProj := decodeError(t, projRec, "E_FORBIDDEN")
	if !strings.Contains(denyProj.Error.Message, string(policy.ReasonDeniedOutOfScope)) {
		t.Errorf("project-scoped grant deny message = %q, want it to carry the stable reason %q",
			denyProj.Error.Message, policy.ReasonDeniedOutOfScope)
	}

	// Wire-level proof: an env-scoped grant principal — even one
	// naming THIS service's parent environment id — is also denied
	// at the boundary on the bare-service-id route.
	envTargetGrantee := policy.Principal{
		ID: "sa_env_target", Kind: domain.KindServiceAccount, OrganizationID: org,
		Grants: []policy.Grant{{Role: policy.RoleViewer, Scope: policy.Scope{OrganizationID: org, ProjectID: project, EnvironmentID: env}}},
	}
	var envCaptured store.ListServiceBackupsInput
	envReader := fakeServiceBackupReader{
		backups: canonicalBackupsForMatrix(),
		got:     &envCaptured,
	}
	envHandler := listServiceBackupsHandlerFor(
		auth.Identity{Principal: envTargetGrantee, Method: auth.MethodAPIKey}, nil, envReader)
	envRec := listServiceBackups(envHandler, svcID, "yk_env_scoped")
	if envRec.Code != http.StatusForbidden {
		t.Fatalf("env-scoped grant wire status = %d, want 403 (covers() is one-way); body %s",
			envRec.Code, envRec.Body.String())
	}
	if envCaptured.OrganizationID != "" || envCaptured.ServiceID != "" {
		t.Errorf("reader was reached for an env-scoped grant principal; got %+v",
			envCaptured)
	}
	if body := envRec.Body.String(); backupsDenyBodyLeak(body) {
		t.Errorf("env-scoped grant deny response leaked canonical backup data: %s", body)
	}

	// Wire-level proof: a service-scoped grant principal — even one
	// naming THIS service's id directly — is also denied at the
	// boundary on the bare-service-id route.
	var svcCaptured store.ListServiceBackupsInput
	svcReader := fakeServiceBackupReader{
		backups: canonicalBackupsForMatrix(),
		got:     &svcCaptured,
	}
	svcHandler := listServiceBackupsHandlerFor(
		auth.Identity{Principal: svcGrantee, Method: auth.MethodAPIKey}, nil, svcReader)
	svcRec := listServiceBackups(svcHandler, svcID, "yk_svc_scoped")
	if svcRec.Code != http.StatusForbidden {
		t.Fatalf("service-scoped grant wire status = %d, want 403; body %s", svcRec.Code, svcRec.Body.String())
	}
	if svcCaptured.OrganizationID != "" || svcCaptured.ServiceID != "" {
		t.Errorf("reader was reached for a service-scoped grant principal; got %+v",
			svcCaptured)
	}
	if body := svcRec.Body.String(); backupsDenyBodyLeak(body) {
		t.Errorf("service-scoped grant deny response leaked canonical backup data: %s", body)
	}

	// Wire-level proof: an org-level Viewer grant principal passes
	// the engine and reaches the reader with the principal's home
	// org id and the path service_id — the load-bearing CapRead
	// allow distinction.
	var orgCaptured store.ListServiceBackupsInput
	orgReader := fakeServiceBackupReader{
		backups: canonicalBackupsForMatrix(),
		got:     &orgCaptured,
	}
	orgHandler := listServiceBackupsHandlerFor(
		auth.Identity{Principal: orgViewerGrantee, Method: auth.MethodAPIKey}, nil, orgReader)
	orgRec := listServiceBackups(orgHandler, svcID, "yk_org_viewer")
	if orgRec.Code != http.StatusOK {
		t.Fatalf("org-viewer grant wire status = %d, want 200 (CapRead allowed by org-level grant); body %s",
			orgRec.Code, orgRec.Body.String())
	}
	if orgCaptured.OrganizationID != org || orgCaptured.ServiceID != svcID {
		t.Errorf("reader captured (org=%q, svc=%q), want (%q, %q) for the org-viewer allow path",
			orgCaptured.OrganizationID, orgCaptured.ServiceID, org, svcID)
	}
}
