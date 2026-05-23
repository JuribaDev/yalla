package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeAdminConfigPromotionManager struct {
	manifest store.AdminConfigExportManifest
	report   store.AdminConfigImportReport
	err      error

	gotExport store.AdminConfigExportInput
	gotImport store.AdminConfigImportInput
}

func (f *fakeAdminConfigPromotionManager) Export(_ context.Context, in store.AdminConfigExportInput, _ store.AdminConfigAuditContext) (store.AdminConfigExportManifest, error) {
	f.gotExport = in
	if f.err != nil {
		return store.AdminConfigExportManifest{}, f.err
	}
	if f.manifest.SchemaVersion == "" {
		f.manifest = adminConfigPromotionManifest()
	}
	return f.manifest, nil
}

func (f *fakeAdminConfigPromotionManager) Import(_ context.Context, in store.AdminConfigImportInput, _ store.AdminConfigAuditContext) (store.AdminConfigImportReport, error) {
	f.gotImport = in
	if f.err != nil {
		return store.AdminConfigImportReport{}, f.err
	}
	if len(f.report.Changes) == 0 {
		f.report = store.AdminConfigImportReport{Valid: true, Applied: !in.DryRun, Changes: []store.AdminConfigImportChange{{Operation: "create_set", Slug: "pricing-export", Domain: store.AdminConfigDomainPricing}}}
	}
	return f.report, nil
}

func adminConfigPromotionHandlerFor(authn Authenticator, manager AdminConfigPromotionManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminConfigExportAndImportEndpoints(t *testing.T) {
	t.Parallel()
	orgID := string(domain.MustNewID(domain.KindOrganization))
	manager := &fakeAdminConfigPromotionManager{}
	h := adminConfigPromotionHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleConfigPublisher),
		Method:    auth.MethodAPIKey,
	}}, manager)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/config/export?source_environment=staging", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Request-Id", "req_admin_config_export")
	req.Header.Set("X-Yalla-Reason", "promote staging config")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if manager.gotExport.SourceEnvironment != "staging" {
		t.Fatalf("export input = %+v", manager.gotExport)
	}
	var exportEnv struct {
		SchemaVersion string                          `json:"schema_version"`
		OK            bool                            `json:"ok"`
		RequestID     string                          `json:"request_id"`
		Data          store.AdminConfigExportManifest `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &exportEnv); err != nil {
		t.Fatalf("decode export: %v; body %s", err, rec.Body.String())
	}
	if exportEnv.SchemaVersion != "yalla.output.v1" || !exportEnv.OK || exportEnv.RequestID != "req_admin_config_export" || exportEnv.Data.SchemaVersion != store.AdminConfigExportSchemaVersion {
		t.Fatalf("export envelope = %+v", exportEnv)
	}

	body := `{"target_environment":"production","dry_run":true,"available_secret_refs":["billing/stripe"],"manifest":` + string(mustJSON(t, adminConfigPromotionManifest())) + `}`
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/config/import", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Request-Id", "req_admin_config_import")
	req.Header.Set("X-Yalla-Reason", "promote staging config")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !manager.gotImport.DryRun || manager.gotImport.TargetEnvironment != "production" || len(manager.gotImport.AvailableSecretRefs) != 1 {
		t.Fatalf("import input = %+v", manager.gotImport)
	}
}

func TestAdminConfigPromotionAuthValidationAndErrors(t *testing.T) {
	t.Parallel()
	orgID := string(domain.MustNewID(domain.KindOrganization))

	h := adminConfigPromotionHandlerFor(fakeAuthenticator{}, &fakeAdminConfigPromotionManager{})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/config/export", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminConfigPromotionHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleAdmin),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminConfigPromotionManager{})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/config/import", strings.NewReader(`{"target_environment":"production","manifest":{"schema_version":"yalla.admin_config_export.v1"}}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Yalla-Reason", "promote staging config")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)

	h = adminConfigPromotionHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleConfigPublisher),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminConfigPromotionManager{})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/config/import", strings.NewReader(`{"target_environment":"production","manifest":`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Yalla-Reason", "promote staging config")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)

	h = adminConfigPromotionHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleConfigPublisher),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminConfigPromotionManager{err: apierr.Conflict("unsafe config import downgrade")})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/config/import", strings.NewReader(`{"target_environment":"production","manifest":{"schema_version":"yalla.admin_config_export.v1","config_sets":[]}}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_config")
	req.Header.Set("X-Yalla-Reason", "promote staging config")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertErrorCode(t, rec, http.StatusConflict, yerr.CodeConflict)
}

func adminConfigPromotionManifest() store.AdminConfigExportManifest {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	return store.AdminConfigExportManifest{
		SchemaVersion:     store.AdminConfigExportSchemaVersion,
		SourceEnvironment: "staging",
		ExportedAt:        now,
		ConfigSets: []store.AdminConfigExportSet{{
			Slug:   "pricing-export",
			Domain: store.AdminConfigDomainPricing,
			Name:   "Pricing Export",
			Versions: []store.AdminConfigExportVersion{{
				Version:     1,
				Status:      store.AdminConfigStatusPublished,
				Payload:     json.RawMessage(`{"credential_ref":"billing/stripe"}`),
				EffectiveAt: &now,
				PublishedBy: "usr_admin",
			}},
		}},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return out
}
