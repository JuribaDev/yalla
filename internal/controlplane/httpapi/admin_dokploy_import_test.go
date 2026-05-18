package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
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
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeAdminDokployImporter struct {
	job store.ProvisioningJob
	err error

	got   store.ImportDokployInput
	calls int
}

func (f *fakeAdminDokployImporter) ImportDokploy(ctx context.Context, in store.ImportDokployInput) (store.ProvisioningJob, error) {
	f.calls++
	f.got = in
	if f.err != nil {
		return store.ProvisioningJob{}, f.err
	}
	return f.job, nil
}

func adminImportHandlerFor(authn Authenticator, importer AdminDokployImporter) http.Handler {
	return adminImportHandlerForWithLogger(authn, importer, nil)
}

func adminImportHandlerForWithLogger(authn Authenticator, importer AdminDokployImporter, logger *slog.Logger) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, importer)
}

func TestImportAdminDokployQueuesAuthorizedImport(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	now := time.Date(2026, 5, 19, 8, 0, 0, 0, time.UTC)
	importer := &fakeAdminDokployImporter{job: store.ProvisioningJob{
		ID:             "job_0123456789abcdefghjkmnpqrs",
		OrganizationID: targetOrg,
		JobType:        "import_dokploy_resource",
		IdempotencyKey: "import-once",
		Status:         store.JobStatusQueued,
		MaxAttempts:    20,
		Payload: map[string]string{
			"organization_id":           targetOrg,
			"yalla_organization_id":     targetOrg,
			"dokploy_organization_id":   "dkp-org-import",
			"assignment_dokploy_org_id": "dkp-org-import",
		},
		RequestID:     "req_admin_import",
		CorrelationID: "corr_admin_import",
		NextRunAt:     now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}}
	h := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+targetOrg, strings.NewReader(`{"organization_id":"`+targetOrg+`","yalla_organization_id":"`+targetOrg+`","dokploy_organization_id":"dkp-org-import","assignment_dokploy_org_id":"dkp-org-import","idempotency_key":"import-once"}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_import")
	req.Header.Set("X-Request-Id", "req_admin_import")
	req.Header.Set("X-Correlation-Id", "corr_admin_import")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if importer.calls != 1 {
		t.Fatalf("importer calls = %d, want 1", importer.calls)
	}
	if importer.got.OrganizationID != targetOrg || importer.got.YallaOrganizationID != targetOrg || importer.got.DokployOrganizationID != "dkp-org-import" {
		t.Fatalf("import request = %+v, want target binding", importer.got)
	}
	if importer.got.ActorID != "usr_admin_drift" || importer.got.ActorOrgID != homeOrg || importer.got.RequestID != "req_admin_import" || importer.got.CorrelationID != "corr_admin_import" {
		t.Fatalf("import request actor/correlation = %+v", importer.got)
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			OrganizationID        string `json:"organization_id"`
			YallaOrganizationID   string `json:"yalla_organization_id"`
			DokployOrganizationID string `json:"dokploy_organization_id"`
			Job                   struct {
				ID             string            `json:"id"`
				OrganizationID string            `json:"organization_id"`
				JobType        string            `json:"job_type"`
				Status         string            `json:"status"`
				Payload        map[string]string `json:"payload"`
			} `json:"job"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_import" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.OrganizationID != targetOrg || env.Data.YallaOrganizationID != targetOrg || env.Data.DokployOrganizationID != "dkp-org-import" {
		t.Fatalf("data = %+v, want import target", env.Data)
	}
	if env.Data.Job.ID != "job_0123456789abcdefghjkmnpqrs" || env.Data.Job.JobType != "import_dokploy_resource" || env.Data.Job.Status != "queued" {
		t.Fatalf("job = %+v, want queued import job", env.Data.Job)
	}
}

func TestImportAdminDokployRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	foreignOrg := string(domain.MustNewID(domain.KindOrganization))
	importer := &fakeAdminDokployImporter{}
	h := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import", strings.NewReader(`{"organization_id":"`+foreignOrg+`","dokploy_organization_id":"dkp-org-import","idempotency_key":"import-once"}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_import")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
	if importer.calls != 0 {
		t.Fatalf("importer calls = %d, want 0 on validation failure", importer.calls)
	}
}

func TestImportAdminDokployAuthFailures(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	importer := &fakeAdminDokployImporter{}
	h := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, importer)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-import","idempotency_key":"import-once"}`))
	req.Header.Set("Authorization", "Bearer yk_owner_not_support")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")

	h = adminImportHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, importer)
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-import","idempotency_key":"import-once"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if importer.calls != 0 {
		t.Fatalf("importer calls = %d, want 0 when auth fails", importer.calls)
	}
}

func TestImportAdminDokployPropagatesNotFound(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	missingOrg := string(domain.MustNewID(domain.KindOrganization))
	importer := &fakeAdminDokployImporter{err: apierr.NotFound("organization", missingOrg)}
	h := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+missingOrg, strings.NewReader(`{"dokploy_organization_id":"dkp-org-import","idempotency_key":"import-once"}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_import")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

func TestImportAdminDokployContractRedactsRequestLogs(t *testing.T) {
	t.Parallel()

	const queryToken = "dokploy-import-query-token-secret"
	const bearerSecret = "yk_live_admin_import_secret"
	orgID := string(domain.MustNewID(domain.KindOrganization))

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	importer := &fakeAdminDokployImporter{job: store.ProvisioningJob{
		ID:             "job_0123456789abcdefghjkmnpqrs",
		OrganizationID: orgID,
		JobType:        "import_dokploy_resource",
		IdempotencyKey: "import-once",
		Status:         store.JobStatusQueued,
		MaxAttempts:    20,
		Payload:        map[string]string{"organization_id": orgID, "dokploy_organization_id": "dkp-org-import"},
	}}
	h := adminImportHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer, logger)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID+"&token="+queryToken, strings.NewReader(`{"dokploy_organization_id":"dkp-org-import","idempotency_key":"import-once"}`))
	req.Header.Set("Authorization", "Bearer "+bearerSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{queryToken, bearerSecret} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("response body leaked secret %q: %s", secret, rec.Body.String())
		}
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("request logs leaked secret %q: %s", secret, logs.String())
		}
	}
	if !strings.Contains(logs.String(), output.Sentinel) {
		t.Fatalf("request logs = %s, want at least one redaction sentinel", logs.String())
	}
}

func TestImportAdminDokployOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	h := adminImportHandlerFor(fakeAuthenticator{}, &fakeAdminDokployImporter{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string           `json:"operationId"`
			RequiredAction string           `json:"x-required-action"`
			Security       []map[string]any `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/admin/dokploy/import"]["post"]
	if !ok {
		t.Fatalf("POST /v1/admin/dokploy/import is missing from OpenAPI")
	}
	if op.OperationID != "importAdminDokploy" {
		t.Errorf("operationId = %q, want importAdminDokploy", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAdminImport) {
		t.Errorf("required action = %q, want %q", op.RequiredAction, policy.ActionAdminImport)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement")
	}
}
