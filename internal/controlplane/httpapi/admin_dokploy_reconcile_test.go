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

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeAdminDokployReconciler struct {
	result AdminDokployReconcileResult
	err    error

	got   AdminDokployReconcileRequest
	calls int
}

func (f *fakeAdminDokployReconciler) ReconcileDokploy(ctx context.Context, req AdminDokployReconcileRequest) (AdminDokployReconcileResult, error) {
	f.calls++
	f.got = req
	if f.err != nil {
		return AdminDokployReconcileResult{}, f.err
	}
	return f.result, nil
}

func adminReconcileHandlerFor(authn Authenticator, reconciler AdminDokployReconciler) http.Handler {
	return adminReconcileHandlerForWithLogger(authn, reconciler, nil)
}

func adminReconcileHandlerForWithLogger(authn Authenticator, reconciler AdminDokployReconciler, logger *slog.Logger) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, reconciler)
}

func TestReconcileAdminDokployRunsForAuthorizedTarget(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	reconciler := &fakeAdminDokployReconciler{result: AdminDokployReconcileResult{
		OrganizationID: targetOrg,
		DryRun:         true,
		Repaired:       2,
		Reviewed:       1,
		Quarantined:    1,
		Failures: []AdminDokployReconcileFailure{{
			ActionType: "update_env_var",
			DriftKind:  "safe",
			Reason:     "env_var_changed",
			ServiceID:  "svc_redacted",
			Error:      output.Sentinel,
		}},
	}}
	h := adminReconcileHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reconciler)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile?organization_id="+targetOrg, strings.NewReader(`{"organization_id":"`+targetOrg+`","dry_run":true}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_reconcile")
	req.Header.Set("X-Request-Id", "req_admin_reconcile")
	req.Header.Set("X-Correlation-Id", "corr_admin_reconcile")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if reconciler.calls != 1 {
		t.Fatalf("reconciler calls = %d, want 1", reconciler.calls)
	}
	if reconciler.got.OrganizationID != targetOrg || reconciler.got.ActorID != "usr_admin_drift" {
		t.Fatalf("reconcile request = %+v, want target org and actor", reconciler.got)
	}
	if reconciler.got.RequestID != "req_admin_reconcile" || reconciler.got.CorrelationID != "corr_admin_reconcile" || !reconciler.got.DryRun {
		t.Fatalf("reconcile request correlation/dry_run = %+v", reconciler.got)
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			OrganizationID string `json:"organization_id"`
			DryRun         bool   `json:"dry_run"`
			Repaired       int    `json:"repaired"`
			Reviewed       int    `json:"reviewed"`
			Quarantined    int    `json:"quarantined"`
			FailureCount   int    `json:"failure_count"`
			Failures       []struct {
				ActionType string `json:"action_type"`
				Error      string `json:"error"`
			} `json:"failures"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_reconcile" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.OrganizationID != targetOrg || !env.Data.DryRun || env.Data.Repaired != 2 || env.Data.Reviewed != 1 || env.Data.Quarantined != 1 || env.Data.FailureCount != 1 {
		t.Fatalf("data = %+v, want reconcile summary", env.Data)
	}
	if len(env.Data.Failures) != 1 || env.Data.Failures[0].ActionType != "update_env_var" || env.Data.Failures[0].Error != output.Sentinel {
		t.Fatalf("failures = %+v, want redacted failure", env.Data.Failures)
	}
}

func TestReconcileAdminDokployRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	foreignOrg := string(domain.MustNewID(domain.KindOrganization))
	reconciler := &fakeAdminDokployReconciler{}
	h := adminReconcileHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reconciler)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile", strings.NewReader(`{"organization_id":"`+foreignOrg+`"}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_reconcile")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if reconciler.calls != 0 {
		t.Fatalf("reconciler calls = %d, want 0 on validation failure", reconciler.calls)
	}
}

func TestReconcileAdminDokployAuthFailures(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	reconciler := &fakeAdminDokployReconciler{}
	h := adminReconcileHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, reconciler)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile?organization_id="+orgID, strings.NewReader(`{"organization_id":"`+orgID+`"}`))
	req.Header.Set("Authorization", "Bearer yk_owner_not_support")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")

	h = adminReconcileHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, reconciler)
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile?organization_id="+orgID, strings.NewReader(`{"organization_id":"`+orgID+`"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
	if reconciler.calls != 0 {
		t.Fatalf("reconciler calls = %d, want 0 when auth fails", reconciler.calls)
	}
}

func TestReconcileAdminDokployPropagatesNotFound(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	missingOrg := string(domain.MustNewID(domain.KindOrganization))
	reconciler := &fakeAdminDokployReconciler{err: apierr.NotFound("organization", missingOrg)}
	h := adminReconcileHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reconciler)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile?organization_id="+missingOrg, strings.NewReader(`{"organization_id":"`+missingOrg+`"}`))
	req.Header.Set("Authorization", "Bearer yk_test_admin_reconcile")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

func TestReconcileAdminDokployContractRedactsRequestLogs(t *testing.T) {
	t.Parallel()

	const queryToken = "dokploy-reconcile-query-token-secret"
	const bearerSecret = "yk_live_admin_reconcile_secret"
	orgID := string(domain.MustNewID(domain.KindOrganization))

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reconciler := &fakeAdminDokployReconciler{}
	h := adminReconcileHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reconciler, logger)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/reconcile?organization_id="+orgID+"&token="+queryToken, strings.NewReader(`{"organization_id":"`+orgID+`"}`))
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

func TestReconcileAdminDokployOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	h := adminReconcileHandlerFor(fakeAuthenticator{}, &fakeAdminDokployReconciler{})
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
	op, ok := doc.Paths["/v1/admin/dokploy/reconcile"]["post"]
	if !ok {
		t.Fatalf("POST /v1/admin/dokploy/reconcile is missing from OpenAPI")
	}
	if op.OperationID != "reconcileAdminDokploy" {
		t.Errorf("operationId = %q, want reconcileAdminDokploy", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAdminReconcile) {
		t.Errorf("required action = %q, want %q", op.RequiredAction, policy.ActionAdminReconcile)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement")
	}
}
