package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeAdminPlanManager struct {
	plan  store.Plan
	err   error
	calls []string
}

func (f *fakeAdminPlanManager) CreatePlan(_ context.Context, _ AdminPlanCreateInput, _ store.AdminPlanAuditContext) (store.Plan, error) {
	f.calls = append(f.calls, "create")
	return f.out()
}

func (f *fakeAdminPlanManager) EditPlan(_ context.Context, id string, _ AdminPlanEditInput, _ store.AdminPlanAuditContext) (store.Plan, error) {
	f.calls = append(f.calls, "edit:"+id)
	return f.out()
}

func (f *fakeAdminPlanManager) PublishPlan(_ context.Context, id string, _ store.AdminPlanAuditContext) (store.Plan, error) {
	f.calls = append(f.calls, "publish:"+id)
	return f.out()
}

func (f *fakeAdminPlanManager) ArchivePlan(_ context.Context, id string, _ store.AdminPlanAuditContext) (store.Plan, error) {
	f.calls = append(f.calls, "archive:"+id)
	return f.out()
}

func (f *fakeAdminPlanManager) RollbackPlan(_ context.Context, id string, _ store.AdminPlanAuditContext) (store.Plan, error) {
	f.calls = append(f.calls, "rollback:"+id)
	return f.out()
}

func (f *fakeAdminPlanManager) UpsertPlanEntitlement(_ context.Context, planID string, in AdminPlanEntitlementUpsertInput, _ store.AdminPlanAuditContext) (store.PlanEntitlement, error) {
	f.calls = append(f.calls, "upsert-entitlement:"+planID+":"+in.EntitlementKey)
	return store.PlanEntitlement{}, f.err
}

func (f *fakeAdminPlanManager) RenamePlanEntitlement(_ context.Context, planID, fromKey, toKey, impactValidationID string, _ store.AdminPlanAuditContext) (store.PlanEntitlement, error) {
	f.calls = append(f.calls, "rename-entitlement:"+planID+":"+fromKey+":"+toKey+":"+impactValidationID)
	return store.PlanEntitlement{}, f.err
}

func (f *fakeAdminPlanManager) DeletePlanEntitlement(_ context.Context, planID, key, impactValidationID string, _ store.AdminPlanAuditContext) error {
	f.calls = append(f.calls, "delete-entitlement:"+planID+":"+key+":"+impactValidationID)
	return f.err
}

func (f *fakeAdminPlanManager) out() (store.Plan, error) {
	if f.err != nil {
		return store.Plan{}, f.err
	}
	if f.plan.ID == "" {
		f.plan = adminPlanFixture("plan_business_monthly_v2", store.PlanStatusDraft)
	}
	return f.plan, nil
}

func adminPlanHandlerFor(authn Authenticator, manager AdminPlanManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminPlansCreateReturnsDraftPlanEnvelope(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminPlanManager{plan: adminPlanFixture("plan_business_monthly_v2", store.PlanStatusDraft)}
	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)
	req := adminPlanRequest(http.MethodPost, "/v1/admin/plans", `{"slug":"business","name":"Business Next","billing_period":"monthly","display_order":30}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "create" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	env := decodeAdminPlanEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.Status != "draft" || env.Data.Version != 2 {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestAdminPlansEditPublishArchiveAndRollbackDelegateToManager(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name   string
		method string
		path   string
		body   string
		want   string
		status int
	}{
		{"edit", http.MethodPatch, "/v1/admin/plans/plan_business_monthly_v2", `{"name":"Business Next","display_order":35}`, "edit:plan_business_monthly_v2", http.StatusOK},
		{"publish", http.MethodPost, "/v1/admin/plans/plan_business_monthly_v2/publish", `{}`, "publish:plan_business_monthly_v2", http.StatusOK},
		{"archive", http.MethodPost, "/v1/admin/plans/plan_business_monthly_v2/archive", `{}`, "archive:plan_business_monthly_v2", http.StatusOK},
		{"rollback", http.MethodPost, "/v1/admin/plans/plan_business_monthly_v1/rollback", `{}`, "rollback:plan_business_monthly_v1", http.StatusCreated},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			manager := &fakeAdminPlanManager{plan: adminPlanFixture("plan_business_monthly_v3", store.PlanStatusActive)}
			h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminPlanRequest(row.method, row.path, row.body))
			if rec.Code != row.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, row.status, rec.Body.String())
			}
			if len(manager.calls) != 1 || manager.calls[0] != row.want {
				t.Fatalf("calls = %#v, want %q", manager.calls, row.want)
			}
			if env := decodeAdminPlanEnvelope(t, rec); env.Data.ID == "" || env.Data.Status != "active" {
				t.Fatalf("data = %+v", env.Data)
			}
		})
	}
}

func TestAdminPlansRequireAuthentication(t *testing.T) {
	t.Parallel()

	h := adminPlanHandlerFor(fakeAuthenticator{}, &fakeAdminPlanManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/plans", strings.NewReader(`{"slug":"business","name":"Business","billing_period":"monthly"}`)))

	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)
}

func TestAdminPlansDenyNonSupportPrincipal(t *testing.T) {
	t.Parallel()

	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleAdmin), &fakeAdminPlanManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPost, "/v1/admin/plans", `{"slug":"business","name":"Business","billing_period":"monthly"}`))

	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestAdminPlansRejectInvalidCreateBody(t *testing.T) {
	t.Parallel()

	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminPlanManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPost, "/v1/admin/plans", `{"slug":"bad slug","name":"","billing_period":"weekly"}`))

	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)
}

func TestAdminPlansPropagateNotFoundAndConflict(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name   string
		err    error
		status int
		code   yerr.Code
	}{
		{"not-found", apierr.NotFound("plan", "plan_missing"), http.StatusNotFound, yerr.CodeNotFound},
		{"conflict", apierr.Conflict("plan version cannot be published"), http.StatusConflict, yerr.CodeConflict},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminPlanManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminPlanRequest(http.MethodPost, "/v1/admin/plans/plan_missing/publish", `{}`))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminPlanAuth(t *testing.T, role policy.Role) fakeAuthenticator {
	t.Helper()
	orgID := string(domain.MustNewID(domain.KindOrganization))
	return fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, role),
		Method:    auth.MethodAPIKey,
	}}
}

func adminPlanRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_plan")
	req.Header.Set("X-Request-Id", "req_admin_plan")
	return req
}

func adminPlanFixture(id string, status store.PlanStatus) store.Plan {
	return store.Plan{
		ID:            id,
		Slug:          "business",
		Name:          "Business Next",
		Status:        status,
		BillingPeriod: store.BillingPeriodMonthly,
		DisplayOrder:  30,
		Version:       2,
	}
}

func decodeAdminPlanEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		ID            string `json:"id"`
		Slug          string `json:"slug"`
		Name          string `json:"name"`
		Status        string `json:"status"`
		BillingPeriod string `json:"billing_period"`
		DisplayOrder  int    `json:"display_order"`
		Version       int    `json:"version"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ID            string `json:"id"`
			Slug          string `json:"slug"`
			Name          string `json:"name"`
			Status        string `json:"status"`
			BillingPeriod string `json:"billing_period"`
			DisplayOrder  int    `json:"display_order"`
			Version       int    `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
