package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeAdminEntitlementManager struct {
	ent   store.PlanEntitlement
	err   error
	calls []string
}

func (f *fakeAdminEntitlementManager) CreatePlan(ctx context.Context, in AdminPlanCreateInput, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
	return (&fakeAdminPlanManager{}).CreatePlan(ctx, in, auditCtx)
}

func (f *fakeAdminEntitlementManager) EditPlan(ctx context.Context, id string, in AdminPlanEditInput, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
	return (&fakeAdminPlanManager{}).EditPlan(ctx, id, in, auditCtx)
}

func (f *fakeAdminEntitlementManager) PublishPlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
	return (&fakeAdminPlanManager{}).PublishPlan(ctx, id, auditCtx)
}

func (f *fakeAdminEntitlementManager) ArchivePlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
	return (&fakeAdminPlanManager{}).ArchivePlan(ctx, id, auditCtx)
}

func (f *fakeAdminEntitlementManager) RollbackPlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
	return (&fakeAdminPlanManager{}).RollbackPlan(ctx, id, auditCtx)
}

func (f *fakeAdminEntitlementManager) UpsertPlanEntitlement(_ context.Context, planID string, in AdminPlanEntitlementUpsertInput, _ store.AdminPlanAuditContext) (store.PlanEntitlement, error) {
	f.calls = append(f.calls, "upsert:"+planID+":"+in.EntitlementKey)
	return f.out()
}

func (f *fakeAdminEntitlementManager) RenamePlanEntitlement(_ context.Context, planID, fromKey, toKey, impactValidationID string, _ store.AdminPlanAuditContext) (store.PlanEntitlement, error) {
	f.calls = append(f.calls, "rename:"+planID+":"+fromKey+":"+toKey+":"+impactValidationID)
	return f.out()
}

func (f *fakeAdminEntitlementManager) DeletePlanEntitlement(_ context.Context, planID, key, impactValidationID string, _ store.AdminPlanAuditContext) error {
	f.calls = append(f.calls, "delete:"+planID+":"+key+":"+impactValidationID)
	return f.err
}

func (f *fakeAdminEntitlementManager) out() (store.PlanEntitlement, error) {
	if f.err != nil {
		return store.PlanEntitlement{}, f.err
	}
	if f.ent.ID == "" {
		limit := int64(25)
		f.ent = store.PlanEntitlement{
			ID:              "pent_business_projects_v2",
			PlanID:          "plan_business_monthly_v2",
			EntitlementKey:  "projects",
			LimitValue:      &limit,
			EnforcementMode: store.EnforcementModeHard,
			Metadata:        []byte(`{"unit":"project","warning_threshold":80,"upgrade_hint":"Upgrade","overage_behavior":"block"}`),
		}
	}
	return f.ent, nil
}

func TestAdminEntitlementsUpsertReturnsEnvelope(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminEntitlementManager{}
	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/plans/plan_business_monthly_v2/entitlements/projects", `{"limit_value":25,"enforcement_mode":"hard","unit":"project","warning_threshold":80,"upgrade_hint":"Upgrade","overage_behavior":"block"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:plan_business_monthly_v2:projects" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	env := decodeAdminEntitlementEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.EntitlementKey != "projects" || env.Data.Unit != "project" || env.Data.OverageBehavior != "block" {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestAdminEntitlementsRenameAndDeleteRequireImpactValidation(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminEntitlementManager{}
	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPost, "/v1/admin/plans/plan_business_monthly_v2/entitlements/projects/rename", `{"new_entitlement_key":"service_projects"}`))
	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodDelete, "/v1/admin/plans/plan_business_monthly_v2/entitlements/projects", `{}`))
	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPost, "/v1/admin/plans/plan_business_monthly_v2/entitlements/projects/rename", `{"new_entitlement_key":"service_projects","impact_validation_id":"impact_123"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodDelete, "/v1/admin/plans/plan_business_monthly_v2/entitlements/service_projects", `{"impact_validation_id":"impact_456"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestAdminEntitlementsRequireSupportAndPropagateErrors(t *testing.T) {
	t.Parallel()

	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleAdmin), &fakeAdminEntitlementManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/plans/plan_business_monthly_v2/entitlements/projects", `{"enforcement_mode":"hard"}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)

	h = adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminEntitlementManager{err: apierr.NotFound("plan", "plan_missing")})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/plans/plan_missing/entitlements/projects", `{"enforcement_mode":"hard"}`))
	assertErrorCode(t, rec, http.StatusNotFound, yerr.CodeNotFound)
}

func TestAdminEntitlementsRejectInvalidInput(t *testing.T) {
	t.Parallel()

	h := adminPlanHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminEntitlementManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/plans/plan_business_monthly_v2/entitlements/-bad", `{"limit_value":-1,"enforcement_mode":"unknown","unit":"`+strings.Repeat("x", 40)+`","warning_threshold":101,"overage_behavior":"explode"}`))
	assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)
}

func decodeAdminEntitlementEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		ID               string `json:"id"`
		PlanID           string `json:"plan_id"`
		EntitlementKey   string `json:"entitlement_key"`
		LimitValue       *int64 `json:"limit_value"`
		EnforcementMode  string `json:"enforcement_mode"`
		Unit             string `json:"unit,omitempty"`
		WarningThreshold *int   `json:"warning_threshold,omitempty"`
		UpgradeHint      string `json:"upgrade_hint,omitempty"`
		OverageBehavior  string `json:"overage_behavior,omitempty"`
		ImpactValidation string `json:"impact_validation_id,omitempty"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ID               string `json:"id"`
			PlanID           string `json:"plan_id"`
			EntitlementKey   string `json:"entitlement_key"`
			LimitValue       *int64 `json:"limit_value"`
			EnforcementMode  string `json:"enforcement_mode"`
			Unit             string `json:"unit,omitempty"`
			WarningThreshold *int   `json:"warning_threshold,omitempty"`
			UpgradeHint      string `json:"upgrade_hint,omitempty"`
			OverageBehavior  string `json:"overage_behavior,omitempty"`
			ImpactValidation string `json:"impact_validation_id,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
