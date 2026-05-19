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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeAdminSubscriptionManager struct {
	sub         store.Subscription
	entitlement store.SubscriptionEntitlement
	err         error
	calls       []string
}

func (f *fakeAdminSubscriptionManager) SetSubscription(_ context.Context, organizationID string, in AdminSubscriptionSetInput, _ store.AdminPlanAuditContext) (store.Subscription, error) {
	f.calls = append(f.calls, "set:"+organizationID+":"+in.PlanID+":"+string(in.Status))
	if f.err != nil {
		return store.Subscription{}, f.err
	}
	if f.sub.ID == "" {
		f.sub = adminSubscriptionFixture(organizationID, in.PlanID, in.Status)
		f.sub.Metadata = in.Metadata
	}
	return f.sub, nil
}

func (f *fakeAdminSubscriptionManager) UpsertSubscriptionEntitlement(_ context.Context, organizationID string, in AdminSubscriptionEntitlementUpsertInput, _ store.AdminPlanAuditContext) (store.SubscriptionEntitlement, error) {
	f.calls = append(f.calls, "upsert:"+organizationID+":"+in.EntitlementKey+":"+string(in.Source))
	if f.err != nil {
		return store.SubscriptionEntitlement{}, f.err
	}
	if f.entitlement.ID == "" {
		f.entitlement = adminSubscriptionEntitlementFixture(organizationID, in)
	}
	return f.entitlement, nil
}

func adminSubscriptionHandlerFor(authn Authenticator, manager AdminSubscriptionManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminSubscriptionsSetReturnsEnvelopeAndRedactsMetadata(t *testing.T) {
	t.Parallel()

	orgID := "org_admin_subscription_target"
	manager := &fakeAdminSubscriptionManager{}
	h := adminSubscriptionHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)
	body := `{"plan_id":"plan_business_monthly_v2","status":"trialing","current_period_start":"2026-05-01T00:00:00Z","current_period_end":"2026-06-01T00:00:00Z","trial_ends_at":"2026-05-15T00:00:00Z","metadata":{"ticket":"INC-42","api_token":"secret-token-value"}}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/organizations/"+orgID+"/subscription", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || !strings.Contains(manager.calls[0], "set:"+orgID+":plan_business_monthly_v2:trialing") {
		t.Fatalf("calls = %#v", manager.calls)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ID       string          `json:"id"`
			Status   string          `json:"status"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.ID == "" || env.Data.Status != "trialing" {
		t.Fatalf("envelope = %+v", env)
	}
	if strings.Contains(rec.Body.String(), "secret-token-value") || !strings.Contains(rec.Body.String(), output.Sentinel) {
		t.Fatalf("metadata was not redacted in body %s", rec.Body.String())
	}
}

func TestAdminSubscriptionsUpsertEntitlementReturnsEnvelope(t *testing.T) {
	t.Parallel()

	orgID := "org_admin_subscription_target"
	manager := &fakeAdminSubscriptionManager{}
	h := adminSubscriptionHandlerFor(adminPlanAuth(t, policy.RoleSupport), manager)
	body := `{"subscription_id":"sub_business_current","source":"subscription_override","limit_value":25,"enforcement_mode":"hard","reason":"temporary launch allowance","effective_from":"2026-05-01T00:00:00Z"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/organizations/"+orgID+"/subscription/entitlements/projects", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:"+orgID+":projects:subscription_override" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if !strings.Contains(rec.Body.String(), `"entitlement_key":"projects"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestAdminSubscriptionsRequireAuthenticationAndSupportRole(t *testing.T) {
	t.Parallel()

	body := `{"plan_id":"plan_business_monthly_v2","status":"active","current_period_start":"2026-05-01T00:00:00Z","current_period_end":"2026-06-01T00:00:00Z"}`
	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		h := adminSubscriptionHandlerFor(fakeAuthenticator{}, &fakeAdminSubscriptionManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/organizations/org_target/subscription", strings.NewReader(body)))
		assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)
	})
	t.Run("non-support", func(t *testing.T) {
		t.Parallel()
		h := adminSubscriptionHandlerFor(adminPlanAuth(t, policy.RoleAdmin), &fakeAdminSubscriptionManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/organizations/org_target/subscription", body))
		assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
	})
}

func TestAdminSubscriptionsValidationAndNotFound(t *testing.T) {
	t.Parallel()

	t.Run("invalid assignment", func(t *testing.T) {
		t.Parallel()
		h := adminSubscriptionHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminSubscriptionManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/organizations/org_target/subscription", `{"plan_id":"","status":"expired","current_period_start":"2026-06-01T00:00:00Z","current_period_end":"2026-05-01T00:00:00Z"}`))
		assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)
	})
	t.Run("manager not found", func(t *testing.T) {
		t.Parallel()
		h := adminSubscriptionHandlerFor(adminPlanAuth(t, policy.RoleSupport), &fakeAdminSubscriptionManager{err: apierr.NotFound("organization", "org_missing")})
		rec := httptest.NewRecorder()
		body := `{"plan_id":"plan_business_monthly_v2","status":"active","current_period_start":"2026-05-01T00:00:00Z","current_period_end":"2026-06-01T00:00:00Z"}`
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/organizations/org_missing/subscription", body))
		assertErrorCode(t, rec, http.StatusNotFound, yerr.CodeNotFound)
	})
}

func adminSubscriptionFixture(orgID, planID string, status store.SubscriptionStatus) store.Subscription {
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	trialEnds := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	return store.Subscription{
		ID:                 "sub_business_current",
		OrganizationID:     orgID,
		PlanID:             planID,
		Status:             status,
		CurrentPeriodStart: start,
		CurrentPeriodEnd:   end,
		Provider:           "manual",
		TrialEndsAt:        &trialEnds,
		Metadata:           []byte(`{}`),
	}
}

func adminSubscriptionEntitlementFixture(orgID string, in AdminSubscriptionEntitlementUpsertInput) store.SubscriptionEntitlement {
	subID := strings.TrimSpace(in.SubscriptionID)
	return store.SubscriptionEntitlement{
		ID:              "sent_projects_override",
		OrganizationID:  orgID,
		SubscriptionID:  &subID,
		Source:          in.Source,
		EntitlementKey:  in.EntitlementKey,
		LimitValue:      in.LimitValue,
		EnforcementMode: in.EnforcementMode,
		Reason:          in.Reason,
		EffectiveFrom:   in.EffectiveFrom,
		Metadata:        []byte(`{}`),
	}
}
