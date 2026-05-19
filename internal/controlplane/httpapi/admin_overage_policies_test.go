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
)

type fakeAdminOveragePolicyManager struct {
	policy store.OveragePolicy
	err    error
	calls  []string
}

func (f *fakeAdminOveragePolicyManager) UpsertOveragePolicy(_ context.Context, in AdminOveragePolicyUpsertInput, _ store.AdminOveragePolicyAuditContext) (store.OveragePolicy, error) {
	f.calls = append(f.calls, string(in.Scope)+":"+in.PlanID+":"+in.OrganizationID+":"+in.EntitlementKey+":"+string(in.Mode))
	if f.err != nil {
		return store.OveragePolicy{}, f.err
	}
	if f.policy.ID == "" {
		f.policy = adminOveragePolicyFixture(in)
	}
	return f.policy, nil
}

func adminOveragePolicyHandlerFor(authn Authenticator, manager AdminOveragePolicyManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminOveragePoliciesUpsertGlobalPlanAndOrganization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		auth string
		want string
	}{
		{"global", "/v1/admin/overage-policies/global/http_bandwidth_total", "org_admin", "global:::http_bandwidth_total:warn"},
		{"plan", "/v1/admin/plans/plan_business_monthly_v1/overage-policies/http_bandwidth_total", "org_admin", "plan:plan_business_monthly_v1::http_bandwidth_total:warn"},
		{"organization", "/v1/admin/organizations/org_target/overage-policies/http_bandwidth_total", "org_target", "organization::org_target:http_bandwidth_total:warn"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			manager := &fakeAdminOveragePolicyManager{}
			h := adminOveragePolicyHandlerFor(adminPlanAuthForOrg(tc.auth, policy.RolePricingAdmin), manager)
			rec := httptest.NewRecorder()
			body := `{"mode":"warn","effective_at":"2026-05-19T12:00:00Z"}`
			h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, tc.path, body))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if len(manager.calls) != 1 || manager.calls[0] != tc.want {
				t.Fatalf("calls = %#v, want %q", manager.calls, tc.want)
			}
			var env struct {
				SchemaVersion string `json:"schema_version"`
				OK            bool   `json:"ok"`
				Data          struct {
					ID             string `json:"id"`
					Scope          string `json:"scope"`
					EntitlementKey string `json:"entitlement_key"`
					Mode           string `json:"mode"`
					EffectiveAt    string `json:"effective_at"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
			}
			if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.ID == "" || env.Data.Mode != "warn" {
				t.Fatalf("envelope = %+v", env)
			}
		})
	}
}

func TestAdminOveragePoliciesRequirePricingRoleAndValidateInput(t *testing.T) {
	t.Parallel()

	body := `{"mode":"warn","effective_at":"2026-05-19T12:00:00Z"}`
	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		h := adminOveragePolicyHandlerFor(fakeAuthenticator{}, &fakeAdminOveragePolicyManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/overage-policies/global/http_bandwidth_total", strings.NewReader(body)))
		assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)
	})
	t.Run("non-pricing", func(t *testing.T) {
		t.Parallel()
		h := adminOveragePolicyHandlerFor(adminPlanAuthForOrg("org_admin", policy.RoleAdmin), &fakeAdminOveragePolicyManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/overage-policies/global/http_bandwidth_total", body))
		assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
	})
	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		h := adminOveragePolicyHandlerFor(adminPlanAuthForOrg("org_admin", policy.RolePricingAdmin), &fakeAdminOveragePolicyManager{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/overage-policies/global/-bad", `{"mode":"explode"}`))
		assertErrorCode(t, rec, http.StatusBadRequest, yerr.CodeValidation)
	})
	t.Run("manager not found", func(t *testing.T) {
		t.Parallel()
		h := adminOveragePolicyHandlerFor(adminPlanAuthForOrg("org_admin", policy.RolePricingAdmin), &fakeAdminOveragePolicyManager{err: apierr.NotFound("plan", "missing")})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, adminPlanRequest(http.MethodPut, "/v1/admin/plans/missing/overage-policies/http_bandwidth_total", body))
		assertErrorCode(t, rec, http.StatusNotFound, yerr.CodeNotFound)
	})
}

func adminOveragePolicyFixture(in AdminOveragePolicyUpsertInput) store.OveragePolicy {
	effectiveAt := in.EffectiveAt
	if effectiveAt.IsZero() {
		effectiveAt = time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	}
	out := store.OveragePolicy{
		ID:             "ovpol_fixture",
		Scope:          in.Scope,
		EntitlementKey: in.EntitlementKey,
		Mode:           in.Mode,
		EffectiveAt:    effectiveAt,
		Revision:       1,
	}
	if in.PlanID != "" {
		out.PlanID = &in.PlanID
	}
	if in.OrganizationID != "" {
		out.OrganizationID = &in.OrganizationID
	}
	return out
}
