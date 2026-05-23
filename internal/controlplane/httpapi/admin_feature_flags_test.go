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

type fakeAdminFeatureFlagManager struct {
	flag  store.FeatureFlag
	eval  store.FeatureFlagEvaluation
	err   error
	calls []string
	got   AdminFeatureFlagUpsertInput
}

func (f *fakeAdminFeatureFlagManager) UpsertFeatureFlag(_ context.Context, key string, in AdminFeatureFlagUpsertInput, _ store.AdminFeatureFlagAuditContext) (store.FeatureFlag, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.FeatureFlag{}, f.err
	}
	if f.flag.ID == "" {
		f.flag = adminFeatureFlagFixture(key)
	}
	return f.flag, nil
}

func (f *fakeAdminFeatureFlagManager) GetFeatureFlag(_ context.Context, key string) (store.FeatureFlag, error) {
	f.calls = append(f.calls, "get:"+key)
	if f.err != nil {
		return store.FeatureFlag{}, f.err
	}
	if f.flag.ID == "" {
		f.flag = adminFeatureFlagFixture(key)
	}
	return f.flag, nil
}

func (f *fakeAdminFeatureFlagManager) EvaluateFeatureFlag(_ context.Context, key string, in AdminFeatureFlagEvaluateInput, _ store.AdminFeatureFlagAuditContext) (store.FeatureFlagEvaluation, error) {
	f.calls = append(f.calls, "evaluate:"+key+":"+in.ServiceID)
	if f.err != nil {
		return store.FeatureFlagEvaluation{}, f.err
	}
	if len(f.eval.Value) == 0 {
		f.eval = store.FeatureFlagEvaluation{
			FlagKey:           key,
			ValueType:         "boolean",
			Value:             json.RawMessage("true"),
			Enabled:           true,
			MatchedScope:      "service",
			MatchedRuleIndex:  0,
			RolloutPercentage: 10000,
			RolloutIncluded:   true,
			Revision:          1,
		}
	}
	return f.eval, nil
}

func adminFeatureFlagHandlerFor(authn Authenticator, manager AdminFeatureFlagManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminFeatureFlagsUpsertGetAndEvaluate(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminFeatureFlagManager{}
	h := adminFeatureFlagHandlerFor(adminMeteringSourceAuth(t, policy.RoleFeatureFlagAdmin), manager)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminFeatureFlagRequest(http.MethodPut, "/v1/admin/feature-flags/previews", `{"value_type":"boolean","default_value":false,"targeting_rules":[{"scope":"service","service_id":"svc_demo","value":true,"rollout_percentage":10000}],"rollout_percentage":0,"admin_sensitive":true,"enabled":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:previews" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.ValueType != store.FeatureFlagBoolean || len(manager.got.TargetingRules) != 1 {
		t.Fatalf("manager input = %+v", manager.got)
	}
	env := decodeAdminFeatureFlagEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.FlagKey != "previews" || env.Data.ValueType != "boolean" {
		t.Fatalf("envelope = %+v", env)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminFeatureFlagRequest(http.MethodGet, "/v1/admin/feature-flags/previews", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminFeatureFlagRequest(http.MethodPost, "/v1/admin/feature-flags/previews/evaluate", `{"organization_id":"org_demo","service_id":"svc_demo","subject_id":"usr_demo"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var eval struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			FlagKey           string          `json:"flag_key"`
			Value             json.RawMessage `json:"value"`
			MatchedScope      string          `json:"matched_scope"`
			RolloutIncluded   bool            `json:"rollout_included"`
			EvaluationAudited bool            `json:"evaluation_audited"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode evaluate: %v", err)
	}
	if !eval.OK || eval.Data.FlagKey != "previews" || string(eval.Data.Value) != "true" || eval.Data.MatchedScope != "service" || !eval.Data.RolloutIncluded {
		t.Fatalf("evaluation envelope = %+v", eval)
	}
}

func TestAdminFeatureFlagsAuthValidationAndNotFound(t *testing.T) {
	t.Parallel()

	h := adminFeatureFlagHandlerFor(fakeAuthenticator{}, &fakeAdminFeatureFlagManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/feature-flags/previews", strings.NewReader(`{"value_type":"boolean","default_value":false,"enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminFeatureFlagHandlerFor(adminMeteringSourceAuth(t, policy.RoleAdmin), &fakeAdminFeatureFlagManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminFeatureFlagRequest(http.MethodPut, "/v1/admin/feature-flags/previews", `{"value_type":"boolean","default_value":false,"enabled":true}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)

	rows := []struct {
		name   string
		method string
		path   string
		body   string
		err    error
		status int
		code   yerr.Code
	}{
		{"invalid", http.MethodPut, "/v1/admin/feature-flags/bad", `{"value_type":"boolean","default_value":"no","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "default_value", Reason: "must match value_type"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodGet, "/v1/admin/feature-flags/missing", ``, apierr.NotFound("feature_flag", "missing"), http.StatusNotFound, yerr.CodeNotFound},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminFeatureFlagHandlerFor(adminMeteringSourceAuth(t, policy.RoleFeatureFlagAdmin), &fakeAdminFeatureFlagManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminFeatureFlagRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminFeatureFlagRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_feature_flag")
	req.Header.Set("X-Request-Id", "req_admin_feature_flag")
	req.Header.Set("X-Yalla-Reason", "configure feature flags")
	return req
}

func adminFeatureFlagFixture(key string) store.FeatureFlag {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	return store.FeatureFlag{
		ID:                "fflag_test",
		FlagKey:           key,
		ValueType:         store.FeatureFlagBoolean,
		DefaultValue:      json.RawMessage("false"),
		TargetingRules:    []store.FeatureFlagRule{{Scope: store.FeatureFlagScopeService, ServiceID: "svc_demo", Value: json.RawMessage("true"), RolloutPercentage: 10000}},
		RolloutPercentage: 0,
		AdminSensitive:    true,
		Enabled:           true,
		Revision:          1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func decodeAdminFeatureFlagEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		FlagKey   string `json:"flag_key"`
		ValueType string `json:"value_type"`
		Enabled   bool   `json:"enabled"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			FlagKey   string `json:"flag_key"`
			ValueType string `json:"value_type"`
			Enabled   bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
