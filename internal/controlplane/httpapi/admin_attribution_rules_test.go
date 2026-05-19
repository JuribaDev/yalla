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

type fakeAdminAttributionRuleManager struct {
	rule   store.AttributionRule
	result AdminAttributionRuleDryRunResult
	err    error
	calls  []string
	got    AdminAttributionRuleUpsertInput
}

func (f *fakeAdminAttributionRuleManager) UpsertAttributionRule(_ context.Context, key string, in AdminAttributionRuleUpsertInput, _ store.AdminAttributionRuleAuditContext) (store.AttributionRule, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.AttributionRule{}, f.err
	}
	if f.rule.ID == "" {
		f.rule = adminAttributionRuleFixture(key)
	}
	return f.rule, nil
}

func (f *fakeAdminAttributionRuleManager) GetAttributionRule(_ context.Context, key string) (store.AttributionRule, error) {
	f.calls = append(f.calls, "get:"+key)
	if f.err != nil {
		return store.AttributionRule{}, f.err
	}
	if f.rule.ID == "" {
		f.rule = adminAttributionRuleFixture(key)
	}
	return f.rule, nil
}

func (f *fakeAdminAttributionRuleManager) DryRunAttributionRules(_ context.Context, in AdminAttributionRuleDryRunInput) (AdminAttributionRuleDryRunResult, error) {
	f.calls = append(f.calls, "dry-run")
	if f.err != nil {
		return AdminAttributionRuleDryRunResult{}, f.err
	}
	if len(f.result.Decisions) == 0 {
		f.result = store.AttributionDryRunResult{
			Decisions: []store.AttributionDryRunDecision{{
				Index:      0,
				MetricName: in.Samples[0].MetricName,
				Decision:   "attribute",
				RuleKey:    "label-service-id",
				Source:     store.AttributionRuleSourceTraefik,
				Confidence: store.AttributionRuleConfidenceHigh,
				ServiceID:  "svc_demo",
				Billable:   true,
			}},
			Summary: map[string]int{"attributed": 1, "quarantined": 0, "ignored": 0},
		}
	}
	return f.result, nil
}

func adminAttributionRuleHandlerFor(authn Authenticator, manager AdminAttributionRuleManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminAttributionRulesUpsertGetAndDryRun(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminAttributionRuleManager{}
	h := adminAttributionRuleHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), manager)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminAttributionRuleRequest(http.MethodPut, "/v1/admin/metering/attribution/rules/label-service-id", `{"source":"traefik","priority":10,"match_kind":"traefik_service_label","label_key":"yalla_service_id","min_confidence":"high","quarantine_unmatched":true,"quarantine_ambiguous":true,"enabled":true}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:label-service-id" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.MatchKind != store.AttributionRuleMatchTraefikServiceLabel || manager.got.LabelKey != "yalla_service_id" {
		t.Fatalf("manager input = %+v", manager.got)
	}
	env := decodeAdminAttributionRuleEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.RuleKey != "label-service-id" || env.Data.MatchKind != "traefik_service_label" {
		t.Fatalf("envelope = %+v", env)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminAttributionRuleRequest(http.MethodGet, "/v1/admin/metering/attribution/rules/label-service-id", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminAttributionRuleRequest(http.MethodPost, "/v1/admin/metering/attribution/dry-run", `{"samples":[{"source":"traefik","metric_name":"http_requests","labels":{"yalla_service_id":"svc_demo"}}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var dry struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			Decisions []struct {
				Decision string `json:"decision"`
				Billable bool   `json:"billable"`
			} `json:"decisions"`
			Summary map[string]int `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dry); err != nil {
		t.Fatalf("decode dry-run: %v", err)
	}
	if !dry.OK || len(dry.Data.Decisions) != 1 || dry.Data.Decisions[0].Decision != "attribute" || dry.Data.Summary["attributed"] != 1 {
		t.Fatalf("dry-run envelope = %+v", dry)
	}
}

func TestAdminAttributionRulesAuthValidationAndNotFound(t *testing.T) {
	t.Parallel()

	h := adminAttributionRuleHandlerFor(fakeAuthenticator{}, &fakeAdminAttributionRuleManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/metering/attribution/rules/label-service-id", strings.NewReader(`{"source":"traefik","match_kind":"traefik_service_label","label_key":"yalla_service_id","enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminAttributionRuleHandlerFor(adminMeteringSourceAuth(t, policy.RoleAdmin), &fakeAdminAttributionRuleManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminAttributionRuleRequest(http.MethodPut, "/v1/admin/metering/attribution/rules/label-service-id", `{"source":"traefik","match_kind":"traefik_service_label","label_key":"yalla_service_id","enabled":true}`))
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
		{"invalid", http.MethodPut, "/v1/admin/metering/attribution/rules/bad", `{"source":"traefik","match_kind":"traefik_service_label","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "label_key", Reason: "must not be blank"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodGet, "/v1/admin/metering/attribution/rules/missing", ``, apierr.NotFound("attribution_rule", "missing"), http.StatusNotFound, yerr.CodeNotFound},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminAttributionRuleHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), &fakeAdminAttributionRuleManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminAttributionRuleRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminAttributionRuleRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_attribution")
	req.Header.Set("X-Request-Id", "req_admin_attribution")
	req.Header.Set("X-Yalla-Reason", "configure attribution")
	return req
}

func adminAttributionRuleFixture(key string) store.AttributionRule {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	return store.AttributionRule{
		ID:                  "arule_test",
		RuleKey:             key,
		Source:              store.AttributionRuleSourceTraefik,
		Priority:            10,
		MatchKind:           store.AttributionRuleMatchTraefikServiceLabel,
		LabelKey:            "yalla_service_id",
		MinConfidence:       store.AttributionRuleConfidenceHigh,
		QuarantineUnmatched: true,
		QuarantineAmbiguous: true,
		Enabled:             true,
		Revision:            1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func decodeAdminAttributionRuleEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		RuleKey   string `json:"rule_key"`
		MatchKind string `json:"match_kind"`
		Enabled   bool   `json:"enabled"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			RuleKey   string `json:"rule_key"`
			MatchKind string `json:"match_kind"`
			Enabled   bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
