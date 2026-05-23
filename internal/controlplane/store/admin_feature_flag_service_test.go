package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminFeatureFlagEvaluationPrecedenceRolloutAuditAndCacheInvalidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	f := testutil.NewFactory(t)

	actorOrg := seedOrg(t, db, f, "AdminFeatureFlagActor")

	svc, err := store.NewAdminFeatureFlagService(s, store.NewOrganizationRepository(), store.NewFeatureFlagRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminFeatureFlagService: %v", err)
	}
	auditCtx := store.AdminFeatureFlagAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_feature_flag",
		ActorKind:     "usr",
		RequestID:     "req_admin_feature_flag_store",
		CorrelationID: "corr_admin_feature_flag_store",
		Reason:        "enable previews",
	}
	flag, err := svc.UpsertFeatureFlag(ctx, "previews", store.UpsertFeatureFlagInput{
		ValueType:    store.FeatureFlagBoolean,
		DefaultValue: json.RawMessage("false"),
		TargetingRules: []store.FeatureFlagRule{
			{Scope: store.FeatureFlagScopeOrganization, OrganizationID: "org_target", Value: json.RawMessage("false"), RolloutPercentage: 10000},
			{Scope: store.FeatureFlagScopeService, ServiceID: "svc_target", Value: json.RawMessage("true"), RolloutPercentage: 10000},
		},
		AdminSensitive: true,
		Enabled:        true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertFeatureFlag: %v", err)
	}
	if flag.FlagKey != "previews" || !flag.AdminSensitive || len(flag.TargetingRules) != 2 {
		t.Fatalf("flag = %+v", flag)
	}

	eval, err := svc.EvaluateFeatureFlag(ctx, "previews", store.FeatureFlagEvaluationContext{OrganizationID: "org_target", ServiceID: "svc_target", SubjectID: "usr_target"}, auditCtx)
	if err != nil {
		t.Fatalf("EvaluateFeatureFlag: %v", err)
	}
	if string(eval.Value) != "true" || eval.MatchedScope != "service" || !eval.EvaluationAudited {
		t.Fatalf("eval = %+v", eval)
	}

	_, err = svc.UpsertFeatureFlag(ctx, "previews", store.UpsertFeatureFlagInput{
		ValueType:    store.FeatureFlagBoolean,
		DefaultValue: json.RawMessage("false"),
		TargetingRules: []store.FeatureFlagRule{
			{Scope: store.FeatureFlagScopeService, ServiceID: "svc_target", Value: json.RawMessage("false"), RolloutPercentage: 10000},
		},
		AdminSensitive: true,
		Enabled:        true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("second UpsertFeatureFlag: %v", err)
	}
	eval, err = svc.EvaluateFeatureFlag(ctx, "previews", store.FeatureFlagEvaluationContext{ServiceID: "svc_target", SubjectID: "usr_target"}, auditCtx)
	if err != nil {
		t.Fatalf("second EvaluateFeatureFlag: %v", err)
	}
	if string(eval.Value) != "false" || eval.MatchedScope != "service" {
		t.Fatalf("cache was not invalidated, eval = %+v", eval)
	}

	stableA, err := svc.EvaluateFeatureFlag(ctx, "previews", store.FeatureFlagEvaluationContext{ServiceID: "svc_target", SubjectID: "usr_target"}, auditCtx)
	if err != nil {
		t.Fatalf("stable eval A: %v", err)
	}
	stableB, err := svc.EvaluateFeatureFlag(ctx, "previews", store.FeatureFlagEvaluationContext{ServiceID: "svc_target", SubjectID: "usr_target"}, auditCtx)
	if err != nil {
		t.Fatalf("stable eval B: %v", err)
	}
	if stableA.RolloutIncluded != stableB.RolloutIncluded || string(stableA.Value) != string(stableB.Value) {
		t.Fatalf("rollout not deterministic: A=%+v B=%+v", stableA, stableB)
	}
}
