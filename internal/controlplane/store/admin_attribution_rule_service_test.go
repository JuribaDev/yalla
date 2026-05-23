package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminAttributionRuleServicePublishDryRunAndRuntimeReload(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminAttributionRuleActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminAttributionRuleServiceForTest(t, s)
	auditCtx := store.AdminAttributionRuleAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_attribution_rule",
		ActorKind:     "user",
		RequestID:     "req_admin_attribution_rule_store",
		CorrelationID: "corr_admin_attribution_rule_store",
		Reason:        "publish attribution rule",
	}

	rule, err := svc.UpsertAttributionRule(ctx, "label-service-id", store.UpsertAttributionRuleInput{
		Source:              store.AttributionRuleSourceTraefik,
		Priority:            10,
		MatchKind:           store.AttributionRuleMatchTraefikServiceLabel,
		LabelKey:            "yalla_service_id",
		MinConfidence:       store.AttributionRuleConfidenceHigh,
		QuarantineUnmatched: true,
		QuarantineAmbiguous: true,
		Enabled:             true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertAttributionRule: %v", err)
	}
	if rule.RuleKey != "label-service-id" || rule.MatchKind != store.AttributionRuleMatchTraefikServiceLabel || !rule.Enabled {
		t.Fatalf("published rule = %+v", rule)
	}

	result, err := svc.DryRunAttributionRules(ctx, store.AttributionDryRunInput{Samples: []store.AttributionDryRunSample{
		{Source: store.AttributionRuleSourceTraefik, MetricName: "http_requests", Labels: map[string]string{"yalla_service_id": "svc_abc"}},
		{Source: store.AttributionRuleSourceTraefik, MetricName: "http_requests", Service: "unmanaged-service"},
	}})
	if err != nil {
		t.Fatalf("DryRunAttributionRules: %v", err)
	}
	if len(result.Decisions) != 2 || result.Summary["attributed"] != 1 || result.Summary["quarantined"] != 1 {
		t.Fatalf("dry-run result = %+v", result)
	}
	if !result.Decisions[0].Billable || result.Decisions[0].ServiceID != "svc_abc" {
		t.Fatalf("attributed decision = %+v", result.Decisions[0])
	}
	if !result.Decisions[1].Quarantined || result.Decisions[1].Reason != "unmatched" {
		t.Fatalf("unmatched decision = %+v", result.Decisions[1])
	}

	repo := store.NewAttributionRuleRepository()
	var runtimeRules []store.AttributionRule
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		runtimeRules, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled: %v", err)
	}
	if len(runtimeRules) != 1 || runtimeRules[0].RuleKey != "label-service-id" {
		t.Fatalf("runtime rules = %+v", runtimeRules)
	}

	var eventCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action = 'admin.attribution_rule.upsert'`, actorOrg.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("audit event count = %d, want 1", eventCount)
	}
}

func TestAttributionRuleDryRunAmbiguousAndQuarantinePolicy(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminAttributionRuleServiceForTest(t, s)

	result, err := svc.DryRunAttributionRules(ctx, store.AttributionDryRunInput{
		Rules: []store.UpsertAttributionRuleInput{
			{Source: store.AttributionRuleSourceTraefik, Priority: 10, MatchKind: store.AttributionRuleMatchTraefikServiceLabel, LabelKey: "yalla_service_id", MinConfidence: store.AttributionRuleConfidenceHigh, QuarantineUnmatched: true, QuarantineAmbiguous: true, Enabled: true},
			{Source: store.AttributionRuleSourceTraefik, Priority: 20, MatchKind: store.AttributionRuleMatchDokployAppName, Pattern: "yalla-{service_id}", MinConfidence: store.AttributionRuleConfidenceMedium, QuarantineUnmatched: true, QuarantineAmbiguous: true, Enabled: true},
			{Source: store.AttributionRuleSourceDokploy, Priority: 30, MatchKind: store.AttributionRuleMatchExplicitDokployRef, DokployResource: "application", MinConfidence: store.AttributionRuleConfidenceHigh, QuarantineUnmatched: false, QuarantineAmbiguous: true, Enabled: true},
		},
		Samples: []store.AttributionDryRunSample{
			{Source: store.AttributionRuleSourceTraefik, MetricName: "http_requests", AppName: "yalla-svc_two", Labels: map[string]string{"yalla_service_id": "svc_one"}},
			{Source: store.AttributionRuleSourceDokploy, MetricName: "deployments", DokployRefID: "dref_123"},
			{Source: store.AttributionRuleSourceDokploy, MetricName: "deployments"},
		},
	})
	if err != nil {
		t.Fatalf("DryRunAttributionRules: %v", err)
	}
	if result.Decisions[0].Decision != "quarantine" || result.Decisions[0].Reason != "ambiguous" || result.Decisions[0].Billable {
		t.Fatalf("ambiguous decision = %+v", result.Decisions[0])
	}
	if result.Decisions[1].Decision != "attribute" || result.Decisions[1].DokployRef != "dref_123" || !result.Decisions[1].Billable {
		t.Fatalf("dokploy_ref decision = %+v", result.Decisions[1])
	}
	if result.Decisions[2].Decision != "ignore" || result.Decisions[2].Billable || result.Decisions[2].Quarantined {
		t.Fatalf("unmatched quarantine policy decision = %+v", result.Decisions[2])
	}
}

func TestAttributionRuleRepositoryValidationAndNotFound(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	repo := store.NewAttributionRuleRepository()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, "bad", store.UpsertAttributionRuleInput{
			Source:    store.AttributionRuleSourceTraefik,
			MatchKind: store.AttributionRuleMatchTraefikServiceLabel,
			Enabled:   true,
		})
		return err
	}); err == nil {
		t.Fatal("invalid attribution rule was accepted")
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, "missing")
		return err
	}); err == nil {
		t.Fatal("missing attribution rule returned nil error")
	}
}

func newAdminAttributionRuleServiceForTest(t *testing.T, s *store.Store) *store.AdminAttributionRuleService {
	t.Helper()
	svc, err := store.NewAdminAttributionRuleService(s, store.NewOrganizationRepository(), store.NewAttributionRuleRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminAttributionRuleService: %v", err)
	}
	return svc
}
