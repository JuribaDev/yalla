package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestAdminConfigServiceAuditsPublishDiffWithRedaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	org := seedOrg(t, db, testutil.NewFactory(t), "Admin")
	svc := newAdminConfigServiceForTest(t, s)
	auditRepo := store.NewAuditRepository()
	auditCtx := adminConfigAuditCtx(org.ID)

	set, err := svc.CreateSet(ctx, store.CreateAdminConfigSetInput{
		Slug:   "pricing-audit",
		Domain: store.AdminConfigDomainPricing,
		Name:   "Pricing Audit",
	}, auditCtx)
	if err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	draft, err := svc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{
		ConfigSetID: set.ID,
		Payload:     []byte(`{"plans":[{"slug":"starter","entitlements":{"projects":1},"enforcement_mode":"soft"}],"provider_token":"tok_live_secret_123"}`),
	}, auditCtx)
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	effectiveAt := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	if _, err := svc.Publish(ctx, draft.ID, store.PublishAdminConfigVersionInput{
		EffectiveAt: effectiveAt,
		PublishedBy: "usr_admin",
	}, auditCtx); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	events := listAdminConfigAuditEvents(t, ctx, s, auditRepo, org.ID)
	publish := findAuditEventByAction(t, events, "admin.config.publish")
	if publish.ActorID != "usr_admin" || publish.ActorKind != "usr" || publish.RequestID != "req_admin_config_audit" {
		t.Fatalf("publish actor/request = %q/%q/%q", publish.ActorID, publish.ActorKind, publish.RequestID)
	}
	if publish.Metadata["reason"] != "approved pricing rollout" || publish.Metadata["effective_at"] != effectiveAt.Format(time.RFC3339Nano) {
		t.Fatalf("publish metadata reason/effective_at = %+v", publish.Metadata)
	}
	if strings.Contains(publish.Metadata["after"], "tok_live_secret_123") || !strings.Contains(publish.Metadata["after"], output.Sentinel) {
		t.Fatalf("publish after metadata did not redact secret token: %s", publish.Metadata["after"])
	}
	changed := decodeStringSlice(t, publish.Metadata["changed_fields"])
	assertContainsString(t, changed, "effective_at")
	assertContainsString(t, changed, "published_by")
	assertContainsString(t, changed, "status")

	var after map[string]any
	if err := json.Unmarshal([]byte(publish.Metadata["after"]), &after); err != nil {
		t.Fatalf("decode after metadata: %v", err)
	}
	if after["status"] != "published" {
		t.Fatalf("after.status = %v, want published", after["status"])
	}
}

func TestAdminConfigServiceAuditsRollbackTargetAndPayloadDiff(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	org := seedOrg(t, db, testutil.NewFactory(t), "Admin")
	svc := newAdminConfigServiceForTest(t, s)
	auditRepo := store.NewAuditRepository()
	auditCtx := adminConfigAuditCtx(org.ID)
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)

	set, err := svc.CreateSet(ctx, store.CreateAdminConfigSetInput{Slug: "quota-audit", Domain: store.AdminConfigDomainQuota, Name: "Quota Audit"}, auditCtx)
	if err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	firstDraft, err := svc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{ConfigSetID: set.ID, Payload: []byte(`{"thresholds":{"projects":3},"enforcement_mode":"hard"}`)}, auditCtx)
	if err != nil {
		t.Fatalf("CreateDraft first: %v", err)
	}
	first, err := svc.Publish(ctx, firstDraft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now, PublishedBy: "usr_admin"}, auditCtx)
	if err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	secondDraft, err := svc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{ConfigSetID: set.ID, Payload: []byte(`{"thresholds":{"projects":9},"enforcement_mode":"soft"}`)}, auditCtx)
	if err != nil {
		t.Fatalf("CreateDraft second: %v", err)
	}
	second, err := svc.Publish(ctx, secondDraft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now.Add(time.Hour), PublishedBy: "usr_admin"}, auditCtx)
	if err != nil {
		t.Fatalf("Publish second: %v", err)
	}
	rollback, err := svc.Rollback(ctx, set.ID, first.ID, store.RollbackAdminConfigInput{
		EffectiveAt:     now.Add(2 * time.Hour),
		PublishedBy:     "usr_admin",
		RollbackVersion: second.ID,
		RollbackReason:  "restore hard quota",
	}, auditCtx)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	events := listAdminConfigAuditEvents(t, ctx, s, auditRepo, org.ID)
	event := findAuditEventByAction(t, events, "admin.config.rollback")
	if event.ResourceID != rollback.ID || event.Metadata["rollback_target_version_id"] != second.ID {
		t.Fatalf("rollback audit resource/target = %q/%q, want %q/%q", event.ResourceID, event.Metadata["rollback_target_version_id"], rollback.ID, second.ID)
	}
	changed := decodeStringSlice(t, event.Metadata["changed_fields"])
	assertContainsString(t, changed, "id")
	assertContainsString(t, changed, "rollback_of_version_id")
	assertContainsString(t, changed, "rollback_reason")
}

func TestAdminConfigServiceAuditsDeniedActions(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	org := seedOrg(t, db, testutil.NewFactory(t), "Admin")
	svc := newAdminConfigServiceForTest(t, s)
	auditRepo := store.NewAuditRepository()

	if err := svc.AuditAdminConfigDenied(ctx, adminConfigAuditCtx(org.ID), "admin.config.publish", "cfgver_denied", "denied_no_capability"); err != nil {
		t.Fatalf("AuditAdminConfigDenied: %v", err)
	}
	events := listAdminConfigAuditEvents(t, ctx, s, auditRepo, org.ID)
	event := findAuditEventByAction(t, events, "admin.config.publish")
	if event.Decision != store.AuditDecisionDenied || event.Reason != "denied_no_capability" {
		t.Fatalf("denied event decision/reason = %q/%q", event.Decision, event.Reason)
	}
	if event.Metadata["operation"] != "denied" || event.Metadata["reason"] != "approved pricing rollout" {
		t.Fatalf("denied metadata = %+v", event.Metadata)
	}
}

func TestAdminConfigServiceRequiresAuditReasonAndPreservesImmutability(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	org := seedOrg(t, db, testutil.NewFactory(t), "Admin")
	svc := newAdminConfigServiceForTest(t, s)
	auditRepo := store.NewAuditRepository()

	_, err := svc.CreateSet(ctx, store.CreateAdminConfigSetInput{Slug: "features-audit", Domain: store.AdminConfigDomainFeatures, Name: "Features Audit"}, store.AdminConfigAuditContext{
		ActorOrgID: org.ID,
		ActorID:    "usr_admin",
		ActorKind:  "usr",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("missing reason code = %s, want %s (err=%v)", ye.Code, yerr.CodeValidation, err)
	}

	if _, err := svc.CreateSet(ctx, store.CreateAdminConfigSetInput{Slug: "features-audit", Domain: store.AdminConfigDomainFeatures, Name: "Features Audit"}, adminConfigAuditCtx(org.ID)); err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	events := listAdminConfigAuditEvents(t, ctx, s, auditRepo, org.ID)
	event := findAuditEventByAction(t, events, "admin.config.create_set")

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, execErr := tx.Exec(ctx, `UPDATE audit_events SET reason = 'tampered' WHERE id = $1`, event.ID)
		return execErr
	})
	if err == nil || !strings.Contains(err.Error(), "audit_events is append-only") {
		t.Fatalf("audit UPDATE err = %v, want append-only rejection", err)
	}
}

func newAdminConfigServiceForTest(t *testing.T, s *store.Store) *store.AdminConfigService {
	t.Helper()
	svc, err := store.NewAdminConfigService(s, store.NewOrganizationRepository(), store.NewAdminConfigRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminConfigService: %v", err)
	}
	return svc
}

func adminConfigAuditCtx(orgID string) store.AdminConfigAuditContext {
	return store.AdminConfigAuditContext{
		ActorOrgID:    orgID,
		ActorID:       "usr_admin",
		ActorKind:     "usr",
		RequestID:     "req_admin_config_audit",
		CorrelationID: "corr_admin_config_audit",
		Reason:        "approved pricing rollout",
	}
}

func listAdminConfigAuditEvents(t *testing.T, ctx context.Context, s *store.Store, repo *store.AuditRepository, orgID string) []store.AuditEvent {
	t.Helper()
	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		events, err = repo.ListByOrganization(ctx, q, orgID, 200)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	return events
}

func findAuditEventByAction(t *testing.T, events []store.AuditEvent, action string) store.AuditEvent {
	t.Helper()
	for _, event := range events {
		if event.Action == action {
			return event
		}
	}
	t.Fatalf("audit action %q not found in %+v", action, events)
	return store.AuditEvent{}
}

func decodeStringSlice(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode string slice %q: %v", raw, err)
	}
	return out
}

func assertContainsString(t *testing.T, values []string, want string) {
	t.Helper()
	for _, got := range values {
		if got == want {
			return
		}
	}
	t.Fatalf("%q not found in %v", want, values)
}
