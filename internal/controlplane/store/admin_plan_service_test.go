package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminPlanServiceEditPublishArchiveRollbackAndAudit(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "AdminPlanAudit")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminPlanServiceForTest(t, s)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    org.ID,
		ActorID:       "usr_admin_plan",
		ActorKind:     "usr",
		RequestID:     "req_admin_plan_service",
		CorrelationID: "corr_admin_plan_service",
	}

	draft, err := svc.EditPlan(ctx, "plan_business_monthly_v1", store.UpdatePlanInput{
		Name:         "Business Next",
		Status:       store.PlanStatusDraft,
		DisplayOrder: 31,
	}, auditCtx)
	if err != nil {
		t.Fatalf("EditPlan: %v", err)
	}
	if draft.Status != store.PlanStatusDraft || draft.Version != 2 {
		t.Fatalf("draft = %+v, want draft v2", draft)
	}
	activeBefore := getPlanOrFail(ctx, t, s, store.NewPricingPlanRepository(), "plan_business_monthly_v1")
	if activeBefore.Status != store.PlanStatusActive || activeBefore.ArchivedAt != nil {
		t.Fatalf("active before publish = %+v, want still active", activeBefore)
	}

	published, err := svc.PublishPlan(ctx, draft.ID, auditCtx)
	if err != nil {
		t.Fatalf("PublishPlan: %v", err)
	}
	if published.Status != store.PlanStatusActive || published.Version != 2 {
		t.Fatalf("published = %+v, want active v2", published)
	}
	old := getPlanOrFail(ctx, t, s, store.NewPricingPlanRepository(), "plan_business_monthly_v1")
	if old.Status != store.PlanStatusArchived || old.ArchivedAt == nil {
		t.Fatalf("old plan = %+v, want archived", old)
	}

	archived, err := svc.ArchivePlan(ctx, published.ID, auditCtx)
	if err != nil {
		t.Fatalf("ArchivePlan: %v", err)
	}
	if archived.Status != store.PlanStatusArchived || archived.ArchivedAt == nil {
		t.Fatalf("archived = %+v, want archived", archived)
	}

	rollback, err := svc.RollbackPlan(ctx, old.ID, auditCtx)
	if err != nil {
		t.Fatalf("RollbackPlan: %v", err)
	}
	if rollback.Status != store.PlanStatusActive || rollback.Version != 3 || rollback.Name != old.Name {
		t.Fatalf("rollback = %+v, want active v3 copy of old", rollback)
	}

	var events []store.AuditEvent
	err = s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		events, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, org.ID, 10)
		return readErr
	})
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("audit events = %d, want 4: %+v", len(events), events)
	}
	for _, event := range events {
		if event.RequestID != auditCtx.RequestID || event.CorrelationID != auditCtx.CorrelationID || event.ActorID != auditCtx.ActorID {
			t.Fatalf("audit event missing request/actor identity: %+v", event)
		}
		if event.ResourceKind != "plan" || event.Decision != store.AuditDecisionAllowed {
			t.Fatalf("audit event = %+v, want allowed plan event", event)
		}
	}
}

func TestAdminPlanServiceRejectsArchivedEditAndUnknownActorOrg(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminPlanServiceForTest(t, s)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    "org_missing",
		ActorID:       "usr_missing",
		ActorKind:     "usr",
		RequestID:     "req_admin_plan_missing",
		CorrelationID: "corr_admin_plan_missing",
	}

	if _, err := svc.PublishPlan(ctx, "plan_business_monthly_v1", auditCtx); err == nil {
		t.Fatal("PublishPlan with unknown actor org error = nil, want not found")
	}

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "AdminPlanConflict")
	auditCtx.ActorOrgID = org.ID
	auditCtx.ActorID = "usr_admin_plan_conflict"
	if _, err := svc.ArchivePlan(ctx, "plan_business_monthly_v1", auditCtx); err != nil {
		t.Fatalf("ArchivePlan active: %v", err)
	}
	if _, err := svc.EditPlan(ctx, "plan_business_monthly_v1", store.UpdatePlanInput{
		Name:         "Nope",
		Status:       store.PlanStatusDraft,
		DisplayOrder: 1,
	}, auditCtx); err == nil {
		t.Fatal("EditPlan archived error = nil, want conflict")
	}
}

func newAdminPlanServiceForTest(t *testing.T, s *store.Store) *store.AdminPlanService {
	t.Helper()
	svc, err := store.NewAdminPlanService(s, store.NewOrganizationRepository(), store.NewPricingPlanRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminPlanService: %v", err)
	}
	return svc
}

func newStoreForAdminPlanTest(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}
