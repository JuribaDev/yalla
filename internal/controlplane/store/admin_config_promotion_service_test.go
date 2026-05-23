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
)

func TestAdminConfigServiceExportsAndImportsWithDryRunDiff(t *testing.T) {
	t.Parallel()
	sourceDB := testutil.RequireMigratedDB(t)
	sourceStore := newStore(t, sourceDB)
	targetDB := testutil.RequireMigratedDB(t)
	targetStore := newStore(t, targetDB)
	ctx := context.Background()
	sourceOrg := seedOrg(t, sourceDB, testutil.NewFactory(t), "AdminConfigPromotionSource")
	targetOrg := seedOrg(t, targetDB, testutil.NewFactory(t), "AdminConfigPromotionTarget")
	sourceSvc := newAdminConfigServiceForTest(t, sourceStore)
	targetSvc := newAdminConfigServiceForTest(t, targetStore)
	sourceAuditCtx := adminConfigAuditCtx(sourceOrg.ID)
	targetAuditCtx := adminConfigAuditCtx(targetOrg.ID)
	now := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)

	set, err := sourceSvc.CreateSet(ctx, store.CreateAdminConfigSetInput{
		Slug:        "pricing-export",
		Domain:      store.AdminConfigDomainPricing,
		Name:        "Pricing Export",
		Description: "promoted between environments",
	}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	draft, err := sourceSvc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{
		ConfigSetID: set.ID,
		Payload:     []byte(`{"plans":[{"slug":"starter"}],"credential_ref":"billing/stripe","provider_token":"sk_live_secret"}`),
	}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	first, err := sourceSvc.Publish(ctx, draft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now, PublishedBy: "usr_admin"}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	secondDraft, err := sourceSvc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{ConfigSetID: set.ID, Payload: []byte(`{"plans":[{"slug":"pro"}],"credential_ref":"billing/stripe"}`)}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("CreateDraft second: %v", err)
	}
	second, err := sourceSvc.Publish(ctx, secondDraft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now.Add(time.Hour), PublishedBy: "usr_admin"}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("Publish second: %v", err)
	}
	if _, err := sourceSvc.Rollback(ctx, set.ID, first.ID, store.RollbackAdminConfigInput{EffectiveAt: now.Add(2 * time.Hour), PublishedBy: "usr_admin", RollbackVersion: second.ID, RollbackReason: "restore starter"}, sourceAuditCtx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	manifest, err := sourceSvc.Export(ctx, store.AdminConfigExportInput{SourceEnvironment: "staging"}, sourceAuditCtx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if manifest.SchemaVersion != store.AdminConfigExportSchemaVersion || manifest.SourceEnvironment != "staging" || len(manifest.ConfigSets) != 1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if len(manifest.ConfigSets[0].Versions) != 3 || manifest.ConfigSets[0].Versions[2].RollbackOfVersion != 2 {
		t.Fatalf("exported rollback lineage = %+v", manifest.ConfigSets[0].Versions)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if string(raw) == "" || strings.Contains(string(raw), "sk_live_") {
		t.Fatalf("export leaked secret-shaped value: %s", raw)
	}

	dryRun, err := targetSvc.Import(ctx, store.AdminConfigImportInput{
		TargetEnvironment:   "production",
		Manifest:            manifest,
		DryRun:              true,
		AvailableSecretRefs: []string{"billing/stripe"},
	}, targetAuditCtx)
	if err != nil {
		t.Fatalf("Import dry-run: %v", err)
	}
	if !dryRun.Valid || dryRun.Applied || len(dryRun.Changes) != 1 || dryRun.Changes[0].Operation != "create_set" {
		t.Fatalf("dry-run report = %+v", dryRun)
	}

	applied, err := targetSvc.Import(ctx, store.AdminConfigImportInput{
		TargetEnvironment:   "production",
		Manifest:            manifest,
		AvailableSecretRefs: []string{"billing/stripe"},
	}, targetAuditCtx)
	if err != nil {
		t.Fatalf("Import apply: %v", err)
	}
	if !applied.Valid || !applied.Applied || len(applied.Changes) != 1 {
		t.Fatalf("applied report = %+v", applied)
	}

	sourceEvents := listAdminConfigAuditEvents(t, ctx, sourceStore, store.NewAuditRepository(), sourceOrg.ID)
	if findAuditEventByAction(t, sourceEvents, "admin.config.export").ResourceID == "" {
		t.Fatalf("missing export audit event")
	}
	targetEvents := listAdminConfigAuditEvents(t, ctx, targetStore, store.NewAuditRepository(), targetOrg.ID)
	if findAuditEventByAction(t, targetEvents, "admin.config.import").ResourceID == "" {
		t.Fatalf("missing import audit event")
	}
}

func TestAdminConfigServiceImportBlocksMissingSecretRefsAndUnsafeDowngrade(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	org := seedOrg(t, db, testutil.NewFactory(t), "AdminConfigPromotionUnsafe")
	svc := newAdminConfigServiceForTest(t, s)
	auditCtx := adminConfigAuditCtx(org.ID)
	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)

	existing, err := svc.CreateSet(ctx, store.CreateAdminConfigSetInput{Slug: "pricing-import", Domain: store.AdminConfigDomainPricing, Name: "Pricing Import"}, auditCtx)
	if err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	for _, payload := range [][]byte{[]byte(`{"plans":[{"slug":"v1"}]}`), []byte(`{"plans":[{"slug":"v2"}]}`)} {
		draft, err := svc.CreateDraft(ctx, store.CreateAdminConfigDraftInput{ConfigSetID: existing.ID, Payload: payload}, auditCtx)
		if err != nil {
			t.Fatalf("CreateDraft: %v", err)
		}
		if _, err := svc.Publish(ctx, draft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now, PublishedBy: "usr_admin"}, auditCtx); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	manifest := store.AdminConfigExportManifest{
		SchemaVersion:     store.AdminConfigExportSchemaVersion,
		SourceEnvironment: "staging",
		ExportedAt:        now,
		ConfigSets: []store.AdminConfigExportSet{{
			Slug:   "pricing-import",
			Domain: store.AdminConfigDomainPricing,
			Name:   "Pricing Import",
			Versions: []store.AdminConfigExportVersion{{
				Version:     1,
				Status:      store.AdminConfigStatusPublished,
				Payload:     json.RawMessage(`{"plans":[{"slug":"v1"}],"credential_ref":"billing/stripe"}`),
				EffectiveAt: &now,
				PublishedBy: "usr_admin",
			}},
		}},
	}

	missing, err := svc.Import(ctx, store.AdminConfigImportInput{
		TargetEnvironment: "production",
		Manifest:          manifest,
		DryRun:            true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("Import missing secret dry-run: %v", err)
	}
	if missing.Valid || len(missing.MissingSecretRefs) != 1 || missing.MissingSecretRefs[0] != "billing/stripe" {
		t.Fatalf("missing secret report = %+v", missing)
	}

	_, err = svc.Import(ctx, store.AdminConfigImportInput{
		TargetEnvironment:   "production",
		Manifest:            manifest,
		AvailableSecretRefs: []string{"billing/stripe"},
	}, auditCtx)
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("unsafe downgrade err code = %s, want %s (err=%v)", ye.Code, yerr.CodeConflict, err)
	}
}
