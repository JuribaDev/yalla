package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminBillingProviderServiceUpsertEncryptsCredentialAuditsAndRuntimeReload(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminBillingProviderActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminBillingProviderServiceForTest(t, s)
	auditCtx := store.AdminBillingProviderAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_billing",
		ActorKind:     "user",
		RequestID:     "req_admin_billing_store",
		CorrelationID: "corr_admin_billing_store",
		Reason:        "rotate billing secret=manual-secret-token",
	}
	secretValue := "manual-secret-token"

	provider, err := svc.UpsertBillingProvider(ctx, "manual-main", store.UpsertBillingProviderInput{
		ProviderType:               store.BillingProviderTypeManual,
		DisplayName:                "Manual exports",
		SecretReference:            "vault/billing/manual",
		CredentialValue:            &secretValue,
		ExportCadenceSeconds:       86400,
		RetryMaxAttempts:           5,
		RetryInitialBackoffSeconds: 60,
		DryRun:                     true,
		Metadata:                   map[string]string{"owner": "finance"},
		Enabled:                    true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertBillingProvider: %v", err)
	}
	if !provider.CredentialSet || provider.SecretProvider == "" || provider.SecretKeyID == "" || len(provider.SecretCiphertext) == 0 {
		t.Fatalf("provider credential tuple not sealed: %+v", provider)
	}
	if bytes.Contains(provider.SecretCiphertext, []byte(secretValue)) {
		t.Fatalf("ciphertext contains plaintext credential")
	}

	var valueColumn string
	var ciphertext []byte
	if err := db.QueryRow(ctx, `SELECT credential_value, credential_ciphertext FROM admin_billing_providers WHERE provider_key = $1`, "manual-main").Scan(&valueColumn, &ciphertext); err != nil {
		t.Fatalf("read provider secret columns: %v", err)
	}
	if valueColumn != "" || bytes.Contains(ciphertext, []byte(secretValue)) {
		t.Fatalf("credential storage leaked plaintext: value=%q ciphertext=%q", valueColumn, string(ciphertext))
	}

	repo := store.NewBillingProviderConfigRepository()
	var enabled []store.BillingProviderConfig
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		enabled, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ProviderKey != "manual-main" || !enabled[0].DryRun {
		t.Fatalf("runtime providers = %+v", enabled)
	}

	result, err := svc.TestBillingProvider(ctx, "manual-main", store.BillingProviderTestInput{FakeCounterCount: 2}, auditCtx)
	if err != nil {
		t.Fatalf("TestBillingProvider: %v", err)
	}
	if result.Status != "ok" || result.FakeCounterCount != 2 {
		t.Fatalf("test result = %+v", result)
	}

	_, err = svc.UpsertBillingProvider(ctx, "manual-main", store.UpsertBillingProviderInput{
		ProviderType:               store.BillingProviderTypeManual,
		DisplayName:                "Manual exports",
		ExportCadenceSeconds:       86400,
		RetryMaxAttempts:           5,
		RetryInitialBackoffSeconds: 60,
		Enabled:                    false,
	}, auditCtx)
	if err != nil {
		t.Fatalf("disable provider by upsert: %v", err)
	}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		enabled, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled after disable: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("disabled provider remained in runtime list: %+v", enabled)
	}

	var events []store.AuditEvent
	err = s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		events, err = store.NewAuditRepository().ListByOrganization(ctx, q, actorOrg.ID, 10)
		return err
	})
	if err != nil {
		t.Fatalf("List audit events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("audit event count = %d, want 3: %+v", len(events), events)
	}
	testutil.AssertRedactedValue(t, events[0].Reason, secretValue)
	testutil.AssertRedactedValue(t, events[0].Metadata["reason"], secretValue)
}

func TestBillingProviderRepositoryValidationAndStripePlaceholder(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	repo := store.NewBillingProviderConfigRepository()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, "bad key!", store.UpsertBillingProviderInput{
			ProviderType: store.BillingProviderTypeStripe,
			Enabled:      true,
		}, store.BillingProviderCredential{})
		return err
	}); err == nil {
		t.Fatal("invalid provider key was accepted")
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, "stripe_main", store.UpsertBillingProviderInput{
			ProviderType:               store.BillingProviderTypeStripe,
			DisplayName:                "Stripe dry run",
			SecretReference:            "vault/billing/stripe",
			ExportCadenceSeconds:       3600,
			RetryMaxAttempts:           3,
			RetryInitialBackoffSeconds: 30,
			DryRun:                     true,
			Enabled:                    true,
		}, store.BillingProviderCredential{})
		return err
	}); err != nil {
		t.Fatalf("stripe placeholder upsert: %v", err)
	}
}

func newAdminBillingProviderServiceForTest(t *testing.T, s *store.Store) *store.AdminBillingProviderService {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	provider, err := secrets.NewAESGCM([][]byte{key})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	svc, err := store.NewAdminBillingProviderService(s, store.NewOrganizationRepository(), store.NewBillingProviderConfigRepository(), store.NewAuditRepository(), provider)
	if err != nil {
		t.Fatalf("NewAdminBillingProviderService: %v", err)
	}
	return svc
}
