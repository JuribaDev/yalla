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
	"github.com/JuribaDev/yalla/internal/output"
)

func TestAdminMeteringSourceServiceUpsertEncryptsCredentialAndAudits(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminMeteringSourceActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminMeteringSourceServiceForTest(t, s)
	auditCtx := store.AdminMeteringSourceAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_metering",
		ActorKind:     "user",
		RequestID:     "req_admin_metering_store",
		CorrelationID: "corr_admin_metering_store",
		Reason:        "rotate bearer token=super-secret-token",
	}
	secretValue := "super-secret-token"

	source, err := svc.UpsertMeteringSource(ctx, "prometheus-main", store.UpsertMeteringSourceInput{
		SourceType:            store.MeteringSourceTypePrometheus,
		EndpointURL:           "https://metrics.internal.example",
		AuthScheme:            "bearer",
		AuthReference:         "vault/prometheus/main",
		CredentialValue:       &secretValue,
		ScrapeIntervalSeconds: 60,
		QueryIntervalSeconds:  300,
		TimeoutSeconds:        10,
		Labels:                map[string]string{"cluster": "prod"},
		Enabled:               true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertMeteringSource: %v", err)
	}
	if !source.CredentialSet || source.SecretProvider == "" || source.SecretKeyID == "" || len(source.SecretCiphertext) == 0 {
		t.Fatalf("source credential tuple not sealed: %+v", source)
	}
	if bytes.Contains(source.SecretCiphertext, []byte(secretValue)) {
		t.Fatalf("ciphertext contains plaintext credential")
	}

	var valueColumn string
	var ciphertext []byte
	if err := db.QueryRow(ctx, `SELECT credential_value, credential_ciphertext FROM admin_metering_sources WHERE source_key = $1`, "prometheus-main").Scan(&valueColumn, &ciphertext); err != nil {
		t.Fatalf("read source secret columns: %v", err)
	}
	if valueColumn != "" || bytes.Contains(ciphertext, []byte(secretValue)) {
		t.Fatalf("credential storage leaked plaintext: value=%q ciphertext=%q", valueColumn, string(ciphertext))
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
	if len(events) != 1 || events[0].Action != "admin.metering_source.upsert" || events[0].RequestID != auditCtx.RequestID {
		t.Fatalf("audit events = %+v", events)
	}
	testutil.AssertRedactedValue(t, events[0].Reason, secretValue)
	testutil.AssertRedactedValue(t, events[0].Metadata["reason"], secretValue)
}

func TestAdminMeteringSourceRepositoryRuntimeListAndDisable(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminMeteringSourceRuntimeActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminMeteringSourceServiceForTest(t, s)
	auditCtx := store.AdminMeteringSourceAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_metering",
		ActorKind:     "user",
		RequestID:     "req_admin_metering_runtime",
		CorrelationID: "corr_admin_metering_runtime",
		Reason:        "runtime reload test",
	}
	secretValue := "first-token"
	if _, err := svc.UpsertMeteringSource(ctx, "prometheus-main", store.UpsertMeteringSourceInput{
		SourceType:            store.MeteringSourceTypePrometheus,
		EndpointURL:           "https://metrics.internal.example",
		AuthScheme:            "bearer",
		CredentialValue:       &secretValue,
		ScrapeIntervalSeconds: 60,
		QueryIntervalSeconds:  300,
		TimeoutSeconds:        10,
		Enabled:               true,
	}, auditCtx); err != nil {
		t.Fatalf("Upsert enabled: %v", err)
	}

	repo := store.NewMeteringSourceRepository()
	var enabled []store.MeteringSource
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		enabled, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled: %v", err)
	}
	if len(enabled) != 1 || enabled[0].SourceKey != "prometheus-main" || !enabled[0].CredentialSet {
		t.Fatalf("enabled = %+v", enabled)
	}

	if _, err := svc.UpsertMeteringSource(ctx, "prometheus-main", store.UpsertMeteringSourceInput{
		SourceType:            store.MeteringSourceTypePrometheus,
		EndpointURL:           "https://metrics.internal.example",
		AuthScheme:            "bearer",
		ScrapeIntervalSeconds: 60,
		QueryIntervalSeconds:  300,
		TimeoutSeconds:        10,
		Enabled:               false,
	}, auditCtx); err != nil {
		t.Fatalf("Upsert disabled: %v", err)
	}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		enabled, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled after disable: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("disabled source remained in runtime list: %+v", enabled)
	}
}

func newAdminMeteringSourceServiceForTest(t *testing.T, s *store.Store) *store.AdminMeteringSourceService {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	provider, err := secrets.NewAESGCM([][]byte{key})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	svc, err := store.NewAdminMeteringSourceService(s, store.NewOrganizationRepository(), store.NewMeteringSourceRepository(), store.NewAuditRepository(), provider)
	if err != nil {
		t.Fatalf("NewAdminMeteringSourceService: %v", err)
	}
	if output.Sentinel == "" {
		t.Fatal("redaction sentinel must be non-empty")
	}
	return svc
}
