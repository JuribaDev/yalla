package billing_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/billing"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

func TestBatchFromStoreExportIsProviderNeutral(t *testing.T) {
	t.Parallel()
	export := store.BillingExport{
		ID:             "bexp_test",
		OrganizationID: "org_test",
		SubscriptionID: "sub_test",
		Provider:       "stripe_main",
		PeriodStart:    time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:      time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Items: []store.BillingExportItem{
			{CounterID: "ucnt_1", Key: "http_requests", Unit: "request", Quantity: 42, Source: "traefik"},
			{CounterID: "ucnt_2", Key: "build_minutes", Unit: "minute", Quantity: 7.5, Source: "yalla_jobs"},
		},
	}

	batch := billing.BatchFromStoreExport(export)
	if batch.ExportID != export.ID || batch.OrganizationID != export.OrganizationID || batch.SubscriptionID != export.SubscriptionID {
		t.Fatalf("batch scope = %+v, want export scope", batch)
	}
	if batch.Provider != "stripe_main" {
		t.Fatalf("batch provider = %q, want stripe_main", batch.Provider)
	}
	if len(batch.Items) != 2 {
		t.Fatalf("batch items = %d, want 2", len(batch.Items))
	}
	if batch.Items[0].CounterID != "ucnt_1" || batch.Items[0].Key != "http_requests" || batch.Items[0].Quantity != 42 {
		t.Fatalf("first batch item = %+v, want http_requests snapshot", batch.Items[0])
	}
}

func TestProviderInterfaceAcceptsManualAdapter(t *testing.T) {
	t.Parallel()
	provider := billing.ProviderFunc(func(context.Context, billing.ExportBatch) (billing.ProviderResponse, error) {
		return billing.ProviderResponse{ProviderResponseID: "manual-export-1"}, nil
	})

	response, err := provider.ExportUsage(context.Background(), billing.ExportBatch{ExportID: "bexp_test"})
	if err != nil {
		t.Fatalf("ExportUsage returned %v", err)
	}
	if response.ProviderResponseID != "manual-export-1" {
		t.Fatalf("ProviderResponseID = %q, want manual-export-1", response.ProviderResponseID)
	}
}
