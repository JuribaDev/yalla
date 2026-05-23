// Package billing defines provider-neutral billing export contracts.
package billing

import (
	"context"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Provider exports one immutable usage batch to a billing system. Implementors
// adapt this small contract to Stripe, manual invoicing, or another provider
// without letting provider SDK details leak into core metering.
type Provider interface {
	ExportUsage(context.Context, ExportBatch) (ProviderResponse, error)
}

// ProviderFunc adapts a function to Provider for tests and simple providers.
type ProviderFunc func(context.Context, ExportBatch) (ProviderResponse, error)

// ExportUsage calls f(ctx, batch).
func (f ProviderFunc) ExportUsage(ctx context.Context, batch ExportBatch) (ProviderResponse, error) {
	return f(ctx, batch)
}

// ProviderResponse is the safe provider acknowledgement stored on a durable
// billing export. It must contain remote object identifiers only, never
// provider credentials or request secrets.
type ProviderResponse struct {
	ProviderResponseID string
}

// ExportBatch is the provider-neutral usage snapshot for one organization,
// subscription, billing period, and provider.
type ExportBatch struct {
	ExportID       string
	OrganizationID string
	SubscriptionID string
	Provider       string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	Items          []ExportItem
}

// ExportItem is one usage-counter line in a provider-neutral batch.
type ExportItem struct {
	CounterID         string
	Key               string
	Unit              string
	Quantity          float64
	Source            string
	EntitlementKey    *string
	OveragePolicyMode *string
	OverageDecision   *string
	IncludedQuantity  *float64
	OverageQuantity   *float64
}

// BatchFromStoreExport projects the durable store snapshot into the provider
// boundary. The projection deliberately carries no provider credentials.
func BatchFromStoreExport(export store.BillingExport) ExportBatch {
	items := make([]ExportItem, 0, len(export.Items))
	for _, item := range export.Items {
		items = append(items, ExportItem{
			CounterID:         item.CounterID,
			Key:               item.Key,
			Unit:              item.Unit,
			Quantity:          item.Quantity,
			Source:            item.Source,
			EntitlementKey:    item.EntitlementKey,
			OveragePolicyMode: item.OveragePolicyMode,
			OverageDecision:   item.OverageDecision,
			IncludedQuantity:  item.IncludedQuantity,
			OverageQuantity:   item.OverageQuantity,
		})
	}
	return ExportBatch{
		ExportID:       export.ID,
		OrganizationID: export.OrganizationID,
		SubscriptionID: export.SubscriptionID,
		Provider:       export.Provider,
		PeriodStart:    export.PeriodStart,
		PeriodEnd:      export.PeriodEnd,
		Items:          items,
	}
}
