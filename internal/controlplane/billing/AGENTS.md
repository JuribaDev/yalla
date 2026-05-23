# internal/controlplane/billing

Provider-facing billing code lives here. Keep this package provider-neutral:

- Core metering and quota write `usage_events` / `usage_counters`; billing
  providers consume immutable `store.BillingExport` snapshots through
  `ExportBatch`.
- Provider adapters should consume overage metadata from `ExportItem`
  (`entitlement_key`, `overage_policy_mode`, `overage_decision`,
  `included_quantity`, `overage_quantity`) rather than re-reading quota or
  entitlement state; the export snapshot is the retry-stable billing basis.
- Provider adapters must store only safe remote response identifiers through
  `store.BillingExportRepository`; never store provider API keys, webhook
  secrets, request tokens, raw headers, or full provider payloads.
- Failed provider attempts should be recorded on `billing_exports` with
  redacted summaries and retry timing. They must not block quota enforcement or
  mutate usage counters.
