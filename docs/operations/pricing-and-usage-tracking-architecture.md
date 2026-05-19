# Pricing and Usage Tracking Architecture

This runbook explains how Yalla Control Plane handles pricing, entitlements,
metering, and billing counters. It covers the versioned backend binaries
`/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`, the Customer /
Agent / CI traffic boundary, Postgres source of truth, Provisioning worker,
PostgreSQL, and the private Dokploy API dependency. Customer / Agent / CI
traffic must flow through Yalla; customers must never receive Dokploy API
tokens or call Dokploy directly.

## Why Dokploy monitoring is not the billing source of truth

Dokploy exposes application metrics, container metrics, and server metrics
through its private API. Yalla reads those operational signals for health and
provisioning diagnostics, but they are **not** the billing source of truth.

The billing source of truth is Yalla's own append-only `usage_events` and
periodic `usage_counters` tables. This design guarantees:

- **Tenant isolation.** Dokploy metrics are infrastructure-scoped; Yalla usage
counters are organization-scoped and verified through tenant-scoped
`dokploy_refs` attribution.
- **Deterministic replay.** `usage_events` are append-only and idempotent by
`(organization_id, source, idempotency_key)`. Counters can be replayed from
events without re-querying Dokploy.
- **Auditable corrections.** Corrections are new `adjusted` rows, never updates
to closed periods.
- **Provider neutrality.** Billing exports are provider-neutral snapshots over
`usage_counters`. Stripe, manual invoicing, or future adapters consume the same
`billing.ExportBatch` contract.
- **Defense in depth.** A compromised or unavailable Dokploy monitoring endpoint
cannot silently corrupt billing data. Yalla degrades optional monitoring sources
with stable error codes while preserving its own usage pipeline.

```text
Customer traffic -> Traefik -> Dokploy service
                       |
                       v
                Prometheus metrics (operational input only)
                       |
                       v
           Yalla metering source adapters (normalize + checksum)
                       |
                       v
           Attribution layer (dokploy_refs -> org/project/env/service)
                       |
                       v
           Append-only usage_events + usage_counters (billing source of truth)
                       |
                       v
           Billing export snapshots -> provider adapters
```

## Entitlement resolution

Runtime entitlements are resolved by `internal/controlplane/entitlements.Resolver`
from the pricing catalog, accepted subscriptions, and overrides.

Resolution precedence (newest active `effective_from`, then `created_at`, then
`id` as tie-breaker):

1. Plan defaults from the accepted plan version.
2. Subscription-scoped overrides (`subscription_override`).
3. Organization-level emergency admin overrides (`emergency_admin`).

Canceled or out-of-period subscriptions contribute no runtime entitlements.
The resolver caches snapshots by `(organization_id, instant)` and validates the
cache through `SubscriptionRepository.EntitlementRevision` so plan, subscription,
or override changes invalidate stale entries without a process restart.

Quota code should construct `quota.Checker` with
`quota.WithEntitlementResolver(resolver)` and keep legacy `quota_policies` as a
fallback for dimensions with no entitlement key yet.

## Metering pipeline

The metering pipeline lives under `internal/controlplane/metering` and follows
a source/attribution/emission split:

1. **Source adapters** normalize bounded windows into deterministic samples:
   - `metering.TraefikUsageEmitter` for Traefik metrics.
   - `metering.ContainerUsageEmitter` for container metrics.
   - `metering.CurrentStateUsageEmitter` for current-state resource counts.
   - `metering.DeploymentUsageEmitter` for deployment counts.
   - `metering.BackupUsageEmitter` for backup storage.
2. **Attribution** resolves `dokploy_refs` to full
   `org_id -> project_id -> environment_id -> service_id` scope. Ambiguous or
deleted services are quarantined before billing.
3. **Emission** writes only fully attributed, billing-grade samples to
   append-only `usage_events` through `store.UsageEventRepository.Append`.

### Traefik metrics attribution

Traefik metric labels carry service identifiers such as `svc_456`. The
attribution layer resolves these through `dokploy_refs` where
`yalla_kind='service'` and `yalla_id=svc_456`. Samples that cannot be resolved
to a full tenant scope are quarantined and never become billing-grade
`usage_events` automatically.

```text
Traefik metric label: service=yalla-svc_456
         |
         v
   dokploy_refs (yalla_kind=service, yalla_id=svc_456)
         |
         v
   service_id -> environment_id -> project_id -> org_id
         |
         v
   org-scoped usage counter
```

### Usage aggregation

`UsageCounterRepository.AggregateUsageEvents` replays append-only `usage_events`
into deterministic billing-period counters:

- Open periods upsert counters by
  `(organization_id, key, unit, period_start, period_end, source)`.
- Closed periods keep frozen quantities and record late-arriving usage in
  `usage_counter_adjustments` so replays are idempotent and invoice corrections
  stay auditable.

Metered overage hooks run at the usage-counter aggregation boundary, not inside
quota/resource mutation code. `AggregateUsageEvents` stamps counters with
`entitlement_key`, `overage_policy_mode`, `overage_decision`,
included/overage quantities, and an audit event.

## Hard-limit, soft-limit, and metered usage keys

The closed `metering.MetricDefinition` set defines the runtime metric contract.
Each key carries an enforcement mode and a billing-grade flag.

### Hard-limit keys

Hard-limit keys reject usage above the configured limit and are backed by
`quota.Checker` against current `usage_counters` plus active reservations.

| Key | Unit | Source |
| --- | --- | --- |
| `active_services` | service | current_state |
| `active_databases` | database | current_state |
| `active_domains` | domain | current_state |

### Soft-limit keys

Soft-limit keys record warning-grade usage without rejection. They emit
structured `yalla.output.v1.warnings` through `apienvelope.WriteDataWithWarnings`
when the threshold is crossed.

| Key | Unit | Source |
| --- | --- | --- |
| `http_rps_peak_1m` | requests_per_second | traefik |

### Metered keys

Metered keys record billing-grade usage without a hard ceiling. They feed
`usage_events` and `usage_counters` for billing export.

| Key | Unit | Source |
| --- | --- | --- |
| `http_requests` | request | traefik |
| `http_response_bytes` | byte | traefik |
| `http_request_bytes` | byte | traefik |
| `http_bandwidth_total` | byte | traefik |
| `container_cpu_millicore_seconds` | millicore_second | dokploy_or_cadvisor |
| `container_memory_mb_hours` | mb_hour | dokploy_or_cadvisor |
| `storage_gb_month` | gb_month | volume_scanner |
| `backup_storage_gb_month` | gb_month | backup_metadata |
| `build_minutes` | minute | build_pipeline |
| `deployments` | deployment | deployment_events |

### Observability-only keys

Observability-only keys are non-billing operational signals.

| Key | Unit | Source |
| --- | --- | --- |
| `http_5xx_count` | response | traefik |
| `latency_p95_ms` | millisecond | traefik |

Adding a new billing-grade metric requires four coordinated changes:
1. Add a `metering.MetricDefinition` to the closed `metricDefinitions` map.
2. Add a `quota_resource` migration and `store.QuotaResource` constant when the
   key is invoiceable.
3. Build an idempotent emitter that writes only fully attributed samples into
   `usage_events`.
4. Add a customer usage projection from current-period `usage_counters`.

## Data model

The pricing and usage data model pivots on these source-of-truth tables:

- `plans`: versioned global plan catalog with immutable accepted versions.
- `plan_entitlements`: per-plan entitlement defaults.
- `subscriptions`: accepted organization subscriptions with current period bounds.
- `subscription_entitlements`: subscription-scoped entitlement overrides.
- `usage_events`: append-only billing-grade events.
- `usage_counters`: deterministic billing-period aggregations.
- `usage_counter_adjustments`: late-arriving corrections for closed periods.
- `billing_exports`: provider-neutral export snapshots.
- `billing_export_items`: immutable provider-neutral line items.
- `admin_overage_policies`: runtime overage behavior by effective time.
- `admin_metric_definitions`: versioned global metric definitions.
- `admin_metering_sources`: runtime metering source configuration.
- `admin_attribution_rules`: global runtime attribution contracts.
- `admin_usage_aggregation_schedules`: per-source metric aggregation cadence.

## Stable outputs

All public HTTP responses above pricing and usage code use stable JSON envelopes:

```yaml
schema_version: yalla.output.v1
ok: true
request_id: req_example
data:
  usage_counters:
    - key: http_requests
      quantity: 12345
```

Errors use the stable error envelope:

```yaml
schema_version: yalla.error.v1
ok: false
request_id: req_example
error:
  code: E_QUOTA_EXCEEDED
  message: quota exceeded
```

## Required environment variables

Most pricing and usage unit tests use fakes and need no external services.
Persistence and integration tests require an isolated local Postgres base DSN:

```bash
export YALLA_POSTGRES_PASSWORD=<redacted:postgres-password>
docker compose up -d postgres
docker compose ps postgres
export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>
```

expected output: the `postgres` service reports a healthy status, and Go test
packages with runnable tests end in `ok`. When the database variable is not
configured, expected output includes
`YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test`.

Live Dokploy credentials are not required for pricing and usage work. The only
allowed live smoke remains explicit and external:

```bash
YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...
```

That command must never run against production.

## Verification commands

Run focused metering and billing checks while developing:

```bash
go test ./internal/controlplane/metering/...
go test ./internal/controlplane/billing/...
go test ./internal/controlplane/entitlements/...
go test ./internal/controlplane/quota/...
go test ./internal/controlplane/store/...
go test -run TestQuotaConcurrency ./...
go test -run TestTenantIsolation ./...
```

Run the full required pre-commit gate before marking a pricing or usage story
complete:

```bash
gofmt -w .
goimports -w .
go mod tidy
go test ./...
go test -race ./...
go vet ./...
scripts/verify.sh
```

The release gate for this document is:

```bash
go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact
```

If `goimports` is not installed, document that in `ralph/progress.txt` and keep
the remaining checks explicit.

Unit tests cover success, validation failure, authorization failure, and not-found behavior.
Integration tests run against isolated Postgres migrations and never require a live Dokploy server unless explicitly marked external.
Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted in logs, errors, audit metadata, and test output.

## Test coverage expectations

Pricing and usage changes should include the coverage that matches their blast
radius:

- Unit tests for entitlement resolution: plan defaults, subscription overrides,
  emergency admin overrides, cache invalidation, and expiration logic.
- Unit tests for metric definitions: closed-set lookups, enforcement modes, and
  billing-grade flags.
- Repository integration tests using `testutil.RequireMigratedDB` for
  migration-backed reads, writes, rollback, and tenant isolation.
- Quota concurrency tests for hard-limit rejection when multiple transactions
  reserve the same tenant and resource at once.
- HTTP contract tests for stable status, envelope, `request_id`, authorization
  failure, not-found behavior, quota failure, and redaction.
- Fake Dokploy worker tests when the protected path enqueues provisioning;
  metering itself must not depend on live Dokploy.
- fake Dokploy fixtures are the default for all metering and billing tests.
- Normal verification gates must never require a live Dokploy server.

## Safety rules

- Do not expose raw Dokploy operations.
- Do not call Dokploy from quota code.
- Do not use Dokploy monitoring as the billing source of truth.
- Do not emit billing-grade `usage_events` for unattributed or quarantined
  samples.
- Do not bypass auth, scoped grants, idempotency, or audit on a mutating path.
- Every customer-data query must be tenant-scoped by `organization_id` or a
  verified parent join.
- Do not build SQL dynamically from caller-supplied metric keys or entitlement
  dimensions.
- Do not print SQL bind values, DSNs, request bodies, tokens, cookies, API keys,
  rendered environment variable values, or secret metadata in errors, logs,
  audit payloads, dry-run output, or test output.
- Do not print database URLs in errors, logs, audit metadata, or test output.
- Dashboard config, screenshots, incident notes, tickets, audit metadata, dry-run
  output, and log excerpts must not print database URLs.
- Dashboard evidence must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values.
- Do not disclose whether cross-tenant IDs exist.
- Do not add a billing-grade metric without updating the migration, Go constant,
  membership map, emitter, usage projection, and focused tests.

## Failure recovery

If Postgres is unavailable:

```bash
docker compose logs postgres
docker compose ps postgres
docker compose down
docker compose up -d postgres
```

Fix the local dependency first. Use `docker compose down` only for the local
dependency stack, then restart Postgres. Do not point pricing or usage tests at
production, staging, or any shared database.

If tests are returning stale results:

```bash
go clean -testcache
go test ./internal/controlplane/metering/...
go test ./internal/controlplane/entitlements/...
```

If a usage aggregation test fails, inspect the `AggregateUsageEvents`
transaction first. The aggregation must be idempotent across replays and must
record late-arriving usage in `usage_counter_adjustments` for closed periods.

If migration-backed tests fail after changing metric dimensions or entitlement
keys, rerun:

```bash
go test -run TestMigrations ./...
go test ./internal/controlplane/store/...
```

If a pricing error, audit metadata payload, dry-run output, or test log contains
secret-shaped data, stop the run, rotate the local value if needed, add or fix
a redaction test, and remove the output before committing.

## Change log

| Date       | Change                                                        | Owner              |
|------------|---------------------------------------------------------------|--------------------|
| 2026-05-19 | Initial pricing and usage tracking architecture doc (BE-0582).| Backend Operations |
