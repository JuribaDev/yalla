# Contributing to Yalla

Yalla is a CLI for AI agents, so the bar for predictability is
unusually high: every flag, exit code, JSON envelope, and error code
is part of a public contract. This document tells you the minimum you
need to satisfy before opening a pull request.

## TL;DR

```bash
# From the repo root.
scripts/verify.sh
```

If `scripts/verify.sh` exits 0 you are good to push. If it reports an
optional tool as missing, install it or document the skip in
`ralph/progress.txt` — the project policy is **never silently skip a
check**.

To install the repository pre-commit hook:

```bash
scripts/install-hooks.sh
```

The hook runs `scripts/verify.sh --strict --release`, which mirrors the
CI test, security, lint, and release dry-run gates before Git creates a
commit.

## Required Checks Before Every Commit

These are non-negotiable. CI runs them on every push and pull request,
and they must all pass on every commit you propose:

1. `gofmt -w .`
2. `go mod tidy`
3. `go vet ./...`
4. `go test ./...`
5. `go test -race ./...`
6. `go test ./internal/controlplane/store/...`
7. `go test ./internal/controlplane/httpapi/...`
8. `go test ./internal/controlplane/openapi/...`
9. `go test -run TestPolicyMatrix ./...`
10. `go test -run TestQuotaConcurrency ./...`
11. `go test -run TestJobWorkerLease ./...`
12. `go test -run TestFakeDokploy ./...`
13. `go test -run TestRedaction ./...`
14. `go test -run TestFuzzValidator ./...`
15. `go test -run TestMigrationsEmptyDB ./...`
16. `go test -run TestMigrationsDowngradeSafety ./...`
17. `go test -run TestLoadSmoke ./...`
18. `go test -run TestChaosDokployTimeouts ./...`
19. `go test -run TestChaosPostgresDisconnects ./...`
20. `go test -run TestIdempotencyReplay ./...`
21. `go test -run TestAuditCompleteness ./...`
22. `go test -run TestPaginationStability ./...`
23. `go test -run TestTenantIsolation ./...`
24. `go test -run TestBackupRestoreRehearsal ./...`
25. `go test -run TestReleaseBuild ./...`
26. `go test -run TestConfigValidation ./...`
27. `go test -run TestAdminEndpoint ./...`
28. `go test -run TestBreakGlass ./...`
29. `go test -run TestReconciliation ./...`
30. `go test -run TestImportDryRun ./...`
31. `go test -run TestServiceDesiredState ./...`
32. `go test -run TestDeploymentLifecycleE2E ./...`

`scripts/verify.sh` runs the full set in one command and is the local
mirror of the `test` job in `.github/workflows/ci.yml`. Step 6 — the
repository integration suite under `internal/controlplane/store/...` —
is the persistence-layer gate documented in BE-0380; even though
`go test ./...` covers the same packages, the dedicated invocation is
defence-in-depth and surfaces a faster, more targeted failure if any
repository-layer regression slips in. Step 7 — the HTTP handler
contract suite under `internal/controlplane/httpapi/...` — is the
wire-contract gate documented in BE-0381; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the contract gate firing as a
fast, targeted failure rather than buried inside the umbrella log.
Step 8 — the OpenAPI schema conformance suite under
`internal/controlplane/openapi/...` — is the published-document gate
documented in BE-0382; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the OpenAPI conformance gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. Step 9 — the policy matrix suite bound by the
`-run TestPolicyMatrix` filter — is the RBAC + cross-tenant gate
documented in BE-0383; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the matrix gate firing as a
fast, targeted failure rather than buried inside the umbrella log.
Step 10 — the quota concurrency suite bound by the
`-run TestQuotaConcurrency` filter — is the hard-limit + cross-tenant
concurrency gate documented in BE-0384; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the concurrency gate firing as
a fast, targeted failure rather than buried inside the umbrella log.
Step 11 — the job worker lease suite bound by the
`-run TestJobWorkerLease` filter — is the exclusivity +
shutdown-safety gate documented in BE-0385; the dedicated invocation
is defence-in-depth on the same principle so a narrowing of the
umbrella `go test ./...` step would still leave the lease gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. Step 12 — the fake Dokploy contract suite bound by
the `-run TestFakeDokploy` filter — is the deterministic-fixtures +
recorder-redaction gate documented in BE-0386; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the
fake-Dokploy gate firing as a fast, targeted failure rather than
buried inside the umbrella log. Step 13 — the redaction suite bound
by the `-run TestRedaction` filter — is the
secrets-never-leak-into-logs gate documented in BE-0387; the
dedicated invocation is defence-in-depth on the same principle so a
narrowing of the umbrella `go test ./...` step would still leave the
redaction gate firing as a fast, targeted failure rather than buried
inside the umbrella log. The filter binds across every package whose
tests assert the redaction contract — the central `Redactor` in
`internal/output`, the per-tenant variable redaction in
`internal/controlplane/variables`, and the CLI envelope and dry-run
redaction in `internal/cli` — so a regression in any one of them
trips the dedicated step before it can ship under the umbrella log.
Step 14 — the fuzz validator suite bound by the
`-run TestFuzzValidator` filter — is the
hostile-input-never-panics-or-leaks gate documented in BE-0388; the
dedicated invocation is defence-in-depth on the same principle so a
narrowing of the umbrella `go test ./...` step would still leave the
fuzz gate firing as a fast, targeted failure rather than buried
inside the umbrella log. The canonical pair
(`TestFuzzValidatorContractCoversExpectedValidators` and
`TestFuzzValidatorContractSeedCorpusRejectsHostileInputs`) lives in
`internal/controlplane/validate/fuzz_test.go` next to the `FuzzName`
/ `FuzzPath` / `FuzzDomain` / `FuzzEnvVarName` / `FuzzEnvVarValue` /
`FuzzDecodeJSON` / `FuzzImageRef` / `FuzzURL` / `FuzzGitBranch`
targets it pins; the wrapper drives every validator through the
shared hostile seed corpus (long strings, invalid UTF-8, traversal
sequences, embedded NUL, control characters, Unicode tricks) under
a `recover()` guard so a regression surfaces with the offending
validator AND the seed index. The optional randomised driver
remains available as `go test -fuzz=Fuzz<Name>
./internal/controlplane/validate/...` for soak runs.
Step 15 — the migrations-from-empty-DB suite bound by the
`-run TestMigrationsEmptyDB` filter — is the empty-database
bootstrap gate documented in BE-0389; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the
umbrella `go test ./...` step would still leave the migration-runner
gate firing as a fast, targeted failure rather than buried inside
the umbrella log. The canonical pair
(`TestMigrationsEmptyDBContractCoversAllNumberedFiles` and
`TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`)
lives in `internal/controlplane/store/migrate/migrate_test.go`. The
first member pins the closed-set coverage invariant — every
`NNNN_*.up.sql` file in the embedded migrations directory MUST
surface as a loaded `Migration`, strictly ascending and gap-free
from version 1 — and runs without a Postgres dependency so a
new-file-missing-from-the-loader regression trips on every
developer machine. The second member pins the applies-cleanly
invariant — a throwaway database accepts the embedded ladder in
order, the `schema_migrations` ledger ends with one clean row per
migration (correct checksum, dirty=false), and a second `Up` is a
no-op — and skips cleanly when `YALLA_TEST_DATABASE_URL` is unset
so the suite stays green on machines without Postgres. Failures
surface with the offending migration version AND the resource_id
(`schema_migrations.version=N`) so an operator can map the failure
to the exact migration without re-running the suite locally.

Step 17 — the load smoke suite bound by the `-run TestLoadSmoke`
filter — is the bootstrap-surface burst-stability gate documented in
BE-0392; the dedicated invocation is defence-in-depth on the same
principle so a narrowing of the umbrella `go test ./...` step would
still leave the burst gate firing as a fast, targeted failure rather
than buried inside the umbrella log. The canonical pair
(`TestLoadSmokeContractCoversCoreEndpoints` and
`TestLoadSmokeContractRunsBurstWithStableEnvelopes`) lives in
`internal/controlplane/httpapi/load_smoke_test.go`. The first member
pins the closed-set bootstrap-coverage invariant — the endpoint
table the burst harness iterates MUST stay non-empty, free of
duplicates, scoped to the bootstrap surface (`/healthz`, `/readyz`,
`/version`, nothing under `/v1/`), and every entry MUST carry a
valid HTTP method — and runs without any infrastructure dependency
so a typo or scope-creep regression trips on every developer
machine. The second member pins the burst-stability invariant — the
in-process public HTTP handler accepts
`loadSmokeWorkers * loadSmokeIterationsPerWorker` concurrent
requests per endpoint and every response carries the canonical
status, a stable `yalla.output.v1` envelope with ok=true, a
SafeID-clean `request_id` unique across the whole burst, and no
secret-shaped substring in body or header. Failures surface with
the offending endpoint AND the observed request_id so an operator
can correlate the gate failure with a specific in-flight request
without re-running the suite locally. Both members are
deterministic by design: the bootstrap surface is the one part of
the API that needs no backing infrastructure, so the load smoke
gate stays green on every machine without Postgres or a live
Dokploy server.

Step 18 — the chaos-timeout suite bound by the
`-run TestChaosDokployTimeouts` filter — is the typed-Dokploy-client
chaos-classification gate documented in BE-0393; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the chaos gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestChaosDokployTimeoutsCoversCallSites` and
`TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`) lives in
`internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go`. The
first member pins the closed-set chaos-scenario coverage invariant —
the scenario table the burst harness iterates MUST stay non-empty,
free of duplicate names, scoped to the typed client surface (GET,
POST, DELETE) and to the idempotency rule (POST attempted exactly
once; GET and DELETE attempted 1 + MaxRetries), and every entry MUST
map to `yerr.CodeTimeout` attributed to `apierr.DependencyDokploy` —
and runs without any infrastructure dependency so a typo or
classification-regression trips on every developer machine. The
second member pins the runtime chaos invariant — the typed Dokploy
client spun up against a per-iteration fake-Dokploy server and
firing `chaosWorkers * chaosIterationsPerWorker` concurrent scenario
invocations MUST yield only failures that are typed `*yerr.Error`
values with `Code=yerr.CodeTimeout`, attribute to
`apierr.DependencyDokploy`, carry the caller's
`telemetry.HeaderRequestID` into every recorded attempt, leave every
recorded Authorization header redacted to `output.Sentinel`, and
carry no Dokploy bearer-token literal in any wrapped cause. Failures
surface with the offending scenario name AND the observed request_id
so an operator can correlate the gate failure with a specific
in-flight chaos run without re-running the suite locally. Both
members are deterministic by design: the in-process fake-Dokploy is
the only dependency the chaos harness needs, the `TimeoutFault`
primitive honours `r.Context().Done()` so each per-attempt deadline
cancels the in-flight request, and the gate stays green on every
machine without Postgres or a live Dokploy server.

Step 19 — the chaos-disconnect suite bound by the
`-run TestChaosPostgresDisconnects` filter — is the store-layer
chaos-classification gate documented in BE-0394; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the chaos gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestChaosPostgresDisconnectsCoversCallSites` and
`TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`) lives in
`internal/controlplane/store/chaos_postgres_disconnects_test.go`. The
first member pins the closed-set chaos-scenario coverage invariant —
the scenario table the burst harness iterates MUST stay non-empty,
free of duplicate names, scoped to the pgxpool surface every store
method uses (`Ping`, `Acquire`, `Begin`, `Exec`, `Query`), and every
entry MUST map to `yerr.CodeUnavailable` attributed to
`apierr.DependencyStore` — and runs without any infrastructure
dependency so a typo or classification-regression trips on every
developer machine. The second member pins the runtime chaos invariant
— a fresh `pgxpool.Pool` wired against a per-iteration
`fakepg.Server` (a tiny in-process TCP listener that gracefully closes
accepted connections so pgx fails on its startup-handshake read) and
firing `chaosPostgresWorkers * chaosPostgresIterationsPerWorker`
concurrent scenario invocations MUST yield only failures that wrap
via `apierr.StoreUnavailable` into typed `*yerr.Error` values with
`Code=yerr.CodeUnavailable`, attribute to `apierr.DependencyStore`,
record at least one accepted TCP connection per attempt, leave the
wrapped envelope's rendered message free of any DSN field (neither
the sentinel password nor the sentinel username), and carry no
sentinel password literal in any wrapped cause. Failures surface with
the offending scenario name AND the observed request_id so an
operator can correlate the gate failure with a specific in-flight
chaos run without re-running the suite locally. Both members are
deterministic by design: the in-process `fakepg.Server` is the only
dependency the chaos harness needs, no live Postgres is required, the
fake closes accepted connections gracefully so pgx's dial completes
and the chaos error surfaces on the startup-handshake read, and the
gate stays green on every machine without Postgres or a live Dokploy
server.

Step 20 — the idempotency-replay suite bound by the
`-run TestIdempotencyReplay` filter — is the HTTP idempotency
middleware replay gate documented in BE-0395; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the replay
gate firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestIdempotencyReplayCoversCallSites` and
`TestIdempotencyReplayPreservesByteIdenticalEnvelope`) lives in
`internal/controlplane/httpapi/idempotency_replay_test.go`. The first
member pins the closed-set replay-coverage invariant — for every
outcome category the middleware records (a 202 `yalla.output.v1`
success envelope, a 400 `E_INVALID_INPUT` validation failure, a 403
`E_FORBIDDEN` authorization failure, a 404 `E_NOT_FOUND` not-found
failure), a second request with the same `Idempotency-Key` and the
same body MUST receive the byte-identical recorded envelope, the
same status, and an `Idempotency-Replayed: true` header without
re-invoking the wrapped handler, and a sentinel marker placed inside
the submitted request body MUST NOT leak into the recorded claim or
the replayed response. The 5xx server-failure case is deliberately
excluded from the replay closed set — the middleware releases the
claim on 5xx so a retry re-runs the handler rather than replaying an
unfinished result. The second member pins the deterministic-replay
invariant under contention — seeding a completed claim and firing
`replayWorkers * replayIterationsPerWorker` concurrent retries
against the same key MUST yield byte-identical replayed bodies,
identical statuses, the `Idempotency-Replayed: true` header on
every retry, and exactly zero handler invocations across the burst.
Both members are deterministic by design: the in-process
`fakeIdempotencyStore` is the only dependency the replay harness
needs, no live Postgres is required, and the gate stays green on
every machine without Postgres or a live Dokploy server.

Step 21 — the audit-completeness suite bound by the
`-run TestAuditCompleteness` filter — is the audit-log completeness
gate documented in BE-0396; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the audit-completeness gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestAuditCompletenessCoversCallSites` and
`TestAuditCompletenessPreservesRecordedFieldsUnderContention`) lives
in `internal/controlplane/audit/audit_completeness_test.go`. The
first member pins the closed-set audit-completeness coverage
invariant — for each canonical action surface (organization, project,
environment, service, api_keys, limits) recorded as both an allowed
and a denied decision, the recorded `store.AuditEvent` MUST carry a
non-empty `Action`, `ResourceKind`, `ResourceID`, `Decision` (allowed
or denied), `Reason`, `OrganizationID`, `ActorID`, `ActorKind`,
`RequestID`, and `CorrelationID`, every value MUST match the scenario
inputs byte-for-byte, the sensitive-shaped metadata value MUST be
replaced with `output.Sentinel` in the recorded `Metadata` map, and
the sentinel marker MUST NOT leak into any non-Metadata recorded
field (`Action`, `ResourceID`, `Reason`, `IPAddress`, `UserAgent`).
The second member pins the per-emitter field-fidelity invariant
under contention — a single shared `audit.Auditor` seeded from
`auditCompletenessWorkers * auditCompletenessIterationsPerWorker`
goroutines MUST yield exactly that many captured events, every
event's `RequestID` MUST resolve to its emitter (no drop, no
duplicate, no cross-write of one emitter's request id onto another's
recorded event), every event MUST carry the matching organization id
and a non-empty actor id, the sentinel marker MUST stay redacted on
every event, and the marker substring MUST NOT appear in any
captured event's `Action`, `Reason`, `ResourceID`, `IPAddress`, or
`UserAgent`. Failures surface with the offending scenario name (or
the worker + iteration index) AND the observed `request_id` so an
operator reading the CI log can correlate the gate failure with a
specific in-flight emission without re-running the suite locally.
Both members are deterministic by design: the in-package
`fakeRecorder` (reused from `audit_test.go`) and the file-local
`concurrentAuditRecorder` are the only dependencies the audit-
completeness harness needs, no live Postgres is required, and the
gate stays green on every machine without Postgres or a live
Dokploy server.

Step 22 — the pagination-stability suite bound by the
`-run TestPaginationStability` filter — is the list-endpoint cursor
stability gate documented in BE-0397; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the pagination-stability gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestPaginationStabilityCoversCallSites` and
`TestPaginationStabilityPreservesPagesUnderInserts`) lives in
`internal/controlplane/pagination/pagination_stability_test.go`. The
first member pins the closed-set pagination-stability coverage
invariant — for each canonical list-endpoint shape (empty set, single
row, exact page, multi-page no remainder, multi-page with trailing
partial, ascending, descending) the paged traversal MUST visit every
seeded row exactly once with no duplicates and no drops, the terminal
page's `next_cursor` MUST be empty exactly when there are no further
rows, every emitted Page MUST carry a non-nil Items slice, every
non-terminal `next_cursor` MUST decode through `DecodeCursor` with a
Sort and Direction that match the request (so a subsequent
`ParseParams` call does not silently reject the cursor as
sort/direction mismatch), the encoded cursor wire shape MUST stay
base64url-safe (no padding, no `+`, no `/`, no `=`, no whitespace),
and a cursor issued for the coverage tenant MUST yield zero rows
when applied against a cross tenant. The second member pins the
per-page stability invariant under contention — a single shared
`concurrentPaginationStore` seeded with
`paginationStabilitySeedRows` rows and burst by
`paginationStabilityWorkers * paginationStabilityIterationsPerWorker`
goroutines firing mixed insert + delete operations while a reader
paginates end-to-end MUST yield no duplicate rows across the
reader's cursor stream, every undeleted seed row observed exactly
once, no resurrection of a row already deleted from the stream, and
a deterministic terminal page. Failures surface with the offending
scenario name (or the worker + iteration index) AND the offending
row id so an operator reading the CI log can correlate the gate
failure with a specific in-flight traversal without re-running the
suite locally. Both members are deterministic by design: the
in-package `fakeStore` (declared in `page_test.go`) and the
file-local `concurrentPaginationStore` are the only dependencies
the pagination-stability harness needs, no live Postgres is
required, and the gate stays green on every machine without
Postgres or a live Dokploy server.

Step 23 — the tenant-isolation suite bound by the
`-run TestTenantIsolation` filter — is the cross-tenant authorization
gate documented in BE-0398; the dedicated invocation is
defence-in-depth on the same principle so a narrowing of the umbrella
`go test ./...` step would still leave the tenant-isolation gate
firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestTenantIsolationCoversCallSites` and
`TestTenantIsolationPreservesScopeUnderContention`) lives in
`internal/controlplane/policy/tenant_isolation_test.go`. The first
member pins the closed-set cross-tenant coverage invariant — for every
built-in role × every catalogued action × a resource whose
`Scope.OrganizationID` is the cross tenant, the engine's verdict MUST
match the engine's documented cross-tenant ordering: `CapSelf`
actions are organization-independent and always allowed
(`ReasonAllowedSelf`), the support role's `CapSupport` bridges the
tenant boundary for `CapRead` and `CapSupport` actions only
(`ReasonAllowedBySupport`), every other role on every other action
falls through to `ReasonDeniedCrossTenant`, and a scoped `Grant`
whose `Scope.OrganizationID` is the cross tenant is silently ignored
(grants never bridge tenants). The same closed set covers the
disabled-principal short-circuit (cross-tenant denial NEVER masks a
disabled-principal denial), the missing-principal short-circuit
(`ReasonDeniedNoPrincipal` precedes the cross-tenant check), and the
uncatalogued-action short-circuit (`ReasonDeniedUnknownAction`
precedes the cross-tenant check). The second member pins the
per-decision stability invariant under contention — a single shared
`policy.Engine` is hit by
`tenantIsolationWorkers * tenantIsolationIterationsPerWorker`
goroutines firing mixed-tenant `Decide(...)` tuples drawn from the
coverage table, and every goroutine asserts the verdict it observed
matches the verdict the closed-set scenario for its OWN tuple
predicts — a cross-write that swapped two goroutines' resources or
principals under the race would fail the per-iteration assertion
even when the aggregate verdict count is correct. Failures surface
with the offending tuple's role + action + tenant-pair (for the
coverage member) or the worker + iteration index AND the offending
tuple (for the burst member) so an operator reading the CI log can
correlate the gate failure with a specific decision without
re-running the suite locally. Both members are deterministic by
design: the in-process `policy.Engine` is constructed via
`NewEngine()` from the package's default action catalog, the
principals and resources are built from constant tenant IDs, and no
test reaches a live Postgres, a live Dokploy, or any external
network.

Step 24 — the backup and restore rehearsal suite bound by the
`-run TestBackupRestoreRehearsal` filter — is the
backup-and-restore-loop gate documented in BE-0399; the dedicated
invocation is defence-in-depth on the same principle so a narrowing
of the umbrella `go test ./...` step would still leave the rehearsal
gate firing as a fast, targeted failure rather than buried inside the
umbrella log. The canonical pair
(`TestBackupRestoreRehearsalCoversCallSites` and
`TestBackupRestoreRehearsalPreservesContractUnderContention`) lives
in
`internal/controlplane/backup/backup_restore_rehearsal_test.go`. The
first member pins the closed-set rehearsal coverage invariant — every
documented `backup.FileReporter` state (pristine post-restore with
`ErrNoBackupRecorded`, fresh, on-`MaxAge` boundary, stale,
zero-MaxAge opt-out, clock-skew clamp to `Age=0`, whitespace-tolerant
parse, empty file, whitespace-only file, malformed parse, secret-
seeded file with the parse error stripped of the seeded marker,
`Unconfigured()` zero-state, cancelled-context bubble-up) yields the
predicted `(Status, error)` pair, and every typed `yerr.CodeServer`
error names the status file path so an operator can correlate the
failure with the AC3 resource id without re-running the suite. The
second member pins the per-decision stability invariant under
contention — a single shared `FileReporter` per scenario is hit by
`rehearsalWorkers * rehearsalIterationsPerWorker` goroutines drawing
fixtures from the same coverage table, and every goroutine asserts
its OWN fixture's predicate; a cross-write under the race that
swapped two goroutines' fixtures would fail the per-iteration
assertion even when the aggregate pass count matched. Both members
are deterministic by design: the FileReporters are built against
`t.TempDir`-backed fixtures with injected clocks, and no test
reaches a live Postgres, a live Dokploy, or any external network.
Step 25 — the release build suite bound by the `-run TestReleaseBuild`
filter — is the release-derivation gate documented in BE-0401; the
dedicated invocation is defence-in-depth on the same principle so a
narrowing of the umbrella `go test ./...` step would still leave the
release build gate firing as a fast, targeted failure rather than
buried inside the umbrella log. The canonical pair
(`TestReleaseBuildCoversCallSites` and
`TestReleaseBuildPreservesContractUnderContention`) lives in
`internal/release/release_build_test.go`. The first member pins the
closed-set release-derivation coverage invariant — every documented
(OS, arch) coordinate in `release.SupportedTargets` yields the
predicted `ArchiveExt`, `BinaryName`, `ArchiveName`, and
`ChecksumsName` for a fixed sample version, and every documented
coordinate (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64,
windows/amd64, windows/arm64) appears exactly once with no off-list
pair slipping in; a regression in any of those projections (a renamed
target, a flipped archive extension, a dropped windows `.exe` suffix,
a checksums-template drift) trips the gate on the offending scenario
name. The second member pins the per-decision stability invariant
under contention — `releaseBuildWorkers *
releaseBuildIterationsPerWorker` goroutines derive each target's
projections from a shared slice and every goroutine asserts the
projection for its OWN target matches the predicted values; a cross-
write under the race that swapped two goroutines' scenarios would
fail the per-iteration assertion even when the aggregate pass count
matched. Both members are deterministic by design: the release
package functions are pure projections from the (OS, arch) coordinate
to a string and no test reaches the network, a live Postgres, a live
Dokploy, or the GoReleaser binary.
Step 26 — the config validation suite bound by the
`-run TestConfigValidation` filter — is the configuration-loader gate
documented in BE-0402; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella `go test ./...`
step would still leave the config-validation gate firing as a fast,
targeted failure rather than buried inside the umbrella log. The
canonical pair (`TestConfigValidationCoversCallSites` and
`TestConfigValidationPreservesContractUnderContention`) lives in
`internal/controlplane/config/config_validation_test.go`. The first
member pins the closed-set validation coverage invariant — every
documented validation rule in `config.Validate` (invalid profile,
invalid log level, invalid listen address, invalid public URL,
invalid Dokploy URL, non-postgres database scheme, short signing
key, wrong-length secret key, non-hex secret key, malformed /
too-small / too-large shutdown timeout, non-absolute backup status
file path, malformed / negative backup max age, bad feature flag
value / empty flag name, negative / out-of-range rate-limit RPS /
burst / idle TTL, malformed bool / int rate-limit overrides) and
every documented strict-profile presence check in
`config.requireStrictFields` (`YALLA_PUBLIC_URL`,
`YALLA_DATABASE_URL`, `YALLA_SIGNING_KEYS`, `YALLA_SECRET_KEYS`,
`YALLA_DOKPLOY_BASE_URL`, `YALLA_DOKPLOY_TOKEN`) yields a typed
`*yerr.Error` with `Code == CodeConfig`, an error message that names
the offending env var, and zero echo of the seeded secret marker so
a future regression that started embedding the offending value in
the error string would fail the redaction predicate before it could
ship. The second member pins the per-decision stability invariant
under contention —
`configValidationWorkers * configValidationIterationsPerWorker`
goroutines each build their own env map from the scenario table and
run `config.Load(MapLookup(env))` and every goroutine asserts the
rule its OWN scenario predicts; a cross-write under the race that
swapped two goroutines' scenarios — or a future regression that
introduced shared mutable state in the validator — would fail the
per-iteration assertion even when the aggregate pass count matched.
Both members are deterministic by design: the validator is a pure
function from the env map to a `*Config` or a typed `*yerr.Error`
value, and no test reaches the process environment, the network,
a live Postgres, a live Dokploy, or any external service.
Step 27 — the admin endpoint suite bound by the
`-run TestAdminEndpoint` filter — is the admin-authorization gate
documented in BE-0403; the dedicated invocation is defence-in-depth
on the same principle so a narrowing of the umbrella `go test ./...`
step would still leave the admin-endpoint gate firing as a fast,
targeted failure rather than buried inside the umbrella log. The
canonical pair (`TestAdminEndpointCoversCallSites` and
`TestAdminEndpointPreservesContractUnderContention`) lives in
`internal/controlplane/policy/admin_endpoint_policy_test.go`. The
first member pins the closed-set admin-endpoint coverage invariant —
every tagged-admin HTTP route (`GET /v1/admin/dokploy/drift`,
`POST /v1/admin/dokploy/reconcile`, `POST /v1/admin/dokploy/import`,
`GET /v1/admin/organizations/{org_id}/dokploy-refs`,
`POST /v1/admin/break-glass`,
`DELETE /v1/admin/break-glass/{session_id}`) is bound to one of the
four ActionAdmin* constants (`admin.read`, `admin.import`,
`admin.reconcile`, `admin.break_glass`), every admin action is
catalogued as `CapSupport`, the role-to-capability matrix admits
`CapSupport` only for `RoleSupport`, every admin endpoint's resource
is org-rooted (`Kind=KindOrganization`, only `OrganizationID`
pinned), and the cartesian table of (endpoint × built-in role ×
same-tenant / cross-tenant axis × grant scope) yields the predicted
`policy.Decision` from the engine's pure `Decide` function — a
regression that demoted any admin action's capability, added
`CapSupport` to a non-Support built-in role, pinned a deeper-than-org
leg on an admin endpoint's resource, or dropped the cross-tenant
Support exception (`CapSupport` OR `CapRead`) would fail a per-row
verdict before it could ship. The second member pins the per-decision
stability invariant under contention —
`adminEndpointWorkers * adminEndpointIterationsPerWorker` goroutines
each draw a row from the same scenario table by deterministic
mod-index and assert the verdict their OWN row predicts; a
cross-write under the race that swapped two goroutines' scenarios —
or a future regression that introduced shared mutable state in the
engine (a cached role-cap table, a sync.Once mutating a per-action
capability map, a leaky `builtinRoleCaps` reuse) — would fail the
per-iteration assertion even when the aggregate pass count matched.
Both members are deterministic by design: the engine is a pure
function from `(principal, action, resource)` to a `Decision`
value, and no test reaches the process environment, the network,
a live Postgres, a live Dokploy, or any external service.

## Required Checks Before Every Release

Cutting a release tag enables the `release` workflow, which produces
binaries, archives, and downstream packages (Homebrew, Scoop, WinGet,
npm). Before tagging:

1. Run `scripts/verify.sh --release` locally — this layers the
   release-config dry run on top of the commit gate.
2. Confirm the security gate is green:
   - `govulncheck ./...` — no high-severity advisories.
   - `staticcheck ./...` — clean.
   - `golangci-lint run ./...` — clean.
3. Confirm the release gate is green:
   - `goreleaser check` — config valid.
   - `goreleaser release --snapshot --clean` — archives build.
4. Review the dependency diff since the last tag (`go list -m -json
   all`) and update `SECURITY.md` if any threat assumption changed.
5. Spot-check `yalla manifest --json` and the JSON schemas published
   under `yalla schema list --json` for unintentional removals or
   exit-code remappings.

The CI pipeline mirrors steps 1–3 automatically. Step 4 is a human
checklist item that is part of the dependency-review expectation in
US-0011.

## Optional Tools

The required checks above use only the Go toolchain. The optional
tools below are part of the security gate, configured in this repo,
and run on every PR in CI. Install them locally for a faster feedback
loop:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
# golangci-lint: see https://golangci-lint.run/welcome/install/
# goreleaser:    see https://goreleaser.com/install/
```

`scripts/verify.sh --strict` treats a missing optional tool as a
failure; use it from CI scripts that need a hard gate.

### Opt-in external suites

A few suites only run when the operator explicitly opts in by setting an
environment variable. They are not part of the on-every-PR gate; CI runs
them out-of-band (a dedicated workflow on a schedule + manual dispatch).
Run them locally before opening a PR that touches the Dokploy client,
the Dokploy mapping layer, or the worker's provisioning path:

- `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...` —
  opt-in external live-Dokploy smoke. Also requires
  `YALLA_EXTERNAL_DOKPLOY_BASE_URL` and `YALLA_EXTERNAL_DOKPLOY_TOKEN`.
  An optional `YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE` enables an
  end-to-end read against a known service id. The smoke `t.Skip`s
  cleanly when `YALLA_EXTERNAL_DOKPLOY` is unset so this command is
  safe to run on a laptop without external infrastructure (it will
  pass, not fail). The dedicated CI workflow lives at
  `.github/workflows/external-smoke.yml` and runs on
  `workflow_dispatch` plus a nightly schedule; see
  `SECURITY.md` → "External Live-Dokploy Smoke Tests" for the full
  contract.

## Coding Conventions

- Cobra commands return typed `*errors.Error` from `internal/errors`
  via `RunE`; never let `fmt.Errorf` escape a `RunE`.
- All visible output flows through `internal/output.Renderer`. Hand-
  rolled JSON in commands is a contract violation — there is exactly
  one schema-versioned envelope per shape.
- `--json` data lives on stdout; everything else (logs, prompts,
  warnings, errors) lives on stderr.
- Stable codes/flags/exit-codes are public API. Renaming or removing
  one is a breaking change, requires a SemVer bump, and must be
  documented in the release notes.
- Tests construct the root via `cli.NewRootCommand` (or, preferably,
  `internal/testutil.RunArgs`) so they exercise the production exit-
  code path.

## Dependency Review Checklist

Before adding or upgrading a third-party Go module:

1. **Justify it.** Add a one-line note in the PR description
   explaining why the standard library is insufficient.
2. **License.** Confirm the dependency is on the allowlist in
   `.github/workflows/dependency-review.yml` (MIT, Apache-2.0,
   BSD-2/3-Clause, ISC, MPL-2.0, CC0-1.0, Unlicense, 0BSD). Anything
   else needs a separate, documented exception.
3. **Maintenance.** Check the upstream repo for recent activity and
   open security advisories. Avoid abandonware.
4. **Surface area.** Prefer narrow, leaf packages over kitchen-sink
   frameworks. Stdlib first, focused module second, framework last.
5. **Reproducibility.** Pin to a specific minor version and run
   `go mod tidy` so `go.sum` is updated.
6. **Vulnerability scan.** Run `govulncheck ./...` after the upgrade
   — the CI security gate will run it again, but local feedback is
   faster.
7. **Update docs.** If the new dependency changes a public schema or
   error-code surface, update the manifest, schemas, and any AGENTS.md
   files in directories you touched.

The CI pipeline runs `actions/dependency-review-action` on every PR
and will fail the build automatically when these expectations are
violated.

## Working with AI Coding Agents (Ralph Loop)

Yalla is built with the Ralph Loop methodology. Each iteration
implements one user story from `ralph/prd.json`, runs the required
checks, and appends to `ralph/progress.txt`. If you are running a
loop:

- Read `ralph/progress.txt`'s `## Codebase Patterns` section first.
- Follow the AGENTS.md files in the directories you touch.
- Treat every leaked secret in tests, logs, dry-run output, or error
  envelopes as a release blocker — see `SECURITY.md` for the full
  contract.

## Reporting Security Issues

See [`SECURITY.md`](./SECURITY.md). Do not open a public issue for a
security problem.
