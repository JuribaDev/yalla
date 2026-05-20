# Control Plane Production Readiness Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the production blockers found after `ralph/prd.json`: durable provisioning jobs must be persisted atomically with desired state, readiness must reflect real dependencies, internal worker authentication must be configurable and wired, and the verification path must prove the database-backed contracts.

**Architecture:** Keep the existing boundaries: HTTP handlers stay thin, store services own transactional desired-state writes, `internal/controlplane/jobs` owns durable job enqueue adapters, `internal/controlplane/worker` owns execution, `runtime.Readiness` owns startup gates, and `config/auth` own credential configuration. Do not expose raw Dokploy or move business logic into `cmd/yalla-api`.

**Tech Stack:** Go 1.25/1.26 toolchain, `net/http`, `pgx`, embedded migrations, existing `store.JobRepository`, existing `worker.Provisioner`, existing `runtime.Readiness`, existing `auth.Authenticator`, existing `config.Load`.

---

## Target Flow

```mermaid
flowchart LR
  HTTP["HTTP handler"] --> StoreSvc["store service unit of work"]
  StoreSvc --> Authz["in-tx authorizer"]
  StoreSvc --> Quota["in-tx quota reservation"]
  StoreSvc --> State["desired-state row"]
  StoreSvc --> Jobs["jobs.Enqueuer -> provisioning_jobs"]
  StoreSvc --> Audit["audit_events"]
  Jobs --> Worker["worker.StoreClaimer"]
  Worker --> Provisioner["worker.Provisioner"]
  Provisioner --> Dokploy["typed Dokploy client"]
```

## Readiness Flow

```mermaid
flowchart TD
  Start["cmd/yalla-api startup"] --> DB["pool.Ping"]
  DB --> Mig["migrate.Status"]
  Mig --> Queue["jobs.CheckQueueReady"]
  Queue --> DOK{"Dokploy configured?"}
  DOK -- yes --> DOKCheck["dokploy.GetUserServerMetrics or health check"]
  DOK -- no --> Ready["mark required gates ready"]
  DOKCheck --> Ready
  Mig --> Meta["runtime.Meta.SetMigrationVersion"]
```

## File Map

- Modify `internal/controlplane/store/projectservice.go`: widen `JobEnqueuer` to structured input and pass request/correlation ids.
- Modify `internal/controlplane/store/organizationservice.go`: enqueue `ensure_dokploy_organization` on organization creation.
- Modify `internal/controlplane/store/environmentservice.go`: pass structured job input.
- Modify `internal/controlplane/store/preview_environment_service.go`: pass structured job input.
- Modify `internal/controlplane/store/serviceservice.go`: pass structured job input for create/start/stop/restart.
- Modify `internal/controlplane/store/deployment_service.go`: pass structured job input for create/rollback.
- Create `internal/controlplane/jobs/types.go`: durable job type constants shared by enqueue and worker.
- Create `internal/controlplane/jobs/enqueuer.go`: production `store.JobEnqueuer` adapter backed by `store.JobRepository`.
- Create `internal/controlplane/jobs/enqueuer_test.go`: fake-pg/unit tests for payload, idempotency keys, and request/correlation propagation.
- Modify `internal/controlplane/worker/provisioner.go`: alias job type constants from `jobs` package so the worker and enqueuer share vocabulary.
- Modify `cmd/yalla-api/main.go`: wire `jobs.NewEnqueuer`, remove `noopJobEnqueuer`, and wire real startup checks.
- Create `cmd/yalla-api/main_test.go`: process-wiring tests for no no-op jobs, readiness checks, and internal worker token wiring.
- Modify `internal/controlplane/config/config.go`: add `YALLA_INTERNAL_WORKER_TOKEN` as a secret config field.
- Modify `internal/controlplane/config/load.go`: load, validate, and redact the internal worker token.
- Modify `internal/controlplane/config/config_test.go` and `config_validation_test.go`: add success, strict-profile, and redaction tests.
- Modify `cmd/yalla-worker/main.go`: validate that worker and API use the same internal worker token when private callbacks are enabled.
- Modify `deploy/config/control-plane.env.example`, `deploy/systemd/control-plane.env.example`, and `deploy/kubernetes/yalla-control-plane.yaml`: document and mount the new secret.
- Modify `scripts/verify.sh` and `ralph/VERIFICATION.md`: add explicit database-backed verification commands.

---

### Task 1: Structured JobEnqueuer Port

**Files:**
- Modify: `internal/controlplane/store/projectservice.go`
- Modify: `internal/controlplane/store/*service*_test.go`

- [ ] **Step 1: Write the failing compile-time contract**

Add the structured input next to the existing `JobEnqueuer` in `projectservice.go`:

```go
type EnqueueJobInput struct {
	OrganizationID string
	JobKind        string
	ResourceID     string
	RequestID      string
	CorrelationID  string
}

type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx *Tx, in EnqueueJobInput) error
}
```

- [ ] **Step 2: Run compile check**

Run: `go test ./internal/controlplane/store`

Expected: FAIL with call-site and fake-enqueuer signature errors.

- [ ] **Step 3: Update every store service call site**

Use this pattern in each service after the desired row has been inserted or selected:

```go
if err := svc.jobs.Enqueue(ctx, tx, EnqueueJobInput{
	OrganizationID: row.OrganizationID,
	JobKind:        projectProvisionJob,
	ResourceID:     row.ID,
	RequestID:      strings.TrimSpace(in.RequestID),
	CorrelationID:  strings.TrimSpace(in.CorrelationID),
}); err != nil {
	return err
}
```

For service start/stop/restart and deployment rollback, use the operation-specific job kind already declared in the file.

- [ ] **Step 4: Update store test fakes**

Replace fake signatures with:

```go
func (j *recordingJobs) Enqueue(_ context.Context, _ *store.Tx, in store.EnqueueJobInput) error {
	j.calls = append(j.calls, in)
	return j.err
}
```

- [ ] **Step 5: Verify**

Run: `go test ./internal/controlplane/store`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/controlplane/store
git commit -m "refactor(controlplane): pass structured job enqueue input"
```

### Task 2: Durable Job Vocabulary

**Files:**
- Create: `internal/controlplane/jobs/types.go`
- Modify: `internal/controlplane/worker/provisioner.go`
- Test: `internal/controlplane/worker/provisioner_test.go`

- [ ] **Step 1: Create shared durable job constants**

```go
package jobs

const (
	TypeEnsureDokployOrganization = "ensure_dokploy_organization"
	TypeEnsureProject             = "ensure_project"
	TypeEnsureEnvironment         = "ensure_environment"
	TypeEnsureApplicationService  = "ensure_application_service"
	TypeEnsureComposeService      = "ensure_compose_service"
	TypeEnsureDatabaseService     = "ensure_database_service"
	TypeDeployService             = "service.deploy"
	TypeRestartService            = "service.restart"
	TypeRollbackService           = "service.rollback"
	TypeStopService               = "service.stop"
	TypeStartService              = "service.start"
	TypeDeleteService             = "service.delete"
	TypeDeleteEnvironment         = "environment.delete"
	TypeDeleteProject             = "project.delete"
	TypeCreatePreviewEnvironment  = "create_preview_environment"
	TypeDeletePreviewEnvironment  = "delete_preview_environment"
)
```

- [ ] **Step 2: Alias worker constants to jobs constants**

In `worker/provisioner.go`, import `internal/controlplane/jobs` and define:

```go
const JobTypeEnsureProject = jobs.TypeEnsureProject
```

Apply the same alias for each existing job type constant. Keep alias names unchanged so worker tests and callers do not churn.

- [ ] **Step 3: Verify**

Run: `go test ./internal/controlplane/worker ./internal/controlplane/jobs`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/controlplane/jobs internal/controlplane/worker/provisioner.go
git commit -m "refactor(controlplane): share durable job type constants"
```

### Task 3: Production Durable Job Enqueuer

**Files:**
- Create: `internal/controlplane/jobs/enqueuer.go`
- Create: `internal/controlplane/jobs/enqueuer_test.go`
- Modify: `internal/controlplane/jobs/doc.go`

- [ ] **Step 1: Write tests for organization/project/environment/service/preview/deployment enqueue**

Test each public mutation produces one `provisioning_jobs` row with:

```go
want := store.ProvisioningJob{
	OrganizationID: orgID,
	JobType:        jobs.TypeEnsureProject,
	ProjectID:      projectID,
	DesiredVersion: project.Version,
	IdempotencyKey: "project.provision:" + projectID + ":v" + strconv.FormatInt(project.Version, 10),
	RequestID:      "req_test",
	CorrelationID:  "corr_test",
	Payload: map[string]string{
		"organization_id": orgID,
		"project_id":      projectID,
	},
}
```

- [ ] **Step 2: Implement `jobs.Enqueuer`**

Core shape:

```go
type Enqueuer struct {
	jobs         *store.JobRepository
	projects     *store.ProjectRepository
	environments *store.EnvironmentRepository
	services     *store.ServiceRepository
	deployments  *store.DeploymentRepository
}

func NewEnqueuer() *Enqueuer {
	return &Enqueuer{
		jobs:         store.NewJobRepository(),
		projects:     store.NewProjectRepository(),
		environments: store.NewEnvironmentRepository(),
		services:     store.NewServiceRepository(),
		deployments:  store.NewDeploymentRepository(),
	}
}
```

Map store job kinds to durable worker job types:

```go
switch in.JobKind {
case jobs.TypeEnsureDokployOrganization:
	return e.enqueueOrganization(ctx, tx, in)
case "project.provision":
	return e.enqueueProject(ctx, tx, in)
case "environment.provision":
	return e.enqueueEnvironment(ctx, tx, in)
case "service.provision":
	return e.enqueueService(ctx, tx, in)
case jobs.TypeDeployService, jobs.TypeRestartService, jobs.TypeStopService, jobs.TypeStartService:
	return e.enqueueServiceRuntime(ctx, tx, in)
case jobs.TypeCreatePreviewEnvironment, jobs.TypeDeletePreviewEnvironment:
	return e.enqueuePreview(ctx, tx, in)
default:
	return apierr.Internal(fmt.Errorf("jobs: unsupported job kind %q", in.JobKind))
}
```

Organization creation uses `jobs.TypeEnsureDokployOrganization` with payload:

```go
store.ProvisioningJob{
	OrganizationID: in.OrganizationID,
	JobType:        jobs.TypeEnsureDokployOrganization,
	DesiredVersion: organization.Version,
	IdempotencyKey: idempotencyKey(jobs.TypeEnsureDokployOrganization, organization.ID, organization.Version),
	RequestID:      in.RequestID,
	CorrelationID:  in.CorrelationID,
	Payload: map[string]string{
		"organization_id": organization.ID,
	},
}
```

- [ ] **Step 3: Ensure idempotency keys are stable and versioned**

Use:

```go
func idempotencyKey(kind, resourceID string, version int64) string {
	return kind + ":" + resourceID + ":v" + strconv.FormatInt(version, 10)
}
```

- [ ] **Step 4: Verify**

Run: `go test ./internal/controlplane/jobs`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controlplane/jobs
git commit -m "feat(controlplane): enqueue durable provisioning jobs"
```

### Task 4: Wire Real Jobs Into the API Binary

**Files:**
- Modify: `cmd/yalla-api/main.go`
- Create: `cmd/yalla-api/main_test.go`

- [ ] **Step 1: Add wiring test**

Add a static test that fails if `noopJobEnqueuer` remains in production wiring:

```go
func TestMainDoesNotWireNoopJobEnqueuer(t *testing.T) {
	src := readSelfOrFail(t, "main.go")
	if strings.Contains(src, "noopJobEnqueuer{}") {
		t.Fatal("cmd/yalla-api must wire jobs.NewEnqueuer, not noopJobEnqueuer")
	}
}
```

- [ ] **Step 2: Wire the real enqueuer**

In `cmd/yalla-api/main.go`:

```go
jobEnqueuer := jobs.NewEnqueuer()
projectJobs := jobEnqueuer
environmentJobs := jobEnqueuer
serviceJobs := jobEnqueuer
```

Remove `noopJobEnqueuer`.

- [ ] **Step 3: Verify no desired-state write can silently skip a job**

Run:

```bash
go test ./cmd/yalla-api ./internal/controlplane/jobs ./internal/controlplane/store
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/yalla-api internal/controlplane/jobs internal/controlplane/store
git commit -m "feat(controlplane): wire durable jobs into api"
```

### Task 5: Real Startup Readiness

**Files:**
- Modify: `cmd/yalla-api/main.go`
- Create: `cmd/yalla-api/readiness_test.go`
- Create: `internal/controlplane/jobs/health.go`
- Create: `internal/controlplane/jobs/health_test.go`

- [ ] **Step 1: Add queue health check**

```go
func CheckQueueReady(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `SELECT 1 FROM provisioning_jobs LIMIT 0`)
	if err != nil {
		return apierr.QueueUnavailable(err)
	}
	return nil
}
```

- [ ] **Step 2: Add migration readiness check**

Replace `runStartupChecks(ctx, pool)` with:

```go
func runStartupChecks(ctx context.Context, pool *pgxpool.Pool, meta *runtime.Meta, dokployChecker func(context.Context) error) map[string]error {
	results := map[string]error{}
	if err := pool.Ping(ctx); err != nil {
		results["database"] = err
	}
	migrator, err := migrate.New(pool, slog.Default())
	if err != nil {
		results["migrations"] = err
	} else if st, err := migrator.Status(ctx); err != nil {
		results["migrations"] = err
	} else {
		meta.SetMigrationVersion(fmt.Sprintf("%04d", st.Current))
		if st.Dirty || len(st.Pending) > 0 {
			results["migrations"] = apierr.MigrationRequired(fmt.Errorf("migration current=%d pending=%d dirty=%v", st.Current, len(st.Pending), st.Dirty))
		}
	}
	if err := jobs.CheckQueueReady(ctx, pool); err != nil {
		results["queue"] = err
	}
	if dokployChecker != nil {
		if err := dokployChecker(ctx); err != nil {
			results["dokploy"] = err
		}
	}
	return results
}
```

- [ ] **Step 3: Mark only passing gates**

```go
results := runStartupChecks(ctx, pool, meta, dokployChecker)
for _, gate := range readinessGates {
	if results[gate] == nil {
		readiness.MarkReady(gate)
	}
}
```

- [ ] **Step 4: Verify**

Run:

```bash
go test ./cmd/yalla-api ./internal/controlplane/jobs ./internal/controlplane/runtime
```

Expected: PASS. With `YALLA_TEST_DATABASE_URL` set, migration readiness tests must fail when a migration is pending or dirty.

- [ ] **Step 5: Commit**

```bash
git add cmd/yalla-api internal/controlplane/jobs
git commit -m "feat(controlplane): gate readiness on real dependencies"
```

### Task 6: Internal Worker Token Config and Auth Wiring

**Files:**
- Modify: `internal/controlplane/config/config.go`
- Modify: `internal/controlplane/config/load.go`
- Modify: `internal/controlplane/config/config_test.go`
- Modify: `internal/controlplane/config/config_validation_test.go`
- Modify: `cmd/yalla-api/main.go`
- Modify: `deploy/config/control-plane.env.example`
- Modify: `deploy/systemd/control-plane.env.example`
- Modify: `deploy/kubernetes/yalla-control-plane.yaml`

- [ ] **Step 1: Add config field and env var**

```go
const EnvInternalWorkerToken = "YALLA_INTERNAL_WORKER_TOKEN"

type Config struct {
	InternalWorkerToken string
}
```

Keep it in the existing `Config` struct with the other secrets.

- [ ] **Step 2: Load and validate**

```go
InternalWorkerToken: valueOr(lookup, EnvInternalWorkerToken, ""),
```

Strict profiles must require it:

```go
if c.Profile.IsStrict() && c.InternalWorkerToken == "" {
	missing = append(missing, EnvInternalWorkerToken)
}
```

Use the same minimum length rule as signing keys or a new `minInternalWorkerTokenLen = 32`.

- [ ] **Step 3: Redact**

Add to `RedactedConfig`, `Redacted()`, `LogValue()`, and `String()`:

```go
InternalWorkerToken: redact(c.InternalWorkerToken),
```

- [ ] **Step 4: Wire authenticator**

```go
authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{
	Store:               credentials,
	SigningKeys:         cfg.SigningKeys,
	InternalWorkerToken: cfg.InternalWorkerToken,
})
```

- [ ] **Step 5: Verify**

Run:

```bash
go test ./internal/controlplane/config ./internal/controlplane/auth ./cmd/yalla-api
```

Expected: PASS, with tests proving `slog.Any("config", cfg)` does not leak the token.

- [ ] **Step 6: Commit**

```bash
git add internal/controlplane/config cmd/yalla-api deploy
git commit -m "feat(controlplane): wire internal worker token config"
```

### Task 7: Production Verification and Runbook

**Files:**
- Modify: `scripts/verify.sh`
- Modify: `ralph/VERIFICATION.md`
- Modify: `README.md` or `deploy/operations/README.md`

- [ ] **Step 1: Add a database-backed verification mode**

Add a script mode that requires `YALLA_TEST_DATABASE_URL`:

```bash
case "${1:-}" in
  --with-postgres)
    : "${YALLA_TEST_DATABASE_URL:?YALLA_TEST_DATABASE_URL is required for --with-postgres}"
    go test ./...
    go test -race ./internal/controlplane/...
    go test -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...
    go vet ./...
    ;;
esac
```

- [ ] **Step 2: Document exact operator command**

```bash
docker compose up -d postgres
export YALLA_TEST_DATABASE_URL='postgres://yalla:yalla@127.0.0.1:5432/yalla_test?sslmode=disable'
./scripts/verify.sh --with-postgres
```

- [ ] **Step 3: Verify**

Run:

```bash
./scripts/verify.sh
```

Expected: PASS without Postgres. Run `./scripts/verify.sh --with-postgres` when Postgres is configured.

- [ ] **Step 4: Commit**

```bash
git add scripts/verify.sh ralph/VERIFICATION.md README.md deploy/operations/README.md
git commit -m "docs(controlplane): add production verification path"
```

## Completion Gate

Do not call this production-ready until all of these pass:

```bash
gofmt -w cmd internal deploy scripts
go mod tidy
go test ./...
go test -race ./internal/controlplane/...
go vet ./...
YALLA_TEST_DATABASE_URL='postgres://...' go test -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...
```

## Self-Review

- Spec coverage: durable jobs close the no-op enqueue gap; readiness checks cover database, migrations, queue, and Dokploy; internal worker token is loaded and redacted; verification distinguishes unit-only from Postgres-backed evidence.
- Codebase alignment: plan keeps HTTP in `cmd/yalla-api`, transactions in `store`, durable job construction in `jobs`, execution in `worker`, and credentials in `config/auth`.
- Risk controls: each change has a failing test first, short package-level verification, and a commit boundary.
