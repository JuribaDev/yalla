#!/usr/bin/env bash
# scripts/verify.sh — yalla local verification gate.
#
# Runs the minimum required checks (gofmt, go mod tidy, go vet,
# `go test ./...`, `go test -race ./...`) and the optional security gates
# (govulncheck, staticcheck, golangci-lint, goreleaser check) when those
# tools are installed. Missing optional tools are reported, never silently
# skipped — that mirrors the rule called out in CONTRIBUTING.md.
#
# Usage:
#   scripts/verify.sh                Required + optional checks (commit gate)
#   scripts/verify.sh --release      Adds `goreleaser release --snapshot --clean`
#   scripts/verify.sh --strict       Treats every missing optional tool as a failure
#   scripts/verify.sh --quiet        Suppresses per-step banners (CI-friendly)
#   scripts/verify.sh --with-postgres
#                                    Requires YALLA_TEST_DATABASE_URL and adds
#                                    database-backed control-plane checks
#
# Exit codes:
#   0   all run checks passed
#   1   one or more required checks failed
#   2   --strict was set and an optional tool was missing

set -euo pipefail

release=0
strict=0
quiet=0
with_postgres=0
for arg in "$@"; do
  case "$arg" in
    --release) release=1 ;;
    --strict)  strict=1 ;;
    --quiet)   quiet=1 ;;
    --with-postgres) with_postgres=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "verify.sh: unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

step() {
  if [[ "$quiet" -eq 0 ]]; then
    printf '\n=== %s ===\n' "$1" >&2
  fi
}

skipped_tools=()
required_failed=0

if [[ "$with_postgres" -eq 1 ]]; then
  : "${YALLA_TEST_DATABASE_URL:?YALLA_TEST_DATABASE_URL is required for --with-postgres}"
fi

# 1. Required: formatting (gofmt -l should be empty)
step "gofmt -l ."
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt: the following files are not formatted:" >&2
  echo "$unformatted" >&2
  required_failed=1
fi

# 2. Required: module hygiene
step "go mod tidy"
go mod tidy

# 3. Required: vet
step "go vet ./..."
if ! go vet ./...; then
  required_failed=1
fi

# 4. Required: tests
step "go test ./..."
if ! go test ./...; then
  required_failed=1
fi

# 5. Required: race detector
step "go test -race ./..."
if ! go test -race ./...; then
  required_failed=1
fi

# 6. Required: repository integration tests
step "go test ./internal/controlplane/store/..."
if ! go test ./internal/controlplane/store/...; then
  required_failed=1
fi

# 7. Required: HTTP handler contract tests
step "go test ./internal/controlplane/httpapi/..."
if ! go test ./internal/controlplane/httpapi/...; then
  required_failed=1
fi

# 8. Required: OpenAPI schema conformance tests
step "go test ./internal/controlplane/openapi/..."
if ! go test ./internal/controlplane/openapi/...; then
  required_failed=1
fi

# 9. Required: policy matrix tests
step "go test -run TestPolicyMatrix ./..."
if ! go test -run TestPolicyMatrix ./...; then
  required_failed=1
fi

# 10. Required: quota concurrency tests
step "go test -run TestQuotaConcurrency ./..."
if ! go test -run TestQuotaConcurrency ./...; then
  required_failed=1
fi

# 11. Required: job worker lease tests
step "go test -run TestJobWorkerLease ./..."
if ! go test -run TestJobWorkerLease ./...; then
  required_failed=1
fi

# 12. Required: fake Dokploy contract tests
step "go test -run TestFakeDokploy ./..."
if ! go test -run TestFakeDokploy ./...; then
  required_failed=1
fi

# 13. Required: redaction tests
step "go test -run TestRedaction ./..."
if ! go test -run TestRedaction ./...; then
  required_failed=1
fi

# 14. Required: fuzz tests for validators
step "go test -run TestFuzzValidator ./..."
if ! go test -run TestFuzzValidator ./...; then
  required_failed=1
fi

# 15. Required: migration tests from empty DB
step "go test -run TestMigrationsEmptyDB ./..."
if ! go test -run TestMigrationsEmptyDB ./...; then
  required_failed=1
fi

# 16. Required: migration downgrade safety tests
step "go test -run TestMigrationsDowngradeSafety ./..."
if ! go test -run TestMigrationsDowngradeSafety ./...; then
  required_failed=1
fi

# 17. Required: load smoke tests
step "go test -run TestLoadSmoke ./..."
if ! go test -run TestLoadSmoke ./...; then
  required_failed=1
fi

# 18. Required: chaos tests for Dokploy timeouts
step "go test -run TestChaosDokployTimeouts ./..."
if ! go test -run TestChaosDokployTimeouts ./...; then
  required_failed=1
fi

# 19. Required: chaos tests for Postgres disconnects
step "go test -run TestChaosPostgresDisconnects ./..."
if ! go test -run TestChaosPostgresDisconnects ./...; then
  required_failed=1
fi

# 20. Required: idempotency replay tests
step "go test -run TestIdempotencyReplay ./..."
if ! go test -run TestIdempotencyReplay ./...; then
  required_failed=1
fi

# 21. Required: audit completeness tests
step "go test -run TestAuditCompleteness ./..."
if ! go test -run TestAuditCompleteness ./...; then
  required_failed=1
fi

# 22. Required: pagination stability tests
step "go test -run TestPaginationStability ./..."
if ! go test -run TestPaginationStability ./...; then
  required_failed=1
fi

# 23. Required: tenant isolation tests
step "go test -run TestTenantIsolation ./..."
if ! go test -run TestTenantIsolation ./...; then
  required_failed=1
fi

# 24. Required: backup and restore rehearsal tests
step "go test -run TestBackupRestoreRehearsal ./..."
if ! go test -run TestBackupRestoreRehearsal ./...; then
  required_failed=1
fi

# 25. Required: release build tests
step "go test -run TestReleaseBuild ./..."
if ! go test -run TestReleaseBuild ./...; then
  required_failed=1
fi

# 26. Required: config validation tests
step "go test -run TestConfigValidation ./..."
if ! go test -run TestConfigValidation ./...; then
  required_failed=1
fi

# 27. Required: admin endpoint tests
step "go test -run TestAdminEndpoint ./..."
if ! go test -run TestAdminEndpoint ./...; then
  required_failed=1
fi

# 28. Required: break-glass tests
step "go test -run TestBreakGlass ./..."
if ! go test -run TestBreakGlass ./...; then
  required_failed=1
fi

# 29. Required: reconciliation tests
step "go test -run TestReconciliation ./..."
if ! go test -run TestReconciliation ./...; then
  required_failed=1
fi

# 30. Required: import dry-run tests
step "go test -run TestImportDryRun ./..."
if ! go test -run TestImportDryRun ./...; then
  required_failed=1
fi

# 31. Required: service desired-state golden tests
step "go test -run TestServiceDesiredState ./..."
if ! go test -run TestServiceDesiredState ./...; then
  required_failed=1
fi

# 32. Required: deployment lifecycle end-to-end tests
step "go test -run TestDeploymentLifecycleE2E ./..."
if ! go test -run TestDeploymentLifecycleE2E ./...; then
  required_failed=1
fi

# Required when --with-postgres is set: database-backed verification against
# the Postgres DSN supplied through YALLA_TEST_DATABASE_URL. The normal unit
# loop skips these integration members when the env var is unset; this mode
# turns that skip into an explicit operator contract.
if [[ "$with_postgres" -eq 1 ]]; then
  step "go test ./... (with Postgres)"
  if ! go test ./...; then
    required_failed=1
  fi

  step "go test -race ./internal/controlplane/... (with Postgres)"
  if ! go test -race ./internal/controlplane/...; then
    required_failed=1
  fi

  step "go test -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/... (with Postgres)"
  if ! go test -run 'TestMigrations|TestQuotaConcurrency|TestTenantIsolation' ./internal/controlplane/...; then
    required_failed=1
  fi

  step "go vet ./... (with Postgres mode)"
  if ! go vet ./...; then
    required_failed=1
  fi
fi

# Required: Kubernetes operations artifact static tests
step "go test ./internal/release/... -run TestKubernetesArtifact"
if ! go test ./internal/release/... -run TestKubernetesArtifact; then
  required_failed=1
fi

# Required: systemd operations artifact static tests
step "go test ./internal/release/... -run TestSystemdArtifact"
if ! go test ./internal/release/... -run TestSystemdArtifact; then
  required_failed=1
fi

# Required: database migration command artifact static tests
step "go test ./internal/release/... -run TestDatabaseMigrationCommand"
if ! go test ./internal/release/... -run TestDatabaseMigrationCommand; then
  required_failed=1
fi

# Required: database migration authoring artifact static tests
step "go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact"
if ! go test ./internal/release/... -run TestDatabaseMigrationAuthoringArtifact; then
  required_failed=1
fi

# Required: worker job authoring artifact static tests
step "go test ./internal/release/... -run TestWorkerJobAuthoringArtifact"
if ! go test ./internal/release/... -run TestWorkerJobAuthoringArtifact; then
  required_failed=1
fi

# Required: fake Dokploy usage artifact static tests
step "go test ./internal/release/... -run TestFakeDokployUsageArtifact"
if ! go test ./internal/release/... -run TestFakeDokployUsageArtifact; then
  required_failed=1
fi

# Required: OpenAPI update procedure artifact static tests
step "go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact"
if ! go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact; then
  required_failed=1
fi

# Required: security review checklist artifact static tests
step "go test ./internal/release/... -run TestSecurityReviewChecklistArtifact"
if ! go test ./internal/release/... -run TestSecurityReviewChecklistArtifact; then
  required_failed=1
fi

# Required: production config reference artifact static tests
step "go test ./internal/release/... -run TestProductionConfigReferenceArtifact"
if ! go test ./internal/release/... -run TestProductionConfigReferenceArtifact; then
  required_failed=1
fi

# Required: environment variable reference artifact static tests
step "go test ./internal/release/... -run TestEnvironmentVariableReferenceArtifact"
if ! go test ./internal/release/... -run TestEnvironmentVariableReferenceArtifact; then
  required_failed=1
fi

# Required: observability dashboard guide artifact static tests
step "go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact"
if ! go test ./internal/release/... -run TestObservabilityDashboardGuideArtifact; then
  required_failed=1
fi

# Required: external live-Dokploy smoke test guide artifact static tests
step "go test ./internal/release/... -run TestExternalLiveDokploySmokeTestGuideArtifact"
if ! go test ./internal/release/... -run TestExternalLiveDokploySmokeTestGuideArtifact; then
  required_failed=1
fi

# Required: seed admin command artifact static tests
step "go test ./internal/release/... -run TestSeedAdminCommand"
if ! go test ./internal/release/... -run TestSeedAdminCommand; then
  required_failed=1
fi

# Required: backup command artifact static tests
step "go test ./internal/release/... -run TestBackupCommand"
if ! go test ./internal/release/... -run TestBackupCommand; then
  required_failed=1
fi

# Required: restore rehearsal command artifact static tests
step "go test ./internal/release/... -run TestRestoreRehearsalCommand"
if ! go test ./internal/release/... -run TestRestoreRehearsalCommand; then
  required_failed=1
fi

# Required: backup restore rehearsal artifact static tests
step "go test ./internal/release/... -run TestBackupRestoreRehearsalArtifact"
if ! go test ./internal/release/... -run TestBackupRestoreRehearsalArtifact; then
  required_failed=1
fi

# Required: config example artifact static tests
step "go test ./internal/release/... -run TestConfigExamplesArtifact"
if ! go test ./internal/release/... -run TestConfigExamplesArtifact; then
  required_failed=1
fi

# Required: deployment runbook artifact static tests
step "go test ./internal/release/... -run TestDeploymentRunbookArtifact"
if ! go test ./internal/release/... -run TestDeploymentRunbookArtifact; then
  required_failed=1
fi

# Required: local development setup artifact static tests
step "go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact"
if ! go test ./internal/release/... -run TestLocalDevelopmentSetupArtifact; then
  required_failed=1
fi

# Required: API handler conventions artifact static tests
step "go test ./internal/release/... -run TestAPIHandlerConventionsArtifact"
if ! go test ./internal/release/... -run TestAPIHandlerConventionsArtifact; then
  required_failed=1
fi

# Required: policy engine conventions artifact static tests
step "go test ./internal/release/... -run TestPolicyEngineConventionsArtifact"
if ! go test ./internal/release/... -run TestPolicyEngineConventionsArtifact; then
  required_failed=1
fi

# Required: quota implementation guide artifact static tests
step "go test ./internal/release/... -run TestQuotaImplementationGuideArtifact"
if ! go test ./internal/release/... -run TestQuotaImplementationGuideArtifact; then
  required_failed=1
fi

# Required: repository conventions artifact static tests
step "go test ./internal/release/... -run TestRepositoryConventionsArtifact"
if ! go test ./internal/release/... -run TestRepositoryConventionsArtifact; then
  required_failed=1
fi

# Required: incident response runbook artifact static tests
step "go test ./internal/release/... -run TestIncidentResponseRunbookArtifact"
if ! go test ./internal/release/... -run TestIncidentResponseRunbookArtifact; then
  required_failed=1
fi

# Required: tenant import playbook artifact static tests
step "go test ./internal/release/... -run TestTenantImportPlaybookArtifact"
if ! go test ./internal/release/... -run TestTenantImportPlaybookArtifact; then
  required_failed=1
fi

# Required: on-call dashboard artifact static tests
step "go test ./internal/release/... -run TestOnCallDashboardArtifact"
if ! go test ./internal/release/... -run TestOnCallDashboardArtifact; then
  required_failed=1
fi

# Required: SLO document artifact static tests
step "go test ./internal/release/... -run TestSLODocumentArtifact"
if ! go test ./internal/release/... -run TestSLODocumentArtifact; then
  required_failed=1
fi

# Required: release checklist artifact static tests
step "go test ./internal/release/... -run TestReleaseChecklistArtifact"
if ! go test ./internal/release/... -run TestReleaseChecklistArtifact; then
  required_failed=1
fi

# Required: rollback checklist artifact static tests
step "go test ./internal/release/... -run TestRollbackChecklistArtifact"
if ! go test ./internal/release/... -run TestRollbackChecklistArtifact; then
  required_failed=1
fi

# Required: break-glass playbook artifact static tests
step "go test ./internal/release/... -run TestBreakGlassPlaybookArtifact"
if ! go test ./internal/release/... -run TestBreakGlassPlaybookArtifact; then
  required_failed=1
fi

# Required: frontend handoff API guide artifact static tests
step "go test ./internal/release/... -run TestFrontendHandoffAPIGuideArtifact"
if ! go test ./internal/release/... -run TestFrontendHandoffAPIGuideArtifact; then
  required_failed=1
fi

# Required: agent story execution guide artifact static tests
step "go test ./internal/release/... -run TestAgentStoryExecutionGuideArtifact"
if ! go test ./internal/release/... -run TestAgentStoryExecutionGuideArtifact; then
  required_failed=1
fi

# Required: pricing and usage tracking architecture artifact static tests
step "go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact"
if ! go test ./internal/release/... -run TestPricingAndUsageTrackingArchitectureArtifact; then
  required_failed=1
fi

# 33. Optional: govulncheck (vulnerability scan)
step "govulncheck ./... (optional)"
if command -v govulncheck >/dev/null 2>&1; then
  if ! govulncheck ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)")
fi

# 34. Optional: staticcheck
step "staticcheck ./... (optional)"
if command -v staticcheck >/dev/null 2>&1; then
  if ! staticcheck ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)")
fi

# 35. Optional: golangci-lint
step "golangci-lint run ./... (optional)"
if command -v golangci-lint >/dev/null 2>&1; then
  if ! golangci-lint run ./...; then
    required_failed=1
  fi
else
  skipped_tools+=("golangci-lint (install: https://golangci-lint.run/welcome/install/)")
fi

# 36. Optional: goreleaser check (release config)
step "goreleaser check (optional)"
if command -v goreleaser >/dev/null 2>&1; then
  if ! goreleaser check; then
    required_failed=1
  fi
  if [[ "$release" -eq 1 ]]; then
    step "goreleaser release --snapshot --clean (optional)"
    if ! goreleaser release --snapshot --clean; then
      required_failed=1
    fi
  fi
else
  skipped_tools+=("goreleaser (install: https://goreleaser.com/install/)")
  if [[ "$release" -eq 1 ]]; then
    echo "verify.sh: --release requires goreleaser to be installed" >&2
    required_failed=1
  fi
fi

# 37. Optional: external live-Dokploy smoke tests
# The smoke reaches a real Dokploy server and is only meaningful when the
# operator has explicitly opted in by setting YALLA_EXTERNAL_DOKPLOY=1
# (along with YALLA_EXTERNAL_DOKPLOY_BASE_URL and
# YALLA_EXTERNAL_DOKPLOY_TOKEN). When the opt-in env var is unset, the
# step is skipped so a developer running scripts/verify.sh on a laptop
# without external infrastructure does not see a failure. This is a
# deliberate opt-out (not a missing tool) so it is reported on stderr but
# NOT appended to skipped_tools — that keeps --strict free to fail only on
# genuinely missing optional tooling.
step "YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./... (optional)"
if [[ "${YALLA_EXTERNAL_DOKPLOY:-}" = "1" ]]; then
  if ! YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...; then
    required_failed=1
  fi
else
  echo "verify.sh: external live-Dokploy smoke is opt-in; export YALLA_EXTERNAL_DOKPLOY=1 with YALLA_EXTERNAL_DOKPLOY_BASE_URL/TOKEN to enable" >&2
fi

if [[ ${#skipped_tools[@]} -gt 0 ]]; then
  echo "" >&2
  echo "verify.sh: optional tools not installed (skipped, NOT silently — see CONTRIBUTING.md):" >&2
  for tool in "${skipped_tools[@]}"; do
    echo "  - $tool" >&2
  done
  if [[ "$strict" -eq 1 ]]; then
    echo "verify.sh: --strict was set; missing optional tools are a failure" >&2
    exit 2
  fi
fi

if [[ "$required_failed" -ne 0 ]]; then
  echo "" >&2
  echo "verify.sh: one or more checks failed" >&2
  exit 1
fi

echo ""
echo "verify.sh: all checks passed"
