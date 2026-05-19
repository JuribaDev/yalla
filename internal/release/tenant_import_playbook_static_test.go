package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const tenantImportPlaybookPath = "docs/operations/tenant-import.md"

func TestTenantImportPlaybookArtifactDocumentsImportContract(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, tenantImportPlaybookPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"POST /v1/admin/dokploy/import",
		"Import dry-run",
		"OwnerAssignment",
		"support.manage",
		"admin.import",
		"Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API",
		"Customers must never receive Dokploy API tokens",
		"tenant-scoped `dokploy_refs`",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"correlation_id",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", tenantImportPlaybookPath, want)
		}
	}
}

func TestTenantImportPlaybookArtifactDocumentsCommandsEnvironmentAndOutputs(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, tenantImportPlaybookPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"YALLA_CONTROL_PLANE_ENV_FILE",
		"YALLA_API_BASE_URL",
		"YALLA_ADMIN_API_KEY",
		"YALLA_IMPORT_OWNER_ORGANIZATION_ID",
		"YALLA_IMPORT_DOKPLOY_ORGANIZATION_ID",
		"YALLA_IMPORT_IDEMPOTENCY_KEY",
		"curl -fsS -X POST",
		"Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>",
		"Idempotency-Key: <redacted:YALLA_IMPORT_IDEMPOTENCY_KEY>",
		"jq -e '.schema_version == \"yalla.output.v1\" and .ok == true'",
		"go test -run TestImportDryRun ./...",
		"go test ./internal/release/... -run TestTenantImportPlaybookArtifact",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
		"## Expected outputs",
		"\"schema_version\":\"yalla.output.v1\"",
		"\"schema_version\":\"yalla.error.v1\"",
		"\"request_id\":\"req_",
		"\"job_id\":\"job_",
		"PASS",
		"ok  github.com/juribadev/yalla",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", tenantImportPlaybookPath, want)
		}
	}
}

func TestTenantImportPlaybookArtifactDocumentsRecoveryAndRedaction(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, tenantImportPlaybookPath))

	for _, want := range []string{
		"Failure recovery",
		"pause `yalla-worker`",
		"resume `yalla-worker`",
		"do not run ad hoc write SQL",
		"retry with the same idempotency key",
		"unknown and cross-tenant identifiers",
		"break-glass",
		"audit event",
		"redacted",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
		"Never paste the full dry-run plan",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", tenantImportPlaybookPath, want)
		}
	}
	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer yk_",
		"api-key-",
		"dokploy-service-token",
		"cookie:",
		"password:",
	} {
		if strings.Contains(strings.ToLower(playbook), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", tenantImportPlaybookPath, forbidden)
		}
	}
}

func TestTenantImportPlaybookArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestTenantImportPlaybookArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Tenant import playbook artifact static tests",
				"go test ./internal/release/... -run TestTenantImportPlaybookArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Tenant Import Playbook Artifact",
				tenantImportPlaybookPath,
				"go test ./internal/release/... -run TestTenantImportPlaybookArtifact",
			},
		},
	} {
		body := readTextFile(t, filepath.Join(root, tc.path))
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q", tc.path, want)
			}
		}
	}
}
