package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const breakGlassPlaybookPath = "docs/operations/break-glass-playbook.md"

func TestBreakGlassPlaybookArtifactDocumentsBreakGlassContract(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, breakGlassPlaybookPath))

	for _, want := range []string{
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"POST /v1/organizations/{org_id}/break-glass",
		"POST /v1/admin/break-glass",
		"DELETE /v1/organizations/{org_id}/break-glass/{session_id}",
		"DELETE /v1/admin/break-glass/{session_id}",
		"admin.break_glass",
		"CapSupport",
		"RoleSupport",
		"elevated_access",
		"access-only",
		"no customer credential mint",
		"Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API",
		"Customers must never receive Dokploy API tokens",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"correlation_id",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", breakGlassPlaybookPath, want)
		}
	}
}

func TestBreakGlassPlaybookArtifactDocumentsCommandsEnvironmentAndOutputs(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, breakGlassPlaybookPath))

	for _, want := range []string{
		"/etc/yalla/control-plane.env",
		"YALLA_CONTROL_PLANE_ENV_FILE",
		"YALLA_API_BASE_URL",
		"YALLA_ADMIN_API_KEY",
		"YALLA_BREAK_GLASS_TARGET_ORG_ID",
		"curl -fsS -X POST",
		"Authorization: Bearer <redacted:YALLA_ADMIN_API_KEY>",
		"jq -e '.schema_version == \"yalla.output.v1\" and .ok == true'",
		"ttl_seconds",
		"reason",
		"go test -run TestBreakGlass ./...",
		"go test ./internal/release/... -run TestBreakGlassPlaybookArtifact",
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
		"\"id\":\"bgs_",
		"PASS",
		"ok  github.com/juribadev/yalla",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", breakGlassPlaybookPath, want)
		}
	}
}

func TestBreakGlassPlaybookArtifactDocumentsRecoveryAndRedaction(t *testing.T) {
	root := projectRoot(t)
	playbook := readTextFile(t, filepath.Join(root, breakGlassPlaybookPath))

	for _, want := range []string{
		"Failure recovery",
		"pause `yalla-worker`",
		"resume `yalla-worker`",
		"do not run ad hoc write SQL",
		"break-glass",
		"audit event",
		"redacted",
		"must never contain tokens, API keys, cookies, database URLs, Dokploy tokens, or rendered environment variable values",
	} {
		if !strings.Contains(playbook, want) {
			t.Fatalf("%s missing %q", breakGlassPlaybookPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", breakGlassPlaybookPath, forbidden)
		}
	}
}

func TestBreakGlassPlaybookArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestBreakGlassPlaybookArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Break-glass playbook artifact static tests",
				"go test ./internal/release/... -run TestBreakGlassPlaybookArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Break-Glass Playbook Artifact",
				breakGlassPlaybookPath,
				"go test ./internal/release/... -run TestBreakGlassPlaybookArtifact",
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
