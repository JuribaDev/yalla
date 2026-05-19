package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const securityReviewChecklistPath = "docs/development/security-review-checklist.md"

func TestSecurityReviewChecklistArtifactDocumentsReviewScope(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, securityReviewChecklistPath))

	for _, want := range []string{
		"Yalla Control Plane security review checklist",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"Dokploy",
		"PostgreSQL",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", securityReviewChecklistPath, want)
		}
	}
}

func TestSecurityReviewChecklistArtifactDocumentsRequiredSecurityGates(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, securityReviewChecklistPath))

	for _, want := range []string{
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"go test ./internal/controlplane/...",
		"go test -race ./internal/controlplane/...",
		"go test -run TestMigrations ./...",
		"go test -run TestPolicyMatrix ./...",
		"go test -run TestQuotaConcurrency ./...",
		"go test -run TestFakeDokploy ./...",
		"go test ./internal/release/... -run TestSecurityReviewChecklistArtifact",
		"scripts/verify.sh",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", securityReviewChecklistPath, want)
		}
	}
}

func TestSecurityReviewChecklistArtifactDocumentsContractsAndFailurePaths(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, securityReviewChecklistPath))

	for _, want := range []string{
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"stable error codes",
		"success",
		"validation failure",
		"authorization failure",
		"not-found",
		"tenant isolation",
		"quota failure",
		"idempotency",
		"audit",
		"OpenAPI",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", securityReviewChecklistPath, want)
		}
	}
}

func TestSecurityReviewChecklistArtifactDocumentsEnvironmentAndExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, securityReviewChecklistPath))

	for _, want := range []string{
		"YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"PASS",
		"ok  ",
		"no changes",
		"HTTP/1.1 200 OK",
		"\"schema_version\":\"yalla.output.v1\"",
		"\"schema_version\":\"yalla.error.v1\"",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", securityReviewChecklistPath, want)
		}
	}
}

func TestSecurityReviewChecklistArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	checklist := readTextFile(t, filepath.Join(root, securityReviewChecklistPath))

	for _, want := range []string{
		"must never contain",
		"tokens, cookies, API keys, database URLs, Dokploy tokens",
		"authorization headers",
		"request bodies",
		"response bodies",
		"rendered environment values",
		"redacted",
		"failure recovery",
		"Normal security review gates must never require a live Dokploy server",
		"must never run against production",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("%s missing %q", securityReviewChecklistPath, want)
		}
	}
	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"Bearer ",
		"api-key-",
		"dokploy-service-token",
		"cookie:",
		"password:",
	} {
		if strings.Contains(strings.ToLower(checklist), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", securityReviewChecklistPath, forbidden)
		}
	}
}

func TestSecurityReviewChecklistArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestSecurityReviewChecklistArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Security review checklist artifact static tests",
				"go test ./internal/release/... -run TestSecurityReviewChecklistArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Security Review Checklist Artifact",
				securityReviewChecklistPath,
				"go test ./internal/release/... -run TestSecurityReviewChecklistArtifact",
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
