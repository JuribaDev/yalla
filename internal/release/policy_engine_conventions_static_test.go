package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const policyEngineConventionsPath = "docs/development/policy-engine-conventions.md"

func TestPolicyEngineConventionsArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, policyEngineConventionsPath))

	for _, want := range []string{
		"Add or change a policy action",
		"internal/controlplane/policy/catalog.go",
		"policy.Action",
		"policy.Resource",
		"policy.Principal",
		"policy.Engine.Authorize",
		"apierr.Forbidden",
		"apierr.ScopeRequired",
		"telemetry.PolicyDecisionMetrics",
		"Yalla API -> Postgres source of truth -> worker -> private Dokploy API",
		"go test ./internal/controlplane/policy/...",
		"go test -run TestPolicyMatrix ./...",
		"go test -run TestTenantIsolation ./...",
		"go test -run TestAdminEndpoint ./...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", policyEngineConventionsPath, want)
		}
	}
}

func TestPolicyEngineConventionsArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, policyEngineConventionsPath))

	for _, want := range []string{
		"required environment variables",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example",
		"export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"expected output",
		"ok",
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"Failure recovery",
		"go clean -testcache",
		"docker compose up -d postgres",
		"docker compose logs postgres",
		"docker compose down",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", policyEngineConventionsPath, want)
		}
	}
}

func TestPolicyEngineConventionsArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, policyEngineConventionsPath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"ReasonDeniedCrossTenant",
		"ReasonDeniedNoCapability",
		"ReasonDeniedUnknownAction",
		"ReasonDeniedUnknownRole",
		"tenant isolation",
		"action catalog",
		"scoped grants",
		"audit",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", policyEngineConventionsPath, want)
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
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", policyEngineConventionsPath, forbidden)
		}
	}
}

func TestPolicyEngineConventionsArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestPolicyEngineConventionsArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Policy engine conventions artifact static tests",
				"go test ./internal/release/... -run TestPolicyEngineConventionsArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Policy Engine Conventions Artifact",
				policyEngineConventionsPath,
				"go test ./internal/release/... -run TestPolicyEngineConventionsArtifact",
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
