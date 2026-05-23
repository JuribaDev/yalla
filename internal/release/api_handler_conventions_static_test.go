package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const apiHandlerConventionsPath = "docs/development/api-handler-conventions.md"

func TestAPIHandlerConventionsArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, apiHandlerConventionsPath))

	for _, want := range []string{
		"Add or change an API handler",
		"internal/controlplane/httpapi/routes.go",
		"newRouteTable",
		"openapi.Endpoint",
		"validate.DecodeJSON",
		"apienvelope.WriteData",
		"apienvelope.WriteError",
		"apierr",
		"policy.Action",
		"telemetry.RequestID",
		"Yalla API -> Postgres source of truth -> worker -> private Dokploy API",
		"go test ./internal/controlplane/httpapi/...",
		"go test ./internal/controlplane/openapi/...",
		"go test -run TestEveryRegisteredRouteIsDocumented ./internal/controlplane/httpapi/...",
		"go test -run TestPolicyMatrix ./...",
		"go test -run TestQuotaConcurrency ./...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", apiHandlerConventionsPath, want)
		}
	}
}

func TestAPIHandlerConventionsArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, apiHandlerConventionsPath))

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
		"docs/development/database-migration-authoring.md",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", apiHandlerConventionsPath, want)
		}
	}
}

func TestAPIHandlerConventionsArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, apiHandlerConventionsPath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not marshal JSON directly in handlers",
		"Do not read request bodies outside validate.DecodeJSON",
		"Do not write Access-Control-* headers",
		"Do not read Cookie as a credential",
		"tenant isolation",
		"idempotency",
		"audit",
		"quota",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", apiHandlerConventionsPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", apiHandlerConventionsPath, forbidden)
		}
	}
}

func TestAPIHandlerConventionsArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestAPIHandlerConventionsArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"API handler conventions artifact static tests",
				"go test ./internal/release/... -run TestAPIHandlerConventionsArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## API Handler Conventions Artifact",
				apiHandlerConventionsPath,
				"go test ./internal/release/... -run TestAPIHandlerConventionsArtifact",
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
