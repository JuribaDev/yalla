package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const openAPIUpdateProcedurePath = "docs/development/openapi-update-procedure.md"

func TestOpenAPIUpdateProcedureArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, openAPIUpdateProcedurePath))

	for _, want := range []string{
		"Update the OpenAPI contract",
		"internal/controlplane/openapi",
		"internal/controlplane/httpapi/routes.go",
		"openapi.Endpoint",
		"x-required-action",
		"apienvelope.WriteData",
		"apienvelope.WriteError",
		"apierr",
		"validate.DecodeJSON",
		"policy.Action",
		"go test ./internal/controlplane/openapi/...",
		"go test -run TestOpenAPI ./...",
		"go test -run TestEveryRegisteredRouteIsDocumented ./internal/controlplane/httpapi/...",
		"go test ./internal/controlplane/httpapi/...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", openAPIUpdateProcedurePath, want)
		}
	}
}

func TestOpenAPIUpdateProcedureArtifactDocumentsEnvironmentOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, openAPIUpdateProcedurePath))

	for _, want := range []string{
		"required environment variables",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example",
		"export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
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
		"TestOpenAPIConformance",
		"TestOpenAPIExamplesAreRedacted",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", openAPIUpdateProcedurePath, want)
		}
	}
}

func TestOpenAPIUpdateProcedureArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, openAPIUpdateProcedurePath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not hand-write an OpenAPI operation that is not backed by a registered route",
		"tenant isolation",
		"idempotency",
		"audit",
		"quota",
		"dokploy_refs",
		"Yalla API -> Postgres source of truth -> worker -> private Dokploy API",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", openAPIUpdateProcedurePath, want)
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
		"YALLA_SIGNING_KEYS=",
		"YALLA_SECRET_KEYS=",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", openAPIUpdateProcedurePath, forbidden)
		}
	}
}

func TestOpenAPIUpdateProcedureArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"OpenAPI update procedure artifact static tests",
				"go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## OpenAPI Update Procedure Artifact",
				openAPIUpdateProcedurePath,
				"go test ./internal/release/... -run TestOpenAPIUpdateProcedureArtifact",
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
