package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const frontendHandoffAPIGuidePath = "docs/development/frontend-handoff-api-guide.md"

func TestFrontendHandoffAPIGuideArtifactDocumentsScope(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"Yalla Control Plane frontend handoff API guide",
		"/v1",
		"/v1/admin",
		"Customer / Agent / CI / Frontend",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"frontend",
		"stable contracts",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsAuthAndEnvelopes(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"Authorization: Bearer yka_",
		"session_token",
		"schema_version",
		"yalla.output.v1",
		"yalla.error.v1",
		"request_id",
		"\"ok\": true",
		"\"ok\": false",
		"error.code",
		"message",
		"hint",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsHierarchyAndIDs(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"Organization",
		"Project",
		"Environment",
		"Service",
		"org_",
		"proj_",
		"env_",
		"svc_",
		"Stable ID prefixes",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsEndpointsAndPagination(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"List endpoints",
		"cursor-based pagination",
		"next_cursor",
		"has_more",
		"202 Accepted",
		"job_id",
		"deployment_id",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsErrorHandling(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"E_VALIDATION",
		"E_SCOPE_REQUIRED",
		"E_AUTHENTICATION_REQUIRED",
		"E_AUTH_INVALID",
		"E_FORBIDDEN",
		"E_NOT_FOUND",
		"E_CONFLICT",
		"E_INVALID_STATE_TRANSITION",
		"E_RATE_LIMITED",
		"E_DB_UNAVAILABLE",
		"E_MIGRATION_REQUIRED",
		"request_id",
		"Frontend action",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsEnvironmentAndExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"YALLA_API_BASE_URL",
		"YALLA_PUBLIC_URL",
		"YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"docker compose up -d postgres",
		"go run ./cmd/yalla-api",
		"http://localhost:8080/v1/healthz",
		"PASS",
		"ok  ",
		"schema_version\":\"yalla.output.v1\"",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, frontendHandoffAPIGuidePath))

	for _, want := range []string{
		"must never contain",
		"tokens, cookies, API keys, database URLs, Dokploy tokens",
		"redacted",
		"failure recovery",
		"Envelope version mismatch",
		"Unexpected 401",
		"Unexpected 403",
		"Unexpected 404 after a create",
		"Rate limit (429)",
		"5xx errors",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", frontendHandoffAPIGuidePath, want)
		}
	}
	for _, forbidden := range []string{
		"postgres://",
		"postgresql://",
		"api-key-",
		"dokploy-service-token",
		"cookie:",
		"password:",
	} {
		if strings.Contains(strings.ToLower(guide), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", frontendHandoffAPIGuidePath, forbidden)
		}
	}
}

func TestFrontendHandoffAPIGuideArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestFrontendHandoffAPIGuideArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Frontend handoff API guide artifact static tests",
				"go test ./internal/release/... -run TestFrontendHandoffAPIGuideArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Frontend Handoff API Guide Artifact",
				frontendHandoffAPIGuidePath,
				"go test ./internal/release/... -run TestFrontendHandoffAPIGuideArtifact",
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
