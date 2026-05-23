package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const externalLiveDokploySmokeTestGuidePath = "docs/development/external-live-dokploy-smoke-test-guide.md"

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsScope(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"External Live-Dokploy Smoke Test Guide",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"provisioning worker",
		"private Dokploy API",
		"Dokploy",
		"internal/controlplane/dokploy/live_dokploy_smoke_test.go",
		"internal/release/verification_suite_external_dokploy_smoke_static_test.go",
		".github/workflows/external-smoke.yml",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsFunctions(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"TestLiveDokploySmokeRespectsOptInFlag",
		"TestLiveDokploySmokeExercisesLiveEndpoint",
		"TestVerificationSuiteExternalDokploySmoke",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsRequiredVariables(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"YALLA_EXTERNAL_DOKPLOY",
		"YALLA_EXTERNAL_DOKPLOY_BASE_URL",
		"YALLA_EXTERNAL_DOKPLOY_TOKEN",
		"YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsVerificationCommands(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"gofmt -w .",
		"goimports -w .",
		"go mod tidy",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
		"go test ./internal/release/... -run TestVerificationSuiteExternalDokploySmoke",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"YALLA_EXTERNAL_DOKPLOY_BASE_URL=<redacted:YALLA_EXTERNAL_DOKPLOY_BASE_URL>",
		"YALLA_EXTERNAL_DOKPLOY_TOKEN=<redacted:YALLA_EXTERNAL_DOKPLOY_TOKEN>",
		"YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE=<redacted:YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE>",
		"schema_version: yalla.error.v1",
		"request_id",
		"resource_id",
		"yerr.Error",
		"t.Skip",
		"deterministic",
		"opt-in",
		"nightly",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, externalLiveDokploySmokeTestGuidePath))

	for _, want := range []string{
		"must never contain rendered tokens",
		"must never contain rendered tokens, cookies, API keys, database URLs, Dokploy tokens, or rendered environment variable values",
		"redacted",
		"failure recovery",
		"Normal verification gates must never require a live Dokploy server",
		"must never run against production",
		"disposable",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", externalLiveDokploySmokeTestGuidePath, want)
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
		if strings.Contains(strings.ToLower(guide), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", externalLiveDokploySmokeTestGuidePath, forbidden)
		}
	}
}

func TestExternalLiveDokploySmokeTestGuideArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestExternalLiveDokploySmokeTestGuideArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"External live-Dokploy smoke test guide artifact static tests",
				"go test ./internal/release/... -run TestExternalLiveDokploySmokeTestGuideArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## External Live-Dokploy Smoke Test Guide Artifact",
				externalLiveDokploySmokeTestGuidePath,
				"go test ./internal/release/... -run TestExternalLiveDokploySmokeTestGuideArtifact",
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
