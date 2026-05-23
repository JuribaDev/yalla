package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const agentStoryExecutionGuidePath = "docs/development/agent-story-execution-guide.md"

func TestAgentStoryExecutionGuideArtifactDocumentsScope(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, agentStoryExecutionGuidePath))

	for _, want := range []string{
		"Yalla Control Plane agent story execution guide",
		"ralph/prd.json",
		"ralph/progress.txt",
		"codex/yalla-control-plane-backend",
		"passes: false",
		"one story per iteration",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", agentStoryExecutionGuidePath, want)
		}
	}
}

func TestAgentStoryExecutionGuideArtifactDocumentsRequiredCommands(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, agentStoryExecutionGuidePath))

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
		"scripts/verify.sh",
		"golangci-lint run ./...",
		"staticcheck ./...",
		"govulncheck ./...",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", agentStoryExecutionGuidePath, want)
		}
	}
}

func TestAgentStoryExecutionGuideArtifactDocumentsContractsAndFailurePaths(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, agentStoryExecutionGuidePath))

	for _, want := range []string{
		"schema_version: yalla.output.v1",
		"schema_version: yalla.error.v1",
		"request_id",
		"stable error codes",
		"tenant isolation",
		"quota checks are transactional",
		"idempotent",
		"retry-safe",
		"audit",
		"success",
		"validation failure",
		"authorization failure",
		"not-found",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", agentStoryExecutionGuidePath, want)
		}
	}
}

func TestAgentStoryExecutionGuideArtifactDocumentsEnvironmentAndExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, agentStoryExecutionGuidePath))

	for _, want := range []string{
		"YALLA_DATABASE_URL=<redacted:YALLA_DATABASE_URL>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"PASS",
		"ok  ",
		"docker compose up -d postgres",
		"feat(controlplane): [BE-",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", agentStoryExecutionGuidePath, want)
		}
	}
}

func TestAgentStoryExecutionGuideArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	guide := readTextFile(t, filepath.Join(root, agentStoryExecutionGuidePath))

	for _, want := range []string{
		"must never contain",
		"tokens, cookies, API keys, database URLs, Dokploy tokens",
		"redacted",
		"failure recovery",
		"Normal story execution must never require a live Dokploy server",
		"must never run against production",
		"Never print secrets",
		"Never expose broad Dokploy raw API access",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("%s missing %q", agentStoryExecutionGuidePath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", agentStoryExecutionGuidePath, forbidden)
		}
	}
}

func TestAgentStoryExecutionGuideArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestAgentStoryExecutionGuideArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Agent story execution guide artifact static tests",
				"go test ./internal/release/... -run TestAgentStoryExecutionGuideArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Agent Story Execution Guide Artifact",
				agentStoryExecutionGuidePath,
				"go test ./internal/release/... -run TestAgentStoryExecutionGuideArtifact",
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
