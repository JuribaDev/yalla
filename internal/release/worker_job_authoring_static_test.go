package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const workerJobAuthoringPath = "docs/development/worker-job-authoring.md"

func TestWorkerJobAuthoringArtifactDocumentsWorkflow(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, workerJobAuthoringPath))

	for _, want := range []string{
		"Author a worker job",
		"internal/controlplane/worker",
		"internal/controlplane/store",
		"provisioning_jobs",
		"StoreClaimer",
		"Provisioner",
		"JobRunner",
		"store.JobRepository",
		"ClaimNext",
		"SELECT ... FOR UPDATE SKIP LOCKED",
		"ExpectedLeaseOwner",
		"apierr.JobNotClaimed",
		"apierr.JobCancelled",
		"Terminal",
		"RunnerFunc",
		"dokploy/dokployfake.New",
		"Yalla API -> Postgres source of truth -> provisioning worker -> private Dokploy API",
		"go test ./internal/controlplane/worker/...",
		"go test -run TestJobWorkerLease ./...",
		"go test -run TestFakeDokploy ./...",
		"go test ./internal/controlplane/store/...",
		"go test ./...",
		"go test -race ./...",
		"go vet ./...",
		"scripts/verify.sh",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", workerJobAuthoringPath, want)
		}
	}
}

func TestWorkerJobAuthoringArtifactDocumentsOutputsAndRecovery(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, workerJobAuthoringPath))

	for _, want := range []string{
		"required environment variables",
		"export YALLA_TEST_DATABASE_URL=<redacted:postgres-dsn>",
		"export YALLA_DOKPLOY_BASE_URL=https://dokploy.internal.example",
		"export YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
		"expected output",
		"ok",
		"YALLA_TEST_DATABASE_URL not set; skipping Postgres integration test",
		"schema_version yalla.output.v1",
		"schema_version yalla.error.v1",
		"request_id",
		"Failure recovery",
		"go clean -testcache",
		"docker compose up -d postgres",
		"docker compose logs postgres",
		"docker compose down",
		"dead_letter",
		"retrying",
		"E_JOB_NOT_CLAIMED",
		"E_JOB_CANCELLED",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"must never run against production",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", workerJobAuthoringPath, want)
		}
	}
}

func TestWorkerJobAuthoringArtifactDocumentsContractsAndSafety(t *testing.T) {
	root := projectRoot(t)
	doc := readTextFile(t, filepath.Join(root, workerJobAuthoringPath))

	for _, want := range []string{
		"stable JSON envelopes",
		"Unit tests cover success, validation failure, authorization failure, and not-found behavior",
		"Integration tests run against isolated Postgres migrations",
		"never require a live Dokploy server unless explicitly marked external",
		"Secrets, tokens, API keys, cookies, and rendered environment variable values are redacted",
		"Do not expose raw Dokploy operations",
		"Do not call Dokploy from handlers",
		"Do not enqueue a job before auth, policy, quota, idempotency, audit, and desired-state writes",
		"tenant isolation",
		"idempotency",
		"audit",
		"quota",
		"request_id",
		"dokploy_refs",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing %q", workerJobAuthoringPath, want)
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
			t.Fatalf("%s must not contain rendered secret-looking value %q", workerJobAuthoringPath, forbidden)
		}
	}
}

func TestWorkerJobAuthoringArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestWorkerJobAuthoringArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Worker job authoring artifact static tests",
				"go test ./internal/release/... -run TestWorkerJobAuthoringArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Worker Job Authoring Artifact",
				workerJobAuthoringPath,
				"go test ./internal/release/... -run TestWorkerJobAuthoringArtifact",
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
