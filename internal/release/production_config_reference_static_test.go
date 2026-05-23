package release_test

import (
	"path/filepath"
	"strings"
	"testing"
)

const productionConfigReferencePath = "docs/operations/production-config-reference.md"

func TestProductionConfigReferenceArtifactDocumentsReviewScope(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

	for _, want := range []string{
		"Yalla Control Plane Production Config Reference",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"Customer / Agent / CI",
		"Postgres source of truth",
		"Provisioning worker",
		"private Dokploy API",
		"Dokploy",
		"PostgreSQL",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
		}
	}
}

func TestProductionConfigReferenceArtifactDocumentsRequiredVariables(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

	for _, want := range []string{
		"YALLA_PROFILE",
		"YALLA_API_ADDR",
		"YALLA_PUBLIC_URL",
		"YALLA_DATABASE_URL",
		"YALLA_SIGNING_KEYS",
		"YALLA_SECRET_KEYS",
		"YALLA_DOKPLOY_BASE_URL",
		"YALLA_DOKPLOY_TOKEN",
		"YALLA_INTERNAL_WORKER_TOKEN",
		"YALLA_SHUTDOWN_TIMEOUT",
		"YALLA_BACKUP_STATUS_FILE",
		"YALLA_BACKUP_MAX_AGE",
		"YALLA_LOG_LEVEL",
		"YALLA_FEATURE_FLAGS",
		"YALLA_RATE_LIMIT_DISABLED",
		"YALLA_RATE_LIMIT_ORG_READ_RPS",
		"YALLA_RATE_LIMIT_ORG_READ_BURST",
		"YALLA_RATE_LIMIT_ORG_WRITE_RPS",
		"YALLA_RATE_LIMIT_ORG_WRITE_BURST",
		"YALLA_RATE_LIMIT_KEY_READ_RPS",
		"YALLA_RATE_LIMIT_KEY_READ_BURST",
		"YALLA_RATE_LIMIT_KEY_WRITE_RPS",
		"YALLA_RATE_LIMIT_KEY_WRITE_BURST",
		"YALLA_RATE_LIMIT_IP_READ_RPS",
		"YALLA_RATE_LIMIT_IP_READ_BURST",
		"YALLA_RATE_LIMIT_IP_WRITE_RPS",
		"YALLA_RATE_LIMIT_IP_WRITE_BURST",
		"YALLA_RATE_LIMIT_IDLE_TTL",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
		}
	}
}

func TestProductionConfigReferenceArtifactDocumentsValidationAndRecovery(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

	for _, want := range []string{
		"E_CONFIG",
		"invalid YALLA_API_ADDR",
		"invalid YALLA_SHUTDOWN_TIMEOUT",
		"profile \"production\" requires",
		"Validation and failure recovery",
		"journalctl -u yalla-api -u yalla-worker -o json",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
		}
	}
}

func TestProductionConfigReferenceArtifactDocumentsVerificationCommands(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

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
		"go test ./internal/release/... -run TestProductionConfigReferenceArtifact",
		"scripts/verify.sh",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
		}
	}
}

func TestProductionConfigReferenceArtifactDocumentsExpectedOutputs(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

	for _, want := range []string{
		"YALLA_DATABASE_URL=<redacted:postgres-dsn>",
		"YALLA_DOKPLOY_BASE_URL=<redacted:YALLA_DOKPLOY_BASE_URL>",
		"YALLA_DOKPLOY_TOKEN=<redacted:YALLA_DOKPLOY_TOKEN>",
		"YALLA_INTERNAL_WORKER_TOKEN=<redacted:YALLA_INTERNAL_WORKER_TOKEN>",
		"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...",
		"PASS",
		"ok  ",
		"no changes",
		"HTTP/1.1 200 OK",
		"\"schema_version\":\"yalla.output.v1\"",
		"\"schema_version\":\"yalla.error.v1\"",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
		}
	}
}

func TestProductionConfigReferenceArtifactDocumentsRedactionAndRecovery(t *testing.T) {
	root := projectRoot(t)
	ref := readTextFile(t, filepath.Join(root, productionConfigReferencePath))

	for _, want := range []string{
		"must redact",
		"tokens, cookies, API keys, database URLs, Dokploy tokens",
		"Signing keys, secret-encryption keys",
		"Rendered environment variable values",
		"redacted",
		"failure recovery",
		"Normal verification gates must never require a live Dokploy server",
		"must never run against production",
	} {
		if !strings.Contains(ref, want) {
			t.Fatalf("%s missing %q", productionConfigReferencePath, want)
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
		if strings.Contains(strings.ToLower(ref), strings.ToLower(forbidden)) {
			t.Fatalf("%s must not contain rendered secret-looking value %q", productionConfigReferencePath, forbidden)
		}
	}
}

func TestProductionConfigReferenceArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestProductionConfigReferenceArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Production config reference artifact static tests",
				"go test ./internal/release/... -run TestProductionConfigReferenceArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Production Config Reference Artifact",
				productionConfigReferencePath,
				"go test ./internal/release/... -run TestProductionConfigReferenceArtifact",
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
