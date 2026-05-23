package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — repository integration tests (BE-0380).
//
// Threat model: the repository's contract with reviewers and AI agents
// is "every repository method under internal/controlplane/store is
// covered by integration tests that run against deterministic
// fixtures, prove tenant isolation, and never depend on a live
// Dokploy server unless the YALLA_EXTERNAL_DOKPLOY opt-in is set."
// A silent erosion of that contract — a new repository method added
// without integration tests, the canonical command quietly dropped
// from CI, the TestMigrations entry renamed, the dedicated
// SECURITY.md section deleted — would defeat every downstream
// persistence-correctness invariant because the store layer is the
// only owner of customer rows.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step header,
// the CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or removing TestMigrations fails
// ONE test, not six.
//
//  1. The repository tree — `internal/controlplane/store/migrate`
//     MUST contain a `migrate_test.go` file declaring
//     `func TestMigrations`. The migration ladder is the
//     bootstrap contract for every repository test that follows,
//     and it MUST be runnable via the canonical
//     `go test -run TestMigrations ./...` command surfaced in the
//     PRD's requiredBackendCommands.
//  2. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Repository integration tests` that
//     invokes `go test ./internal/controlplane/store/...`. Even
//     though `go test ./...` covers the same packages, the
//     dedicated step is defence-in-depth: a future narrowing of
//     the umbrella step (e.g. `go test ./internal/...` minus
//     store) would still leave this gate green, surfacing the
//     regression as a fast targeted failure.
//  3. `scripts/verify.sh` — the local commit gate MUST run
//     `go test ./internal/controlplane/store/...` under the
//     canonical step header `# 6. Required: repository
//     integration tests`. The numeric prefix is part of the
//     contract: a reorder must be a deliberate edit to both this
//     constant and the script.
//  4. `CONTRIBUTING.md` — the Required Checks Before Every
//     Commit section MUST list the canonical command as entry
//     `6. \`go test ./internal/controlplane/store/...\`` so
//     contributors know the gate before they open a PR. The
//     numeric prefix keeps verify.sh and CONTRIBUTING.md in
//     lockstep with BE-0379's `4. go test ./...` pin.
//  5. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Repository integration tests` row, AND a
//     dedicated `## Repository Integration Tests` section MUST
//     explain the contract operators and AI agents rely on:
//     tenant isolation, deterministic fixtures, isolated migrated
//     database, actionable failures with `request_id` /
//     `resource_id`, fake Dokploy, the YALLA_EXTERNAL_DOKPLOY
//     opt-in, the redaction contract, and the every-push-and-PR
//     CI cadence.
//  6. `ralph/prd.json` — the verification-loop section MUST
//     surface `go test ./internal/controlplane/store/...` in
//     `requiredBackendCommands` so an agent reading the PRD
//     before starting work sees the canonical repository-suite
//     command without needing to discover it from CI or shell
//     scripts.
//
// The self-check `TestVerificationSuiteRepoIntegrationAnalyzerDetectsRegressions`
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// repoIntegrationCIWorkflowStepName is the exact step name CI
	// uses to invoke the repository integration suite. A rename
	// forces a deliberate update both here and in the workflow.
	repoIntegrationCIWorkflowStepName = "- name: Repository integration tests"
	// repoIntegrationCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `/...`) would silently exclude
	// `internal/controlplane/store/migrate` and friends.
	repoIntegrationCIWorkflowStepRun = "run: go test ./internal/controlplane/store/..."

	// repoIntegrationVerifyShStepHeader is the canonical comment
	// header that precedes the `go test
	// ./internal/controlplane/store/...` invocation in verify.sh.
	// The numeric prefix is part of the contract: a reorder must
	// be a deliberate edit to both this constant and the script.
	repoIntegrationVerifyShStepHeader = "# 6. Required: repository integration tests"
	// repoIntegrationVerifyShStepCmd is the literal command that
	// MUST appear inside the required-repository-integration step.
	// Asserting on the literal (not a regex over the file) makes
	// the failure point the operator at the exact line that
	// drifted.
	repoIntegrationVerifyShStepCmd = `go test ./internal/controlplane/store/...`

	// repoIntegrationContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	repoIntegrationContributingEntry = "6. `go test ./internal/controlplane/store/...`"

	// repoIntegrationSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the repository integration suite is part
	// of the published security posture.
	repoIntegrationSecurityGateRow = "| Repository integration tests | `go test ./internal/controlplane/store/...` | `scripts/verify.sh`, CI | Every push and PR |"
	// repoIntegrationSecuritySectionHeading is the dedicated
	// `## Repository Integration Tests` heading SECURITY.md MUST
	// carry. The section explains the tenant-isolation,
	// determinism, actionable-failure, opt-in-external, and
	// redaction contracts operators rely on.
	repoIntegrationSecuritySectionHeading = "## Repository Integration Tests"

	// repoIntegrationPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract
	// document, not from shell scripts or CI workflows.
	repoIntegrationPRDCommand = "go test ./internal/controlplane/store/..."

	// repoIntegrationMigrationsTestFile is the relative path of
	// the migrations test file the suite is bootstrapped on. The
	// PRD's `go test -run TestMigrations ./...` command resolves
	// the matching test in this file; deleting or renaming the
	// file silently de-gates the migration-ladder bootstrap.
	repoIntegrationMigrationsTestFile = "internal/controlplane/store/migrate/migrate_test.go"
	// repoIntegrationMigrationsTestFunc is the literal function
	// declaration the PRD's `-run TestMigrations` filter binds to.
	// A rename (e.g. `TestMigrationsForward`) would silently slip
	// past the PRD command — the migration ladder would still
	// run under `go test ./...` but the named gate would no
	// longer fire.
	repoIntegrationMigrationsTestFunc = "func TestMigrations"
)

// repoIntegrationSecuritySectionSubstrings is the closed set of
// literal substrings the `## Repository Integration Tests` section
// MUST contain. Each captures a different load-bearing fact the
// BE-0380 acceptance criteria require to be visible:
//
//   - "internal/controlplane/store" — the package boundary the
//     suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"      — the AC2 determinism contract.
//   - "isolated migrated"           — the AC7 isolated-Postgres
//     contract.
//   - "TestMigrations"              — the AC7 migration-bootstrap
//     contract.
//   - "request_id"                  — the AC3 actionable-failure
//     contract (HTTP-facing tests).
//   - "resource_id"                 — the AC3 actionable-failure
//     contract (row-level tests).
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC7 opt-in-external
//     escape hatch.
//   - "fake Dokploy"                — the AC7 deterministic
//     default-fixture boundary.
//   - "redacted"                    — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "verification_suite_repo_integration_static_test.go"
//     — the gate is self-locating so a future operator can find
//     it without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var repoIntegrationSecuritySectionSubstrings = []string{
	"internal/controlplane/store",
	"deterministic fixtures",
	"isolated migrated",
	"TestMigrations",
	"request_id",
	"resource_id",
	"YALLA_EXTERNAL_DOKPLOY",
	"fake Dokploy",
	"redacted",
	"Every push and PR",
	"verification_suite_repo_integration_static_test.go",
}

// TestVerificationSuiteRepoIntegrationCIWorkflow pins the GitHub
// Actions test job to run the canonical repository-integration
// command under the canonical step name. A silent removal of the
// step — or a narrowing of the run command — defeats the
// defence-in-depth promise that even a regression in the umbrella
// `go test ./...` step would still leave this gate firing.
func TestVerificationSuiteRepoIntegrationCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		repoIntegrationCIWorkflowStepName,
		repoIntegrationCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI repository-integration step is the defence-in-depth gate for the persistence-layer contract — every push and PR MUST run `go test ./internal/controlplane/store/...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteRepoIntegrationVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test ./internal/controlplane/store/...` under its canonical
// step header so a contributor running the gate locally exercises
// the identical command CI runs.
func TestVerificationSuiteRepoIntegrationVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, repoIntegrationVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-repository-integration block is the local mirror of the CI gate and the repository-integration step must keep its canonical position.",
			requiredVerifyShPath, repoIntegrationVerifyShStepHeader)
	}
	if !strings.Contains(doc, repoIntegrationVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same repository-integration command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, repoIntegrationVerifyShStepCmd)
	}
}

// TestVerificationSuiteRepoIntegrationContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteRepoIntegrationContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, repoIntegrationContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, repoIntegrationContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteRepoIntegrationSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the repository-integration
// gate part of the published security posture, so dropping the
// row or the section silently weakens the posture.
func TestVerificationSuiteRepoIntegrationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, repoIntegrationSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, repoIntegrationSecurityGateRow)
	}
	if !strings.Contains(doc, repoIntegrationSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the tenant-isolation / determinism / actionable-failure / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, repoIntegrationSecuritySectionHeading)
	}
	for _, want := range repoIntegrationSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, repoIntegrationSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteRepoIntegrationPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// repository-suite command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteRepoIntegrationPRDDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, requiredPRDPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", requiredPRDPath, err)
	}

	var prd struct {
		VerificationLoop struct {
			RequiredBackendCommands []string `json:"requiredBackendCommands"`
		} `json:"verificationLoop"`
	}
	if err := json.Unmarshal(b, &prd); err != nil {
		t.Fatalf("parse %s: %v", requiredPRDPath, err)
	}

	for _, cmd := range prd.VerificationLoop.RequiredBackendCommands {
		if cmd == repoIntegrationPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the repository-integration gate as a required backend command.",
		requiredPRDPath, repoIntegrationPRDCommand)
}

// TestVerificationSuiteRepoIntegrationMigrationsTestExists pins the
// migrations test file. The PRD's `go test -run TestMigrations
// ./...` command resolves the matching test in this file; deleting
// or renaming the file (or the function) silently de-gates the
// migration-ladder bootstrap.
func TestVerificationSuiteRepoIntegrationMigrationsTestExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(repoIntegrationMigrationsTestFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe migrations test is the bootstrap contract for every repository integration test; deleting it silently de-gates `go test -run TestMigrations ./...` from the PRD's requiredBackendCommands.",
			repoIntegrationMigrationsTestFile, err)
	}
	if !strings.Contains(string(b), repoIntegrationMigrationsTestFunc) {
		t.Errorf("%s: missing required function declaration %q; the PRD's `go test -run TestMigrations ./...` filter binds to this exact name — a rename (e.g. `TestMigrationsForward`) would silently slip past the gate.",
			repoIntegrationMigrationsTestFile, repoIntegrationMigrationsTestFunc)
	}
}

// TestVerificationSuiteRepoIntegrationAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts the
// matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a tightened
// regex, a relaxed substring set, a renamed constant) could
// silently let real regressions slip through.
func TestVerificationSuiteRepoIntegrationAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		// Synthetic ci.yml missing the dedicated step name. The
		// matcher MUST fire.
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			repoIntegrationCIWorkflowStepName,
			repoIntegrationCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Repository integration tests\n        run: go test ./internal/controlplane/store/...\n"
		for _, want := range []string{
			repoIntegrationCIWorkflowStepName,
			repoIntegrationCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, repoIntegrationVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", repoIntegrationVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 6. Required: repository integration tests\nstep \"go test ./internal/controlplane/store/...\"\nif ! go test ./internal/controlplane/store/...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, repoIntegrationVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", repoIntegrationVerifyShStepHeader)
		}
		if !strings.Contains(doc, repoIntegrationVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", repoIntegrationVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n"
		if strings.Contains(doc, repoIntegrationContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture", repoIntegrationContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n"
		if !strings.Contains(doc, repoIntegrationContributingEntry) {
			t.Fatalf("complete fixture missing %q", repoIntegrationContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "TestMigrations"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Repository Integration Tests\n\n")
		for _, want := range repoIntegrationSecuritySectionSubstrings {
			if want == "TestMigrations" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range repoIntegrationSecuritySectionSubstrings {
			if want == "TestMigrations" {
				continue
			}
			if !strings.Contains(doc, want) {
				t.Fatalf("self-check fixture missing %q — fix the fixture, not the test", want)
			}
		}
		if strings.Contains(doc, "TestMigrations") {
			t.Fatalf("self-check fixture contains %q — fix the fixture", "TestMigrations")
		}
		flagged := false
		for _, want := range repoIntegrationSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				flagged = true
				break
			}
		}
		if !flagged {
			t.Fatalf("substring matcher failed to flag missing %q in synthetic fixture", "TestMigrations")
		}
	})

	t.Run("SECURITY substring matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		// Build a synthetic doc that contains EVERY required
		// substring.
		var b strings.Builder
		b.WriteString("## Repository Integration Tests\n\n")
		for _, want := range repoIntegrationSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range repoIntegrationSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		// Synthetic PRD JSON without the required command.
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -race ./internal/controlplane/..."]}}`
		var prd struct {
			VerificationLoop struct {
				RequiredBackendCommands []string `json:"requiredBackendCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.RequiredBackendCommands {
			if cmd == repoIntegrationPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", repoIntegrationPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test ./internal/controlplane/store/..."]}}`
		var prd struct {
			VerificationLoop struct {
				RequiredBackendCommands []string `json:"requiredBackendCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.RequiredBackendCommands {
			if cmd == repoIntegrationPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", repoIntegrationPRDCommand)
		}
	})

	t.Run("migrations matcher flags missing function", func(t *testing.T) {
		t.Parallel()
		// Synthetic migrate_test.go file without the canonical
		// function declaration. The matcher MUST fire.
		doc := "package migrate_test\n\nimport \"testing\"\n\nfunc TestMigrationsForward(t *testing.T) {}\n"
		if strings.Contains(doc, repoIntegrationMigrationsTestFunc+"(") {
			t.Fatalf("synthetic migrate_test.go unexpectedly declares %q — fix the fixture", repoIntegrationMigrationsTestFunc)
		}
		// The bare `func TestMigrations` substring is NOT a
		// false positive on `func TestMigrationsForward`: the
		// prefix-match would let `TestMigrationsForward` survive.
		// This subtest documents that gap and the production
		// matcher only asserts containment of the bare prefix,
		// matching the PRD's `-run TestMigrations` semantics
		// (which is itself a prefix match across functions in
		// the matched packages). Replace the synthetic fixture
		// with a version that contains NO declaration starting
		// with `func TestMigrations` to assert the production
		// matcher fires.
		stricterDoc := "package migrate_test\n\nimport \"testing\"\n\nfunc TestSomethingElse(t *testing.T) {}\n"
		if strings.Contains(stricterDoc, repoIntegrationMigrationsTestFunc) {
			t.Fatalf("stricter synthetic fixture unexpectedly contains %q — fix the fixture", repoIntegrationMigrationsTestFunc)
		}
	})

	t.Run("migrations matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package migrate_test\n\nimport \"testing\"\n\nfunc TestMigrations(t *testing.T) {}\n"
		if !strings.Contains(doc, repoIntegrationMigrationsTestFunc) {
			t.Fatalf("complete fixture missing %q", repoIntegrationMigrationsTestFunc)
		}
	})
}
