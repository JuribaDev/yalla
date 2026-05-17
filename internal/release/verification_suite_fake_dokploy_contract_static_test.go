package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — fake Dokploy contract tests (BE-0386).
//
// Threat model: the contract between Yalla's fake Dokploy
// (`internal/controlplane/dokploy/dokployfake`) and every operator,
// AI agent, CI pipeline, downstream SDK, and future frontend is
// "every worker/handler/agent test exercising Dokploy-shaped
// behaviour runs against the deterministic in-memory fake — never
// a live Dokploy server — and every request the recorder captures
// has its bearer token replaced by the shared output sentinel
// before it can land in a CI log, an audit metadata blob, or a
// developer's terminal." That invariant is enforced by the
// `dokployfake.New()` constructor (deterministic per-server state,
// monotonically incremented hierarchy IDs that restart from 1 in
// every fresh server) and by the recorder hot path that rewrites
// the Authorization header to `output.Sentinel` before the request
// row enters `Server.Requests()`. A silent erosion of that contract
// — the dedicated CI step quietly dropped, the verify.sh entry
// renumbered without updating CONTRIBUTING.md, the SECURITY.md
// section deleted, the canonical `dokployfake_test.go` file removed,
// or the canonical `TestFakeDokployContract…` function pair renamed
// — would let a fake regression (a per-server counter promoted to a
// global, a recorder seam that forgets to redact headers on a
// specific status code) ship without firing any gate.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step
// header, the CONTRIBUTING numeric prefix, the SECURITY row, the
// PRD requiredBackendCommands array, or deleting the canonical
// fake-Dokploy test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Fake Dokploy contract tests` that
//     invokes `go test -run TestFakeDokploy ./...`. Even though
//     `go test ./...` covers the same packages, the dedicated step
//     is defence-in-depth: a future narrowing of the umbrella step
//     (e.g. `go test ./internal/...` minus dokployfake) would still
//     leave this gate green, surfacing the regression as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestFakeDokploy ./...` under the canonical
//     step header `# 12. Required: fake Dokploy contract tests`.
//     The numeric prefix is part of the contract: a reorder must
//     be a deliberate edit to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `12. \`go test -run TestFakeDokploy ./...\`` so
//     contributors know the gate before they open a PR. The
//     numeric prefix keeps verify.sh and CONTRIBUTING.md in
//     lockstep with BE-0379's `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, BE-0381's
//     `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
//     `8. go test ./internal/controlplane/openapi/...`, BE-0383's
//     `9. go test -run TestPolicyMatrix ./...`, BE-0384's
//     `10. go test -run TestQuotaConcurrency ./...`, and
//     BE-0385's `11. go test -run TestJobWorkerLease ./...` pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Fake Dokploy contract tests` row, AND a
//     dedicated `## Fake Dokploy Contract Tests` section MUST
//     explain the contract operators, auditors, and AI agents rely
//     on: the determinism invariant, the recorder-redaction
//     invariant, deterministic Postgres-migration fixtures (no
//     live Dokploy), opt-in `YALLA_EXTERNAL_DOKPLOY` external
//     smoke, redaction, and the CI-on-every-push-and-PR cadence.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestFakeDokploy ./...` so an AI agent reading
//     the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/dokploy/dokployfake/dokployfake_test.go`
//     — the canonical reference fake-Dokploy test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestFakeDokployContractDeterministicHierarchyIDs`,
//     `TestFakeDokployContractRecordedRequestsRedactCredentials`).
//     The PRD's `go test -run TestFakeDokploy ./...` filter binds
//     to the `TestFakeDokploy…` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     fake-Dokploy suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteFakeDokployContractAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// fakeDokployContractCIWorkflowStepName is the exact step name
	// CI uses to invoke the fake-Dokploy contract suite. A rename
	// forces a deliberate update both here and in the workflow.
	fakeDokployContractCIWorkflowStepName = "- name: Fake Dokploy contract tests"
	// fakeDokployContractCIWorkflowStepRun is the literal command
	// the step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future package
	// that declares a `TestFakeDokploy…` test.
	fakeDokployContractCIWorkflowStepRun = "run: go test -run TestFakeDokploy ./..."

	// fakeDokployContractVerifyShStepHeader is the canonical
	// comment header that precedes the
	// `go test -run TestFakeDokploy ./...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and
	// the script.
	fakeDokployContractVerifyShStepHeader = "# 12. Required: fake Dokploy contract tests"
	// fakeDokployContractVerifyShStepCmd is the literal command
	// that MUST appear inside the required-fake-Dokploy step.
	// Asserting on the literal (not a regex over the file) makes
	// the failure point the operator at the exact line that
	// drifted.
	fakeDokployContractVerifyShStepCmd = `go test -run TestFakeDokploy ./...`

	// fakeDokployContractContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	fakeDokployContractContributingEntry = "12. `go test -run TestFakeDokploy ./...`"

	// fakeDokployContractSecurityGateRow is the verification-gates
	// row that MUST appear in SECURITY.md so external operators
	// and reviewers can see the fake-Dokploy contract suite is
	// part of the published security posture.
	fakeDokployContractSecurityGateRow = "| Fake Dokploy contract tests | `go test -run TestFakeDokploy ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// fakeDokployContractSecuritySectionHeading is the dedicated
	// `## Fake Dokploy Contract Tests` heading SECURITY.md MUST
	// carry. The section explains the determinism invariant, the
	// recorder-redaction invariant, the actionable-failure
	// contract, the opt-in-external escape hatch, and the
	// schema-version contract.
	fakeDokployContractSecuritySectionHeading = "## Fake Dokploy Contract Tests"

	// fakeDokployContractPRDCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	fakeDokployContractPRDCommand = "go test -run TestFakeDokploy ./..."

	// fakeDokployContractCanonicalFile is the relative path of the
	// canonical reference fake-Dokploy test file. The
	// `internal/controlplane/dokploy/dokployfake/dokployfake_test.go`
	// file declares the function pair every other fake-Dokploy
	// test pivots on; deleting it silently kills the convention
	// future fake-Dokploy tests must mirror.
	fakeDokployContractCanonicalFile = "internal/controlplane/dokploy/dokployfake/dokployfake_test.go"
)

// fakeDokployContractCanonicalFuncs is the closed set of function
// declarations the canonical `dokployfake_test.go` file MUST
// carry. The PRD's `-run TestFakeDokploy` filter binds to function
// names containing the `TestFakeDokploy` substring; renaming any
// entry to a name that does not match the prefix silently de-gates
// the fake-Dokploy suite for any caller relying on the filter. The
// pair captures the two load-bearing fake-Dokploy invariants the
// fake MUST keep:
//
//   - TestFakeDokployContractDeterministicHierarchyIDs — two
//     independent `dokployfake.New()` servers driven through the
//     same org -> project -> environment -> application ->
//     deployment chain mint byte-identical resource IDs at every
//     level (org_1, proj_1, env_1, app_1, dep_1) while keeping
//     per-server state isolated. The determinism is what makes the
//     fake usable as a deterministic fixture — every test that
//     drives the same call sequence sees the same IDs across runs
//     and across goroutines.
//   - TestFakeDokployContractRecordedRequestsRedactCredentials —
//     the recorder swaps the Authorization header for
//     `output.Sentinel` and scans the body for the bearer literal
//     before any caller reads `Server.Requests()` back. The
//     contract holds across every kind of request the worker
//     might issue (creates that succeed, creates that 4xx, GETs
//     that return read-back state).
var fakeDokployContractCanonicalFuncs = []string{
	"func TestFakeDokployContractDeterministicHierarchyIDs(",
	"func TestFakeDokployContractRecordedRequestsRedactCredentials(",
}

// fakeDokployContractSecuritySectionSubstrings is the closed set
// of literal substrings the `## Fake Dokploy Contract Tests`
// section MUST contain. Each captures a different load-bearing
// fact the BE-0386 acceptance criteria require to be visible:
//
//   - "internal/controlplane/dokploy/dokployfake" — the package
//     boundary the suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"      — the AC2 determinism
//     contract.
//   - "dokployfake.New"             — the constructor that mints
//     the fixture; deleting it would break every worker test.
//   - "Server.Requests"             — the recorder seam the
//     redaction contract is enforced through.
//   - "output.Sentinel"             — the shared redaction
//     sentinel; a different substitute would silently lose the
//     stable contract every other redaction story relies on.
//   - "resource_id"                 — the actionable-failure
//     identifier every fake-Dokploy diagnostic surfaces.
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC2 opt-in-external
//     escape hatch.
//   - "TestLiveDokploySmoke"        — the opt-in external test
//     name (the PRD's
//     verificationLoop.optionalWhenConfigured names it).
//   - "yalla.output.v1"             — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"              — the AC5 error envelope
//     schema_version contract.
//   - "TestFakeDokployContractDeterministicHierarchyIDs" — the
//     canonical determinism function the -run filter binds to.
//   - "TestFakeDokployContractRecordedRequestsRedactCredentials"
//     — the canonical recorder-redaction function that pins the
//     no-leaked-bearer invariant.
//   - "redacted"                    — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "verification_suite_fake_dokploy_contract_static_test.go"
//     — the gate is self-locating so a future operator can find
//     it without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var fakeDokployContractSecuritySectionSubstrings = []string{
	"internal/controlplane/dokploy/dokployfake",
	"deterministic fixtures",
	"dokployfake.New",
	"Server.Requests",
	"output.Sentinel",
	"resource_id",
	"YALLA_EXTERNAL_DOKPLOY",
	"TestLiveDokploySmoke",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestFakeDokployContractDeterministicHierarchyIDs",
	"TestFakeDokployContractRecordedRequestsRedactCredentials",
	"redacted",
	"Every push and PR",
	"verification_suite_fake_dokploy_contract_static_test.go",
}

// TestVerificationSuiteFakeDokployContractCIWorkflow pins the
// GitHub Actions test job to run the canonical fake-Dokploy
// contract command under the canonical step name. A silent
// removal of the step — or a narrowing of the run command —
// defeats the defence-in-depth promise that even a regression in
// the umbrella `go test ./...` step would still leave this gate
// firing.
func TestVerificationSuiteFakeDokployContractCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		fakeDokployContractCIWorkflowStepName,
		fakeDokployContractCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI fake-Dokploy-contract step is the defence-in-depth gate for the determinism + recorder-redaction invariant — every push and PR MUST run `go test -run TestFakeDokploy ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteFakeDokployContractVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestFakeDokploy ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteFakeDokployContractVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, fakeDokployContractVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-fake-Dokploy block is the local mirror of the CI gate and the fake-Dokploy step must keep its canonical position.",
			requiredVerifyShPath, fakeDokployContractVerifyShStepHeader)
	}
	if !strings.Contains(doc, fakeDokployContractVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same fake-Dokploy command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, fakeDokployContractVerifyShStepCmd)
	}
}

// TestVerificationSuiteFakeDokployContractContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteFakeDokployContractContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, fakeDokployContractContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, fakeDokployContractContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteFakeDokployContractSecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the fake-Dokploy contract
// gate part of the published security posture, so dropping the
// row or the section silently weakens the posture.
func TestVerificationSuiteFakeDokployContractSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, fakeDokployContractSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, fakeDokployContractSecurityGateRow)
	}
	if !strings.Contains(doc, fakeDokployContractSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the determinism / recorder-redaction / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, fakeDokployContractSecuritySectionHeading)
	}
	for _, want := range fakeDokployContractSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, fakeDokployContractSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteFakeDokployContractPRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI
// agent reading the PRD before picking up a story sees the
// canonical fake-Dokploy command without needing to discover it
// from CI workflows or shell scripts.
func TestVerificationSuiteFakeDokployContractPRDDocumentsCommand(t *testing.T) {
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
		if cmd == fakeDokployContractPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the fake-Dokploy contract gate as a required backend command.",
		requiredPRDPath, fakeDokployContractPRDCommand)
}

// TestVerificationSuiteFakeDokployContractCanonicalFileExists pins
// the canonical reference fake-Dokploy test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestFakeDokploy`
// prefix silently de-gates the fake-Dokploy suite for any caller
// relying on the PRD's `-run TestFakeDokploy` filter.
func TestVerificationSuiteFakeDokployContractCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(fakeDokployContractCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical fake-Dokploy test file is the load-bearing convention every other fake-Dokploy test pivots on; deleting it silently removes the pattern future fake-Dokploy tests must mirror.",
			fakeDokployContractCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range fakeDokployContractCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the fake-Dokploy pair is the load-bearing assertion set every fake-Dokploy regression MUST trip — a rename or deletion silently relaxes the determinism + recorder-redaction contract for every downstream caller.",
				fakeDokployContractCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteFakeDokployContractAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts the
// matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a tightened
// regex, a relaxed substring set, a renamed constant) could
// silently let real regressions slip through.
func TestVerificationSuiteFakeDokployContractAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			fakeDokployContractCIWorkflowStepName,
			fakeDokployContractCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Fake Dokploy contract tests\n        run: go test -run TestFakeDokploy ./...\n"
		for _, want := range []string{
			fakeDokployContractCIWorkflowStepName,
			fakeDokployContractCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, fakeDokployContractVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", fakeDokployContractVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 12. Required: fake Dokploy contract tests\nstep \"go test -run TestFakeDokploy ./...\"\nif ! go test -run TestFakeDokploy ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, fakeDokployContractVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", fakeDokployContractVerifyShStepHeader)
		}
		if !strings.Contains(doc, fakeDokployContractVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", fakeDokployContractVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n"
		if strings.Contains(doc, fakeDokployContractContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", fakeDokployContractContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n"
		if !strings.Contains(doc, fakeDokployContractContributingEntry) {
			t.Fatalf("complete fixture missing %q", fakeDokployContractContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Fake Dokploy Contract Tests\n\n")
		for _, want := range fakeDokployContractSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range fakeDokployContractSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic SECURITY.md unexpectedly contains every required substring — fix the fixture, not the test")
		}
	})

	t.Run("SECURITY substring matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Fake Dokploy Contract Tests\n\n")
		for _, want := range fakeDokployContractSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range fakeDokployContractSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
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
			if cmd == fakeDokployContractPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", fakeDokployContractPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestFakeDokploy ./..."]}}`
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
			if cmd == fakeDokployContractPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", fakeDokployContractPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic dokployfake_test.go declaring only one of the
		// two fake-Dokploy functions. The matcher MUST fire on the
		// missing second.
		doc := "package dokployfake_test\n\nimport \"testing\"\n\nfunc TestFakeDokployContractDeterministicHierarchyIDs(t *testing.T) {}\n"
		missing := 0
		for _, want := range fakeDokployContractCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every fake-Dokploy-pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package dokployfake_test\n\nimport \"testing\"\n\nfunc TestFakeDokployContractDeterministicHierarchyIDs(t *testing.T) {}\nfunc TestFakeDokployContractRecordedRequestsRedactCredentials(t *testing.T) {}\n"
		for _, want := range fakeDokployContractCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestFakeDokploy prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestFakeDokploy ./...` filter
		// binds to function names containing the `TestFakeDokploy`
		// substring. A canonical-funcs entry that drops the prefix
		// would silently de-gate the fake-Dokploy suite for any
		// caller relying on the filter. This subtest asserts every
		// canonical-funcs entry begins with `func TestFakeDokploy`.
		const wantPrefix = "func TestFakeDokploy"
		for _, want := range fakeDokployContractCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestFakeDokploy` filter binds to the `TestFakeDokploy` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
