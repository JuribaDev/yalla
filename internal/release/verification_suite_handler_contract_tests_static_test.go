package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — HTTP handler contract tests (BE-0381).
//
// Threat model: the contract between Yalla's HTTP API and every
// caller (customer, AI agent, CI pipeline, downstream SDK) is
// "every public endpoint under internal/controlplane/httpapi is
// covered by a *_contract_test.go file that pins the wire envelope
// (yalla.output.v1 / yalla.error.v1), proves response data is
// written only to the http.ResponseWriter, proves the per-request
// structured log stays redacted of bearer credentials even on the
// authorization-failure path, and proves an error envelope built
// from a wrapped dependency cause never leaks that cause onto the
// wire." A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `me_contract_test.go` file removed, or the contract-triple
// function names renamed — would defeat every downstream wire
// invariant because the httpapi layer is the only surface the
// outside world ever sees.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step
// header, the CONTRIBUTING numeric prefix, the SECURITY row, the
// PRD requiredBackendCommands array, or deleting the canonical
// contract test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `HTTP handler contract tests` that
//     invokes `go test ./internal/controlplane/httpapi/...`. Even
//     though `go test ./...` covers the same packages, the
//     dedicated step is defence-in-depth: a future narrowing of
//     the umbrella step (e.g. `go test ./internal/...` minus
//     httpapi) would still leave this gate green, surfacing the
//     regression as a fast targeted failure.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test ./internal/controlplane/httpapi/...` under the
//     canonical step header `# 7. Required: HTTP handler
//     contract tests`. The numeric prefix is part of the
//     contract: a reorder must be a deliberate edit to both this
//     constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every
//     Commit section MUST list the canonical command as entry
//     `7. \`go test ./internal/controlplane/httpapi/...\`` so
//     contributors know the gate before they open a PR. The
//     numeric prefix keeps verify.sh and CONTRIBUTING.md in
//     lockstep with BE-0379's `4. go test ./...` and BE-0380's
//     `6. go test ./internal/controlplane/store/...` pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `HTTP handler contract tests` row, AND a
//     dedicated `## HTTP Handler Contract Tests` section MUST
//     explain the contract operators and AI agents rely on:
//     deterministic fixtures, fake Dokploy, the
//     YALLA_EXTERNAL_DOKPLOY opt-in, actionable failures with
//     `request_id` / `resource_id`, the contract triple
//     (`ServerWritesResponseDataOnlyToResponseWriter`,
//     `RequestLogRedactsBearerToken`,
//     `ErrorEnvelopeDoesNotLeakDependencyCause`), the
//     yalla.output.v1 / yalla.error.v1 envelope contract, the
//     redaction contract, and the every-push-and-PR CI cadence.
//  5. `ralph/prd.json` — the verification-loop section MUST
//     surface `go test ./internal/controlplane/httpapi/...` in
//     `requiredBackendCommands` so an agent reading the PRD
//     before starting work sees the canonical handler-contract
//     command without needing to discover it from CI or shell
//     scripts.
//  6. `internal/controlplane/httpapi/me_contract_test.go` —
//     the canonical reference contract test file MUST exist and
//     MUST declare the contract triple function set
//     (`TestMeServerWritesResponseDataOnlyToResponseWriter`,
//     `TestMeRequestLogRedactsBearerToken`,
//     `TestMeErrorEnvelopeDoesNotLeakDependencyCause`). The
//     `GET /v1/me` endpoint is the oldest and most-cited
//     contract example in the repo (referenced by every
//     downstream contract test for a reason); deleting the file
//     or renaming one of the triple silently kills the
//     load-bearing convention every other contract test follows.
//
// The self-check
// `TestVerificationSuiteHandlerContractAnalyzerDetectsRegressions`
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// handlerContractCIWorkflowStepName is the exact step name CI
	// uses to invoke the handler contract suite. A rename forces a
	// deliberate update both here and in the workflow.
	handlerContractCIWorkflowStepName = "- name: HTTP handler contract tests"
	// handlerContractCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `/...`) would silently exclude subpackages added
	// under internal/controlplane/httpapi.
	handlerContractCIWorkflowStepRun = "run: go test ./internal/controlplane/httpapi/..."

	// handlerContractVerifyShStepHeader is the canonical comment
	// header that precedes the `go test
	// ./internal/controlplane/httpapi/...` invocation in verify.sh.
	// The numeric prefix is part of the contract: a reorder must
	// be a deliberate edit to both this constant and the script.
	handlerContractVerifyShStepHeader = "# 7. Required: HTTP handler contract tests"
	// handlerContractVerifyShStepCmd is the literal command that
	// MUST appear inside the required-handler-contract step.
	// Asserting on the literal (not a regex over the file) makes
	// the failure point the operator at the exact line that
	// drifted.
	handlerContractVerifyShStepCmd = `go test ./internal/controlplane/httpapi/...`

	// handlerContractContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	handlerContractContributingEntry = "7. `go test ./internal/controlplane/httpapi/...`"

	// handlerContractSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the handler contract suite is part of the
	// published security posture.
	handlerContractSecurityGateRow = "| HTTP handler contract tests | `go test ./internal/controlplane/httpapi/...` | `scripts/verify.sh`, CI | Every push and PR |"
	// handlerContractSecuritySectionHeading is the dedicated
	// `## HTTP Handler Contract Tests` heading SECURITY.md MUST
	// carry. The section explains the determinism,
	// actionable-failure, contract-triple, envelope-pinning,
	// opt-in-external, and redaction contracts operators rely on.
	handlerContractSecuritySectionHeading = "## HTTP Handler Contract Tests"

	// handlerContractPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract
	// document, not from shell scripts or CI workflows.
	handlerContractPRDCommand = "go test ./internal/controlplane/httpapi/..."

	// handlerContractCanonicalFile is the relative path of the
	// canonical reference contract test file. The
	// `GET /v1/me` endpoint is the oldest and most-cited
	// contract test in the repo; deleting the file silently kills
	// the convention every other contract test follows.
	handlerContractCanonicalFile = "internal/controlplane/httpapi/me_contract_test.go"
)

// handlerContractCanonicalFuncs is the closed set of function
// declarations the canonical reference file MUST declare. Each is a
// load-bearing assertion in the contract triple:
//
//   - TestMeServerWritesResponseDataOnlyToResponseWriter — proves
//     response data is written only through the
//     http.ResponseWriter, never to stdout or stderr.
//   - TestMeRequestLogRedactsBearerToken — proves the per-request
//     structured log stays redacted of bearer credentials even on
//     the authorization-failure path.
//   - TestMeErrorEnvelopeDoesNotLeakDependencyCause — proves an
//     error envelope built from a wrapped dependency cause never
//     leaks that cause onto the wire.
//
// A refactor that drops any of the three MUST fail the gate so the
// convention every other contract test depends on stays intact.
var handlerContractCanonicalFuncs = []string{
	"func TestMeServerWritesResponseDataOnlyToResponseWriter",
	"func TestMeRequestLogRedactsBearerToken",
	"func TestMeErrorEnvelopeDoesNotLeakDependencyCause",
}

// handlerContractSecuritySectionSubstrings is the closed set of
// literal substrings the `## HTTP Handler Contract Tests` section
// MUST contain. Each captures a different load-bearing fact the
// BE-0381 acceptance criteria require to be visible:
//
//   - "internal/controlplane/httpapi" — the package boundary the
//     suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"        — the AC2 determinism
//     contract.
//   - "request_id"                    — the AC3 actionable-failure
//     contract (HTTP-facing tests).
//   - "resource_id"                   — the AC3 actionable-failure
//     contract (resource-owning endpoints).
//   - "YALLA_EXTERNAL_DOKPLOY"        — the AC7 opt-in-external
//     escape hatch.
//   - "fake Dokploy"                  — the AC7 deterministic
//     default-fixture boundary.
//   - "yalla.output.v1"               — the AC5 success-envelope
//     contract.
//   - "yalla.error.v1"                — the AC5 error-envelope
//     contract.
//   - "ServerWritesResponseDataOnlyToResponseWriter" — the
//     contract-triple member that pins "no writes to stdout".
//   - "RequestLogRedactsBearerToken" — the contract-triple member
//     that pins "log stays redacted on the auth-failure path".
//   - "ErrorEnvelopeDoesNotLeakDependencyCause" — the
//     contract-triple member that pins "wrapped cause never reaches
//     the wire".
//   - "redacted"                      — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"             — the AC4 CI gating cadence.
//   - "verification_suite_handler_contract_tests_static_test.go"
//     — the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var handlerContractSecuritySectionSubstrings = []string{
	"internal/controlplane/httpapi",
	"deterministic fixtures",
	"request_id",
	"resource_id",
	"YALLA_EXTERNAL_DOKPLOY",
	"fake Dokploy",
	"yalla.output.v1",
	"yalla.error.v1",
	"ServerWritesResponseDataOnlyToResponseWriter",
	"RequestLogRedactsBearerToken",
	"ErrorEnvelopeDoesNotLeakDependencyCause",
	"redacted",
	"Every push and PR",
	"verification_suite_handler_contract_tests_static_test.go",
}

// TestVerificationSuiteHandlerContractCIWorkflow pins the GitHub
// Actions test job to run the canonical handler-contract command
// under the canonical step name. A silent removal of the step — or
// a narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuiteHandlerContractCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		handlerContractCIWorkflowStepName,
		handlerContractCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI HTTP-handler-contract step is the defence-in-depth gate for the wire-contract surface — every push and PR MUST run `go test ./internal/controlplane/httpapi/...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteHandlerContractVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test ./internal/controlplane/httpapi/...` under its
// canonical step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteHandlerContractVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, handlerContractVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-handler-contract block is the local mirror of the CI gate and the handler-contract step must keep its canonical position.",
			requiredVerifyShPath, handlerContractVerifyShStepHeader)
	}
	if !strings.Contains(doc, handlerContractVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same handler-contract command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, handlerContractVerifyShStepCmd)
	}
}

// TestVerificationSuiteHandlerContractContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteHandlerContractContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, handlerContractContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, handlerContractContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteHandlerContractSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the handler-contract gate part
// of the published security posture, so dropping the row or the
// section silently weakens the posture.
func TestVerificationSuiteHandlerContractSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, handlerContractSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, handlerContractSecurityGateRow)
	}
	if !strings.Contains(doc, handlerContractSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the determinism / actionable-failure / contract-triple / envelope-pinning / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, handlerContractSecuritySectionHeading)
	}
	for _, want := range handlerContractSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, handlerContractSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteHandlerContractPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// handler-contract command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteHandlerContractPRDDocumentsCommand(t *testing.T) {
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
		if cmd == handlerContractPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the handler-contract gate as a required backend command.",
		requiredPRDPath, handlerContractPRDCommand)
}

// TestVerificationSuiteHandlerContractCanonicalFileExists pins the
// canonical reference contract test file and its load-bearing
// function triple. Deleting the file or renaming any of the three
// functions silently kills the convention every other contract
// test follows.
func TestVerificationSuiteHandlerContractCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(handlerContractCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical contract test file is the load-bearing convention every other *_contract_test.go file follows; deleting it silently removes the pattern future contract tests must mirror.",
			handlerContractCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range handlerContractCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the contract triple is the load-bearing assertion set every endpoint MUST keep — a rename or deletion silently relaxes the wire contract for every downstream contract test.",
				handlerContractCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteHandlerContractAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher
// fires (or stays silent) correctly. Without this self-check a
// future "improvement" to the matchers (a tightened regex, a
// relaxed substring set, a renamed constant) could silently let
// real regressions slip through.
func TestVerificationSuiteHandlerContractAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			handlerContractCIWorkflowStepName,
			handlerContractCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: HTTP handler contract tests\n        run: go test ./internal/controlplane/httpapi/...\n"
		for _, want := range []string{
			handlerContractCIWorkflowStepName,
			handlerContractCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, handlerContractVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", handlerContractVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 7. Required: HTTP handler contract tests\nstep \"go test ./internal/controlplane/httpapi/...\"\nif ! go test ./internal/controlplane/httpapi/...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, handlerContractVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", handlerContractVerifyShStepHeader)
		}
		if !strings.Contains(doc, handlerContractVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", handlerContractVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n"
		if strings.Contains(doc, handlerContractContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture", handlerContractContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n"
		if !strings.Contains(doc, handlerContractContributingEntry) {
			t.Fatalf("complete fixture missing %q", handlerContractContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## HTTP Handler Contract Tests\n\n")
		for _, want := range handlerContractSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range handlerContractSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			if !strings.Contains(doc, want) {
				t.Fatalf("self-check fixture missing %q — fix the fixture, not the test", want)
			}
		}
		if strings.Contains(doc, "yalla.output.v1") {
			t.Fatalf("self-check fixture contains %q — fix the fixture", "yalla.output.v1")
		}
		flagged := false
		for _, want := range handlerContractSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				flagged = true
				break
			}
		}
		if !flagged {
			t.Fatalf("substring matcher failed to flag missing %q in synthetic fixture", "yalla.output.v1")
		}
	})

	t.Run("SECURITY substring matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## HTTP Handler Contract Tests\n\n")
		for _, want := range handlerContractSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range handlerContractSecuritySectionSubstrings {
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
			if cmd == handlerContractPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", handlerContractPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test ./internal/controlplane/httpapi/..."]}}`
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
			if cmd == handlerContractPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", handlerContractPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing triple member", func(t *testing.T) {
		t.Parallel()
		// Synthetic me_contract_test.go declaring only two of the
		// three triple functions. The matcher MUST fire on the
		// missing third.
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestMeServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {}\nfunc TestMeRequestLogRedactsBearerToken(t *testing.T) {}\n"
		missing := 0
		for _, want := range handlerContractCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every triple member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestMeServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {}\nfunc TestMeRequestLogRedactsBearerToken(t *testing.T) {}\nfunc TestMeErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {}\n"
		for _, want := range handlerContractCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q", want)
			}
		}
	})
}
