package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — OpenAPI schema conformance tests (BE-0382).
//
// Threat model: the contract between Yalla's published
// `/openapi.json` document and every caller (customer, AI agent,
// CI pipeline, downstream SDK, generated client) is "every
// documented HTTP operation the `internal/controlplane/openapi`
// package surfaces is covered by a canonical conformance test that
// pins the OpenAPI 3.1 identity, the
// `yalla.output.v1` / `yalla.error.v1` envelope schema_version
// enums, the `ApiKeyAuth` security wiring for authenticated
// operations, the `x-required-action` extension that names the
// policy action each operation authorizes, the required-string-in-
// path shape of every path parameter, and the redaction of every
// example body that resembles a credential." A silent erosion of
// that contract — the dedicated CI step quietly dropped, the
// verify.sh entry renumbered without updating CONTRIBUTING.md, the
// SECURITY.md section deleted, the canonical
// `openapi_conformance_test.go` file removed, or the conformance
// triple function names renamed — would defeat every downstream
// SDK contract because the published document is the only
// machine-readable view of the API every external caller sees.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step
// header, the CONTRIBUTING numeric prefix, the SECURITY row, the
// PRD requiredBackendCommands array, or deleting the canonical
// conformance test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `OpenAPI schema conformance tests`
//     that invokes `go test ./internal/controlplane/openapi/...`.
//     Even though `go test ./...` covers the same packages, the
//     dedicated step is defence-in-depth: a future narrowing of
//     the umbrella step (e.g. `go test ./internal/...` minus
//     openapi) would still leave this gate green, surfacing the
//     regression as a fast targeted failure.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test ./internal/controlplane/openapi/...` under the
//     canonical step header `# 8. Required: OpenAPI schema
//     conformance tests`. The numeric prefix is part of the
//     contract: a reorder must be a deliberate edit to both this
//     constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every
//     Commit section MUST list the canonical command as entry
//     `8. \`go test ./internal/controlplane/openapi/...\`` so
//     contributors know the gate before they open a PR. The
//     numeric prefix keeps verify.sh and CONTRIBUTING.md in
//     lockstep with BE-0379's `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, and
//     BE-0381's `7. go test ./internal/controlplane/httpapi/...`
//     pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `OpenAPI schema conformance tests` row, AND a
//     dedicated `## OpenAPI Schema Conformance Tests` section
//     MUST explain the contract operators, auditors, and AI
//     agents rely on: deterministic fixtures,
//     `yalla.output.v1` / `yalla.error.v1` envelope pinning, the
//     conformance triple, `x-required-action`, path-parameter
//     shape, redaction, opt-in `YALLA_EXTERNAL_DOKPLOY` external
//     smoke, and the CI-on-every-push-and-PR cadence.
//  5. `ralph/prd.json` — `verificationLoop.requiredBackendCommands`
//     MUST list `go test ./internal/controlplane/openapi/...` so
//     an AI agent reading the PRD before picking up a story sees
//     the canonical command without needing to discover it from
//     CI workflows or shell scripts.
//  6. `internal/controlplane/openapi/openapi_conformance_test.go`
//     — the canonical reference conformance test file MUST exist
//     and MUST declare the load-bearing function triple
//     (`TestOpenAPIConformance`,
//     `TestOpenAPIEnvelopesReferenceStableSchemaVersions`,
//     `TestOpenAPIExamplesAreRedacted`). The PRD's
//     `go test -run TestOpenAPI ./...` filter binds to the
//     `TestOpenAPI…` prefix; a rename to a function whose name
//     does not match the prefix silently de-gates the conformance
//     suite for any caller relying on the `-run` filter.
//
// The self-check (`TestVerificationSuiteOpenAPIConformanceAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// openapiConformanceCIWorkflowStepName is the exact step name
	// CI uses to invoke the OpenAPI conformance suite. A rename
	// forces a deliberate update both here and in the workflow.
	openapiConformanceCIWorkflowStepName = "- name: OpenAPI schema conformance tests"
	// openapiConformanceCIWorkflowStepRun is the literal command
	// the step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `/...`) would silently exclude subpackages added
	// under internal/controlplane/openapi.
	openapiConformanceCIWorkflowStepRun = "run: go test ./internal/controlplane/openapi/..."

	// openapiConformanceVerifyShStepHeader is the canonical
	// comment header that precedes the
	// `go test ./internal/controlplane/openapi/...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and
	// the script.
	openapiConformanceVerifyShStepHeader = "# 8. Required: OpenAPI schema conformance tests"
	// openapiConformanceVerifyShStepCmd is the literal command
	// that MUST appear inside the required-OpenAPI-conformance
	// step. Asserting on the literal (not a regex over the file)
	// makes the failure point the operator at the exact line that
	// drifted.
	openapiConformanceVerifyShStepCmd = `go test ./internal/controlplane/openapi/...`

	// openapiConformanceContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	openapiConformanceContributingEntry = "8. `go test ./internal/controlplane/openapi/...`"

	// openapiConformanceSecurityGateRow is the verification-gates
	// row that MUST appear in SECURITY.md so external operators
	// and reviewers can see the OpenAPI conformance suite is part
	// of the published security posture.
	openapiConformanceSecurityGateRow = "| OpenAPI schema conformance tests | `go test ./internal/controlplane/openapi/...` | `scripts/verify.sh`, CI | Every push and PR |"
	// openapiConformanceSecuritySectionHeading is the dedicated
	// `## OpenAPI Schema Conformance Tests` heading SECURITY.md
	// MUST carry. The section explains the determinism,
	// actionable-failure, conformance-triple, envelope-pinning,
	// opt-in-external, and redaction contracts operators rely on.
	openapiConformanceSecuritySectionHeading = "## OpenAPI Schema Conformance Tests"

	// openapiConformancePRDCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	openapiConformancePRDCommand = "go test ./internal/controlplane/openapi/..."

	// openapiConformanceCanonicalFile is the relative path of the
	// canonical reference conformance test file. The
	// `internal/controlplane/openapi/openapi_conformance_test.go`
	// file declares the conformance triple every other openapi
	// test pivots on; deleting it silently kills the convention
	// future conformance tests must mirror.
	openapiConformanceCanonicalFile = "internal/controlplane/openapi/openapi_conformance_test.go"
)

// openapiConformanceCanonicalFuncs is the closed set of function
// declarations the canonical
// `openapi_conformance_test.go` file MUST carry. The PRD's
// `-run TestOpenAPI` filter binds to the `TestOpenAPI` prefix;
// renaming any entry to a name that does not match the prefix
// silently de-gates the conformance suite for any caller relying
// on the filter. The triple captures the three load-bearing wire
// invariants the published `/openapi.json` artifact MUST keep:
//
//   - TestOpenAPIConformance — every documented operation has a
//     success response and a stable error envelope response,
//     authenticated operations require ApiKeyAuth and declare
//     x-required-action, public operations advertise explicit
//     empty security, and every path parameter is required string
//     in path.
//   - TestOpenAPIEnvelopesReferenceStableSchemaVersions — the
//     envelope component schemas pin the schema_version enum to
//     the published `output.SuccessSchema` /
//     `yerr.SchemaVersion` constants.
//   - TestOpenAPIExamplesAreRedacted — every example body that
//     resembles a credential is rendered through `output.Sentinel`
//     and no credential-shaped token appears in the marshalled
//     document.
var openapiConformanceCanonicalFuncs = []string{
	"func TestOpenAPIConformance(",
	"func TestOpenAPIEnvelopesReferenceStableSchemaVersions(",
	"func TestOpenAPIExamplesAreRedacted(",
}

// openapiConformanceSecuritySectionSubstrings is the closed set of
// literal substrings the
// `## OpenAPI Schema Conformance Tests` section MUST contain. Each
// captures a different load-bearing fact the BE-0382 acceptance
// criteria require to be visible:
//
//   - "internal/controlplane/openapi" — the package boundary the
//     suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"        — the AC2 determinism
//     contract.
//   - "operationId"                   — the AC3 actionable-failure
//     contract (the failing operationId surfaces in every
//     diagnostic so an operator can map the failure to the exact
//     documented endpoint without re-running the suite).
//   - "x-required-action"             — the AC6
//     authorization-failure / policy-action contract (the OpenAPI
//     extension that names the policy action every authenticated
//     operation authorizes).
//   - "YALLA_EXTERNAL_DOKPLOY"        — the AC7 opt-in-external
//     escape hatch.
//   - "yalla.output.v1"               — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"                — the AC5 error envelope
//     schema_version contract.
//   - "TestOpenAPIConformance"        — the conformance-triple
//     member that pins end-to-end document conformance.
//   - "TestOpenAPIEnvelopesReferenceStableSchemaVersions" — the
//     conformance-triple member that pins the schema_version
//     enums against the published Go constants.
//   - "TestOpenAPIExamplesAreRedacted" — the conformance-triple
//     member that pins "no credential-shaped token in the
//     marshalled document".
//   - "redacted"                      — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"             — the AC4 CI gating cadence.
//   - "verification_suite_openapi_conformance_static_test.go"
//     — the gate is self-locating so a future operator can find
//     it without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var openapiConformanceSecuritySectionSubstrings = []string{
	"internal/controlplane/openapi",
	"deterministic fixtures",
	"operationId",
	"x-required-action",
	"YALLA_EXTERNAL_DOKPLOY",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestOpenAPIConformance",
	"TestOpenAPIEnvelopesReferenceStableSchemaVersions",
	"TestOpenAPIExamplesAreRedacted",
	"redacted",
	"Every push and PR",
	"verification_suite_openapi_conformance_static_test.go",
}

// TestVerificationSuiteOpenAPIConformanceCIWorkflow pins the
// GitHub Actions test job to run the canonical OpenAPI conformance
// command under the canonical step name. A silent removal of the
// step — or a narrowing of the run command — defeats the
// defence-in-depth promise that even a regression in the umbrella
// `go test ./...` step would still leave this gate firing.
func TestVerificationSuiteOpenAPIConformanceCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		openapiConformanceCIWorkflowStepName,
		openapiConformanceCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI OpenAPI-conformance step is the defence-in-depth gate for the published-document surface — every push and PR MUST run `go test ./internal/controlplane/openapi/...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteOpenAPIConformanceVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test ./internal/controlplane/openapi/...` under its canonical
// step header so a contributor running the gate locally exercises
// the identical command CI runs.
func TestVerificationSuiteOpenAPIConformanceVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, openapiConformanceVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-OpenAPI-conformance block is the local mirror of the CI gate and the OpenAPI-conformance step must keep its canonical position.",
			requiredVerifyShPath, openapiConformanceVerifyShStepHeader)
	}
	if !strings.Contains(doc, openapiConformanceVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same OpenAPI-conformance command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, openapiConformanceVerifyShStepCmd)
	}
}

// TestVerificationSuiteOpenAPIConformanceContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteOpenAPIConformanceContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, openapiConformanceContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, openapiConformanceContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteOpenAPIConformanceSecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the OpenAPI-conformance gate
// part of the published security posture, so dropping the row or
// the section silently weakens the posture.
func TestVerificationSuiteOpenAPIConformanceSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, openapiConformanceSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, openapiConformanceSecurityGateRow)
	}
	if !strings.Contains(doc, openapiConformanceSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the determinism / actionable-failure / conformance-triple / envelope-pinning / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, openapiConformanceSecuritySectionHeading)
	}
	for _, want := range openapiConformanceSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, openapiConformanceSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteOpenAPIConformancePRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI
// agent reading the PRD before picking up a story sees the
// canonical OpenAPI-conformance command without needing to
// discover it from CI workflows or shell scripts.
func TestVerificationSuiteOpenAPIConformancePRDDocumentsCommand(t *testing.T) {
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
		if cmd == openapiConformancePRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the OpenAPI-conformance gate as a required backend command.",
		requiredPRDPath, openapiConformancePRDCommand)
}

// TestVerificationSuiteOpenAPIConformanceCanonicalFileExists pins
// the canonical reference conformance test file and its
// load-bearing function triple. Deleting the file or renaming any
// of the three functions to a name that does not match the
// `TestOpenAPI` prefix silently de-gates the conformance suite for
// any caller relying on the PRD's `-run TestOpenAPI` filter.
func TestVerificationSuiteOpenAPIConformanceCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(openapiConformanceCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical conformance test file is the load-bearing convention every other OpenAPI test pivots on; deleting it silently removes the pattern future conformance tests must mirror.",
			openapiConformanceCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range openapiConformanceCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the conformance triple is the load-bearing assertion set every documented operation MUST keep — a rename or deletion silently relaxes the wire contract for every downstream SDK or AI agent reading the published document.",
				openapiConformanceCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteOpenAPIConformanceAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts the
// matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a tightened
// regex, a relaxed substring set, a renamed constant) could
// silently let real regressions slip through.
func TestVerificationSuiteOpenAPIConformanceAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			openapiConformanceCIWorkflowStepName,
			openapiConformanceCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: OpenAPI schema conformance tests\n        run: go test ./internal/controlplane/openapi/...\n"
		for _, want := range []string{
			openapiConformanceCIWorkflowStepName,
			openapiConformanceCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, openapiConformanceVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", openapiConformanceVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 8. Required: OpenAPI schema conformance tests\nstep \"go test ./internal/controlplane/openapi/...\"\nif ! go test ./internal/controlplane/openapi/...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, openapiConformanceVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", openapiConformanceVerifyShStepHeader)
		}
		if !strings.Contains(doc, openapiConformanceVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", openapiConformanceVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n"
		if strings.Contains(doc, openapiConformanceContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", openapiConformanceContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n"
		if !strings.Contains(doc, openapiConformanceContributingEntry) {
			t.Fatalf("complete fixture missing %q", openapiConformanceContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## OpenAPI Schema Conformance Tests\n\n")
		for _, want := range openapiConformanceSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range openapiConformanceSecuritySectionSubstrings {
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
		b.WriteString("## OpenAPI Schema Conformance Tests\n\n")
		for _, want := range openapiConformanceSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range openapiConformanceSecuritySectionSubstrings {
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
			if cmd == openapiConformancePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", openapiConformancePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test ./internal/controlplane/openapi/..."]}}`
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
			if cmd == openapiConformancePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", openapiConformancePRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing triple member", func(t *testing.T) {
		t.Parallel()
		// Synthetic openapi_conformance_test.go declaring only two
		// of the three triple functions. The matcher MUST fire on
		// the missing third.
		doc := "package openapi\n\nimport \"testing\"\n\nfunc TestOpenAPIConformance(t *testing.T) {}\nfunc TestOpenAPIEnvelopesReferenceStableSchemaVersions(t *testing.T) {}\n"
		missing := 0
		for _, want := range openapiConformanceCanonicalFuncs {
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
		doc := "package openapi\n\nimport \"testing\"\n\nfunc TestOpenAPIConformance(t *testing.T) {}\nfunc TestOpenAPIEnvelopesReferenceStableSchemaVersions(t *testing.T) {}\nfunc TestOpenAPIExamplesAreRedacted(t *testing.T) {}\n"
		for _, want := range openapiConformanceCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestOpenAPI prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestOpenAPI ./...` filter binds
		// to function names containing the `TestOpenAPI` substring.
		// A canonical-funcs entry that drops the prefix would
		// silently de-gate the conformance suite for any caller
		// relying on the filter. This subtest asserts every
		// canonical-funcs entry begins with `func TestOpenAPI`.
		const wantPrefix = "func TestOpenAPI"
		for _, want := range openapiConformanceCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestOpenAPI` filter binds to the `TestOpenAPI` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
