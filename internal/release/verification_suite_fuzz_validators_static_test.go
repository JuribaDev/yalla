package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — fuzz tests for validators (BE-0388).
//
// Threat model: the contract between Yalla's request-validation toolkit
// (`internal/controlplane/validate`) and every handler, worker, audit
// pipeline, downstream SDK, and AI agent that submits user-controlled
// input is "no validator ever panics on hostile input, no validator
// echoes a submitted value back into an error or log, and no validator
// accepts an invalid value." That invariant is enforced by the
// `FuzzName` / `FuzzPath` / `FuzzDomain` / `FuzzEnvVarName` /
// `FuzzEnvVarValue` / `FuzzDecodeJSON` / `FuzzImageRef` / `FuzzURL` /
// `FuzzGitBranch` targets in
// `internal/controlplane/validate/fuzz_test.go`. The targets replay a
// shared hostile seed corpus (long strings, invalid UTF-8, path
// traversal, NUL bytes, control characters, Unicode tricks, embedded
// credentials, IPv4 literals, reserved DNS suffixes) on every `go test
// ./...` run AND can be driven through Go's randomised fuzz engine via
// `go test -fuzz=Fuzz<Name> ./internal/controlplane/validate/...`.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `fuzz_test.go` file removed, or the canonical
// `TestFuzzValidatorContract…` function pair renamed — would let a
// validator regression (a new validator added without a Fuzz target,
// a tightened rule that accidentally panics on a NUL byte, a value
// echoed into a reason field for the first time) ship without firing
// any gate.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical fuzz test fixture fails ONE test,
// not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Fuzz validator tests` that invokes
//     `go test -run TestFuzzValidator ./...`. Even though
//     `go test ./...` covers the same packages, the dedicated step
//     is defence-in-depth: a future narrowing of the umbrella step
//     (e.g. `go test ./internal/...` minus controlplane/validate)
//     would still leave this gate green, surfacing the regression
//     as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestFuzzValidator ./...` under the canonical
//     step header `# 14. Required: fuzz tests for validators`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `14. \`go test -run TestFuzzValidator ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix keeps
//     verify.sh and CONTRIBUTING.md in lockstep with BE-0379's
//     `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, BE-0381's
//     `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
//     `8. go test ./internal/controlplane/openapi/...`, BE-0383's
//     `9. go test -run TestPolicyMatrix ./...`, BE-0384's
//     `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
//     `11. go test -run TestJobWorkerLease ./...`, BE-0386's
//     `12. go test -run TestFakeDokploy ./...`, and BE-0387's
//     `13. go test -run TestRedaction ./...` pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Fuzz validator tests` row, AND a dedicated
//     `## Fuzz Validator Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the no-panic
//     invariant (every validator survives every hostile seed
//     without panicking), the no-value-echo invariant (a rejected
//     value never appears in the error message or audit metadata),
//     the closed-set coverage invariant (every public validator has
//     a Fuzz target), deterministic seed-corpus fixtures (no live
//     Dokploy, no live Postgres), opt-in `YALLA_EXTERNAL_DOKPLOY`
//     external smoke, the optional randomised `-fuzz=Fuzz<Name>`
//     escape hatch, and the CI-on-every-push-and-PR cadence.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestFuzzValidator ./...` so an AI agent reading
//     the PRD before picking up a story sees the canonical command
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/controlplane/validate/fuzz_test.go` — the canonical
//     reference fuzz test file MUST exist and MUST declare the
//     load-bearing function pair
//     (`TestFuzzValidatorContractCoversExpectedValidators`,
//     `TestFuzzValidatorContractSeedCorpusRejectsHostileInputs`).
//     The PRD's `go test -run TestFuzzValidator ./...` filter binds
//     to the `TestFuzzValidator` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     fuzz suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteFuzzValidatorsAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// fuzzValidatorsCIWorkflowStepName is the exact step name CI uses
	// to invoke the fuzz validator suite. A rename forces a deliberate
	// update both here and in the workflow.
	fuzzValidatorsCIWorkflowStepName = "- name: Fuzz validator tests"
	// fuzzValidatorsCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestFuzzValidator…` test.
	fuzzValidatorsCIWorkflowStepRun = "run: go test -run TestFuzzValidator ./..."

	// fuzzValidatorsVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestFuzzValidator ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	fuzzValidatorsVerifyShStepHeader = "# 14. Required: fuzz tests for validators"
	// fuzzValidatorsVerifyShStepCmd is the literal command that MUST
	// appear inside the required-fuzz step. Asserting on the literal
	// (not a regex over the file) makes the failure point the operator
	// at the exact line that drifted.
	fuzzValidatorsVerifyShStepCmd = `go test -run TestFuzzValidator ./...`

	// fuzzValidatorsContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	fuzzValidatorsContributingEntry = "14. `go test -run TestFuzzValidator ./...`"

	// fuzzValidatorsSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the fuzz suite is part of the published security
	// posture.
	fuzzValidatorsSecurityGateRow = "| Fuzz validator tests | `go test -run TestFuzzValidator ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// fuzzValidatorsSecuritySectionHeading is the dedicated
	// `## Fuzz Validator Tests` heading SECURITY.md MUST carry. The
	// section explains the no-panic invariant, the no-value-echo
	// invariant, the closed-set coverage invariant, the
	// actionable-failure contract, the opt-in-external escape hatch,
	// the optional randomised `-fuzz` driver, and the schema-version
	// contract.
	fuzzValidatorsSecuritySectionHeading = "## Fuzz Validator Tests"

	// fuzzValidatorsPRDCommand is the literal command that MUST appear
	// in the PRD's verificationLoop.requiredBackendCommands array so
	// an agent surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	fuzzValidatorsPRDCommand = "go test -run TestFuzzValidator ./..."

	// fuzzValidatorsCanonicalFile is the relative path of the
	// canonical reference fuzz test file. The
	// `internal/controlplane/validate/fuzz_test.go` file declares the
	// function pair every other fuzz test pivots on; deleting it
	// silently kills the convention future fuzz tests must mirror.
	fuzzValidatorsCanonicalFile = "internal/controlplane/validate/fuzz_test.go"
)

// fuzzValidatorsCanonicalFuncs is the closed set of function
// declarations the canonical `fuzz_test.go` file MUST carry. The PRD's
// `-run TestFuzzValidator` filter binds to function names containing
// the `TestFuzzValidator` substring; renaming any entry to a name that
// does not match the prefix silently de-gates the fuzz suite for any
// caller relying on the filter. The pair captures the two load-bearing
// fuzz invariants the validate package MUST keep:
//
//   - TestFuzzValidatorContractCoversExpectedValidators — the
//     closed-set coverage invariant: every public validator in
//     `internal/controlplane/validate` MUST have a corresponding Fuzz
//     target so the seed corpus replays hostile inputs across every
//     surface. A new validator added without a Fuzz target — or a
//     deletion of an existing target — trips this matcher.
//   - TestFuzzValidatorContractSeedCorpusRejectsHostileInputs — the
//     no-panic runtime invariant: every validator survives every
//     hostile seed without panicking. The wrapper drives every
//     validator under a `recover()` guard so a panic surfaces with
//     the offending validator name AND the seed index (the
//     actionable-failure contract).
var fuzzValidatorsCanonicalFuncs = []string{
	"func TestFuzzValidatorContractCoversExpectedValidators(",
	"func TestFuzzValidatorContractSeedCorpusRejectsHostileInputs(",
}

// fuzzValidatorsSecuritySectionSubstrings is the closed set of literal
// substrings the `## Fuzz Validator Tests` section MUST contain. Each
// captures a different load-bearing fact the BE-0388 acceptance
// criteria require to be visible:
//
//   - "internal/controlplane/validate" — the package boundary the
//     canonical validators live in (AC1 documented suite scope).
//   - "fuzz_test.go"                 — the canonical reference fuzz
//     file name; deleting it would break every fuzz target the gate
//     pivots on.
//   - "deterministic"                — the AC2 determinism contract;
//     the seed corpus replays the same hostile inputs on every run.
//   - "seed corpus"                  — the deterministic-fixture
//     substrate every Fuzz target replays under `go test ./...`.
//   - "no panic"                     — the weakest runtime invariant
//     the canonical-pair pins (the wrapper drives every validator
//     under `recover()`).
//   - "FuzzName"                     — the first FuzzXxx target in
//     the closed-set coverage list; deleting it would break the
//     `validate.Name` hostile-input replay.
//   - "FuzzDecodeJSON"               — the binary-body Fuzz target;
//     deleting it would break the request-body hostile-input replay
//     that all mutating endpoints depend on.
//   - "request_id"                   — the actionable-failure
//     identifier surfaced when a panic IS encountered (the wrapper
//     reports the offending validator AND the seed index).
//   - "YALLA_EXTERNAL_DOKPLOY"       — the AC2 opt-in-external
//     escape hatch.
//   - "TestLiveDokploySmoke"         — the opt-in external test
//     name (the PRD's
//     verificationLoop.optionalWhenConfigured names it).
//   - "-fuzz="                       — the optional randomised driver
//     (Go's native fuzz engine) the FuzzXxx targets accept; CI runs
//     the seed-corpus replay on every PR, the `-fuzz=` driver is the
//     opt-in randomised escape hatch for soak runs.
//   - "yalla.output.v1"              — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"               — the AC5 error envelope
//     schema_version contract.
//   - "TestFuzzValidatorContractCoversExpectedValidators" — the
//     canonical closed-set coverage function the -run filter binds
//     to.
//   - "TestFuzzValidatorContractSeedCorpusRejectsHostileInputs" —
//     the canonical no-panic runtime function the -run filter binds
//     to.
//   - "Every push and PR"            — the AC4 CI gating cadence.
//   - "verification_suite_fuzz_validators_static_test.go" — the gate
//     is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var fuzzValidatorsSecuritySectionSubstrings = []string{
	"internal/controlplane/validate",
	"fuzz_test.go",
	"deterministic",
	"seed corpus",
	"no panic",
	"FuzzName",
	"FuzzDecodeJSON",
	"request_id",
	"YALLA_EXTERNAL_DOKPLOY",
	"TestLiveDokploySmoke",
	"-fuzz=",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestFuzzValidatorContractCoversExpectedValidators",
	"TestFuzzValidatorContractSeedCorpusRejectsHostileInputs",
	"Every push and PR",
	"verification_suite_fuzz_validators_static_test.go",
}

// TestVerificationSuiteFuzzValidatorsCIWorkflow pins the GitHub Actions
// test job to run the canonical fuzz validator command under the
// canonical step name. A silent removal of the step — or a narrowing
// of the run command — defeats the defence-in-depth promise that even
// a regression in the umbrella `go test ./...` step would still leave
// this gate firing.
func TestVerificationSuiteFuzzValidatorsCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		fuzzValidatorsCIWorkflowStepName,
		fuzzValidatorsCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI fuzz validator step is the defence-in-depth gate for the no-panic + no-value-echo + closed-set-coverage invariants — every push and PR MUST run `go test -run TestFuzzValidator ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteFuzzValidatorsVerifyShRunsCanonicalCommand pins
// the local commit gate to run `go test -run TestFuzzValidator ./...`
// under its canonical step header so a contributor running the gate
// locally exercises the identical command CI runs.
func TestVerificationSuiteFuzzValidatorsVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, fuzzValidatorsVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-fuzz-validator block is the local mirror of the CI gate and the fuzz step must keep its canonical position.",
			requiredVerifyShPath, fuzzValidatorsVerifyShStepHeader)
	}
	if !strings.Contains(doc, fuzzValidatorsVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same fuzz validator command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, fuzzValidatorsVerifyShStepCmd)
	}
}

// TestVerificationSuiteFuzzValidatorsContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a contributor
// opens a PR. The numeric prefix matches the verify.sh step number to
// keep the two surfaces in lockstep.
func TestVerificationSuiteFuzzValidatorsContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, fuzzValidatorsContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, fuzzValidatorsContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteFuzzValidatorsSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the fuzz validator gate part of
// the published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteFuzzValidatorsSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, fuzzValidatorsSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, fuzzValidatorsSecurityGateRow)
	}
	if !strings.Contains(doc, fuzzValidatorsSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the no-panic / no-value-echo / closed-set-coverage / actionable-failure / opt-in-external / `-fuzz=` / schema-version contracts auditable.",
			requiredSecurityPath, fuzzValidatorsSecuritySectionHeading)
	}
	for _, want := range fuzzValidatorsSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, fuzzValidatorsSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteFuzzValidatorsPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical fuzz
// validator command without needing to discover it from CI workflows
// or shell scripts.
func TestVerificationSuiteFuzzValidatorsPRDDocumentsCommand(t *testing.T) {
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
		if cmd == fuzzValidatorsPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the fuzz validator gate as a required backend command.",
		requiredPRDPath, fuzzValidatorsPRDCommand)
}

// TestVerificationSuiteFuzzValidatorsCanonicalFileExists pins the
// canonical reference fuzz test file and its load-bearing function
// pair. Deleting the file or renaming either function to a name that
// does not match the `TestFuzzValidator` prefix silently de-gates the
// fuzz suite for any caller relying on the PRD's
// `-run TestFuzzValidator` filter.
func TestVerificationSuiteFuzzValidatorsCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(fuzzValidatorsCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical fuzz test file is the load-bearing convention every other fuzz test pivots on; deleting it silently removes the pattern future fuzz tests must mirror.",
			fuzzValidatorsCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range fuzzValidatorsCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the fuzz validator pair is the load-bearing assertion set every fuzz regression MUST trip — a rename or deletion silently relaxes the no-panic + no-value-echo + closed-set-coverage contract for every downstream caller.",
				fuzzValidatorsCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteFuzzValidatorsAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteFuzzValidatorsAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			fuzzValidatorsCIWorkflowStepName,
			fuzzValidatorsCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Fuzz validator tests\n        run: go test -run TestFuzzValidator ./...\n"
		for _, want := range []string{
			fuzzValidatorsCIWorkflowStepName,
			fuzzValidatorsCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, fuzzValidatorsVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", fuzzValidatorsVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 14. Required: fuzz tests for validators\nstep \"go test -run TestFuzzValidator ./...\"\nif ! go test -run TestFuzzValidator ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, fuzzValidatorsVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", fuzzValidatorsVerifyShStepHeader)
		}
		if !strings.Contains(doc, fuzzValidatorsVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", fuzzValidatorsVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n"
		if strings.Contains(doc, fuzzValidatorsContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", fuzzValidatorsContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n"
		if !strings.Contains(doc, fuzzValidatorsContributingEntry) {
			t.Fatalf("complete fixture missing %q", fuzzValidatorsContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Fuzz Validator Tests\n\n")
		for _, want := range fuzzValidatorsSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range fuzzValidatorsSecuritySectionSubstrings {
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
		b.WriteString("## Fuzz Validator Tests\n\n")
		for _, want := range fuzzValidatorsSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range fuzzValidatorsSecuritySectionSubstrings {
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
			if cmd == fuzzValidatorsPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", fuzzValidatorsPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestFuzzValidator ./..."]}}`
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
			if cmd == fuzzValidatorsPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", fuzzValidatorsPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic fuzz_test.go declaring only one of the two
		// fuzz canonical functions. The matcher MUST fire on the
		// missing second.
		doc := "package validate_test\n\nimport \"testing\"\n\nfunc TestFuzzValidatorContractCoversExpectedValidators(t *testing.T) {}\n"
		missing := 0
		for _, want := range fuzzValidatorsCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every fuzz-pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package validate_test\n\nimport \"testing\"\n\nfunc TestFuzzValidatorContractCoversExpectedValidators(t *testing.T) {}\nfunc TestFuzzValidatorContractSeedCorpusRejectsHostileInputs(t *testing.T) {}\n"
		for _, want := range fuzzValidatorsCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestFuzzValidator prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestFuzzValidator ./...` filter
		// binds to function names containing the
		// `TestFuzzValidator` substring. A canonical-funcs entry
		// that drops the prefix would silently de-gate the fuzz
		// suite for any caller relying on the filter. This subtest
		// asserts every canonical-funcs entry begins with
		// `func TestFuzzValidator`.
		const wantPrefix = "func TestFuzzValidator"
		for _, want := range fuzzValidatorsCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestFuzzValidator` filter binds to the `TestFuzzValidator` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
