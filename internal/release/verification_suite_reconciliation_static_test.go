package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — reconciliation tests (BE-0405).
//
// Threat model: the reconcile loop is the only customer-facing
// surface that consumes both the Yalla desired-state snapshot
// (source of truth) and the live Dokploy actual-state snapshot
// (defence-in-depth) in the same evaluation. The pure decision
// logic that classifies divergence is `reconcile.Diff`: it is a
// deterministic function from `(DesiredOrganization,
// ActualOrganization)` to a `Plan` whose every `Action` carries a
// stable closed-set tag `(ActionType, DriftKind, DriftReason)`.
// The classifier reads desired env-var values only to route them
// to `Action.DesiredValue` (the single field a Repairer adapter
// consumes); it never echoes a value into `Action.Type`,
// `Action.Kind`, `Action.Reason`, `Action.EnvVarKey`,
// `Action.Service`, `Action.Domain`, or `Action.Unmanaged`. A
// silent regression that demoted any documented reason from the
// closed set, that flipped a `dangerous` kind to `safe` (auto-
// repairing dangerous drift risks data loss), that introduced
// non-deterministic ordering into the planner, or that started
// echoing an env-var value into a classification field, would
// corrupt the audit/review queue or let the engine auto-repair
// drift it must not touch. The canonical pair
// (`TestReconciliationCoversCallSites`,
//  `TestReconciliationPreservesContractUnderContention`) lives
// in `internal/controlplane/reconcile/reconcile_canonical_test.go`
// and binds to the PRD's `-run TestReconciliation` filter. The
// pair members are deterministic by design — both walk a closed
// scenario table built from every documented `DriftReason` and
// `ActionType` of `reconcile.Diff`, and `Diff` is a pure
// function from `(desired, actual)` to a `Plan`. Neither member
// reaches the process environment, the network, a live Postgres,
// a live Dokploy, or any external service.
//
// A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted, the
// canonical `reconcile_canonical_test.go` file removed, or the
// canonical `TestReconciliation…` function pair renamed — would
// let a planner drift or a new drift reason ship without firing
// any gate. This file is the load-bearing static defence for
// that meta-contract. It pins SIX surfaces in one file so a
// future contributor changing the CI step name, the verify.sh
// step header, the CONTRIBUTING numeric prefix, the SECURITY
// row, the PRD requiredBackendCommands array, or deleting the
// canonical reconcile test fixture fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Reconciliation tests` that invokes
//     `go test -run TestReconciliation ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package,
//     the dedicated step is defence-in-depth: a future narrowing
//     of the umbrella step would still leave this gate firing as
//     a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestReconciliation ./...` under the
//     canonical step header `# 29. Required: reconciliation
//     tests`. The numeric prefix is part of the contract: a
//     reorder must be a deliberate edit to both this constant
//     and the script. #29 extends the BE-0379..BE-0404 sequence
//     by one and pushes BE-0400's optional `# 34. Optional:
//     external live-Dokploy smoke tests` block down by one in
//     the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry an
//     entry `29. \`go test -run TestReconciliation ./...\`` so a
//     contributor preparing a PR sees the gate before running
//     scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table MUST
//     carry a row for the reconciliation suite, AND a dedicated
//     `## Reconciliation Tests` section MUST explain the closed-
//     set coverage invariant (every documented `DriftReason` and
//     every documented `ActionType`), the determinism invariant
//     (`Diff(desired, actual)` is a pure function of its inputs),
//     the value-free classification invariant (no env-var value
//     echoes into a classification field), the safety dispatch
//     invariant (`safe` drift is auto-repaired, `dangerous`
//     drift is reviewed, `unmanaged` drift is quarantined), the
//     deterministic-by-default behaviour, the actionable-failure
//     contract, the schema-version contract, and the redaction
//     contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestReconciliation ./...` so an AI agent
//     reading the PRD before picking up a story sees the gate
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/controlplane/reconcile/reconcile_canonical_test.go`
//     — the canonical reference reconciliation test file MUST
//     exist and MUST declare the load-bearing function pair
//     (`TestReconciliationCoversCallSites`,
//      `TestReconciliationPreservesContractUnderContention`).
//     The PRD's `go test -run TestReconciliation ./...` filter
//     binds to the `TestReconciliation` substring; a rename to a
//     function whose name does not match the substring silently
//     de-gates the reconciliation suite for any caller relying
//     on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteReconciliationAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips
// through) are both caught at the package-internal API.

const (
	// reconciliationCIWorkflowStepName is the exact step name CI
	// uses to invoke the reconciliation suite. A rename forces a
	// deliberate update both here and in the workflow.
	reconciliationCIWorkflowStepName = "- name: Reconciliation tests"
	// reconciliationCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future package
	// that declares a `TestReconciliation…` test.
	reconciliationCIWorkflowStepRun = "run: go test -run TestReconciliation ./..."

	// reconciliationVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestReconciliation
	// ./...` invocation in verify.sh. The numeric prefix is part
	// of the contract: a reorder must be a deliberate edit to
	// both this constant and the script.
	reconciliationVerifyShStepHeader = "# 29. Required: reconciliation tests"
	// reconciliationVerifyShStepCmd is the literal command that
	// MUST appear inside the required-reconciliation step.
	// Asserting on the literal (not a regex over the file) makes
	// the failure point the operator at the exact line that
	// drifted.
	reconciliationVerifyShStepCmd = `go test -run TestReconciliation ./...`

	// reconciliationContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	reconciliationContributingEntry = "29. `go test -run TestReconciliation ./...`"

	// reconciliationSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the reconciliation suite is part of the
	// published security posture.
	reconciliationSecurityGateRow = "| Reconciliation tests | `go test -run TestReconciliation ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// reconciliationSecuritySectionHeading is the dedicated
	// `## Reconciliation Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant, the
	// determinism invariant, the value-free classification
	// invariant, the safety dispatch invariant, the deterministic-
	// by-default behaviour, the actionable-failure contract, the
	// schema-version contract, and the redaction contract.
	reconciliationSecuritySectionHeading = "## Reconciliation Tests"

	// reconciliationPRDCommand is the literal command that MUST
	// appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	reconciliationPRDCommand = "go test -run TestReconciliation ./..."

	// reconciliationCanonicalFile is the relative path of the
	// canonical reference reconciliation test file. The
	// `internal/controlplane/reconcile/reconcile_canonical_test.go`
	// file declares the function pair every reconciliation
	// regression MUST trip; deleting it silently kills the
	// convention.
	reconciliationCanonicalFile = "internal/controlplane/reconcile/reconcile_canonical_test.go"
)

// reconciliationCanonicalFuncs is the closed set of function
// declarations the canonical `reconcile_canonical_test.go` file
// MUST carry. The PRD's `-run TestReconciliation` filter binds
// to function names containing the `TestReconciliation`
// substring; renaming any entry to a name that does not match
// the substring silently de-gates the reconciliation suite for
// any caller relying on the filter.
var reconciliationCanonicalFuncs = []string{
	"func TestReconciliationCoversCallSites(t *testing.T)",
	"func TestReconciliationPreservesContractUnderContention(t *testing.T)",
}

// reconciliationSecuritySectionSubstrings is the closed set of
// substrings the dedicated `## Reconciliation Tests` section in
// SECURITY.md MUST contain. The substrings name every load-
// bearing fact the operator- and auditor-facing documentation
// MUST surface so a future contributor changing the gate's
// contract is forced to update the public security posture in
// the same edit.
var reconciliationSecuritySectionSubstrings = []string{
	"TestReconciliation",
	"Diff",
	"DriftReason",
	"DriftKind",
	"ActionType",
	"DesiredValue",
	"safe",
	"dangerous",
	"unmanaged",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379).
// Reusing them here keeps the path / helper layer single-
// sourced so a repository-wide rename only touches that file.

// TestVerificationSuiteReconciliationCIWorkflowDeclaresStep pins
// the CI workflow to a dedicated step that invokes
// `go test -run TestReconciliation ./...`. Even though the
// umbrella `go test ./...` step exercises the same package, the
// dedicated step is defence-in-depth: a future narrowing of the
// umbrella step would still leave this gate firing as a fast
// targeted failure rather than buried inside the umbrella log.
func TestVerificationSuiteReconciliationCIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		reconciliationCIWorkflowStepName,
		reconciliationCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI reconciliation step is the defence-in-depth gate for the closed-set planner coverage + determinism + value-free + safety-dispatch invariants — every push and PR MUST run `go test -run TestReconciliation ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteReconciliationVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestReconciliation ./...` under its canonical
// step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteReconciliationVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, reconciliationVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-reconciliation block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, reconciliationVerifyShStepHeader)
	}
	if !strings.Contains(doc, reconciliationVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same reconciliation command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, reconciliationVerifyShStepCmd)
	}
}

// TestVerificationSuiteReconciliationContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the
// verify.sh step number to keep the two surfaces in lockstep.
func TestVerificationSuiteReconciliationContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, reconciliationContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, reconciliationContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteReconciliationSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the reconciliation gate part
// of the published security posture, so dropping the row or the
// section silently weakens the posture.
func TestVerificationSuiteReconciliationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, reconciliationSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, reconciliationSecurityGateRow)
	}
	if !strings.Contains(doc, reconciliationSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / determinism / value-free / safety-dispatch / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, reconciliationSecuritySectionHeading)
	}
	for _, want := range reconciliationSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, reconciliationSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteReconciliationPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// reconciliation command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteReconciliationPRDDocumentsCommand(t *testing.T) {
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
		if cmd == reconciliationPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the reconciliation gate as a required backend command.",
		requiredPRDPath, reconciliationPRDCommand)
}

// TestVerificationSuiteReconciliationCanonicalFileExists pins the
// canonical reference reconciliation test file and its load-
// bearing function pair. Deleting the file or renaming either
// function to a name that does not match the
// `TestReconciliation` substring silently de-gates the
// reconciliation suite for any caller relying on the PRD's
// `-run TestReconciliation` filter.
func TestVerificationSuiteReconciliationCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(reconciliationCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical reconciliation test file is the load-bearing convention every reconciliation regression MUST trip; deleting it silently removes the reconciliation gate.",
			reconciliationCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range reconciliationCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the reconciliation pair is the load-bearing assertion set every reconciliation regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				reconciliationCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteReconciliationAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts
// the matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a tightened
// regex, a relaxed substring set, a renamed constant) could
// silently let real regressions slip through.
func TestVerificationSuiteReconciliationAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			reconciliationCIWorkflowStepName,
			reconciliationCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Reconciliation tests\n        run: go test -run TestReconciliation ./...\n"
		for _, want := range []string{
			reconciliationCIWorkflowStepName,
			reconciliationCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, reconciliationVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", reconciliationVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 29. Required: reconciliation tests\nstep \"go test -run TestReconciliation ./...\"\nif ! go test -run TestReconciliation ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, reconciliationVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", reconciliationVerifyShStepHeader)
		}
		if !strings.Contains(doc, reconciliationVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", reconciliationVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n28. `go test -run TestBreakGlass ./...`\n"
		if strings.Contains(doc, reconciliationContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", reconciliationContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n28. `go test -run TestBreakGlass ./...`\n29. `go test -run TestReconciliation ./...`\n"
		if !strings.Contains(doc, reconciliationContributingEntry) {
			t.Fatalf("complete fixture missing %q", reconciliationContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Reconciliation Tests\n\n")
		for _, want := range reconciliationSecuritySectionSubstrings {
			if want == "DesiredValue" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range reconciliationSecuritySectionSubstrings {
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
		b.WriteString("## Reconciliation Tests\n\n")
		for _, want := range reconciliationSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range reconciliationSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestReleaseBuild ./..."]}}`
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
			if cmd == reconciliationPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", reconciliationPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestReconciliation ./..."]}}`
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
			if cmd == reconciliationPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", reconciliationPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package reconcile_test\n\nimport \"testing\"\n\nfunc TestReconciliationCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range reconciliationCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package reconcile_test\n\nimport \"testing\"\n\nfunc TestReconciliationCoversCallSites(t *testing.T) {}\nfunc TestReconciliationPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range reconciliationCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestReconciliation substring locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantSubstring = "TestReconciliation"
		for _, want := range reconciliationCanonicalFuncs {
			if !strings.Contains(want, wantSubstring) {
				t.Errorf("canonical-funcs entry %q does not contain %q — the PRD's `-run TestReconciliation` filter binds to the `TestReconciliation` substring and would silently miss this function", want, wantSubstring)
			}
		}
	})
}
