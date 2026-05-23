package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — import dry-run tests (BE-0406).
//
// Threat model: the import dry-run is the operator-facing
// surface a Yalla admin uses to preview which pre-existing
// Dokploy resources would become customer-visible if the
// operator committed to an `OwnerAssignment`. The pure
// classifier chokepoint is
// `(*migrateimport.Importer).Plan(ctx, PlanInput) (Plan, error)`:
// it walks the live Dokploy snapshot, queries the Repository
// port for collisions and pre-existing links, and emits a
// deterministic `Plan` whose every `PlanItem` carries a stable
// closed-set tag `(Level, Status, Reason)`. The classifier
// never writes to the Repository when invoked without an
// `OwnerAssignment` (the pending-owner short-circuit) and is
// always read-only — no `CreateProject`, `CreateEnvironment`,
// or `CreateService` call is allowed on any Plan code path.
// A silent regression that demoted an `ItemStatus` or
// `ItemReason` out of the closed set, that started echoing the
// untrusted Dokploy display name into a classification field
// (`Status`, `Reason`, `Level`), that introduced non-
// deterministic ordering into the planner, or that started
// writing to the Repository in dry-run mode, would either let
// the operator commit to an import they did not preview or
// expose untrusted input through what is meant to be a stable
// audit-ready surface. The canonical pair
// (`TestImportDryRunCoversCallSites`,
//  `TestImportDryRunPreservesContractUnderContention`) lives
// in
// `internal/controlplane/migrateimport/import_dry_run_canonical_test.go`
// and binds to the PRD's `-run TestImportDryRun` filter. The
// pair members are deterministic by design — both walk a
// closed scenario table built from every documented
// `ItemStatus` and `ItemReason` of `Importer.Plan`, and the
// classifier is a deterministic function of its inputs and the
// seeded Repository state. Neither member reaches the process
// environment, the network, a live Postgres, a live Dokploy,
// or any external service.
//
// A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted,
// the canonical `import_dry_run_canonical_test.go` file
// removed, or the canonical `TestImportDryRun…` function pair
// renamed — would let a planner drift or a new import status
// ship without firing any gate. This file is the load-bearing
// static defence for that meta-contract. It pins SIX surfaces
// in one file so a future contributor changing the CI step
// name, the verify.sh step header, the CONTRIBUTING numeric
// prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical import-dry-run test fixture
// fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Import dry-run tests` that invokes
//     `go test -run TestImportDryRun ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package,
//     the dedicated step is defence-in-depth: a future narrowing
//     of the umbrella step would still leave this gate firing as
//     a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestImportDryRun ./...` under the
//     canonical step header `# 30. Required: import dry-run
//     tests`. The numeric prefix is part of the contract: a
//     reorder must be a deliberate edit to both this constant
//     and the script. #30 extends the BE-0379..BE-0405
//     sequence by one and pushes the trailing optional steps
//     #30-#34 down to #31-#35 in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry
//     an entry `30. \`go test -run TestImportDryRun ./...\`` so
//     a contributor preparing a PR sees the gate before
//     running scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table
//     MUST carry a row for the import dry-run suite, AND a
//     dedicated `## Import Dry-Run Tests` section MUST explain
//     the closed-set coverage invariant (every documented
//     `ItemStatus` and every documented `ItemReason`), the
//     determinism invariant
//     (`Plan(ctx, in)` is a deterministic function of its
//     inputs and the seeded Repository state), the value-free
//     classification invariant (no untrusted Dokploy display
//     name echoes into `Status`, `Reason`, or `Level`), the
//     dry-run purity invariant (no Repository writes; no
//     Repository reads under a pending-owner short-circuit),
//     the deterministic-by-default behaviour, the actionable-
//     failure contract, the schema-version contract, and the
//     redaction contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestImportDryRun ./...` so an AI agent
//     reading the PRD before picking up a story sees the gate
//     without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/migrateimport/import_dry_run_canonical_test.go`
//     — the canonical reference import dry-run test file MUST
//     exist and MUST declare the load-bearing function pair
//     (`TestImportDryRunCoversCallSites`,
//      `TestImportDryRunPreservesContractUnderContention`).
//     The PRD's `go test -run TestImportDryRun ./...` filter
//     binds to the `TestImportDryRun` substring; a rename to a
//     function whose name does not match the substring
//     silently de-gates the import dry-run suite for any
//     caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteImportDryRunAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips
// through) are both caught at the package-internal API.

const (
	// importDryRunCIWorkflowStepName is the exact step name CI
	// uses to invoke the import dry-run suite. A rename forces a
	// deliberate update both here and in the workflow.
	importDryRunCIWorkflowStepName = "- name: Import dry-run tests"
	// importDryRunCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future
	// package that declares a `TestImportDryRun…` test.
	importDryRunCIWorkflowStepRun = "run: go test -run TestImportDryRun ./..."

	// importDryRunVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestImportDryRun
	// ./...` invocation in verify.sh. The numeric prefix is
	// part of the contract: a reorder must be a deliberate
	// edit to both this constant and the script.
	importDryRunVerifyShStepHeader = "# 30. Required: import dry-run tests"
	// importDryRunVerifyShStepCmd is the literal command that
	// MUST appear inside the required-import-dry-run step.
	// Asserting on the literal (not a regex over the file)
	// makes the failure point the operator at the exact line
	// that drifted.
	importDryRunVerifyShStepCmd = `go test -run TestImportDryRun ./...`

	// importDryRunContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	importDryRunContributingEntry = "30. `go test -run TestImportDryRun ./...`"

	// importDryRunSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the import dry-run suite is part of the
	// published security posture.
	importDryRunSecurityGateRow = "| Import dry-run tests | `go test -run TestImportDryRun ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// importDryRunSecuritySectionHeading is the dedicated
	// `## Import Dry-Run Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant,
	// the determinism invariant, the value-free classification
	// invariant, the dry-run purity invariant, the
	// deterministic-by-default behaviour, the actionable-
	// failure contract, the schema-version contract, and the
	// redaction contract.
	importDryRunSecuritySectionHeading = "## Import Dry-Run Tests"

	// importDryRunPRDCommand is the literal command that MUST
	// appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an
	// agent surfaces the gate from the contract document, not
	// from shell scripts or CI workflows.
	importDryRunPRDCommand = "go test -run TestImportDryRun ./..."

	// importDryRunCanonicalFile is the relative path of the
	// canonical reference import dry-run test file. The
	// `internal/controlplane/migrateimport/import_dry_run_canonical_test.go`
	// file declares the function pair every import-dry-run
	// regression MUST trip; deleting it silently kills the
	// convention.
	importDryRunCanonicalFile = "internal/controlplane/migrateimport/import_dry_run_canonical_test.go"
)

// importDryRunCanonicalFuncs is the closed set of function
// declarations the canonical `import_dry_run_canonical_test.go`
// file MUST carry. The PRD's `-run TestImportDryRun` filter
// binds to function names containing the `TestImportDryRun`
// substring; renaming any entry to a name that does not match
// the substring silently de-gates the import-dry-run suite for
// any caller relying on the filter.
var importDryRunCanonicalFuncs = []string{
	"func TestImportDryRunCoversCallSites(t *testing.T)",
	"func TestImportDryRunPreservesContractUnderContention(t *testing.T)",
}

// importDryRunSecuritySectionSubstrings is the closed set of
// substrings the dedicated `## Import Dry-Run Tests` section
// in SECURITY.md MUST contain. The substrings name every load-
// bearing fact the operator- and auditor-facing documentation
// MUST surface so a future contributor changing the gate's
// contract is forced to update the public security posture in
// the same edit.
var importDryRunSecuritySectionSubstrings = []string{
	"TestImportDryRun",
	"Plan",
	"ItemStatus",
	"ItemReason",
	"ResourceLevel",
	"OwnerAssignment",
	"ProposedDisplay",
	"ready",
	"pending_owner",
	"skip_duplicate",
	"skip_missing_parent",
	"skip_unsupported_type",
	"skip_already_imported",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379).
// Reusing them here keeps the path / helper layer single-
// sourced so a repository-wide rename only touches that file.

// TestVerificationSuiteImportDryRunCIWorkflowDeclaresStep pins
// the CI workflow to a dedicated step that invokes
// `go test -run TestImportDryRun ./...`. Even though the
// umbrella `go test ./...` step exercises the same package,
// the dedicated step is defence-in-depth: a future narrowing
// of the umbrella step would still leave this gate firing as a
// fast targeted failure rather than buried inside the umbrella
// log.
func TestVerificationSuiteImportDryRunCIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		importDryRunCIWorkflowStepName,
		importDryRunCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI import-dry-run step is the defence-in-depth gate for the closed-set planner coverage + determinism + value-free classification + dry-run purity invariants — every push and PR MUST run `go test -run TestImportDryRun ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteImportDryRunVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestImportDryRun ./...` under its canonical
// step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteImportDryRunVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, importDryRunVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-import-dry-run block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, importDryRunVerifyShStepHeader)
	}
	if !strings.Contains(doc, importDryRunVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same import-dry-run command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, importDryRunVerifyShStepCmd)
	}
}

// TestVerificationSuiteImportDryRunContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the
// verify.sh step number to keep the two surfaces in lockstep.
func TestVerificationSuiteImportDryRunContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, importDryRunContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, importDryRunContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteImportDryRunSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the import-dry-run gate
// part of the published security posture, so dropping the row
// or the section silently weakens the posture.
func TestVerificationSuiteImportDryRunSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, importDryRunSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, importDryRunSecurityGateRow)
	}
	if !strings.Contains(doc, importDryRunSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / determinism / value-free / dry-run-purity / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, importDryRunSecuritySectionHeading)
	}
	for _, want := range importDryRunSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, importDryRunSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteImportDryRunPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// import-dry-run command without needing to discover it from
// CI workflows or shell scripts.
func TestVerificationSuiteImportDryRunPRDDocumentsCommand(t *testing.T) {
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
		if cmd == importDryRunPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the import-dry-run gate as a required backend command.",
		requiredPRDPath, importDryRunPRDCommand)
}

// TestVerificationSuiteImportDryRunCanonicalFileExists pins the
// canonical reference import-dry-run test file and its load-
// bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestImportDryRun`
// substring silently de-gates the import-dry-run suite for any
// caller relying on the PRD's `-run TestImportDryRun` filter.
func TestVerificationSuiteImportDryRunCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(importDryRunCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical import-dry-run test file is the load-bearing convention every import-dry-run regression MUST trip; deleting it silently removes the import-dry-run gate.",
			importDryRunCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range importDryRunCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the import-dry-run pair is the load-bearing assertion set every import-dry-run regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				importDryRunCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteImportDryRunAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts
// the matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a
// tightened regex, a relaxed substring set, a renamed
// constant) could silently let real regressions slip through.
func TestVerificationSuiteImportDryRunAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			importDryRunCIWorkflowStepName,
			importDryRunCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Import dry-run tests\n        run: go test -run TestImportDryRun ./...\n"
		for _, want := range []string{
			importDryRunCIWorkflowStepName,
			importDryRunCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, importDryRunVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", importDryRunVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 30. Required: import dry-run tests\nstep \"go test -run TestImportDryRun ./...\"\nif ! go test -run TestImportDryRun ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, importDryRunVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", importDryRunVerifyShStepHeader)
		}
		if !strings.Contains(doc, importDryRunVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", importDryRunVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n29. `go test -run TestReconciliation ./...`\n"
		if strings.Contains(doc, importDryRunContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", importDryRunContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n29. `go test -run TestReconciliation ./...`\n30. `go test -run TestImportDryRun ./...`\n"
		if !strings.Contains(doc, importDryRunContributingEntry) {
			t.Fatalf("complete fixture missing %q", importDryRunContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Import Dry-Run Tests\n\n")
		for _, want := range importDryRunSecuritySectionSubstrings {
			if want == "ProposedDisplay" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range importDryRunSecuritySectionSubstrings {
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
		b.WriteString("## Import Dry-Run Tests\n\n")
		for _, want := range importDryRunSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range importDryRunSecuritySectionSubstrings {
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
			if cmd == importDryRunPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", importDryRunPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestImportDryRun ./..."]}}`
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
			if cmd == importDryRunPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", importDryRunPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package migrateimport_test\n\nimport \"testing\"\n\nfunc TestImportDryRunCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range importDryRunCanonicalFuncs {
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
		doc := "package migrateimport_test\n\nimport \"testing\"\n\nfunc TestImportDryRunCoversCallSites(t *testing.T) {}\nfunc TestImportDryRunPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range importDryRunCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestImportDryRun substring locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantSubstring = "TestImportDryRun"
		for _, want := range importDryRunCanonicalFuncs {
			if !strings.Contains(want, wantSubstring) {
				t.Errorf("canonical-funcs entry %q does not contain %q — the PRD's `-run TestImportDryRun` filter binds to the `TestImportDryRun` substring and would silently miss this function", want, wantSubstring)
			}
		}
	})
}
