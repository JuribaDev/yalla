package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — deployment lifecycle end-to-end tests (BE-0408).
//
// Threat model: the deployment lifecycle is the customer-visible
// state machine `queued -> running -> succeeded | failed |
// cancelled | rolled_back`. The pure-projection chokepoint is
// `(store.Deployment).LogValue() slog.Value` — the redaction-
// safe debug surface every slog record capturing a Deployment
// funnels through. A silent regression that demoted a
// DeploymentSource or DeploymentStatus value out of the closed
// set, that started echoing a raw SourceRef, IdempotencyKey, or
// ErrorMessage into the LogValue group, that violated the
// terminal-implies-finished_at lifecycle invariant, or that
// smuggled package-level shared state into a goroutine-shared
// projection would either let an operator commit to a deployment
// whose status did not match what they reviewed in a log, audit
// record, or dashboard, or leak a customer-supplied reference,
// idempotency key, or raw error string through a debug surface
// meant to be safe to log, audit, and store. The canonical pair
// (`TestDeploymentLifecycleE2ECoversCallSites`,
//
//	`TestDeploymentLifecycleE2EPreservesContractUnderContention`)
//
// lives in
// `internal/controlplane/store/deployment_lifecycle_e2e_canonical_test.go`
// and binds to the PRD's `-run TestDeploymentLifecycleE2E`
// filter. The pair members are deterministic by design — both
// walk a closed scenario table built from every documented
// DeploymentSource and DeploymentStatus value, and LogValue is a
// deterministic pure function of its input. Neither member
// reaches the process environment, the network, a live Postgres,
// a live Dokploy, or any external service.
//
// A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted,
// the canonical `deployment_lifecycle_e2e_canonical_test.go`
// file removed, or the canonical `TestDeploymentLifecycleE2E…`
// function pair renamed — would let a lifecycle drift or a new
// closed-set enum value ship without firing any gate. This file
// is the load-bearing static defence for that meta-contract. It
// pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical
// deployment-lifecycle test fixture fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Deployment lifecycle end-to-end tests`
//     that invokes `go test -run TestDeploymentLifecycleE2E
//     ./...`. Even though the umbrella `go test ./...` step
//     exercises the same package, the dedicated step is defence-
//     in-depth: a future narrowing of the umbrella step would
//     still leave this gate firing as a fast targeted failure
//     rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestDeploymentLifecycleE2E ./...` under the
//     canonical step header `# 32. Required: deployment
//     lifecycle end-to-end tests`. The numeric prefix is part of
//     the contract: a reorder must be a deliberate edit to both
//     this constant and the script. #32 extends the
//     BE-0379..BE-0407 sequence by one and pushes the trailing
//     optional steps #32-#36 down to #33-#37 in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry an
//     entry `32. \`go test -run TestDeploymentLifecycleE2E
//     ./...\`` so a contributor preparing a PR sees the gate
//     before running scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table
//     MUST carry a row for the deployment lifecycle end-to-end
//     suite, AND a dedicated
//     `## Deployment Lifecycle End-to-End Tests` section MUST
//     explain the closed-set coverage invariant (every
//     documented `DeploymentSource` and `DeploymentStatus`), the
//     terminal-implies-finished_at lifecycle invariant, the
//     determinism invariant (`LogValue()` is a deterministic
//     pure function of its input), the value-free LogValue
//     invariant (the redacted slog projection never carries
//     SourceRef, IdempotencyKey, ErrorMessage, RequestID, or
//     CorrelationID), the actionable-failure contract, the
//     schema-version contract, and the redaction contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestDeploymentLifecycleE2E ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     gate without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/store/deployment_lifecycle_e2e_canonical_test.go`
//     — the canonical reference deployment-lifecycle test file
//     MUST exist and MUST declare the load-bearing function pair
//     (`TestDeploymentLifecycleE2ECoversCallSites`,
//     `TestDeploymentLifecycleE2EPreservesContractUnderContention`).
//     The PRD's `go test -run TestDeploymentLifecycleE2E ./...`
//     filter binds to the `TestDeploymentLifecycleE2E`
//     substring; a rename to a function whose name does not
//     match the substring silently de-gates the deployment-
//     lifecycle suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteDeploymentLifecycleE2EAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips
// through) are both caught at the package-internal API.

const (
	// deploymentLifecycleCIWorkflowStepName is the exact step
	// name CI uses to invoke the deployment-lifecycle suite. A
	// rename forces a deliberate update both here and in the
	// workflow.
	deploymentLifecycleCIWorkflowStepName = "- name: Deployment lifecycle end-to-end tests"
	// deploymentLifecycleCIWorkflowStepRun is the literal
	// command the step MUST invoke. Anything narrower (e.g.
	// dropping the trailing `./...`) would silently exclude any
	// future package that declares a `TestDeploymentLifecycleE2E…`
	// test.
	deploymentLifecycleCIWorkflowStepRun = "run: go test -run TestDeploymentLifecycleE2E ./..."

	// deploymentLifecycleVerifyShStepHeader is the canonical
	// comment header that precedes the
	// `go test -run TestDeploymentLifecycleE2E ./...` invocation
	// in verify.sh. The numeric prefix is part of the contract:
	// a reorder must be a deliberate edit to both this constant
	// and the script.
	deploymentLifecycleVerifyShStepHeader = "# 32. Required: deployment lifecycle end-to-end tests"
	// deploymentLifecycleVerifyShStepCmd is the literal command
	// that MUST appear inside the required-deployment-lifecycle
	// step. Asserting on the literal (not a regex over the file)
	// makes the failure point the operator at the exact line
	// that drifted.
	deploymentLifecycleVerifyShStepCmd = `go test -run TestDeploymentLifecycleE2E ./...`

	// deploymentLifecycleContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading
	// in CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	deploymentLifecycleContributingEntry = "32. `go test -run TestDeploymentLifecycleE2E ./...`"

	// deploymentLifecycleSecurityGateRow is the verification-
	// gates row that MUST appear in SECURITY.md so external
	// operators and reviewers can see the deployment-lifecycle
	// suite is part of the published security posture.
	deploymentLifecycleSecurityGateRow = "| Deployment lifecycle end-to-end tests | `go test -run TestDeploymentLifecycleE2E ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// deploymentLifecycleSecuritySectionHeading is the dedicated
	// `## Deployment Lifecycle End-to-End Tests` heading
	// SECURITY.md MUST carry. The section explains the closed-
	// set coverage invariant, the terminal-implies-finished_at
	// lifecycle invariant, the determinism invariant, the value-
	// free LogValue invariant, the actionable-failure contract,
	// the schema-version contract, and the redaction contract.
	deploymentLifecycleSecuritySectionHeading = "## Deployment Lifecycle End-to-End Tests"

	// deploymentLifecyclePRDCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	deploymentLifecyclePRDCommand = "go test -run TestDeploymentLifecycleE2E ./..."

	// deploymentLifecycleCanonicalFile is the relative path of
	// the canonical reference deployment-lifecycle test file.
	// The
	// `internal/controlplane/store/deployment_lifecycle_e2e_canonical_test.go`
	// file declares the function pair every deployment-
	// lifecycle regression MUST trip; deleting it silently
	// kills the convention.
	deploymentLifecycleCanonicalFile = "internal/controlplane/store/deployment_lifecycle_e2e_canonical_test.go"
)

// deploymentLifecycleCanonicalFuncs is the closed set of
// function declarations the canonical
// `deployment_lifecycle_e2e_canonical_test.go` file MUST carry.
// The PRD's `-run TestDeploymentLifecycleE2E` filter binds to
// function names containing the `TestDeploymentLifecycleE2E`
// substring; renaming any entry to a name that does not match
// the substring silently de-gates the deployment-lifecycle
// suite for any caller relying on the filter.
var deploymentLifecycleCanonicalFuncs = []string{
	"func TestDeploymentLifecycleE2ECoversCallSites(t *testing.T)",
	"func TestDeploymentLifecycleE2EPreservesContractUnderContention(t *testing.T)",
}

// deploymentLifecycleSecuritySectionSubstrings is the closed set
// of substrings the dedicated
// `## Deployment Lifecycle End-to-End Tests` section in
// SECURITY.md MUST contain. The substrings name every load-
// bearing fact the operator- and auditor-facing documentation
// MUST surface so a future contributor changing the gate's
// contract is forced to update the public security posture in
// the same edit.
var deploymentLifecycleSecuritySectionSubstrings = []string{
	"TestDeploymentLifecycleE2E",
	"LogValue",
	"DeploymentSource",
	"DeploymentStatus",
	"git",
	"image",
	"manual",
	"queued",
	"running",
	"succeeded",
	"failed",
	"cancelled",
	"rolled_back",
	"FinishedAt",
	"SourceRef",
	"IdempotencyKey",
	"ErrorMessage",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379).
// Reusing them here keeps the path / helper layer single-
// sourced so a repository-wide rename only touches that file.

// TestVerificationSuiteDeploymentLifecycleE2ECIWorkflowDeclaresStep
// pins the CI workflow to a dedicated step that invokes
// `go test -run TestDeploymentLifecycleE2E ./...`. Even though
// the umbrella `go test ./...` step exercises the same package,
// the dedicated step is defence-in-depth: a future narrowing of
// the umbrella step would still leave this gate firing as a
// fast targeted failure rather than buried inside the umbrella
// log.
func TestVerificationSuiteDeploymentLifecycleE2ECIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		deploymentLifecycleCIWorkflowStepName,
		deploymentLifecycleCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI deployment-lifecycle step is the defence-in-depth gate for the closed-set DeploymentSource/DeploymentStatus coverage + terminal-implies-finished_at lifecycle invariant + value-free LogValue invariants — every push and PR MUST run `go test -run TestDeploymentLifecycleE2E ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteDeploymentLifecycleE2EVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestDeploymentLifecycleE2E ./...` under its
// canonical step header so a contributor running the gate
// locally exercises the identical command CI runs.
func TestVerificationSuiteDeploymentLifecycleE2EVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, deploymentLifecycleVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-deployment-lifecycle block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, deploymentLifecycleVerifyShStepHeader)
	}
	if !strings.Contains(doc, deploymentLifecycleVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same deployment-lifecycle command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, deploymentLifecycleVerifyShStepCmd)
	}
}

// TestVerificationSuiteDeploymentLifecycleE2EContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the
// verify.sh step number to keep the two surfaces in lockstep.
func TestVerificationSuiteDeploymentLifecycleE2EContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, deploymentLifecycleContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, deploymentLifecycleContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteDeploymentLifecycleE2ESecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the deployment-lifecycle gate
// part of the published security posture, so dropping the row or
// the section silently weakens the posture.
func TestVerificationSuiteDeploymentLifecycleE2ESecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, deploymentLifecycleSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, deploymentLifecycleSecurityGateRow)
	}
	if !strings.Contains(doc, deploymentLifecycleSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / lifecycle-timestamp consistency / determinism / value-free LogValue / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, deploymentLifecycleSecuritySectionHeading)
	}
	for _, want := range deploymentLifecycleSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, deploymentLifecycleSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteDeploymentLifecycleE2EPRDDocumentsCommand
// pins the PRD's verificationLoop.requiredBackendCommands so an
// AI agent reading the PRD before picking up a story sees the
// canonical deployment-lifecycle command without needing to
// discover it from CI workflows or shell scripts.
func TestVerificationSuiteDeploymentLifecycleE2EPRDDocumentsCommand(t *testing.T) {
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
		if cmd == deploymentLifecyclePRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the deployment-lifecycle gate as a required backend command.",
		requiredPRDPath, deploymentLifecyclePRDCommand)
}

// TestVerificationSuiteDeploymentLifecycleE2ECanonicalFileExists
// pins the canonical reference deployment-lifecycle test file
// and its load-bearing function pair. Deleting the file or
// renaming either function to a name that does not match the
// `TestDeploymentLifecycleE2E` substring silently de-gates the
// deployment-lifecycle suite for any caller relying on the PRD's
// `-run TestDeploymentLifecycleE2E` filter.
func TestVerificationSuiteDeploymentLifecycleE2ECanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(deploymentLifecycleCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical deployment-lifecycle test file is the load-bearing convention every deployment-lifecycle regression MUST trip; deleting it silently removes the deployment-lifecycle gate.",
			deploymentLifecycleCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range deploymentLifecycleCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the deployment-lifecycle pair is the load-bearing assertion set every deployment-lifecycle regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + lifecycle-timestamp consistency + per-decision-stability contract for every downstream caller.",
				deploymentLifecycleCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteDeploymentLifecycleE2EAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts
// the matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a
// tightened regex, a relaxed substring set, a renamed constant)
// could silently let real regressions slip through.
func TestVerificationSuiteDeploymentLifecycleE2EAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			deploymentLifecycleCIWorkflowStepName,
			deploymentLifecycleCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Deployment lifecycle end-to-end tests\n        run: go test -run TestDeploymentLifecycleE2E ./...\n"
		for _, want := range []string{
			deploymentLifecycleCIWorkflowStepName,
			deploymentLifecycleCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, deploymentLifecycleVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", deploymentLifecycleVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 32. Required: deployment lifecycle end-to-end tests\nstep \"go test -run TestDeploymentLifecycleE2E ./...\"\nif ! go test -run TestDeploymentLifecycleE2E ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, deploymentLifecycleVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", deploymentLifecycleVerifyShStepHeader)
		}
		if !strings.Contains(doc, deploymentLifecycleVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", deploymentLifecycleVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n31. `go test -run TestServiceDesiredState ./...`\n"
		if strings.Contains(doc, deploymentLifecycleContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", deploymentLifecycleContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n31. `go test -run TestServiceDesiredState ./...`\n32. `go test -run TestDeploymentLifecycleE2E ./...`\n"
		if !strings.Contains(doc, deploymentLifecycleContributingEntry) {
			t.Fatalf("complete fixture missing %q", deploymentLifecycleContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Deployment Lifecycle End-to-End Tests\n\n")
		for _, want := range deploymentLifecycleSecuritySectionSubstrings {
			if want == "LogValue" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range deploymentLifecycleSecuritySectionSubstrings {
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
		b.WriteString("## Deployment Lifecycle End-to-End Tests\n\n")
		for _, want := range deploymentLifecycleSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range deploymentLifecycleSecuritySectionSubstrings {
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
			if cmd == deploymentLifecyclePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", deploymentLifecyclePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestDeploymentLifecycleE2E ./..."]}}`
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
			if cmd == deploymentLifecyclePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", deploymentLifecyclePRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package store_test\n\nimport \"testing\"\n\nfunc TestDeploymentLifecycleE2ECoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range deploymentLifecycleCanonicalFuncs {
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
		doc := "package store_test\n\nimport \"testing\"\n\nfunc TestDeploymentLifecycleE2ECoversCallSites(t *testing.T) {}\nfunc TestDeploymentLifecycleE2EPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range deploymentLifecycleCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestDeploymentLifecycleE2E substring locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantSubstring = "TestDeploymentLifecycleE2E"
		for _, want := range deploymentLifecycleCanonicalFuncs {
			if !strings.Contains(want, wantSubstring) {
				t.Errorf("canonical-funcs entry %q does not contain %q — the PRD's `-run TestDeploymentLifecycleE2E` filter binds to the `TestDeploymentLifecycleE2E` substring and would silently miss this function", want, wantSubstring)
			}
		}
	})
}
