package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — chaos tests for Dokploy timeouts (BE-0393).
//
// Threat model: the contract between Yalla's typed Dokploy client and
// every operator, AI agent, audit reviewer, or upstream retry surface
// is "every chaos-timeout failure surfaces as a *yerr.Error with
// Code=yerr.CodeTimeout attributed to apierr.DependencyDokploy, the
// caller's telemetry.HeaderRequestID propagates into every recorded
// attempt, the per-attempt timeout fires inside the bounded retry
// budget (POST attempted exactly once; GET and DELETE attempted 1 +
// MaxRetries), every Authorization header is redacted to
// output.Sentinel on the wire, and no Dokploy bearer token leaks at
// any level of the wrapped cause chain even under
// chaosWorkers * chaosIterationsPerWorker concurrent goroutines per
// scenario." That invariant is enforced by the canonical pair
// `TestChaosDokployTimeoutsCoversCallSites` and
// `TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope` in
// `internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go`. Both
// members are deterministic by design — they spin a per-iteration
// fake-Dokploy server up in-process and never reach a live Dokploy or
// any Postgres — so the gate stays green on every developer machine.
// The fake's TimeoutFault honours r.Context().Done() so each
// per-attempt deadline cancels the in-flight request and the harness
// finishes well under one second.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `chaos_dokploy_timeouts_test.go` file removed, or the canonical
// `TestChaosDokployTimeouts…` function pair renamed — would let a
// chaos-classification regression (a Dokploy timeout surfacing as
// E_INTERNAL, a POST silently retried after a timeout that duplicates
// a provisioning side effect, a request_id that fails to propagate
// from the calling context into the Dokploy attempt header, a leaked
// bearer token in an error message that an audit reviewer would
// otherwise spot) ship without firing any gate. An operator reading a
// Dokploy outage post-mortem would see misattributed timeouts, missed
// correlation between request_ids and Dokploy attempts, or — worst
// case — a leaked bearer token in an error message archive.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical chaos-timeout test fixture fails
// ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Chaos tests for Dokploy timeouts` that
//     invokes `go test -run TestChaosDokployTimeouts ./...`. Even
//     though the umbrella `go test ./...` step exercises the same
//     package, the dedicated step is defence-in-depth: a future
//     narrowing of the umbrella step would still leave this gate
//     firing as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestChaosDokployTimeouts ./...` under the
//     canonical step header
//     `# 18. Required: chaos tests for Dokploy timeouts`. The numeric
//     prefix is part of the contract: a reorder must be a deliberate
//     edit to both this constant and the script. #18 extends the
//     BE-0379..BE-0392 sequence by one slot; the trailing optionals
//     (#19 govulncheck, #20 staticcheck, #21 golangci-lint,
//     #22 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `18. \`go test -run TestChaosDokployTimeouts ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0392's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Chaos tests for Dokploy timeouts` row, AND a
//     dedicated `## Chaos Tests For Dokploy Timeouts` section MUST
//     explain the contract operators, auditors, and AI agents rely
//     on: the closed-set chaos-scenario coverage invariant (GET,
//     POST, DELETE call sites with the typed client's idempotency
//     rule), the runtime classification invariant (every failure maps
//     to yerr.CodeTimeout with DependencyDokploy), the
//     deterministic-by-default behaviour (in-process fake-Dokploy
//     per iteration, no Postgres, no live Dokploy), opt-in
//     `YALLA_EXTERNAL_DOKPLOY` external smoke, the
//     CI-on-every-push-and-PR cadence, and the actionable-failure
//     contract (failures carry the offending scenario name AND the
//     observed request_id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestChaosDokployTimeouts ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go` —
//     the canonical reference chaos-timeout test file MUST exist and
//     MUST declare the load-bearing function pair
//     (`TestChaosDokployTimeoutsCoversCallSites`,
//     `TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope`). The PRD's
//     `go test -run TestChaosDokployTimeouts ./...` filter binds to
//     the `TestChaosDokployTimeouts` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     chaos-timeout suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteChaosDokployTimeoutsAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the analyser)
// and under-tightening (a real regression slips through) are both
// caught at the package-internal API.

const (
	// chaosDokployTimeoutsCIWorkflowStepName is the exact step name CI
	// uses to invoke the chaos-timeout suite. A rename forces a
	// deliberate update both here and in the workflow.
	chaosDokployTimeoutsCIWorkflowStepName = "- name: Chaos tests for Dokploy timeouts"
	// chaosDokployTimeoutsCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestChaosDokployTimeouts…` test.
	chaosDokployTimeoutsCIWorkflowStepRun = "run: go test -run TestChaosDokployTimeouts ./..."

	// chaosDokployTimeoutsVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestChaosDokployTimeouts
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	chaosDokployTimeoutsVerifyShStepHeader = "# 18. Required: chaos tests for Dokploy timeouts"
	// chaosDokployTimeoutsVerifyShStepCmd is the literal command that
	// MUST appear inside the required-chaos-timeout step. Asserting on
	// the literal (not a regex over the file) makes the failure point
	// the operator at the exact line that drifted.
	chaosDokployTimeoutsVerifyShStepCmd = `go test -run TestChaosDokployTimeouts ./...`

	// chaosDokployTimeoutsContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	chaosDokployTimeoutsContributingEntry = "18. `go test -run TestChaosDokployTimeouts ./...`"

	// chaosDokployTimeoutsSecurityGateRow is the verification-gates
	// row that MUST appear in SECURITY.md so external operators and
	// reviewers can see the chaos-timeout suite is part of the
	// published security posture.
	chaosDokployTimeoutsSecurityGateRow = "| Chaos tests for Dokploy timeouts | `go test -run TestChaosDokployTimeouts ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// chaosDokployTimeoutsSecuritySectionHeading is the dedicated
	// `## Chaos Tests For Dokploy Timeouts` heading SECURITY.md MUST
	// carry. The section explains the closed-set scenario coverage
	// invariant, the runtime classification invariant, the
	// deterministic-by-default behaviour, the opt-in-external escape
	// hatch, the actionable-failure contract, and the schema-version
	// contract.
	chaosDokployTimeoutsSecuritySectionHeading = "## Chaos Tests For Dokploy Timeouts"

	// chaosDokployTimeoutsPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	chaosDokployTimeoutsPRDCommand = "go test -run TestChaosDokployTimeouts ./..."

	// chaosDokployTimeoutsCanonicalFile is the relative path of the
	// canonical reference chaos-timeout test file. The
	// `internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go`
	// file declares the function pair every chaos-timeout regression
	// MUST trip; deleting it silently kills the convention.
	chaosDokployTimeoutsCanonicalFile = "internal/controlplane/dokploy/chaos_dokploy_timeouts_test.go"
)

// chaosDokployTimeoutsCanonicalFuncs is the closed set of function
// declarations the canonical `chaos_dokploy_timeouts_test.go` file
// MUST carry. The PRD's `-run TestChaosDokployTimeouts` filter binds
// to function names containing the `TestChaosDokployTimeouts`
// substring; renaming any entry to a name that does not match the
// prefix silently de-gates the chaos-timeout suite for any caller
// relying on the filter. The pair captures the two load-bearing
// chaos-timeout invariants the harness MUST keep:
//
//   - TestChaosDokployTimeoutsCoversCallSites — the closed-set
//     chaos-scenario coverage invariant: the scenario table the burst
//     harness iterates MUST stay non-empty, free of duplicate names,
//     scoped to the typed Dokploy client surface (GET, POST, DELETE),
//     and every entry MUST carry a valid HTTP method, an attempt
//     count consistent with the idempotency rule (POST=1; GET/DELETE
//     =1+MaxRetries), a closed-set expected error code
//     (yerr.CodeTimeout), and a closed-set expected dependency
//     (apierr.DependencyDokploy). Trips at the package-internal API
//     with no infrastructure dependency.
//   - TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope — the
//     runtime chaos invariant: spinning the typed Dokploy client up
//     against a per-iteration fake-Dokploy server and firing
//     `chaosWorkers * chaosIterationsPerWorker` concurrent scenario
//     invocations MUST yield only failures that are typed *yerr.Error
//     values with Code=yerr.CodeTimeout attributed to
//     apierr.DependencyDokploy, with the bearer token redacted from
//     every level of the wrapped cause chain, with every recorded
//     request carrying the caller's telemetry.HeaderRequestID, and
//     with every recorded Authorization header redacted to
//     output.Sentinel. Failures surface with the offending scenario
//     name AND the observed request_id so an operator can correlate.
var chaosDokployTimeoutsCanonicalFuncs = []string{
	"func TestChaosDokployTimeoutsCoversCallSites(",
	"func TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope(",
}

// chaosDokployTimeoutsSecuritySectionSubstrings is the closed set of
// literal substrings the `## Chaos Tests For Dokploy Timeouts`
// section MUST contain. Each captures a different load-bearing fact
// the BE-0393 acceptance criteria require to be visible:
//
//   - "internal/controlplane/dokploy" — the package boundary the
//     canonical chaos-timeout harness lives in (AC1 documented suite
//     scope).
//   - "chaos_dokploy_timeouts_test.go" — the canonical reference
//     test file name; deleting it would break the function pair the
//     gate pivots on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process fake-Dokploy and no
//     other infrastructure dependency.
//   - "fake Dokploy"              — the AC7 fake-fixture contract;
//     the gate must never require a live Dokploy server.
//   - "TimeoutFault"              — the specific fake-Dokploy
//     primitive the runtime member uses; documenting it stops a
//     future test from drifting onto a different fault type that
//     does not exercise the timeout classification path.
//   - "yerr.CodeTimeout"          — the load-bearing typed-error
//     mapping the runtime classification invariant pins.
//   - "apierr.DependencyDokploy"  — the dependency tag every
//     chaos-timeout failure MUST carry.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (failures carry the observed request_id so
//     operators can correlate).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "TestChaosDokployTimeoutsCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope" — the
//     canonical runtime burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "YALLA_EXTERNAL_DOKPLOY"    — the AC2 opt-in-external escape
//     hatch shared with every BE-0379..BE-0392 sibling.
//   - "redacted"                  — the AC8 redaction contract; the
//     runtime member asserts no secret-shaped substring leaks in the
//     error chain or the recorded Authorization header.
//   - "verification_suite_chaos_dokploy_timeouts_static_test.go" —
//     the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var chaosDokployTimeoutsSecuritySectionSubstrings = []string{
	"internal/controlplane/dokploy",
	"chaos_dokploy_timeouts_test.go",
	"deterministic",
	"fake Dokploy",
	"TimeoutFault",
	"yerr.CodeTimeout",
	"apierr.DependencyDokploy",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestChaosDokployTimeoutsCoversCallSites",
	"TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope",
	"Every push and PR",
	"YALLA_EXTERNAL_DOKPLOY",
	"redacted",
	"verification_suite_chaos_dokploy_timeouts_static_test.go",
}

// TestVerificationSuiteChaosDokployTimeoutsCIWorkflow pins the GitHub
// Actions test job to run the canonical chaos-timeout command under
// the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth promise
// that even a regression in the umbrella `go test ./...` step would
// still leave this gate firing.
func TestVerificationSuiteChaosDokployTimeoutsCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		chaosDokployTimeoutsCIWorkflowStepName,
		chaosDokployTimeoutsCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI chaos-timeout step is the defence-in-depth gate for the closed-set chaos-scenario coverage + runtime classification invariants — every push and PR MUST run `go test -run TestChaosDokployTimeouts ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteChaosDokployTimeoutsVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestChaosDokployTimeouts ./...` under its canonical
// step header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteChaosDokployTimeoutsVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, chaosDokployTimeoutsVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-chaos-timeout block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, chaosDokployTimeoutsVerifyShStepHeader)
	}
	if !strings.Contains(doc, chaosDokployTimeoutsVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same chaos-timeout command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, chaosDokployTimeoutsVerifyShStepCmd)
	}
}

// TestVerificationSuiteChaosDokployTimeoutsContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteChaosDokployTimeoutsContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, chaosDokployTimeoutsContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, chaosDokployTimeoutsContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteChaosDokployTimeoutsSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the chaos-timeout gate part of
// the published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteChaosDokployTimeoutsSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, chaosDokployTimeoutsSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, chaosDokployTimeoutsSecurityGateRow)
	}
	if !strings.Contains(doc, chaosDokployTimeoutsSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-chaos-scenario-coverage / runtime-classification-invariant / deterministic-by-default / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, chaosDokployTimeoutsSecuritySectionHeading)
	}
	for _, want := range chaosDokployTimeoutsSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, chaosDokployTimeoutsSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteChaosDokployTimeoutsPRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// chaos-timeout command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteChaosDokployTimeoutsPRDDocumentsCommand(t *testing.T) {
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
		if cmd == chaosDokployTimeoutsPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the chaos-timeout gate as a required backend command.",
		requiredPRDPath, chaosDokployTimeoutsPRDCommand)
}

// TestVerificationSuiteChaosDokployTimeoutsCanonicalFileExists pins
// the canonical reference chaos-timeout test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the
// `TestChaosDokployTimeouts` prefix silently de-gates the
// chaos-timeout suite for any caller relying on the PRD's
// `-run TestChaosDokployTimeouts` filter.
func TestVerificationSuiteChaosDokployTimeoutsCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(chaosDokployTimeoutsCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical chaos-timeout test file is the load-bearing convention every chaos-timeout regression MUST trip; deleting it silently removes the chaos-timeout gate.",
			chaosDokployTimeoutsCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range chaosDokployTimeoutsCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the chaos-timeout pair is the load-bearing assertion set every chaos-timeout regression MUST trip — a rename or deletion silently relaxes the closed-set-chaos-scenario-coverage + runtime-classification contract for every downstream caller.",
				chaosDokployTimeoutsCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteChaosDokployTimeoutsAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteChaosDokployTimeoutsAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			chaosDokployTimeoutsCIWorkflowStepName,
			chaosDokployTimeoutsCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Chaos tests for Dokploy timeouts\n        run: go test -run TestChaosDokployTimeouts ./...\n"
		for _, want := range []string{
			chaosDokployTimeoutsCIWorkflowStepName,
			chaosDokployTimeoutsCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, chaosDokployTimeoutsVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", chaosDokployTimeoutsVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 18. Required: chaos tests for Dokploy timeouts\nstep \"go test -run TestChaosDokployTimeouts ./...\"\nif ! go test -run TestChaosDokployTimeouts ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, chaosDokployTimeoutsVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", chaosDokployTimeoutsVerifyShStepHeader)
		}
		if !strings.Contains(doc, chaosDokployTimeoutsVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", chaosDokployTimeoutsVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n16. `go test -run TestMigrationsDowngradeSafety ./...`\n17. `go test -run TestLoadSmoke ./...`\n"
		if strings.Contains(doc, chaosDokployTimeoutsContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", chaosDokployTimeoutsContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n16. `go test -run TestMigrationsDowngradeSafety ./...`\n17. `go test -run TestLoadSmoke ./...`\n18. `go test -run TestChaosDokployTimeouts ./...`\n"
		if !strings.Contains(doc, chaosDokployTimeoutsContributingEntry) {
			t.Fatalf("complete fixture missing %q", chaosDokployTimeoutsContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yerr.CodeTimeout"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Chaos Tests For Dokploy Timeouts\n\n")
		for _, want := range chaosDokployTimeoutsSecuritySectionSubstrings {
			if want == "yerr.CodeTimeout" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range chaosDokployTimeoutsSecuritySectionSubstrings {
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
		b.WriteString("## Chaos Tests For Dokploy Timeouts\n\n")
		for _, want := range chaosDokployTimeoutsSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range chaosDokployTimeoutsSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestLoadSmoke ./..."]}}`
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
			if cmd == chaosDokployTimeoutsPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", chaosDokployTimeoutsPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestChaosDokployTimeouts ./..."]}}`
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
			if cmd == chaosDokployTimeoutsPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", chaosDokployTimeoutsPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic chaos_dokploy_timeouts_test.go declaring only one
		// of the two canonical functions. The matcher MUST fire on
		// the missing second.
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestChaosDokployTimeoutsCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range chaosDokployTimeoutsCanonicalFuncs {
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
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestChaosDokployTimeoutsCoversCallSites(t *testing.T) {}\nfunc TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope(t *testing.T) {}\n"
		for _, want := range chaosDokployTimeoutsCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestChaosDokployTimeouts prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestChaosDokployTimeouts ./...`
		// filter binds to function names containing the
		// `TestChaosDokployTimeouts` substring. A canonical-funcs
		// entry that drops the prefix would silently de-gate the
		// chaos-timeout suite for any caller relying on the filter.
		// This subtest asserts every canonical-funcs entry begins
		// with `func TestChaosDokployTimeouts`.
		const wantPrefix = "func TestChaosDokployTimeouts"
		for _, want := range chaosDokployTimeoutsCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestChaosDokployTimeouts` filter binds to the `TestChaosDokployTimeouts` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
