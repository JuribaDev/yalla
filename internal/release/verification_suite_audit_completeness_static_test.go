package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — audit completeness tests (BE-0396).
//
// Threat model: the audit log is the only persistent record an
// operator, auditor, or downstream incident-response agent has of
// security-relevant policy decisions. The contract every agent, CI
// runner, and operator relies on is "every security-relevant policy
// decision recorded through audit.Auditor.Record surfaces as a
// store.AuditEvent that carries the full closed set of identifying
// fields — action, resource kind, resource id, decision (allowed |
// denied), reason, organization id, actor id, actor kind, request id,
// correlation id — for BOTH allowed AND denied decisions across the
// canonical action surface (organization / project / environment /
// service / api_key / grants / admin break-glass), with every
// metadata value redacted before persistence so a sentinel marker
// placed under a sensitive-shaped key never reaches the audit log,
// and under concurrent emission no event is dropped, spuriously
// added, or cross-written with another emitter's fields." That
// invariant is enforced by the canonical pair
// `TestAuditCompletenessCoversCallSites` and
// `TestAuditCompletenessPreservesRecordedFieldsUnderContention` in
// `internal/controlplane/audit/audit_completeness_test.go`. Both pair
// members are deterministic by design — they use the in-package
// `fakeRecorder` (and a file-local `concurrentAuditRecorder` for the
// burst), so the gate stays green on every developer machine without
// a live Postgres or any external dependency.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `audit_completeness_test.go` file removed, or the canonical
// `TestAuditCompleteness…` function pair renamed — would let an
// audit-completeness regression (a denied decision that is never
// written to the audit log because the deny path forgot to call
// Record; a recorded event that drops its request_id because the
// auth middleware regressed; a cross-write under contention where
// one emitter's request_id lands on another's recorded event; a
// sensitive-shaped metadata value reflected unredacted into the
// recorded Metadata or into a non-Metadata field) ship without
// firing any gate. An operator reading an incident post-mortem would
// see missing audit rows, mis-attributed actors, or — worst case — a
// leaked credential in a recorded Metadata value.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical audit-completeness test fixture
// fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Audit completeness tests` that invokes
//     `go test -run TestAuditCompleteness ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestAuditCompleteness ./...` under the canonical
//     step header `# 21. Required: audit completeness tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #21
//     extends the BE-0379..BE-0395 sequence by one slot; the trailing
//     optionals (#22 govulncheck, #23 staticcheck, #24 golangci-lint,
//     #25 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `21. \`go test -run TestAuditCompleteness ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0395's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Audit completeness tests` row, AND a dedicated
//     `## Audit Completeness Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     coverage invariant (allowed AND denied decisions across every
//     canonical action surface), the per-emitter field-fidelity
//     invariant under concurrent emission, the deterministic-by-
//     default behaviour (in-process `fakeRecorder` /
//     `concurrentAuditRecorder`, no live Postgres, no live Dokploy),
//     the CI-on-every-push-and-PR cadence, the schema-version
//     contract (`yalla.output.v1` / `yalla.error.v1`), and the
//     redaction contract (no sentinel marker placed under a
//     sensitive-shaped metadata key leaks into the recorded event).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestAuditCompleteness ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/audit/audit_completeness_test.go` — the
//     canonical reference audit-completeness test file MUST exist and
//     MUST declare the load-bearing function pair
//     (`TestAuditCompletenessCoversCallSites`,
//     `TestAuditCompletenessPreservesRecordedFieldsUnderContention`).
//     The PRD's `go test -run TestAuditCompleteness ./...` filter
//     binds to the `TestAuditCompleteness` prefix; a rename to a
//     function whose name does not match the prefix silently de-gates
//     the audit-completeness suite for any caller relying on the
//     `-run` filter.
//
// The self-check
// (`TestVerificationSuiteAuditCompletenessAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// auditCompletenessCIWorkflowStepName is the exact step name CI
	// uses to invoke the audit-completeness suite. A rename forces a
	// deliberate update both here and in the workflow.
	auditCompletenessCIWorkflowStepName = "- name: Audit completeness tests"
	// auditCompletenessCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestAuditCompleteness…` test.
	auditCompletenessCIWorkflowStepRun = "run: go test -run TestAuditCompleteness ./..."

	// auditCompletenessVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestAuditCompleteness
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	auditCompletenessVerifyShStepHeader = "# 21. Required: audit completeness tests"
	// auditCompletenessVerifyShStepCmd is the literal command that
	// MUST appear inside the required-audit-completeness step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	auditCompletenessVerifyShStepCmd = `go test -run TestAuditCompleteness ./...`

	// auditCompletenessContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	auditCompletenessContributingEntry = "21. `go test -run TestAuditCompleteness ./...`"

	// auditCompletenessSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the audit-completeness suite is part of the
	// published security posture.
	auditCompletenessSecurityGateRow = "| Audit completeness tests | `go test -run TestAuditCompleteness ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// auditCompletenessSecuritySectionHeading is the dedicated
	// `## Audit Completeness Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant, the
	// per-emitter field-fidelity invariant, the deterministic-by-
	// default behaviour, the actionable-failure contract, the
	// schema-version contract, and the redaction contract.
	auditCompletenessSecuritySectionHeading = "## Audit Completeness Tests"

	// auditCompletenessPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	auditCompletenessPRDCommand = "go test -run TestAuditCompleteness ./..."

	// auditCompletenessCanonicalFile is the relative path of the
	// canonical reference audit-completeness test file. The
	// `internal/controlplane/audit/audit_completeness_test.go` file
	// declares the function pair every audit-completeness regression
	// MUST trip; deleting it silently kills the convention.
	auditCompletenessCanonicalFile = "internal/controlplane/audit/audit_completeness_test.go"
)

// auditCompletenessCanonicalFuncs is the closed set of function
// declarations the canonical `audit_completeness_test.go` file MUST
// carry. The PRD's `-run TestAuditCompleteness` filter binds to
// function names containing the `TestAuditCompleteness` substring;
// renaming any entry to a name that does not match the prefix
// silently de-gates the audit-completeness suite for any caller
// relying on the filter. The pair captures the two load-bearing
// audit-completeness invariants the harness MUST keep:
//
//   - TestAuditCompletenessCoversCallSites — the closed-set audit-
//     completeness coverage invariant: for each canonical action-
//     surface scenario the test asserts every required field
//     (Action, ResourceKind, ResourceID, Decision, Reason,
//     OrganizationID, ActorID, ActorKind, RequestID, CorrelationID)
//     is non-empty on the recorded event, every value matches the
//     scenario inputs byte-for-byte, the sensitive-shaped metadata
//     value is redacted to `output.Sentinel`, and the sentinel
//     marker never leaks into a non-Metadata recorded field. Trips
//     at the package-internal API with no infrastructure dependency.
//   - TestAuditCompletenessPreservesRecordedFieldsUnderContention —
//     the per-emitter field-fidelity invariant under contention:
//     seeding a single shared audit.Auditor from
//     `auditCompletenessWorkers * auditCompletenessIterationsPerWorker`
//     goroutines MUST yield exactly that many captured events, every
//     event's request_id MUST resolve to its emitter (no drop, no
//     duplicate, no cross-write), and the sentinel marker MUST stay
//     redacted on every event.
var auditCompletenessCanonicalFuncs = []string{
	"func TestAuditCompletenessCoversCallSites(",
	"func TestAuditCompletenessPreservesRecordedFieldsUnderContention(",
}

// auditCompletenessSecuritySectionSubstrings is the closed set of
// literal substrings the `## Audit Completeness Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0396
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/audit" — the package boundary the
//     canonical audit-completeness harness lives in (AC1 documented
//     suite scope).
//   - "audit_completeness_test.go" — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process `fakeRecorder` /
//     `concurrentAuditRecorder` and no other infrastructure
//     dependency.
//   - "fakeRecorder"              — the in-memory single-call
//     recorder reused from `audit_test.go` by the coverage member.
//   - "concurrentAuditRecorder"   — the in-memory mutex-guarded
//     recorder declared by the burst member; documenting it stops a
//     future contention test from drifting onto a different fixture
//     that does not exercise the audit-completeness contract.
//   - "Auditor.Record"            — the single chokepoint the gate
//     pivots on; recording bypasses MUST go through this method so
//     the audit log stays uniform and redacted.
//   - "allowed"                   — the AC closed-set coverage
//     anchor for allowed decisions.
//   - "denied"                    — the AC closed-set coverage
//     anchor for denied decisions; an audit log that omits denied
//     decisions is incomplete by definition.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (every recorded event carries the originating
//     request_id so an operator can correlate without re-running
//     the suite locally).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "policy.Action"             — the canonical action-surface
//     type the closed-set coverage scenario table iterates.
//   - "policy.Decision"           — the canonical verdict type the
//     coverage member asserts on; an audit row whose Decision does
//     not match the policy verdict is a regression.
//   - "TestAuditCompletenessCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestAuditCompletenessPreservesRecordedFieldsUnderContention" —
//     the canonical runtime burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "redacted"                  — the AC8 redaction contract; the
//     coverage member asserts the sensitive-shaped metadata value is
//     replaced with `output.Sentinel` on the recorded event.
//   - "verification_suite_audit_completeness_static_test.go" — the
//     gate is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var auditCompletenessSecuritySectionSubstrings = []string{
	"internal/controlplane/audit",
	"audit_completeness_test.go",
	"deterministic",
	"fakeRecorder",
	"concurrentAuditRecorder",
	"Auditor.Record",
	"allowed",
	"denied",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"policy.Action",
	"policy.Decision",
	"TestAuditCompletenessCoversCallSites",
	"TestAuditCompletenessPreservesRecordedFieldsUnderContention",
	"Every push and PR",
	"redacted",
	"verification_suite_audit_completeness_static_test.go",
}

// TestVerificationSuiteAuditCompletenessCIWorkflow pins the GitHub
// Actions test job to run the canonical audit-completeness command
// under the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth promise
// that even a regression in the umbrella `go test ./...` step would
// still leave this gate firing.
func TestVerificationSuiteAuditCompletenessCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		auditCompletenessCIWorkflowStepName,
		auditCompletenessCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI audit-completeness step is the defence-in-depth gate for the closed-set audit-coverage + per-emitter field-fidelity invariants — every push and PR MUST run `go test -run TestAuditCompleteness ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteAuditCompletenessVerifyShRunsCanonicalCommand
// pins the local commit gate to run `go test -run TestAuditCompleteness
// ./...` under its canonical step header so a contributor running the
// gate locally exercises the identical command CI runs.
func TestVerificationSuiteAuditCompletenessVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, auditCompletenessVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-audit-completeness block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, auditCompletenessVerifyShStepHeader)
	}
	if !strings.Contains(doc, auditCompletenessVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same audit-completeness command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, auditCompletenessVerifyShStepCmd)
	}
}

// TestVerificationSuiteAuditCompletenessContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteAuditCompletenessContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, auditCompletenessContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, auditCompletenessContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteAuditCompletenessSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the audit-completeness gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteAuditCompletenessSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, auditCompletenessSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, auditCompletenessSecurityGateRow)
	}
	if !strings.Contains(doc, auditCompletenessSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / per-emitter-field-fidelity / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, auditCompletenessSecuritySectionHeading)
	}
	for _, want := range auditCompletenessSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, auditCompletenessSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteAuditCompletenessPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// audit-completeness command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteAuditCompletenessPRDDocumentsCommand(t *testing.T) {
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
		if cmd == auditCompletenessPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the audit-completeness gate as a required backend command.",
		requiredPRDPath, auditCompletenessPRDCommand)
}

// TestVerificationSuiteAuditCompletenessCanonicalFileExists pins the
// canonical reference audit-completeness test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestAuditCompleteness`
// prefix silently de-gates the audit-completeness suite for any
// caller relying on the PRD's `-run TestAuditCompleteness` filter.
func TestVerificationSuiteAuditCompletenessCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(auditCompletenessCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical audit-completeness test file is the load-bearing convention every audit-completeness regression MUST trip; deleting it silently removes the audit-completeness gate.",
			auditCompletenessCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range auditCompletenessCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the audit-completeness pair is the load-bearing assertion set every audit-completeness regression MUST trip — a rename or deletion silently relaxes the closed-set-audit-coverage + per-emitter-field-fidelity contract for every downstream caller.",
				auditCompletenessCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteAuditCompletenessAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteAuditCompletenessAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			auditCompletenessCIWorkflowStepName,
			auditCompletenessCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Audit completeness tests\n        run: go test -run TestAuditCompleteness ./...\n"
		for _, want := range []string{
			auditCompletenessCIWorkflowStepName,
			auditCompletenessCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, auditCompletenessVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", auditCompletenessVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 21. Required: audit completeness tests\nstep \"go test -run TestAuditCompleteness ./...\"\nif ! go test -run TestAuditCompleteness ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, auditCompletenessVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", auditCompletenessVerifyShStepHeader)
		}
		if !strings.Contains(doc, auditCompletenessVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", auditCompletenessVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n20. `go test -run TestIdempotencyReplay ./...`\n"
		if strings.Contains(doc, auditCompletenessContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", auditCompletenessContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n20. `go test -run TestIdempotencyReplay ./...`\n21. `go test -run TestAuditCompleteness ./...`\n"
		if !strings.Contains(doc, auditCompletenessContributingEntry) {
			t.Fatalf("complete fixture missing %q", auditCompletenessContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Audit Completeness Tests\n\n")
		for _, want := range auditCompletenessSecuritySectionSubstrings {
			if want == "denied" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range auditCompletenessSecuritySectionSubstrings {
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
		b.WriteString("## Audit Completeness Tests\n\n")
		for _, want := range auditCompletenessSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range auditCompletenessSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestIdempotencyReplay ./..."]}}`
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
			if cmd == auditCompletenessPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", auditCompletenessPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestAuditCompleteness ./..."]}}`
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
			if cmd == auditCompletenessPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", auditCompletenessPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package audit_test\n\nimport \"testing\"\n\nfunc TestAuditCompletenessCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range auditCompletenessCanonicalFuncs {
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
		doc := "package audit_test\n\nimport \"testing\"\n\nfunc TestAuditCompletenessCoversCallSites(t *testing.T) {}\nfunc TestAuditCompletenessPreservesRecordedFieldsUnderContention(t *testing.T) {}\n"
		for _, want := range auditCompletenessCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestAuditCompleteness prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestAuditCompleteness"
		for _, want := range auditCompletenessCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestAuditCompleteness` filter binds to the `TestAuditCompleteness` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
