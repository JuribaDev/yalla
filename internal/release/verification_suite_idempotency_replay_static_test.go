package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — idempotency replay tests (BE-0395).
//
// Threat model: the contract between Yalla's HTTP idempotency
// middleware and every agent, CI runner, audit reviewer, or operator
// that retries an unsafe request is "a second request with the same
// Idempotency-Key and the same body replays the original response
// byte-identically — same status, same envelope bytes, with the
// Idempotency-Replayed: true header — without re-invoking the wrapped
// handler, for every outcome category the middleware records
// (success, validation failure, authorization failure, not-found
// failure), even under concurrent retry contention, and without
// reflecting any sentinel marker from the submitted request body into
// the recorded claim or the replayed response." That invariant is
// enforced by the canonical pair
// `TestIdempotencyReplayCoversCallSites` and
// `TestIdempotencyReplayPreservesByteIdenticalEnvelope` in
// `internal/controlplane/httpapi/idempotency_replay_test.go`. Both
// members are deterministic by design — they use the in-process
// `fakeIdempotencyStore` and the package-local `recordingHandler`, so
// the gate stays green on every developer machine without a live
// Postgres or any external dependency.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `idempotency_replay_test.go` file removed, or the canonical
// `TestIdempotencyReplay…` function pair renamed — would let a
// replay-classification regression (a retry that re-runs the handler
// and double-creates a project, a recorded body that drifts on
// replay so an agent sees a different `request_id` on the second
// call, an in-memory recorder that returns truncated bytes under
// concurrent retries, or a submitted request body reflected into the
// recorded envelope so an Authorization-Bearer sentinel surfaces in
// an audit log) ship without firing any gate. An operator reading an
// idempotency-retry incident post-mortem would see double-mutations,
// inconsistent agent-visible request_ids, or — worst case — a leaked
// credential in a recorded claim row.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical idempotency-replay test fixture
// fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Idempotency replay tests` that invokes
//     `go test -run TestIdempotencyReplay ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestIdempotencyReplay ./...` under the canonical
//     step header `# 20. Required: idempotency replay tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #20
//     extends the BE-0379..BE-0394 sequence by one slot; the trailing
//     optionals (#21 govulncheck, #22 staticcheck, #23 golangci-lint,
//     #24 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `20. \`go test -run TestIdempotencyReplay ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0394's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Idempotency replay tests` row, AND a dedicated
//     `## Idempotency Replay Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     coverage invariant (success / validation failure /
//     authorization failure / not-found, with the 5xx exclusion
//     spelled out so a reader understands why server failures are not
//     replayed), the byte-identical-envelope invariant under
//     concurrent retry contention, the deterministic-by-default
//     behaviour (in-process `fakeIdempotencyStore` per scenario, no
//     live Postgres, no live Dokploy), the
//     CI-on-every-push-and-PR cadence, the schema-version contract
//     (`yalla.output.v1` / `yalla.error.v1`), and the redaction
//     contract (no sentinel marker placed inside the submitted
//     request body leaks into the recorded claim or the replayed
//     response).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestIdempotencyReplay ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/httpapi/idempotency_replay_test.go` —
//     the canonical reference idempotency-replay test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestIdempotencyReplayCoversCallSites`,
//     `TestIdempotencyReplayPreservesByteIdenticalEnvelope`). The
//     PRD's `go test -run TestIdempotencyReplay ./...` filter binds
//     to the `TestIdempotencyReplay` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     idempotency-replay suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteIdempotencyReplayAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// idempotencyReplayCIWorkflowStepName is the exact step name CI
	// uses to invoke the idempotency-replay suite. A rename forces a
	// deliberate update both here and in the workflow.
	idempotencyReplayCIWorkflowStepName = "- name: Idempotency replay tests"
	// idempotencyReplayCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestIdempotencyReplay…` test.
	idempotencyReplayCIWorkflowStepRun = "run: go test -run TestIdempotencyReplay ./..."

	// idempotencyReplayVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestIdempotencyReplay
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	idempotencyReplayVerifyShStepHeader = "# 20. Required: idempotency replay tests"
	// idempotencyReplayVerifyShStepCmd is the literal command that
	// MUST appear inside the required-idempotency-replay step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	idempotencyReplayVerifyShStepCmd = `go test -run TestIdempotencyReplay ./...`

	// idempotencyReplayContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	idempotencyReplayContributingEntry = "20. `go test -run TestIdempotencyReplay ./...`"

	// idempotencyReplaySecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the idempotency-replay suite is part of the
	// published security posture.
	idempotencyReplaySecurityGateRow = "| Idempotency replay tests | `go test -run TestIdempotencyReplay ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// idempotencyReplaySecuritySectionHeading is the dedicated
	// `## Idempotency Replay Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant, the
	// byte-identical-envelope invariant, the deterministic-by-default
	// behaviour, the actionable-failure contract, the schema-version
	// contract, and the redaction contract.
	idempotencyReplaySecuritySectionHeading = "## Idempotency Replay Tests"

	// idempotencyReplayPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	idempotencyReplayPRDCommand = "go test -run TestIdempotencyReplay ./..."

	// idempotencyReplayCanonicalFile is the relative path of the
	// canonical reference idempotency-replay test file. The
	// `internal/controlplane/httpapi/idempotency_replay_test.go` file
	// declares the function pair every idempotency-replay regression
	// MUST trip; deleting it silently kills the convention.
	idempotencyReplayCanonicalFile = "internal/controlplane/httpapi/idempotency_replay_test.go"
)

// idempotencyReplayCanonicalFuncs is the closed set of function
// declarations the canonical `idempotency_replay_test.go` file MUST
// carry. The PRD's `-run TestIdempotencyReplay` filter binds to
// function names containing the `TestIdempotencyReplay` substring;
// renaming any entry to a name that does not match the prefix
// silently de-gates the idempotency-replay suite for any caller
// relying on the filter. The pair captures the two load-bearing
// idempotency-replay invariants the harness MUST keep:
//
//   - TestIdempotencyReplayCoversCallSites — the closed-set replay
//     coverage invariant: for each outcome category the middleware
//     records (success / validation failure / authorization failure /
//     not-found failure) a second request with the same Idempotency-
//     Key and the same body MUST receive the byte-identical recorded
//     envelope, the same status, and an Idempotency-Replayed: true
//     header, without re-invoking the wrapped handler, and without
//     reflecting a sentinel marker placed inside the submitted body
//     into the recorded claim or the replayed response. Trips at the
//     package-internal API with no infrastructure dependency.
//   - TestIdempotencyReplayPreservesByteIdenticalEnvelope — the
//     deterministic replay invariant under contention: seeding a
//     completed claim and firing
//     `replayWorkers * replayIterationsPerWorker` concurrent retries
//     against the same key MUST yield byte-identical replayed bodies,
//     identical statuses, the Idempotency-Replayed: true header on
//     every retry, and exactly zero handler invocations across the
//     burst. A drift in the body bytes, the status, the replay header,
//     or the run count under contention is the regression report.
var idempotencyReplayCanonicalFuncs = []string{
	"func TestIdempotencyReplayCoversCallSites(",
	"func TestIdempotencyReplayPreservesByteIdenticalEnvelope(",
}

// idempotencyReplaySecuritySectionSubstrings is the closed set of
// literal substrings the `## Idempotency Replay Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0395
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/httpapi" — the package boundary the
//     canonical idempotency-replay harness lives in (AC1 documented
//     suite scope).
//   - "idempotency_replay_test.go" — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process fakeIdempotencyStore
//     and no other infrastructure dependency.
//   - "fakeIdempotencyStore"      — the in-memory store the test
//     harness uses. Documenting it stops a future test from drifting
//     onto a different fixture that does not exercise the replay path.
//   - "Idempotency-Replayed"      — the wire-contract header agents
//     read to distinguish a replay from a first execution.
//   - "Idempotency-Key"           — the wire-contract request header
//     that opts a request into the idempotency path.
//   - "byte-identical"            — the AC determinism contract for
//     replayed responses; a regression that re-rendered the envelope
//     on replay would drift here.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (the recorded body carries the original request_id
//     so an agent's replay observes the same correlation token).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "E_INVALID_INPUT"           — the AC6 validation-failure error
//     code; pinning it stops a future test from drifting onto a
//     different error category.
//   - "E_FORBIDDEN"               — the AC6 authorization-failure
//     error code.
//   - "E_NOT_FOUND"               — the AC6 not-found error code.
//   - "TestIdempotencyReplayCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestIdempotencyReplayPreservesByteIdenticalEnvelope" — the
//     canonical runtime burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "redacted"                  — the AC8 redaction contract; the
//     coverage member asserts no sentinel marker placed inside the
//     submitted body leaks into the recorded claim or the replayed
//     response.
//   - "verification_suite_idempotency_replay_static_test.go" — the
//     gate is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var idempotencyReplaySecuritySectionSubstrings = []string{
	"internal/controlplane/httpapi",
	"idempotency_replay_test.go",
	"deterministic",
	"fakeIdempotencyStore",
	"Idempotency-Replayed",
	"Idempotency-Key",
	"byte-identical",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"E_INVALID_INPUT",
	"E_FORBIDDEN",
	"E_NOT_FOUND",
	"TestIdempotencyReplayCoversCallSites",
	"TestIdempotencyReplayPreservesByteIdenticalEnvelope",
	"Every push and PR",
	"redacted",
	"verification_suite_idempotency_replay_static_test.go",
}

// TestVerificationSuiteIdempotencyReplayCIWorkflow pins the GitHub
// Actions test job to run the canonical idempotency-replay command
// under the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth promise
// that even a regression in the umbrella `go test ./...` step would
// still leave this gate firing.
func TestVerificationSuiteIdempotencyReplayCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		idempotencyReplayCIWorkflowStepName,
		idempotencyReplayCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI idempotency-replay step is the defence-in-depth gate for the closed-set replay-coverage + byte-identical-envelope invariants — every push and PR MUST run `go test -run TestIdempotencyReplay ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteIdempotencyReplayVerifyShRunsCanonicalCommand
// pins the local commit gate to run `go test -run TestIdempotencyReplay
// ./...` under its canonical step header so a contributor running the
// gate locally exercises the identical command CI runs.
func TestVerificationSuiteIdempotencyReplayVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, idempotencyReplayVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-idempotency-replay block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, idempotencyReplayVerifyShStepHeader)
	}
	if !strings.Contains(doc, idempotencyReplayVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same idempotency-replay command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, idempotencyReplayVerifyShStepCmd)
	}
}

// TestVerificationSuiteIdempotencyReplayContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteIdempotencyReplayContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, idempotencyReplayContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, idempotencyReplayContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteIdempotencyReplaySecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the idempotency-replay gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteIdempotencyReplaySecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, idempotencyReplaySecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, idempotencyReplaySecurityGateRow)
	}
	if !strings.Contains(doc, idempotencyReplaySecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / byte-identical-envelope / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, idempotencyReplaySecuritySectionHeading)
	}
	for _, want := range idempotencyReplaySecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, idempotencyReplaySecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteIdempotencyReplayPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// idempotency-replay command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteIdempotencyReplayPRDDocumentsCommand(t *testing.T) {
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
		if cmd == idempotencyReplayPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the idempotency-replay gate as a required backend command.",
		requiredPRDPath, idempotencyReplayPRDCommand)
}

// TestVerificationSuiteIdempotencyReplayCanonicalFileExists pins the
// canonical reference idempotency-replay test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestIdempotencyReplay`
// prefix silently de-gates the idempotency-replay suite for any
// caller relying on the PRD's `-run TestIdempotencyReplay` filter.
func TestVerificationSuiteIdempotencyReplayCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(idempotencyReplayCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical idempotency-replay test file is the load-bearing convention every idempotency-replay regression MUST trip; deleting it silently removes the idempotency-replay gate.",
			idempotencyReplayCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range idempotencyReplayCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the idempotency-replay pair is the load-bearing assertion set every idempotency-replay regression MUST trip — a rename or deletion silently relaxes the closed-set-replay-coverage + byte-identical-envelope contract for every downstream caller.",
				idempotencyReplayCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteIdempotencyReplayAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteIdempotencyReplayAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			idempotencyReplayCIWorkflowStepName,
			idempotencyReplayCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Idempotency replay tests\n        run: go test -run TestIdempotencyReplay ./...\n"
		for _, want := range []string{
			idempotencyReplayCIWorkflowStepName,
			idempotencyReplayCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, idempotencyReplayVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", idempotencyReplayVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 20. Required: idempotency replay tests\nstep \"go test -run TestIdempotencyReplay ./...\"\nif ! go test -run TestIdempotencyReplay ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, idempotencyReplayVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", idempotencyReplayVerifyShStepHeader)
		}
		if !strings.Contains(doc, idempotencyReplayVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", idempotencyReplayVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n19. `go test -run TestChaosPostgresDisconnects ./...`\n"
		if strings.Contains(doc, idempotencyReplayContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", idempotencyReplayContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n19. `go test -run TestChaosPostgresDisconnects ./...`\n20. `go test -run TestIdempotencyReplay ./...`\n"
		if !strings.Contains(doc, idempotencyReplayContributingEntry) {
			t.Fatalf("complete fixture missing %q", idempotencyReplayContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Idempotency Replay Tests\n\n")
		for _, want := range idempotencyReplaySecuritySectionSubstrings {
			if want == "byte-identical" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range idempotencyReplaySecuritySectionSubstrings {
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
		b.WriteString("## Idempotency Replay Tests\n\n")
		for _, want := range idempotencyReplaySecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range idempotencyReplaySecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestChaosPostgresDisconnects ./..."]}}`
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
			if cmd == idempotencyReplayPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", idempotencyReplayPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
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
			if cmd == idempotencyReplayPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", idempotencyReplayPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestIdempotencyReplayCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range idempotencyReplayCanonicalFuncs {
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
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestIdempotencyReplayCoversCallSites(t *testing.T) {}\nfunc TestIdempotencyReplayPreservesByteIdenticalEnvelope(t *testing.T) {}\n"
		for _, want := range idempotencyReplayCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestIdempotencyReplay prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestIdempotencyReplay"
		for _, want := range idempotencyReplayCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestIdempotencyReplay` filter binds to the `TestIdempotencyReplay` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
