package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — chaos tests for Postgres disconnects (BE-0394).
//
// Threat model: the contract between Yalla's store layer and every
// operator, AI agent, audit reviewer, or upstream retry surface that
// consumes a Postgres-disconnect failure is "every chaos-disconnect
// failure surfaces as a *yerr.Error with Code=yerr.CodeUnavailable
// attributed to apierr.DependencyStore (via apierr.StoreUnavailable),
// the caller's telemetry request_id propagates through the per-op
// context so an operator can correlate the gate failure with a
// specific in-flight chaos run, the fake records at least one
// accepted TCP connection per attempt so a regression that
// short-circuited pgx without ever attempting a network connect trips
// here, the wrapped envelope's rendered Error() message stays static
// (apierr.StoreUnavailable MUST NOT echo any pgx cause-chain field —
// neither the DSN password nor the DSN username), and no DSN password
// literal leaks at any level of the wrapped cause chain even under
// chaosPostgresWorkers * chaosPostgresIterationsPerWorker concurrent
// goroutines per scenario." That invariant is enforced by the
// canonical pair `TestChaosPostgresDisconnectsCoversCallSites` and
// `TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope` in
// `internal/controlplane/store/chaos_postgres_disconnects_test.go`.
// Both members are deterministic by design — they spin a per-iteration
// `fakepg.Server` (a tiny TCP listener that gracefully closes accepted
// connections so pgx fails on its startup-handshake read) up
// in-process and never reach a live Postgres or any Dokploy server —
// so the gate stays green on every developer machine. The fake closes
// gracefully (FIN, not RST) so pgx's dial completes and the chaos
// error surfaces on the startup-handshake read, which is the
// production failure mode an actual Postgres restart or network
// partition produces.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `chaos_postgres_disconnects_test.go` file removed, or the canonical
// `TestChaosPostgresDisconnects…` function pair renamed — would let a
// disconnect-classification regression (a Postgres disconnect
// surfacing as E_INTERNAL or E_TIMEOUT instead of E_UNAVAILABLE, a
// store-layer call that classifies a transient transport failure as a
// permanent failure and refuses to retry, a request_id that fails to
// propagate through the per-op context so an operator cannot correlate
// the failure with the originating request, or a DSN password leak in
// an error message archive an audit reviewer would otherwise spot)
// ship without firing any gate. An operator reading a Postgres outage
// post-mortem would see misattributed disconnects, missed correlation
// between request_ids and store ops, or — worst case — a leaked DSN
// password in an error message archive.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical chaos-disconnect test fixture fails
// ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Chaos tests for Postgres disconnects` that
//     invokes `go test -run TestChaosPostgresDisconnects ./...`. Even
//     though the umbrella `go test ./...` step exercises the same
//     package, the dedicated step is defence-in-depth: a future
//     narrowing of the umbrella step would still leave this gate
//     firing as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestChaosPostgresDisconnects ./...` under the
//     canonical step header
//     `# 19. Required: chaos tests for Postgres disconnects`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #19
//     extends the BE-0379..BE-0393 sequence by one slot; the trailing
//     optionals (#20 govulncheck, #21 staticcheck, #22 golangci-lint,
//     #23 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `19. \`go test -run TestChaosPostgresDisconnects ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0393's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Chaos tests for Postgres disconnects` row, AND a
//     dedicated `## Chaos Tests For Postgres Disconnects` section MUST
//     explain the contract operators, auditors, and AI agents rely
//     on: the closed-set chaos-scenario coverage invariant (Pool.Ping,
//     Pool.Acquire, Pool.Begin, Pool.Exec, Pool.Query call sites of
//     the pgxpool surface every store method uses), the runtime
//     classification invariant (every failure maps to
//     yerr.CodeUnavailable with DependencyStore via
//     apierr.StoreUnavailable), the deterministic-by-default
//     behaviour (in-process fakepg.Server per iteration, no live
//     Postgres, no live Dokploy), the
//     CI-on-every-push-and-PR cadence, and the actionable-failure
//     contract (failures carry the offending scenario name AND the
//     observed request_id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestChaosPostgresDisconnects ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     canonical command without needing to discover it from CI
//     workflows or shell scripts.
//  6. `internal/controlplane/store/chaos_postgres_disconnects_test.go`
//     — the canonical reference chaos-disconnect test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestChaosPostgresDisconnectsCoversCallSites`,
//     `TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope`).
//     The PRD's `go test -run TestChaosPostgresDisconnects ./...`
//     filter binds to the `TestChaosPostgresDisconnects` prefix; a
//     rename to a function whose name does not match the prefix
//     silently de-gates the chaos-disconnect suite for any caller
//     relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteChaosPostgresDisconnectsAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the analyser)
// and under-tightening (a real regression slips through) are both
// caught at the package-internal API.

const (
	// chaosPostgresDisconnectsCIWorkflowStepName is the exact step name
	// CI uses to invoke the chaos-disconnect suite. A rename forces a
	// deliberate update both here and in the workflow.
	chaosPostgresDisconnectsCIWorkflowStepName = "- name: Chaos tests for Postgres disconnects"
	// chaosPostgresDisconnectsCIWorkflowStepRun is the literal command
	// the step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future package that
	// declares a `TestChaosPostgresDisconnects…` test.
	chaosPostgresDisconnectsCIWorkflowStepRun = "run: go test -run TestChaosPostgresDisconnects ./..."

	// chaosPostgresDisconnectsVerifyShStepHeader is the canonical
	// comment header that precedes the `go test -run
	// TestChaosPostgresDisconnects ./...` invocation in verify.sh. The
	// numeric prefix is part of the contract: a reorder must be a
	// deliberate edit to both this constant and the script.
	chaosPostgresDisconnectsVerifyShStepHeader = "# 19. Required: chaos tests for Postgres disconnects"
	// chaosPostgresDisconnectsVerifyShStepCmd is the literal command
	// that MUST appear inside the required-chaos-disconnect step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	chaosPostgresDisconnectsVerifyShStepCmd = `go test -run TestChaosPostgresDisconnects ./...`

	// chaosPostgresDisconnectsContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	chaosPostgresDisconnectsContributingEntry = "19. `go test -run TestChaosPostgresDisconnects ./...`"

	// chaosPostgresDisconnectsSecurityGateRow is the verification-gates
	// row that MUST appear in SECURITY.md so external operators and
	// reviewers can see the chaos-disconnect suite is part of the
	// published security posture.
	chaosPostgresDisconnectsSecurityGateRow = "| Chaos tests for Postgres disconnects | `go test -run TestChaosPostgresDisconnects ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// chaosPostgresDisconnectsSecuritySectionHeading is the dedicated
	// `## Chaos Tests For Postgres Disconnects` heading SECURITY.md
	// MUST carry. The section explains the closed-set scenario coverage
	// invariant, the runtime classification invariant, the
	// deterministic-by-default behaviour, the actionable-failure
	// contract, and the schema-version contract.
	chaosPostgresDisconnectsSecuritySectionHeading = "## Chaos Tests For Postgres Disconnects"

	// chaosPostgresDisconnectsPRDCommand is the literal command that
	// MUST appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	chaosPostgresDisconnectsPRDCommand = "go test -run TestChaosPostgresDisconnects ./..."

	// chaosPostgresDisconnectsCanonicalFile is the relative path of the
	// canonical reference chaos-disconnect test file. The
	// `internal/controlplane/store/chaos_postgres_disconnects_test.go`
	// file declares the function pair every chaos-disconnect regression
	// MUST trip; deleting it silently kills the convention.
	chaosPostgresDisconnectsCanonicalFile = "internal/controlplane/store/chaos_postgres_disconnects_test.go"
)

// chaosPostgresDisconnectsCanonicalFuncs is the closed set of function
// declarations the canonical `chaos_postgres_disconnects_test.go` file
// MUST carry. The PRD's `-run TestChaosPostgresDisconnects` filter binds
// to function names containing the `TestChaosPostgresDisconnects`
// substring; renaming any entry to a name that does not match the
// prefix silently de-gates the chaos-disconnect suite for any caller
// relying on the filter. The pair captures the two load-bearing
// chaos-disconnect invariants the harness MUST keep:
//
//   - TestChaosPostgresDisconnectsCoversCallSites — the closed-set
//     chaos-scenario coverage invariant: the scenario table the burst
//     harness iterates MUST stay non-empty, free of duplicate names,
//     scoped to the pgxpool surface every store method uses (Ping,
//     Acquire, Begin, Exec, Query), and every entry MUST carry a
//     recognised op, a non-nil call closure, a closed-set expected
//     error code (yerr.CodeUnavailable), and a closed-set expected
//     dependency (apierr.DependencyStore). Trips at the
//     package-internal API with no infrastructure dependency.
//   - TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope —
//     the runtime chaos invariant: spinning a per-iteration fakepg
//     server up against a fresh pgxpool with a sentinel DSN and firing
//     `chaosPostgresWorkers * chaosPostgresIterationsPerWorker`
//     concurrent scenario invocations MUST yield only failures that
//     wrap into typed *yerr.Error values with
//     Code=yerr.CodeUnavailable attributed to apierr.DependencyStore
//     via apierr.StoreUnavailable, with the DSN password redacted
//     from every level of the wrapped cause chain, with the wrapped
//     envelope's rendered message echoing no DSN field, and with the
//     fake recording at least one accepted TCP connection per
//     attempt. Failures surface with the offending scenario name AND
//     the observed request_id so an operator can correlate.
var chaosPostgresDisconnectsCanonicalFuncs = []string{
	"func TestChaosPostgresDisconnectsCoversCallSites(",
	"func TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope(",
}

// chaosPostgresDisconnectsSecuritySectionSubstrings is the closed set
// of literal substrings the `## Chaos Tests For Postgres Disconnects`
// section MUST contain. Each captures a different load-bearing fact
// the BE-0394 acceptance criteria require to be visible:
//
//   - "internal/controlplane/store" — the package boundary the
//     canonical chaos-disconnect harness lives in (AC1 documented
//     suite scope).
//   - "chaos_postgres_disconnects_test.go" — the canonical reference
//     test file name; deleting it would break the function pair the
//     gate pivots on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process fakepg server and no
//     other infrastructure dependency.
//   - "fakepg"                    — the in-process Postgres fake the
//     runtime member uses. Documenting it stops a future test from
//     drifting onto a different fault source that does not exercise
//     the disconnect classification path.
//   - "DisconnectFault"           — the specific fakepg primitive
//     the runtime member uses; documenting it pins the chaos shape.
//   - "yerr.CodeUnavailable"      — the load-bearing typed-error
//     mapping the runtime classification invariant pins.
//   - "apierr.DependencyStore"    — the dependency tag every
//     chaos-disconnect failure MUST carry.
//   - "apierr.StoreUnavailable"   — the production classifier
//     chokepoint the runtime member wraps the pgx error through.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (failures carry the observed request_id so
//     operators can correlate).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "TestChaosPostgresDisconnectsCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope" —
//     the canonical runtime burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "redacted"                  — the AC8 redaction contract; the
//     runtime member asserts no DSN password literal leaks in the
//     error chain or the wrapped envelope.
//   - "verification_suite_chaos_postgres_disconnects_static_test.go" —
//     the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var chaosPostgresDisconnectsSecuritySectionSubstrings = []string{
	"internal/controlplane/store",
	"chaos_postgres_disconnects_test.go",
	"deterministic",
	"fakepg",
	"DisconnectFault",
	"yerr.CodeUnavailable",
	"apierr.DependencyStore",
	"apierr.StoreUnavailable",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestChaosPostgresDisconnectsCoversCallSites",
	"TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope",
	"Every push and PR",
	"redacted",
	"verification_suite_chaos_postgres_disconnects_static_test.go",
}

// TestVerificationSuiteChaosPostgresDisconnectsCIWorkflow pins the
// GitHub Actions test job to run the canonical chaos-disconnect
// command under the canonical step name. A silent removal of the step
// — or a narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...` step
// would still leave this gate firing.
func TestVerificationSuiteChaosPostgresDisconnectsCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		chaosPostgresDisconnectsCIWorkflowStepName,
		chaosPostgresDisconnectsCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI chaos-disconnect step is the defence-in-depth gate for the closed-set chaos-scenario coverage + runtime classification invariants — every push and PR MUST run `go test -run TestChaosPostgresDisconnects ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteChaosPostgresDisconnectsVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestChaosPostgresDisconnects ./...` under its
// canonical step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteChaosPostgresDisconnectsVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, chaosPostgresDisconnectsVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-chaos-disconnect block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, chaosPostgresDisconnectsVerifyShStepHeader)
	}
	if !strings.Contains(doc, chaosPostgresDisconnectsVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same chaos-disconnect command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, chaosPostgresDisconnectsVerifyShStepCmd)
	}
}

// TestVerificationSuiteChaosPostgresDisconnectsContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteChaosPostgresDisconnectsContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, chaosPostgresDisconnectsContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, chaosPostgresDisconnectsContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteChaosPostgresDisconnectsSecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the chaos-disconnect gate part of
// the published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteChaosPostgresDisconnectsSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, chaosPostgresDisconnectsSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, chaosPostgresDisconnectsSecurityGateRow)
	}
	if !strings.Contains(doc, chaosPostgresDisconnectsSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-chaos-scenario-coverage / runtime-classification-invariant / deterministic-by-default / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, chaosPostgresDisconnectsSecuritySectionHeading)
	}
	for _, want := range chaosPostgresDisconnectsSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, chaosPostgresDisconnectsSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteChaosPostgresDisconnectsPRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// chaos-disconnect command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteChaosPostgresDisconnectsPRDDocumentsCommand(t *testing.T) {
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
		if cmd == chaosPostgresDisconnectsPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the chaos-disconnect gate as a required backend command.",
		requiredPRDPath, chaosPostgresDisconnectsPRDCommand)
}

// TestVerificationSuiteChaosPostgresDisconnectsCanonicalFileExists
// pins the canonical reference chaos-disconnect test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the
// `TestChaosPostgresDisconnects` prefix silently de-gates the
// chaos-disconnect suite for any caller relying on the PRD's
// `-run TestChaosPostgresDisconnects` filter.
func TestVerificationSuiteChaosPostgresDisconnectsCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(chaosPostgresDisconnectsCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical chaos-disconnect test file is the load-bearing convention every chaos-disconnect regression MUST trip; deleting it silently removes the chaos-disconnect gate.",
			chaosPostgresDisconnectsCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range chaosPostgresDisconnectsCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the chaos-disconnect pair is the load-bearing assertion set every chaos-disconnect regression MUST trip — a rename or deletion silently relaxes the closed-set-chaos-scenario-coverage + runtime-classification contract for every downstream caller.",
				chaosPostgresDisconnectsCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteChaosPostgresDisconnectsAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteChaosPostgresDisconnectsAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			chaosPostgresDisconnectsCIWorkflowStepName,
			chaosPostgresDisconnectsCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Chaos tests for Postgres disconnects\n        run: go test -run TestChaosPostgresDisconnects ./...\n"
		for _, want := range []string{
			chaosPostgresDisconnectsCIWorkflowStepName,
			chaosPostgresDisconnectsCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, chaosPostgresDisconnectsVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", chaosPostgresDisconnectsVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 19. Required: chaos tests for Postgres disconnects\nstep \"go test -run TestChaosPostgresDisconnects ./...\"\nif ! go test -run TestChaosPostgresDisconnects ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, chaosPostgresDisconnectsVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", chaosPostgresDisconnectsVerifyShStepHeader)
		}
		if !strings.Contains(doc, chaosPostgresDisconnectsVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", chaosPostgresDisconnectsVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n18. `go test -run TestChaosDokployTimeouts ./...`\n"
		if strings.Contains(doc, chaosPostgresDisconnectsContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", chaosPostgresDisconnectsContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n18. `go test -run TestChaosDokployTimeouts ./...`\n19. `go test -run TestChaosPostgresDisconnects ./...`\n"
		if !strings.Contains(doc, chaosPostgresDisconnectsContributingEntry) {
			t.Fatalf("complete fixture missing %q", chaosPostgresDisconnectsContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Chaos Tests For Postgres Disconnects\n\n")
		for _, want := range chaosPostgresDisconnectsSecuritySectionSubstrings {
			if want == "yerr.CodeUnavailable" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range chaosPostgresDisconnectsSecuritySectionSubstrings {
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
		b.WriteString("## Chaos Tests For Postgres Disconnects\n\n")
		for _, want := range chaosPostgresDisconnectsSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range chaosPostgresDisconnectsSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
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
			if cmd == chaosPostgresDisconnectsPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", chaosPostgresDisconnectsPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
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
			if cmd == chaosPostgresDisconnectsPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", chaosPostgresDisconnectsPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package store_test\n\nimport \"testing\"\n\nfunc TestChaosPostgresDisconnectsCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range chaosPostgresDisconnectsCanonicalFuncs {
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
		doc := "package store_test\n\nimport \"testing\"\n\nfunc TestChaosPostgresDisconnectsCoversCallSites(t *testing.T) {}\nfunc TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope(t *testing.T) {}\n"
		for _, want := range chaosPostgresDisconnectsCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestChaosPostgresDisconnects prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestChaosPostgresDisconnects"
		for _, want := range chaosPostgresDisconnectsCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestChaosPostgresDisconnects` filter binds to the `TestChaosPostgresDisconnects` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
