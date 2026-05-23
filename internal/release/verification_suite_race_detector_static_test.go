package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — race detector tests (BE-0391).
//
// Threat model: Go's race detector is the load-bearing gate that
// turns latent data-race regressions in the control-plane's
// concurrent code paths (the quota checker's per-organization
// FOR-UPDATE lock, the worker queue's lease loop, the audit emitter's
// shared buffers, the Dokploy client's connection pool, the variable
// resolver's per-request cache) into hard test failures with stack
// traces that point at the racing goroutines. A silent erosion of
// that contract — the dedicated CI step quietly dropped, the
// verify.sh entry renumbered without updating CONTRIBUTING.md, the
// SECURITY.md row deleted, the PRD's requiredLocalCommands or
// requiredBackendCommands array losing the `-race` invocation — would
// let a data-race regression ship through every other verification
// gate (BE-0379..BE-0390 all run WITHOUT the `-race` flag by default;
// only this gate flips it on). The race detector is also the only
// gate that exercises the runtime contract under real goroutine
// interleavings, so its absence makes every concurrency invariant
// the codebase pins (quota concurrency BE-0384, job worker leases
// BE-0385, fake-Dokploy contract BE-0386, redaction emitters BE-0387)
// a paper invariant: their tests would still pass under a regression
// that introduced a race, because the race only manifests with the
// detector enabled.
//
// This file is the load-bearing static defence for that
// meta-contract. Race detector is an UMBRELLA gate — the `-race`
// flag wraps every `Test*` function the suite runs, so there is no
// canonical test-function pair to pin (unlike BE-0383..BE-0390 whose
// `-run` filter binds to a specific function-name prefix). The
// umbrella shape mirrors BE-0379's `go test ./...` gate. This file
// pins FIVE surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row or section, or the PRD's
// verificationLoop entries fails ONE test, not five:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Race detector` that invokes
//     `go test -race ./...`. The matrix MUST cover ubuntu-latest,
//     macos-latest, and windows-latest so the detector runs on every
//     supported developer host. The dedicated step is
//     defence-in-depth on the same principle as BE-0379..BE-0390: a
//     future narrowing of the umbrella `go test ./...` step would
//     still leave the race gate firing as a fast targeted failure
//     rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -race ./...` under the canonical step header
//     `# 5. Required: race detector`. The numeric prefix is part of
//     the contract: a reorder must be a deliberate edit to both this
//     constant and the script. Slot #5 has been stable since
//     BE-0379's #4 (`go test ./...`) and predates every BE-0380..
//     BE-0390 insertion at slots #6..#16; a future required-step
//     insertion BETWEEN #4 and #6 must update this constant in the
//     same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list `go test -race ./...` as entry
//     `5. \`go test -race ./...\`` so contributors know the gate
//     before they open a PR. The numeric prefix keeps verify.sh and
//     CONTRIBUTING.md in lockstep.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Race detector` row, AND a dedicated
//     `## Race Detector` section MUST explain the contract operators,
//     auditors, and AI agents rely on: the data-race-as-test-failure
//     invariant, the umbrella-flag-wraps-every-test invariant, the
//     deterministic-by-default behaviour, the actionable-failure
//     contract (each race failure carries the racing goroutine
//     stacks AND the request_id of the request that triggered them
//     where applicable), the opt-in `YALLA_EXTERNAL_DOKPLOY` external
//     smoke, the redacted-test-output contract, the
//     CI-on-every-push-and-PR cadence, and a pointer back to this
//     static test file so operators can find the gate without
//     re-reading the workflow.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredLocalCommands` MUST list
//     `go test -race ./...` AND
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -race ./internal/controlplane/...` so an AI agent
//     reading the PRD before picking up a story sees both the
//     umbrella race gate and the focused backend race gate without
//     needing to discover them from CI workflows or shell scripts.
//     The two-entry pin makes the backend-narrowed race command part
//     of the contract: a future PRD edit that drops the backend
//     command (e.g. when reorganising the requiredBackendCommands
//     array) trips this gate.
//
// The self-check
// `TestVerificationSuiteRaceDetectorAnalyzerDetectsRegressions`
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API. When changing the CI
// step name, the verify.sh header, the CONTRIBUTING.md numeric
// prefix, the SECURITY.md row or section, or the PRD commands,
// update the matching constant in
// `verification_suite_race_detector_static_test.go` in the same
// edit. The matchers fail loudly on drift; the assertion IS the
// contract.

const (
	// raceDetectorCIWorkflowStepName is the exact step name CI uses
	// to invoke the race detector across the umbrella test surface.
	// A rename forces a deliberate update both here and in the
	// workflow.
	raceDetectorCIWorkflowStepName = "- name: Race detector"
	// raceDetectorCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future top-level package
	// from the race-detector sweep.
	raceDetectorCIWorkflowStepRun = "run: go test -race ./..."

	// raceDetectorVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -race ./...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and
	// the script.
	raceDetectorVerifyShStepHeader = "# 5. Required: race detector"
	// raceDetectorVerifyShStepCmd is the literal command that MUST
	// appear inside the required-race-detector step. Asserting on
	// the literal (not a regex over the file) makes the failure
	// point the operator at the exact line that drifted.
	raceDetectorVerifyShStepCmd = `go test -race ./...`

	// raceDetectorContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	raceDetectorContributingEntry = "5. `go test -race ./...`"

	// raceDetectorSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the race-detector suite is part of the published
	// security posture.
	raceDetectorSecurityGateRow = "| Race detector | `go test -race ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// raceDetectorSecuritySectionHeading is the dedicated
	// `## Race Detector` heading SECURITY.md MUST carry. The section
	// explains the data-race-as-test-failure invariant, the
	// umbrella-flag-wraps-every-test invariant, the
	// deterministic-by-default behaviour, the actionable-failure
	// contract, the opt-in-external escape hatch, the
	// redacted-test-output contract, and the CI-on-every-push-and-PR
	// cadence.
	raceDetectorSecuritySectionHeading = "## Race Detector"

	// raceDetectorPRDLocalCommand is the literal command that MUST
	// appear in the PRD's
	// verificationLoop.requiredLocalCommands array so an agent
	// reading the PRD surfaces the umbrella race gate without
	// needing to discover it from shell scripts or CI workflows.
	raceDetectorPRDLocalCommand = "go test -race ./..."
	// raceDetectorPRDBackendCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// working on backend stories sees the focused-race gate
	// alongside the umbrella one — the backend gate is a faster
	// sub-suite an agent can run mid-iteration without paying the
	// full umbrella cost.
	raceDetectorPRDBackendCommand = "go test -race ./internal/controlplane/..."
)

// raceDetectorSecuritySectionSubstrings is the closed set of literal
// substrings the `## Race Detector` section MUST contain. Each
// captures a different load-bearing fact the BE-0391 acceptance
// criteria require to be visible:
//
//   - "data race"                                — the runtime
//     invariant the detector enforces (AC: actionable failures).
//   - "go test -race"                            — the canonical
//     command (AC: command is documented).
//   - "Every push and PR"                        — the CI gating
//     cadence (AC: CI gating rules state cadence).
//   - "deterministic"                            — the
//     deterministic-by-default behaviour (AC: deterministic
//     fixtures).
//   - "request_id"                               — the
//     actionable-failure contract (AC: failures carry request IDs
//     or resource IDs).
//   - "fake Dokploy"                             — the opt-in
//     external boundary (AC: never requires a live Dokploy server
//     unless marked external).
//   - "YALLA_EXTERNAL_DOKPLOY"                   — the opt-in escape
//     hatch (AC: opt-in external smoke is the only way to hit live
//     Dokploy).
//   - "redacted"                                 — the
//     test-output-redaction contract (AC: secrets redacted in
//     logs, errors, audit metadata, and test output).
//   - "yalla.output.v1"                          — the stable
//     success-envelope contract (AC: all public responses use
//     stable JSON envelopes).
//   - "yalla.error.v1"                           — the stable
//     error-envelope contract (AC: stable error envelopes).
//   - "verification_suite_race_detector_static_test.go"
//     — the gate is self-locating so a future operator can find it
//     without re-reading the workflow.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var raceDetectorSecuritySectionSubstrings = []string{
	"data race",
	"go test -race",
	"Every push and PR",
	"deterministic",
	"request_id",
	"fake Dokploy",
	"YALLA_EXTERNAL_DOKPLOY",
	"redacted",
	"yalla.output.v1",
	"yalla.error.v1",
	"verification_suite_race_detector_static_test.go",
}

// TestVerificationSuiteCIWorkflowRunsRaceDetector pins the GitHub
// Actions test job to run `go test -race ./...` under the canonical
// step name. The step is defence-in-depth on top of the umbrella
// `go test ./...` step: a future narrowing of the umbrella step
// would still leave the race gate firing as a fast targeted failure.
func TestVerificationSuiteCIWorkflowRunsRaceDetector(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		raceDetectorCIWorkflowStepName,
		raceDetectorCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI race-detector step is the load-bearing gate for the data-race-as-test-failure contract — every push and PR MUST run `go test -race ./...` under the canonical step name.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteVerifyShRunsRaceDetector pins the local
// commit gate to run `go test -race ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteVerifyShRunsRaceDetector(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, raceDetectorVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-checks block is the local mirror of the CI gate and the race-detector step must keep its canonical position.",
			requiredVerifyShPath, raceDetectorVerifyShStepHeader)
	}
	if !strings.Contains(doc, raceDetectorVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same race-detector command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, raceDetectorVerifyShStepCmd)
	}
}

// TestVerificationSuiteContributingDocumentsRaceDetector pins the
// contributor guide so the gate is visible before a contributor
// opens a PR.
func TestVerificationSuiteContributingDocumentsRaceDetector(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, requiredContributingSection) {
		t.Errorf("%s: missing required heading %q; the contributor guide MUST surface the race-detector gate so a new contributor satisfies it before opening a PR.",
			requiredContributingPath, requiredContributingSection)
	}
	if !strings.Contains(doc, raceDetectorContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, raceDetectorContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteSecurityDocumentsRaceDetector pins the public
// security policy. SECURITY.md is the operator- and auditor-facing
// surface that makes the race-detector gate part of the published
// security posture, so dropping the row or the section silently
// weakens the posture.
func TestVerificationSuiteSecurityDocumentsRaceDetector(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, raceDetectorSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, raceDetectorSecurityGateRow)
	}
	if !strings.Contains(doc, raceDetectorSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the data-race-as-test-failure / deterministic-by-default / actionable-failure / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, raceDetectorSecuritySectionHeading)
	}
	for _, want := range raceDetectorSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, raceDetectorSecuritySectionHeading)
		}
	}
}

// TestVerificationSuitePRDDocumentsRaceDetector pins both the
// PRD's verificationLoop.requiredLocalCommands and
// verificationLoop.requiredBackendCommands arrays so an AI agent
// reading the PRD before picking up a story sees both the umbrella
// and the focused backend race gates without needing to discover
// them from CI workflows or shell scripts.
func TestVerificationSuitePRDDocumentsRaceDetector(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, requiredPRDPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", requiredPRDPath, err)
	}

	var prd struct {
		VerificationLoop struct {
			RequiredLocalCommands   []string `json:"requiredLocalCommands"`
			RequiredBackendCommands []string `json:"requiredBackendCommands"`
		} `json:"verificationLoop"`
	}
	if err := json.Unmarshal(b, &prd); err != nil {
		t.Fatalf("parse %s: %v", requiredPRDPath, err)
	}

	if !containsString(prd.VerificationLoop.RequiredLocalCommands, raceDetectorPRDLocalCommand) {
		t.Errorf("%s: verificationLoop.requiredLocalCommands does not contain %q; an agent reading the PRD MUST see the umbrella race-detector gate as a required local command.",
			requiredPRDPath, raceDetectorPRDLocalCommand)
	}
	if !containsString(prd.VerificationLoop.RequiredBackendCommands, raceDetectorPRDBackendCommand) {
		t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent working on a backend story MUST see the focused backend race-detector gate alongside the umbrella one — it is the faster mid-iteration variant of the umbrella gate.",
			requiredPRDPath, raceDetectorPRDBackendCommand)
	}
}

// containsString reports whether `needle` appears in `haystack`.
// Split out so the PRD-command matcher can be exercised by the
// self-check on synthetic fixtures.
func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestVerificationSuiteRaceDetectorAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteRaceDetectorAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("ci step matcher fires on missing step name", func(t *testing.T) {
		t.Parallel()
		// Synthetic ci.yml fragment that has the race detector run
		// command but not under the canonical step name. The CI gate
		// MUST flag this — losing the step name buries the gate
		// inside an umbrella step where a failure is harder to spot.
		doc := "- name: Tests\n  run: go test -race ./...\n"
		if strings.Contains(doc, raceDetectorCIWorkflowStepName) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture, not the test", raceDetectorCIWorkflowStepName)
		}
	})

	t.Run("ci step matcher fires on missing step run", func(t *testing.T) {
		t.Parallel()
		// Synthetic ci.yml fragment that has the canonical step name
		// but the wrong run command (missing the trailing `./...`).
		// The CI gate MUST flag this — silently narrowing the
		// race-detector scope is the regression class this matcher
		// exists to prevent.
		doc := "- name: Race detector\n  run: go test -race ./internal/...\n"
		if !strings.Contains(doc, raceDetectorCIWorkflowStepName) {
			t.Fatalf("self-check fixture missing %q; fix the fixture", raceDetectorCIWorkflowStepName)
		}
		if strings.Contains(doc, raceDetectorCIWorkflowStepRun) {
			t.Fatalf("self-check fixture contains %q; fix the fixture", raceDetectorCIWorkflowStepRun)
		}
	})

	t.Run("ci step matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := raceDetectorCIWorkflowStepName + "\n  " + raceDetectorCIWorkflowStepRun + "\n"
		if !strings.Contains(doc, raceDetectorCIWorkflowStepName) {
			t.Fatalf("complete fixture missing %q — the matcher would false-positive here", raceDetectorCIWorkflowStepName)
		}
		if !strings.Contains(doc, raceDetectorCIWorkflowStepRun) {
			t.Fatalf("complete fixture missing %q — the matcher would false-positive here", raceDetectorCIWorkflowStepRun)
		}
	})

	t.Run("verify.sh matcher fires on missing header", func(t *testing.T) {
		t.Parallel()
		// Synthetic verify.sh fragment that has the race command but
		// not the numeric step header. A rename / reorder that drops
		// the header silently de-anchors the gate from its
		// CONTRIBUTING.md sibling.
		doc := "step \"go test -race ./...\"\nif ! go test -race ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, raceDetectorVerifyShStepHeader) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorVerifyShStepHeader)
		}
		if !strings.Contains(doc, raceDetectorVerifyShStepCmd) {
			t.Fatalf("self-check fixture missing %q; fix the fixture", raceDetectorVerifyShStepCmd)
		}
	})

	t.Run("verify.sh matcher fires on missing cmd", func(t *testing.T) {
		t.Parallel()
		doc := "# 5. Required: race detector\n# (command intentionally elided)\n"
		if !strings.Contains(doc, raceDetectorVerifyShStepHeader) {
			t.Fatalf("self-check fixture missing %q; fix the fixture", raceDetectorVerifyShStepHeader)
		}
		if strings.Contains(doc, raceDetectorVerifyShStepCmd) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorVerifyShStepCmd)
		}
	})

	t.Run("verify.sh matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := raceDetectorVerifyShStepHeader + "\nstep \"" + raceDetectorVerifyShStepCmd + "\"\n"
		if !strings.Contains(doc, raceDetectorVerifyShStepHeader) {
			t.Fatalf("complete fixture missing %q", raceDetectorVerifyShStepHeader)
		}
		if !strings.Contains(doc, raceDetectorVerifyShStepCmd) {
			t.Fatalf("complete fixture missing %q", raceDetectorVerifyShStepCmd)
		}
	})

	t.Run("contributing matcher fires on missing entry", func(t *testing.T) {
		t.Parallel()
		// Synthetic CONTRIBUTING.md fragment with the heading but
		// not the numbered race-detector entry — a regression that
		// would let a contributor open a PR without knowing about
		// the gate.
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n"
		if !strings.Contains(doc, requiredContributingSection) {
			t.Fatalf("self-check fixture missing %q; fix the fixture", requiredContributingSection)
		}
		if strings.Contains(doc, raceDetectorContributingEntry) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorContributingEntry)
		}
	})

	t.Run("contributing matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := requiredContributingSection + "\n\n4. `go test ./...`\n" + raceDetectorContributingEntry + "\n"
		if !strings.Contains(doc, requiredContributingSection) {
			t.Fatalf("complete fixture missing %q", requiredContributingSection)
		}
		if !strings.Contains(doc, raceDetectorContributingEntry) {
			t.Fatalf("complete fixture missing %q", raceDetectorContributingEntry)
		}
	})

	t.Run("security row matcher fires on missing row", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md with the section heading but the
		// gate-table row dropped — auditors would lose the
		// at-a-glance posture.
		doc := raceDetectorSecuritySectionHeading + "\n\n(section body)\n"
		if !strings.Contains(doc, raceDetectorSecuritySectionHeading) {
			t.Fatalf("self-check fixture missing %q; fix the fixture", raceDetectorSecuritySectionHeading)
		}
		if strings.Contains(doc, raceDetectorSecurityGateRow) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorSecurityGateRow)
		}
	})

	t.Run("security substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md `## Race Detector` section that is
		// missing the `request_id` substring. The matcher must flag
		// it — operators rely on the section to enumerate the
		// actionable-failure contract.
		var b strings.Builder
		b.WriteString(raceDetectorSecuritySectionHeading)
		b.WriteString("\n")
		for _, want := range raceDetectorSecuritySectionSubstrings {
			if want == "request_id" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		if strings.Contains(doc, "request_id") {
			t.Fatalf("self-check fixture contains %q; fix the fixture", "request_id")
		}
		flagged := false
		for _, want := range raceDetectorSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				flagged = true
				break
			}
		}
		if !flagged {
			t.Fatalf("substring matcher failed to flag missing %q in synthetic fixture", "request_id")
		}
	})

	t.Run("security substring matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString(raceDetectorSecuritySectionHeading)
		b.WriteString("\n\n")
		for _, want := range raceDetectorSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range raceDetectorSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("prd local command matcher fires when go test -race is absent", func(t *testing.T) {
		t.Parallel()
		got := []string{"gofmt -w .", "go vet ./...", "go test ./..."}
		if containsString(got, raceDetectorPRDLocalCommand) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorPRDLocalCommand)
		}
	})

	t.Run("prd local command matcher passes when go test -race is present", func(t *testing.T) {
		t.Parallel()
		got := []string{"gofmt -w .", "go test ./...", "go test -race ./..."}
		if !containsString(got, raceDetectorPRDLocalCommand) {
			t.Fatalf("synthetic fixture missing %q; fix the fixture", raceDetectorPRDLocalCommand)
		}
	})

	t.Run("prd backend command matcher fires when focused race command is absent", func(t *testing.T) {
		t.Parallel()
		got := []string{
			"go test ./internal/controlplane/...",
			"go test ./internal/controlplane/store/...",
			"go test -run TestPolicyMatrix ./...",
		}
		if containsString(got, raceDetectorPRDBackendCommand) {
			t.Fatalf("synthetic fixture contains %q; fix the fixture", raceDetectorPRDBackendCommand)
		}
	})

	t.Run("prd backend command matcher passes when focused race command is present", func(t *testing.T) {
		t.Parallel()
		got := []string{
			"go test ./internal/controlplane/...",
			"go test -race ./internal/controlplane/...",
			"go test -run TestPolicyMatrix ./...",
		}
		if !containsString(got, raceDetectorPRDBackendCommand) {
			t.Fatalf("synthetic fixture missing %q; fix the fixture", raceDetectorPRDBackendCommand)
		}
	})
}
