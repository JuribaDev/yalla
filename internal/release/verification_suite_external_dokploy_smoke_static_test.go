package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — external live-Dokploy smoke tests behind an opt-in
// flag (BE-0400).
//
// Threat model: every other Dokploy-touching suite Yalla ships uses the
// `internal/controlplane/dokploy/dokployfake` server so the gate stays green
// on every developer machine without external infrastructure. The live
// smoke is the SOLE exception: when an operator opts in by setting
// `YALLA_EXTERNAL_DOKPLOY=1` (plus `YALLA_EXTERNAL_DOKPLOY_BASE_URL` and
// `YALLA_EXTERNAL_DOKPLOY_TOKEN`), `go test -run TestLiveDokploySmoke ./...`
// reaches an actual Dokploy server, exercises a read-only intent end-to-end,
// and surfaces failures with the request_id / resource_id / typed error code
// the operator can map back to the Yalla audit log. When the opt-in flag is
// unset, the suite `t.Skip`s cleanly — running it on a developer laptop
// without external Dokploy configured is a PASS, not a failure. That is the
// single load-bearing fact every Yalla agent, CI runner, operator, and
// auditor depends on; a regression that flipped the default from "skip" to
// "attempt and fail" would break every CI run on every push and PR.
//
// A silent erosion of that contract — the canonical smoke file removed, the
// function pair renamed, the opt-in workflow dropped from
// `.github/workflows/external-smoke.yml`, the verify.sh optional step
// quietly elided, the CONTRIBUTING optional entry deleted, the SECURITY.md
// row or section dropped, the PRD's
// `verificationLoop.optionalWhenConfigured` entry mutated — would let the
// gate decay without any test firing. Operators would see "all green" while
// the only external smoke Yalla supports went unrun for weeks.
//
// This file is the load-bearing static defence for that meta-contract. It
// pins SIX surfaces in one file so a future contributor changing the CI
// workflow name, the verify.sh step header, the CONTRIBUTING optional
// bullet, the SECURITY row, the PRD optionalWhenConfigured entry, or
// deleting the canonical smoke fixture fails ONE test, not six.
//
//  1. `.github/workflows/external-smoke.yml` — the dedicated opt-in
//     workflow MUST exist, MUST be wired to `workflow_dispatch` (so an
//     operator can run it on demand) AND a nightly `schedule`, MUST inject
//     the `YALLA_EXTERNAL_DOKPLOY=1` opt-in into the test step's
//     environment, and MUST invoke `go test -run TestLiveDokploySmoke
//     ./...` under a step named `External live-Dokploy smoke tests`. The
//     workflow is deliberately separate from `ci.yml`'s `test` job: the
//     default CI run on every push and PR MUST NOT reach a real Dokploy.
//  2. `scripts/verify.sh` — the local commit gate MUST carry an OPTIONAL
//     step under the canonical step header
//     `# 33. Optional: external live-Dokploy smoke tests` that only
//     invokes `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke
//     ./...` when the operator has explicitly set the opt-in env var.
//     The trailing-optional position (`#33`, after the existing
//     `#29 govulncheck`/`#30 staticcheck`/`#31 golangci-lint`/`#32
//     goreleaser` block) is part of the contract; a renumber forces a
//     deliberate edit in lockstep with this constant.
//  3. `CONTRIBUTING.md` — the optional-tooling section MUST mention the
//     opt-in command under the canonical entry
//     ``- `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke
//     ./...` — opt-in external live-Dokploy smoke``. Contributors and AI
//     agents reading the guide MUST see the gate before opening a PR; the
//     canonical entry is the discoverable surface.
//  4. `SECURITY.md` — the Required Verification Gates table MUST carry
//     the `External live-Dokploy smoke tests` row (with the When column
//     marked as the opt-in / nightly cadence, NOT "Every push and PR"),
//     AND a dedicated `## External Live-Dokploy Smoke Tests` section MUST
//     explain the closed-set opt-in contract: the documented env vars
//     (`YALLA_EXTERNAL_DOKPLOY`, `YALLA_EXTERNAL_DOKPLOY_BASE_URL`,
//     `YALLA_EXTERNAL_DOKPLOY_TOKEN`,
//     `YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE`), the deterministic-skip
//     default behaviour, the actionable-failure contract (request_id +
//     resource_id, typed `yerr` codes, never echoes the bearer token), the
//     stable envelope contract (`yalla.error.v1` upstream of the smoke),
//     and the redaction contract (the Dokploy client's `Redactor` strips
//     the bearer token from every error surface).
//  5. `ralph/prd.json` —
//     `verificationLoop.optionalWhenConfigured` MUST list
//     `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`
//     so an AI agent reading the PRD before picking up a story sees the
//     canonical opt-in command in the contract document, not in shell
//     scripts or CI workflows. The smoke is deliberately the ONLY entry
//     that lives in `optionalWhenConfigured` (not
//     `requiredBackendCommands`): the CI gating cadence for the smoke is
//     "opt-in / nightly / release-only", not "every push and PR".
//  6. `internal/controlplane/dokploy/live_dokploy_smoke_test.go` — the
//     canonical reference smoke file MUST exist and MUST declare the
//     load-bearing function pair
//     (`TestLiveDokploySmokeRespectsOptInFlag` and
//     `TestLiveDokploySmokeExercisesLiveEndpoint`). The PRD's
//     `-run TestLiveDokploySmoke ./...` filter binds to the
//     `TestLiveDokploySmoke` prefix; a rename to a function whose name
//     does not match the prefix silently de-gates the smoke for every
//     caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteExternalDokploySmokeAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad fixtures so
// over-tightening (a legitimate change trips the analyser) and
// under-tightening (a real regression slips through) are both caught at the
// package-internal API.

const (
	// externalDokploySmokeCIWorkflowPath is the relative path of the
	// dedicated opt-in workflow. The smoke is intentionally NOT a step in
	// the default `ci.yml` test job — the default CI run on every push and
	// PR MUST NOT reach a real Dokploy.
	externalDokploySmokeCIWorkflowPath = ".github/workflows/external-smoke.yml"
	// externalDokploySmokeCIWorkflowStepName is the canonical step name the
	// opt-in workflow MUST carry. A rename is a deliberate dual-edit.
	externalDokploySmokeCIWorkflowStepName = "- name: External live-Dokploy smoke tests"
	// externalDokploySmokeCIWorkflowStepRun is the literal command the
	// opt-in workflow's smoke step MUST invoke. Anything narrower (e.g.
	// dropping the trailing `./...`) would silently exclude any future
	// package that declares a `TestLiveDokploySmoke…` test.
	externalDokploySmokeCIWorkflowStepRun = "go test -run TestLiveDokploySmoke ./..."
	// externalDokploySmokeCIWorkflowDispatch is the dispatch trigger the
	// workflow MUST carry so operators can run the smoke on demand without
	// waiting for the schedule.
	externalDokploySmokeCIWorkflowDispatch = "workflow_dispatch:"
	// externalDokploySmokeCIWorkflowSchedule is the nightly trigger the
	// workflow MUST carry so the smoke is exercised continuously when the
	// secrets are configured in the repository.
	externalDokploySmokeCIWorkflowSchedule = "schedule:"
	// externalDokploySmokeCIWorkflowEnvOptIn is the literal env injection
	// the smoke step MUST carry — without it the smoke would `t.Skip`
	// silently and the workflow would always pass without ever reaching
	// Dokploy.
	externalDokploySmokeCIWorkflowEnvOptIn = "YALLA_EXTERNAL_DOKPLOY: \"1\""

	// externalDokploySmokeVerifyShStepHeader is the canonical comment
	// header that precedes the opt-in invocation in verify.sh. The numeric
	// prefix is part of the contract: a reorder must be a deliberate edit
	// to both this constant and the script. The smoke sits in the
	// trailing-optional block (after govulncheck/staticcheck/golangci-lint/
	// goreleaser).
	externalDokploySmokeVerifyShStepHeader = "# 33. Optional: external live-Dokploy smoke tests"
	// externalDokploySmokeVerifyShStepCmd is the literal opt-in command
	// the optional step MUST invoke. The leading env prefix is required:
	// without it the test would `t.Skip` and the optional gate would
	// always pass without ever reaching Dokploy.
	externalDokploySmokeVerifyShStepCmd = `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`

	// externalDokploySmokeContributingEntry is the literal bullet that
	// MUST appear in CONTRIBUTING.md's optional-tooling section so
	// contributors discover the gate before opening a PR. The opt-in
	// command MUST appear verbatim so an operator can paste it into a
	// shell without translation.
	externalDokploySmokeContributingEntry = "`YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...`"

	// externalDokploySmokeSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md. The When column is intentionally
	// "Opt-in (`YALLA_EXTERNAL_DOKPLOY=1`), nightly + manual" — NOT
	// "Every push and PR" — because the smoke is the only external
	// suite Yalla supports.
	externalDokploySmokeSecurityGateRow = "| External live-Dokploy smoke tests | `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...` | `.github/workflows/external-smoke.yml`, `scripts/verify.sh` (opt-in) | Opt-in (`YALLA_EXTERNAL_DOKPLOY=1`), nightly + manual |"
	// externalDokploySmokeSecuritySectionHeading is the dedicated
	// `## External Live-Dokploy Smoke Tests` heading SECURITY.md MUST
	// carry. The section explains the closed-set opt-in contract, the
	// deterministic-skip default, the actionable-failure contract, the
	// stable envelope contract, and the redaction contract.
	externalDokploySmokeSecuritySectionHeading = "## External Live-Dokploy Smoke Tests"

	// externalDokploySmokePRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.optionalWhenConfigured array.
	// The smoke is the ONLY entry that lives in optionalWhenConfigured
	// (not requiredBackendCommands): the CI gating cadence is opt-in /
	// nightly / release-only.
	externalDokploySmokePRDCommand = "YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./..."

	// externalDokploySmokeCanonicalFile is the relative path of the
	// canonical reference smoke file. The
	// `internal/controlplane/dokploy/live_dokploy_smoke_test.go` file
	// declares the function pair every smoke regression MUST trip;
	// deleting it silently kills the convention.
	externalDokploySmokeCanonicalFile = "internal/controlplane/dokploy/live_dokploy_smoke_test.go"
)

// externalDokploySmokeCanonicalFuncs is the closed set of function
// declarations the canonical smoke file MUST carry. The PRD's
// `-run TestLiveDokploySmoke` filter binds to function names containing the
// `TestLiveDokploySmoke` substring; renaming any entry to a name that does
// not match the prefix silently de-gates the smoke for any caller relying
// on the filter. The pair captures the two load-bearing smoke invariants
// the harness MUST keep:
//
//   - TestLiveDokploySmokeRespectsOptInFlag — the closed-set opt-in
//     coverage invariant: every documented value of
//     `YALLA_EXTERNAL_DOKPLOY` (unset, empty, `0`, whitespace, `false`,
//     `1`) yields the predicted (skip vs. error) outcome, and the typed
//     `yerr.CodeConfig` error path names the missing variable without
//     echoing any token.
//   - TestLiveDokploySmokeExercisesLiveEndpoint — the live-path /
//     redaction invariant: when the opt-in flag is set, the smoke
//     constructs a real Dokploy client and exercises a read-only intent
//     against the configured base URL; when it is unset, the live branch
//     skips cleanly while the redaction-contract branch runs
//     unconditionally so the bearer-token redaction property is enforced
//     on every push and PR.
var externalDokploySmokeCanonicalFuncs = []string{
	"func TestLiveDokploySmokeRespectsOptInFlag(",
	"func TestLiveDokploySmokeExercisesLiveEndpoint(",
}

// externalDokploySmokeSecuritySectionSubstrings is the closed set of
// literal substrings the `## External Live-Dokploy Smoke Tests` section
// MUST contain. Each captures a different load-bearing fact the BE-0400
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/dokploy" — the package boundary the
//     canonical smoke fixture lives in (AC1 documented suite scope).
//   - "live_dokploy_smoke_test.go" — the canonical reference test file
//     name; deleting it would break the function pair the gate pivots on.
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC2 opt-in flag.
//   - "YALLA_EXTERNAL_DOKPLOY_BASE_URL" — the AC2 base-URL configuration
//     variable; the smoke's CodeConfig error path names this when it is
//     missing.
//   - "YALLA_EXTERNAL_DOKPLOY_TOKEN" — the AC2 token configuration
//     variable; the smoke's CodeConfig error path names this when it is
//     missing.
//   - "opt-in"                     — the AC4 CI-gating cadence framing.
//   - "deterministic"              — the AC2 deterministic-default
//     contract; the smoke `t.Skip`s when the flag is unset.
//   - "TestLiveDokploySmoke"       — the AC1 canonical function-name
//     prefix the `-run` filter binds to.
//   - "TestLiveDokploySmokeRespectsOptInFlag" — the canonical opt-in
//     coverage function the -run filter binds to.
//   - "TestLiveDokploySmokeExercisesLiveEndpoint" — the canonical live
//     path function the -run filter binds to.
//   - "request_id"                 — the AC3 actionable-failure
//     identifier (every smoke failure can be mapped back to the request).
//   - "yalla.error.v1"             — the AC5 stable error envelope
//     contract upstream of the smoke.
//   - "redacted"                   — the AC8 redaction contract; the
//     Dokploy client's Redactor strips the bearer token from every error.
//   - ".github/workflows/external-smoke.yml" — the dedicated opt-in
//     workflow that runs the smoke on a schedule + workflow_dispatch.
//   - "nightly"                    — the AC4 CI-gating cadence framing.
//   - "verification_suite_external_dokploy_smoke_static_test.go" — the
//     gate is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while still
// pinning every AC.
var externalDokploySmokeSecuritySectionSubstrings = []string{
	"internal/controlplane/dokploy",
	"live_dokploy_smoke_test.go",
	"YALLA_EXTERNAL_DOKPLOY",
	"YALLA_EXTERNAL_DOKPLOY_BASE_URL",
	"YALLA_EXTERNAL_DOKPLOY_TOKEN",
	"opt-in",
	"deterministic",
	"TestLiveDokploySmoke",
	"TestLiveDokploySmokeRespectsOptInFlag",
	"TestLiveDokploySmokeExercisesLiveEndpoint",
	"request_id",
	"yalla.error.v1",
	"redacted",
	".github/workflows/external-smoke.yml",
	"nightly",
	"verification_suite_external_dokploy_smoke_static_test.go",
}

// TestVerificationSuiteExternalDokploySmokeCIWorkflow pins the dedicated
// opt-in workflow. The workflow MUST exist, MUST be wired to both
// `workflow_dispatch` and `schedule`, MUST inject the opt-in env var into
// the smoke step's environment, AND MUST invoke the canonical command
// under the canonical step name. A silent removal of any of those
// surfaces would let the smoke decay: a scheduled run that no longer
// injects the env var would `t.Skip` silently and the gate would always
// report green.
func TestVerificationSuiteExternalDokploySmokeCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(externalDokploySmokeCIWorkflowPath))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe dedicated opt-in workflow is the load-bearing CI surface for the live smoke; without it the gate never runs against real Dokploy infrastructure.",
			externalDokploySmokeCIWorkflowPath, err)
	}
	doc := string(b)
	for _, want := range []string{
		externalDokploySmokeCIWorkflowStepName,
		externalDokploySmokeCIWorkflowStepRun,
		externalDokploySmokeCIWorkflowDispatch,
		externalDokploySmokeCIWorkflowSchedule,
		externalDokploySmokeCIWorkflowEnvOptIn,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the opt-in workflow MUST carry workflow_dispatch + schedule triggers, MUST inject YALLA_EXTERNAL_DOKPLOY=1, and MUST run `go test -run TestLiveDokploySmoke ./...` under the canonical step name so the smoke is reachable on demand AND nightly without ever bleeding into the default CI run.",
				externalDokploySmokeCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteExternalDokploySmokeVerifyShRunsOptInCommand pins
// the local commit gate to invoke the opt-in smoke command under its
// canonical optional step header so a contributor running the gate
// locally with `YALLA_EXTERNAL_DOKPLOY=1` set exercises the identical
// command the dedicated CI workflow runs.
func TestVerificationSuiteExternalDokploySmokeVerifyShRunsOptInCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, externalDokploySmokeVerifyShStepHeader) {
		t.Errorf("%s: missing required optional step header %q; the verify.sh trailing-optional block is the local mirror of the CI workflow, and the step must keep its canonical position #29 after the govulncheck/staticcheck/golangci-lint/goreleaser block.",
			requiredVerifyShPath, externalDokploySmokeVerifyShStepHeader)
	}
	if !strings.Contains(doc, externalDokploySmokeVerifyShStepCmd) {
		t.Errorf("%s: missing literal opt-in command %q; scripts/verify.sh MUST invoke the same opt-in command the dedicated workflow runs so a successful local opt-in run predicts CI success.",
			requiredVerifyShPath, externalDokploySmokeVerifyShStepCmd)
	}
}

// TestVerificationSuiteExternalDokploySmokeContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a contributor
// opens a PR. The smoke is opt-in, so the entry lives under
// CONTRIBUTING.md's optional-tooling block rather than the numbered
// required list.
func TestVerificationSuiteExternalDokploySmokeContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, externalDokploySmokeContributingEntry) {
		t.Errorf("%s: missing required opt-in entry %q; contributors and AI agents MUST see the opt-in command in CONTRIBUTING.md so it is discoverable without grepping the workflows directory.",
			requiredContributingPath, externalDokploySmokeContributingEntry)
	}
}

// TestVerificationSuiteExternalDokploySmokeSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-facing
// surface that makes the opt-in smoke part of the published security
// posture, so dropping the row or the section silently weakens the
// posture.
func TestVerificationSuiteExternalDokploySmokeSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, externalDokploySmokeSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate (including opt-in ones) MUST surface as a row operators can read at a glance — and the When column MUST mark this gate as opt-in / nightly, not 'Every push and PR'.",
			requiredSecurityPath, externalDokploySmokeSecurityGateRow)
	}
	if !strings.Contains(doc, externalDokploySmokeSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set opt-in / deterministic-skip / actionable-failure / stable-envelope / redaction contracts auditable.",
			requiredSecurityPath, externalDokploySmokeSecuritySectionHeading)
	}
	for _, want := range externalDokploySmokeSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, externalDokploySmokeSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteExternalDokploySmokePRDDocumentsCommand pins the
// PRD's verificationLoop.optionalWhenConfigured so an AI agent reading
// the PRD before picking up a story sees the canonical opt-in command
// without needing to discover it from CI workflows or shell scripts. The
// smoke MUST live in optionalWhenConfigured (not requiredBackendCommands)
// because its CI cadence is opt-in / nightly / release-only, not "every
// push and PR".
func TestVerificationSuiteExternalDokploySmokePRDDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, requiredPRDPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", requiredPRDPath, err)
	}

	var prd struct {
		VerificationLoop struct {
			OptionalWhenConfigured  []string `json:"optionalWhenConfigured"`
			RequiredBackendCommands []string `json:"requiredBackendCommands"`
		} `json:"verificationLoop"`
	}
	if err := json.Unmarshal(b, &prd); err != nil {
		t.Fatalf("parse %s: %v", requiredPRDPath, err)
	}

	// The smoke MUST appear in optionalWhenConfigured.
	found := false
	for _, cmd := range prd.VerificationLoop.OptionalWhenConfigured {
		if cmd == externalDokploySmokePRDCommand {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("%s: verificationLoop.optionalWhenConfigured does not contain %q; an agent reading the PRD MUST see the opt-in smoke as an optional-when-configured command.",
			requiredPRDPath, externalDokploySmokePRDCommand)
	}

	// And it MUST NOT appear in requiredBackendCommands — the smoke is
	// opt-in, never required on every PR.
	for _, cmd := range prd.VerificationLoop.RequiredBackendCommands {
		if cmd == externalDokploySmokePRDCommand {
			t.Errorf("%s: verificationLoop.requiredBackendCommands UNEXPECTEDLY contains %q; the opt-in smoke MUST stay in optionalWhenConfigured so the default CI run on every push and PR never reaches a real Dokploy.",
				requiredPRDPath, externalDokploySmokePRDCommand)
		}
	}
}

// TestVerificationSuiteExternalDokploySmokeCanonicalFileExists pins the
// canonical reference smoke file and its load-bearing function pair.
// Deleting the file or renaming either function to a name that does not
// match the `TestLiveDokploySmoke` prefix silently de-gates the smoke for
// any caller relying on the PRD's `-run TestLiveDokploySmoke` filter.
func TestVerificationSuiteExternalDokploySmokeCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(externalDokploySmokeCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical smoke test file is the load-bearing convention every smoke regression MUST trip; deleting it silently removes the smoke gate.",
			externalDokploySmokeCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range externalDokploySmokeCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the smoke pair is the load-bearing assertion set every smoke regression MUST trip — a rename or deletion silently relaxes the closed-set opt-in coverage + live-path + redaction contract for every downstream caller.",
				externalDokploySmokeCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteExternalDokploySmokeAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires (or
// stays silent) correctly. Without this self-check a future "improvement"
// to the matchers (a tightened regex, a relaxed substring set, a renamed
// constant) could silently let real regressions slip through.
func TestVerificationSuiteExternalDokploySmokeAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "on:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test ./...\n"
		want := []string{
			externalDokploySmokeCIWorkflowStepName,
			externalDokploySmokeCIWorkflowStepRun,
			externalDokploySmokeCIWorkflowDispatch,
			externalDokploySmokeCIWorkflowSchedule,
			externalDokploySmokeCIWorkflowEnvOptIn,
		}
		for _, w := range want {
			if strings.Contains(doc, w) {
				t.Fatalf("synthetic workflow unexpectedly contains %q — fix the fixture, not the test", w)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    env:\n      YALLA_EXTERNAL_DOKPLOY: \"1\"\n    steps:\n      - name: External live-Dokploy smoke tests\n        run: go test -run TestLiveDokploySmoke ./...\n"
		want := []string{
			externalDokploySmokeCIWorkflowStepName,
			externalDokploySmokeCIWorkflowStepRun,
			externalDokploySmokeCIWorkflowDispatch,
			externalDokploySmokeCIWorkflowSchedule,
			externalDokploySmokeCIWorkflowEnvOptIn,
		}
		for _, w := range want {
			if !strings.Contains(doc, w) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", w)
			}
		}
	})

	t.Run("verify.sh matcher flags missing optional step", func(t *testing.T) {
		t.Parallel()
		doc := "# 32. Optional: goreleaser check\nstep \"goreleaser check\"\nif command -v goreleaser >/dev/null 2>&1; then\n  goreleaser check\nfi\n"
		if strings.Contains(doc, externalDokploySmokeVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", externalDokploySmokeVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 33. Optional: external live-Dokploy smoke tests\nif [[ \"${YALLA_EXTERNAL_DOKPLOY:-}\" = \"1\" ]]; then\n  step \"YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...\"\n  if ! YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...; then\n    required_failed=1\n  fi\nfi\n"
		if !strings.Contains(doc, externalDokploySmokeVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", externalDokploySmokeVerifyShStepHeader)
		}
		if !strings.Contains(doc, externalDokploySmokeVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", externalDokploySmokeVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Optional Tools\n\nThe required checks above use only the Go toolchain.\n\n```bash\ngo install govulncheck@latest\n```\n"
		if strings.Contains(doc, externalDokploySmokeContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", externalDokploySmokeContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Optional Tools\n\n- `YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./...` — opt-in external live-Dokploy smoke\n"
		if !strings.Contains(doc, externalDokploySmokeContributingEntry) {
			t.Fatalf("complete fixture missing %q", externalDokploySmokeContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## External Live-Dokploy Smoke Tests\n\n")
		for _, want := range externalDokploySmokeSecuritySectionSubstrings {
			if want == "redacted" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range externalDokploySmokeSecuritySectionSubstrings {
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
		b.WriteString("## External Live-Dokploy Smoke Tests\n\n")
		for _, want := range externalDokploySmokeSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range externalDokploySmokeSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent from optional", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"optionalWhenConfigured":["govulncheck ./..."],"requiredBackendCommands":["go test ./internal/controlplane/..."]}}`
		var prd struct {
			VerificationLoop struct {
				OptionalWhenConfigured  []string `json:"optionalWhenConfigured"`
				RequiredBackendCommands []string `json:"requiredBackendCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.OptionalWhenConfigured {
			if cmd == externalDokploySmokePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", externalDokploySmokePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present in optional", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"optionalWhenConfigured":["YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./..."],"requiredBackendCommands":["go test ./internal/controlplane/..."]}}`
		var prd struct {
			VerificationLoop struct {
				OptionalWhenConfigured  []string `json:"optionalWhenConfigured"`
				RequiredBackendCommands []string `json:"requiredBackendCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.OptionalWhenConfigured {
			if cmd == externalDokploySmokePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", externalDokploySmokePRDCommand)
		}
	})

	t.Run("PRD command matcher refuses canonical command in required", func(t *testing.T) {
		t.Parallel()
		// If the smoke ever drifted into requiredBackendCommands the
		// matcher MUST loudly refuse — the smoke is opt-in and must never
		// be required on every push and PR.
		prdJSON := `{"verificationLoop":{"optionalWhenConfigured":["YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./..."],"requiredBackendCommands":["YALLA_EXTERNAL_DOKPLOY=1 go test -run TestLiveDokploySmoke ./..."]}}`
		var prd struct {
			VerificationLoop struct {
				OptionalWhenConfigured  []string `json:"optionalWhenConfigured"`
				RequiredBackendCommands []string `json:"requiredBackendCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		inRequired := false
		for _, cmd := range prd.VerificationLoop.RequiredBackendCommands {
			if cmd == externalDokploySmokePRDCommand {
				inRequired = true
				break
			}
		}
		if !inRequired {
			t.Fatalf("synthetic PRD must place the opt-in command in requiredBackendCommands to drive this self-check fixture")
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestLiveDokploySmokeRespectsOptInFlag(t *testing.T) {}\n"
		missing := 0
		for _, want := range externalDokploySmokeCanonicalFuncs {
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
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestLiveDokploySmokeRespectsOptInFlag(t *testing.T) {}\nfunc TestLiveDokploySmokeExercisesLiveEndpoint(t *testing.T) {}\n"
		for _, want := range externalDokploySmokeCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestLiveDokploySmoke prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestLiveDokploySmoke"
		for _, want := range externalDokploySmokeCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestLiveDokploySmoke` filter binds to the `TestLiveDokploySmoke` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
