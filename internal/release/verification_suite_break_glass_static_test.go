package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — break-glass tests (BE-0404).
//
// Threat model: the break-glass surface (`POST /v1/admin/break-glass`
// and `DELETE /v1/admin/break-glass/{session_id}`) is the elevated
// cross-tenant access chokepoint. A support principal opens a
// session, the access is recorded as an immutable audit row stamped
// with `metadata.elevated_access = "true"`, the unit of work is
// access-only (no credential mint), and every persisted reason /
// user-agent is scrubbed through the redactor before it lands on
// disk. The pure decision logic that gates a session opening is
// `store.BreakGlassService.buildSessionToCreate`: it returns a
// typed `*yerr.Error` of code `CodeInvalidInput` naming the
// offending field (organization_id, actor_id, actor_kind, reason,
// or ttl) when an input violates the documented rules, returns the
// composed `BreakGlassSession` with `ExpiresAt = StartedAt + TTL`
// (capped at `breakGlassMaxTTL`) when the input is accepted, and
// never echoes the submitted reason value into the typed error.
// A silent regression that demoted any rule, that started echoing
// the submitted reason into the error message, that dropped the
// TTL cap, or that allowed an unknown actor_kind through would
// either authorise a malformed session row or leak operator-
// supplied data into an error path operators ship into logs and
// dashboards. The canonical pair
// (`TestBreakGlassCoversCallSites`,
//  `TestBreakGlassPreservesContractUnderContention`) lives in
// `internal/controlplane/store/break_glass_canonical_test.go` and
// binds to the PRD's `-run TestBreakGlass` filter. The pair
// members are deterministic by design — both walk a closed
// scenario table built from every documented rule and every
// documented accept path of `buildSessionToCreate`, and the
// validator is a pure function from (input, now) to either a
// `BreakGlassSession` or a typed `*yerr.Error`. Neither member
// reaches the process environment, the network, a live Postgres,
// a live Dokploy, or any external service.
//
// A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted, the
// canonical `break_glass_canonical_test.go` file removed, or the
// canonical `TestBreakGlass…` function pair renamed — would let
// a validator drift or a new break-glass rule ship without
// firing any gate. This file is the load-bearing static defence
// for that meta-contract. It pins SIX surfaces in one file so a
// future contributor changing the CI step name, the verify.sh
// step header, the CONTRIBUTING numeric prefix, the SECURITY
// row, the PRD requiredBackendCommands array, or deleting the
// canonical break-glass test fixture fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Break-glass tests` that invokes
//     `go test -run TestBreakGlass ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package,
//     the dedicated step is defence-in-depth: a future narrowing
//     of the umbrella step would still leave this gate firing as
//     a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestBreakGlass ./...` under the canonical
//     step header `# 28. Required: break-glass tests`. The
//     numeric prefix is part of the contract: a reorder must be
//     a deliberate edit to both this constant and the script.
//     #28 extends the BE-0379..BE-0403 sequence by one and
//     pushes BE-0400's optional `# 33. Optional: external live-
//     Dokploy smoke tests` block down by one in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry an
//     entry `28. \`go test -run TestBreakGlass ./...\`` so a
//     contributor preparing a PR sees the gate before running
//     scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table MUST
//     carry a row for the break-glass suite, AND a dedicated
//     `## Break-Glass Tests` section MUST explain the closed-set
//     coverage invariant (every documented validator rule and
//     every documented accept path), the field-naming invariant
//     (every rejection names the offending field), the redaction
//     invariant (no rejection echoes the submitted reason
//     value), the TTL cap invariant (`ExpiresAt - StartedAt ==
//     breakGlassMaxTTL` when the requested TTL exceeds the cap),
//     the access-only invariant (the unit of work mints no
//     credential), the deterministic-by-default behaviour, the
//     actionable-failure contract, the schema-version contract,
//     and the redaction contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestBreakGlass ./...` so an AI agent reading
//     the PRD before picking up a story sees the gate without
//     needing to discover it from CI workflows or shell scripts.
//  6. `internal/controlplane/store/break_glass_canonical_test.go`
//     — the canonical reference break-glass test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestBreakGlassCoversCallSites`,
//      `TestBreakGlassPreservesContractUnderContention`). The
//     PRD's `go test -run TestBreakGlass ./...` filter binds to
//     the `TestBreakGlass` substring; a rename to a function
//     whose name does not match the substring silently de-gates
//     the break-glass suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteBreakGlassAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips
// through) are both caught at the package-internal API.

const (
	// breakGlassCIWorkflowStepName is the exact step name CI uses
	// to invoke the break-glass suite. A rename forces a deliberate
	// update both here and in the workflow.
	breakGlassCIWorkflowStepName = "- name: Break-glass tests"
	// breakGlassCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestBreakGlass…` test.
	breakGlassCIWorkflowStepRun = "run: go test -run TestBreakGlass ./..."

	// breakGlassVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestBreakGlass ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	breakGlassVerifyShStepHeader = "# 28. Required: break-glass tests"
	// breakGlassVerifyShStepCmd is the literal command that MUST
	// appear inside the required-break-glass step. Asserting on
	// the literal (not a regex over the file) makes the failure
	// point the operator at the exact line that drifted.
	breakGlassVerifyShStepCmd = `go test -run TestBreakGlass ./...`

	// breakGlassContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	breakGlassContributingEntry = "28. `go test -run TestBreakGlass ./...`"

	// breakGlassSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and
	// reviewers can see the break-glass suite is part of the
	// published security posture.
	breakGlassSecurityGateRow = "| Break-glass tests | `go test -run TestBreakGlass ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// breakGlassSecuritySectionHeading is the dedicated
	// `## Break-Glass Tests` heading SECURITY.md MUST carry. The
	// section explains the closed-set coverage invariant, the
	// field-naming invariant, the redaction invariant, the TTL
	// cap invariant, the access-only invariant, the
	// deterministic-by-default behaviour, the actionable-failure
	// contract, the schema-version contract, and the redaction
	// contract.
	breakGlassSecuritySectionHeading = "## Break-Glass Tests"

	// breakGlassPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract
	// document, not from shell scripts or CI workflows.
	breakGlassPRDCommand = "go test -run TestBreakGlass ./..."

	// breakGlassCanonicalFile is the relative path of the
	// canonical reference break-glass test file. The
	// `internal/controlplane/store/break_glass_canonical_test.go`
	// file declares the function pair every break-glass
	// regression MUST trip; deleting it silently kills the
	// convention.
	breakGlassCanonicalFile = "internal/controlplane/store/break_glass_canonical_test.go"
)

// breakGlassCanonicalFuncs is the closed set of function
// declarations the canonical `break_glass_canonical_test.go`
// file MUST carry. The PRD's `-run TestBreakGlass` filter binds
// to function names containing the `TestBreakGlass` substring;
// renaming any entry to a name that does not match the
// substring silently de-gates the break-glass suite for any
// caller relying on the filter.
var breakGlassCanonicalFuncs = []string{
	"func TestBreakGlassCoversCallSites(t *testing.T)",
	"func TestBreakGlassPreservesContractUnderContention(t *testing.T)",
}

// breakGlassSecuritySectionSubstrings is the closed set of
// substrings the dedicated `## Break-Glass Tests` section in
// SECURITY.md MUST contain. The substrings name every load-
// bearing fact the operator- and auditor-facing documentation
// MUST surface so a future contributor changing the gate's
// contract is forced to update the public security posture in
// the same edit.
var breakGlassSecuritySectionSubstrings = []string{
	"TestBreakGlass",
	"buildSessionToCreate",
	"organization_id",
	"actor_id",
	"actor_kind",
	"reason",
	"ttl",
	"breakGlassMaxTTL",
	"elevated_access",
	"access-only",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379).
// Reusing them here keeps the path / helper layer single-
// sourced so a repository-wide rename only touches that file.

// TestVerificationSuiteBreakGlassCIWorkflowDeclaresStep pins the
// CI workflow to a dedicated step that invokes
// `go test -run TestBreakGlass ./...`. Even though the umbrella
// `go test ./...` step exercises the same package, the
// dedicated step is defence-in-depth: a future narrowing of the
// umbrella step would still leave this gate firing as a fast
// targeted failure rather than buried inside the umbrella log.
func TestVerificationSuiteBreakGlassCIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		breakGlassCIWorkflowStepName,
		breakGlassCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI break-glass step is the defence-in-depth gate for the closed-set validator coverage + field-naming + redaction + TTL-cap + access-only invariants — every push and PR MUST run `go test -run TestBreakGlass ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteBreakGlassVerifyShRunsCanonicalCommand pins
// the local commit gate to run `go test -run TestBreakGlass ./...`
// under its canonical step header so a contributor running the
// gate locally exercises the identical command CI runs.
func TestVerificationSuiteBreakGlassVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, breakGlassVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-break-glass block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, breakGlassVerifyShStepHeader)
	}
	if !strings.Contains(doc, breakGlassVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same break-glass command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, breakGlassVerifyShStepCmd)
	}
}

// TestVerificationSuiteBreakGlassContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the
// verify.sh step number to keep the two surfaces in lockstep.
func TestVerificationSuiteBreakGlassContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, breakGlassContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, breakGlassContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteBreakGlassSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the break-glass gate part
// of the published security posture, so dropping the row or
// the section silently weakens the posture.
func TestVerificationSuiteBreakGlassSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, breakGlassSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, breakGlassSecurityGateRow)
	}
	if !strings.Contains(doc, breakGlassSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / field-naming / redaction / TTL-cap / access-only / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, breakGlassSecuritySectionHeading)
	}
	for _, want := range breakGlassSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, breakGlassSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteBreakGlassPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// break-glass command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteBreakGlassPRDDocumentsCommand(t *testing.T) {
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
		if cmd == breakGlassPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the break-glass gate as a required backend command.",
		requiredPRDPath, breakGlassPRDCommand)
}

// TestVerificationSuiteBreakGlassCanonicalFileExists pins the
// canonical reference break-glass test file and its load-bearing
// function pair. Deleting the file or renaming either function
// to a name that does not match the `TestBreakGlass` substring
// silently de-gates the break-glass suite for any caller relying
// on the PRD's `-run TestBreakGlass` filter.
func TestVerificationSuiteBreakGlassCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(breakGlassCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical break-glass test file is the load-bearing convention every break-glass regression MUST trip; deleting it silently removes the break-glass gate.",
			breakGlassCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range breakGlassCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the break-glass pair is the load-bearing assertion set every break-glass regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				breakGlassCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteBreakGlassAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher
// fires (or stays silent) correctly. Without this self-check a
// future "improvement" to the matchers (a tightened regex, a
// relaxed substring set, a renamed constant) could silently let
// real regressions slip through.
func TestVerificationSuiteBreakGlassAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			breakGlassCIWorkflowStepName,
			breakGlassCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Break-glass tests\n        run: go test -run TestBreakGlass ./...\n"
		for _, want := range []string{
			breakGlassCIWorkflowStepName,
			breakGlassCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, breakGlassVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", breakGlassVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 28. Required: break-glass tests\nstep \"go test -run TestBreakGlass ./...\"\nif ! go test -run TestBreakGlass ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, breakGlassVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", breakGlassVerifyShStepHeader)
		}
		if !strings.Contains(doc, breakGlassVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", breakGlassVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n27. `go test -run TestAdminEndpoint ./...`\n"
		if strings.Contains(doc, breakGlassContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", breakGlassContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n27. `go test -run TestAdminEndpoint ./...`\n28. `go test -run TestBreakGlass ./...`\n"
		if !strings.Contains(doc, breakGlassContributingEntry) {
			t.Fatalf("complete fixture missing %q", breakGlassContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Break-Glass Tests\n\n")
		for _, want := range breakGlassSecuritySectionSubstrings {
			if want == "elevated_access" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range breakGlassSecuritySectionSubstrings {
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
		b.WriteString("## Break-Glass Tests\n\n")
		for _, want := range breakGlassSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range breakGlassSecuritySectionSubstrings {
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
			if cmd == breakGlassPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", breakGlassPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestBreakGlass ./..."]}}`
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
			if cmd == breakGlassPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", breakGlassPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package store\n\nimport \"testing\"\n\nfunc TestBreakGlassCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range breakGlassCanonicalFuncs {
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
		doc := "package store\n\nimport \"testing\"\n\nfunc TestBreakGlassCoversCallSites(t *testing.T) {}\nfunc TestBreakGlassPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range breakGlassCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestBreakGlass substring locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantSubstring = "TestBreakGlass"
		for _, want := range breakGlassCanonicalFuncs {
			if !strings.Contains(want, wantSubstring) {
				t.Errorf("canonical-funcs entry %q does not contain %q — the PRD's `-run TestBreakGlass` filter binds to the `TestBreakGlass` substring and would silently miss this function", want, wantSubstring)
			}
		}
	})
}
