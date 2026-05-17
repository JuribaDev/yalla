package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — backup and restore rehearsal tests (BE-0399).
//
// Threat model: Yalla's source of truth is its Postgres database. A
// backup-and-restore rehearsal is the closed loop between (1) the
// operator's external pipeline producing a backup and writing the
// RFC3339 status timestamp to `YALLA_BACKUP_STATUS_FILE`, and (2) the
// Yalla Control Plane API restoring awareness of that backup on its
// next GET /healthz/backup probe. The single chokepoint between the two
// halves is `backup.FileReporter`: every other process — the
// unauthenticated probe handler, the operator's dashboard, and any
// future operator-facing surface — depends on the reporter's documented
// state set: ErrNoBackupRecorded when the source is wired but no
// successful backup has landed yet; a typed CodeServer error when the
// file is empty, whitespace-only, or malformed (the message MUST name
// the path but MUST NOT echo the content); a parsed Status with Age
// clamped non-negative under clock skew; Fresh()==true at the on-Age
// boundary and on any zero-MaxAge opt-out; Configured=false for the
// Unconfigured() reporter; and context.Canceled bubbling cleanly under
// a shutting-down request. That invariant is enforced by the canonical
// pair `TestBackupRestoreRehearsalCoversCallSites` (closed-set
// scenario coverage) and
// `TestBackupRestoreRehearsalPreservesContractUnderContention`
// (per-decision stability under concurrent contention) in
// `internal/controlplane/backup/backup_restore_rehearsal_test.go`. Both
// pair members are deterministic by design — they construct
// FileReporters against `t.TempDir`-backed fixtures with injected
// clocks, share each reporter across burst goroutines, and never reach
// a live Postgres, a live Dokploy, or any external network.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `backup_restore_rehearsal_test.go` file removed, or the canonical
// `TestBackupRestoreRehearsal…` function pair renamed — would let a
// rehearsal regression (a reporter that quietly returned a 200 envelope
// on a malformed status; a parse error path that started echoing the
// file content into the wire message; a freshness predicate switched
// from `Age <= MaxAge` to `Age < MaxAge` so the on-boundary value
// flapped; a regression that turned the `pristine post-restore` case
// into a 5xx because the missing-file sentinel was dropped) ship
// without firing any gate. An operator would see "all green" while the
// backup pipeline silently abandoned the database; an audit reviewer
// would never see the violation because the probe surfaced no error.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical rehearsal test fixture fails ONE
// test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Backup restore rehearsal tests` that
//     invokes `go test -run TestBackupRestoreRehearsal ./...`. Even
//     though the umbrella `go test ./...` step exercises the same
//     package, the dedicated step is defence-in-depth: a future
//     narrowing of the umbrella step would still leave this gate
//     firing as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestBackupRestoreRehearsal ./...` under the
//     canonical step header
//     `# 24. Required: backup and restore rehearsal tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #24
//     extends the BE-0379..BE-0398 sequence by one slot; the trailing
//     optionals (#25 govulncheck, #26 staticcheck, #27 golangci-lint,
//     #28 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `24. \`go test -run TestBackupRestoreRehearsal ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0398's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Backup restore rehearsal tests` row, AND a
//     dedicated `## Backup Restore Rehearsal Tests` section MUST
//     explain the contract operators, auditors, and AI agents rely on:
//     the closed-set rehearsal coverage invariant (every documented
//     reporter state — pristine, fresh, on-boundary, stale, opt-out,
//     clock-skew, whitespace, empty, malformed, secret-seeded,
//     unconfigured, cancelled), the deterministic-by-default behaviour
//     (t.TempDir fixtures, injected clocks, no live Postgres, no live
//     Dokploy), the CI-on-every-push-and-PR cadence, the
//     schema-version contract (`yalla.output.v1` /
//     `yalla.error.v1`), and the redaction contract (the wire error
//     message never echoes the status file content, even when the
//     content was a secret the misconfigured pipeline wrote by
//     mistake).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestBackupRestoreRehearsal ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/backup/backup_restore_rehearsal_test.go`
//     — the canonical reference rehearsal test file MUST exist and
//     MUST declare the load-bearing function pair
//     (`TestBackupRestoreRehearsalCoversCallSites`,
//     `TestBackupRestoreRehearsalPreservesContractUnderContention`).
//     The PRD's `go test -run TestBackupRestoreRehearsal ./...`
//     filter binds to the `TestBackupRestoreRehearsal` prefix; a
//     rename to a function whose name does not match the prefix
//     silently de-gates the rehearsal suite for any caller relying on
//     the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteBackupRestoreAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the analyser)
// and under-tightening (a real regression slips through) are both
// caught at the package-internal API.

const (
	// backupRestoreCIWorkflowStepName is the exact step name CI uses to
	// invoke the rehearsal suite. A rename forces a deliberate update
	// both here and in the workflow.
	backupRestoreCIWorkflowStepName = "- name: Backup restore rehearsal tests"
	// backupRestoreCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestBackupRestoreRehearsal…` test.
	backupRestoreCIWorkflowStepRun = "run: go test -run TestBackupRestoreRehearsal ./..."

	// backupRestoreVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestBackupRestoreRehearsal ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	backupRestoreVerifyShStepHeader = "# 24. Required: backup and restore rehearsal tests"
	// backupRestoreVerifyShStepCmd is the literal command that MUST
	// appear inside the required-rehearsal step. Asserting on the
	// literal (not a regex over the file) makes the failure point the
	// operator at the exact line that drifted.
	backupRestoreVerifyShStepCmd = `go test -run TestBackupRestoreRehearsal ./...`

	// backupRestoreContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in CONTRIBUTING.md.
	// Preserving the numeric prefix keeps verify.sh and CONTRIBUTING.md
	// in lockstep.
	backupRestoreContributingEntry = "24. `go test -run TestBackupRestoreRehearsal ./...`"

	// backupRestoreSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the rehearsal suite is part of the published security
	// posture.
	backupRestoreSecurityGateRow = "| Backup restore rehearsal tests | `go test -run TestBackupRestoreRehearsal ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// backupRestoreSecuritySectionHeading is the dedicated
	// `## Backup Restore Rehearsal Tests` heading SECURITY.md MUST
	// carry. The section explains the closed-set rehearsal coverage
	// invariant, the documented reporter state set, the
	// deterministic-by-default behaviour, the actionable-failure
	// contract, the schema-version contract, and the redaction
	// contract.
	backupRestoreSecuritySectionHeading = "## Backup Restore Rehearsal Tests"

	// backupRestorePRDCommand is the literal command that MUST appear
	// in the PRD's verificationLoop.requiredBackendCommands array so an
	// agent surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	backupRestorePRDCommand = "go test -run TestBackupRestoreRehearsal ./..."

	// backupRestoreCanonicalFile is the relative path of the canonical
	// reference rehearsal test file. The
	// `internal/controlplane/backup/backup_restore_rehearsal_test.go`
	// file declares the function pair every rehearsal regression MUST
	// trip; deleting it silently kills the convention.
	backupRestoreCanonicalFile = "internal/controlplane/backup/backup_restore_rehearsal_test.go"
)

// backupRestoreCanonicalFuncs is the closed set of function declarations
// the canonical `backup_restore_rehearsal_test.go` file MUST carry. The
// PRD's `-run TestBackupRestoreRehearsal` filter binds to function names
// containing the `TestBackupRestoreRehearsal` substring; renaming any
// entry to a name that does not match the prefix silently de-gates the
// rehearsal suite for any caller relying on the filter. The pair
// captures the two load-bearing rehearsal invariants the harness MUST
// keep:
//
//   - TestBackupRestoreRehearsalCoversCallSites — the closed-set
//     rehearsal coverage invariant: every documented reporter state
//     (pristine post-restore, fresh, on-Age boundary, stale, opt-out
//     MaxAge=0, clock-skew, whitespace-tolerant parse, empty,
//     whitespace-only, malformed, secret-seeded, unconfigured,
//     cancelled-context) yields the predicted Status + error pair, and
//     the typed CodeServer error path names the status file path
//     without echoing the file content.
//   - TestBackupRestoreRehearsalPreservesContractUnderContention — the
//     per-decision stability invariant under contention: firing
//     `rehearsalWorkers * rehearsalIterationsPerWorker` goroutines
//     against a single FileReporter per scenario MUST yield, for every
//     goroutine, the predicate the closed-set scenario for ITS OWN
//     fixture predicts — a cross-write under the race that swapped
//     two goroutines' fixtures would fail the per-iteration assertion
//     even when the aggregate pass count matched.
var backupRestoreCanonicalFuncs = []string{
	"func TestBackupRestoreRehearsalCoversCallSites(",
	"func TestBackupRestoreRehearsalPreservesContractUnderContention(",
}

// backupRestoreSecuritySectionSubstrings is the closed set of literal
// substrings the `## Backup Restore Rehearsal Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0399
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/backup" — the package boundary the
//     canonical rehearsal harness lives in (AC1 documented suite
//     scope).
//   - "backup_restore_rehearsal_test.go" — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"      — the AC2 determinism contract; both pair
//     members run with `t.TempDir` fixtures and injected clocks.
//   - "FileReporter"       — the single chokepoint the gate pivots on;
//     an alternative reporter would bypass the rehearsal contract.
//   - "NewFileReporter"    — the deterministic constructor the suite
//     binds to.
//   - "ErrNoBackupRecorded" — the pristine-post-restore sentinel; a
//     regression that dropped the sentinel would convert a
//     freshly-restored DB into a 5xx.
//   - "Status.Fresh"       — the freshness predicate the rehearsal
//     contract preserves at the on-Age boundary.
//   - "MaxAge"             — the operator-chosen freshness threshold
//     the rehearsal contract opts out of when zero.
//   - "RFC3339"            — the contract status-file format.
//   - "request_id"         — the AC3 actionable-failure identifier
//     (every healthz envelope carries it).
//   - "yalla.output.v1"    — the AC5 success envelope schema_version
//     contract.
//   - "yalla.error.v1"     — the AC5 error envelope schema_version
//     contract.
//   - "rehearsal"          — the framing this entire suite enforces.
//   - "TestBackupRestoreRehearsalCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestBackupRestoreRehearsalPreservesContractUnderContention" —
//     the canonical contention burst function the -run filter binds to.
//   - "Every push and PR"  — the AC4 CI gating cadence.
//   - "redacted"           — the AC8 redaction contract; the wire
//     error message never echoes the status file content.
//   - "verification_suite_backup_restore_static_test.go" — the gate is
//     self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while still
// pinning every AC.
var backupRestoreSecuritySectionSubstrings = []string{
	"internal/controlplane/backup",
	"backup_restore_rehearsal_test.go",
	"deterministic",
	"FileReporter",
	"NewFileReporter",
	"ErrNoBackupRecorded",
	"Status.Fresh",
	"MaxAge",
	"RFC3339",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"rehearsal",
	"TestBackupRestoreRehearsalCoversCallSites",
	"TestBackupRestoreRehearsalPreservesContractUnderContention",
	"Every push and PR",
	"redacted",
	"verification_suite_backup_restore_static_test.go",
}

// TestVerificationSuiteBackupRestoreCIWorkflow pins the GitHub Actions
// test job to run the canonical rehearsal command under the canonical
// step name. A silent removal of the step — or a narrowing of the run
// command — defeats the defence-in-depth promise that even a regression
// in the umbrella `go test ./...` step would still leave this gate
// firing.
func TestVerificationSuiteBackupRestoreCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		backupRestoreCIWorkflowStepName,
		backupRestoreCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI rehearsal step is the defence-in-depth gate for the closed-set rehearsal coverage + per-decision stability invariants — every push and PR MUST run `go test -run TestBackupRestoreRehearsal ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteBackupRestoreVerifyShRunsCanonicalCommand pins
// the local commit gate to run
// `go test -run TestBackupRestoreRehearsal ./...` under its canonical
// step header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteBackupRestoreVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, backupRestoreVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-rehearsal block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, backupRestoreVerifyShStepHeader)
	}
	if !strings.Contains(doc, backupRestoreVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same rehearsal command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, backupRestoreVerifyShStepCmd)
	}
}

// TestVerificationSuiteBackupRestoreContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a contributor
// opens a PR. The numeric prefix matches the verify.sh step number to
// keep the two surfaces in lockstep.
func TestVerificationSuiteBackupRestoreContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, backupRestoreContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, backupRestoreContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteBackupRestoreSecurityDocumented pins the public
// security policy. SECURITY.md is the operator- and auditor-facing
// surface that makes the rehearsal gate part of the published security
// posture, so dropping the row or the section silently weakens the
// posture.
func TestVerificationSuiteBackupRestoreSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, backupRestoreSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, backupRestoreSecurityGateRow)
	}
	if !strings.Contains(doc, backupRestoreSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / pristine-sentinel / freshness-boundary / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, backupRestoreSecuritySectionHeading)
	}
	for _, want := range backupRestoreSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, backupRestoreSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteBackupRestorePRDDocumentsCommand pins the PRD's
// verificationLoop.requiredBackendCommands so an AI agent reading the
// PRD before picking up a story sees the canonical rehearsal command
// without needing to discover it from CI workflows or shell scripts.
func TestVerificationSuiteBackupRestorePRDDocumentsCommand(t *testing.T) {
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
		if cmd == backupRestorePRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the rehearsal gate as a required backend command.",
		requiredPRDPath, backupRestorePRDCommand)
}

// TestVerificationSuiteBackupRestoreCanonicalFileExists pins the
// canonical reference rehearsal test file and its load-bearing function
// pair. Deleting the file or renaming either function to a name that
// does not match the `TestBackupRestoreRehearsal` prefix silently
// de-gates the rehearsal suite for any caller relying on the PRD's
// `-run TestBackupRestoreRehearsal` filter.
func TestVerificationSuiteBackupRestoreCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(backupRestoreCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical rehearsal test file is the load-bearing convention every rehearsal regression MUST trip; deleting it silently removes the rehearsal gate.",
			backupRestoreCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range backupRestoreCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the rehearsal pair is the load-bearing assertion set every rehearsal regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				backupRestoreCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteBackupRestoreAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires (or
// stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed substring
// set, a renamed constant) could silently let real regressions slip
// through.
func TestVerificationSuiteBackupRestoreAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			backupRestoreCIWorkflowStepName,
			backupRestoreCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Backup restore rehearsal tests\n        run: go test -run TestBackupRestoreRehearsal ./...\n"
		for _, want := range []string{
			backupRestoreCIWorkflowStepName,
			backupRestoreCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, backupRestoreVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", backupRestoreVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 24. Required: backup and restore rehearsal tests\nstep \"go test -run TestBackupRestoreRehearsal ./...\"\nif ! go test -run TestBackupRestoreRehearsal ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, backupRestoreVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", backupRestoreVerifyShStepHeader)
		}
		if !strings.Contains(doc, backupRestoreVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", backupRestoreVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n23. `go test -run TestTenantIsolation ./...`\n"
		if strings.Contains(doc, backupRestoreContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", backupRestoreContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n23. `go test -run TestTenantIsolation ./...`\n24. `go test -run TestBackupRestoreRehearsal ./...`\n"
		if !strings.Contains(doc, backupRestoreContributingEntry) {
			t.Fatalf("complete fixture missing %q", backupRestoreContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Backup Restore Rehearsal Tests\n\n")
		for _, want := range backupRestoreSecuritySectionSubstrings {
			if want == "ErrNoBackupRecorded" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range backupRestoreSecuritySectionSubstrings {
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
		b.WriteString("## Backup Restore Rehearsal Tests\n\n")
		for _, want := range backupRestoreSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range backupRestoreSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestTenantIsolation ./..."]}}`
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
			if cmd == backupRestorePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", backupRestorePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestBackupRestoreRehearsal ./..."]}}`
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
			if cmd == backupRestorePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", backupRestorePRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package backup_test\n\nimport \"testing\"\n\nfunc TestBackupRestoreRehearsalCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range backupRestoreCanonicalFuncs {
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
		doc := "package backup_test\n\nimport \"testing\"\n\nfunc TestBackupRestoreRehearsalCoversCallSites(t *testing.T) {}\nfunc TestBackupRestoreRehearsalPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range backupRestoreCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestBackupRestoreRehearsal prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestBackupRestoreRehearsal"
		for _, want := range backupRestoreCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestBackupRestoreRehearsal` filter binds to the `TestBackupRestoreRehearsal` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
