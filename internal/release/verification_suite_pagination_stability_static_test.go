package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — pagination stability tests (BE-0397).
//
// Threat model: every Yalla Control Plane list endpoint composes its
// yalla.output.v1 success payload from `pagination.Page[T]` and pages
// the underlying tenant-scoped result set through opaque cursors
// produced by EncodeCursor / consumed by DecodeCursor. Agents, CI
// runners, operators, and audit reviewers rely on four load-bearing
// stability invariants every list endpoint MUST preserve: (1)
// end-to-end paged traversal visits every row exactly once — no
// duplicates, no drops, and the terminal page's `next_cursor` is
// empty exactly when there are no further rows; (2) the cursor wire
// shape is opaque (base64url, no padding, no '+', no '/', no '=', no
// whitespace) and never carries a tenant identifier, so a caller
// cannot hand-craft a cursor to escape tenant scoping; (3) the
// cursor is stable under concurrent inserts and deletes — a row
// inserted between two page fetches against the same cursor stream
// never appears in two pages, never displaces a row off the
// boundary, and never resurrects a row already deleted from the
// stream; (4) cross-tenant cursors do not leak rows. That invariant
// is enforced by the canonical pair
// `TestPaginationStabilityCoversCallSites` (closed-set scenario
// coverage) and
// `TestPaginationStabilityPreservesPagesUnderInserts` (per-page
// stability under a concurrent insert + delete burst) in
// `internal/controlplane/pagination/pagination_stability_test.go`.
// Both pair members are deterministic by design — they use the
// in-package `fakeStore` (declared in `page_test.go`) for the
// coverage member and a file-local `concurrentPaginationStore` (a
// mutex-guarded sibling of `fakeStore`) for the contention burst,
// so the gate stays green on every developer machine without a
// live Postgres or any external dependency.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `pagination_stability_test.go` file removed, or the canonical
// `TestPaginationStability…` function pair renamed — would let a
// pagination-stability regression (a list endpoint that silently
// duplicates rows under a concurrent insert; a cursor that decodes
// without sort/direction integrity checking, allowing a caller to
// mix cursors across endpoints; an encoding switch from base64url to
// a non-URL-safe shape; a cross-tenant cursor that leaks rows
// because the store layer dropped the orgID scope) ship without
// firing any gate. An agent paging an audit-event list under
// concurrent inserts would see duplicate rows, an operator
// reconciling a deployment list would see ghost rows, and — worst
// case — a cross-tenant probe would silently return another
// tenant's rows.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical pagination-stability test fixture
// fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Pagination stability tests` that invokes
//     `go test -run TestPaginationStability ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestPaginationStability ./...` under the
//     canonical step header
//     `# 22. Required: pagination stability tests`. The numeric
//     prefix is part of the contract: a reorder must be a deliberate
//     edit to both this constant and the script. #22 extends the
//     BE-0379..BE-0396 sequence by one slot; the trailing optionals
//     (#23 govulncheck, #24 staticcheck, #25 golangci-lint, #26
//     goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `22. \`go test -run TestPaginationStability ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0396's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Pagination stability tests` row, AND a dedicated
//     `## Pagination Stability Tests` section MUST explain the
//     contract operators, auditors, and AI agents rely on: the
//     closed-set coverage invariant (every canonical
//     direction/page-size shape), the cursor-opaqueness invariant
//     (base64url, no padding leakage), the cursor-stability invariant
//     under concurrent inserts/deletes, the cross-tenant-leak
//     prohibition, the deterministic-by-default behaviour (in-process
//     `fakeStore` / `concurrentPaginationStore`, no live Postgres, no
//     live Dokploy), the CI-on-every-push-and-PR cadence, the
//     schema-version contract (`yalla.output.v1` / `yalla.error.v1`),
//     and the redaction contract (the cursor wire payload never
//     embeds a tenant identifier or any other field a caller could
//     mutate to reach another tenant's rows).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestPaginationStability ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/pagination/pagination_stability_test.go`
//     — the canonical reference pagination-stability test file MUST
//     exist and MUST declare the load-bearing function pair
//     (`TestPaginationStabilityCoversCallSites`,
//     `TestPaginationStabilityPreservesPagesUnderInserts`). The
//     PRD's `go test -run TestPaginationStability ./...` filter
//     binds to the `TestPaginationStability` prefix; a rename to a
//     function whose name does not match the prefix silently
//     de-gates the pagination-stability suite for any caller relying
//     on the `-run` filter.
//
// The self-check
// (`TestVerificationSuitePaginationStabilityAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// paginationStabilityCIWorkflowStepName is the exact step name
	// CI uses to invoke the pagination-stability suite. A rename
	// forces a deliberate update both here and in the workflow.
	paginationStabilityCIWorkflowStepName = "- name: Pagination stability tests"
	// paginationStabilityCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestPaginationStability…` test.
	paginationStabilityCIWorkflowStepRun = "run: go test -run TestPaginationStability ./..."

	// paginationStabilityVerifyShStepHeader is the canonical comment
	// header that precedes the
	// `go test -run TestPaginationStability ./...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and the
	// script.
	paginationStabilityVerifyShStepHeader = "# 22. Required: pagination stability tests"
	// paginationStabilityVerifyShStepCmd is the literal command that
	// MUST appear inside the required-pagination-stability step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	paginationStabilityVerifyShStepCmd = `go test -run TestPaginationStability ./...`

	// paginationStabilityContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	paginationStabilityContributingEntry = "22. `go test -run TestPaginationStability ./...`"

	// paginationStabilitySecurityGateRow is the verification-gates
	// row that MUST appear in SECURITY.md so external operators and
	// reviewers can see the pagination-stability suite is part of
	// the published security posture.
	paginationStabilitySecurityGateRow = "| Pagination stability tests | `go test -run TestPaginationStability ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// paginationStabilitySecuritySectionHeading is the dedicated
	// `## Pagination Stability Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant, the
	// cursor-opaqueness invariant, the cursor-stability invariant
	// under contention, the cross-tenant-leak prohibition, the
	// deterministic-by-default behaviour, the actionable-failure
	// contract, the schema-version contract, and the redaction
	// contract.
	paginationStabilitySecuritySectionHeading = "## Pagination Stability Tests"

	// paginationStabilityPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	paginationStabilityPRDCommand = "go test -run TestPaginationStability ./..."

	// paginationStabilityCanonicalFile is the relative path of the
	// canonical reference pagination-stability test file. The
	// `internal/controlplane/pagination/pagination_stability_test.go`
	// file declares the function pair every pagination-stability
	// regression MUST trip; deleting it silently kills the
	// convention.
	paginationStabilityCanonicalFile = "internal/controlplane/pagination/pagination_stability_test.go"
)

// paginationStabilityCanonicalFuncs is the closed set of function
// declarations the canonical `pagination_stability_test.go` file
// MUST carry. The PRD's `-run TestPaginationStability` filter binds
// to function names containing the `TestPaginationStability`
// substring; renaming any entry to a name that does not match the
// prefix silently de-gates the pagination-stability suite for any
// caller relying on the filter. The pair captures the two
// load-bearing pagination-stability invariants the harness MUST
// keep:
//
//   - TestPaginationStabilityCoversCallSites — the closed-set
//     pagination-stability coverage invariant: for each canonical
//     scenario (empty / single / exact-page / multi-page / partial
//     trailing / ascending / descending) the test asserts every
//     seeded row is visited exactly once, no duplicates surface
//     across pages, the terminal page's `next_cursor` is empty
//     exactly when there are no further rows, the emitted cursor is
//     opaque (base64url, no padding, no '+', no '/', no '=', no
//     whitespace), every emitted cursor round-trips through
//     DecodeCursor with matching Sort and Direction, and a cursor
//     issued for the coverage tenant produces zero rows when applied
//     against the cross tenant. Trips at the package-internal API
//     with no infrastructure dependency.
//   - TestPaginationStabilityPreservesPagesUnderInserts — the
//     per-page stability invariant under contention: seeding a
//     single shared `concurrentPaginationStore` from
//     `paginationStabilityWorkers * paginationStabilityIterationsPerWorker`
//     goroutines each firing a mixed insert/delete burst while a
//     reader paginates end-to-end MUST yield no duplicate rows
//     across the reader's cursor stream, every undeleted seed row
//     observed exactly once, no resurrection of a row already
//     deleted from the stream, and a deterministic terminal page.
var paginationStabilityCanonicalFuncs = []string{
	"func TestPaginationStabilityCoversCallSites(",
	"func TestPaginationStabilityPreservesPagesUnderInserts(",
}

// paginationStabilitySecuritySectionSubstrings is the closed set of
// literal substrings the `## Pagination Stability Tests` section
// MUST contain. Each captures a different load-bearing fact the
// BE-0397 acceptance criteria require to be visible:
//
//   - "internal/controlplane/pagination" — the package boundary the
//     canonical pagination-stability harness lives in (AC1
//     documented suite scope).
//   - "pagination_stability_test.go" — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process `fakeStore` /
//     `concurrentPaginationStore` and no other infrastructure
//     dependency.
//   - "fakeStore"                 — the in-memory single-call list
//     fixture reused from `page_test.go` by the coverage member.
//   - "concurrentPaginationStore" — the in-memory mutex-guarded
//     list fixture declared by the burst member; documenting it
//     stops a future contention test from drifting onto a different
//     fixture that does not exercise the pagination-stability
//     contract.
//   - "EncodeCursor"              — the single chokepoint the gate
//     pivots on for cursor emission; an alternative encoder would
//     bypass the opaqueness invariant.
//   - "DecodeCursor"              — the chokepoint for cursor
//     ingestion; ParseParams' sort/direction integrity check binds
//     to the decoded Cursor.
//   - "base64url"                 — the AC8 wire-shape contract;
//     a regression that switched to standard base64 would surface
//     here.
//   - "no duplicates"             — the AC closed-set coverage
//     anchor for the duplicate-row prohibition.
//   - "no drops"                  — the AC closed-set coverage
//     anchor for the silent-skip prohibition.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (every list-endpoint response carries the
//     originating request_id so an operator can correlate without
//     re-running the suite locally).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "tenant isolation"          — the cross-tenant-leak
//     prohibition; a cursor issued for tenant A applied against
//     tenant B's store MUST yield zero rows.
//   - "TestPaginationStabilityCoversCallSites" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestPaginationStabilityPreservesPagesUnderInserts" — the
//     canonical contention burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "redacted"                  — the AC8 redaction contract; the
//     cursor wire payload never embeds a tenant identifier so the
//     opaque cursor cannot be a reflection channel.
//   - "verification_suite_pagination_stability_static_test.go" —
//     the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var paginationStabilitySecuritySectionSubstrings = []string{
	"internal/controlplane/pagination",
	"pagination_stability_test.go",
	"deterministic",
	"fakeStore",
	"concurrentPaginationStore",
	"EncodeCursor",
	"DecodeCursor",
	"base64url",
	"no duplicates",
	"no drops",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"tenant isolation",
	"TestPaginationStabilityCoversCallSites",
	"TestPaginationStabilityPreservesPagesUnderInserts",
	"Every push and PR",
	"redacted",
	"verification_suite_pagination_stability_static_test.go",
}

// TestVerificationSuitePaginationStabilityCIWorkflow pins the GitHub
// Actions test job to run the canonical pagination-stability command
// under the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuitePaginationStabilityCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		paginationStabilityCIWorkflowStepName,
		paginationStabilityCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI pagination-stability step is the defence-in-depth gate for the closed-set coverage + per-page contention-stability invariants — every push and PR MUST run `go test -run TestPaginationStability ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuitePaginationStabilityVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestPaginationStability ./...` under its canonical
// step header so a contributor running the gate locally exercises
// the identical command CI runs.
func TestVerificationSuitePaginationStabilityVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, paginationStabilityVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-pagination-stability block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, paginationStabilityVerifyShStepHeader)
	}
	if !strings.Contains(doc, paginationStabilityVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same pagination-stability command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, paginationStabilityVerifyShStepCmd)
	}
}

// TestVerificationSuitePaginationStabilityContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuitePaginationStabilityContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, paginationStabilityContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, paginationStabilityContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuitePaginationStabilitySecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the pagination-stability gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuitePaginationStabilitySecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, paginationStabilitySecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, paginationStabilitySecurityGateRow)
	}
	if !strings.Contains(doc, paginationStabilitySecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / cursor-opaqueness / per-page-stability / cross-tenant-leak / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, paginationStabilitySecuritySectionHeading)
	}
	for _, want := range paginationStabilitySecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, paginationStabilitySecuritySectionHeading)
		}
	}
}

// TestVerificationSuitePaginationStabilityPRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// pagination-stability command without needing to discover it from
// CI workflows or shell scripts.
func TestVerificationSuitePaginationStabilityPRDDocumentsCommand(t *testing.T) {
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
		if cmd == paginationStabilityPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the pagination-stability gate as a required backend command.",
		requiredPRDPath, paginationStabilityPRDCommand)
}

// TestVerificationSuitePaginationStabilityCanonicalFileExists pins
// the canonical reference pagination-stability test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestPaginationStability`
// prefix silently de-gates the pagination-stability suite for any
// caller relying on the PRD's `-run TestPaginationStability` filter.
func TestVerificationSuitePaginationStabilityCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(paginationStabilityCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical pagination-stability test file is the load-bearing convention every pagination-stability regression MUST trip; deleting it silently removes the pagination-stability gate.",
			paginationStabilityCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range paginationStabilityCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the pagination-stability pair is the load-bearing assertion set every pagination-stability regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-page-contention-stability contract for every downstream caller.",
				paginationStabilityCanonicalFile, want)
		}
	}
}

// TestVerificationSuitePaginationStabilityAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts the
// matcher fires (or stays silent) correctly. Without this self-check
// a future "improvement" to the matchers (a tightened regex, a
// relaxed substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuitePaginationStabilityAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			paginationStabilityCIWorkflowStepName,
			paginationStabilityCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Pagination stability tests\n        run: go test -run TestPaginationStability ./...\n"
		for _, want := range []string{
			paginationStabilityCIWorkflowStepName,
			paginationStabilityCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, paginationStabilityVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", paginationStabilityVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 22. Required: pagination stability tests\nstep \"go test -run TestPaginationStability ./...\"\nif ! go test -run TestPaginationStability ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, paginationStabilityVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", paginationStabilityVerifyShStepHeader)
		}
		if !strings.Contains(doc, paginationStabilityVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", paginationStabilityVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n21. `go test -run TestAuditCompleteness ./...`\n"
		if strings.Contains(doc, paginationStabilityContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", paginationStabilityContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n21. `go test -run TestAuditCompleteness ./...`\n22. `go test -run TestPaginationStability ./...`\n"
		if !strings.Contains(doc, paginationStabilityContributingEntry) {
			t.Fatalf("complete fixture missing %q", paginationStabilityContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Pagination Stability Tests\n\n")
		for _, want := range paginationStabilitySecuritySectionSubstrings {
			if want == "no duplicates" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range paginationStabilitySecuritySectionSubstrings {
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
		b.WriteString("## Pagination Stability Tests\n\n")
		for _, want := range paginationStabilitySecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range paginationStabilitySecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
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
			if cmd == paginationStabilityPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", paginationStabilityPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestPaginationStability ./..."]}}`
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
			if cmd == paginationStabilityPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", paginationStabilityPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package pagination\n\nimport \"testing\"\n\nfunc TestPaginationStabilityCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range paginationStabilityCanonicalFuncs {
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
		doc := "package pagination\n\nimport \"testing\"\n\nfunc TestPaginationStabilityCoversCallSites(t *testing.T) {}\nfunc TestPaginationStabilityPreservesPagesUnderInserts(t *testing.T) {}\n"
		for _, want := range paginationStabilityCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestPaginationStability prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestPaginationStability"
		for _, want := range paginationStabilityCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestPaginationStability` filter binds to the `TestPaginationStability` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
