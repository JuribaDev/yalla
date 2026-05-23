package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — quota concurrency tests (BE-0384).
//
// Threat model: the contract between Yalla's quota checker
// (`internal/controlplane/quota`) and every caller (customer-facing
// HTTP handler, AI agent, CI pipeline, downstream SDK, provisioning
// worker, future frontend) is "two units of work for the same tenant
// and resource can never both decide they have headroom and both
// commit a reservation past a hard limit, and two tenants' parallel
// reservations can never leak into one another's count." That
// invariant is enforced at the persistence layer by the FOR UPDATE
// lock on the per-organization, per-resource usage counter row and
// by the organization predicate carried through every counter, sum,
// and insert. A silent erosion of that contract — the dedicated CI
// step quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted, the
// canonical `quota_test.go` file removed, or the canonical
// concurrency function pair renamed — would silently flatten the
// concurrency suite to a single happy-path row and let a race
// regression (a dropped lock, a missing organization predicate, a
// reservation insert that bypasses the usage counter) ship without
// firing any gate.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step header,
// the CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical
// concurrency test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Quota concurrency tests` that invokes
//     `go test -run TestQuotaConcurrency ./...`. Even though
//     `go test ./...` covers the same packages, the dedicated step
//     is defence-in-depth: a future narrowing of the umbrella step
//     (e.g. `go test ./internal/...` minus quota) would still
//     leave this gate green, surfacing the regression as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestQuotaConcurrency ./...` under the canonical
//     step header `# 10. Required: quota concurrency tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `10. \`go test -run TestQuotaConcurrency ./...\`` so
//     contributors know the gate before they open a PR. The
//     numeric prefix keeps verify.sh and CONTRIBUTING.md in
//     lockstep with BE-0379's `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, BE-0381's
//     `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
//     `8. go test ./internal/controlplane/openapi/...`, and
//     BE-0383's `9. go test -run TestPolicyMatrix ./...` pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Quota concurrency tests` row, AND a dedicated
//     `## Quota Concurrency Tests` section MUST explain the
//     contract operators, auditors, and AI agents rely on: the
//     hard-limit-never-overallocates invariant, the cross-tenant
//     isolation invariant, deterministic Postgres-migration
//     fixtures (no live Dokploy), opt-in `YALLA_EXTERNAL_DOKPLOY`
//     external smoke, redaction, and the CI-on-every-push-and-PR
//     cadence.
//  5. `ralph/prd.json` — `verificationLoop.requiredBackendCommands`
//     MUST list `go test -run TestQuotaConcurrency ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     canonical command without needing to discover it from CI
//     workflows or shell scripts.
//  6. `internal/controlplane/quota/quota_test.go` — the canonical
//     reference concurrency test file MUST exist and MUST declare
//     the load-bearing concurrency function pair
//     (`TestQuotaConcurrencyHardLimitNeverOverallocates`,
//     `TestQuotaConcurrencyTenantIsolation`). The PRD's
//     `go test -run TestQuotaConcurrency ./...` filter binds to
//     the `TestQuotaConcurrency…` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     concurrency suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteQuotaConcurrencyAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// quotaConcurrencyCIWorkflowStepName is the exact step name CI
	// uses to invoke the quota concurrency suite. A rename forces a
	// deliberate update both here and in the workflow.
	quotaConcurrencyCIWorkflowStepName = "- name: Quota concurrency tests"
	// quotaConcurrencyCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future package
	// that declares a `TestQuotaConcurrency…` test.
	quotaConcurrencyCIWorkflowStepRun = "run: go test -run TestQuotaConcurrency ./..."

	// quotaConcurrencyVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestQuotaConcurrency
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both
	// this constant and the script.
	quotaConcurrencyVerifyShStepHeader = "# 10. Required: quota concurrency tests"
	// quotaConcurrencyVerifyShStepCmd is the literal command that
	// MUST appear inside the required-quota-concurrency step.
	// Asserting on the literal (not a regex over the file) makes
	// the failure point the operator at the exact line that
	// drifted.
	quotaConcurrencyVerifyShStepCmd = `go test -run TestQuotaConcurrency ./...`

	// quotaConcurrencyContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	quotaConcurrencyContributingEntry = "10. `go test -run TestQuotaConcurrency ./...`"

	// quotaConcurrencySecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the quota concurrency suite is part of the
	// published security posture.
	quotaConcurrencySecurityGateRow = "| Quota concurrency tests | `go test -run TestQuotaConcurrency ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// quotaConcurrencySecuritySectionHeading is the dedicated
	// `## Quota Concurrency Tests` heading SECURITY.md MUST carry.
	// The section explains the hard-limit-never-overallocates
	// invariant, the cross-tenant isolation invariant, the
	// determinism contract, the actionable-failure contract, the
	// opt-in-external escape hatch, and the redaction posture.
	quotaConcurrencySecuritySectionHeading = "## Quota Concurrency Tests"

	// quotaConcurrencyPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract
	// document, not from shell scripts or CI workflows.
	quotaConcurrencyPRDCommand = "go test -run TestQuotaConcurrency ./..."

	// quotaConcurrencyCanonicalFile is the relative path of the
	// canonical reference concurrency test file. The
	// `internal/controlplane/quota/quota_test.go` file declares the
	// concurrency function pair every other quota concurrency test
	// pivots on; deleting it silently kills the convention future
	// concurrency tests must mirror.
	quotaConcurrencyCanonicalFile = "internal/controlplane/quota/quota_test.go"
)

// quotaConcurrencyCanonicalFuncs is the closed set of function
// declarations the canonical `quota_test.go` file MUST carry. The
// PRD's `-run TestQuotaConcurrency` filter binds to function names
// containing the `TestQuotaConcurrency` substring; renaming any
// entry to a name that does not match the prefix silently de-gates
// the concurrency suite for any caller relying on the filter. The
// pair captures the two load-bearing concurrency invariants the
// checker MUST keep:
//
//   - TestQuotaConcurrencyHardLimitNeverOverallocates — parallel
//     reservations against a single organization with a hard limit
//     below the number of attempts result in exactly limit
//     successes and the rest rejected, with the database agreeing
//     on the same count. The FOR UPDATE lock on the per-tenant,
//     per-resource usage counter row is what makes "two units of
//     work both decide they have headroom" impossible.
//   - TestQuotaConcurrencyTenantIsolation — parallel reservations
//     against two organizations, each with its own hard limit,
//     each respect their own organization's limit and never have
//     one tenant's usage leak into the other. The organization
//     predicate carried through every counter, sum, and insert is
//     what makes "two tenants flatten into one bucket"
//     impossible.
var quotaConcurrencyCanonicalFuncs = []string{
	"func TestQuotaConcurrencyHardLimitNeverOverallocates(",
	"func TestQuotaConcurrencyTenantIsolation(",
}

// quotaConcurrencySecuritySectionSubstrings is the closed set of
// literal substrings the `## Quota Concurrency Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0384
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/quota" — the package boundary the
//     suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"      — the AC2 determinism
//     contract.
//   - "FOR UPDATE"                  — the AC3 actionable-failure
//     contract is grounded in the lock the failing diagnostic
//     points at when the invariant breaks.
//   - "organization_id"             — the cross-tenant predicate
//     that MUST appear in every counter, sum, and insert.
//   - "CodeQuotaExceeded"           — the typed rejection code an
//     operator sees in the failure path.
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC7 opt-in-external
//     escape hatch.
//   - "yalla.output.v1"             — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"              — the AC5 error envelope
//     schema_version contract.
//   - "TestQuotaConcurrencyHardLimitNeverOverallocates" — the
//     canonical hard-limit function the -run filter binds to.
//   - "TestQuotaConcurrencyTenantIsolation" — the canonical
//     cross-tenant function that pins the no-cross-tenant-leak
//     invariant under concurrency.
//   - "redacted"                    — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "verification_suite_quota_concurrency_static_test.go"
//     — the gate is self-locating so a future operator can find
//     it without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var quotaConcurrencySecuritySectionSubstrings = []string{
	"internal/controlplane/quota",
	"deterministic fixtures",
	"FOR UPDATE",
	"organization_id",
	"CodeQuotaExceeded",
	"YALLA_EXTERNAL_DOKPLOY",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestQuotaConcurrencyHardLimitNeverOverallocates",
	"TestQuotaConcurrencyTenantIsolation",
	"redacted",
	"Every push and PR",
	"verification_suite_quota_concurrency_static_test.go",
}

// TestVerificationSuiteQuotaConcurrencyCIWorkflow pins the GitHub
// Actions test job to run the canonical quota concurrency command
// under the canonical step name. A silent removal of the step — or
// a narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuiteQuotaConcurrencyCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		quotaConcurrencyCIWorkflowStepName,
		quotaConcurrencyCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI quota-concurrency step is the defence-in-depth gate for the hard-limit + cross-tenant invariant — every push and PR MUST run `go test -run TestQuotaConcurrency ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteQuotaConcurrencyVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestQuotaConcurrency ./...` under its canonical
// step header so a contributor running the gate locally exercises
// the identical command CI runs.
func TestVerificationSuiteQuotaConcurrencyVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, quotaConcurrencyVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-quota-concurrency block is the local mirror of the CI gate and the quota-concurrency step must keep its canonical position.",
			requiredVerifyShPath, quotaConcurrencyVerifyShStepHeader)
	}
	if !strings.Contains(doc, quotaConcurrencyVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same quota-concurrency command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, quotaConcurrencyVerifyShStepCmd)
	}
}

// TestVerificationSuiteQuotaConcurrencyContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteQuotaConcurrencyContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, quotaConcurrencyContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, quotaConcurrencyContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteQuotaConcurrencySecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the quota-concurrency gate part
// of the published security posture, so dropping the row or the
// section silently weakens the posture.
func TestVerificationSuiteQuotaConcurrencySecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, quotaConcurrencySecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, quotaConcurrencySecurityGateRow)
	}
	if !strings.Contains(doc, quotaConcurrencySecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the hard-limit-never-overallocates / cross-tenant-isolation / determinism / actionable-failure / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, quotaConcurrencySecuritySectionHeading)
	}
	for _, want := range quotaConcurrencySecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, quotaConcurrencySecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteQuotaConcurrencyPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// quota-concurrency command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteQuotaConcurrencyPRDDocumentsCommand(t *testing.T) {
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
		if cmd == quotaConcurrencyPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the quota-concurrency gate as a required backend command.",
		requiredPRDPath, quotaConcurrencyPRDCommand)
}

// TestVerificationSuiteQuotaConcurrencyCanonicalFileExists pins the
// canonical reference concurrency test file and its load-bearing
// concurrency function pair. Deleting the file or renaming either
// function to a name that does not match the `TestQuotaConcurrency`
// prefix silently de-gates the concurrency suite for any caller
// relying on the PRD's `-run TestQuotaConcurrency` filter.
func TestVerificationSuiteQuotaConcurrencyCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(quotaConcurrencyCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical concurrency test file is the load-bearing convention every other quota concurrency test pivots on; deleting it silently removes the pattern future concurrency tests must mirror.",
			quotaConcurrencyCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range quotaConcurrencyCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the concurrency pair is the load-bearing assertion set every quota race regression MUST trip — a rename or deletion silently relaxes the hard-limit + cross-tenant contract for every downstream caller.",
				quotaConcurrencyCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteQuotaConcurrencyAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts the
// matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a tightened
// regex, a relaxed substring set, a renamed constant) could
// silently let real regressions slip through.
func TestVerificationSuiteQuotaConcurrencyAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			quotaConcurrencyCIWorkflowStepName,
			quotaConcurrencyCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Quota concurrency tests\n        run: go test -run TestQuotaConcurrency ./...\n"
		for _, want := range []string{
			quotaConcurrencyCIWorkflowStepName,
			quotaConcurrencyCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, quotaConcurrencyVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", quotaConcurrencyVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 10. Required: quota concurrency tests\nstep \"go test -run TestQuotaConcurrency ./...\"\nif ! go test -run TestQuotaConcurrency ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, quotaConcurrencyVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", quotaConcurrencyVerifyShStepHeader)
		}
		if !strings.Contains(doc, quotaConcurrencyVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", quotaConcurrencyVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n"
		if strings.Contains(doc, quotaConcurrencyContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", quotaConcurrencyContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n"
		if !strings.Contains(doc, quotaConcurrencyContributingEntry) {
			t.Fatalf("complete fixture missing %q", quotaConcurrencyContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Quota Concurrency Tests\n\n")
		for _, want := range quotaConcurrencySecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range quotaConcurrencySecuritySectionSubstrings {
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
		b.WriteString("## Quota Concurrency Tests\n\n")
		for _, want := range quotaConcurrencySecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range quotaConcurrencySecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test ./internal/controlplane/store/..."]}}`
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
			if cmd == quotaConcurrencyPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", quotaConcurrencyPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestQuotaConcurrency ./..."]}}`
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
			if cmd == quotaConcurrencyPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", quotaConcurrencyPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic quota_test.go declaring only one of the two
		// concurrency functions. The matcher MUST fire on the
		// missing second.
		doc := "package quota_test\n\nimport \"testing\"\n\nfunc TestQuotaConcurrencyHardLimitNeverOverallocates(t *testing.T) {}\n"
		missing := 0
		for _, want := range quotaConcurrencyCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every concurrency-pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package quota_test\n\nimport \"testing\"\n\nfunc TestQuotaConcurrencyHardLimitNeverOverallocates(t *testing.T) {}\nfunc TestQuotaConcurrencyTenantIsolation(t *testing.T) {}\n"
		for _, want := range quotaConcurrencyCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestQuotaConcurrency prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestQuotaConcurrency ./...`
		// filter binds to function names containing the
		// `TestQuotaConcurrency` substring. A canonical-funcs entry
		// that drops the prefix would silently de-gate the
		// concurrency suite for any caller relying on the filter.
		// This subtest asserts every canonical-funcs entry begins
		// with `func TestQuotaConcurrency`.
		const wantPrefix = "func TestQuotaConcurrency"
		for _, want := range quotaConcurrencyCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestQuotaConcurrency` filter binds to the `TestQuotaConcurrency` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
