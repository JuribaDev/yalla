package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — redaction tests (BE-0387).
//
// Threat model: the contract between Yalla's redactor
// (`internal/output`), the per-tenant variable redaction in
// `internal/controlplane/variables`, the CLI envelope and dry-run
// redaction in `internal/cli`, and every operator, AI agent, CI
// pipeline, downstream SDK, audit pipeline, and future frontend is
// "secrets, tokens, API keys, cookies, and rendered environment
// variable values never appear in customer-facing output, logs,
// errors, audit metadata, test output, or dry-run output." That
// invariant is enforced by the `Redactor` in `internal/output`
// (structural scrubbing of Authorization-style headers, token-bearing
// query parameters, and explicit secrets registered via
// `NewRedactor`) and by the per-package suites that pivot on it. A
// silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `redact_test.go` file removed, or the canonical
// `TestRedactionContract…` function pair renamed — would let a
// redaction regression (a tightened regex that accidentally exempts
// a header casing, a Sentinel substitution that silently loses the
// public-API contract every other matcher relies on, a new transport
// added to `NewRedactor` callers without an assertion) ship without
// firing any gate.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step header,
// the CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical
// redaction test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Redaction tests` that invokes
//     `go test -run TestRedaction ./...`. Even though
//     `go test ./...` covers the same packages, the dedicated step
//     is defence-in-depth: a future narrowing of the umbrella step
//     (e.g. `go test ./internal/...` minus output) would still
//     leave this gate green, surfacing the regression as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestRedaction ./...` under the canonical step
//     header `# 13. Required: redaction tests`. The numeric prefix
//     is part of the contract: a reorder must be a deliberate edit
//     to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `13. \`go test -run TestRedaction ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix
//     keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379's `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, BE-0381's
//     `7. go test ./internal/controlplane/httpapi/...`, BE-0382's
//     `8. go test ./internal/controlplane/openapi/...`, BE-0383's
//     `9. go test -run TestPolicyMatrix ./...`, BE-0384's
//     `10. go test -run TestQuotaConcurrency ./...`, BE-0385's
//     `11. go test -run TestJobWorkerLease ./...`, and BE-0386's
//     `12. go test -run TestFakeDokploy ./...` pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Redaction tests` row, AND a dedicated
//     `## Redaction Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the
//     structural-transport invariant (every header/query/explicit
//     transport scrubbed before any caller can read it back), the
//     explicit-secret + idempotency invariant
//     (`Redact(Redact(s)) == Redact(s)`, sub-threshold secrets
//     dropped, duplicates de-duplicated, sentinel cannot be
//     re-registered), deterministic Postgres-migration fixtures
//     (no live Dokploy), opt-in `YALLA_EXTERNAL_DOKPLOY` external
//     smoke, and the CI-on-every-push-and-PR cadence.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestRedaction ./...` so an AI agent reading
//     the PRD before picking up a story sees the canonical command
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/output/redact_test.go` — the canonical reference
//     redaction test file MUST exist and MUST declare the
//     load-bearing function pair
//     (`TestRedactionContractStructuralPatternsAcrossKnownTransports`,
//     `TestRedactionContractExplicitSecretsAndIdempotency`). The
//     PRD's `go test -run TestRedaction ./...` filter binds to the
//     `TestRedaction…` prefix; a rename to a function whose name
//     does not match the prefix silently de-gates the redaction
//     suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteRedactionAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// redactionCIWorkflowStepName is the exact step name CI uses to
	// invoke the redaction suite. A rename forces a deliberate
	// update both here and in the workflow.
	redactionCIWorkflowStepName = "- name: Redaction tests"
	// redactionCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestRedaction…` test.
	redactionCIWorkflowStepRun = "run: go test -run TestRedaction ./..."

	// redactionVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestRedaction ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	redactionVerifyShStepHeader = "# 13. Required: redaction tests"
	// redactionVerifyShStepCmd is the literal command that MUST
	// appear inside the required-redaction step. Asserting on the
	// literal (not a regex over the file) makes the failure point
	// the operator at the exact line that drifted.
	redactionVerifyShStepCmd = `go test -run TestRedaction ./...`

	// redactionContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	redactionContributingEntry = "13. `go test -run TestRedaction ./...`"

	// redactionSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and
	// reviewers can see the redaction suite is part of the
	// published security posture.
	redactionSecurityGateRow = "| Redaction tests | `go test -run TestRedaction ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// redactionSecuritySectionHeading is the dedicated
	// `## Redaction Tests` heading SECURITY.md MUST carry. The
	// section explains the structural-transport invariant, the
	// explicit-secret + idempotency invariant, the
	// actionable-failure contract, the opt-in-external escape
	// hatch, and the schema-version contract.
	redactionSecuritySectionHeading = "## Redaction Tests"

	// redactionPRDCommand is the literal command that MUST appear
	// in the PRD's verificationLoop.requiredBackendCommands array
	// so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	redactionPRDCommand = "go test -run TestRedaction ./..."

	// redactionCanonicalFile is the relative path of the canonical
	// reference redaction test file. The
	// `internal/output/redact_test.go` file declares the function
	// pair every other redaction test pivots on; deleting it
	// silently kills the convention future redaction tests must
	// mirror.
	redactionCanonicalFile = "internal/output/redact_test.go"
)

// redactionCanonicalFuncs is the closed set of function declarations
// the canonical `redact_test.go` file MUST carry. The PRD's
// `-run TestRedaction` filter binds to function names containing the
// `TestRedaction` substring; renaming any entry to a name that does
// not match the prefix silently de-gates the redaction suite for any
// caller relying on the filter. The pair captures the two
// load-bearing redaction invariants the `Redactor` MUST keep:
//
//   - TestRedactionContractStructuralPatternsAcrossKnownTransports —
//     the structural net every transport must cross: the canonical
//     sentinel literal `[REDACTED]`, the Authorization /
//     X-API-Key / X-Auth-Token header scrubbing across casing, the
//     `?token=` / `?api_key=` / `?api-key=` / `?access_token=` /
//     `?x-auth-token=` query-parameter scrubbing across positions,
//     the non-secret query-parameter pass-through, and panic-free
//     behaviour on hostile inputs (header lines without a colon,
//     query parameters without a value, URLs with adjacent
//     ampersands, NUL-prefixed strings).
//   - TestRedactionContractExplicitSecretsAndIdempotency — an
//     explicit secret registered via `NewRedactor` is replaced by
//     `Sentinel` everywhere it appears regardless of surrounding
//     characters; sub-threshold / empty / whitespace secrets are
//     dropped on construction; duplicates are de-duplicated;
//     `Redact(Redact(s)) == Redact(s)` across the contract corpus;
//     empty input passes through unchanged; the sentinel literal
//     itself cannot be re-registered as a secret.
var redactionCanonicalFuncs = []string{
	"func TestRedactionContractStructuralPatternsAcrossKnownTransports(",
	"func TestRedactionContractExplicitSecretsAndIdempotency(",
}

// redactionSecuritySectionSubstrings is the closed set of literal
// substrings the `## Redaction Tests` section MUST contain. Each
// captures a different load-bearing fact the BE-0387 acceptance
// criteria require to be visible:
//
//   - "internal/output"              — the package boundary the
//     canonical redactor lives in (AC1 documented suite scope).
//   - "internal/controlplane/variables" — the per-tenant
//     redaction surface the gate also covers (AC1 documented suite
//     scope, AC8 secret-redaction contract).
//   - "internal/cli"                 — the CLI envelope / dry-run
//     redaction surface the gate also covers (AC1 documented suite
//     scope).
//   - "deterministic fixtures"      — the AC2 determinism contract.
//   - "NewRedactor"                  — the constructor that mints
//     the redactor; deleting it would break every redaction test.
//   - "output.Sentinel"              — the shared redaction
//     sentinel; a different substitute would silently lose the
//     stable contract every other redaction story relies on.
//   - "[REDACTED]"                   — the canonical sentinel
//     literal value (AC8 secret-redaction contract).
//   - "request_id"                   — the actionable-failure
//     identifier per-tenant redaction diagnostics surface.
//   - "YALLA_EXTERNAL_DOKPLOY"       — the AC2 opt-in-external
//     escape hatch.
//   - "TestLiveDokploySmoke"         — the opt-in external test
//     name (the PRD's
//     verificationLoop.optionalWhenConfigured names it).
//   - "yalla.output.v1"              — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"               — the AC5 error envelope
//     schema_version contract.
//   - "TestRedactionContractStructuralPatternsAcrossKnownTransports"
//     — the canonical structural-transport function the -run
//     filter binds to.
//   - "TestRedactionContractExplicitSecretsAndIdempotency" — the
//     canonical explicit-secret + idempotency function the -run
//     filter binds to.
//   - "Every push and PR"            — the AC4 CI gating cadence.
//   - "verification_suite_redaction_static_test.go" — the gate is
//     self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var redactionSecuritySectionSubstrings = []string{
	"internal/output",
	"internal/controlplane/variables",
	"internal/cli",
	"deterministic fixtures",
	"NewRedactor",
	"output.Sentinel",
	"[REDACTED]",
	"request_id",
	"YALLA_EXTERNAL_DOKPLOY",
	"TestLiveDokploySmoke",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestRedactionContractStructuralPatternsAcrossKnownTransports",
	"TestRedactionContractExplicitSecretsAndIdempotency",
	"Every push and PR",
	"verification_suite_redaction_static_test.go",
}

// TestVerificationSuiteRedactionCIWorkflow pins the GitHub Actions
// test job to run the canonical redaction command under the
// canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuiteRedactionCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		redactionCIWorkflowStepName,
		redactionCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI redaction step is the defence-in-depth gate for the structural-transport + explicit-secret + idempotency invariants — every push and PR MUST run `go test -run TestRedaction ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteRedactionVerifyShRunsCanonicalCommand pins
// the local commit gate to run `go test -run TestRedaction ./...`
// under its canonical step header so a contributor running the
// gate locally exercises the identical command CI runs.
func TestVerificationSuiteRedactionVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, redactionVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-redaction block is the local mirror of the CI gate and the redaction step must keep its canonical position.",
			requiredVerifyShPath, redactionVerifyShStepHeader)
	}
	if !strings.Contains(doc, redactionVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same redaction command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, redactionVerifyShStepCmd)
	}
}

// TestVerificationSuiteRedactionContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteRedactionContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, redactionContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, redactionContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteRedactionSecurityDocumented pins the public
// security policy. SECURITY.md is the operator- and auditor-facing
// surface that makes the redaction gate part of the published
// security posture, so dropping the row or the section silently
// weakens the posture.
func TestVerificationSuiteRedactionSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, redactionSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, redactionSecurityGateRow)
	}
	if !strings.Contains(doc, redactionSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the structural-transport / explicit-secret / idempotency / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, redactionSecuritySectionHeading)
	}
	for _, want := range redactionSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, redactionSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteRedactionPRDDocumentsCommand pins the PRD's
// verificationLoop.requiredBackendCommands so an AI agent reading
// the PRD before picking up a story sees the canonical redaction
// command without needing to discover it from CI workflows or
// shell scripts.
func TestVerificationSuiteRedactionPRDDocumentsCommand(t *testing.T) {
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
		if cmd == redactionPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the redaction gate as a required backend command.",
		requiredPRDPath, redactionPRDCommand)
}

// TestVerificationSuiteRedactionCanonicalFileExists pins the
// canonical reference redaction test file and its load-bearing
// function pair. Deleting the file or renaming either function to
// a name that does not match the `TestRedaction` prefix silently
// de-gates the redaction suite for any caller relying on the
// PRD's `-run TestRedaction` filter.
func TestVerificationSuiteRedactionCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(redactionCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical redaction test file is the load-bearing convention every other redaction test pivots on; deleting it silently removes the pattern future redaction tests must mirror.",
			redactionCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range redactionCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the redaction pair is the load-bearing assertion set every redaction regression MUST trip — a rename or deletion silently relaxes the structural-transport + explicit-secret + idempotency contract for every downstream caller.",
				redactionCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteRedactionAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteRedactionAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			redactionCIWorkflowStepName,
			redactionCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Redaction tests\n        run: go test -run TestRedaction ./...\n"
		for _, want := range []string{
			redactionCIWorkflowStepName,
			redactionCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, redactionVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", redactionVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 13. Required: redaction tests\nstep \"go test -run TestRedaction ./...\"\nif ! go test -run TestRedaction ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, redactionVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", redactionVerifyShStepHeader)
		}
		if !strings.Contains(doc, redactionVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", redactionVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n"
		if strings.Contains(doc, redactionContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", redactionContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n"
		if !strings.Contains(doc, redactionContributingEntry) {
			t.Fatalf("complete fixture missing %q", redactionContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Redaction Tests\n\n")
		for _, want := range redactionSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range redactionSecuritySectionSubstrings {
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
		b.WriteString("## Redaction Tests\n\n")
		for _, want := range redactionSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range redactionSecuritySectionSubstrings {
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
			if cmd == redactionPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", redactionPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestRedaction ./..."]}}`
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
			if cmd == redactionPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", redactionPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic redact_test.go declaring only one of the two
		// redaction functions. The matcher MUST fire on the
		// missing second.
		doc := "package output\n\nimport \"testing\"\n\nfunc TestRedactionContractStructuralPatternsAcrossKnownTransports(t *testing.T) {}\n"
		missing := 0
		for _, want := range redactionCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every redaction-pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package output\n\nimport \"testing\"\n\nfunc TestRedactionContractStructuralPatternsAcrossKnownTransports(t *testing.T) {}\nfunc TestRedactionContractExplicitSecretsAndIdempotency(t *testing.T) {}\n"
		for _, want := range redactionCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestRedaction prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestRedaction ./...` filter
		// binds to function names containing the `TestRedaction`
		// substring. A canonical-funcs entry that drops the prefix
		// would silently de-gate the redaction suite for any
		// caller relying on the filter. This subtest asserts every
		// canonical-funcs entry begins with `func TestRedaction`.
		const wantPrefix = "func TestRedaction"
		for _, want := range redactionCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestRedaction` filter binds to the `TestRedaction` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
