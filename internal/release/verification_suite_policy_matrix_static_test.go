package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — policy matrix tests (BE-0383).
//
// Threat model: the contract between Yalla's RBAC + grants engine
// (`internal/controlplane/policy`) and every caller (customer, AI
// agent, CI pipeline, downstream SDK, future frontend) is "for every
// built-in role and every catalogued action, the verdict is
// deterministically derived from the role/capability matrix, the
// action catalog, and the tenant scope of the resource — including
// the cross-tenant invariant that no role except support reads can
// see another organization's data." A silent erosion of that
// contract — the dedicated CI step quietly dropped, the verify.sh
// entry renumbered without updating CONTRIBUTING.md, the SECURITY.md
// section deleted, the canonical `policy_test.go` file removed, or
// the matrix function pair renamed — would silently flatten the
// matrix to a single happy-path row and let a role/action drift
// leak data across tenants without firing any gate.
//
// This file is the load-bearing static defence for that
// meta-contract. It pins SIX surfaces in one file so a future
// contributor changing the CI step name, the verify.sh step header,
// the CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical matrix
// test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Policy matrix tests` that invokes
//     `go test -run TestPolicyMatrix ./...`. Even though
//     `go test ./...` covers the same packages, the dedicated step
//     is defence-in-depth: a future narrowing of the umbrella step
//     (e.g. `go test ./internal/...` minus policy) would still
//     leave this gate green, surfacing the regression as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestPolicyMatrix ./...` under the canonical
//     step header `# 9. Required: policy matrix tests`. The numeric
//     prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `9. \`go test -run TestPolicyMatrix ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix
//     keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379's `4. go test ./...`, BE-0380's
//     `6. go test ./internal/controlplane/store/...`, BE-0381's
//     `7. go test ./internal/controlplane/httpapi/...`, and
//     BE-0382's `8. go test ./internal/controlplane/openapi/...`
//     pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Policy matrix tests` row, AND a dedicated
//     `## Policy Matrix Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: exhaustive
//     role-action coverage, the cross-tenant invariant, the
//     CapSelf/CapSupport documented exceptions, deterministic
//     in-memory fixtures (no live Postgres, no live Dokploy),
//     opt-in `YALLA_EXTERNAL_DOKPLOY` external smoke, redaction,
//     and the CI-on-every-push-and-PR cadence.
//  5. `ralph/prd.json` — `verificationLoop.requiredBackendCommands`
//     MUST list `go test -run TestPolicyMatrix ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     canonical command without needing to discover it from CI
//     workflows or shell scripts.
//  6. `internal/controlplane/policy/policy_test.go` — the canonical
//     reference matrix test file MUST exist and MUST declare the
//     load-bearing matrix function pair (`TestPolicyMatrix`,
//     `TestPolicyMatrixDeniesCrossTenant`). The PRD's
//     `go test -run TestPolicyMatrix ./...` filter binds to the
//     `TestPolicyMatrix…` prefix; a rename to a function whose
//     name does not match the prefix silently de-gates the matrix
//     suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuitePolicyMatrixAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// policyMatrixCIWorkflowStepName is the exact step name CI uses
	// to invoke the policy matrix suite. A rename forces a
	// deliberate update both here and in the workflow.
	policyMatrixCIWorkflowStepName = "- name: Policy matrix tests"
	// policyMatrixCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestPolicyMatrix…` test.
	policyMatrixCIWorkflowStepRun = "run: go test -run TestPolicyMatrix ./..."

	// policyMatrixVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestPolicyMatrix ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	policyMatrixVerifyShStepHeader = "# 9. Required: policy matrix tests"
	// policyMatrixVerifyShStepCmd is the literal command that MUST
	// appear inside the required-policy-matrix step. Asserting on
	// the literal (not a regex over the file) makes the failure
	// point the operator at the exact line that drifted.
	policyMatrixVerifyShStepCmd = `go test -run TestPolicyMatrix ./...`

	// policyMatrixContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	policyMatrixContributingEntry = "9. `go test -run TestPolicyMatrix ./...`"

	// policyMatrixSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the policy matrix suite is part of the
	// published security posture.
	policyMatrixSecurityGateRow = "| Policy matrix tests | `go test -run TestPolicyMatrix ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// policyMatrixSecuritySectionHeading is the dedicated
	// `## Policy Matrix Tests` heading SECURITY.md MUST carry. The
	// section explains the exhaustive role-action coverage, the
	// cross-tenant invariant, the CapSelf/CapSupport exceptions,
	// the determinism contract, the actionable-failure contract,
	// the opt-in-external escape hatch, and the redaction posture.
	policyMatrixSecuritySectionHeading = "## Policy Matrix Tests"

	// policyMatrixPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract
	// document, not from shell scripts or CI workflows.
	policyMatrixPRDCommand = "go test -run TestPolicyMatrix ./..."

	// policyMatrixCanonicalFile is the relative path of the
	// canonical reference matrix test file. The
	// `internal/controlplane/policy/policy_test.go` file declares
	// the matrix function pair every other policy decision test
	// pivots on; deleting it silently kills the convention future
	// matrix tests must mirror.
	policyMatrixCanonicalFile = "internal/controlplane/policy/policy_test.go"
)

// policyMatrixCanonicalFuncs is the closed set of function
// declarations the canonical `policy_test.go` file MUST carry. The
// PRD's `-run TestPolicyMatrix` filter binds to function names
// containing the `TestPolicyMatrix` substring; renaming any entry
// to a name that does not match the prefix silently de-gates the
// matrix suite for any caller relying on the filter. The pair
// captures the two load-bearing matrix invariants the engine MUST
// keep:
//
//   - TestPolicyMatrix — every built-in role × every catalogued
//     action on an in-organization resource resolves to the
//     verdict derived from the role/capability matrix and the
//     action catalog (ReasonAllowedSelf for CapSelf,
//     ReasonAllowedByRole when the role's capability set covers
//     the required cap, ReasonDeniedNoCapability otherwise).
//   - TestPolicyMatrixDeniesCrossTenant — every built-in role ×
//     every catalogued action on a *foreign* tenant's resource
//     resolves to ReasonAllowedSelf (CapSelf shortcut),
//     ReasonAllowedBySupport (support's CapSupport bridging
//     CapRead/CapSupport only), or ReasonDeniedCrossTenant
//     (everything else) — the engine's cross-tenant invariant
//     against silent cross-org data leaks.
var policyMatrixCanonicalFuncs = []string{
	"func TestPolicyMatrix(",
	"func TestPolicyMatrixDeniesCrossTenant(",
}

// policyMatrixSecuritySectionSubstrings is the closed set of
// literal substrings the `## Policy Matrix Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0383
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/policy" — the package boundary the
//     suite owns (AC1 documented suite scope).
//   - "deterministic fixtures"       — the AC2 determinism
//     contract.
//   - "ReasonDeniedCrossTenant"      — the AC3 actionable-failure
//     contract (the failing reason surfaces in every diagnostic
//     so an operator can map the failure to the exact decision
//     branch without re-running the suite).
//   - "CapSelf"                      — the AC6 self-action
//     exception (organization-independent actions MUST stay
//     allowed without tenant gating).
//   - "CapSupport"                   — the AC6 support-bridge
//     exception (the only documented cross-tenant allow path).
//   - "YALLA_EXTERNAL_DOKPLOY"       — the AC7 opt-in-external
//     escape hatch.
//   - "yalla.output.v1"              — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"               — the AC5 error envelope
//     schema_version contract.
//   - "TestPolicyMatrix"             — the canonical matrix
//     function the -run filter binds to.
//   - "TestPolicyMatrixDeniesCrossTenant" — the canonical
//     cross-tenant matrix function that pins the no-cross-org
//     -leak invariant.
//   - "redacted"                     — the AC8 secret-redaction
//     contract.
//   - "Every push and PR"            — the AC4 CI gating cadence.
//   - "verification_suite_policy_matrix_static_test.go"
//     — the gate is self-locating so a future operator can find
//     it without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var policyMatrixSecuritySectionSubstrings = []string{
	"internal/controlplane/policy",
	"deterministic fixtures",
	"ReasonDeniedCrossTenant",
	"CapSelf",
	"CapSupport",
	"YALLA_EXTERNAL_DOKPLOY",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestPolicyMatrix",
	"TestPolicyMatrixDeniesCrossTenant",
	"redacted",
	"Every push and PR",
	"verification_suite_policy_matrix_static_test.go",
}

// TestVerificationSuitePolicyMatrixCIWorkflow pins the GitHub
// Actions test job to run the canonical policy matrix command under
// the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuitePolicyMatrixCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		policyMatrixCIWorkflowStepName,
		policyMatrixCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI policy-matrix step is the defence-in-depth gate for the RBAC + cross-tenant invariant — every push and PR MUST run `go test -run TestPolicyMatrix ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuitePolicyMatrixVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestPolicyMatrix ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuitePolicyMatrixVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, policyMatrixVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-policy-matrix block is the local mirror of the CI gate and the policy-matrix step must keep its canonical position.",
			requiredVerifyShPath, policyMatrixVerifyShStepHeader)
	}
	if !strings.Contains(doc, policyMatrixVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same policy-matrix command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, policyMatrixVerifyShStepCmd)
	}
}

// TestVerificationSuitePolicyMatrixContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuitePolicyMatrixContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, policyMatrixContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, policyMatrixContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuitePolicyMatrixSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the policy-matrix gate part of
// the published security posture, so dropping the row or the
// section silently weakens the posture.
func TestVerificationSuitePolicyMatrixSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, policyMatrixSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, policyMatrixSecurityGateRow)
	}
	if !strings.Contains(doc, policyMatrixSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the exhaustive-coverage / cross-tenant-invariant / determinism / actionable-failure / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, policyMatrixSecuritySectionHeading)
	}
	for _, want := range policyMatrixSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, policyMatrixSecuritySectionHeading)
		}
	}
}

// TestVerificationSuitePolicyMatrixPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// policy-matrix command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuitePolicyMatrixPRDDocumentsCommand(t *testing.T) {
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
		if cmd == policyMatrixPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the policy-matrix gate as a required backend command.",
		requiredPRDPath, policyMatrixPRDCommand)
}

// TestVerificationSuitePolicyMatrixCanonicalFileExists pins the
// canonical reference matrix test file and its load-bearing matrix
// function pair. Deleting the file or renaming either function to a
// name that does not match the `TestPolicyMatrix` prefix silently
// de-gates the matrix suite for any caller relying on the PRD's
// `-run TestPolicyMatrix` filter.
func TestVerificationSuitePolicyMatrixCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(policyMatrixCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical matrix test file is the load-bearing convention every other policy decision test pivots on; deleting it silently removes the pattern future matrix tests must mirror.",
			policyMatrixCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range policyMatrixCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the matrix pair is the load-bearing assertion set every built-in role × every catalogued action MUST satisfy — a rename or deletion silently relaxes the RBAC + cross-tenant contract for every downstream caller.",
				policyMatrixCanonicalFile, want)
		}
	}
}

// TestVerificationSuitePolicyMatrixAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher
// fires (or stays silent) correctly. Without this self-check a
// future "improvement" to the matchers (a tightened regex, a
// relaxed substring set, a renamed constant) could silently let
// real regressions slip through.
func TestVerificationSuitePolicyMatrixAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			policyMatrixCIWorkflowStepName,
			policyMatrixCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Policy matrix tests\n        run: go test -run TestPolicyMatrix ./...\n"
		for _, want := range []string{
			policyMatrixCIWorkflowStepName,
			policyMatrixCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, policyMatrixVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", policyMatrixVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 9. Required: policy matrix tests\nstep \"go test -run TestPolicyMatrix ./...\"\nif ! go test -run TestPolicyMatrix ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, policyMatrixVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", policyMatrixVerifyShStepHeader)
		}
		if !strings.Contains(doc, policyMatrixVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", policyMatrixVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n"
		if strings.Contains(doc, policyMatrixContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", policyMatrixContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n"
		if !strings.Contains(doc, policyMatrixContributingEntry) {
			t.Fatalf("complete fixture missing %q", policyMatrixContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece while
		// still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Policy Matrix Tests\n\n")
		for _, want := range policyMatrixSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range policyMatrixSecuritySectionSubstrings {
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
		b.WriteString("## Policy Matrix Tests\n\n")
		for _, want := range policyMatrixSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range policyMatrixSecuritySectionSubstrings {
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
			if cmd == policyMatrixPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", policyMatrixPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestPolicyMatrix ./..."]}}`
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
			if cmd == policyMatrixPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", policyMatrixPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic policy_test.go declaring only one of the two
		// matrix functions. The matcher MUST fire on the missing
		// second.
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestPolicyMatrix(t *testing.T) {}\n"
		missing := 0
		for _, want := range policyMatrixCanonicalFuncs {
			if !strings.Contains(doc, want) {
				missing++
			}
		}
		if missing == 0 {
			t.Fatalf("synthetic fixture unexpectedly contains every matrix-pair member — the matcher would false-negative here")
		}
	})

	t.Run("canonical-funcs matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestPolicyMatrix(t *testing.T) {}\nfunc TestPolicyMatrixDeniesCrossTenant(t *testing.T) {}\n"
		for _, want := range policyMatrixCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestPolicyMatrix prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestPolicyMatrix ./...` filter
		// binds to function names containing the `TestPolicyMatrix`
		// substring. A canonical-funcs entry that drops the prefix
		// would silently de-gate the matrix suite for any caller
		// relying on the filter. This subtest asserts every
		// canonical-funcs entry begins with `func TestPolicyMatrix`.
		const wantPrefix = "func TestPolicyMatrix"
		for _, want := range policyMatrixCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestPolicyMatrix` filter binds to the `TestPolicyMatrix` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
