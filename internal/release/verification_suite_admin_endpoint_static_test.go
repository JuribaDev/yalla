package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — admin endpoint tests (BE-0403).
//
// Threat model: every /v1/admin/* HTTP route in the control-plane
// API binary (`cmd/yalla-api`) ships behind a single role: only the
// Yalla-internal Support principal can reach it. The admin actions
// (admin.read, admin.import, admin.reconcile, admin.break_glass)
// authorise cross-tenant inspection, mutating reconciliation,
// importing pre-existing Dokploy resources into Yalla, and opening
// elevated cross-tenant access sessions — capabilities that exist
// for Yalla operations alone. A silent regression that demoted any
// admin action to CapRead, CapAdmin, or CapOwner, that added
// CapSupport to a non-Support built-in role, that pinned a deeper-
// than-org leg on an admin endpoint's resource scope, or that
// silently dropped the cross-tenant Support exception (CapSupport
// OR CapRead) would let an Owner or Admin enumerate the tenant's
// Yalla<->Dokploy mapping graph, terminate another tenant's break-
// glass session, or import a Dokploy resource that did not belong to
// the caller. The canonical pair
// (`TestAdminEndpointCoversCallSites`,
//  `TestAdminEndpointPreservesContractUnderContention`) lives in
// `internal/controlplane/policy/admin_endpoint_policy_test.go` and
// binds to the PRD's `-run TestAdminEndpoint` filter. The pair
// members are deterministic by design — both walk a closed scenario
// table built from the cartesian product of every admin endpoint ×
// every ActionAdmin* constant × every built-in role × every grant-
// scope position × the same-tenant / cross-tenant axes, and the
// engine's `Decide` is a pure function from (principal, action,
// resource) to a Decision value. Neither member reaches the process
// environment, the network, a live Postgres, a live Dokploy, or any
// external service.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `admin_endpoint_policy_test.go` file removed, or the canonical
// `TestAdminEndpoint…` function pair renamed — would let an engine
// drift or a new admin endpoint ship without firing any gate. This
// file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical admin-endpoint test fixture
// fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Admin endpoint tests` that invokes
//     `go test -run TestAdminEndpoint ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestAdminEndpoint ./...` under the canonical
//     step header `# 27. Required: admin endpoint tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #27
//     extends the BE-0379..BE-0402 sequence by one and pushes
//     BE-0400's optional `# 31. Optional: external live-Dokploy
//     smoke tests` block down by one in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry an
//     entry `27. \`go test -run TestAdminEndpoint ./...\`` so a
//     contributor preparing a PR sees the gate before running
//     scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table MUST
//     carry a row for the admin-endpoint suite, AND a dedicated
//     `## Admin Endpoint Tests` section MUST explain the closed-
//     set coverage invariant (every admin endpoint × every admin
//     action × every built-in role × every grant scope), the
//     resource-rooting invariant (every admin endpoint is org-
//     rooted), the cross-tenant-support invariant (Support holds
//     CapSupport, the engine admits CapSupport OR CapRead in the
//     cross-tenant exception), the role-allow-set invariant (only
//     RoleSupport holds CapSupport), the deterministic-by-default
//     behaviour, the actionable-failure contract, the schema-
//     version contract, and the redaction contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestAdminEndpoint ./...` so an AI agent reading
//     the PRD before picking up a story sees the gate without
//     needing to discover it from CI workflows or shell scripts.
//  6. `internal/controlplane/policy/admin_endpoint_policy_test.go`
//     — the canonical reference admin-endpoint test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestAdminEndpointCoversCallSites`,
//      `TestAdminEndpointPreservesContractUnderContention`). The
//     PRD's `go test -run TestAdminEndpoint ./...` filter binds to
//     the `TestAdminEndpoint` prefix; a rename to a function whose
//     name does not match the prefix silently de-gates the admin-
//     endpoint suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteAdminEndpointAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// adminEndpointCIWorkflowStepName is the exact step name CI uses
	// to invoke the admin-endpoint suite. A rename forces a deliberate
	// update both here and in the workflow.
	adminEndpointCIWorkflowStepName = "- name: Admin endpoint tests"
	// adminEndpointCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestAdminEndpoint…` test.
	adminEndpointCIWorkflowStepRun = "run: go test -run TestAdminEndpoint ./..."

	// adminEndpointVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestAdminEndpoint ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	adminEndpointVerifyShStepHeader = "# 27. Required: admin endpoint tests"
	// adminEndpointVerifyShStepCmd is the literal command that MUST
	// appear inside the required-admin-endpoint step. Asserting on the
	// literal (not a regex over the file) makes the failure point the
	// operator at the exact line that drifted.
	adminEndpointVerifyShStepCmd = `go test -run TestAdminEndpoint ./...`

	// adminEndpointContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	adminEndpointContributingEntry = "27. `go test -run TestAdminEndpoint ./...`"

	// adminEndpointSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the admin-endpoint suite is part of the published
	// security posture.
	adminEndpointSecurityGateRow = "| Admin endpoint tests | `go test -run TestAdminEndpoint ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// adminEndpointSecuritySectionHeading is the dedicated
	// `## Admin Endpoint Tests` heading SECURITY.md MUST carry. The
	// section explains the closed-set coverage invariant, the
	// resource-rooting invariant, the cross-tenant-support invariant,
	// the role-allow-set invariant, the deterministic-by-default
	// behaviour, the actionable-failure contract, the schema-version
	// contract, and the redaction contract.
	adminEndpointSecuritySectionHeading = "## Admin Endpoint Tests"

	// adminEndpointPRDCommand is the literal command that MUST appear
	// in the PRD's verificationLoop.requiredBackendCommands array so
	// an agent surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	adminEndpointPRDCommand = "go test -run TestAdminEndpoint ./..."

	// adminEndpointCanonicalFile is the relative path of the canonical
	// reference admin-endpoint test file. The
	// `internal/controlplane/policy/admin_endpoint_policy_test.go`
	// file declares the function pair every admin-endpoint regression
	// MUST trip; deleting it silently kills the convention.
	adminEndpointCanonicalFile = "internal/controlplane/policy/admin_endpoint_policy_test.go"
)

// adminEndpointCanonicalFuncs is the closed set of function
// declarations the canonical `admin_endpoint_policy_test.go` file
// MUST carry. The PRD's `-run TestAdminEndpoint` filter binds to
// function names containing the `TestAdminEndpoint` substring;
// renaming any entry to a name that does not match the prefix
// silently de-gates the admin-endpoint suite for any caller relying
// on the filter.
var adminEndpointCanonicalFuncs = []string{
	"func TestAdminEndpointCoversCallSites(t *testing.T)",
	"func TestAdminEndpointPreservesContractUnderContention(t *testing.T)",
}

// adminEndpointSecuritySectionSubstrings is the closed set of
// substrings the dedicated `## Admin Endpoint Tests` section in
// SECURITY.md MUST contain. The substrings name every load-bearing
// fact the operator- and auditor-facing documentation MUST surface
// so a future contributor changing the gate's contract is forced
// to update the public security posture in the same edit.
var adminEndpointSecuritySectionSubstrings = []string{
	"TestAdminEndpoint",
	"admin.read",
	"admin.import",
	"admin.reconcile",
	"admin.break_glass",
	"CapSupport",
	"RoleSupport",
	"org-rooted",
	"cross-tenant",
	"closed-set",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379). Reusing
// them here keeps the path / helper layer single-sourced so a
// repository-wide rename only touches that file.

// TestVerificationSuiteAdminEndpointCIWorkflowDeclaresStep pins the
// CI workflow to a dedicated step that invokes
// `go test -run TestAdminEndpoint ./...`. Even though the umbrella
// `go test ./...` step exercises the same package, the dedicated
// step is defence-in-depth: a future narrowing of the umbrella step
// would still leave this gate firing as a fast targeted failure
// rather than buried inside the umbrella log.
func TestVerificationSuiteAdminEndpointCIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		adminEndpointCIWorkflowStepName,
		adminEndpointCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI admin-endpoint step is the defence-in-depth gate for the closed-set coverage + cross-tenant-support + role-allow-set invariants — every push and PR MUST run `go test -run TestAdminEndpoint ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteAdminEndpointVerifyShRunsCanonicalCommand pins
// the local commit gate to run `go test -run TestAdminEndpoint ./...`
// under its canonical step header so a contributor running the gate
// locally exercises the identical command CI runs.
func TestVerificationSuiteAdminEndpointVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, adminEndpointVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-admin-endpoint block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, adminEndpointVerifyShStepHeader)
	}
	if !strings.Contains(doc, adminEndpointVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same admin-endpoint command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, adminEndpointVerifyShStepCmd)
	}
}

// TestVerificationSuiteAdminEndpointContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a contributor
// opens a PR. The numeric prefix matches the verify.sh step number to
// keep the two surfaces in lockstep.
func TestVerificationSuiteAdminEndpointContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, adminEndpointContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, adminEndpointContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteAdminEndpointSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the admin-endpoint gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteAdminEndpointSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, adminEndpointSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, adminEndpointSecurityGateRow)
	}
	if !strings.Contains(doc, adminEndpointSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / resource-rooting / cross-tenant-support / role-allow-set / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, adminEndpointSecuritySectionHeading)
	}
	for _, want := range adminEndpointSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, adminEndpointSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteAdminEndpointPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// admin-endpoint command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteAdminEndpointPRDDocumentsCommand(t *testing.T) {
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
		if cmd == adminEndpointPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the admin-endpoint gate as a required backend command.",
		requiredPRDPath, adminEndpointPRDCommand)
}

// TestVerificationSuiteAdminEndpointCanonicalFileExists pins the
// canonical reference admin-endpoint test file and its load-bearing
// function pair. Deleting the file or renaming either function to a
// name that does not match the `TestAdminEndpoint` prefix silently
// de-gates the admin-endpoint suite for any caller relying on the
// PRD's `-run TestAdminEndpoint` filter.
func TestVerificationSuiteAdminEndpointCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(adminEndpointCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical admin-endpoint test file is the load-bearing convention every admin-endpoint regression MUST trip; deleting it silently removes the admin-endpoint gate.",
			adminEndpointCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range adminEndpointCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the admin-endpoint pair is the load-bearing assertion set every admin-endpoint regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				adminEndpointCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteAdminEndpointAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher
// fires (or stays silent) correctly. Without this self-check a
// future "improvement" to the matchers (a tightened regex, a
// relaxed substring set, a renamed constant) could silently let
// real regressions slip through.
func TestVerificationSuiteAdminEndpointAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			adminEndpointCIWorkflowStepName,
			adminEndpointCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Admin endpoint tests\n        run: go test -run TestAdminEndpoint ./...\n"
		for _, want := range []string{
			adminEndpointCIWorkflowStepName,
			adminEndpointCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, adminEndpointVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", adminEndpointVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 27. Required: admin endpoint tests\nstep \"go test -run TestAdminEndpoint ./...\"\nif ! go test -run TestAdminEndpoint ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, adminEndpointVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", adminEndpointVerifyShStepHeader)
		}
		if !strings.Contains(doc, adminEndpointVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", adminEndpointVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n26. `go test -run TestConfigValidation ./...`\n"
		if strings.Contains(doc, adminEndpointContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", adminEndpointContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n26. `go test -run TestConfigValidation ./...`\n27. `go test -run TestAdminEndpoint ./...`\n"
		if !strings.Contains(doc, adminEndpointContributingEntry) {
			t.Fatalf("complete fixture missing %q", adminEndpointContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Admin Endpoint Tests\n\n")
		for _, want := range adminEndpointSecuritySectionSubstrings {
			if want == "CapSupport" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range adminEndpointSecuritySectionSubstrings {
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
		b.WriteString("## Admin Endpoint Tests\n\n")
		for _, want := range adminEndpointSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range adminEndpointSecuritySectionSubstrings {
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
			if cmd == adminEndpointPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", adminEndpointPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestAdminEndpoint ./..."]}}`
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
			if cmd == adminEndpointPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", adminEndpointPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestAdminEndpointCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range adminEndpointCanonicalFuncs {
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
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestAdminEndpointCoversCallSites(t *testing.T) {}\nfunc TestAdminEndpointPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range adminEndpointCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestAdminEndpoint prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestAdminEndpoint"
		for _, want := range adminEndpointCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestAdminEndpoint` filter binds to the `TestAdminEndpoint` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
