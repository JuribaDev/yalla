package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — tenant isolation tests (BE-0398).
//
// Threat model: every authenticated Yalla Control Plane endpoint flows
// through policy.Engine.Decide / Authorize. The engine's documented
// cross-tenant ordering is the chokepoint that prevents a principal in
// orgA from reading, mutating, or even probing the existence of a
// resource in orgB. The contract operators, AI agents, audit reviewers,
// and CI runners rely on is the closed set of verdicts the engine MUST
// return on a cross-tenant resource: (1) a missing principal short-
// circuits with ReasonDeniedNoPrincipal BEFORE the cross-tenant check;
// (2) a disabled principal short-circuits with
// ReasonDeniedPrincipalDisabled BEFORE the cross-tenant check; (3) an
// uncatalogued action short-circuits with ReasonDeniedUnknownAction
// BEFORE the cross-tenant check; (4) CapSelf actions are organization-
// independent and surface ReasonAllowedSelf even on a cross-tenant
// resource (the engine deliberately exposes self-identity actions
// before applying the tenant boundary); (5) the support role's
// CapSupport bridges the tenant boundary for CapRead and CapSupport
// actions only and surfaces ReasonAllowedBySupport; (6) every other
// (role, action) pair on a cross-tenant resource surfaces
// ReasonDeniedCrossTenant; (7) a scoped Grant whose Scope.OrganizationID
// is the cross tenant is silently ignored by the engine — grants
// NEVER bridge tenants. That invariant is enforced by the canonical
// pair `TestTenantIsolationCoversCallSites` (closed-set scenario
// coverage) and `TestTenantIsolationPreservesScopeUnderContention`
// (per-decision stability under concurrent contention) in
// `internal/controlplane/policy/tenant_isolation_test.go`. Both pair
// members are deterministic by design — they construct an in-process
// `policy.Engine` via `NewEngine()` from the package's default action
// catalog, build principals and resources from constant tenant ids
// (`orgA`, `orgB`), and never reach a live Postgres, a live Dokploy, or
// any external network.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `tenant_isolation_test.go` file removed, or the canonical
// `TestTenantIsolation…` function pair renamed — would let a
// tenant-isolation regression (a role drift that quietly allowed
// RoleAdmin to read another tenant's project; a re-ordering of
// Engine.Decide's short-circuits that let a cross-tenant resource
// bypass the disabled-principal check; a scoped Grant that silently
// bridged tenants because the engine forgot to compare
// Grant.Scope.OrganizationID against Principal.OrganizationID; a
// custom-role hook regression that minted CapWrite across tenants)
// ship without firing any gate. An agent acting in orgA would silently
// read or mutate orgB's resources; an audit reviewer would never see
// the violation because the policy engine never recorded a denial.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical tenant-isolation test fixture
// fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Tenant isolation tests` that invokes
//     `go test -run TestTenantIsolation ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestTenantIsolation ./...` under the canonical
//     step header
//     `# 23. Required: tenant isolation tests`. The numeric prefix is
//     part of the contract: a reorder must be a deliberate edit to
//     both this constant and the script. #23 extends the
//     BE-0379..BE-0397 sequence by one slot; the trailing optionals
//     (#24 govulncheck, #25 staticcheck, #26 golangci-lint, #27
//     goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `23. \`go test -run TestTenantIsolation ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix keeps
//     verify.sh and CONTRIBUTING.md in lockstep with BE-0379..BE-0397's
//     pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Tenant isolation tests` row, AND a dedicated
//     `## Tenant Isolation Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     coverage invariant (every built-in role × every catalogued
//     action × cross-tenant resource), the short-circuit ordering
//     (no-principal / disabled / unknown-action precede the
//     cross-tenant check), the grants-never-bridge-tenants rule, the
//     deterministic-by-default behaviour (in-process policy.Engine
//     constructed via NewEngine(), no live Postgres, no live Dokploy),
//     the CI-on-every-push-and-PR cadence, the schema-version contract
//     (`yalla.output.v1` / `yalla.error.v1`), and the redaction
//     contract (the wire error message never carries a principal id,
//     a resource id, or a cross-tenant organization id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestTenantIsolation ./...` so an AI agent reading
//     the PRD before picking up a story sees the canonical command
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/controlplane/policy/tenant_isolation_test.go` — the
//     canonical reference tenant-isolation test file MUST exist and
//     MUST declare the load-bearing function pair
//     (`TestTenantIsolationCoversCallSites`,
//     `TestTenantIsolationPreservesScopeUnderContention`). The PRD's
//     `go test -run TestTenantIsolation ./...` filter binds to the
//     `TestTenantIsolation` prefix; a rename to a function whose name
//     does not match the prefix silently de-gates the tenant-isolation
//     suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteTenantIsolationAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// tenantIsolationCIWorkflowStepName is the exact step name CI
	// uses to invoke the tenant-isolation suite. A rename forces a
	// deliberate update both here and in the workflow.
	tenantIsolationCIWorkflowStepName = "- name: Tenant isolation tests"
	// tenantIsolationCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestTenantIsolation…` test.
	tenantIsolationCIWorkflowStepRun = "run: go test -run TestTenantIsolation ./..."

	// tenantIsolationVerifyShStepHeader is the canonical comment
	// header that precedes the
	// `go test -run TestTenantIsolation ./...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and
	// the script.
	tenantIsolationVerifyShStepHeader = "# 23. Required: tenant isolation tests"
	// tenantIsolationVerifyShStepCmd is the literal command that
	// MUST appear inside the required-tenant-isolation step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	tenantIsolationVerifyShStepCmd = `go test -run TestTenantIsolation ./...`

	// tenantIsolationContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	tenantIsolationContributingEntry = "23. `go test -run TestTenantIsolation ./...`"

	// tenantIsolationSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the tenant-isolation suite is part of the
	// published security posture.
	tenantIsolationSecurityGateRow = "| Tenant isolation tests | `go test -run TestTenantIsolation ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// tenantIsolationSecuritySectionHeading is the dedicated
	// `## Tenant Isolation Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set cross-tenant coverage
	// invariant, the short-circuit ordering, the grants-never-bridge-
	// tenants rule, the deterministic-by-default behaviour, the
	// actionable-failure contract, the schema-version contract, and
	// the redaction contract.
	tenantIsolationSecuritySectionHeading = "## Tenant Isolation Tests"

	// tenantIsolationPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	tenantIsolationPRDCommand = "go test -run TestTenantIsolation ./..."

	// tenantIsolationCanonicalFile is the relative path of the
	// canonical reference tenant-isolation test file. The
	// `internal/controlplane/policy/tenant_isolation_test.go` file
	// declares the function pair every tenant-isolation regression
	// MUST trip; deleting it silently kills the convention.
	tenantIsolationCanonicalFile = "internal/controlplane/policy/tenant_isolation_test.go"
)

// tenantIsolationCanonicalFuncs is the closed set of function
// declarations the canonical `tenant_isolation_test.go` file MUST
// carry. The PRD's `-run TestTenantIsolation` filter binds to function
// names containing the `TestTenantIsolation` substring; renaming any
// entry to a name that does not match the prefix silently de-gates the
// tenant-isolation suite for any caller relying on the filter. The
// pair captures the two load-bearing tenant-isolation invariants the
// harness MUST keep:
//
//   - TestTenantIsolationCoversCallSites — the closed-set tenant-
//     isolation coverage invariant: for every built-in role × every
//     catalogued action × a cross-tenant resource the test asserts
//     the engine's verdict matches the documented cross-tenant
//     ordering (CapSelf -> allow-self, support+read/support ->
//     allow-by-support, everything else -> denied-cross-tenant); plus
//     the three short-circuit ordering cases (no-principal, disabled,
//     unknown-action) AND the grants-never-bridge-tenants rule. Trips
//     at the package-internal API with no infrastructure dependency.
//   - TestTenantIsolationPreservesScopeUnderContention — the per-
//     decision stability invariant under contention: firing
//     `tenantIsolationWorkers * tenantIsolationIterationsPerWorker`
//     goroutines against a single shared `policy.Engine` with tuples
//     drawn from the same coverage table MUST yield, for every
//     goroutine, the verdict the closed-set scenario for its OWN
//     tuple predicts — a cross-write that swapped two goroutines'
//     principals or resources under the race would fail the
//     per-iteration assertion even when the aggregate verdict counts
//     matched.
var tenantIsolationCanonicalFuncs = []string{
	"func TestTenantIsolationCoversCallSites(",
	"func TestTenantIsolationPreservesScopeUnderContention(",
}

// tenantIsolationSecuritySectionSubstrings is the closed set of
// literal substrings the `## Tenant Isolation Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0398
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/policy" — the package boundary the
//     canonical tenant-isolation harness lives in (AC1 documented
//     suite scope).
//   - "tenant_isolation_test.go" — the canonical reference test file
//     name; deleting it would break the function pair the gate pivots
//     on.
//   - "deterministic"             — the AC2 determinism contract;
//     both pair members run with an in-process `policy.Engine` and
//     no other infrastructure dependency.
//   - "policy.Engine"             — the single chokepoint the gate
//     pivots on; an alternative authorization path would bypass the
//     gate.
//   - "NewEngine"                 — the deterministic constructor
//     binding the test to the default action catalog.
//   - "ReasonDeniedCrossTenant"   — the AC stable-code anchor for the
//     cross-tenant verdict.
//   - "ReasonAllowedBySupport"    — the AC stable-code anchor for the
//     support-role bridge.
//   - "ReasonAllowedSelf"         — the AC stable-code anchor for the
//     organization-independent CapSelf allow.
//   - "ReasonDeniedNoPrincipal"   — the AC short-circuit anchor for
//     the no-principal case.
//   - "ReasonDeniedPrincipalDisabled" — the AC short-circuit anchor
//     for the disabled-principal case.
//   - "ReasonDeniedUnknownAction" — the AC short-circuit anchor for
//     the uncatalogued-action case.
//   - "request_id"                — the AC3 actionable-failure
//     identifier (every authorization-denied envelope carries the
//     originating request_id).
//   - "yalla.output.v1"           — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"            — the AC5 error envelope
//     schema_version contract.
//   - "tenant isolation"          — the cross-tenant-leak prohibition
//     this entire suite enforces.
//   - "TestTenantIsolationCoversCallSites" — the canonical closed-
//     set coverage function the -run filter binds to.
//   - "TestTenantIsolationPreservesScopeUnderContention" — the
//     canonical contention burst function the -run filter binds to.
//   - "Every push and PR"         — the AC4 CI gating cadence.
//   - "redacted"                  — the AC8 redaction contract; the
//     wire error message never carries a principal or resource id.
//   - "verification_suite_tenant_isolation_static_test.go" — the gate
//     is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var tenantIsolationSecuritySectionSubstrings = []string{
	"internal/controlplane/policy",
	"tenant_isolation_test.go",
	"deterministic",
	"policy.Engine",
	"NewEngine",
	"ReasonDeniedCrossTenant",
	"ReasonAllowedBySupport",
	"ReasonAllowedSelf",
	"ReasonDeniedNoPrincipal",
	"ReasonDeniedPrincipalDisabled",
	"ReasonDeniedUnknownAction",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"tenant isolation",
	"TestTenantIsolationCoversCallSites",
	"TestTenantIsolationPreservesScopeUnderContention",
	"Every push and PR",
	"redacted",
	"verification_suite_tenant_isolation_static_test.go",
}

// TestVerificationSuiteTenantIsolationCIWorkflow pins the GitHub
// Actions test job to run the canonical tenant-isolation command
// under the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth promise
// that even a regression in the umbrella `go test ./...` step would
// still leave this gate firing.
func TestVerificationSuiteTenantIsolationCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		tenantIsolationCIWorkflowStepName,
		tenantIsolationCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI tenant-isolation step is the defence-in-depth gate for the closed-set cross-tenant coverage + per-decision stability invariants — every push and PR MUST run `go test -run TestTenantIsolation ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteTenantIsolationVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestTenantIsolation ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteTenantIsolationVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, tenantIsolationVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-tenant-isolation block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, tenantIsolationVerifyShStepHeader)
	}
	if !strings.Contains(doc, tenantIsolationVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same tenant-isolation command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, tenantIsolationVerifyShStepCmd)
	}
}

// TestVerificationSuiteTenantIsolationContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteTenantIsolationContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, tenantIsolationContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, tenantIsolationContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteTenantIsolationSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the tenant-isolation gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteTenantIsolationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, tenantIsolationSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, tenantIsolationSecurityGateRow)
	}
	if !strings.Contains(doc, tenantIsolationSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / short-circuit-ordering / grants-never-bridge-tenants / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, tenantIsolationSecuritySectionHeading)
	}
	for _, want := range tenantIsolationSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, tenantIsolationSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteTenantIsolationPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// tenant-isolation command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteTenantIsolationPRDDocumentsCommand(t *testing.T) {
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
		if cmd == tenantIsolationPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the tenant-isolation gate as a required backend command.",
		requiredPRDPath, tenantIsolationPRDCommand)
}

// TestVerificationSuiteTenantIsolationCanonicalFileExists pins the
// canonical reference tenant-isolation test file and its load-bearing
// function pair. Deleting the file or renaming either function to a
// name that does not match the `TestTenantIsolation` prefix silently
// de-gates the tenant-isolation suite for any caller relying on the
// PRD's `-run TestTenantIsolation` filter.
func TestVerificationSuiteTenantIsolationCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(tenantIsolationCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical tenant-isolation test file is the load-bearing convention every tenant-isolation regression MUST trip; deleting it silently removes the tenant-isolation gate.",
			tenantIsolationCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range tenantIsolationCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the tenant-isolation pair is the load-bearing assertion set every tenant-isolation regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				tenantIsolationCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteTenantIsolationAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteTenantIsolationAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			tenantIsolationCIWorkflowStepName,
			tenantIsolationCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Tenant isolation tests\n        run: go test -run TestTenantIsolation ./...\n"
		for _, want := range []string{
			tenantIsolationCIWorkflowStepName,
			tenantIsolationCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, tenantIsolationVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", tenantIsolationVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 23. Required: tenant isolation tests\nstep \"go test -run TestTenantIsolation ./...\"\nif ! go test -run TestTenantIsolation ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, tenantIsolationVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", tenantIsolationVerifyShStepHeader)
		}
		if !strings.Contains(doc, tenantIsolationVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", tenantIsolationVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n22. `go test -run TestPaginationStability ./...`\n"
		if strings.Contains(doc, tenantIsolationContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", tenantIsolationContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n22. `go test -run TestPaginationStability ./...`\n23. `go test -run TestTenantIsolation ./...`\n"
		if !strings.Contains(doc, tenantIsolationContributingEntry) {
			t.Fatalf("complete fixture missing %q", tenantIsolationContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Tenant Isolation Tests\n\n")
		for _, want := range tenantIsolationSecuritySectionSubstrings {
			if want == "ReasonDeniedCrossTenant" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range tenantIsolationSecuritySectionSubstrings {
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
		b.WriteString("## Tenant Isolation Tests\n\n")
		for _, want := range tenantIsolationSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range tenantIsolationSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
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
			if cmd == tenantIsolationPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", tenantIsolationPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
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
			if cmd == tenantIsolationPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", tenantIsolationPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestTenantIsolationCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range tenantIsolationCanonicalFuncs {
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
		doc := "package policy\n\nimport \"testing\"\n\nfunc TestTenantIsolationCoversCallSites(t *testing.T) {}\nfunc TestTenantIsolationPreservesScopeUnderContention(t *testing.T) {}\n"
		for _, want := range tenantIsolationCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestTenantIsolation prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestTenantIsolation"
		for _, want := range tenantIsolationCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestTenantIsolation` filter binds to the `TestTenantIsolation` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
