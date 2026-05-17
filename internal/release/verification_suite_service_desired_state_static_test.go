package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — service desired-state golden tests (BE-0407).
//
// Threat model: the renderer is the single point at which
// Yalla's source-of-truth hierarchy (organization, project,
// environment, service) is projected into the desired Dokploy
// spec the provisioning worker reconciles. The pure-function
// chokepoint is
// `(*dokploy.Renderer).Render(in RenderInput) (RenderedSpec, error)`
// — it takes a fully-validated RenderInput and emits a
// `RenderedSpec` whose every closed-taxonomy field
// (`ServiceType`, `ServiceRole`, `Builder`, `Engine`,
// `EnvironmentTier`) carries a documented enum value, whose
// variable, domain, and label ordering is deterministic, and
// whose redaction-safe `Summary` projection never echoes a raw
// variable Value. A silent regression that demoted an enum
// value out of the closed set, that started echoing a raw
// variable Value into the redacted `Summary` JSON, the
// `Summary.String()` form, or the `slog` LogValue, that
// introduced non-deterministic ordering into the rendered spec,
// or that smuggled package-level shared state into a
// goroutine-shared renderer, would either let an operator
// commit to a deploy whose desired state did not match what
// they reviewed in a log, audit record, or dry-run preview, or
// leak a customer secret through a debug surface that is meant
// to be safe to log, audit, and store. The canonical pair
// (`TestServiceDesiredStateCoversCallSites`,
//
//	`TestServiceDesiredStatePreservesContractUnderContention`) lives
//
// in
// `internal/controlplane/dokploy/service_desired_state_canonical_test.go`
// and binds to the PRD's `-run TestServiceDesiredState` filter.
// The pair members are deterministic by design — both walk a
// closed scenario table built from every documented
// `ServiceType`, `ServiceRole`, `Builder`, `Engine`, and
// `EnvironmentTier` value, and the renderer is a deterministic
// pure function of its input. Neither member reaches the
// process environment, the network, a live Postgres, a live
// Dokploy, or any external service.
//
// A silent erosion of that contract — the dedicated CI step
// quietly dropped, the verify.sh entry renumbered without
// updating CONTRIBUTING.md, the SECURITY.md section deleted,
// the canonical `service_desired_state_canonical_test.go` file
// removed, or the canonical `TestServiceDesiredState…` function
// pair renamed — would let a renderer drift or a new
// closed-set enum value ship without firing any gate. This file
// is the load-bearing static defence for that meta-contract. It
// pins SIX surfaces in one file so a future contributor
// changing the CI step name, the verify.sh step header, the
// CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical
// service-desired-state test fixture fails ONE test, not six:
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Service desired-state golden tests`
//     that invokes `go test -run TestServiceDesiredState ./...`.
//     Even though the umbrella `go test ./...` step exercises
//     the same package, the dedicated step is defence-in-depth:
//     a future narrowing of the umbrella step would still leave
//     this gate firing as a fast targeted failure rather than
//     buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestServiceDesiredState ./...` under the
//     canonical step header
//     `# 31. Required: service desired-state golden tests`. The
//     numeric prefix is part of the contract: a reorder must be
//     a deliberate edit to both this constant and the script.
//     #31 extends the BE-0379..BE-0406 sequence by one and
//     pushes the trailing optional steps #31-#35 down to
//     #32-#36 in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks list MUST carry
//     an entry `31. \`go test -run TestServiceDesiredState
//     ./...\`` so a contributor preparing a PR sees the gate
//     before running scripts/verify.sh.
//  4. `SECURITY.md` — the published verification-gates table
//     MUST carry a row for the service desired-state golden
//     suite, AND a dedicated
//     `## Service Desired-State Golden Tests` section MUST
//     explain the closed-set coverage invariant (every
//     documented `ServiceType`, `ServiceRole`, `Builder`,
//     `Engine`, and `EnvironmentTier`), the determinism
//     invariant (`Render(in)` is a deterministic pure function
//     of its input), the value-free Summary invariant (the
//     redacted Summary JSON, the slog LogValue, and the
//     Summary.String() form never carry a raw variable Value),
//     the actionable-failure contract, the schema-version
//     contract, and the redaction contract.
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestServiceDesiredState ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     gate without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/dokploy/service_desired_state_canonical_test.go`
//     — the canonical reference service-desired-state test file
//     MUST exist and MUST declare the load-bearing function
//     pair (`TestServiceDesiredStateCoversCallSites`,
//     `TestServiceDesiredStatePreservesContractUnderContention`).
//     The PRD's `go test -run TestServiceDesiredState ./...`
//     filter binds to the `TestServiceDesiredState` substring;
//     a rename to a function whose name does not match the
//     substring silently de-gates the service-desired-state
//     suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteServiceDesiredStateAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips
// through) are both caught at the package-internal API.

const (
	// serviceDesiredStateCIWorkflowStepName is the exact step
	// name CI uses to invoke the service-desired-state suite. A
	// rename forces a deliberate update both here and in the
	// workflow.
	serviceDesiredStateCIWorkflowStepName = "- name: Service desired-state golden tests"
	// serviceDesiredStateCIWorkflowStepRun is the literal command
	// the step MUST invoke. Anything narrower (e.g. dropping the
	// trailing `./...`) would silently exclude any future
	// package that declares a `TestServiceDesiredState…` test.
	serviceDesiredStateCIWorkflowStepRun = "run: go test -run TestServiceDesiredState ./..."

	// serviceDesiredStateVerifyShStepHeader is the canonical
	// comment header that precedes the
	// `go test -run TestServiceDesiredState ./...` invocation in
	// verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant
	// and the script.
	serviceDesiredStateVerifyShStepHeader = "# 31. Required: service desired-state golden tests"
	// serviceDesiredStateVerifyShStepCmd is the literal command
	// that MUST appear inside the required-service-desired-state
	// step. Asserting on the literal (not a regex over the file)
	// makes the failure point the operator at the exact line
	// that drifted.
	serviceDesiredStateVerifyShStepCmd = `go test -run TestServiceDesiredState ./...`

	// serviceDesiredStateContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading
	// in CONTRIBUTING.md. Preserving the numeric prefix keeps
	// verify.sh and CONTRIBUTING.md in lockstep.
	serviceDesiredStateContributingEntry = "31. `go test -run TestServiceDesiredState ./...`"

	// serviceDesiredStateSecurityGateRow is the verification-
	// gates row that MUST appear in SECURITY.md so external
	// operators and reviewers can see the service-desired-state
	// suite is part of the published security posture.
	serviceDesiredStateSecurityGateRow = "| Service desired-state golden tests | `go test -run TestServiceDesiredState ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// serviceDesiredStateSecuritySectionHeading is the dedicated
	// `## Service Desired-State Golden Tests` heading
	// SECURITY.md MUST carry. The section explains the closed-
	// set coverage invariant, the determinism invariant, the
	// value-free Summary invariant, the actionable-failure
	// contract, the schema-version contract, and the redaction
	// contract.
	serviceDesiredStateSecuritySectionHeading = "## Service Desired-State Golden Tests"

	// serviceDesiredStatePRDCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	serviceDesiredStatePRDCommand = "go test -run TestServiceDesiredState ./..."

	// serviceDesiredStateCanonicalFile is the relative path of
	// the canonical reference service-desired-state test file.
	// The
	// `internal/controlplane/dokploy/service_desired_state_canonical_test.go`
	// file declares the function pair every service-desired-
	// state regression MUST trip; deleting it silently kills the
	// convention.
	serviceDesiredStateCanonicalFile = "internal/controlplane/dokploy/service_desired_state_canonical_test.go"
)

// serviceDesiredStateCanonicalFuncs is the closed set of
// function declarations the canonical
// `service_desired_state_canonical_test.go` file MUST carry.
// The PRD's `-run TestServiceDesiredState` filter binds to
// function names containing the `TestServiceDesiredState`
// substring; renaming any entry to a name that does not match
// the substring silently de-gates the service-desired-state
// suite for any caller relying on the filter.
var serviceDesiredStateCanonicalFuncs = []string{
	"func TestServiceDesiredStateCoversCallSites(t *testing.T)",
	"func TestServiceDesiredStatePreservesContractUnderContention(t *testing.T)",
}

// serviceDesiredStateSecuritySectionSubstrings is the closed
// set of substrings the dedicated
// `## Service Desired-State Golden Tests` section in
// SECURITY.md MUST contain. The substrings name every load-
// bearing fact the operator- and auditor-facing documentation
// MUST surface so a future contributor changing the gate's
// contract is forced to update the public security posture in
// the same edit.
var serviceDesiredStateSecuritySectionSubstrings = []string{
	"TestServiceDesiredState",
	"Render",
	"RenderedSpec",
	"Summary",
	"ServiceType",
	"ServiceRole",
	"Builder",
	"Engine",
	"EnvironmentTier",
	"application",
	"compose",
	"database",
	"web",
	"worker",
	"cron",
	"postgres",
	"mysql",
	"mariadb",
	"mongo",
	"redis",
	"staging",
	"production",
	"preview",
	"yalla.error.v1",
}

// projectRoot, mustReadString, requiredCIWorkflowPath,
// requiredVerifyShPath, requiredContributingPath,
// requiredContributingSection, requiredSecurityPath, and
// requiredPRDPath are package-level helpers declared in
// `verification_suite_unit_tests_static_test.go` (BE-0379).
// Reusing them here keeps the path / helper layer single-
// sourced so a repository-wide rename only touches that file.

// TestVerificationSuiteServiceDesiredStateCIWorkflowDeclaresStep
// pins the CI workflow to a dedicated step that invokes
// `go test -run TestServiceDesiredState ./...`. Even though the
// umbrella `go test ./...` step exercises the same package, the
// dedicated step is defence-in-depth: a future narrowing of
// the umbrella step would still leave this gate firing as a
// fast targeted failure rather than buried inside the umbrella
// log.
func TestVerificationSuiteServiceDesiredStateCIWorkflowDeclaresStep(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		serviceDesiredStateCIWorkflowStepName,
		serviceDesiredStateCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI service-desired-state step is the defence-in-depth gate for the closed-set renderer coverage + determinism + value-free Summary invariants — every push and PR MUST run `go test -run TestServiceDesiredState ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteServiceDesiredStateVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestServiceDesiredState ./...` under its
// canonical step header so a contributor running the gate
// locally exercises the identical command CI runs.
func TestVerificationSuiteServiceDesiredStateVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, serviceDesiredStateVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-service-desired-state block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, serviceDesiredStateVerifyShStepHeader)
	}
	if !strings.Contains(doc, serviceDesiredStateVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same service-desired-state command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, serviceDesiredStateVerifyShStepCmd)
	}
}

// TestVerificationSuiteServiceDesiredStateContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the
// verify.sh step number to keep the two surfaces in lockstep.
func TestVerificationSuiteServiceDesiredStateContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, serviceDesiredStateContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, serviceDesiredStateContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteServiceDesiredStateSecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the service-desired-state
// gate part of the published security posture, so dropping the
// row or the section silently weakens the posture.
func TestVerificationSuiteServiceDesiredStateSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, serviceDesiredStateSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, serviceDesiredStateSecurityGateRow)
	}
	if !strings.Contains(doc, serviceDesiredStateSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / determinism / value-free Summary / actionable-failure / schema-version contracts auditable.",
			requiredSecurityPath, serviceDesiredStateSecuritySectionHeading)
	}
	for _, want := range serviceDesiredStateSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, serviceDesiredStateSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteServiceDesiredStatePRDDocumentsCommand
// pins the PRD's verificationLoop.requiredBackendCommands so
// an AI agent reading the PRD before picking up a story sees
// the canonical service-desired-state command without needing
// to discover it from CI workflows or shell scripts.
func TestVerificationSuiteServiceDesiredStatePRDDocumentsCommand(t *testing.T) {
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
		if cmd == serviceDesiredStatePRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the service-desired-state gate as a required backend command.",
		requiredPRDPath, serviceDesiredStatePRDCommand)
}

// TestVerificationSuiteServiceDesiredStateCanonicalFileExists pins
// the canonical reference service-desired-state test file and
// its load-bearing function pair. Deleting the file or renaming
// either function to a name that does not match the
// `TestServiceDesiredState` substring silently de-gates the
// service-desired-state suite for any caller relying on the
// PRD's `-run TestServiceDesiredState` filter.
func TestVerificationSuiteServiceDesiredStateCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(serviceDesiredStateCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical service-desired-state test file is the load-bearing convention every service-desired-state regression MUST trip; deleting it silently removes the service-desired-state gate.",
			serviceDesiredStateCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range serviceDesiredStateCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the service-desired-state pair is the load-bearing assertion set every service-desired-state regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				serviceDesiredStateCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteServiceDesiredStateAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest
// synthesises a known-good AND a known-bad fixture and asserts
// the matcher fires (or stays silent) correctly. Without this
// self-check a future "improvement" to the matchers (a
// tightened regex, a relaxed substring set, a renamed constant)
// could silently let real regressions slip through.
func TestVerificationSuiteServiceDesiredStateAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			serviceDesiredStateCIWorkflowStepName,
			serviceDesiredStateCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Service desired-state golden tests\n        run: go test -run TestServiceDesiredState ./...\n"
		for _, want := range []string{
			serviceDesiredStateCIWorkflowStepName,
			serviceDesiredStateCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, serviceDesiredStateVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", serviceDesiredStateVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 31. Required: service desired-state golden tests\nstep \"go test -run TestServiceDesiredState ./...\"\nif ! go test -run TestServiceDesiredState ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, serviceDesiredStateVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", serviceDesiredStateVerifyShStepHeader)
		}
		if !strings.Contains(doc, serviceDesiredStateVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", serviceDesiredStateVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n30. `go test -run TestImportDryRun ./...`\n"
		if strings.Contains(doc, serviceDesiredStateContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", serviceDesiredStateContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n30. `go test -run TestImportDryRun ./...`\n31. `go test -run TestServiceDesiredState ./...`\n"
		if !strings.Contains(doc, serviceDesiredStateContributingEntry) {
			t.Fatalf("complete fixture missing %q", serviceDesiredStateContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Service Desired-State Golden Tests\n\n")
		for _, want := range serviceDesiredStateSecuritySectionSubstrings {
			if want == "RenderedSpec" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range serviceDesiredStateSecuritySectionSubstrings {
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
		b.WriteString("## Service Desired-State Golden Tests\n\n")
		for _, want := range serviceDesiredStateSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range serviceDesiredStateSecuritySectionSubstrings {
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
			if cmd == serviceDesiredStatePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", serviceDesiredStatePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestServiceDesiredState ./..."]}}`
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
			if cmd == serviceDesiredStatePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", serviceDesiredStatePRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestServiceDesiredStateCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range serviceDesiredStateCanonicalFuncs {
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
		doc := "package dokploy_test\n\nimport \"testing\"\n\nfunc TestServiceDesiredStateCoversCallSites(t *testing.T) {}\nfunc TestServiceDesiredStatePreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range serviceDesiredStateCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestServiceDesiredState substring locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantSubstring = "TestServiceDesiredState"
		for _, want := range serviceDesiredStateCanonicalFuncs {
			if !strings.Contains(want, wantSubstring) {
				t.Errorf("canonical-funcs entry %q does not contain %q — the PRD's `-run TestServiceDesiredState` filter binds to the `TestServiceDesiredState` substring and would silently miss this function", want, wantSubstring)
			}
		}
	})
}
