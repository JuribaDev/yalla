package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — config validation tests (BE-0402).
//
// Threat model: `internal/controlplane/config.Load` is the single
// configuration chokepoint both backend binaries (`cmd/yalla-api`
// and `cmd/yalla-worker`) call once at startup. A silent regression
// that relaxed one validation rule — accepting a `mysql://` DSN, a
// non-hex YALLA_SECRET_KEYS entry, an out-of-range
// YALLA_SHUTDOWN_TIMEOUT, or a strict profile with a missing
// operational field — would let a misconfigured process enter the
// request path. A regression in the redaction predicate would echo
// the offending value into an error string and leak a credential
// into operator logs, audit metadata, or test output.
//
// The canonical pair
// (`TestConfigValidationCoversCallSites`,
//  `TestConfigValidationPreservesContractUnderContention`) lives in
// `internal/controlplane/config/config_validation_test.go` and binds
// to the PRD's `go test -run TestConfigValidation ./...` filter. The
// pair members are deterministic by design — both walk a closed
// scenario table built from every documented validation rule and
// every documented strict-profile presence check, and the validator
// is a pure function from the env map to a `*Config` or a typed
// `*yerr.Error` value. Neither member reaches the process
// environment, the network, a live Postgres, a live Dokploy, or any
// external service.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `config_validation_test.go` file removed, or the canonical
// `TestConfigValidation…` function pair renamed — would let a
// validator regression ship without firing any gate. A misconfigured
// process would enter request handling under the strict profile
// despite missing operational fields; a credential could echo into
// operator logs.
//
// This file is the load-bearing static defence for that meta-
// contract. It pins SIX surfaces in one file so a future contributor
// changing the CI step name, the verify.sh step header, the
// CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical config-
// validation test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Config validation tests` that invokes
//     `go test -run TestConfigValidation ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestConfigValidation ./...` under the canonical
//     step header `# 26. Required: config validation tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #26
//     extends the BE-0379..BE-0401 sequence by one slot; the
//     trailing optionals (#27 govulncheck, #28 staticcheck, #29
//     golangci-lint, #30 goreleaser check, #31 external smoke) are
//     renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `26. \`go test -run TestConfigValidation ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0401's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Config validation tests` row, AND a dedicated
//     `## Config Validation Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     coverage invariant (every documented validation rule + every
//     documented strict-profile presence check), the typed-error
//     contract (`yerr.CodeConfig` is the load-bearing exit pivot),
//     the deterministic-by-default behaviour (pure validator, no
//     process env, no network, no live Postgres, no live Dokploy),
//     the CI-on-every-push-and-PR cadence, the schema-version
//     contract (every config-derived JSON envelope downstream is
//     `yalla.output.v1`), and the redaction contract (validation
//     errors describe which field failed without echoing its value,
//     even when the offending value is a secret).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestConfigValidation ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/config/config_validation_test.go` —
//     the canonical reference config-validation test file MUST exist
//     and MUST declare the load-bearing function pair
//     (`TestConfigValidationCoversCallSites`,
//     `TestConfigValidationPreservesContractUnderContention`). The
//     PRD's `go test -run TestConfigValidation ./...` filter binds
//     to the `TestConfigValidation` prefix; a rename to a function
//     whose name does not match the prefix silently de-gates the
//     config-validation suite for any caller relying on the `-run`
//     filter.
//
// The self-check
// (`TestVerificationSuiteConfigValidationAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// configValidationCIWorkflowStepName is the exact step name CI
	// uses to invoke the config-validation suite. A rename forces a
	// deliberate update both here and in the workflow.
	configValidationCIWorkflowStepName = "- name: Config validation tests"
	// configValidationCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestConfigValidation…` test.
	configValidationCIWorkflowStepRun = "run: go test -run TestConfigValidation ./..."

	// configValidationVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestConfigValidation
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	configValidationVerifyShStepHeader = "# 26. Required: config validation tests"
	// configValidationVerifyShStepCmd is the literal command that
	// MUST appear inside the required-config-validation step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	configValidationVerifyShStepCmd = `go test -run TestConfigValidation ./...`

	// configValidationContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	configValidationContributingEntry = "26. `go test -run TestConfigValidation ./...`"

	// configValidationSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the config-validation suite is part of the
	// published security posture.
	configValidationSecurityGateRow = "| Config validation tests | `go test -run TestConfigValidation ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// configValidationSecuritySectionHeading is the dedicated
	// `## Config Validation Tests` heading SECURITY.md MUST carry.
	// The section explains the closed-set coverage invariant, the
	// typed-error contract, the deterministic-by-default behaviour,
	// the actionable-failure contract, the schema-version contract,
	// and the redaction contract.
	configValidationSecuritySectionHeading = "## Config Validation Tests"

	// configValidationPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	configValidationPRDCommand = "go test -run TestConfigValidation ./..."

	// configValidationCanonicalFile is the relative path of the
	// canonical reference config-validation test file. The
	// `internal/controlplane/config/config_validation_test.go` file
	// declares the function pair every config-validation regression
	// MUST trip; deleting it silently kills the convention.
	configValidationCanonicalFile = "internal/controlplane/config/config_validation_test.go"
)

// configValidationCanonicalFuncs is the closed set of function
// declarations the canonical `config_validation_test.go` file MUST
// carry. The PRD's `-run TestConfigValidation` filter binds to
// function names containing the `TestConfigValidation` substring;
// renaming any entry to a name that does not match the prefix
// silently de-gates the config-validation suite for any caller
// relying on the filter. The pair captures the two load-bearing
// validation invariants the harness MUST keep:
//
//   - TestConfigValidationCoversCallSites — the closed-set
//     validation coverage invariant: every documented rule in
//     `config.Validate` and every documented strict-profile presence
//     check in `config.requireStrictFields` yields a typed
//     `*yerr.Error` with `Code == CodeConfig`, a message that names
//     the offending env var, and zero echo of the seeded secret
//     marker. Trips at the package-internal API with no
//     infrastructure dependency.
//   - TestConfigValidationPreservesContractUnderContention — the
//     per-decision stability invariant under contention: firing
//     `configValidationWorkers * configValidationIterationsPerWorker`
//     goroutines that each run `Load(MapLookup(env))` against their
//     own scenario's mutated env MUST yield, for every goroutine,
//     the rule its OWN scenario predicts — a cross-write under the
//     race that swapped two goroutines' scenarios would fail the
//     per-iteration assertion even when the aggregate pass count
//     matched.
var configValidationCanonicalFuncs = []string{
	"func TestConfigValidationCoversCallSites(",
	"func TestConfigValidationPreservesContractUnderContention(",
}

// configValidationSecuritySectionSubstrings is the closed set of
// literal substrings the `## Config Validation Tests` section MUST
// contain. Each captures a different load-bearing fact the BE-0402
// acceptance criteria require to be visible:
//
//   - "internal/controlplane/config" — the package boundary the
//     canonical config-validation harness lives in (AC1 documented
//     suite scope).
//   - "config_validation_test.go" — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"              — the AC2 determinism contract;
//     both pair members run against a closed scenario table and the
//     pure validator.
//   - "CodeConfig"                 — the typed-error contract the
//     API and worker binaries pivot their fail-fast exit on.
//   - "strict-profile"             — the closed-set strict-profile
//     presence check the suite covers.
//   - "YALLA_DATABASE_URL"         — a specific env var the validator
//     enforces; documenting at least one canonical name keeps the
//     mapping from rule → env visible to operators.
//   - "YALLA_SECRET_KEYS"          — the secret-bearing env that
//     drives the non-hex / wrong-length scenarios; documenting it
//     makes the redaction contract concrete.
//   - "MapLookup"                  — the test seam the validator is
//     exercised through; documenting it lets reviewers reproduce a
//     failure without touching the process environment.
//   - "yalla.error.v1"             — the AC5 error envelope schema
//     contract every typed `yerr.CodeConfig` error renders through
//     downstream.
//   - "TestConfigValidationCoversCallSites" — the canonical closed-
//     set coverage function the -run filter binds to.
//   - "TestConfigValidationPreservesContractUnderContention" — the
//     canonical contention burst function the -run filter binds to.
//   - "Every push and PR"          — the AC4 CI gating cadence.
//   - "redact"                     — the AC8 redaction contract; the
//     validator names which env var failed without echoing its
//     value, even when the offending value is itself a secret.
//   - "verification_suite_config_validation_static_test.go" — the
//     gate is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var configValidationSecuritySectionSubstrings = []string{
	"internal/controlplane/config",
	"config_validation_test.go",
	"deterministic",
	"CodeConfig",
	"strict-profile",
	"YALLA_DATABASE_URL",
	"YALLA_SECRET_KEYS",
	"MapLookup",
	"yalla.error.v1",
	"TestConfigValidationCoversCallSites",
	"TestConfigValidationPreservesContractUnderContention",
	"Every push and PR",
	"redact",
	"verification_suite_config_validation_static_test.go",
}

// TestVerificationSuiteConfigValidationCIWorkflow pins the GitHub
// Actions test job to run the canonical config-validation command
// under the canonical step name. A silent removal of the step — or
// a narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuiteConfigValidationCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		configValidationCIWorkflowStepName,
		configValidationCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI config-validation step is the defence-in-depth gate for the closed-set rule-coverage + per-decision stability invariants — every push and PR MUST run `go test -run TestConfigValidation ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteConfigValidationVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestConfigValidation ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteConfigValidationVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, configValidationVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-config-validation block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, configValidationVerifyShStepHeader)
	}
	if !strings.Contains(doc, configValidationVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same config-validation command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, configValidationVerifyShStepCmd)
	}
}

// TestVerificationSuiteConfigValidationContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteConfigValidationContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, configValidationContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, configValidationContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteConfigValidationSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the config-validation gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteConfigValidationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, configValidationSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, configValidationSecurityGateRow)
	}
	if !strings.Contains(doc, configValidationSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set rule-coverage / typed-error / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, configValidationSecuritySectionHeading)
	}
	for _, want := range configValidationSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, configValidationSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteConfigValidationPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// config-validation command without needing to discover it from CI
// workflows or shell scripts.
func TestVerificationSuiteConfigValidationPRDDocumentsCommand(t *testing.T) {
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
		if cmd == configValidationPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the config-validation gate as a required backend command.",
		requiredPRDPath, configValidationPRDCommand)
}

// TestVerificationSuiteConfigValidationCanonicalFileExists pins the
// canonical reference config-validation test file and its load-
// bearing function pair. Deleting the file or renaming either
// function to a name that does not match the `TestConfigValidation`
// prefix silently de-gates the config-validation suite for any
// caller relying on the PRD's `-run TestConfigValidation` filter.
func TestVerificationSuiteConfigValidationCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(configValidationCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical config-validation test file is the load-bearing convention every config-validation regression MUST trip; deleting it silently removes the config-validation gate.",
			configValidationCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range configValidationCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the config-validation pair is the load-bearing assertion set every validation regression MUST trip — a rename or deletion silently relaxes the closed-set rule-coverage + per-decision-stability contract for every downstream caller.",
				configValidationCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteConfigValidationAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteConfigValidationAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			configValidationCIWorkflowStepName,
			configValidationCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Config validation tests\n        run: go test -run TestConfigValidation ./...\n"
		for _, want := range []string{
			configValidationCIWorkflowStepName,
			configValidationCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, configValidationVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", configValidationVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 26. Required: config validation tests\nstep \"go test -run TestConfigValidation ./...\"\nif ! go test -run TestConfigValidation ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, configValidationVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", configValidationVerifyShStepHeader)
		}
		if !strings.Contains(doc, configValidationVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", configValidationVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n25. `go test -run TestReleaseBuild ./...`\n"
		if strings.Contains(doc, configValidationContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", configValidationContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n25. `go test -run TestReleaseBuild ./...`\n26. `go test -run TestConfigValidation ./...`\n"
		if !strings.Contains(doc, configValidationContributingEntry) {
			t.Fatalf("complete fixture missing %q", configValidationContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Config Validation Tests\n\n")
		for _, want := range configValidationSecuritySectionSubstrings {
			if want == "CodeConfig" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range configValidationSecuritySectionSubstrings {
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
		b.WriteString("## Config Validation Tests\n\n")
		for _, want := range configValidationSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range configValidationSecuritySectionSubstrings {
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
			if cmd == configValidationPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", configValidationPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestConfigValidation ./..."]}}`
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
			if cmd == configValidationPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", configValidationPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package config\n\nimport \"testing\"\n\nfunc TestConfigValidationCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range configValidationCanonicalFuncs {
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
		doc := "package config\n\nimport \"testing\"\n\nfunc TestConfigValidationCoversCallSites(t *testing.T) {}\nfunc TestConfigValidationPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range configValidationCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestConfigValidation prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestConfigValidation"
		for _, want := range configValidationCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestConfigValidation` filter binds to the `TestConfigValidation` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
