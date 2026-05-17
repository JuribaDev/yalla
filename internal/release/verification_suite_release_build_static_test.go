package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — release build tests (BE-0401).
//
// Threat model: the `internal/release` package is the canonical
// source-of-truth for Yalla's release-derivation matrix. GoReleaser,
// the npm wrapper's `lib/platform.js`, the Homebrew formula's untar
// step, and the Scoop/WinGet manifests all resolve to the same
// (OS, arch) coordinates, archive names, binary names, and per-
// version checksums file. A silent regression in any of those
// projections — a renamed target, a flipped archive extension, a
// dropped windows `.exe` suffix, a checksums-template drift — would
// publish broken archives even when every other suite stays green.
//
// The canonical pair
// (`TestReleaseBuildCoversCallSites`,
//  `TestReleaseBuildPreservesContractUnderContention`) lives in
// `internal/release/release_build_test.go` and binds to the PRD's
// `go test -run TestReleaseBuild ./...` filter. The pair members are
// deterministic by design — both run against the compile-time
// `release.SupportedTargets` table and the pure projection helpers
// `Target.ArchiveExt`, `Target.BinaryName`, `Target.ArchiveName`,
// and `release.ChecksumsName`. Neither member reaches a live
// Postgres, a live Dokploy, the GoReleaser binary, or any external
// network.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `release_build_test.go` file removed, or the canonical
// `TestReleaseBuild…` function pair renamed — would let a release-
// derivation regression ship without firing any gate. An agent
// pulling the published archive would silently fetch a corrupted
// asset; the npm wrapper would 404 on the renamed URL; the Homebrew
// formula would untar into the wrong directory.
//
// This file is the load-bearing static defence for that meta-
// contract. It pins SIX surfaces in one file so a future contributor
// changing the CI step name, the verify.sh step header, the
// CONTRIBUTING numeric prefix, the SECURITY row, the PRD
// requiredBackendCommands array, or deleting the canonical release-
// build test fixture fails ONE test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Release build tests` that invokes
//     `go test -run TestReleaseBuild ./...`. Even though the
//     umbrella `go test ./...` step exercises the same package, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestReleaseBuild ./...` under the canonical step
//     header `# 25. Required: release build tests`. The numeric
//     prefix is part of the contract: a reorder must be a deliberate
//     edit to both this constant and the script. #25 extends the
//     BE-0379..BE-0399 sequence by one slot; the trailing optionals
//     (#26 govulncheck, #27 staticcheck, #28 golangci-lint, #29
//     goreleaser check, #30 external smoke) are renumbered in the
//     same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `25. \`go test -run TestReleaseBuild ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix keeps
//     verify.sh and CONTRIBUTING.md in lockstep with BE-0379..BE-0399's
//     pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Release build tests` row, AND a dedicated
//     `## Release Build Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     (OS, arch) coverage invariant, the documented projection rules
//     (windows → .zip + .exe; everything else → .tar.gz + bare
//     binary; archive-name template `yalla_<version>_<os>_<arch><ext>`;
//     checksums template `yalla_<version>_checksums.txt`), the
//     deterministic-by-default behaviour (pure projection helpers,
//     no GoReleaser binary), the CI-on-every-push-and-PR cadence,
//     the schema-version contract (`yalla.output.v1` `data.version`
//     downstream binding), and the redaction contract (projections
//     take only (OS, arch, version) and return a string).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestReleaseBuild ./...` so an AI agent reading
//     the PRD before picking up a story sees the canonical command
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/release/release_build_test.go` — the canonical
//     reference release-build test file MUST exist and MUST declare
//     the load-bearing function pair
//     (`TestReleaseBuildCoversCallSites`,
//     `TestReleaseBuildPreservesContractUnderContention`). The
//     PRD's `go test -run TestReleaseBuild ./...` filter binds to
//     the `TestReleaseBuild` prefix; a rename to a function whose
//     name does not match the prefix silently de-gates the release-
//     build suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteReleaseBuildAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// releaseBuildCIWorkflowStepName is the exact step name CI uses
	// to invoke the release-build suite. A rename forces a deliberate
	// update both here and in the workflow.
	releaseBuildCIWorkflowStepName = "- name: Release build tests"
	// releaseBuildCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestReleaseBuild…` test.
	releaseBuildCIWorkflowStepRun = "run: go test -run TestReleaseBuild ./..."

	// releaseBuildVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestReleaseBuild ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	releaseBuildVerifyShStepHeader = "# 25. Required: release build tests"
	// releaseBuildVerifyShStepCmd is the literal command that MUST
	// appear inside the required-release-build step. Asserting on the
	// literal (not a regex over the file) makes the failure point the
	// operator at the exact line that drifted.
	releaseBuildVerifyShStepCmd = `go test -run TestReleaseBuild ./...`

	// releaseBuildContributingEntry is the literal list entry that
	// MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	releaseBuildContributingEntry = "25. `go test -run TestReleaseBuild ./...`"

	// releaseBuildSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the release-build suite is part of the published
	// security posture.
	releaseBuildSecurityGateRow = "| Release build tests | `go test -run TestReleaseBuild ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// releaseBuildSecuritySectionHeading is the dedicated
	// `## Release Build Tests` heading SECURITY.md MUST carry. The
	// section explains the closed-set (OS, arch) coverage invariant,
	// the documented projection rules, the deterministic-by-default
	// behaviour, the actionable-failure contract, the schema-version
	// contract, and the redaction contract.
	releaseBuildSecuritySectionHeading = "## Release Build Tests"

	// releaseBuildPRDCommand is the literal command that MUST appear
	// in the PRD's verificationLoop.requiredBackendCommands array so
	// an agent surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	releaseBuildPRDCommand = "go test -run TestReleaseBuild ./..."

	// releaseBuildCanonicalFile is the relative path of the canonical
	// reference release-build test file. The
	// `internal/release/release_build_test.go` file declares the
	// function pair every release-build regression MUST trip;
	// deleting it silently kills the convention.
	releaseBuildCanonicalFile = "internal/release/release_build_test.go"
)

// releaseBuildCanonicalFuncs is the closed set of function
// declarations the canonical `release_build_test.go` file MUST
// carry. The PRD's `-run TestReleaseBuild` filter binds to function
// names containing the `TestReleaseBuild` substring; renaming any
// entry to a name that does not match the prefix silently de-gates
// the release-build suite for any caller relying on the filter. The
// pair captures the two load-bearing release-derivation invariants
// the harness MUST keep:
//
//   - TestReleaseBuildCoversCallSites — the closed-set release-
//     derivation coverage invariant: every documented (OS, arch)
//     coordinate in `release.SupportedTargets` yields the predicted
//     `ArchiveExt`, `BinaryName`, `ArchiveName`, and
//     `ChecksumsName` for a fixed sample version, and the set
//     itself is exhaustive (every documented coordinate appears
//     exactly once; no off-list coordinate slips in). Trips at the
//     package-internal API with no infrastructure dependency.
//   - TestReleaseBuildPreservesContractUnderContention — the per-
//     decision stability invariant under contention: firing
//     `releaseBuildWorkers * releaseBuildIterationsPerWorker`
//     goroutines that derive each target's projections from a
//     shared `release.SupportedTargets`-derived slice MUST yield,
//     for every goroutine, the projection its OWN scenario predicts
//     — a cross-write that swapped two goroutines' scenarios under
//     the race would fail the per-iteration assertion even when the
//     aggregate pass count matched.
var releaseBuildCanonicalFuncs = []string{
	"func TestReleaseBuildCoversCallSites(",
	"func TestReleaseBuildPreservesContractUnderContention(",
}

// releaseBuildSecuritySectionSubstrings is the closed set of literal
// substrings the `## Release Build Tests` section MUST contain.
// Each captures a different load-bearing fact the BE-0401 acceptance
// criteria require to be visible:
//
//   - "internal/release"        — the package boundary the canonical
//     release-build harness lives in (AC1 documented suite scope).
//   - "release_build_test.go"   — the canonical reference test file
//     name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"           — the AC2 determinism contract;
//     both pair members run against the compile-time
//     `release.SupportedTargets` table and pure projection helpers.
//   - "SupportedTargets"        — the closed-set scenario root the
//     gate pivots on.
//   - "ArchiveName"             — the documented archive-name
//     template the gate asserts.
//   - "ChecksumsName"           — the documented per-version
//     checksums template the gate asserts.
//   - "BinaryName"              — the documented binary-name rule
//     the gate asserts (windows → .exe; everything else → bare).
//   - "ArchiveExt"              — the documented archive-extension
//     rule the gate asserts (windows → .zip; everything else →
//     .tar.gz).
//   - "request_id"              — the AC3 actionable-failure
//     identifier surface; the release_test.go suite that wraps the
//     wire envelope carries the originating request_id when the
//     binary fails at runtime.
//   - "yalla.output.v1"         — the AC5 success envelope schema-
//     version contract downstream of the version stamp.
//   - "release"                 — the suite name a future agent
//     would search for.
//   - "TestReleaseBuildCoversCallSites" — the canonical closed-set
//     coverage function the -run filter binds to.
//   - "TestReleaseBuildPreservesContractUnderContention" — the
//     canonical contention burst function the -run filter binds to.
//   - "Every push and PR"       — the AC4 CI gating cadence.
//   - "redact" — the AC8 redaction contract; the projection
//     functions take only (OS, arch, version) and return a string,
//     so test output, error chains, and diagnostic envelopes carry
//     no credentials.
//   - "verification_suite_release_build_static_test.go" — the gate
//     is self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var releaseBuildSecuritySectionSubstrings = []string{
	"internal/release",
	"release_build_test.go",
	"deterministic",
	"SupportedTargets",
	"ArchiveName",
	"ChecksumsName",
	"BinaryName",
	"ArchiveExt",
	"yalla.output.v1",
	"TestReleaseBuildCoversCallSites",
	"TestReleaseBuildPreservesContractUnderContention",
	"Every push and PR",
	"redact",
	"verification_suite_release_build_static_test.go",
}

// TestVerificationSuiteReleaseBuildCIWorkflow pins the GitHub
// Actions test job to run the canonical release-build command under
// the canonical step name. A silent removal of the step — or a
// narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...`
// step would still leave this gate firing.
func TestVerificationSuiteReleaseBuildCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		releaseBuildCIWorkflowStepName,
		releaseBuildCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI release-build step is the defence-in-depth gate for the closed-set (OS, arch) coverage + per-decision stability invariants — every push and PR MUST run `go test -run TestReleaseBuild ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteReleaseBuildVerifyShRunsCanonicalCommand pins
// the local commit gate to run `go test -run TestReleaseBuild ./...`
// under its canonical step header so a contributor running the gate
// locally exercises the identical command CI runs.
func TestVerificationSuiteReleaseBuildVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, releaseBuildVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-release-build block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, releaseBuildVerifyShStepHeader)
	}
	if !strings.Contains(doc, releaseBuildVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same release-build command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, releaseBuildVerifyShStepCmd)
	}
}

// TestVerificationSuiteReleaseBuildContributingDocumentsCommand pins
// the contributor guide so the gate is visible before a contributor
// opens a PR. The numeric prefix matches the verify.sh step number to
// keep the two surfaces in lockstep.
func TestVerificationSuiteReleaseBuildContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, releaseBuildContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, releaseBuildContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteReleaseBuildSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and auditor-
// facing surface that makes the release-build gate part of the
// published security posture, so dropping the row or the section
// silently weakens the posture.
func TestVerificationSuiteReleaseBuildSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, releaseBuildSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, releaseBuildSecurityGateRow)
	}
	if !strings.Contains(doc, releaseBuildSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / projection-rule / deterministic-by-default / actionable-failure / schema-version / redaction contracts auditable.",
			requiredSecurityPath, releaseBuildSecuritySectionHeading)
	}
	for _, want := range releaseBuildSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, releaseBuildSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteReleaseBuildPRDDocumentsCommand pins the PRD's
// verificationLoop.requiredBackendCommands so an AI agent reading the
// PRD before picking up a story sees the canonical release-build
// command without needing to discover it from CI workflows or shell
// scripts.
func TestVerificationSuiteReleaseBuildPRDDocumentsCommand(t *testing.T) {
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
		if cmd == releaseBuildPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the release-build gate as a required backend command.",
		requiredPRDPath, releaseBuildPRDCommand)
}

// TestVerificationSuiteReleaseBuildCanonicalFileExists pins the
// canonical reference release-build test file and its load-bearing
// function pair. Deleting the file or renaming either function to a
// name that does not match the `TestReleaseBuild` prefix silently
// de-gates the release-build suite for any caller relying on the
// PRD's `-run TestReleaseBuild` filter.
func TestVerificationSuiteReleaseBuildCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(releaseBuildCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical release-build test file is the load-bearing convention every release-derivation regression MUST trip; deleting it silently removes the release-build gate.",
			releaseBuildCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range releaseBuildCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the release-build pair is the load-bearing assertion set every release-derivation regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + per-decision-stability contract for every downstream caller.",
				releaseBuildCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteReleaseBuildAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteReleaseBuildAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			releaseBuildCIWorkflowStepName,
			releaseBuildCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Release build tests\n        run: go test -run TestReleaseBuild ./...\n"
		for _, want := range []string{
			releaseBuildCIWorkflowStepName,
			releaseBuildCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, releaseBuildVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", releaseBuildVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 25. Required: release build tests\nstep \"go test -run TestReleaseBuild ./...\"\nif ! go test -run TestReleaseBuild ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, releaseBuildVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", releaseBuildVerifyShStepHeader)
		}
		if !strings.Contains(doc, releaseBuildVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", releaseBuildVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n24. `go test -run TestBackupRestoreRehearsal ./...`\n"
		if strings.Contains(doc, releaseBuildContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", releaseBuildContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n24. `go test -run TestBackupRestoreRehearsal ./...`\n25. `go test -run TestReleaseBuild ./...`\n"
		if !strings.Contains(doc, releaseBuildContributingEntry) {
			t.Fatalf("complete fixture missing %q", releaseBuildContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("## Release Build Tests\n\n")
		for _, want := range releaseBuildSecuritySectionSubstrings {
			if want == "SupportedTargets" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range releaseBuildSecuritySectionSubstrings {
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
		b.WriteString("## Release Build Tests\n\n")
		for _, want := range releaseBuildSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range releaseBuildSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
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
			if cmd == releaseBuildPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", releaseBuildPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
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
			if cmd == releaseBuildPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", releaseBuildPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		doc := "package release_test\n\nimport \"testing\"\n\nfunc TestReleaseBuildCoversCallSites(t *testing.T) {}\n"
		missing := 0
		for _, want := range releaseBuildCanonicalFuncs {
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
		doc := "package release_test\n\nimport \"testing\"\n\nfunc TestReleaseBuildCoversCallSites(t *testing.T) {}\nfunc TestReleaseBuildPreservesContractUnderContention(t *testing.T) {}\n"
		for _, want := range releaseBuildCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestReleaseBuild prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		const wantPrefix = "func TestReleaseBuild"
		for _, want := range releaseBuildCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestReleaseBuild` filter binds to the `TestReleaseBuild` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
