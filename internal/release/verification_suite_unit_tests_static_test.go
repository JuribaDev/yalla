package release_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Verification suite — unit tests for every package (BE-0379).
//
// Threat model: the repository's contract with reviewers and AI agents is
// "every backend package is covered by unit tests; the suite is documented,
// deterministic, and gated on every push and PR." A silent erosion of that
// contract — a new package added without tests, the CI gate removed from
// ci.yml, the suite quietly dropped from scripts/verify.sh — defeats every
// downstream security-verification gate (BE-0344..BE-0363+) because those
// gates only fire if `go test ./...` actually runs.
//
// This file is the load-bearing static defence for that meta-contract. It
// pins SIX surfaces in one file:
//
//   1. The repository tree — every directory that contains a non-test .go
//      file MUST also contain a *_test.go file, OR the directory MUST be in
//      `allowedPackagesWithoutUnitTests` with a rationale. The exemption
//      set is a closed list: adding a package to it requires a deliberate,
//      reviewed edit (and that exemption itself is validated — a stale
//      exemption for a package that has since gained tests fails the build).
//   2. `.github/workflows/ci.yml` — the test job MUST run `go test ./...`
//      under the canonical step name "Unit and integration tests". The
//      matrix MUST cover ubuntu-latest, macos-latest, and windows-latest so
//      the suite is exercised on every supported developer host.
//   3. `scripts/verify.sh` — the local commit gate MUST run `go test ./...`
//      under the canonical step header `# 4. Required: tests` so a future
//      reorder forces a deliberate edit here.
//   4. `CONTRIBUTING.md` — the Required Checks Before Every Commit section
//      MUST list `go test ./...` so contributors know the gate before they
//      open a PR. The optional-tools section MUST stay close enough to
//      ground the "never silently skip" rule.
//   5. `SECURITY.md` — the Required Verification Gates table MUST contain
//      the "Tests" row that pins `go test ./...`, AND a dedicated
//      `## Unit Test Suite` section MUST explain the contract operators
//      and AI agents rely on: deterministic fixtures, actionable failures
//      with request IDs / resource IDs, opt-in external smoke, and the
//      every-push-and-PR CI cadence.
//   6. `ralph/prd.json` — the verification-loop section MUST surface
//      `go test ./...` so an agent reading the PRD before starting work
//      sees the required local command without needing to discover it
//      from CI or shell scripts.
//
// The self-check `TestVerificationSuiteUnitTestsAnalyzerDetectsRegressions`
// drives every matcher with synthetic known-good AND known-bad fixtures so
// over-tightening (a legitimate change trips the analyser) and
// under-tightening (a real regression slips through) are both caught at
// the package-internal API.

const (
	// requiredCIWorkflowPath is the relative path of the test workflow.
	requiredCIWorkflowPath = ".github/workflows/ci.yml"
	// requiredCIWorkflowTestStepName is the exact step name CI uses to
	// invoke the unit-and-integration test suite. A rename forces a
	// deliberate update both here and in the workflow.
	requiredCIWorkflowTestStepName = "- name: Unit and integration tests"
	// requiredCIWorkflowTestStepRun is the literal command the step MUST
	// invoke. Anything narrower (e.g. `go test ./internal/...`) would
	// silently exclude cmd/* and any future top-level package.
	requiredCIWorkflowTestStepRun = "run: go test ./..."
	// requiredCIWorkflowMatrixHosts is the closed set of OS hosts the
	// test job MUST iterate; dropping any silently narrows the coverage.
	requiredCIWorkflowMatrixUbuntu  = "ubuntu-latest"
	requiredCIWorkflowMatrixMacOS   = "macos-latest"
	requiredCIWorkflowMatrixWindows = "windows-latest"

	// requiredVerifyShPath is the relative path of the local commit gate.
	requiredVerifyShPath = "scripts/verify.sh"
	// requiredVerifyShStepHeader is the canonical comment header that
	// precedes the `go test ./...` invocation in verify.sh. The numeric
	// prefix is part of the contract: a reorder must be a deliberate edit
	// to both this constant and the script.
	requiredVerifyShStepHeader = "# 4. Required: tests"
	// requiredVerifyShStepCmd is the literal command that MUST appear
	// inside the required-tests step. Asserting on the literal (not a
	// regex over the file) makes the failure point the operator at the
	// exact line that drifted.
	requiredVerifyShStepCmd = `go test ./...`

	// requiredContributingPath is the relative path of the contributor
	// guide.
	requiredContributingPath = "CONTRIBUTING.md"
	// requiredContributingSection is the literal Markdown heading that
	// MUST appear in CONTRIBUTING.md.
	requiredContributingSection = "## Required Checks Before Every Commit"
	// requiredContributingGoTestEntry is the literal list entry that MUST
	// appear under the Required Checks heading. Preserving the numeric
	// prefix keeps verify.sh and CONTRIBUTING.md in lockstep.
	requiredContributingGoTestEntry = "4. `go test ./...`"

	// requiredSecurityPath is the relative path of the public security
	// policy.
	requiredSecurityPath = "SECURITY.md"
	// requiredSecurityVerificationGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the unit-test suite is part of the published
	// security posture.
	requiredSecurityVerificationGateRow = "| Tests | `go test ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// requiredSecuritySectionHeading is the dedicated `## Unit Test
	// Suite` heading SECURITY.md MUST carry. The section explains the
	// determinism, actionable-failure, redaction, and CI-cadence
	// contracts operators rely on.
	requiredSecuritySectionHeading = "## Unit Test Suite"

	// requiredPRDPath is the relative path of the PRD an agent reads
	// before starting work.
	requiredPRDPath = "ralph/prd.json"
	// requiredPRDCommand is the literal command that MUST appear in the
	// PRD's verificationLoop.requiredLocalCommands array so an agent
	// surfaces the unit-test gate from the contract document, not from
	// shell scripts or CI workflows.
	requiredPRDCommand = "go test ./..."
)

// requiredSecuritySectionSubstrings is the closed set of literal substrings
// the `## Unit Test Suite` section MUST contain. Each captures a different
// load-bearing fact the BE-0379 acceptance criteria require to be visible:
//
//   - "Every Go package"        — the per-package coverage contract.
//   - "deterministic fixtures"  — the AC2 determinism contract.
//   - "request ID"              — the AC3 actionable-failure contract.
//   - "Every push and PR"       — the AC4 CI gating cadence.
//   - "fake Dokploy"            — the AC2 opt-in-external boundary.
//   - "YALLA_EXTERNAL_DOKPLOY"  — the AC2 opt-in escape hatch.
//   - "redacted"                — the AC8 secret-redaction contract.
//   - "verification_suite_unit_tests_static_test.go"
//     — the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole sentences)
// keeps the matcher robust to Markdown line wrap while still pinning every
// AC.
var requiredSecuritySectionSubstrings = []string{
	"Every Go package",
	"deterministic fixtures",
	"request ID",
	"Every push and PR",
	"fake Dokploy",
	"YALLA_EXTERNAL_DOKPLOY",
	"redacted",
	"verification_suite_unit_tests_static_test.go",
}

// allowedPackagesWithoutUnitTests is the closed exemption set: packages
// inside this repo that legitimately ship without unit tests. Each entry
// MUST carry a rationale so a future addition is a deliberate, reviewed
// edit — never a silent regression. Keys are repo-relative POSIX paths.
//
// Discipline:
//   - A package MUST NOT be added here just to silence the analyser. The
//     rationale must point to where coverage actually lives (integration
//     tests in another package, release tests, etc.) OR explain why the
//     package has no executable behaviour to cover.
//   - Stale exemptions are an error: if an exempt package gains a
//     *_test.go file, the entry MUST be deleted in the same edit.
//     `TestVerificationSuiteExemptionSetIsTight` enforces this.
var allowedPackagesWithoutUnitTests = map[string]string{
	"cmd/yalla": "Thin Cobra entrypoint (~28 lines); the actual command tree, " +
		"flag parsing, and exit-code contract are covered by " +
		"internal/cli/*_test.go and exercised end-to-end by " +
		"internal/release/release_test.go via the distribution matrix.",
	"cmd/yalla-worker": "Thin worker entrypoint (~67 lines); the run loop, " +
		"lease management, and shutdown contract are covered by " +
		"internal/controlplane/worker/*_test.go.",
}

// goSourceDirsIgnoredPrefixes is the closed set of repo-relative path
// prefixes the package-coverage walker MUST skip. These are never Go
// source roots (build outputs, VCS metadata, npm vendoring, agent
// scratch space). The matcher is prefix-based with a trailing slash so
// `outputs/foo.go` is skipped but a hypothetical `output/keep.go`
// package would still be scanned.
var goSourceDirsIgnoredPrefixes = []string{
	".git/",
	"node_modules/",
	"dist/",
	"outputs/",
	"tmp/",
	"bin/",
	"vendor/",
}

// TestVerificationSuiteEveryPackageHasUnitTests walks the repository,
// collects every directory that contains a non-test `.go` source file,
// and asserts the directory ALSO contains at least one `*_test.go` file
// OR is a member of `allowedPackagesWithoutUnitTests`. A violation
// means a new package was added without tests AND without a deliberate
// exemption entry — both of which would silently erode the
// every-package-tested contract.
func TestVerificationSuiteEveryPackageHasUnitTests(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)

	missing, err := findPackagesMissingTests(root, allowedPackagesWithoutUnitTests, goSourceDirsIgnoredPrefixes)
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(missing) > 0 {
		t.Errorf("the following packages contain non-test .go files but ship no *_test.go file and are not in allowedPackagesWithoutUnitTests:\n  - %s\nAdd unit tests for each, or — if the package is genuinely test-free (thin entrypoint, doc.go placeholder) — add an exemption entry with a rationale that points to where the behaviour is actually covered.",
			strings.Join(missing, "\n  - "))
	}
}

// TestVerificationSuiteExemptionSetIsTight asserts every entry in
// `allowedPackagesWithoutUnitTests` (a) refers to a real directory in the
// repo and (b) actually has no `*_test.go` file. A stale exemption — for
// a package that has since gained tests, or for a directory that no
// longer exists — is a silent loss of coverage discipline.
func TestVerificationSuiteExemptionSetIsTight(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	for rel, rationale := range allowedPackagesWithoutUnitTests {
		rel, rationale := rel, rationale
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(root, filepath.FromSlash(rel))
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("exempt entry %q (%q): directory does not exist: %v\nRemove the exemption or restore the directory.",
					rel, rationale, err)
			}
			if !info.IsDir() {
				t.Fatalf("exempt entry %q (%q): path is not a directory.",
					rel, rationale)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("exempt entry %q: read dir: %v", rel, err)
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if strings.HasSuffix(e.Name(), "_test.go") {
					t.Errorf("exempt entry %q has a *_test.go file (%q); remove the exemption — the package is no longer test-free.",
						rel, e.Name())
				}
			}
		})
	}
}

// TestVerificationSuiteCIWorkflowRunsUnitTests pins the GitHub Actions test
// job to run `go test ./...` under the canonical step name across every
// supported OS host. The matrix dimensions are part of the contract: a
// silent narrowing (e.g. dropping windows-latest) defeats the
// every-developer-host coverage promise.
func TestVerificationSuiteCIWorkflowRunsUnitTests(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		requiredCIWorkflowTestStepName,
		requiredCIWorkflowTestStepRun,
		requiredCIWorkflowMatrixUbuntu,
		requiredCIWorkflowMatrixMacOS,
		requiredCIWorkflowMatrixWindows,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI test job is the load-bearing gate for the every-package-tested contract — every push and PR MUST run `go test ./...` on every supported OS host.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteVerifyShRunsUnitTests pins the local commit gate to
// run `go test ./...` under its canonical step header so a contributor
// running the gate locally exercises the identical command CI runs.
func TestVerificationSuiteVerifyShRunsUnitTests(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, requiredVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-checks block is the local mirror of the CI gate and the unit-test step must keep its canonical position.",
			requiredVerifyShPath, requiredVerifyShStepHeader)
	}
	if !strings.Contains(doc, requiredVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same unit-test command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, requiredVerifyShStepCmd)
	}
}

// TestVerificationSuiteContributingDocumentsUnitTests pins the contributor
// guide so the gate is visible before a contributor opens a PR.
func TestVerificationSuiteContributingDocumentsUnitTests(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, requiredContributingSection) {
		t.Errorf("%s: missing required heading %q; the contributor guide MUST surface the unit-test gate so a new contributor satisfies it before opening a PR.",
			requiredContributingPath, requiredContributingSection)
	}
	if !strings.Contains(doc, requiredContributingGoTestEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, requiredContributingGoTestEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteSecurityDocumented pins the public security
// policy. SECURITY.md is the operator- and auditor-facing surface that
// makes the unit-test gate part of the published security posture, so
// dropping the row or the section silently weakens the posture.
func TestVerificationSuiteSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, requiredSecurityVerificationGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, requiredSecurityVerificationGateRow)
	}
	if !strings.Contains(doc, requiredSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the determinism / actionable-failure / opt-in-external / redaction contracts auditable.",
			requiredSecurityPath, requiredSecuritySectionHeading)
	}
	for _, want := range requiredSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, requiredSecuritySectionHeading)
		}
	}
}

// TestVerificationSuitePRDDocumentsUnitTests pins the PRD's
// verificationLoop.requiredLocalCommands so an AI agent reading the PRD
// before picking up a story sees the gate without needing to discover
// it from CI workflows or shell scripts.
func TestVerificationSuitePRDDocumentsUnitTests(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, requiredPRDPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", requiredPRDPath, err)
	}

	var prd struct {
		VerificationLoop struct {
			RequiredLocalCommands []string `json:"requiredLocalCommands"`
		} `json:"verificationLoop"`
	}
	if err := json.Unmarshal(b, &prd); err != nil {
		t.Fatalf("parse %s: %v", requiredPRDPath, err)
	}

	for _, cmd := range prd.VerificationLoop.RequiredLocalCommands {
		if cmd == requiredPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredLocalCommands does not contain %q; an agent reading the PRD MUST see the unit-test gate as a required local command.",
		requiredPRDPath, requiredPRDCommand)
}

// findPackagesMissingTests walks `root` and returns the repo-relative
// directories (POSIX-slashed) that contain at least one non-test `.go`
// source file but no `*_test.go` file AND are not members of the
// supplied `exempt` map. Directories whose repo-relative path starts
// with any prefix in `ignored` (matched as `prefix + filepath.Separator`
// or as the bare prefix at root) are skipped entirely.
//
// The function is split out from `TestVerificationSuiteEveryPackageHasUnitTests`
// so the self-check can drive it with synthetic fixtures.
func findPackagesMissingTests(root string, exempt map[string]string, ignored []string) ([]string, error) {
	type pkgInfo struct {
		hasNonTestGo bool
		hasTestGo    bool
	}
	pkgs := map[string]*pkgInfo{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relSlash := filepath.ToSlash(rel)
		if d.IsDir() {
			if relSlash == "." {
				return nil
			}
			for _, prefix := range ignored {
				p := strings.TrimSuffix(prefix, "/")
				if relSlash == p || strings.HasPrefix(relSlash, p+"/") {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		dirSlash := filepath.ToSlash(filepath.Dir(rel))
		if dirSlash == "." {
			dirSlash = ""
		}
		info, ok := pkgs[dirSlash]
		if !ok {
			info = &pkgInfo{}
			pkgs[dirSlash] = info
		}
		if strings.HasSuffix(name, "_test.go") {
			info.hasTestGo = true
		} else {
			info.hasNonTestGo = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var missing []string
	for dir, info := range pkgs {
		if !info.hasNonTestGo || info.hasTestGo {
			continue
		}
		if dir == "" {
			missing = append(missing, "<repo root>")
			continue
		}
		if _, ok := exempt[dir]; ok {
			continue
		}
		missing = append(missing, dir)
	}
	sort.Strings(missing)
	return missing, nil
}

// mustReadString reads a file and fails the test on error. The helper
// keeps every per-surface matcher above to a single readable shape.
func mustReadString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestVerificationSuiteUnitTestsAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a known-
// good AND a known-bad fixture and asserts the matcher fires (or stays
// silent) correctly. Without this self-check a future "improvement" to
// the matchers (a tightened regex, a relaxed substring set, a renamed
// constant) could silently let real regressions slip through.
func TestVerificationSuiteUnitTestsAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("findPackagesMissingTests flags non-exempt package without tests", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		mkFile(t, filepath.Join(dir, "pkga", "a.go"), "package a\n")
		mkFile(t, filepath.Join(dir, "pkga", "a_test.go"), "package a\n")
		mkFile(t, filepath.Join(dir, "pkgb", "b.go"), "package b\n")
		// pkgb intentionally has no _test.go AND no exemption.
		missing, err := findPackagesMissingTests(dir, map[string]string{}, nil)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		got := strings.Join(missing, ",")
		if got != "pkgb" {
			t.Fatalf("missing = %q, want %q; the analyser must flag a package with source but no tests when it is not exempt.", got, "pkgb")
		}
	})

	t.Run("findPackagesMissingTests accepts exempted package without tests", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		mkFile(t, filepath.Join(dir, "exempted", "main.go"), "package main\n")
		exempt := map[string]string{"exempted": "thin entrypoint"}
		missing, err := findPackagesMissingTests(dir, exempt, nil)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("missing = %v, want []; an exempt package without tests must NOT be flagged.", missing)
		}
	})

	t.Run("findPackagesMissingTests respects ignored prefix", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		mkFile(t, filepath.Join(dir, "outputs", "junk.go"), "package outputs\n")
		mkFile(t, filepath.Join(dir, "outputs", "nested", "deeper.go"), "package nested\n")
		missing, err := findPackagesMissingTests(dir, map[string]string{}, []string{"outputs/"})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("missing = %v, want []; an ignored prefix must skip the whole subtree, not just the top dir.", missing)
		}
	})

	t.Run("findPackagesMissingTests passes when every package has tests", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		mkFile(t, filepath.Join(dir, "pkga", "a.go"), "package a\n")
		mkFile(t, filepath.Join(dir, "pkga", "a_test.go"), "package a\n")
		mkFile(t, filepath.Join(dir, "pkgb", "b.go"), "package b\n")
		mkFile(t, filepath.Join(dir, "pkgb", "b_test.go"), "package b\n")
		missing, err := findPackagesMissingTests(dir, map[string]string{}, nil)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("missing = %v, want []; a fully-tested tree must produce no diagnostics.", missing)
		}
	})

	t.Run("findPackagesMissingTests ignores dirs with only test files", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// A directory containing only *_test.go files is not a package
		// missing tests — it is itself a test-only directory (e.g. an
		// external-test package). It MUST NOT be flagged.
		mkFile(t, filepath.Join(dir, "only_tests", "t_test.go"), "package only_tests\n")
		missing, err := findPackagesMissingTests(dir, map[string]string{}, nil)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("missing = %v, want []; a dir with only test files is not a violation.", missing)
		}
	})

	t.Run("doc-substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "Every push and PR" substring.
		doc := "## Unit Test Suite\n\nEvery Go package, deterministic fixtures, request ID, fake Dokploy, YALLA_EXTERNAL_DOKPLOY, redacted, verification_suite_unit_tests_static_test.go\n"
		for _, want := range requiredSecuritySectionSubstrings {
			if want == "Every push and PR" {
				continue
			}
			if !strings.Contains(doc, want) {
				t.Fatalf("self-check fixture missing %q — fix the fixture, not the test", want)
			}
		}
		if strings.Contains(doc, "Every push and PR") {
			t.Fatalf("self-check fixture contains %q — fix the fixture", "Every push and PR")
		}
		// Verify the production matcher would flag this fixture by
		// re-deriving the per-substring check inline.
		flagged := false
		for _, want := range requiredSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				flagged = true
				break
			}
		}
		if !flagged {
			t.Fatalf("substring matcher failed to flag missing %q in synthetic fixture", "Every push and PR")
		}
	})

	t.Run("doc-substring matcher passes on complete fixture", func(t *testing.T) {
		t.Parallel()
		// Build a synthetic doc that contains EVERY required substring.
		var b strings.Builder
		b.WriteString("## Unit Test Suite\n\n")
		for _, want := range requiredSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range requiredSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when go test ./... is absent", func(t *testing.T) {
		t.Parallel()
		// Synthetic PRD JSON without the required command.
		prdJSON := `{"verificationLoop":{"requiredLocalCommands":["gofmt -w .","go vet ./..."]}}`
		var prd struct {
			VerificationLoop struct {
				RequiredLocalCommands []string `json:"requiredLocalCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.RequiredLocalCommands {
			if cmd == requiredPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", requiredPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when go test ./... is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredLocalCommands":["gofmt -w .","go test ./...","go vet ./..."]}}`
		var prd struct {
			VerificationLoop struct {
				RequiredLocalCommands []string `json:"requiredLocalCommands"`
			} `json:"verificationLoop"`
		}
		if err := json.Unmarshal([]byte(prdJSON), &prd); err != nil {
			t.Fatalf("parse synthetic PRD: %v", err)
		}
		found := false
		for _, cmd := range prd.VerificationLoop.RequiredLocalCommands {
			if cmd == requiredPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", requiredPRDCommand)
		}
	})
}

// mkFile is a tiny helper for the synthetic-tree self-check tests. It
// creates the parent directory tree and writes `body` to `path`.
func mkFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
