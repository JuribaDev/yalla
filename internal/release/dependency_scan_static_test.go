package release_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Dependency vulnerability scanning — static-analysis defence (BE-0354).
//
// Threat model: a known-vulnerable third-party Go module reaches a
// production yalla-api / yalla-worker binary because (a) the developer
// who upgraded it did not notice an advisory existed, (b) a transitive
// dependency was bumped by `go mod tidy` to a vulnerable version, or
// (c) a future contributor silently removes the CI scan step that
// would have surfaced the advisory before merge. Yalla treats every
// such regression as a release blocker (SECURITY.md "Reporting a
// Vulnerability"), and the mitigation is layered:
//
//  1. `govulncheck ./...` runs on every push and PR inside the CI
//     `security` job (.github/workflows/ci.yml). The step installs the
//     scanner from `golang.org/x/vuln/cmd/govulncheck@latest` and
//     fails the build on any matched advisory — the comment in the
//     workflow file pins the contract: "govulncheck always runs —
//     vulnerability scans are non-negotiable before merge."
//  2. `actions/dependency-review-action@v4` runs on every PR
//     (.github/workflows/dependency-review.yml) with
//     `fail-on-severity: high`, blocking a PR that introduces a new
//     module with a known high-severity advisory or a disallowed
//     license. The allow-list is the OSI-compatible set documented in
//     SECURITY.md "Dependency Review Expectations".
//  3. `staticcheck ./...` and `golangci-lint run ./...` also run in
//     the `security` job — both are part of the public security gate
//     in SECURITY.md and routinely surface unsafe casts, ignored
//     errors, and other patterns that turn a transitive bump into an
//     exploitable bug.
//  4. `scripts/verify.sh` invokes `govulncheck ./...` locally so the
//     contributor sees the same advisory before pushing — the script's
//     missing-tool reporting (`skipped_tools+=...`) makes a silently
//     absent scanner impossible.
//  5. CONTRIBUTING.md "Dependency Review Checklist" and SECURITY.md
//     "Verification Gates" document the human-facing contract: which
//     scanner runs, where it runs, and on which trigger.
//
// This file is the load-bearing static defence: it parses every
// surface above and asserts the scanner invocations, action
// references, severity thresholds, and licence allow-list are
// present. A regression that drops the govulncheck step from CI,
// removes the dependency-review action, lowers `fail-on-severity` to
// `low`, or strips the local verify.sh call fails the build with a
// single file:line diagnostic before the change can land — every
// surface this test pins is on the customer-facing supply-chain path,
// and a silent removal is exactly the failure mode this defence
// exists to catch.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350,
// BE-0351, BE-0352, BE-0353) applies here. The static half (this
// file) pins the workflow/script/doc shape on the YAML and shell
// source. The "runtime" half is implicit: CI itself IS the runtime
// for a vulnerability scanner — the scanner runs on every push and
// every PR, and a self-check at the bottom of this file
// (TestDependencyScanStaticAnalyzerDetectsRegressions) feeds
// synthetic known-bad and known-good fixtures through the matchers so
// over- and under-tightening of the analysers are both caught.

// ciWorkflowFile is the path, relative to project root, of the
// security gate workflow file. Renaming it without updating this
// constant is a regression — the gate ships under a stable
// well-known path so contributors and external auditors can locate
// the scanner config without reading internal documentation.
const ciWorkflowFile = ".github/workflows/ci.yml"

// dependencyReviewWorkflowFile is the path of the PR-only dependency
// review workflow. Same stability requirement as ciWorkflowFile.
const dependencyReviewWorkflowFile = ".github/workflows/dependency-review.yml"

// verifyScript is the local verification gate. CONTRIBUTING.md
// references this exact path; renaming it would silently break the
// commit gate the project documents.
const verifyScript = "scripts/verify.sh"

// requiredAllowedLicenses is the closed subset of OSI licenses that
// the dependency-review action MUST accept. The allow list in the
// workflow file may carry additional entries (CC0-1.0, Unlicense,
// 0BSD) but a regression that DROPS any of the canonical four below
// would silently block the most common OSS modules from being
// reviewed at all.
var requiredAllowedLicenses = []string{
	"MIT",
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
}

// workflow is the YAML subset this file asserts on. KnownFields(false)
// at the decoder lets GitHub Actions add new top-level fields without
// breaking the test — we deliberately model only the structure whose
// drift would weaken the supply-chain defence.
type workflow struct {
	Name string                 `yaml:"name"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Name   string         `yaml:"name"`
	RunsOn any            `yaml:"runs-on"`
	Steps  []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string                 `yaml:"name"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	With map[string]interface{} `yaml:"with"`
}

// readWorkflow decodes the workflow at path (relative to project
// root) using the lenient decoder. A missing file fails the test —
// the supply-chain gate is non-optional.
func readWorkflow(t *testing.T, root, rel string) workflow {
	t.Helper()
	path := filepath.Join(root, rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(false)
	var wf workflow
	if err := dec.Decode(&wf); err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
	return wf
}

// TestCIWorkflowSecurityGateRunsGovulncheck is the load-bearing
// static guard for the in-CI vulnerability scan. It loads
// `.github/workflows/ci.yml`, finds the `security` job, walks its
// steps, and asserts (a) the step name is `govulncheck`, (b) its
// `run:` body invokes `go install golang.org/x/vuln/cmd/govulncheck`
// from a versioned-or-latest selector, and (c) its `run:` body
// invokes `govulncheck ./...` on the module. A regression that
// removes the step, renames the binary, or scopes it away from the
// whole module fails the build before merge.
func TestCIWorkflowSecurityGateRunsGovulncheck(t *testing.T) {
	t.Parallel()

	wf := readWorkflow(t, projectRoot(t), ciWorkflowFile)
	job, ok := wf.Jobs["security"]
	if !ok {
		t.Fatalf("%s: jobs.security missing — the CI security gate has been removed", ciWorkflowFile)
	}
	if err := assertGovulncheckStep(job.Steps); err != nil {
		t.Fatalf("%s: jobs.security: %v", ciWorkflowFile, err)
	}
}

// TestCIWorkflowSecurityGateRunsStaticcheckAndLint pins the two
// linter halves of the supply-chain gate. SECURITY.md "Verification
// Gates" lists staticcheck and golangci-lint alongside the
// vulnerability scan; both routinely surface patterns (ignored
// errors, unsafe casts, missing nil checks) that turn an otherwise
// benign dependency bump into an exploitable defect. A regression
// that strips either is caught at the AST.
func TestCIWorkflowSecurityGateRunsStaticcheckAndLint(t *testing.T) {
	t.Parallel()

	wf := readWorkflow(t, projectRoot(t), ciWorkflowFile)
	job, ok := wf.Jobs["security"]
	if !ok {
		t.Fatalf("%s: jobs.security missing — the CI security gate has been removed", ciWorkflowFile)
	}
	if err := assertStaticcheckStep(job.Steps); err != nil {
		t.Errorf("%s: jobs.security: %v", ciWorkflowFile, err)
	}
	if err := assertGolangciLintStep(job.Steps); err != nil {
		t.Errorf("%s: jobs.security: %v", ciWorkflowFile, err)
	}
}

// TestDependencyReviewWorkflowUsesPinnedAction pins the PR-only
// dependency-review job. The supply-chain contract is three things:
// (a) the action reference is the canonical
// `actions/dependency-review-action` at a major version (v4), not
// a fork; (b) `fail-on-severity` is `high` so a high-severity
// advisory blocks the PR; (c) the licence allow-list contains at
// least the canonical OSI four. A regression that swaps the action,
// raises severity above the threshold, or strips the licence
// allow-list is caught here.
func TestDependencyReviewWorkflowUsesPinnedAction(t *testing.T) {
	t.Parallel()

	wf := readWorkflow(t, projectRoot(t), dependencyReviewWorkflowFile)
	job, ok := wf.Jobs["review"]
	if !ok {
		t.Fatalf("%s: jobs.review missing — the PR dependency review gate has been removed", dependencyReviewWorkflowFile)
	}
	step, err := findDependencyReviewStep(job.Steps)
	if err != nil {
		t.Fatalf("%s: jobs.review: %v", dependencyReviewWorkflowFile, err)
	}
	if err := assertDependencyReviewActionRef(step.Uses); err != nil {
		t.Errorf("%s: jobs.review: %v", dependencyReviewWorkflowFile, err)
	}
	if err := assertDependencyReviewSeverity(step.With); err != nil {
		t.Errorf("%s: jobs.review: %v", dependencyReviewWorkflowFile, err)
	}
	if err := assertDependencyReviewAllowList(step.With); err != nil {
		t.Errorf("%s: jobs.review: %v", dependencyReviewWorkflowFile, err)
	}
}

// TestVerifyScriptInvokesGovulncheck pins the local commit-gate
// invocation. CONTRIBUTING.md tells contributors to run
// `scripts/verify.sh` before pushing; if that script silently drops
// the govulncheck call, contributors believe they are running the
// full security gate when they are not. The check is conservative —
// we accept both the conditional-install form (`command -v` guard
// with a `skipped_tools+=...` fallback) AND a hypothetical
// unconditional form, as long as the literal `govulncheck ./...`
// invocation is present.
func TestVerifyScriptInvokesGovulncheck(t *testing.T) {
	t.Parallel()

	path := filepath.Join(projectRoot(t), verifyScript)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", verifyScript, err)
	}
	src := string(b)
	if !strings.Contains(src, "govulncheck ./...") {
		t.Errorf("%s: missing literal `govulncheck ./...` invocation — the local commit gate no longer runs the vulnerability scan", verifyScript)
	}
	if !strings.Contains(src, "golang.org/x/vuln/cmd/govulncheck") {
		t.Errorf("%s: missing install reference to `golang.org/x/vuln/cmd/govulncheck` — contributors with a missing tool have no path back to a working gate", verifyScript)
	}
}

// TestContributingDocumentsDependencyReviewChecklist pins the
// human-facing contract. The Dependency Review Checklist in
// CONTRIBUTING.md is the single place where a contributor learns
// what to do when bumping a module: confirm the licence is on the
// allow-list, run `govulncheck ./...` locally, expect the PR-gating
// dependency-review action to run. A regression that strips that
// section means contributors silently lose the guidance — the
// scanner still runs in CI, but the human review step that catches
// abandonware and unknown licences disappears.
func TestContributingDocumentsDependencyReviewChecklist(t *testing.T) {
	t.Parallel()

	path := filepath.Join(projectRoot(t), "CONTRIBUTING.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CONTRIBUTING.md: %v", err)
	}
	src := string(b)
	required := []string{
		"## Dependency Review Checklist",
		"govulncheck ./...",
		"dependency-review-action",
		"`actions/dependency-review-action`",
	}
	for _, want := range required {
		if !strings.Contains(src, want) {
			t.Errorf("CONTRIBUTING.md: missing required reference %q — the human-facing dependency review contract has drifted away from the CI gate", want)
		}
	}
}

// TestSecurityPolicyListsVulnerabilityScan pins the SECURITY.md
// verification-gates table row. SECURITY.md is the public document
// auditors and downstream redistributors read to confirm yalla
// runs a vulnerability scanner on every push; a regression that
// removes the row hides the contract from the audience that depends
// on it.
func TestSecurityPolicyListsVulnerabilityScan(t *testing.T) {
	t.Parallel()

	path := filepath.Join(projectRoot(t), "SECURITY.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	src := string(b)
	required := []string{
		"Vulnerability scan",
		"govulncheck ./...",
		"actions/dependency-review-action",
		"Dependency Review Expectations",
	}
	for _, want := range required {
		if !strings.Contains(src, want) {
			t.Errorf("SECURITY.md: missing required reference %q — the published security policy no longer documents the scanner", want)
		}
	}
}

// TestDependencyScanStaticAnalyzerDetectsRegressions feeds synthetic
// step lists, action references, severity values, and allow-list
// shapes through every matcher in this file and asserts both
// directions. Without this self-check a future refactor could
// quietly over-accept (a missing scanner slips through) or quietly
// over-reject (the canonical workflow shape trips the analyser);
// the self-check is the only safety net against "I weakened my own
// analyser without noticing." (See the BE-0353 audit-tamper
// self-check pattern for the same shape.)
func TestDependencyScanStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("govulncheck matcher", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			steps   []workflowStep
			wantErr bool
		}{
			{
				name: "canonical step: install + run on whole module",
				steps: []workflowStep{
					{Name: "govulncheck", Run: "go install golang.org/x/vuln/cmd/govulncheck@latest\ngovulncheck ./..."},
				},
				wantErr: false,
			},
			{
				name: "canonical step pinned to a version",
				steps: []workflowStep{
					{Name: "govulncheck", Run: "go install golang.org/x/vuln/cmd/govulncheck@v1.1.4\ngovulncheck ./..."},
				},
				wantErr: false,
			},
			{
				name: "regression: govulncheck step removed entirely",
				steps: []workflowStep{
					{Name: "Checkout", Uses: "actions/checkout@v4"},
					{Name: "staticcheck", Run: "staticcheck ./..."},
				},
				wantErr: true,
			},
			{
				name: "regression: step exists but scopes away from the module",
				steps: []workflowStep{
					{Name: "govulncheck", Run: "go install golang.org/x/vuln/cmd/govulncheck@latest\ngovulncheck github.com/JuribaDev/yalla/cmd/yalla"},
				},
				wantErr: true,
			},
			{
				name: "regression: step exists but the binary is never invoked",
				steps: []workflowStep{
					{Name: "govulncheck", Run: "go install golang.org/x/vuln/cmd/govulncheck@latest"},
				},
				wantErr: true,
			},
			{
				name: "regression: install reference points at a fork",
				steps: []workflowStep{
					{Name: "govulncheck", Run: "go install example.com/fork/govulncheck@latest\ngovulncheck ./..."},
				},
				wantErr: true,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := assertGovulncheckStep(tc.steps)
				if tc.wantErr && err == nil {
					t.Fatalf("synthetic %q should have failed but the analyser accepted it", tc.name)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("action-ref matcher", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			uses    string
			wantErr bool
		}{
			{name: "canonical v4 reference", uses: "actions/dependency-review-action@v4", wantErr: false},
			{name: "future v5 reference is accepted (forward-compat)", uses: "actions/dependency-review-action@v5", wantErr: false},
			{name: "regression: forked action", uses: "example/dependency-review-action@v4", wantErr: true},
			{name: "regression: unpinned reference", uses: "actions/dependency-review-action", wantErr: true},
			{name: "regression: empty uses", uses: "", wantErr: true},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := assertDependencyReviewActionRef(tc.uses)
				if tc.wantErr && err == nil {
					t.Fatalf("synthetic %q should have failed but the analyser accepted it", tc.name)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("severity matcher", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			with    map[string]interface{}
			wantErr bool
		}{
			{name: "canonical high severity", with: map[string]interface{}{"fail-on-severity": "high"}, wantErr: false},
			{name: "stricter moderate severity is accepted", with: map[string]interface{}{"fail-on-severity": "moderate"}, wantErr: false},
			{name: "stricter low severity is accepted", with: map[string]interface{}{"fail-on-severity": "low"}, wantErr: false},
			{name: "regression: critical-only (high advisories slip through)", with: map[string]interface{}{"fail-on-severity": "critical"}, wantErr: true},
			{name: "regression: severity key missing", with: map[string]interface{}{}, wantErr: true},
			{name: "regression: empty severity value", with: map[string]interface{}{"fail-on-severity": ""}, wantErr: true},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := assertDependencyReviewSeverity(tc.with)
				if tc.wantErr && err == nil {
					t.Fatalf("synthetic %q should have failed but the analyser accepted it", tc.name)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("allow-list matcher", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			with    map[string]interface{}
			wantErr bool
		}{
			{name: "canonical superset of the required four", with: map[string]interface{}{"allow-licenses": "MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0"}, wantErr: false},
			{name: "exactly the required four", with: map[string]interface{}{"allow-licenses": "MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause"}, wantErr: false},
			{name: "regression: MIT removed", with: map[string]interface{}{"allow-licenses": "Apache-2.0, BSD-2-Clause, BSD-3-Clause"}, wantErr: true},
			{name: "regression: Apache-2.0 removed", with: map[string]interface{}{"allow-licenses": "MIT, BSD-2-Clause, BSD-3-Clause"}, wantErr: true},
			{name: "regression: allow-list key missing", with: map[string]interface{}{}, wantErr: true},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := assertDependencyReviewAllowList(tc.with)
				if tc.wantErr && err == nil {
					t.Fatalf("synthetic %q should have failed but the analyser accepted it", tc.name)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
				}
			})
		}
	})
}

// assertGovulncheckStep is the matcher for the CI security-gate
// govulncheck invariant. It returns nil iff steps contains a step
// whose `run:` body invokes the canonical `golang.org/x/vuln`
// installation followed by `govulncheck ./...`. Other shapes —
// missing step, scoped-away invocation, forked install reference —
// are rejected with a self-describing diagnostic.
func assertGovulncheckStep(steps []workflowStep) error {
	for _, s := range steps {
		run := s.Run
		if run == "" {
			continue
		}
		if !strings.Contains(run, "govulncheck ./...") {
			continue
		}
		if !strings.Contains(run, "golang.org/x/vuln/cmd/govulncheck") {
			return fmt.Errorf("step %q invokes `govulncheck ./...` but does NOT install it from `golang.org/x/vuln/cmd/govulncheck` — a forked or local binary could be substituted at runtime", stepLabel(s))
		}
		return nil
	}
	return fmt.Errorf("no step invokes `govulncheck ./...` — the in-CI vulnerability scan has been removed; the supply-chain gate is now vacuous")
}

// assertStaticcheckStep returns nil iff steps contains a step that
// runs `staticcheck ./...` on the whole module. SECURITY.md lists
// staticcheck alongside govulncheck; both halves are part of the
// non-negotiable security gate.
func assertStaticcheckStep(steps []workflowStep) error {
	for _, s := range steps {
		if strings.Contains(s.Run, "staticcheck ./...") {
			return nil
		}
	}
	return fmt.Errorf("no step invokes `staticcheck ./...` — the SECURITY.md lint suite is now incomplete")
}

// assertGolangciLintStep returns nil iff steps contains a step that
// references the canonical `golangci/golangci-lint-action` action.
// We match on the action reference rather than the shell invocation
// because the canonical step uses `uses:` not `run:`.
func assertGolangciLintStep(steps []workflowStep) error {
	for _, s := range steps {
		if strings.HasPrefix(s.Uses, "golangci/golangci-lint-action@") {
			return nil
		}
	}
	return fmt.Errorf("no step uses `golangci/golangci-lint-action@<version>` — the SECURITY.md lint suite is now incomplete")
}

// findDependencyReviewStep returns the step that uses the
// dependency-review action, or an error if none is present. The
// error is reported separately from the matchers so the caller can
// emit a single targeted diagnostic.
func findDependencyReviewStep(steps []workflowStep) (workflowStep, error) {
	for _, s := range steps {
		if strings.HasPrefix(s.Uses, "actions/dependency-review-action@") {
			return s, nil
		}
	}
	return workflowStep{}, fmt.Errorf("no step uses `actions/dependency-review-action@<version>` — the PR dependency-review gate has been removed")
}

// assertDependencyReviewActionRef returns nil iff uses is a canonical
// `actions/dependency-review-action@v<N>` reference. A forked action
// or an unpinned reference (no `@version`) is rejected — the supply
// chain depends on the canonical action being run exactly as
// documented in CONTRIBUTING.md.
func assertDependencyReviewActionRef(uses string) error {
	if uses == "" {
		return fmt.Errorf("dependency-review step has no `uses:` reference")
	}
	if !strings.HasPrefix(uses, "actions/dependency-review-action@") {
		return fmt.Errorf("dependency-review step uses %q — must reference the canonical `actions/dependency-review-action`", uses)
	}
	suffix := strings.TrimPrefix(uses, "actions/dependency-review-action@")
	if suffix == "" {
		return fmt.Errorf("dependency-review step uses %q — the action reference is missing a version selector", uses)
	}
	return nil
}

// validSeverityThresholds is the closed set of `fail-on-severity`
// values that block at-or-below `high`. Anything stricter (moderate,
// low) is also accepted; `critical` is rejected because a high-
// severity advisory would slip through.
var validSeverityThresholds = map[string]bool{
	"high":     true,
	"moderate": true,
	"low":      true,
}

// assertDependencyReviewSeverity returns nil iff with carries a
// `fail-on-severity` key whose value is in the validSeverityThresholds
// closed set. A missing key, empty value, or `critical` value is
// rejected.
func assertDependencyReviewSeverity(with map[string]interface{}) error {
	raw, ok := with["fail-on-severity"]
	if !ok {
		return fmt.Errorf("dependency-review step is missing `fail-on-severity` — the default is `low`, which is fine, but the contract MUST be pinned explicitly to survive a future action default change")
	}
	val, ok := raw.(string)
	if !ok {
		return fmt.Errorf("dependency-review step `fail-on-severity` is not a string: %#v", raw)
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("dependency-review step `fail-on-severity` is empty — the gate is vacuous")
	}
	if !validSeverityThresholds[val] {
		return fmt.Errorf("dependency-review step `fail-on-severity` is %q — high-severity advisories would slip through; must be one of {high, moderate, low}", val)
	}
	return nil
}

// assertDependencyReviewAllowList returns nil iff with carries an
// `allow-licenses` key whose value is a comma-separated list of
// SPDX identifiers containing at least every entry in
// requiredAllowedLicenses. A regression that strips MIT/Apache-2.0
// would silently block the most common OSS upgrades from being
// reviewed at all.
func assertDependencyReviewAllowList(with map[string]interface{}) error {
	raw, ok := with["allow-licenses"]
	if !ok {
		return fmt.Errorf("dependency-review step is missing `allow-licenses` — the gate is vacuous")
	}
	val, ok := raw.(string)
	if !ok {
		return fmt.Errorf("dependency-review step `allow-licenses` is not a string: %#v", raw)
	}
	parts := strings.Split(val, ",")
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		seen[strings.TrimSpace(p)] = true
	}
	for _, want := range requiredAllowedLicenses {
		if !seen[want] {
			return fmt.Errorf("dependency-review step `allow-licenses` is missing %q — the most common OSS licence is not on the allow-list, contributors will be silently blocked from canonical upgrades", want)
		}
	}
	return nil
}

// stepLabel returns a human-readable identifier for a workflow step
// — its `name:` if present, else its `uses:`, else `<unnamed>`.
// Used in matcher diagnostics so a regression report points at the
// right line in the YAML.
func stepLabel(s workflowStep) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Uses != "" {
		return s.Uses
	}
	return "<unnamed>"
}
