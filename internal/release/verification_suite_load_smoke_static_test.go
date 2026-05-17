package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — load smoke tests (BE-0392).
//
// Threat model: the contract between Yalla's public bootstrap surface
// (`/healthz`, `/readyz`, `/version`) and every operator, AI agent, or
// CI gate that polls those endpoints under burst load is "every
// response carries a stable `yalla.output.v1` envelope with ok=true,
// every response carries a SafeID-clean `request_id` unique to that
// request, and no response leaks a secret-shaped substring in body or
// header even when fired by `loadSmokeWorkers *
// loadSmokeIterationsPerWorker` concurrent goroutines per endpoint."
// That invariant is enforced by the canonical pair
// `TestLoadSmokeContractCoversCoreEndpoints` and
// `TestLoadSmokeContractRunsBurstWithStableEnvelopes` in
// `internal/controlplane/httpapi/load_smoke_test.go`. Both members are
// deterministic by design — they run without Postgres and without a
// live Dokploy server — so the gate stays green on every developer
// machine. The bootstrap surface is the one part of the API that needs
// no backing infrastructure, which is why the load smoke gate can be
// deterministic-by-default rather than the
// deterministic+Postgres-required dual the migration suites use.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `load_smoke_test.go` file removed, or the canonical
// `TestLoadSmokeContract…` function pair renamed — would let a
// burst-stability regression (an unbounded handler that allocates a
// fresh logger per request, a request_id generator that silently
// collides under contention, a recently-added response header that
// echoes the inbound `Authorization` value verbatim) ship without
// firing any gate. An operator polling `/healthz` from a load
// balancer would see intermittent 5xx, repeated request_ids in
// dashboards, or — worst case — a leaked bearer token in a header
// snapshot.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical load smoke test fixture fails ONE
// test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Load smoke tests` that invokes
//     `go test -run TestLoadSmoke ./...`. Even though the umbrella
//     `go test ./...` step exercises the same packages, the
//     dedicated step is defence-in-depth: a future narrowing of the
//     umbrella step would still leave this gate firing as a fast
//     targeted failure rather than buried inside the umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestLoadSmoke ./...` under the canonical step
//     header `# 17. Required: load smoke tests`. The numeric prefix
//     is part of the contract: a reorder must be a deliberate edit
//     to both this constant and the script. #17 extends the
//     BE-0379..BE-0390 sequence by one slot; the trailing optionals
//     (#18 govulncheck, #19 staticcheck, #20 golangci-lint,
//     #21 goreleaser check) are renumbered in the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `17. \`go test -run TestLoadSmoke ./...\`` so contributors
//     know the gate before they open a PR. The numeric prefix keeps
//     verify.sh and CONTRIBUTING.md in lockstep with BE-0379..BE-0390's
//     pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Load smoke tests` row, AND a dedicated
//     `## Load Smoke Tests` section MUST explain the contract
//     operators, auditors, and AI agents rely on: the closed-set
//     bootstrap-coverage invariant (the harness MUST hit
//     `/healthz`, `/readyz`, `/version` and nothing under `/v1/`),
//     the burst-stability invariant (no 5xx, stable envelope,
//     SafeID request_id, unique request_id, no secret leak in body
//     or header), deterministic-by-default behaviour (no Postgres,
//     no live Dokploy server, no fake fixtures needed), opt-in
//     `YALLA_EXTERNAL_DOKPLOY` external smoke, the
//     CI-on-every-push-and-PR cadence, and the actionable-failure
//     contract (failures carry the offending endpoint AND the
//     observed request_id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestLoadSmoke ./...` so an AI agent reading the
//     PRD before picking up a story sees the canonical command
//     without needing to discover it from CI workflows or shell
//     scripts.
//  6. `internal/controlplane/httpapi/load_smoke_test.go` — the
//     canonical reference load smoke test file MUST exist and MUST
//     declare the load-bearing function pair
//     (`TestLoadSmokeContractCoversCoreEndpoints`,
//     `TestLoadSmokeContractRunsBurstWithStableEnvelopes`). The
//     PRD's `go test -run TestLoadSmoke ./...` filter binds to the
//     `TestLoadSmoke` prefix; a rename to a function whose name does
//     not match the prefix silently de-gates the load smoke suite
//     for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteLoadSmokeAnalyzerDetectsRegressions`) drives
// every matcher with synthetic known-good AND known-bad fixtures so
// over-tightening (a legitimate change trips the analyser) and
// under-tightening (a real regression slips through) are both caught
// at the package-internal API.

const (
	// loadSmokeCIWorkflowStepName is the exact step name CI uses to
	// invoke the load smoke suite. A rename forces a deliberate
	// update both here and in the workflow.
	loadSmokeCIWorkflowStepName = "- name: Load smoke tests"
	// loadSmokeCIWorkflowStepRun is the literal command the step
	// MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that
	// declares a `TestLoadSmoke…` test.
	loadSmokeCIWorkflowStepRun = "run: go test -run TestLoadSmoke ./..."

	// loadSmokeVerifyShStepHeader is the canonical comment header
	// that precedes the `go test -run TestLoadSmoke ./...`
	// invocation in verify.sh. The numeric prefix is part of the
	// contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	loadSmokeVerifyShStepHeader = "# 17. Required: load smoke tests"
	// loadSmokeVerifyShStepCmd is the literal command that MUST
	// appear inside the required-load-smoke step. Asserting on the
	// literal (not a regex over the file) makes the failure point
	// the operator at the exact line that drifted.
	loadSmokeVerifyShStepCmd = `go test -run TestLoadSmoke ./...`

	// loadSmokeContributingEntry is the literal list entry that MUST
	// appear under the Required Checks heading in CONTRIBUTING.md.
	// Preserving the numeric prefix keeps verify.sh and
	// CONTRIBUTING.md in lockstep.
	loadSmokeContributingEntry = "17. `go test -run TestLoadSmoke ./...`"

	// loadSmokeSecurityGateRow is the verification-gates row that
	// MUST appear in SECURITY.md so external operators and reviewers
	// can see the load smoke suite is part of the published security
	// posture.
	loadSmokeSecurityGateRow = "| Load smoke tests | `go test -run TestLoadSmoke ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// loadSmokeSecuritySectionHeading is the dedicated
	// `## Load Smoke Tests` heading SECURITY.md MUST carry. The
	// section explains the closed-set bootstrap-coverage invariant,
	// the burst-stability invariant, the deterministic-by-default
	// behaviour, the opt-in-external escape hatch, the
	// actionable-failure contract, and the schema-version contract.
	loadSmokeSecuritySectionHeading = "## Load Smoke Tests"

	// loadSmokePRDCommand is the literal command that MUST appear in
	// the PRD's verificationLoop.requiredBackendCommands array so an
	// agent surfaces the gate from the contract document, not from
	// shell scripts or CI workflows.
	loadSmokePRDCommand = "go test -run TestLoadSmoke ./..."

	// loadSmokeCanonicalFile is the relative path of the canonical
	// reference load smoke test file. The
	// `internal/controlplane/httpapi/load_smoke_test.go` file
	// declares the function pair every load-smoke regression MUST
	// trip; deleting it silently kills the convention.
	loadSmokeCanonicalFile = "internal/controlplane/httpapi/load_smoke_test.go"
)

// loadSmokeCanonicalFuncs is the closed set of function declarations
// the canonical `load_smoke_test.go` file MUST carry. The PRD's
// `-run TestLoadSmoke` filter binds to function names containing the
// `TestLoadSmoke` substring; renaming any entry to a name that does
// not match the prefix silently de-gates the load smoke suite for any
// caller relying on the filter. The pair captures the two
// load-bearing load-smoke invariants the harness MUST keep:
//
//   - TestLoadSmokeContractCoversCoreEndpoints — the closed-set
//     bootstrap-coverage invariant: the endpoint table the burst
//     harness iterates MUST stay non-empty, free of duplicates,
//     scoped to the bootstrap surface (`/healthz`, `/readyz`,
//     `/version`, nothing under `/v1/`), and every entry MUST carry
//     a valid HTTP method. Trips at the package-internal API with no
//     infrastructure dependency.
//   - TestLoadSmokeContractRunsBurstWithStableEnvelopes — the burst
//     stability invariant: spinning the public HTTP handler up
//     in-process and firing `loadSmokeWorkers *
//     loadSmokeIterationsPerWorker` concurrent requests per endpoint
//     MUST yield only responses that (a) return the canonical
//     status, (b) carry a stable yalla.output.v1 envelope with
//     ok=true, (c) carry a SafeID-clean request_id, (d) carry a
//     request_id unique across the whole burst, and (e) contain no
//     secret-shaped substring in body or header. Failures surface
//     with the offending endpoint AND the observed request_id so an
//     operator can correlate.
var loadSmokeCanonicalFuncs = []string{
	"func TestLoadSmokeContractCoversCoreEndpoints(",
	"func TestLoadSmokeContractRunsBurstWithStableEnvelopes(",
}

// loadSmokeSecuritySectionSubstrings is the closed set of literal
// substrings the `## Load Smoke Tests` section MUST contain. Each
// captures a different load-bearing fact the BE-0392 acceptance
// criteria require to be visible:
//
//   - "internal/controlplane/httpapi" — the package boundary the
//     canonical load smoke harness lives in (AC1 documented suite
//     scope).
//   - "load_smoke_test.go"          — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"               — the AC2 determinism contract;
//     the closed-set coverage member and the burst member both run
//     without any infrastructure dependency.
//   - "bootstrap surface"           — the load-bearing scope rule:
//     the harness MUST hit only paths that need no backing state.
//   - "/healthz"                    — one of the closed-set
//     endpoints the burst harness MUST exercise.
//   - "/readyz"                     — one of the closed-set
//     endpoints the burst harness MUST exercise.
//   - "/version"                    — one of the closed-set
//     endpoints the burst harness MUST exercise.
//   - "request_id"                  — the AC3 actionable-failure
//     identifier (failures carry the observed request_id so
//     operators can correlate).
//   - "yalla.output.v1"             — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"              — the AC5 error envelope
//     schema_version contract.
//   - "TestLoadSmokeContractCoversCoreEndpoints" — the canonical
//     closed-set coverage function the -run filter binds to.
//   - "TestLoadSmokeContractRunsBurstWithStableEnvelopes" — the
//     canonical burst function the -run filter binds to.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC2 opt-in-external
//     escape hatch shared with every BE-0379..BE-0391 sibling.
//   - "redacted"                    — the AC8 redaction contract;
//     the burst harness asserts no secret-shaped substring leaks in
//     body or header.
//   - "fake Dokploy"                — the AC7 fake-fixture contract;
//     the gate must never require a live Dokploy server.
//   - "verification_suite_load_smoke_static_test.go" — the gate is
//     self-locating so a future operator can find it without
//     re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var loadSmokeSecuritySectionSubstrings = []string{
	"internal/controlplane/httpapi",
	"load_smoke_test.go",
	"deterministic",
	"bootstrap surface",
	"/healthz",
	"/readyz",
	"/version",
	"request_id",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestLoadSmokeContractCoversCoreEndpoints",
	"TestLoadSmokeContractRunsBurstWithStableEnvelopes",
	"Every push and PR",
	"YALLA_EXTERNAL_DOKPLOY",
	"redacted",
	"fake Dokploy",
	"verification_suite_load_smoke_static_test.go",
}

// TestVerificationSuiteLoadSmokeCIWorkflow pins the GitHub Actions
// test job to run the canonical load-smoke command under the
// canonical step name. A silent removal of the step — or a narrowing
// of the run command — defeats the defence-in-depth promise that even
// a regression in the umbrella `go test ./...` step would still leave
// this gate firing.
func TestVerificationSuiteLoadSmokeCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		loadSmokeCIWorkflowStepName,
		loadSmokeCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI load-smoke step is the defence-in-depth gate for the closed-set bootstrap-coverage + burst-stability invariants — every push and PR MUST run `go test -run TestLoadSmoke ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteLoadSmokeVerifyShRunsCanonicalCommand pins the
// local commit gate to run `go test -run TestLoadSmoke ./...` under
// its canonical step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteLoadSmokeVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, loadSmokeVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-load-smoke block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, loadSmokeVerifyShStepHeader)
	}
	if !strings.Contains(doc, loadSmokeVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same load-smoke command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, loadSmokeVerifyShStepCmd)
	}
}

// TestVerificationSuiteLoadSmokeContributingDocumentsCommand pins the
// contributor guide so the gate is visible before a contributor opens
// a PR. The numeric prefix matches the verify.sh step number to keep
// the two surfaces in lockstep.
func TestVerificationSuiteLoadSmokeContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, loadSmokeContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, loadSmokeContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteLoadSmokeSecurityDocumented pins the public
// security policy. SECURITY.md is the operator- and auditor-facing
// surface that makes the load-smoke gate part of the published
// security posture, so dropping the row or the section silently
// weakens the posture.
func TestVerificationSuiteLoadSmokeSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, loadSmokeSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, loadSmokeSecurityGateRow)
	}
	if !strings.Contains(doc, loadSmokeSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-bootstrap-coverage / burst-stability / deterministic-by-default / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, loadSmokeSecuritySectionHeading)
	}
	for _, want := range loadSmokeSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, loadSmokeSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteLoadSmokePRDDocumentsCommand pins the PRD's
// verificationLoop.requiredBackendCommands so an AI agent reading the
// PRD before picking up a story sees the canonical load-smoke command
// without needing to discover it from CI workflows or shell scripts.
func TestVerificationSuiteLoadSmokePRDDocumentsCommand(t *testing.T) {
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
		if cmd == loadSmokePRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the load-smoke gate as a required backend command.",
		requiredPRDPath, loadSmokePRDCommand)
}

// TestVerificationSuiteLoadSmokeCanonicalFileExists pins the canonical
// reference load smoke test file and its load-bearing function pair.
// Deleting the file or renaming either function to a name that does
// not match the `TestLoadSmoke` prefix silently de-gates the
// load-smoke suite for any caller relying on the PRD's
// `-run TestLoadSmoke` filter.
func TestVerificationSuiteLoadSmokeCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(loadSmokeCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical load smoke test file is the load-bearing convention every load-smoke regression MUST trip; deleting it silently removes the load-smoke gate.",
			loadSmokeCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range loadSmokeCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the load-smoke pair is the load-bearing assertion set every load-smoke regression MUST trip — a rename or deletion silently relaxes the closed-set-bootstrap-coverage + burst-stability contract for every downstream caller.",
				loadSmokeCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteLoadSmokeAnalyzerDetectsRegressions is the
// self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteLoadSmokeAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			loadSmokeCIWorkflowStepName,
			loadSmokeCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Load smoke tests\n        run: go test -run TestLoadSmoke ./...\n"
		for _, want := range []string{
			loadSmokeCIWorkflowStepName,
			loadSmokeCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, loadSmokeVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", loadSmokeVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 17. Required: load smoke tests\nstep \"go test -run TestLoadSmoke ./...\"\nif ! go test -run TestLoadSmoke ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, loadSmokeVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", loadSmokeVerifyShStepHeader)
		}
		if !strings.Contains(doc, loadSmokeVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", loadSmokeVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n16. `go test -run TestMigrationsDowngradeSafety ./...`\n"
		if strings.Contains(doc, loadSmokeContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", loadSmokeContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n16. `go test -run TestMigrationsDowngradeSafety ./...`\n17. `go test -run TestLoadSmoke ./...`\n"
		if !strings.Contains(doc, loadSmokeContributingEntry) {
			t.Fatalf("complete fixture missing %q", loadSmokeContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Load Smoke Tests\n\n")
		for _, want := range loadSmokeSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range loadSmokeSecuritySectionSubstrings {
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
		b.WriteString("## Load Smoke Tests\n\n")
		for _, want := range loadSmokeSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range loadSmokeSecuritySectionSubstrings {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("PRD command matcher fires when canonical command is absent", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestMigrationsEmptyDB ./..."]}}`
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
			if cmd == loadSmokePRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", loadSmokePRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestLoadSmoke ./..."]}}`
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
			if cmd == loadSmokePRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", loadSmokePRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic load_smoke_test.go declaring only one of the
		// two canonical functions. The matcher MUST fire on the
		// missing second.
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestLoadSmokeContractCoversCoreEndpoints(t *testing.T) {}\n"
		missing := 0
		for _, want := range loadSmokeCanonicalFuncs {
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
		doc := "package httpapi\n\nimport \"testing\"\n\nfunc TestLoadSmokeContractCoversCoreEndpoints(t *testing.T) {}\nfunc TestLoadSmokeContractRunsBurstWithStableEnvelopes(t *testing.T) {}\n"
		for _, want := range loadSmokeCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestLoadSmoke prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestLoadSmoke ./...` filter binds
		// to function names containing the `TestLoadSmoke`
		// substring. A canonical-funcs entry that drops the prefix
		// would silently de-gate the load smoke suite for any
		// caller relying on the filter. This subtest asserts every
		// canonical-funcs entry begins with `func TestLoadSmoke`.
		const wantPrefix = "func TestLoadSmoke"
		for _, want := range loadSmokeCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestLoadSmoke` filter binds to the `TestLoadSmoke` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
