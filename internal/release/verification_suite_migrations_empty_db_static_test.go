package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — migration tests from empty DB (BE-0389).
//
// Threat model: the contract between Yalla's migration runner
// (`internal/controlplane/store/migrate`) and every operator booting a
// fresh control-plane database is "every numbered `NNNN_*.up.sql` file
// surfaces as a loaded Migration, the embedded ladder applies cleanly
// to an empty Postgres database in order, the schema_migrations ledger
// ends with one clean row per migration, and a second Up is a no-op."
// That invariant is enforced by the canonical pair
// `TestMigrationsEmptyDBContractCoversAllNumberedFiles` and
// `TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`
// in `internal/controlplane/store/migrate/migrate_test.go`. The first
// runs on every developer machine (no Postgres dependency); the second
// runs against an isolated, throwaway Postgres database and skips
// cleanly when `YALLA_TEST_DATABASE_URL` is unset.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `migrate_test.go` file removed, or the canonical
// `TestMigrationsEmptyDBContract…` function pair renamed — would let a
// migration-runner regression (a new migration that fails on an empty
// database, a partial row left after a rollback, a checksum drift, a
// missing baseline) ship without firing any gate.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical migration test fixture fails ONE
// test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Migration tests from empty DB` that
//     invokes `go test -run TestMigrationsEmptyDB ./...`. Even though
//     the umbrella `go test ./...` step exercises the same packages,
//     the dedicated step is defence-in-depth: a future narrowing of
//     the umbrella step (e.g. `go test ./internal/...` minus
//     controlplane/store/migrate) would still leave this gate firing
//     as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestMigrationsEmptyDB ./...` under the canonical
//     step header `# 15. Required: migration tests from empty DB`.
//     The numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `15. \`go test -run TestMigrationsEmptyDB ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0388's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Migration tests from empty DB` row, AND a
//     dedicated `## Migration Tests From Empty DB` section MUST
//     explain the contract operators, auditors, and AI agents rely
//     on: the closed-set coverage invariant (every `NNNN_*.up.sql`
//     file becomes a loaded Migration), the applies-cleanly invariant
//     (the embedded ladder applies in order with no dirty rows left
//     behind), deterministic-by-default behaviour (the closed-set
//     coverage runs without Postgres; the apply test uses an isolated
//     throwaway database and skips when `YALLA_TEST_DATABASE_URL` is
//     unset), opt-in `YALLA_EXTERNAL_DOKPLOY` external smoke, the
//     CI-on-every-push-and-PR cadence, and the actionable-failure
//     contract (failures carry the migration version AND
//     resource_id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestMigrationsEmptyDB ./...` so an AI agent
//     reading the PRD before picking up a story sees the canonical
//     command without needing to discover it from CI workflows or
//     shell scripts.
//  6. `internal/controlplane/store/migrate/migrate_test.go` — the
//     canonical reference migration test file MUST exist and MUST
//     declare the load-bearing function pair
//     (`TestMigrationsEmptyDBContractCoversAllNumberedFiles`,
//     `TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase`).
//     The PRD's `go test -run TestMigrationsEmptyDB ./...` filter
//     binds to the `TestMigrationsEmptyDB` prefix; a rename to a
//     function whose name does not match the prefix silently de-gates
//     the empty-DB suite for any caller relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteMigrationsEmptyDBAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// migrationsEmptyDBCIWorkflowStepName is the exact step name CI
	// uses to invoke the migrations-from-empty-DB suite. A rename
	// forces a deliberate update both here and in the workflow.
	migrationsEmptyDBCIWorkflowStepName = "- name: Migration tests from empty DB"
	// migrationsEmptyDBCIWorkflowStepRun is the literal command the
	// step MUST invoke. Anything narrower (e.g. dropping the trailing
	// `./...`) would silently exclude any future package that declares
	// a `TestMigrationsEmptyDB…` test.
	migrationsEmptyDBCIWorkflowStepRun = "run: go test -run TestMigrationsEmptyDB ./..."

	// migrationsEmptyDBVerifyShStepHeader is the canonical comment
	// header that precedes the `go test -run TestMigrationsEmptyDB
	// ./...` invocation in verify.sh. The numeric prefix is part of
	// the contract: a reorder must be a deliberate edit to both this
	// constant and the script.
	migrationsEmptyDBVerifyShStepHeader = "# 15. Required: migration tests from empty DB"
	// migrationsEmptyDBVerifyShStepCmd is the literal command that MUST
	// appear inside the required-migration step. Asserting on the
	// literal (not a regex over the file) makes the failure point the
	// operator at the exact line that drifted.
	migrationsEmptyDBVerifyShStepCmd = `go test -run TestMigrationsEmptyDB ./...`

	// migrationsEmptyDBContributingEntry is the literal list entry
	// that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	migrationsEmptyDBContributingEntry = "15. `go test -run TestMigrationsEmptyDB ./...`"

	// migrationsEmptyDBSecurityGateRow is the verification-gates row
	// that MUST appear in SECURITY.md so external operators and
	// reviewers can see the migrations-from-empty-DB suite is part of
	// the published security posture.
	migrationsEmptyDBSecurityGateRow = "| Migration tests from empty DB | `go test -run TestMigrationsEmptyDB ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// migrationsEmptyDBSecuritySectionHeading is the dedicated
	// `## Migration Tests From Empty DB` heading SECURITY.md MUST
	// carry. The section explains the closed-set-coverage invariant,
	// the applies-cleanly invariant, the deterministic-by-default
	// behaviour, the opt-in-external escape hatch, the
	// actionable-failure contract, and the schema-version contract.
	migrationsEmptyDBSecuritySectionHeading = "## Migration Tests From Empty DB"

	// migrationsEmptyDBPRDCommand is the literal command that MUST
	// appear in the PRD's verificationLoop.requiredBackendCommands
	// array so an agent surfaces the gate from the contract document,
	// not from shell scripts or CI workflows.
	migrationsEmptyDBPRDCommand = "go test -run TestMigrationsEmptyDB ./..."

	// migrationsEmptyDBCanonicalFile is the relative path of the
	// canonical reference migration test file. The
	// `internal/controlplane/store/migrate/migrate_test.go` file
	// declares the function pair every migration-runner regression
	// MUST trip; deleting it silently kills the convention.
	migrationsEmptyDBCanonicalFile = "internal/controlplane/store/migrate/migrate_test.go"
)

// migrationsEmptyDBCanonicalFuncs is the closed set of function
// declarations the canonical `migrate_test.go` file MUST carry. The
// PRD's `-run TestMigrationsEmptyDB` filter binds to function names
// containing the `TestMigrationsEmptyDB` substring; renaming any entry
// to a name that does not match the prefix silently de-gates the
// empty-DB suite for any caller relying on the filter. The pair
// captures the two load-bearing migration invariants the runner MUST
// keep:
//
//   - TestMigrationsEmptyDBContractCoversAllNumberedFiles — the
//     closed-set coverage invariant: every `NNNN_*.up.sql` file in
//     the embedded migrations directory MUST surface as a loaded
//     Migration, strictly ascending and gap-free from version 1. A
//     new file added without the loader picking it up — or a
//     numbered file accidentally renamed to a non-numbered form —
//     trips this matcher at the package-internal API with no
//     Postgres dependency.
//   - TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase
//     — the applies-cleanly runtime invariant: a throwaway database
//     accepts the embedded ladder in order, the schema_migrations
//     ledger ends with one clean row per migration (correct
//     checksum, dirty=false), and a second Up is a no-op. Failures
//     surface with the offending migration version AND resource_id
//     (`schema_migrations.version=N`) so an operator can map the
//     failure to the exact migration without re-running the suite
//     locally.
var migrationsEmptyDBCanonicalFuncs = []string{
	"func TestMigrationsEmptyDBContractCoversAllNumberedFiles(",
	"func TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase(",
}

// migrationsEmptyDBSecuritySectionSubstrings is the closed set of
// literal substrings the `## Migration Tests From Empty DB` section
// MUST contain. Each captures a different load-bearing fact the
// BE-0389 acceptance criteria require to be visible:
//
//   - "internal/controlplane/store/migrate" — the package boundary
//     the canonical migration runner lives in (AC1 documented suite
//     scope).
//   - "migrate_test.go"             — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"               — the AC2 determinism contract;
//     the closed-set coverage test replays the embed fixtures on
//     every run without a Postgres dependency.
//   - "schema_migrations"           — the ledger table the
//     applies-cleanly invariant pivots on (every embedded migration
//     MUST land as one clean row).
//   - "NNNN_"                       — the canonical migration
//     filename grammar the coverage matcher binds to (closed-set
//     coverage invariant).
//   - "empty database"              — the load-bearing scenario
//     (fresh deploy starts here; every migration MUST apply
//     cleanly).
//   - "resource_id"                 — the AC3 actionable-failure
//     identifier (failures carry `schema_migrations.version=N` so
//     operators can map the failure to the exact migration).
//   - "request_id"                  — the AC3 actionable-failure
//     identifier surfaced when migrations run through an admin
//     endpoint or worker job (the downstream contract).
//   - "YALLA_TEST_DATABASE_URL"     — the AC2 deterministic-skip
//     environment variable (no Postgres = clean skip, no false
//     failure).
//   - "YALLA_EXTERNAL_DOKPLOY"      — the AC2 opt-in-external
//     escape hatch shared with every BE-0379..BE-0388 sibling.
//   - "TestLiveDokploySmoke"        — the opt-in external test
//     name the PRD's
//     verificationLoop.optionalWhenConfigured names.
//   - "yalla.output.v1"             — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"              — the AC5 error envelope
//     schema_version contract.
//   - "TestMigrationsEmptyDBContractCoversAllNumberedFiles" — the
//     canonical closed-set coverage function the -run filter binds
//     to.
//   - "TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase"
//     — the canonical applies-cleanly runtime function the -run
//     filter binds to.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "verification_suite_migrations_empty_db_static_test.go" — the
//     gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var migrationsEmptyDBSecuritySectionSubstrings = []string{
	"internal/controlplane/store/migrate",
	"migrate_test.go",
	"deterministic",
	"schema_migrations",
	"NNNN_",
	"empty database",
	"resource_id",
	"request_id",
	"YALLA_TEST_DATABASE_URL",
	"YALLA_EXTERNAL_DOKPLOY",
	"TestLiveDokploySmoke",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestMigrationsEmptyDBContractCoversAllNumberedFiles",
	"TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase",
	"Every push and PR",
	"verification_suite_migrations_empty_db_static_test.go",
}

// TestVerificationSuiteMigrationsEmptyDBCIWorkflow pins the GitHub
// Actions test job to run the canonical migrations-from-empty-DB
// command under the canonical step name. A silent removal of the step
// — or a narrowing of the run command — defeats the defence-in-depth
// promise that even a regression in the umbrella `go test ./...` step
// would still leave this gate firing.
func TestVerificationSuiteMigrationsEmptyDBCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		migrationsEmptyDBCIWorkflowStepName,
		migrationsEmptyDBCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI migrations-from-empty-DB step is the defence-in-depth gate for the closed-set coverage + applies-cleanly invariants — every push and PR MUST run `go test -run TestMigrationsEmptyDB ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteMigrationsEmptyDBVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestMigrationsEmptyDB ./...` under its canonical step
// header so a contributor running the gate locally exercises the
// identical command CI runs.
func TestVerificationSuiteMigrationsEmptyDBVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, migrationsEmptyDBVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-migrations-from-empty-DB block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, migrationsEmptyDBVerifyShStepHeader)
	}
	if !strings.Contains(doc, migrationsEmptyDBVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same migrations-from-empty-DB command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, migrationsEmptyDBVerifyShStepCmd)
	}
}

// TestVerificationSuiteMigrationsEmptyDBContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteMigrationsEmptyDBContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, migrationsEmptyDBContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, migrationsEmptyDBContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteMigrationsEmptyDBSecurityDocumented pins the
// public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the migrations-from-empty-DB gate
// part of the published security posture, so dropping the row or the
// section silently weakens the posture.
func TestVerificationSuiteMigrationsEmptyDBSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, migrationsEmptyDBSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, migrationsEmptyDBSecurityGateRow)
	}
	if !strings.Contains(doc, migrationsEmptyDBSecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-coverage / applies-cleanly / deterministic-by-default / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, migrationsEmptyDBSecuritySectionHeading)
	}
	for _, want := range migrationsEmptyDBSecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, migrationsEmptyDBSecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteMigrationsEmptyDBPRDDocumentsCommand pins the
// PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// migrations-from-empty-DB command without needing to discover it
// from CI workflows or shell scripts.
func TestVerificationSuiteMigrationsEmptyDBPRDDocumentsCommand(t *testing.T) {
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
		if cmd == migrationsEmptyDBPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the migrations-from-empty-DB gate as a required backend command.",
		requiredPRDPath, migrationsEmptyDBPRDCommand)
}

// TestVerificationSuiteMigrationsEmptyDBCanonicalFileExists pins the
// canonical reference migration test file and its load-bearing
// function pair. Deleting the file or renaming either function to a
// name that does not match the `TestMigrationsEmptyDB` prefix silently
// de-gates the empty-DB suite for any caller relying on the PRD's
// `-run TestMigrationsEmptyDB` filter.
func TestVerificationSuiteMigrationsEmptyDBCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(migrationsEmptyDBCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical migration test file is the load-bearing convention every migration-runner regression MUST trip; deleting it silently removes the empty-DB gate.",
			migrationsEmptyDBCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range migrationsEmptyDBCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the migrations-from-empty-DB pair is the load-bearing assertion set every migration-runner regression MUST trip — a rename or deletion silently relaxes the closed-set-coverage + applies-cleanly contract for every downstream caller.",
				migrationsEmptyDBCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteMigrationsEmptyDBAnalyzerDetectsRegressions is
// the self-check for every matcher above. Each subtest synthesises a
// known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteMigrationsEmptyDBAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			migrationsEmptyDBCIWorkflowStepName,
			migrationsEmptyDBCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Migration tests from empty DB\n        run: go test -run TestMigrationsEmptyDB ./...\n"
		for _, want := range []string{
			migrationsEmptyDBCIWorkflowStepName,
			migrationsEmptyDBCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, migrationsEmptyDBVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", migrationsEmptyDBVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 15. Required: migration tests from empty DB\nstep \"go test -run TestMigrationsEmptyDB ./...\"\nif ! go test -run TestMigrationsEmptyDB ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, migrationsEmptyDBVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", migrationsEmptyDBVerifyShStepHeader)
		}
		if !strings.Contains(doc, migrationsEmptyDBVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", migrationsEmptyDBVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n"
		if strings.Contains(doc, migrationsEmptyDBContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", migrationsEmptyDBContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n"
		if !strings.Contains(doc, migrationsEmptyDBContributingEntry) {
			t.Fatalf("complete fixture missing %q", migrationsEmptyDBContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Migration Tests From Empty DB\n\n")
		for _, want := range migrationsEmptyDBSecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range migrationsEmptyDBSecuritySectionSubstrings {
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
		b.WriteString("## Migration Tests From Empty DB\n\n")
		for _, want := range migrationsEmptyDBSecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range migrationsEmptyDBSecuritySectionSubstrings {
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
			if cmd == migrationsEmptyDBPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", migrationsEmptyDBPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
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
			if cmd == migrationsEmptyDBPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", migrationsEmptyDBPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic migrate_test.go declaring only one of the two
		// canonical functions. The matcher MUST fire on the missing
		// second.
		doc := "package migrate\n\nimport \"testing\"\n\nfunc TestMigrationsEmptyDBContractCoversAllNumberedFiles(t *testing.T) {}\n"
		missing := 0
		for _, want := range migrationsEmptyDBCanonicalFuncs {
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
		doc := "package migrate\n\nimport \"testing\"\n\nfunc TestMigrationsEmptyDBContractCoversAllNumberedFiles(t *testing.T) {}\nfunc TestMigrationsEmptyDBContractAppliesEmbeddedLadderToEmptyDatabase(t *testing.T) {}\n"
		for _, want := range migrationsEmptyDBCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestMigrationsEmptyDB prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestMigrationsEmptyDB ./...` filter
		// binds to function names containing the
		// `TestMigrationsEmptyDB` substring. A canonical-funcs entry
		// that drops the prefix would silently de-gate the empty-DB
		// suite for any caller relying on the filter. This subtest
		// asserts every canonical-funcs entry begins with
		// `func TestMigrationsEmptyDB`.
		const wantPrefix = "func TestMigrationsEmptyDB"
		for _, want := range migrationsEmptyDBCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestMigrationsEmptyDB` filter binds to the `TestMigrationsEmptyDB` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
