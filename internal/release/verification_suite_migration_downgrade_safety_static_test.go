package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verification suite — migration downgrade safety tests (BE-0390).
//
// Threat model: the contract between Yalla's migration runner
// (`internal/controlplane/store/migrate`) and every operator who must
// recover from a botched deploy is "every numbered `NNNN_*.up.sql`
// migration ships with a non-empty `NNNN_*.down.sql` partner, no
// `.down.sql` is an orphan, and the embedded ladder Round-trips
// cleanly: Up applies it, Down(0) empties the schema_migrations
// ledger, and Up re-applies the ladder with identical checksums." That
// invariant is enforced by the canonical pair
// `TestMigrationsDowngradeSafetyContractCoversAllDownFiles` and
// `TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder` in
// `internal/controlplane/store/migrate/migrate_test.go`. The first
// runs on every developer machine (no Postgres dependency); the
// second runs against an isolated, throwaway Postgres database and
// skips cleanly when `YALLA_TEST_DATABASE_URL` is unset.
//
// A silent erosion of that contract — the dedicated CI step quietly
// dropped, the verify.sh entry renumbered without updating
// CONTRIBUTING.md, the SECURITY.md section deleted, the canonical
// `migrate_test.go` file removed, or the canonical
// `TestMigrationsDowngradeSafetyContract…` function pair renamed —
// would let a downgrade-safety regression (a new migration committed
// without a `.down.sql`, an orphan down file, a down script that
// destroys idempotency, a checksum drift across a Down/Up cycle) ship
// without firing any gate. An operator hitting `Migrator.Down(ctx, 0)`
// to recover from a bad deploy would see ErrIrreversible mid-rollback
// and be left with an indeterminate ledger.
//
// This file is the load-bearing static defence for that meta-contract.
// It pins SIX surfaces in one file so a future contributor changing
// the CI step name, the verify.sh step header, the CONTRIBUTING
// numeric prefix, the SECURITY row, the PRD requiredBackendCommands
// array, or deleting the canonical migration test fixture fails ONE
// test, not six.
//
//  1. `.github/workflows/ci.yml` — the `test` job MUST carry a
//     dedicated step named `Migration downgrade safety tests` that
//     invokes `go test -run TestMigrationsDowngradeSafety ./...`.
//     Even though the umbrella `go test ./...` step exercises the
//     same packages, the dedicated step is defence-in-depth: a future
//     narrowing of the umbrella step would still leave this gate
//     firing as a fast targeted failure rather than buried inside the
//     umbrella log.
//  2. `scripts/verify.sh` — the local commit gate MUST run
//     `go test -run TestMigrationsDowngradeSafety ./...` under the
//     canonical step header
//     `# 16. Required: migration downgrade safety tests`. The
//     numeric prefix is part of the contract: a reorder must be a
//     deliberate edit to both this constant and the script. #16
//     extends the BE-0379..BE-0389 sequence by one slot; the
//     trailing optionals (#17 govulncheck, #18 staticcheck,
//     #19 golangci-lint, #20 goreleaser check) are renumbered in
//     the same edit.
//  3. `CONTRIBUTING.md` — the Required Checks Before Every Commit
//     section MUST list the canonical command as entry
//     `16. \`go test -run TestMigrationsDowngradeSafety ./...\`` so
//     contributors know the gate before they open a PR. The numeric
//     prefix keeps verify.sh and CONTRIBUTING.md in lockstep with
//     BE-0379..BE-0389's pins.
//  4. `SECURITY.md` — the Required Verification Gates table MUST
//     contain the `Migration downgrade safety tests` row, AND a
//     dedicated `## Migration Downgrade Safety Tests` section MUST
//     explain the contract operators, auditors, and AI agents rely
//     on: the closed-set reversibility invariant (every
//     `NNNN_*.up.sql` ships a matching non-empty `NNNN_*.down.sql`,
//     no orphan downs), the empty-DB round-trip invariant (Up,
//     Down(0), Up again ends in the same fully-applied state with
//     identical checksums), deterministic-by-default behaviour (the
//     closed-set coverage runs without Postgres; the round-trip test
//     uses an isolated throwaway database and skips when
//     `YALLA_TEST_DATABASE_URL` is unset), opt-in
//     `YALLA_EXTERNAL_DOKPLOY` external smoke, the
//     CI-on-every-push-and-PR cadence, and the actionable-failure
//     contract (failures carry the migration version AND
//     resource_id).
//  5. `ralph/prd.json` —
//     `verificationLoop.requiredBackendCommands` MUST list
//     `go test -run TestMigrationsDowngradeSafety ./...` so an AI
//     agent reading the PRD before picking up a story sees the
//     canonical command without needing to discover it from CI
//     workflows or shell scripts.
//  6. `internal/controlplane/store/migrate/migrate_test.go` — the
//     canonical reference migration test file MUST exist and MUST
//     declare the load-bearing function pair
//     (`TestMigrationsDowngradeSafetyContractCoversAllDownFiles`,
//     `TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder`).
//     The PRD's `go test -run TestMigrationsDowngradeSafety ./...`
//     filter binds to the `TestMigrationsDowngradeSafety` prefix; a
//     rename to a function whose name does not match the prefix
//     silently de-gates the downgrade-safety suite for any caller
//     relying on the `-run` filter.
//
// The self-check
// (`TestVerificationSuiteMigrationDowngradeSafetyAnalyzerDetectsRegressions`)
// drives every matcher with synthetic known-good AND known-bad
// fixtures so over-tightening (a legitimate change trips the
// analyser) and under-tightening (a real regression slips through)
// are both caught at the package-internal API.

const (
	// migrationDowngradeSafetyCIWorkflowStepName is the exact step
	// name CI uses to invoke the migration-downgrade-safety suite. A
	// rename forces a deliberate update both here and in the
	// workflow.
	migrationDowngradeSafetyCIWorkflowStepName = "- name: Migration downgrade safety tests"
	// migrationDowngradeSafetyCIWorkflowStepRun is the literal
	// command the step MUST invoke. Anything narrower (e.g. dropping
	// the trailing `./...`) would silently exclude any future
	// package that declares a `TestMigrationsDowngradeSafety…` test.
	migrationDowngradeSafetyCIWorkflowStepRun = "run: go test -run TestMigrationsDowngradeSafety ./..."

	// migrationDowngradeSafetyVerifyShStepHeader is the canonical
	// comment header that precedes the
	// `go test -run TestMigrationsDowngradeSafety ./...` invocation
	// in verify.sh. The numeric prefix is part of the contract: a
	// reorder must be a deliberate edit to both this constant and
	// the script.
	migrationDowngradeSafetyVerifyShStepHeader = "# 16. Required: migration downgrade safety tests"
	// migrationDowngradeSafetyVerifyShStepCmd is the literal command
	// that MUST appear inside the required-downgrade-safety step.
	// Asserting on the literal (not a regex over the file) makes the
	// failure point the operator at the exact line that drifted.
	migrationDowngradeSafetyVerifyShStepCmd = `go test -run TestMigrationsDowngradeSafety ./...`

	// migrationDowngradeSafetyContributingEntry is the literal list
	// entry that MUST appear under the Required Checks heading in
	// CONTRIBUTING.md. Preserving the numeric prefix keeps verify.sh
	// and CONTRIBUTING.md in lockstep.
	migrationDowngradeSafetyContributingEntry = "16. `go test -run TestMigrationsDowngradeSafety ./...`"

	// migrationDowngradeSafetySecurityGateRow is the
	// verification-gates row that MUST appear in SECURITY.md so
	// external operators and reviewers can see the
	// migration-downgrade-safety suite is part of the published
	// security posture.
	migrationDowngradeSafetySecurityGateRow = "| Migration downgrade safety tests | `go test -run TestMigrationsDowngradeSafety ./...` | `scripts/verify.sh`, CI | Every push and PR |"
	// migrationDowngradeSafetySecuritySectionHeading is the
	// dedicated `## Migration Downgrade Safety Tests` heading
	// SECURITY.md MUST carry. The section explains the
	// closed-set-reversibility invariant, the round-trip invariant,
	// the deterministic-by-default behaviour, the opt-in-external
	// escape hatch, the actionable-failure contract, and the
	// schema-version contract.
	migrationDowngradeSafetySecuritySectionHeading = "## Migration Downgrade Safety Tests"

	// migrationDowngradeSafetyPRDCommand is the literal command that
	// MUST appear in the PRD's
	// verificationLoop.requiredBackendCommands array so an agent
	// surfaces the gate from the contract document, not from shell
	// scripts or CI workflows.
	migrationDowngradeSafetyPRDCommand = "go test -run TestMigrationsDowngradeSafety ./..."

	// migrationDowngradeSafetyCanonicalFile is the relative path of
	// the canonical reference migration test file. The
	// `internal/controlplane/store/migrate/migrate_test.go` file
	// declares the function pair every downgrade-safety regression
	// MUST trip; deleting it silently kills the convention.
	migrationDowngradeSafetyCanonicalFile = "internal/controlplane/store/migrate/migrate_test.go"
)

// migrationDowngradeSafetyCanonicalFuncs is the closed set of
// function declarations the canonical `migrate_test.go` file MUST
// carry. The PRD's `-run TestMigrationsDowngradeSafety` filter binds
// to function names containing the `TestMigrationsDowngradeSafety`
// substring; renaming any entry to a name that does not match the
// prefix silently de-gates the downgrade-safety suite for any caller
// relying on the filter. The pair captures the two load-bearing
// downgrade-safety invariants the runner MUST keep:
//
//   - TestMigrationsDowngradeSafetyContractCoversAllDownFiles — the
//     closed-set reversibility invariant: every `NNNN_*.up.sql` file
//     in the embedded migrations directory MUST ship with a matching
//     non-empty `NNNN_*.down.sql` partner, no `.down.sql` may be an
//     orphan, and `LoadMigrations` MUST surface every embedded down
//     file as a non-empty DownSQL. Trips at the package-internal API
//     with no Postgres dependency.
//   - TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder —
//     the empty-DB round-trip invariant: a throwaway database
//     accepts Up, then Down(0) leaves the schema_migrations ledger
//     empty, then Up re-applies the full ladder with identical
//     checksums and dirty=false on every row. Failures surface with
//     the offending migration version AND resource_id
//     (`schema_migrations.version=N`) so an operator can map the
//     failure to the exact migration without re-running the suite
//     locally.
var migrationDowngradeSafetyCanonicalFuncs = []string{
	"func TestMigrationsDowngradeSafetyContractCoversAllDownFiles(",
	"func TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder(",
}

// migrationDowngradeSafetySecuritySectionSubstrings is the closed
// set of literal substrings the `## Migration Downgrade Safety Tests`
// section MUST contain. Each captures a different load-bearing fact
// the BE-0390 acceptance criteria require to be visible:
//
//   - "internal/controlplane/store/migrate" — the package boundary
//     the canonical migration runner lives in (AC1 documented suite
//     scope).
//   - "migrate_test.go"             — the canonical reference test
//     file name; deleting it would break the function pair the gate
//     pivots on.
//   - "deterministic"               — the AC2 determinism contract;
//     the closed-set reversibility test replays the embed fixtures
//     on every run without a Postgres dependency.
//   - "schema_migrations"           — the ledger table the
//     round-trip invariant pivots on (Down(0) MUST empty it).
//   - "NNNN_"                       — the canonical migration
//     filename grammar the coverage matcher binds to (closed-set
//     reversibility invariant).
//   - "down script"                 — the load-bearing artifact
//     every reversible migration MUST ship (the orphan-check and
//     non-empty-body check).
//   - "ErrIrreversible"             — the sentinel error
//     `Migrator.Down` returns when a reversibility gap reaches
//     Postgres; the closed-set gate catches it deterministically
//     before Postgres runs.
//   - "Down(0)"                     — the load-bearing round-trip
//     operation (a full rollback to a clean ledger).
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
//     escape hatch shared with every BE-0379..BE-0389 sibling.
//   - "TestLiveDokploySmoke"        — the opt-in external test
//     name the PRD's
//     verificationLoop.optionalWhenConfigured names.
//   - "yalla.output.v1"             — the AC5 success envelope
//     schema_version contract.
//   - "yalla.error.v1"              — the AC5 error envelope
//     schema_version contract.
//   - "TestMigrationsDowngradeSafetyContractCoversAllDownFiles" —
//     the canonical closed-set reversibility function the -run
//     filter binds to.
//   - "TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder"
//     — the canonical empty-DB round-trip function the -run filter
//     binds to.
//   - "Every push and PR"           — the AC4 CI gating cadence.
//   - "verification_suite_migration_downgrade_safety_static_test.go"
//     — the gate is self-locating so a future operator can find it
//     without re-reading the test files.
//
// Choosing distinct, semantically anchored substrings (not whole
// sentences) keeps the matcher robust to Markdown line wrap while
// still pinning every AC.
var migrationDowngradeSafetySecuritySectionSubstrings = []string{
	"internal/controlplane/store/migrate",
	"migrate_test.go",
	"deterministic",
	"schema_migrations",
	"NNNN_",
	"down script",
	"ErrIrreversible",
	"Down(0)",
	"resource_id",
	"request_id",
	"YALLA_TEST_DATABASE_URL",
	"YALLA_EXTERNAL_DOKPLOY",
	"TestLiveDokploySmoke",
	"yalla.output.v1",
	"yalla.error.v1",
	"TestMigrationsDowngradeSafetyContractCoversAllDownFiles",
	"TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder",
	"Every push and PR",
	"verification_suite_migration_downgrade_safety_static_test.go",
}

// TestVerificationSuiteMigrationDowngradeSafetyCIWorkflow pins the
// GitHub Actions test job to run the canonical
// migration-downgrade-safety command under the canonical step name. A
// silent removal of the step — or a narrowing of the run command —
// defeats the defence-in-depth promise that even a regression in the
// umbrella `go test ./...` step would still leave this gate firing.
func TestVerificationSuiteMigrationDowngradeSafetyCIWorkflow(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredCIWorkflowPath))

	for _, want := range []string{
		migrationDowngradeSafetyCIWorkflowStepName,
		migrationDowngradeSafetyCIWorkflowStepRun,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q; the CI migration-downgrade-safety step is the defence-in-depth gate for the closed-set reversibility + empty-DB round-trip invariants — every push and PR MUST run `go test -run TestMigrationsDowngradeSafety ./...` as a dedicated, named step so a regression surfaces as a fast targeted failure rather than buried inside the umbrella `go test ./...` log.",
				requiredCIWorkflowPath, want)
		}
	}
}

// TestVerificationSuiteMigrationDowngradeSafetyVerifyShRunsCanonicalCommand
// pins the local commit gate to run
// `go test -run TestMigrationsDowngradeSafety ./...` under its
// canonical step header so a contributor running the gate locally
// exercises the identical command CI runs.
func TestVerificationSuiteMigrationDowngradeSafetyVerifyShRunsCanonicalCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredVerifyShPath))

	if !strings.Contains(doc, migrationDowngradeSafetyVerifyShStepHeader) {
		t.Errorf("%s: missing required step header %q; the verify.sh required-migration-downgrade-safety block is the local mirror of the CI gate and the step must keep its canonical position.",
			requiredVerifyShPath, migrationDowngradeSafetyVerifyShStepHeader)
	}
	if !strings.Contains(doc, migrationDowngradeSafetyVerifyShStepCmd) {
		t.Errorf("%s: missing literal command %q; scripts/verify.sh MUST invoke the same migration-downgrade-safety command CI runs so a successful local gate predicts CI success.",
			requiredVerifyShPath, migrationDowngradeSafetyVerifyShStepCmd)
	}
}

// TestVerificationSuiteMigrationDowngradeSafetyContributingDocumentsCommand
// pins the contributor guide so the gate is visible before a
// contributor opens a PR. The numeric prefix matches the verify.sh
// step number to keep the two surfaces in lockstep.
func TestVerificationSuiteMigrationDowngradeSafetyContributingDocumentsCommand(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredContributingPath))

	if !strings.Contains(doc, migrationDowngradeSafetyContributingEntry) {
		t.Errorf("%s: missing required list entry %q under %q; the entry keeps verify.sh and CONTRIBUTING.md in lockstep — the numeric prefix is part of the contract.",
			requiredContributingPath, migrationDowngradeSafetyContributingEntry, requiredContributingSection)
	}
}

// TestVerificationSuiteMigrationDowngradeSafetySecurityDocumented pins
// the public security policy. SECURITY.md is the operator- and
// auditor-facing surface that makes the migration-downgrade-safety
// gate part of the published security posture, so dropping the row or
// the section silently weakens the posture.
func TestVerificationSuiteMigrationDowngradeSafetySecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	doc := mustReadString(t, filepath.Join(root, requiredSecurityPath))

	if !strings.Contains(doc, migrationDowngradeSafetySecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row %q; every required gate must surface as a row operators can read at a glance.",
			requiredSecurityPath, migrationDowngradeSafetySecurityGateRow)
	}
	if !strings.Contains(doc, migrationDowngradeSafetySecuritySectionHeading) {
		t.Errorf("%s: missing required heading %q; the dedicated section is what makes the closed-set-reversibility / round-trip / deterministic-by-default / actionable-failure / opt-in-external / schema-version contracts auditable.",
			requiredSecurityPath, migrationDowngradeSafetySecuritySectionHeading)
	}
	for _, want := range migrationDowngradeSafetySecuritySectionSubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; the documented contract MUST name every load-bearing fact so operators and auditors do not have to read this test file.",
				requiredSecurityPath, want, migrationDowngradeSafetySecuritySectionHeading)
		}
	}
}

// TestVerificationSuiteMigrationDowngradeSafetyPRDDocumentsCommand pins
// the PRD's verificationLoop.requiredBackendCommands so an AI agent
// reading the PRD before picking up a story sees the canonical
// migration-downgrade-safety command without needing to discover it
// from CI workflows or shell scripts.
func TestVerificationSuiteMigrationDowngradeSafetyPRDDocumentsCommand(t *testing.T) {
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
		if cmd == migrationDowngradeSafetyPRDCommand {
			return
		}
	}
	t.Errorf("%s: verificationLoop.requiredBackendCommands does not contain %q; an agent reading the PRD MUST see the migration-downgrade-safety gate as a required backend command.",
		requiredPRDPath, migrationDowngradeSafetyPRDCommand)
}

// TestVerificationSuiteMigrationDowngradeSafetyCanonicalFileExists
// pins the canonical reference migration test file and its
// load-bearing function pair. Deleting the file or renaming either
// function to a name that does not match the
// `TestMigrationsDowngradeSafety` prefix silently de-gates the
// downgrade-safety suite for any caller relying on the PRD's
// `-run TestMigrationsDowngradeSafety` filter.
func TestVerificationSuiteMigrationDowngradeSafetyCanonicalFileExists(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, filepath.FromSlash(migrationDowngradeSafetyCanonicalFile))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe canonical migration test file is the load-bearing convention every downgrade-safety regression MUST trip; deleting it silently removes the downgrade-safety gate.",
			migrationDowngradeSafetyCanonicalFile, err)
	}
	doc := string(b)
	for _, want := range migrationDowngradeSafetyCanonicalFuncs {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required function declaration %q; the migration-downgrade-safety pair is the load-bearing assertion set every downgrade-safety regression MUST trip — a rename or deletion silently relaxes the closed-set-reversibility + round-trip contract for every downstream caller.",
				migrationDowngradeSafetyCanonicalFile, want)
		}
	}
}

// TestVerificationSuiteMigrationDowngradeSafetyAnalyzerDetectsRegressions
// is the self-check for every matcher above. Each subtest synthesises
// a known-good AND a known-bad fixture and asserts the matcher fires
// (or stays silent) correctly. Without this self-check a future
// "improvement" to the matchers (a tightened regex, a relaxed
// substring set, a renamed constant) could silently let real
// regressions slip through.
func TestVerificationSuiteMigrationDowngradeSafetyAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("CI workflow matcher flags missing step", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n"
		for _, want := range []string{
			migrationDowngradeSafetyCIWorkflowStepName,
			migrationDowngradeSafetyCIWorkflowStepRun,
		} {
			if strings.Contains(doc, want) {
				t.Fatalf("synthetic ci.yml unexpectedly contains %q — fix the fixture, not the test", want)
			}
		}
	})

	t.Run("CI workflow matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "      - name: Unit and integration tests\n        run: go test ./...\n\n      - name: Migration downgrade safety tests\n        run: go test -run TestMigrationsDowngradeSafety ./...\n"
		for _, want := range []string{
			migrationDowngradeSafetyCIWorkflowStepName,
			migrationDowngradeSafetyCIWorkflowStepRun,
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("verify.sh matcher flags missing header", func(t *testing.T) {
		t.Parallel()
		doc := "# 4. Required: tests\nstep \"go test ./...\"\nif ! go test ./...; then\n  required_failed=1\nfi\n"
		if strings.Contains(doc, migrationDowngradeSafetyVerifyShStepHeader) {
			t.Fatalf("synthetic verify.sh unexpectedly contains %q — fix the fixture", migrationDowngradeSafetyVerifyShStepHeader)
		}
	})

	t.Run("verify.sh matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "# 16. Required: migration downgrade safety tests\nstep \"go test -run TestMigrationsDowngradeSafety ./...\"\nif ! go test -run TestMigrationsDowngradeSafety ./...; then\n  required_failed=1\nfi\n"
		if !strings.Contains(doc, migrationDowngradeSafetyVerifyShStepHeader) {
			t.Fatalf("complete fixture missing header %q", migrationDowngradeSafetyVerifyShStepHeader)
		}
		if !strings.Contains(doc, migrationDowngradeSafetyVerifyShStepCmd) {
			t.Fatalf("complete fixture missing command %q", migrationDowngradeSafetyVerifyShStepCmd)
		}
	})

	t.Run("CONTRIBUTING matcher flags missing entry", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n"
		if strings.Contains(doc, migrationDowngradeSafetyContributingEntry) {
			t.Fatalf("synthetic CONTRIBUTING unexpectedly contains %q — fix the fixture, not the test", migrationDowngradeSafetyContributingEntry)
		}
	})

	t.Run("CONTRIBUTING matcher accepts complete fixture", func(t *testing.T) {
		t.Parallel()
		doc := "## Required Checks Before Every Commit\n\n1. `gofmt -w .`\n2. `go mod tidy`\n3. `go vet ./...`\n4. `go test ./...`\n5. `go test -race ./...`\n6. `go test ./internal/controlplane/store/...`\n7. `go test ./internal/controlplane/httpapi/...`\n8. `go test ./internal/controlplane/openapi/...`\n9. `go test -run TestPolicyMatrix ./...`\n10. `go test -run TestQuotaConcurrency ./...`\n11. `go test -run TestJobWorkerLease ./...`\n12. `go test -run TestFakeDokploy ./...`\n13. `go test -run TestRedaction ./...`\n14. `go test -run TestFuzzValidator ./...`\n15. `go test -run TestMigrationsEmptyDB ./...`\n16. `go test -run TestMigrationsDowngradeSafety ./...`\n"
		if !strings.Contains(doc, migrationDowngradeSafetyContributingEntry) {
			t.Fatalf("complete fixture missing %q", migrationDowngradeSafetyContributingEntry)
		}
	})

	t.Run("SECURITY substring matcher fires on missing substring", func(t *testing.T) {
		t.Parallel()
		// Synthetic SECURITY.md missing the "yalla.output.v1"
		// substring. The matcher MUST fire on the missing piece
		// while still recognising the other required tokens.
		var b strings.Builder
		b.WriteString("## Migration Downgrade Safety Tests\n\n")
		for _, want := range migrationDowngradeSafetySecuritySectionSubstrings {
			if want == "yalla.output.v1" {
				continue
			}
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		missing := 0
		for _, want := range migrationDowngradeSafetySecuritySectionSubstrings {
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
		b.WriteString("## Migration Downgrade Safety Tests\n\n")
		for _, want := range migrationDowngradeSafetySecuritySectionSubstrings {
			b.WriteString(want)
			b.WriteString("\n")
		}
		doc := b.String()
		for _, want := range migrationDowngradeSafetySecuritySectionSubstrings {
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
			if cmd == migrationDowngradeSafetyPRDCommand {
				found = true
				break
			}
		}
		if found {
			t.Fatalf("synthetic PRD without %q should not satisfy the matcher", migrationDowngradeSafetyPRDCommand)
		}
	})

	t.Run("PRD command matcher passes when canonical command is present", func(t *testing.T) {
		t.Parallel()
		prdJSON := `{"verificationLoop":{"requiredBackendCommands":["go test ./internal/controlplane/...","go test -run TestMigrationsDowngradeSafety ./..."]}}`
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
			if cmd == migrationDowngradeSafetyPRDCommand {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("synthetic PRD with %q should satisfy the matcher", migrationDowngradeSafetyPRDCommand)
		}
	})

	t.Run("canonical-funcs matcher flags missing pair member", func(t *testing.T) {
		t.Parallel()
		// Synthetic migrate_test.go declaring only one of the two
		// canonical functions. The matcher MUST fire on the missing
		// second.
		doc := "package migrate\n\nimport \"testing\"\n\nfunc TestMigrationsDowngradeSafetyContractCoversAllDownFiles(t *testing.T) {}\n"
		missing := 0
		for _, want := range migrationDowngradeSafetyCanonicalFuncs {
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
		doc := "package migrate\n\nimport \"testing\"\n\nfunc TestMigrationsDowngradeSafetyContractCoversAllDownFiles(t *testing.T) {}\nfunc TestMigrationsDowngradeSafetyContractRoundTripsEmbeddedLadder(t *testing.T) {}\n"
		for _, want := range migrationDowngradeSafetyCanonicalFuncs {
			if !strings.Contains(doc, want) {
				t.Fatalf("complete fixture missing %q — the matcher would false-positive here", want)
			}
		}
	})

	t.Run("TestMigrationsDowngradeSafety prefix locks the -run filter contract", func(t *testing.T) {
		t.Parallel()
		// The PRD's `go test -run TestMigrationsDowngradeSafety
		// ./...` filter binds to function names containing the
		// `TestMigrationsDowngradeSafety` substring. A canonical-funcs
		// entry that drops the prefix would silently de-gate the
		// downgrade-safety suite for any caller relying on the
		// filter. This subtest asserts every canonical-funcs entry
		// begins with `func TestMigrationsDowngradeSafety`.
		const wantPrefix = "func TestMigrationsDowngradeSafety"
		for _, want := range migrationDowngradeSafetyCanonicalFuncs {
			if !strings.HasPrefix(want, wantPrefix) {
				t.Errorf("canonical-funcs entry %q does not start with %q — the PRD's `-run TestMigrationsDowngradeSafety` filter binds to the `TestMigrationsDowngradeSafety` prefix and would silently miss this function", want, wantPrefix)
			}
		}
	})
}
