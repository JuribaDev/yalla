package migrate

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Audit log tamper resistance — migration-level sealing trap (BE-0353).
//
// Threat model: an audit_events row is the source of truth for both
// "what was done" and "what was refused". If an operator or a future
// migration could mutate an audit row after the fact — patch a reason,
// rewrite metadata, swap an actor id, add an `updated_at` column and
// quietly bump it — the audit log becomes useless as evidence. The
// store-layer AGENTS.md and the package doc on `audit.go` both pin the
// invariant in human words; this file is the load-bearing static guard
// that pins it on the migration file itself, before any code reaches a
// Postgres instance.
//
// Three load-bearing properties of `0007_audit_events.up.sql` are
// asserted here:
//
//  1. The PL/pgSQL function `audit_events_reject_update` is declared
//     and RAISEs with `ERRCODE = 'restrict_violation'`. The errcode is
//     the wire signal the runtime test in
//     `internal/controlplane/store/audit_test.go` asserts on; a future
//     edit that swaps the errcode to a friendlier classification would
//     silently change what the runtime test pins.
//  2. A BEFORE UPDATE trigger named `audit_events_no_update` fires on
//     `audit_events` `FOR EACH ROW` and `EXECUTE`s the rejection
//     function. AFTER UPDATE would let the row mutate first; STATEMENT
//     scope would not fire on the per-row UPDATE shape the runtime
//     test uses; either weakening lets tampering through.
//  3. The `CREATE TABLE audit_events` block does NOT declare an
//     `updated_at` column. The trigger blocks UPDATE at runtime; the
//     missing column blocks "add a mutation timestamp and update it on
//     write" as a design pattern. Both walls are load-bearing.
//
// The reverse migration `0007_audit_events.down.sql` is also pinned:
// it must DROP both the table (so the trigger goes with it) AND the
// rejection function (so it does not orbit unused). A re-application
// that leaves the function behind would attach it to a future
// `audit_events` recreation with subtly different semantics.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0347, BE-0348,
// BE-0349, BE-0350, BE-0351, BE-0352 sibling) applies here. The static
// half (this file) parses the migration text against four regexes and
// fails the build for any drift. The self-check
// (`TestAuditImmutabilityAnalyzerDetectsRegressions`) drives every
// matcher against synthetic known-good and known-bad inputs so a
// future over- or under-tightening is caught. The runtime half lives
// in `internal/controlplane/store/audit_test.go`
// (`TestAuditRepositoryAppendImmutability` and
// `TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation`).

// auditEventsMigrationUpPath is the migration file the trap reads.
// The path is relative to the embedded FS root (`migrations/`).
const auditEventsMigrationUpPath = "migrations/0007_audit_events.up.sql"

// auditEventsMigrationDownPath is the reverse migration.
const auditEventsMigrationDownPath = "migrations/0007_audit_events.down.sql"

// TestAuditEventsMigrationDeclaresRejectUpdateFunction pins the
// PL/pgSQL function that the trigger executes. The shape asserted
// here is "CREATE FUNCTION audit_events_reject_update() RETURNS
// trigger" with a body that RAISEs `ERRCODE = 'restrict_violation'`.
// Both the function name and the errcode are load-bearing — the name
// is what the trigger points at, the errcode is what the runtime test
// asserts on the wire.
func TestAuditEventsMigrationDeclaresRejectUpdateFunction(t *testing.T) {
	t.Parallel()

	sql := mustReadAuditMigration(t, auditEventsMigrationUpPath)
	if !hasAuditRejectUpdateFunction(sql) {
		t.Fatalf("%s: function audit_events_reject_update() is missing or its body does not RAISE with ERRCODE = 'restrict_violation'.\n"+
			"The runtime test in internal/controlplane/store/audit_test.go asserts on this errcode; a missing or renamed function silently breaks the append-only invariant.",
			auditEventsMigrationUpPath)
	}
}

// TestAuditEventsMigrationHasBeforeUpdateRowTrigger pins the trigger
// that calls the rejection function. The shape asserted is
// "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON
// audit_events FOR EACH ROW EXECUTE FUNCTION
// audit_events_reject_update()". BEFORE-vs-AFTER and ROW-vs-STATEMENT
// are both load-bearing — AFTER UPDATE would let the row mutate
// first, STATEMENT would not fire on the per-row UPDATE the runtime
// test uses.
func TestAuditEventsMigrationHasBeforeUpdateRowTrigger(t *testing.T) {
	t.Parallel()

	sql := mustReadAuditMigration(t, auditEventsMigrationUpPath)
	if !hasAuditBeforeUpdateRowTrigger(sql) {
		t.Fatalf("%s: trigger audit_events_no_update is missing or does not have shape "+
			"`CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update()`. "+
			"AFTER UPDATE or STATEMENT scope would silently allow tampering.",
			auditEventsMigrationUpPath)
	}
}

// TestAuditEventsTableHasNoUpdatedAtColumn pins the absence of an
// `updated_at` column on the `audit_events` table. The trigger blocks
// UPDATE at runtime; the missing column blocks the pattern "add a
// mutation timestamp and update it on write." Both walls are
// load-bearing: a future migration that adds `updated_at` would be a
// design-time regression even if the runtime trigger still fires.
func TestAuditEventsTableHasNoUpdatedAtColumn(t *testing.T) {
	t.Parallel()

	sql := mustReadAuditMigration(t, auditEventsMigrationUpPath)
	block, ok := extractAuditEventsCreateTableBlock(sql)
	if !ok {
		t.Fatalf("%s: CREATE TABLE audit_events block not found — the migration shape is unrecognised.",
			auditEventsMigrationUpPath)
	}
	if hasUpdatedAtColumn(block) {
		t.Fatalf("%s: the audit_events table has an updated_at column.\n"+
			"The audit log is append-only by design; a mutation timestamp would silently invite "+
			"the pattern \"update the row and bump updated_at\". Remove the column.\n"+
			"CREATE TABLE block:\n%s",
			auditEventsMigrationUpPath, block)
	}
}

// TestAuditEventsDownMigrationDropsTableAndFunction pins the reverse
// migration: it must DROP both `audit_events` (which drops the
// trigger with the table) AND `audit_events_reject_update` (so the
// function does not orbit unused, possibly attaching to a future
// audit_events recreation with subtly different semantics).
func TestAuditEventsDownMigrationDropsTableAndFunction(t *testing.T) {
	t.Parallel()

	sql := mustReadAuditMigration(t, auditEventsMigrationDownPath)
	if !hasDropAuditEventsTable(sql) {
		t.Fatalf("%s: DROP TABLE audit_events is missing — a forward-then-back cycle would leave the table behind.",
			auditEventsMigrationDownPath)
	}
	if !hasDropAuditRejectUpdateFunction(sql) {
		t.Fatalf("%s: DROP FUNCTION audit_events_reject_update is missing — the rejection function would orbit unused after a rollback.",
			auditEventsMigrationDownPath)
	}
}

// TestAuditImmutabilityAnalyzerDetectsRegressions is the self-check
// for the four matchers above. It feeds synthetic SQL snippets and
// pins both directions of each analyser: canonical shapes are
// recognised, drift shapes (renamed function, wrong errcode,
// AFTER/STATEMENT trigger, added updated_at column, missing DROP) are
// flagged. A future change that weakens any matcher fails its
// matching self-check case.
func TestAuditImmutabilityAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("hasAuditRejectUpdateFunction", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			sql  string
			want bool
		}{
			{
				name: "canonical shape is recognised",
				sql: `CREATE FUNCTION audit_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;`,
				want: true,
			},
			{
				name: "OR REPLACE shape is recognised",
				sql: `CREATE OR REPLACE FUNCTION audit_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;`,
				want: true,
			},
			{
				name: "missing function is flagged",
				sql:  `-- nothing here`,
				want: false,
			},
			{
				name: "renamed function is flagged",
				sql: `CREATE FUNCTION audit_events_block_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;`,
				want: false,
			},
			{
				name: "wrong errcode is flagged",
				sql: `CREATE FUNCTION audit_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'internal_error';
END;
$$;`,
				want: false,
			},
			{
				name: "missing errcode clause is flagged",
				sql: `CREATE FUNCTION audit_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted';
END;
$$;`,
				want: false,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := hasAuditRejectUpdateFunction(tc.sql); got != tc.want {
					t.Errorf("hasAuditRejectUpdateFunction = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("hasAuditBeforeUpdateRowTrigger", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			sql  string
			want bool
		}{
			{
				name: "canonical multi-line shape is recognised",
				sql: `CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();`,
				want: true,
			},
			{
				name: "single-line shape is recognised",
				sql:  `CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();`,
				want: true,
			},
			{
				name: "EXECUTE PROCEDURE legacy syntax is recognised",
				sql: `CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE PROCEDURE audit_events_reject_update();`,
				want: true,
			},
			{
				name: "missing trigger is flagged",
				sql:  `-- nothing here`,
				want: false,
			},
			{
				name: "AFTER UPDATE is flagged",
				sql: `CREATE TRIGGER audit_events_no_update
    AFTER UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();`,
				want: false,
			},
			{
				name: "FOR EACH STATEMENT is flagged",
				sql: `CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_update();`,
				want: false,
			},
			{
				name: "trigger on a different table is flagged",
				sql: `CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON other_table
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();`,
				want: false,
			},
			{
				name: "different EXECUTEd function is flagged",
				sql: `CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION some_other_handler();`,
				want: false,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := hasAuditBeforeUpdateRowTrigger(tc.sql); got != tc.want {
					t.Errorf("hasAuditBeforeUpdateRowTrigger = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("audit_events table block extraction and updated_at probe", func(t *testing.T) {
		t.Parallel()

		canonical := `CREATE TABLE audit_events (
    id              text        PRIMARY KEY,
    organization_id text        NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);`
		drift := `CREATE TABLE audit_events (
    id              text        PRIMARY KEY,
    organization_id text        NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);`
		// Extraction must find the canonical block.
		blk, ok := extractAuditEventsCreateTableBlock(canonical)
		if !ok {
			t.Fatalf("extractAuditEventsCreateTableBlock(canonical) failed to find the block")
		}
		if hasUpdatedAtColumn(blk) {
			t.Errorf("hasUpdatedAtColumn(canonical) = true, want false")
		}
		// Extraction must find the drift block AND flag it.
		blk, ok = extractAuditEventsCreateTableBlock(drift)
		if !ok {
			t.Fatalf("extractAuditEventsCreateTableBlock(drift) failed to find the block")
		}
		if !hasUpdatedAtColumn(blk) {
			t.Errorf("hasUpdatedAtColumn(drift) = false, want true")
		}
		// Missing CREATE TABLE block.
		if _, ok := extractAuditEventsCreateTableBlock(`-- no create table here`); ok {
			t.Errorf("extractAuditEventsCreateTableBlock(missing) = ok, want !ok")
		}
		// Updated_at appearing in a *comment* on the trigger block must
		// not falsely flag — we only scan the CREATE TABLE block.
		commentOnly := `CREATE TABLE audit_events (
    id              text        PRIMARY KEY,
    created_at      timestamptz NOT NULL DEFAULT now()
    -- intentionally no updated_at column
);`
		blk, ok = extractAuditEventsCreateTableBlock(commentOnly)
		if !ok {
			t.Fatalf("extractAuditEventsCreateTableBlock(commentOnly) failed to find the block")
		}
		if hasUpdatedAtColumn(blk) {
			t.Errorf("hasUpdatedAtColumn(commentOnly with -- comment) = true, want false; comments must not trip the probe")
		}
	})

	t.Run("down migration drops both", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			sql  string
			wantTable,
			wantFunc bool
		}{
			{
				name:      "canonical down drops both",
				sql:       `DROP TABLE IF EXISTS audit_events;` + "\n" + `DROP FUNCTION IF EXISTS audit_events_reject_update();`,
				wantTable: true,
				wantFunc:  true,
			},
			{
				name:      "no IF EXISTS still recognised",
				sql:       `DROP TABLE audit_events;` + "\n" + `DROP FUNCTION audit_events_reject_update();`,
				wantTable: true,
				wantFunc:  true,
			},
			{
				name:      "missing table drop flagged",
				sql:       `DROP FUNCTION IF EXISTS audit_events_reject_update();`,
				wantTable: false,
				wantFunc:  true,
			},
			{
				name:      "missing function drop flagged",
				sql:       `DROP TABLE IF EXISTS audit_events;`,
				wantTable: true,
				wantFunc:  false,
			},
			{
				name:      "wrong table drop flagged",
				sql:       `DROP TABLE IF EXISTS audit_events_archive;`,
				wantTable: false,
				wantFunc:  false,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := hasDropAuditEventsTable(tc.sql); got != tc.wantTable {
					t.Errorf("hasDropAuditEventsTable = %v, want %v", got, tc.wantTable)
				}
				if got := hasDropAuditRejectUpdateFunction(tc.sql); got != tc.wantFunc {
					t.Errorf("hasDropAuditRejectUpdateFunction = %v, want %v", got, tc.wantFunc)
				}
			})
		}
	})
}

// mustReadAuditMigration loads the named migration from the embedded
// FS and fails the test on a missing file. A missing file means the
// trap itself is vacuous, which is the loud-failure case we want.
func mustReadAuditMigration(t *testing.T, path string) string {
	t.Helper()
	content, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatalf("read %s: %v — the migration the audit-immutability trap depends on is missing", path, err)
	}
	return string(content)
}

// auditRejectUpdateFunctionShape pins the function declaration. The
// regex tolerates `OR REPLACE` and arbitrary whitespace, but anchors
// on the function name and on the `ERRCODE = 'restrict_violation'`
// clause inside the body — both load-bearing.
var auditRejectUpdateFunctionShape = regexp.MustCompile(
	`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+audit_events_reject_update\s*\(\s*\)\s+RETURNS\s+trigger.*?ERRCODE\s*=\s*'restrict_violation'.*?\$\$\s*;`,
)

// hasAuditRejectUpdateFunction reports whether sql contains the
// pinned function declaration. The body must reach the
// `ERRCODE = 'restrict_violation'` clause — a missing clause silently
// re-classifies the error and breaks the runtime test's wire
// contract.
func hasAuditRejectUpdateFunction(sql string) bool {
	return auditRejectUpdateFunctionShape.MatchString(sql)
}

// auditBeforeUpdateRowTriggerShape pins the trigger declaration. The
// regex anchors on the trigger name, on `BEFORE UPDATE ON
// audit_events`, on `FOR EACH ROW`, and on either
// `EXECUTE FUNCTION audit_events_reject_update` or the legacy
// `EXECUTE PROCEDURE audit_events_reject_update`. AFTER UPDATE,
// STATEMENT scope, wrong table, or a different handler each fail.
var auditBeforeUpdateRowTriggerShape = regexp.MustCompile(
	`(?is)CREATE\s+TRIGGER\s+audit_events_no_update\s+` +
		`BEFORE\s+UPDATE\s+ON\s+audit_events\s+` +
		`FOR\s+EACH\s+ROW\s+EXECUTE\s+(?:FUNCTION|PROCEDURE)\s+audit_events_reject_update\s*\(\s*\)\s*;`,
)

// hasAuditBeforeUpdateRowTrigger reports whether sql contains the
// pinned trigger.
func hasAuditBeforeUpdateRowTrigger(sql string) bool {
	return auditBeforeUpdateRowTriggerShape.MatchString(sql)
}

// auditEventsCreateTableShape locates the `CREATE TABLE
// audit_events (...)` block (parenthesised body, semicolon-
// terminated). The matcher is non-greedy across the body so a later
// `CREATE TABLE ... ;` cannot extend the match.
var auditEventsCreateTableShape = regexp.MustCompile(
	`(?is)CREATE\s+TABLE\s+audit_events\s*\((?P<body>.*?)\)\s*;`,
)

// extractAuditEventsCreateTableBlock returns the parenthesised body
// of the `CREATE TABLE audit_events (...)` statement (without the
// outer parens), or false if no such statement is present.
func extractAuditEventsCreateTableBlock(sql string) (string, bool) {
	m := auditEventsCreateTableShape.FindStringSubmatch(sql)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// updatedAtColumnLineShape recognises an `updated_at` column
// declaration line. It anchors on the column name as a SQL
// identifier (start of line or after a comma, followed by
// whitespace + a type identifier), so a comment line that *mentions*
// updated_at by name does not trip the probe. The matcher requires a
// type word after the name so it cannot match a bare identifier in
// running prose.
var updatedAtColumnLineShape = regexp.MustCompile(
	`(?im)^(?:\s|,)*updated_at\s+[a-zA-Z]`,
)

// hasUpdatedAtColumn reports whether the CREATE TABLE block declares
// an updated_at column. It is fed the parenthesised body extracted by
// extractAuditEventsCreateTableBlock, so comments outside the block
// cannot influence the result. Inside the block, the matcher anchors
// on a column declaration shape rather than a bare token, so an
// in-body `-- intentionally no updated_at` comment passes cleanly.
func hasUpdatedAtColumn(createTableBody string) bool {
	for _, line := range strings.Split(createTableBody, "\n") {
		// Skip `--` comment lines outright; PL/pgSQL line comments
		// extend to end of line.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		if updatedAtColumnLineShape.MatchString(line) {
			return true
		}
	}
	return false
}

// auditEventsDropTableShape matches the reverse migration's table
// drop. Both `DROP TABLE audit_events` and `DROP TABLE IF EXISTS
// audit_events` are accepted.
var auditEventsDropTableShape = regexp.MustCompile(
	`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?audit_events\s*;`,
)

// hasDropAuditEventsTable reports whether sql contains a DROP TABLE
// for audit_events.
func hasDropAuditEventsTable(sql string) bool {
	return auditEventsDropTableShape.MatchString(sql)
}

// auditRejectUpdateDropFunctionShape matches the reverse migration's
// function drop. Both `DROP FUNCTION` and `DROP FUNCTION IF EXISTS`
// are accepted; the trailing `()` argument list is optional because
// Postgres accepts either form.
var auditRejectUpdateDropFunctionShape = regexp.MustCompile(
	`(?is)DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?audit_events_reject_update\s*(?:\(\s*\)\s*)?;`,
)

// hasDropAuditRejectUpdateFunction reports whether sql contains a
// DROP FUNCTION for audit_events_reject_update.
func hasDropAuditRejectUpdateFunction(sql string) bool {
	return auditRejectUpdateDropFunctionShape.MatchString(sql)
}
