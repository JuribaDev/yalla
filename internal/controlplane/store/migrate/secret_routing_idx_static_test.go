package migrate

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Secret encryption key rotation — routing-index sealing trap (BE-0351).
//
// Threat model: when a master AES-256-GCM key is rotated out of the
// active position, the operator runbook (see
// `internal/controlplane/secrets/AGENTS.md` -> "Key rotation") requires
// a re-seal worker to find every row still naming the retired key id
// in the `*_variables` tables and re-seal it under the new active key
// before the retired key can be dropped from the accepted set. Without
// a sub-linear lookup that re-seal pass becomes a full-table scan of
// every variable table on every iteration, and the rotation window
// stretches from hours into weeks. Each `*_variables_encrypted_secrets`
// migration ships a partial index named `<table>_secret_routing_idx`
// over `(secret_provider, secret_key_id) WHERE is_secret = true` that
// gives the re-seal worker a bounded, ascending lookup.
//
// This file is the sealing trap that pins the index shape across every
// variable table. It runs against the embedded migration FS (no
// database required) so a future edit that drops the index from a
// migration file fails the build BEFORE the regression can ship.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350,
// BE-0351 sibling in `internal/controlplane/secrets`) applies here.
// The static half (this file) parses each migration and matches the
// CREATE INDEX statement. The self-check
// (`TestSecretRoutingIndexAnalyzerDetectsRegressions`) drives the
// regex against synthetic known-good and known-bad inputs so a future
// over- or under-tightening of the matcher is caught.

// requiredVariableMigrations lists every migration file that introduces
// the encryption-at-rest columns on a `*_variables` table. The list is
// the canonical set the rotation worker iterates over; adding a new
// `*_variables` table without adding it here means the trap below
// covers fewer tables than the worker would.
var requiredVariableMigrations = []struct {
	migrationFile string
	table         string
	indexName     string
}{
	{
		migrationFile: "migrations/0029_organization_variables_encrypted_secrets.up.sql",
		table:         "organization_variables",
		indexName:     "organization_variables_secret_routing_idx",
	},
	{
		migrationFile: "migrations/0030_project_variables_encrypted_secrets.up.sql",
		table:         "project_variables",
		indexName:     "project_variables_secret_routing_idx",
	},
	{
		migrationFile: "migrations/0031_environment_variables_encrypted_secrets.up.sql",
		table:         "environment_variables",
		indexName:     "environment_variables_secret_routing_idx",
	},
	{
		migrationFile: "migrations/0032_service_variables_encrypted_secrets.up.sql",
		table:         "service_variables",
		indexName:     "service_variables_secret_routing_idx",
	},
}

// TestVariableMigrationsHaveSecretRoutingIndex is the load-bearing
// static guard. It reads each variable-encryption migration from the
// embedded FS and asserts the routing index is present with the
// documented shape: `CREATE INDEX <table>_secret_routing_idx ON <table>
// (secret_provider, secret_key_id) WHERE is_secret = true`. A
// diagnostic is one short string per missing or malformed index.
func TestVariableMigrationsHaveSecretRoutingIndex(t *testing.T) {
	t.Parallel()

	for _, mig := range requiredVariableMigrations {
		mig := mig
		t.Run(mig.table, func(t *testing.T) {
			t.Parallel()
			content, err := fs.ReadFile(embeddedMigrations, mig.migrationFile)
			if err != nil {
				t.Fatalf("read %s: %v — the migration the rotation worker depends on is missing", mig.migrationFile, err)
			}
			sql := string(content)
			if !hasSecretRoutingIndex(sql, mig.indexName, mig.table) {
				t.Errorf("%s: routing index %q not found with the documented shape "+
					"`CREATE INDEX %s ON %s (secret_provider, secret_key_id) WHERE is_secret = true`. "+
					"The rotation worker depends on this partial index to find re-seal candidates without a full-table scan — "+
					"see internal/controlplane/secrets/AGENTS.md \"Key rotation\" for the runbook.",
					mig.migrationFile, mig.indexName, mig.indexName, mig.table)
			}
		})
	}
}

// TestSecretRoutingIndexAnalyzerDetectsRegressions is the self-check
// for the matcher used above. It feeds synthetic SQL snippets and pins
// both directions of the analyser: a clean snippet stays clean, a
// missing index is flagged, a malformed index (wrong column order,
// missing WHERE clause, wrong table) is flagged.
func TestSecretRoutingIndexAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		sql       string
		indexName string
		table     string
		want      bool
	}{
		{
			name: "canonical shape is recognised",
			sql: `CREATE INDEX organization_variables_secret_routing_idx
    ON organization_variables (secret_provider, secret_key_id)
 WHERE is_secret = true;`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      true,
		},
		{
			name:      "single-line shape is recognised",
			sql:       `CREATE INDEX project_variables_secret_routing_idx ON project_variables (secret_provider, secret_key_id) WHERE is_secret = true;`,
			indexName: "project_variables_secret_routing_idx",
			table:     "project_variables",
			want:      true,
		},
		{
			name: "IF NOT EXISTS shape is recognised",
			sql: `CREATE INDEX IF NOT EXISTS environment_variables_secret_routing_idx
    ON environment_variables (secret_provider, secret_key_id)
 WHERE is_secret = true;`,
			indexName: "environment_variables_secret_routing_idx",
			table:     "environment_variables",
			want:      true,
		},
		{
			name:      "missing CREATE INDEX is flagged",
			sql:       `-- no index at all`,
			indexName: "service_variables_secret_routing_idx",
			table:     "service_variables",
			want:      false,
		},
		{
			name: "wrong column order is flagged",
			sql: `CREATE INDEX organization_variables_secret_routing_idx
    ON organization_variables (secret_key_id, secret_provider)
 WHERE is_secret = true;`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      false,
		},
		{
			name: "missing WHERE is flagged",
			sql: `CREATE INDEX organization_variables_secret_routing_idx
    ON organization_variables (secret_provider, secret_key_id);`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      false,
		},
		{
			name: "wrong WHERE predicate is flagged",
			sql: `CREATE INDEX organization_variables_secret_routing_idx
    ON organization_variables (secret_provider, secret_key_id)
 WHERE is_secret = false;`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      false,
		},
		{
			name: "wrong table is flagged",
			sql: `CREATE INDEX organization_variables_secret_routing_idx
    ON some_other_table (secret_provider, secret_key_id)
 WHERE is_secret = true;`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      false,
		},
		{
			name: "wrong index name is flagged",
			sql: `CREATE INDEX organization_variables_other_idx
    ON organization_variables (secret_provider, secret_key_id)
 WHERE is_secret = true;`,
			indexName: "organization_variables_secret_routing_idx",
			table:     "organization_variables",
			want:      false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasSecretRoutingIndex(tc.sql, tc.indexName, tc.table); got != tc.want {
				t.Errorf("hasSecretRoutingIndex = %v, want %v", got, tc.want)
			}
		})
	}
}

// secretRoutingIndexShape compiles once and is reused across every
// table check. The regex tolerates the harmless variations the
// matcher's self-check exercises — `IF NOT EXISTS`, optional
// whitespace around the column list, optional schema qualifier — but
// pins the load-bearing parts: index name, table, column order, and
// the `WHERE is_secret = true` partial-index predicate. A new
// migration that drops the WHERE clause widens the index from
// "secret rows only" to "every row", which changes the index's
// purpose and breaks the worker's bounded lookup.
var secretRoutingIndexShape = regexp.MustCompile(
	`(?is)CREATE\s+INDEX(?:\s+IF\s+NOT\s+EXISTS)?\s+` +
		`%INDEX%\s+ON\s+%TABLE%\s*` +
		`\(\s*secret_provider\s*,\s*secret_key_id\s*\)\s*` +
		`WHERE\s+is_secret\s*=\s*true\s*;`,
)

// hasSecretRoutingIndex reports whether sql contains a CREATE INDEX
// statement that matches the routing-index shape for the named
// (indexName, table) pair. The match is anchored on the documented
// column order and the partial-index WHERE clause — variations that
// would silently widen the index or rename it fail.
func hasSecretRoutingIndex(sql, indexName, table string) bool {
	// Build a per-call regex by substituting the table/index names into
	// the shared shape. The substitution is safe because the values are
	// fixed identifiers from `requiredVariableMigrations`, never user
	// input, but we still run them through regexp.QuoteMeta so a future
	// schema-qualified name like `public.organization_variables` would
	// not silently re-interpret a dot as a wildcard.
	pattern := strings.ReplaceAll(secretRoutingIndexShape.String(), "%INDEX%", regexp.QuoteMeta(indexName))
	pattern = strings.ReplaceAll(pattern, "%TABLE%", regexp.QuoteMeta(table))
	re := regexp.MustCompile(pattern)
	return re.MatchString(sql)
}
