package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// SQL injection — runtime defense (BE-0344).
//
// These are integration tests that prove the parameterization invariant holds
// against real Postgres, not just at the static AST layer. They run an
// isolated, freshly migrated database, seed two organizations, then feed a
// canonical set of SQL-injection payloads through every customer-input string
// field that reaches a parameterized read or write. Three guarantees are
// pinned:
//
//  1. Read-path payloads return through the typed error surface (NotFound)
//     or as an empty result. They MUST NOT surface as `E_UNAVAILABLE` —
//     that error code is the store's mapping for raw driver errors, and a
//     SQL syntax error escaping through the parameter binder would land
//     there. NotFound or empty proves the payload was bound as a parameter
//     value and matched no row.
//  2. After every payload has been exercised, the row counts of all
//     tenant-scoped tables are byte-identical to the pre-loop baseline — no
//     DROP, TRUNCATE, UPDATE, or DELETE side effect leaked through. A
//     successful injection would manifest as a count change on
//     `organizations`, `api_keys`, or `audit_events`.
//  3. A payload submitted to a free-text column (display_name) is stored
//     verbatim by Insert and read back byte-for-byte by Get. That round-trip
//     is the strongest possible proof the pgx parameter binder is the
//     security boundary, not application-layer escaping: the payload
//     survives a write→read cycle exactly as the caller submitted it,
//     including embedded quotes, dollar signs, semicolons, and comment
//     markers.
//
// The tests skip cleanly when YALLA_TEST_DATABASE_URL is unset (the standard
// testutil contract). The companion static-AST test in
// sql_injection_static_test.go runs without a database and is the regression
// backstop.

// sqlInjectionPayloads is the canonical set of attack strings the runtime
// tests submit through each input. They are deliberately printable, valid
// UTF-8, and PostgreSQL-byte-clean (no NUL — pgx rejects NUL bytes before
// they reach the server, which would surface as E_UNAVAILABLE for reasons
// unrelated to SQL injection). The list covers:
//   - the classic quote-break: terminate the value, append a statement, comment out the rest
//   - boolean-tautology: `' OR 1=1 --`
//   - UNION-based exfiltration: `' UNION SELECT NULL …`
//   - stacked-statement injection (Postgres allows multiple statements per
//     simple-protocol query): `1; DELETE FROM organizations`, INSERT/UPDATE
//   - backtick-quote shorthand attempted as escape
//   - subquery in predicate
//   - URL-encoded form (some app layers decode in the wrong place)
//   - comment-style injection: `/*comment*/ OR 1=1`
//   - dollar-quoted string injection — a Postgres-specific delimiter form
//   - multi-line payload with embedded newlines
//
// Every entry is a single string value; pgx must bind it through the
// extended-query protocol with placeholders, so the server treats the whole
// value as a literal text parameter — never as SQL to parse.
var sqlInjectionPayloads = []string{
	`'; DROP TABLE organizations; --`,
	`' OR 1=1 --`,
	`' UNION SELECT NULL, NULL, NULL --`,
	`1; DELETE FROM organizations`,
	`'); INSERT INTO organizations VALUES ('x', 'x', 'x'); --`,
	"`; DROP TABLE organizations; --",
	`x' AND (SELECT count(*) FROM organizations) > 0 --`,
	`%27%20OR%201%3D1`,
	`'; UPDATE organizations SET display_name = 'pwned'; --`,
	`/*comment*/ OR 1=1`,
	`$$; DROP TABLE organizations; --`,
	"line1\n'; DROP TABLE organizations; --\nline3",
}

// TestSQLInjectionReadPathsAreSafelyParameterised feeds every canonical
// injection payload through the customer-controlled string arguments of
// representative read paths. Each call must return a typed NotFound (for
// single-row reads) or an empty list (for list reads). The load-bearing
// negative assertion is that no call returns E_UNAVAILABLE — that error
// surface would indicate the payload reached the SQL parser as raw SQL and
// produced a server-side syntax error or DDL side effect.
func TestSQLInjectionReadPathsAreSafelyParameterised(t *testing.T) {
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgRepo := store.NewOrganizationRepository()
	keyRepo := store.NewAPIKeyRepository()
	auditRepo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Seed two organizations so the count-based integrity assertion below
	// has a non-trivial baseline. A successful DROP TABLE would visibly
	// move the count to 0.
	orgA := seedOrg(t, db, f, "tenant-alpha")
	orgB := seedOrg(t, db, f, "tenant-bravo")

	for _, payload := range sqlInjectionPayloads {
		payload := payload
		t.Run("payload="+sanitizeSubtestName(payload), func(t *testing.T) {
			// OrganizationRepository.Get with payload as id.
			assertReadIsNotFoundOrEmpty(t, "organization.Get(id=payload)",
				s.Read(ctx, func(ctx context.Context, q store.Querier) error {
					_, err := orgRepo.Get(ctx, q, payload)
					return err
				}))

			// APIKeyRepository.FindByPrefix — the lone non-tenant-scoped
			// read path. A successful injection here would be a credential-
			// authentication bypass.
			assertReadIsNotFoundOrEmpty(t, "apikey.FindByPrefix(prefix=payload)",
				s.Read(ctx, func(ctx context.Context, q store.Querier) error {
					_, err := keyRepo.FindByPrefix(ctx, q, payload)
					return err
				}))

			// APIKeyRepository.Get with payload in the key-id position
			// (tenant scoping is intact in the SQL).
			assertReadIsNotFoundOrEmpty(t, "apikey.Get(orgID=valid, keyID=payload)",
				s.Read(ctx, func(ctx context.Context, q store.Querier) error {
					_, err := keyRepo.Get(ctx, q, orgA.ID, payload)
					return err
				}))

			// APIKeyRepository.Get with payload in the organization-id
			// position. A successful injection could trick the predicate
			// into returning a key belonging to a different tenant.
			assertReadIsNotFoundOrEmpty(t, "apikey.Get(orgID=payload, keyID=valid)",
				s.Read(ctx, func(ctx context.Context, q store.Querier) error {
					_, err := keyRepo.Get(ctx, q, payload, "any-key-id")
					return err
				}))

			// AuditRepository.ListByOrganization with payload as org id —
			// must return an empty slice with no error. A non-nil error
			// from this path would surface as E_UNAVAILABLE (the only
			// classification ListByOrganization emits for driver errors),
			// so the negative assertion is identical: no driver error.
			var events []store.AuditEvent
			err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				var listErr error
				events, listErr = auditRepo.ListByOrganization(ctx, q, payload, 10)
				return listErr
			})
			if err != nil {
				ye := yerr.From(err)
				if ye != nil && ye.Code == yerr.CodeUnavailable {
					t.Errorf("audit.ListByOrganization(orgID=payload): payload reached the database raw — got E_UNAVAILABLE: %v", err)
				} else {
					t.Errorf("audit.ListByOrganization(orgID=payload): unexpected error: %v", err)
				}
			}
			if len(events) > 0 {
				t.Errorf("audit.ListByOrganization(orgID=payload) leaked %d events — predicate must match no rows", len(events))
			}
		})
	}

	// Integrity probe: after every payload has run through every read path,
	// the row counts of every customer-data table are byte-identical to
	// the pre-loop baseline (2 orgs, 0 everything-else). A successful
	// DROP/TRUNCATE/UPDATE/DELETE side effect would visibly move these.
	wantCounts := map[string]int64{
		"organizations":    2,
		"projects":         0,
		"environments":     0,
		"services":         0,
		"api_keys":         0,
		"audit_events":     0,
		"service_accounts": 0,
	}
	for table, want := range wantCounts {
		assertRowCount(ctx, t, db, table, want)
	}

	// Belt-and-suspenders: the two seeded organizations are still readable
	// by their own ids through the same repository code that was just fed
	// twelve hostile inputs. A subtle injection that silently corrupted a
	// row would show up here.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		gotA, err := orgRepo.Get(ctx, q, orgA.ID)
		if err != nil {
			return err
		}
		if gotA.ID != orgA.ID || gotA.Slug != orgA.Slug || gotA.DisplayName != orgA.Name {
			return errors.New("orgA changed shape after injection loop")
		}
		gotB, err := orgRepo.Get(ctx, q, orgB.ID)
		if err != nil {
			return err
		}
		if gotB.ID != orgB.ID || gotB.Slug != orgB.Slug || gotB.DisplayName != orgB.Name {
			return errors.New("orgB changed shape after injection loop")
		}
		return nil
	}); err != nil {
		t.Errorf("post-loop read of seeded orgs failed: %v", err)
	}
}

// TestSQLInjectionPayloadsStoredVerbatim proves the pgx parameter binder is
// the security boundary by submitting each injection payload as a free-text
// column value (display_name) and reading it back. The stored value must
// equal the submitted bytes exactly — no truncation, no escaping, no
// transformation. A successful round-trip is the strongest evidence that
// payloads cross the database surface as parameter values, never as SQL to
// parse: the server stored the bytes, did not execute them.
func TestSQLInjectionPayloadsStoredVerbatim(t *testing.T) {
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgRepo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	for i, payload := range sqlInjectionPayloads {
		i, payload := i, payload
		t.Run("payload="+sanitizeSubtestName(payload), func(t *testing.T) {
			// Build a fresh organization with display_name = payload. The
			// slug column has a regex-style constraint via citext and the
			// factory's unique generator, so we don't put the payload there;
			// display_name is the load-bearing free-text column for this
			// test. Each subtest gets its own org id + slug so subtests do
			// not collide on slug uniqueness.
			org := f.Organization("inj")
			org.Name = payload

			var inserted store.Organization
			if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				var insErr error
				inserted, insErr = orgRepo.Insert(ctx, tx, store.Organization{
					ID:          org.ID,
					Slug:        org.Slug,
					DisplayName: org.Name,
				})
				return insErr
			}); err != nil {
				t.Fatalf("Insert(display_name=payload[%d]): %v", i, err)
			}
			if inserted.DisplayName != payload {
				t.Fatalf("Insert returned DisplayName = %q, want byte-identical payload %q",
					inserted.DisplayName, payload)
			}

			// Re-read through the same repository. The round-tripped value
			// must be byte-identical — this is the proof that pgx bound
			// the value as a parameter, the server stored the raw bytes,
			// and our code did no on-the-wire interpretation.
			var fetched store.Organization
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				var getErr error
				fetched, getErr = orgRepo.Get(ctx, q, org.ID)
				return getErr
			}); err != nil {
				t.Fatalf("Get after Insert: %v", err)
			}
			if fetched.DisplayName != payload {
				t.Errorf("round-trip DisplayName = %q, want byte-identical payload %q",
					fetched.DisplayName, payload)
			}
		})
	}
}

// assertReadIsNotFoundOrEmpty pins the contract: a typed NotFound is the
// expected primary error class for an injected lookup id (no row matched);
// E_UNAVAILABLE is the load-bearing rejection — that code is the store's
// driver-error escape hatch and a SQL syntax error that leaked through the
// parameter binder would surface there. Any other typed error class is
// surprising but not necessarily an injection — it is reported as a test
// failure with the actual code so a future maintainer can decide.
func assertReadIsNotFoundOrEmpty(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		// A nil-error result from a read path is fine — list paths
		// legitimately return an empty slice with no error.
		return
	}
	ye := yerr.From(err)
	if ye == nil {
		t.Errorf("%s: expected typed error, got bare error: %v", label, err)
		return
	}
	switch ye.Code {
	case yerr.CodeNotFound:
		return
	case yerr.CodeUnavailable:
		t.Errorf("%s: payload reached the database raw — got E_UNAVAILABLE: %v "+
			"(this indicates the SQL string was assembled with caller input or a parameter binding was missed)",
			label, err)
	default:
		t.Errorf("%s: expected E_NOT_FOUND, got %s: %v", label, ye.Code, err)
	}
}

// assertRowCount fails the test when the named table does not have exactly
// want rows. Used as the post-loop integrity probe: a successful DROP /
// TRUNCATE / DELETE injection would visibly move a count.
func assertRowCount(ctx context.Context, t *testing.T, db *testutil.DB, table string, want int64) {
	t.Helper()
	// SECURITY note: the table name is hard-coded by callers (a string
	// literal), never caller-supplied — this is a test helper, the table
	// list is the closed set in wantCounts above. Postgres has no
	// placeholder syntax for table identifiers, so a per-table count
	// helper is implemented by per-table SQL constants. We keep this one
	// helper trampoline because the alternative is twelve identical
	// blocks of code with literal SQL; a static-test exception for it
	// would weaken the analyzer. Instead we render the SQL with the
	// table name as a small static map.
	var got int64
	if err := db.QueryRow(ctx, rowCountQuery(table)).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Errorf("table %s row count = %d, want %d — a payload may have mutated this table",
			table, got, want)
	}
}

// rowCountQuery is a closed-set lookup from a known table name to a fixed
// constant SQL count statement. The map is keyed by the table-name argument
// of assertRowCount; an unknown table panics so test maintenance fails
// loudly. Keeping the SQL strings as compile-time-constant per-table
// literals preserves the parameterization invariant the static analyzer
// pins for production code — the helper does not assemble SQL from caller
// input.
func rowCountQuery(table string) string {
	switch table {
	case "organizations":
		return `SELECT count(*) FROM organizations`
	case "projects":
		return `SELECT count(*) FROM projects`
	case "environments":
		return `SELECT count(*) FROM environments`
	case "services":
		return `SELECT count(*) FROM services`
	case "api_keys":
		return `SELECT count(*) FROM api_keys`
	case "audit_events":
		return `SELECT count(*) FROM audit_events`
	case "service_accounts":
		return `SELECT count(*) FROM service_accounts`
	}
	panic("unknown table for row-count probe: " + table)
}

// sanitizeSubtestName produces a stable, file-system-friendly subtest name
// from a payload. The Go test runner uses subtest names in -run patterns
// and in test output paths; the raw payloads contain characters (spaces,
// quotes, newlines) the runner re-encodes, which makes failures harder to
// match against the source list. The replacement is deterministic and
// preserves enough of the payload to recognise it in a failure line.
func sanitizeSubtestName(payload string) string {
	r := strings.NewReplacer(
		" ", "_",
		"\n", "\\n",
		"\t", "\\t",
		"/", "_",
		`"`, "'",
	)
	out := r.Replace(payload)
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
