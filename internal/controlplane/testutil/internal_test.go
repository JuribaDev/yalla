package testutil

import "testing"

// White-box unit tests for the pure, database-free helpers. They run on every
// machine — no Postgres required — and cover the success, "validation failure"
// (malformed/empty inputs), and not-found-style branches of the harness logic.

func TestLookupAdminDSN(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		env     map[string]string
		wantDSN string
		wantOK  bool
	}{
		{
			name:    "set",
			env:     map[string]string{EnvDatabaseURL: "postgres://localhost/yalla"},
			wantDSN: "postgres://localhost/yalla",
			wantOK:  true,
		},
		{
			name:    "trimmed",
			env:     map[string]string{EnvDatabaseURL: "  postgres://localhost/yalla \n"},
			wantDSN: "postgres://localhost/yalla",
			wantOK:  true,
		},
		{
			name:    "unset",
			env:     map[string]string{},
			wantDSN: "",
			wantOK:  false,
		},
		{
			name:    "blank",
			env:     map[string]string{EnvDatabaseURL: "   \t  "},
			wantDSN: "",
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(key string) string { return tc.env[key] }
			dsn, ok := lookupAdminDSN(getenv)
			if dsn != tc.wantDSN || ok != tc.wantOK {
				t.Fatalf("lookupAdminDSN = (%q, %v), want (%q, %v)", dsn, ok, tc.wantDSN, tc.wantOK)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"Acme Corp", "acme-corp"},
		{"  Trim  Me  ", "trim-me"},
		{"Mixed_Case.And/Symbols", "mixed-case-and-symbols"},
		{"already-slug", "already-slug"},
		{"UPPER", "upper"},
		{"trailing---", "trailing"},
		{"---leading", "leading"},
		{"", ""},
		{"!!!", ""},
		{"123", "123"},
	}
	for _, tc := range cases {
		if got := slugify(tc.in); got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayName(t *testing.T) {
	t.Parallel()

	if got := displayName("Acme", "Organization", 1); got != "Acme" {
		t.Errorf("displayName with label = %q, want %q", got, "Acme")
	}
	if got := displayName("  ", "Organization", 7); got != "Organization 7" {
		t.Errorf("displayName with blank label = %q, want %q", got, "Organization 7")
	}
}

func TestScanLeaks(t *testing.T) {
	t.Parallel()

	t.Run("detects a leaked secret", func(t *testing.T) {
		t.Parallel()
		leaks := scanLeaks(`{"token":"super-secret-value"}`, []string{"super-secret-value"})
		if len(leaks) != 1 || leaks[0] != "super-secret-value" {
			t.Fatalf("scanLeaks = %v, want [super-secret-value]", leaks)
		}
	})

	t.Run("clean output has no leaks", func(t *testing.T) {
		t.Parallel()
		if leaks := scanLeaks(`{"token":"[REDACTED]"}`, []string{"super-secret-value"}); len(leaks) != 0 {
			t.Fatalf("scanLeaks on clean output = %v, want none", leaks)
		}
	})

	t.Run("empty secrets are ignored", func(t *testing.T) {
		t.Parallel()
		if leaks := scanLeaks("anything at all", []string{"", ""}); len(leaks) != 0 {
			t.Fatalf("scanLeaks with empty secrets = %v, want none", leaks)
		}
	})

	t.Run("reports every leaked secret", func(t *testing.T) {
		t.Parallel()
		leaks := scanLeaks("key=abcd1 and token=wxyz2", []string{"abcd1", "wxyz2", "absent3"})
		if len(leaks) != 2 {
			t.Fatalf("scanLeaks = %v, want 2 leaks", leaks)
		}
	})
}
