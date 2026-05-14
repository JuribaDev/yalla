package domain

import (
	"strings"
	"testing"
)

// FuzzNormalizeSlug asserts the core NormalizeSlug invariants hold for
// arbitrary input: a successful result is always canonical (passes
// ValidateSlug), within the length bounds, and idempotent. A rejected input
// must be rejected with ErrInvalidSlug.
func FuzzNormalizeSlug(f *testing.F) {
	seeds := []string{
		"", "a", "My Service", "café-déjà", "Straße", "ﬁle", "Ｃａｆé",
		"   ", "---", "!@#$%", "🚀 deploy 🚀", "_ - .", "UPPER_CASE-123",
		strings.Repeat("a", 200), "a\x00b", "tab\there", "new\nline",
		"\u200bzero-width", "mixed Ünïcödé 名前",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		slug, err := NormalizeSlug(input)
		if err != nil {
			// The only documented failure is "no usable content".
			if !strings.Contains(err.Error(), "no usable") {
				t.Fatalf("NormalizeSlug(%q) unexpected error: %v", input, err)
			}
			return
		}
		if got := string(slug); len(got) < MinSlugLen || len(got) > MaxSlugLen {
			t.Fatalf("NormalizeSlug(%q) = %q has out-of-range length %d", input, got, len(got))
		}
		if err := ValidateSlug(string(slug)); err != nil {
			t.Fatalf("NormalizeSlug(%q) = %q is not canonical: %v", input, slug, err)
		}
		again, err := NormalizeSlug(string(slug))
		if err != nil || again != slug {
			t.Fatalf("NormalizeSlug not idempotent: %q -> %q -> %q (err %v)", input, slug, again, err)
		}
	})
}

// FuzzValidateSlug asserts ValidateSlug never panics and only ever accepts
// strings that are genuinely canonical.
func FuzzValidateSlug(f *testing.F) {
	for _, s := range []string{"", "ok", "a-b", "-bad", "bad-", "a--b", "UP", "x y", strings.Repeat("a", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if err := ValidateSlug(input); err == nil {
			// Accepted: re-derive the invariants directly.
			if len(input) < MinSlugLen || len(input) > MaxSlugLen {
				t.Fatalf("ValidateSlug accepted out-of-range %q", input)
			}
			for i := 0; i < len(input); i++ {
				c := input[i]
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
					t.Fatalf("ValidateSlug accepted invalid char in %q", input)
				}
			}
			if input[0] == '-' || input[len(input)-1] == '-' || strings.Contains(input, "--") {
				t.Fatalf("ValidateSlug accepted bad hyphenation %q", input)
			}
		}
	})
}

// FuzzParseID asserts ParseID never panics, only accepts canonical IDs, and
// that an accepted ID round-trips and is reported Valid.
func FuzzParseID(f *testing.F) {
	f.Add(string(MustNewID(KindService)))
	f.Add(string(MustNewID(KindOrganization)))
	for _, s := range []string{"", "_", "garbage", "svc_", "svc_short", "SVC_x", "svc_" + strings.Repeat("z", 26)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		id, err := ParseID(input)
		if err != nil {
			return
		}
		if string(id) != input {
			t.Fatalf("ParseID(%q) mutated input to %q", input, id)
		}
		if !id.Valid() {
			t.Fatalf("ParseID(%q) accepted an id that is not Valid()", input)
		}
		if !id.Kind().Valid() {
			t.Fatalf("ParseID(%q) accepted an id with an invalid kind %q", input, id.Kind())
		}
		// A parsed id must produce a Docker-safe Dokploy name.
		name, err := DokployName("label", id)
		if err != nil {
			t.Fatalf("DokployName(label, %q): %v", id, err)
		}
		if err := ValidateDokployName(name); err != nil {
			t.Fatalf("DokployName(label, %q) = %q is not Docker-safe: %v", id, name, err)
		}
	})
}
