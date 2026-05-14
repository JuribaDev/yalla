package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  Slug
	}{
		{"already canonical", "my-service", "my-service"},
		{"uppercase", "My-Service", "my-service"},
		{"spaces", "my cool service", "my-cool-service"},
		{"underscores and dots", "my_cool.service", "my-cool-service"},
		{"collapses separators", "my___---  service", "my-service"},
		{"trims leading and trailing", "  --my-service--  ", "my-service"},
		{"punctuation stripped", "my service! (v2)", "my-service-v2"},
		{"diacritics folded", "Café Déjà-Vu", "cafe-deja-vu"},
		{"german eszett", "Straße", "strasse"},
		{"ligature compatibility", "ﬁle", "file"},
		{"full-width compatibility", "Ｃａｆé", "cafe"},
		{"digits kept", "service-123", "service-123"},
		{"leading digit kept", "9lives", "9lives"},
		{"emoji dropped", "deploy 🚀 now", "deploy-now"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeSlug(tc.input)
			if err != nil {
				t.Fatalf("NormalizeSlug(%q): unexpected error %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeSlug(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// Output of NormalizeSlug must always be canonical.
			if err := ValidateSlug(string(got)); err != nil {
				t.Fatalf("NormalizeSlug(%q) produced non-canonical slug %q: %v", tc.input, got, err)
			}
			// Normalisation is idempotent.
			again, err := NormalizeSlug(string(got))
			if err != nil || again != got {
				t.Fatalf("NormalizeSlug not idempotent: %q -> %q -> %q (err %v)", tc.input, got, again, err)
			}
		})
	}
}

func TestNormalizeSlugTruncates(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxSlugLen*3)
	got, err := NormalizeSlug(long)
	if err != nil {
		t.Fatalf("NormalizeSlug(long): %v", err)
	}
	if len(got) != MaxSlugLen {
		t.Fatalf("NormalizeSlug(long) length = %d, want %d", len(got), MaxSlugLen)
	}
	// Truncation must not leave a trailing hyphen.
	tail := strings.Repeat("a", MaxSlugLen-1) + "-bbbb"
	got, err = NormalizeSlug(tail)
	if err != nil {
		t.Fatalf("NormalizeSlug(tail): %v", err)
	}
	if err := ValidateSlug(string(got)); err != nil {
		t.Fatalf("truncated slug %q is not canonical: %v", got, err)
	}
	if strings.HasSuffix(string(got), "-") {
		t.Fatalf("truncated slug %q ends with a hyphen", got)
	}
}

func TestNormalizeSlugEmpty(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"", "   ", "---", "!@#$%", "🚀🚀", " _ - . "} {
		if _, err := NormalizeSlug(input); !errors.Is(err, ErrInvalidSlug) {
			t.Errorf("NormalizeSlug(%q) error = %v, want ErrInvalidSlug", input, err)
		}
	}
}

func TestValidateSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "my-service", false},
		{"valid single char", "a", false},
		{"valid digits", "9lives-v2", false},
		{"valid max length", strings.Repeat("a", MaxSlugLen), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", MaxSlugLen+1), true},
		{"uppercase", "My-Service", true},
		{"space", "my service", true},
		{"underscore", "my_service", true},
		{"leading hyphen", "-service", true},
		{"trailing hyphen", "service-", true},
		{"double hyphen", "my--service", true},
		{"unicode", "café", true},
		{"slash", "my/service", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSlug(tc.input)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidSlug) {
					t.Fatalf("ValidateSlug(%q) error = %v, want ErrInvalidSlug", tc.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateSlug(%q): unexpected error %v", tc.input, err)
			}
		})
	}
}

func TestParseSlug(t *testing.T) {
	t.Parallel()
	got, err := ParseSlug("my-service")
	if err != nil || got != Slug("my-service") {
		t.Fatalf("ParseSlug(canonical) = %q, %v", got, err)
	}
	if _, err := ParseSlug("My Service"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("ParseSlug(non-canonical) error = %v, want ErrInvalidSlug", err)
	}
}
