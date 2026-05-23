package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestDokployName(t *testing.T) {
	t.Parallel()
	id := MustNewID(KindService)

	name, err := DokployName("My Web API", id)
	if err != nil {
		t.Fatalf("DokployName: %v", err)
	}
	if err := ValidateDokployName(name); err != nil {
		t.Fatalf("DokployName produced an invalid name %q: %v", name, err)
	}
	// The name embeds the full Yalla ID (with the separator rewritten), so the
	// originating resource is recoverable and the name is globally unique.
	dokployID := strings.ReplaceAll(string(id), idSeparator, "-")
	if !strings.HasSuffix(name, "-"+dokployID) {
		t.Fatalf("DokployName %q does not embed id %q", name, dokployID)
	}
	if !strings.HasPrefix(name, "my-web-api-") {
		t.Fatalf("DokployName %q does not start with the normalised label", name)
	}
}

func TestDokployNameDeterministic(t *testing.T) {
	t.Parallel()
	id := MustNewID(KindProject)
	first, err := DokployName("Same Label", id)
	if err != nil {
		t.Fatalf("DokployName: %v", err)
	}
	second, err := DokployName("Same Label", id)
	if err != nil {
		t.Fatalf("DokployName: %v", err)
	}
	if first != second {
		t.Fatalf("DokployName not deterministic: %q != %q", first, second)
	}
	// A label that normalises to the same slug yields the same name.
	third, err := DokployName("  same   label  ", id)
	if err != nil {
		t.Fatalf("DokployName: %v", err)
	}
	if third != first {
		t.Fatalf("DokployName not stable across equivalent labels: %q != %q", third, first)
	}
}

func TestDokployNameEmptyLabelFallsBackToKind(t *testing.T) {
	t.Parallel()
	id := MustNewID(KindEnvironment)
	name, err := DokployName("🚀 !!! 🚀", id)
	if err != nil {
		t.Fatalf("DokployName: %v", err)
	}
	if err := ValidateDokployName(name); err != nil {
		t.Fatalf("invalid name %q: %v", name, err)
	}
	if !strings.HasPrefix(name, string(KindEnvironment)+"-") {
		t.Fatalf("DokployName %q did not fall back to the resource kind", name)
	}
}

func TestDokployNameInvalidID(t *testing.T) {
	t.Parallel()
	if _, err := DokployName("label", ID("not-an-id")); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("DokployName(invalid id) error = %v, want ErrInvalidID", err)
	}
}

func TestDokployNameStaysWithinDockerLimit(t *testing.T) {
	t.Parallel()
	// The longest possible name: a max-length label slug joined to the
	// longest-prefixed kind's ID. It must still fit Docker's 63-char limit.
	longLabel := strings.Repeat("a", MaxSlugLen*2)
	for _, k := range []Kind{
		KindOrganization, KindUser, KindAPIKey, KindProject,
		KindEnvironment, KindService, KindDeployment, KindJob,
	} {
		id := MustNewID(k)
		name, err := DokployName(longLabel, id)
		if err != nil {
			t.Fatalf("DokployName(kind %q): %v", k, err)
		}
		if len(name) > DokployNameMaxLen {
			t.Fatalf("DokployName for kind %q is %d chars (> %d): %q", k, len(name), DokployNameMaxLen, name)
		}
		if err := ValidateDokployName(name); err != nil {
			t.Fatalf("DokployName for kind %q is not Docker-safe: %v", k, err)
		}
	}
}

func TestValidateDokployName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "my-web-api-svc-3p9k7m2n4q6r8s0t1v3w5x7y8z", false},
		{"valid single char", "a", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", DokployNameMaxLen+1), true},
		{"uppercase", "My-Service", true},
		{"underscore", "my_service", true},
		{"leading hyphen", "-svc", true},
		{"trailing hyphen", "svc-", true},
		{"double hyphen", "my--svc", true},
		{"slash", "my/svc", true},
		{"dot", "my.svc", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDokployName(tc.input)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidDokployName) {
					t.Fatalf("ValidateDokployName(%q) error = %v, want ErrInvalidDokployName", tc.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateDokployName(%q): unexpected error %v", tc.input, err)
			}
		})
	}
}
