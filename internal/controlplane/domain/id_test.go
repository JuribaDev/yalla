package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestKindValid(t *testing.T) {
	t.Parallel()
	valid := []Kind{
		KindOrganization, KindUser, KindAPIKey, KindProject,
		KindEnvironment, KindService, KindDeployment, KindJob,
	}
	for _, k := range valid {
		if !k.Valid() {
			t.Errorf("Kind(%q).Valid() = false, want true", k)
		}
	}
	for _, k := range []Kind{"", "ORG", "organization", "user", "unknown", "Org"} {
		if k.Valid() {
			t.Errorf("Kind(%q).Valid() = true, want false", k)
		}
	}
}

func TestNewIDRoundTrip(t *testing.T) {
	t.Parallel()
	kinds := []Kind{
		KindOrganization, KindUser, KindAPIKey, KindProject,
		KindEnvironment, KindService, KindDeployment, KindJob,
	}
	seen := make(map[ID]struct{})
	const perKind = 500
	for _, k := range kinds {
		for i := 0; i < perKind; i++ {
			id, err := NewID(k)
			if err != nil {
				t.Fatalf("NewID(%q): %v", k, err)
			}
			if _, dup := seen[id]; dup {
				t.Fatalf("NewID(%q) produced a duplicate id %q", k, id)
			}
			seen[id] = struct{}{}

			if !id.Valid() {
				t.Fatalf("NewID(%q) produced an invalid id %q", k, id)
			}
			if got := id.Kind(); got != k {
				t.Fatalf("ID(%q).Kind() = %q, want %q", id, got, k)
			}
			if !id.IsKind(k) {
				t.Fatalf("ID(%q).IsKind(%q) = false, want true", id, k)
			}
			parsed, err := ParseID(string(id))
			if err != nil {
				t.Fatalf("ParseID(%q): %v", id, err)
			}
			if parsed != id {
				t.Fatalf("ParseID round-trip: got %q, want %q", parsed, id)
			}
			// Structural shape: <kind>_<26 char suffix>.
			prefix, suffix, ok := strings.Cut(string(id), idSeparator)
			if !ok || Kind(prefix) != k || len(suffix) != idSuffixLen {
				t.Fatalf("id %q has unexpected shape", id)
			}
		}
	}
}

func TestNewIDUnknownKind(t *testing.T) {
	t.Parallel()
	for _, k := range []Kind{"", "bogus", "ORG"} {
		if _, err := NewID(k); !errors.Is(err, ErrUnknownKind) {
			t.Errorf("NewID(%q) error = %v, want ErrUnknownKind", k, err)
		}
	}
}

func TestParseID(t *testing.T) {
	t.Parallel()
	good := MustNewID(KindService)
	suffix := good.suffix() // a known-valid 26-char crockford suffix
	if len(suffix) != idSuffixLen {
		t.Fatalf("test fixture suffix has length %d, want %d", len(suffix), idSuffixLen)
	}
	// Mutate the last suffix character to exercise the per-character check at
	// a known-correct length.
	withLastChar := func(c byte) string {
		return "svc_" + suffix[:idSuffixLen-1] + string(c)
	}
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", string(good), false},
		{"empty", "", true},
		{"missing separator", "svc" + suffix, true},
		{"unknown kind", "bogus_" + suffix, true},
		{"uppercase kind", "SVC_" + suffix, true},
		{"suffix too short", "svc_" + suffix[:idSuffixLen-1], true},
		{"suffix too long", "svc_" + suffix + "z", true},
		{"suffix uppercase char", withLastChar('A'), true},
		{"suffix excluded char i", withLastChar('i'), true},
		{"suffix excluded char l", withLastChar('l'), true},
		{"suffix excluded char o", withLastChar('o'), true},
		{"suffix excluded char u", withLastChar('u'), true},
		{"suffix punctuation", withLastChar('-'), true},
		{"only separator", "_", true},
		{"empty suffix", "svc_", true},
		{"empty prefix", "_" + suffix, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseID(tc.input)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidID) {
					t.Fatalf("ParseID(%q) error = %v, want ErrInvalidID", tc.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseID(%q): unexpected error %v", tc.input, err)
			}
		})
	}
}

func TestParseIDErrorDoesNotEchoInput(t *testing.T) {
	t.Parallel()
	// Error messages should not echo arbitrary untrusted input verbatim.
	bad := "svc_PAYLOAD_INJECTION_ATTEMPT_XYZ"
	_, err := ParseID(bad)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "PAYLOAD_INJECTION_ATTEMPT") {
		t.Fatalf("error message echoed untrusted input: %q", err.Error())
	}
}

func TestIDKindZeroValue(t *testing.T) {
	t.Parallel()
	var zero ID
	if zero.Valid() {
		t.Error("zero ID should not be valid")
	}
	if zero.Kind() != "" {
		t.Errorf("zero ID Kind() = %q, want empty", zero.Kind())
	}
	if zero.IsKind(KindService) {
		t.Error("zero ID should not be any kind")
	}
}

func TestIDIsKindRejectsWrongKind(t *testing.T) {
	t.Parallel()
	id := MustNewID(KindProject)
	if id.IsKind(KindService) {
		t.Errorf("project id %q reported as a service", id)
	}
	if !id.IsKind(KindProject) {
		t.Errorf("project id %q not reported as a project", id)
	}
}

func TestMustParseIDPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("MustParseID did not panic on invalid input")
		}
	}()
	MustParseID("not-an-id")
}

func TestMustNewID(t *testing.T) {
	t.Parallel()
	id := MustNewID(KindJob)
	if !id.IsKind(KindJob) {
		t.Fatalf("MustNewID(KindJob) = %q, not a job id", id)
	}
}
