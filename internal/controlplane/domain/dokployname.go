package domain

import (
	"fmt"
	"strings"
)

// DokployNameMaxLen bounds a Dokploy resource name. Dokploy-provisioned
// resources land in Docker (containers, compose projects, networks), which
// constrain names to 63 characters of a restricted alphabet. Yalla stays
// inside that limit and uses an even stricter [a-z0-9-] alphabet.
const DokployNameMaxLen = 63

// DokployName builds a deterministic, Docker-safe name for the Dokploy
// resource backing a Yalla resource. The name is "<slug>-<dokploy-id>", where
// the slug is NormalizeSlug(label) and the Dokploy id is the resource ID with
// its underscore separator rewritten to a hyphen (so the name is valid Docker
// syntax while still embedding the full Yalla ID).
//
// Because the name embeds the resource ID, it is globally unique and
// deterministic: the same (label, id) pair always yields the same name, and
// the originating Yalla ID can be recovered from it. When label has no usable
// alphanumeric content the resource kind is used as the slug, so a name is
// always produced for a valid ID.
//
// It returns ErrInvalidID if id is not a canonical resource ID, and
// ErrInvalidDokployName if the constructed name would not be Docker-safe
// (which, given the length bounds on Slug and ID, should not happen — the
// check is a defensive contract assertion).
func DokployName(label string, id ID) (string, error) {
	if _, err := ParseID(string(id)); err != nil {
		return "", err
	}
	slug, err := NormalizeSlug(label)
	if err != nil {
		// No usable label: fall back to the resource kind, which is always a
		// valid slug, so a valid ID always yields a name.
		slug = Slug(id.Kind())
	}
	dokployID := strings.ReplaceAll(string(id), idSeparator, "-")
	name := string(slug) + "-" + dokployID
	if err := ValidateDokployName(name); err != nil {
		return "", err
	}
	return name, nil
}

// ValidateDokployName reports whether s is a Docker-safe Dokploy name: 1..
// DokployNameMaxLen characters of [a-z0-9-], starting and ending with an
// alphanumeric character, with no consecutive hyphens.
func ValidateDokployName(s string) error {
	n := len(s)
	if n == 0 {
		return fmt.Errorf("%w: must not be empty", ErrInvalidDokployName)
	}
	if n > DokployNameMaxLen {
		return fmt.Errorf("%w: must be at most %d characters, got %d", ErrInvalidDokployName, DokployNameMaxLen, n)
	}
	for i := 0; i < n; i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("%w: contains an invalid character at position %d", ErrInvalidDokployName, i)
		}
	}
	if s[0] == '-' || s[n-1] == '-' {
		return fmt.Errorf("%w: must not start or end with a hyphen", ErrInvalidDokployName)
	}
	if strings.Contains(s, "--") {
		return fmt.Errorf("%w: must not contain consecutive hyphens", ErrInvalidDokployName)
	}
	return nil
}
