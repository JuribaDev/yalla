package upgrade

import (
	"fmt"
	"strconv"
	"strings"
)

// SemVer is a parsed semantic version. The parser is intentionally
// minimal: it accepts `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` with an
// optional leading `v`. Build metadata is ignored for ordering (per
// SemVer 2.0); pre-release versions sort before their associated
// release.
//
// We do not pull in a full SemVer dependency because every yalla tag is
// authored by the release pipeline and conforms to the simple form.
// Bumping the parser is fine; loosening the contract is a public API
// change because `yalla upgrade --check --json` reports the parsed
// version values.
type SemVer struct {
	Major, Minor, Patch uint64
	PreRelease          string // empty when this is a stable release
	Raw                 string // exact input (without normalisation)
}

// ParseSemVer parses a version string. Leading `v` is stripped. The
// returned SemVer's Raw field preserves the original input so callers
// can echo what they were given back to the user.
func ParseSemVer(s string) (SemVer, error) {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return SemVer{Raw: raw}, fmt.Errorf("empty version")
	}

	// Strip build metadata; SemVer 2.0 says it is ignored for ordering.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}

	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}

	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return SemVer{Raw: raw}, fmt.Errorf("not a semver: %q", raw)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}

	out := SemVer{Raw: raw, PreRelease: pre}
	for i, name := range []string{"major", "minor", "patch"} {
		v, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil {
			return SemVer{Raw: raw}, fmt.Errorf("not a semver %q: %s segment %q is not numeric", raw, name, parts[i])
		}
		switch i {
		case 0:
			out.Major = v
		case 1:
			out.Minor = v
		case 2:
			out.Patch = v
		}
	}
	return out, nil
}

// IsPreRelease reports whether v carries a pre-release identifier.
func (v SemVer) IsPreRelease() bool { return v.PreRelease != "" }

// Compare returns -1 if a < b, 0 if a == b, 1 if a > b. Pre-release
// versions sort before their associated release (so 1.2.3-rc.1 < 1.2.3).
// Within pre-release identifiers we fall back to lexical comparison of
// the dot-separated parts: numeric parts compare numerically, others
// lexicographically. That matches SemVer 2.0 §11 closely enough for
// yalla's release cadence (alpha/beta/rc.N).
func Compare(a, b SemVer) int {
	switch {
	case a.Major != b.Major:
		return cmpUint(a.Major, b.Major)
	case a.Minor != b.Minor:
		return cmpUint(a.Minor, b.Minor)
	case a.Patch != b.Patch:
		return cmpUint(a.Patch, b.Patch)
	}
	switch {
	case a.PreRelease == "" && b.PreRelease == "":
		return 0
	case a.PreRelease == "":
		// a is a release, b is a pre-release; release > pre-release.
		return 1
	case b.PreRelease == "":
		return -1
	}
	return comparePreRelease(a.PreRelease, b.PreRelease)
}

// LessThan reports whether a < b.
func (v SemVer) LessThan(other SemVer) bool { return Compare(v, other) < 0 }

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func comparePreRelease(a, b string) int {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	n := len(ap)
	if len(bp) < n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		ai, ae := strconv.ParseUint(ap[i], 10, 64)
		bi, be := strconv.ParseUint(bp[i], 10, 64)
		switch {
		case ae == nil && be == nil:
			if c := cmpUint(ai, bi); c != 0 {
				return c
			}
		case ae == nil:
			// numeric < non-numeric per SemVer 2.0
			return -1
		case be == nil:
			return 1
		default:
			if c := strings.Compare(ap[i], bp[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(ap) < len(bp):
		// Fewer fields with all-equal prefix means smaller version
		// (per SemVer 2.0 §11).
		return -1
	case len(ap) > len(bp):
		return 1
	default:
		return 0
	}
}
