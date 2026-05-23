package domain

import (
	"fmt"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const (
	// MinSlugLen is the shortest a canonical slug may be.
	MinSlugLen = 1
	// MaxSlugLen bounds a canonical slug. It is deliberately small: a slug is
	// embedded alongside a full resource ID in a Dokploy name (see
	// DokployName), and the combined string must stay within
	// DokployNameMaxLen.
	MaxSlugLen = 30
)

// Slug is a normalised, canonical, DNS-label-shaped label for a Yalla
// resource. A canonical slug is 1..MaxSlugLen characters of [a-z0-9-], starts
// and ends with an alphanumeric character, and contains no consecutive
// hyphens. Uniqueness of a slug within its parent scope is enforced by the
// persistence layer, not this type.
type Slug string

// String returns the slug's string form.
func (s Slug) String() string { return string(s) }

// newSlugTransformer builds the transformer that folds an arbitrary Unicode
// string toward ASCII before slugification:
//   - cases.Fold applies Unicode case folding, which lowercases and also folds
//     characters with no simple lowercase form (e.g. ß -> "ss").
//   - NFD decomposes accented characters into a base letter plus combining
//     marks, and the marks (category Mn) are then removed (é -> e).
//   - NFKC applies compatibility folding (ligatures, full-width forms, etc.),
//     so "ﬁle" -> "file" and "Ｃａｆé" -> "cafe".
//
// This makes visually equivalent labels normalise to the same ASCII base, so
// Unicode tricks cannot smuggle a colliding-but-distinct slug past the
// uniqueness constraint.
//
// A transform.Chain carries internal state and is not safe for concurrent
// use, so each must not be shared across goroutines; slugTransformerPool hands
// out one per in-flight NormalizeSlug call.
func newSlugTransformer() transform.Transformer {
	return transform.Chain(
		cases.Fold(),
		norm.NFD,
		runes.Remove(runes.In(unicode.Mn)),
		norm.NFKC,
	)
}

var slugTransformerPool = sync.Pool{
	New: func() any { return newSlugTransformer() },
}

// NormalizeSlug converts an arbitrary human-authored label into a canonical
// Slug. It folds Unicode toward ASCII, lowercases, replaces every run of
// non-[a-z0-9] characters with a single hyphen, trims leading and trailing
// hyphens, and truncates to MaxSlugLen. It returns ErrInvalidSlug only when
// the input contains no usable alphanumeric content (so it would normalise to
// the empty string). NormalizeSlug is deterministic and idempotent: the output
// of NormalizeSlug always passes ValidateSlug, and normalising it again is a
// no-op.
func NormalizeSlug(input string) (Slug, error) {
	tr, ok := slugTransformerPool.Get().(transform.Transformer)
	if !ok {
		tr = newSlugTransformer()
	}
	folded, _, err := transform.String(tr, input)
	slugTransformerPool.Put(tr)
	if err != nil {
		// The transformer cannot meaningfully fail on a valid Go string, but
		// if it ever does, fall back to the raw input rather than erroring.
		folded = input
	}
	folded = strings.ToLower(folded)

	var b strings.Builder
	b.Grow(len(folded))
	pendingHyphen := false
	for _, r := range folded {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if pendingHyphen && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingHyphen = false
			b.WriteRune(r)
			continue
		}
		// Any other rune (including hyphens, spaces, and punctuation) becomes
		// a separator. Defer writing it so leading/trailing/repeated
		// separators collapse away.
		pendingHyphen = true
	}

	out := b.String()
	if len(out) > MaxSlugLen {
		out = strings.TrimRight(out[:MaxSlugLen], "-")
	}
	if out == "" {
		return "", fmt.Errorf("%w: input has no usable alphanumeric characters", ErrInvalidSlug)
	}
	return Slug(out), nil
}

// ValidateSlug reports whether s is already a canonical slug. It is the strict
// validator for slugs that must arrive pre-normalised (e.g. on a wire contract
// that rejects rather than silently rewrites client input). Use NormalizeSlug
// when the caller wants lenient normalisation instead.
func ValidateSlug(s string) error {
	n := len(s)
	if n < MinSlugLen {
		return fmt.Errorf("%w: must not be empty", ErrInvalidSlug)
	}
	if n > MaxSlugLen {
		return fmt.Errorf("%w: must be at most %d characters, got %d", ErrInvalidSlug, MaxSlugLen, n)
	}
	for i := 0; i < n; i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("%w: contains an invalid character at position %d", ErrInvalidSlug, i)
		}
	}
	if s[0] == '-' || s[n-1] == '-' {
		return fmt.Errorf("%w: must not start or end with a hyphen", ErrInvalidSlug)
	}
	if strings.Contains(s, "--") {
		return fmt.Errorf("%w: must not contain consecutive hyphens", ErrInvalidSlug)
	}
	return nil
}

// ParseSlug validates s and returns it as a Slug, or ErrInvalidSlug if s is
// not already canonical. It does not normalise; callers that want lenient
// rewriting should use NormalizeSlug.
func ParseSlug(s string) (Slug, error) {
	if err := ValidateSlug(s); err != nil {
		return "", err
	}
	return Slug(s), nil
}
