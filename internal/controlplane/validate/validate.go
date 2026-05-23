// Package validate is the Yalla Control Plane backend request-validation
// toolkit. It is the single place handlers and services validate untrusted
// input — display names, slugs, resource identifiers, resource sizes, URLs,
// domains, environment variables, repository paths, and Git/image references —
// so every endpoint rejects bad input the same way.
//
// Two guarantees back the package:
//
//   - Field paths without values. Every rejection is recorded as an
//     apierr.FieldViolation: a stable dotted field path plus a human-readable,
//     machine-classifiable reason. The submitted value is NEVER placed in a
//     reason, so a validation error can name the offending field — including a
//     secret environment variable — without ever leaking its content into a
//     log, an error envelope, or audit metadata.
//   - One typed error per request. A Collector accumulates violations across
//     an entire request and produces exactly one apierr.InvalidInput carrying
//     all of them, so a caller never has to choose between reporting the first
//     bad field and reporting all of them.
//
// The package is pure: it performs no I/O, touches no Postgres, and knows
// nothing about feature flags or quota. Policy-dependent rules (for example
// "wildcard domains are allowed") are passed in as plain options that the
// caller resolves from config, the organization's feature flags, and quota
// before calling.
package validate

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Length and size bounds enforced by the package. They are part of the public
// validation contract: loosening one is a compatibility-affecting change.
const (
	// MaxNameLen bounds a human-authored display name, counted in runes.
	MaxNameLen = 100
	// MaxPathLen bounds a repository-relative file path, counted in bytes.
	MaxPathLen = 1024
	// MaxURLLen bounds an absolute URL, counted in bytes.
	MaxURLLen = 2048
	// MaxHostnameLen bounds a fully-qualified hostname, counted in bytes.
	MaxHostnameLen = 253
	// MaxHostLabelLen bounds a single DNS label within a hostname.
	MaxHostLabelLen = 63
	// MaxEnvVarNameLen bounds an environment variable name.
	MaxEnvVarNameLen = 256
	// MaxEnvVarValueLen bounds a non-secret environment variable value.
	MaxEnvVarValueLen = 32 << 10 // 32 KiB
	// MaxSecretValueLen bounds a secret environment variable value. Secrets
	// are allowed to be larger (certificates, keys) than plain config.
	MaxSecretValueLen = 64 << 10 // 64 KiB
	// MaxCPUMillis bounds a requested CPU allocation, in millicores.
	MaxCPUMillis = 64_000 // 64 cores
	// MaxMemoryMiB bounds a requested memory allocation, in mebibytes.
	MaxMemoryMiB = 262_144 // 256 GiB
	// MaxReplicas bounds a requested replica count.
	MaxReplicas = 100
	// MaxGitRefLen bounds a Git branch, tag, or commit reference.
	MaxGitRefLen = 255
	// MaxImageRefLen bounds a container image reference.
	MaxImageRefLen = 512
)

// Collector accumulates field violations encountered while validating a single
// request, then converts them into one typed error. The zero value is not
// usable; construct with New.
type Collector struct {
	violations []apierr.FieldViolation
}

// New returns an empty Collector ready to accumulate violations.
func New() *Collector { return &Collector{} }

// Add records a violation for field with reason. Both are trimmed; a pair that
// is blank on both sides is dropped so callers may add conditionally without
// guarding. The submitted value must never be passed as reason — reason is for
// classification ("must not be blank", "exceeds the maximum length"), not for
// echoing input.
func (c *Collector) Add(field, reason string) {
	field = strings.TrimSpace(field)
	reason = strings.TrimSpace(reason)
	if field == "" && reason == "" {
		return
	}
	c.violations = append(c.violations, apierr.FieldViolation{Field: field, Reason: reason})
}

// Addf is Add with a formatted reason. Callers must only interpolate
// classification values (bounds, counts) — never the submitted value.
func (c *Collector) Addf(field, format string, args ...any) {
	c.Add(field, fmt.Sprintf(format, args...))
}

// OK reports whether no violations have been recorded.
func (c *Collector) OK() bool { return len(c.violations) == 0 }

// Violations returns a copy of the recorded violations. The slice is freshly
// allocated, so callers may retain or mutate it freely.
func (c *Collector) Violations() []apierr.FieldViolation {
	return append([]apierr.FieldViolation(nil), c.violations...)
}

// Err returns nil when no violations were recorded, otherwise a single
// apierr.InvalidInput carrying every collected violation. The structured
// violations are recoverable from the returned error via apierr.ViolationsOf.
func (c *Collector) Err() error {
	if len(c.violations) == 0 {
		return nil
	}
	return apierr.InvalidInput(c.violations...)
}

// Name validates a human-authored display name: trimmed-non-empty, valid
// UTF-8, free of control characters, and at most MaxNameLen runes.
func Name(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if !utf8.ValidString(v) {
		c.Add(field, "must be valid UTF-8")
		return
	}
	if n := utf8.RuneCountInString(v); n > MaxNameLen {
		c.Addf(field, "must be at most %d characters", MaxNameLen)
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
	}
}

// Slug validates that value is already a canonical Yalla slug. It delegates to
// domain.ValidateSlug and reports a fixed, value-free reason on failure.
// Callers that want lenient normalisation should call domain.NormalizeSlug
// instead and validate the result.
func Slug(c *Collector, field, value string) {
	if err := domain.ValidateSlug(value); err != nil {
		c.Addf(field, "must be a canonical slug: 1-%d characters of [a-z0-9-], "+
			"not starting or ending with a hyphen and with no consecutive hyphens", domain.MaxSlugLen)
	}
}

// ID validates that value is a canonical Yalla resource identifier of the
// wanted kind. It reports a value-free reason: an attacker probing with a
// cross-tenant id learns only that the id was malformed or the wrong kind,
// never whether it exists.
func ID(c *Collector, field, value string, want domain.Kind) {
	id, err := domain.ParseID(value)
	if err != nil {
		c.Addf(field, "must be a valid %s identifier", want)
		return
	}
	if id.Kind() != want {
		c.Addf(field, "must be a %s identifier", want)
	}
}

// Path validates a repository-relative file path, the shape used for a
// Dockerfile path or any other in-repo reference. It rejects absolute paths,
// NUL bytes, backslashes, and ".." traversal segments, so a crafted path can
// never escape the repository root.
func Path(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if !utf8.ValidString(v) {
		c.Add(field, "must be valid UTF-8")
		return
	}
	if len(v) > MaxPathLen {
		c.Addf(field, "must be at most %d characters", MaxPathLen)
	}
	if strings.ContainsRune(v, 0) {
		c.Add(field, "must not contain NUL bytes")
		return
	}
	if strings.ContainsRune(v, '\\') {
		c.Add(field, "must use forward slashes, not backslashes")
	}
	if strings.HasPrefix(v, "/") {
		c.Add(field, "must be a repository-relative path, not absolute")
	}
	for _, seg := range strings.Split(v, "/") {
		if seg == ".." {
			c.Add(field, "must not contain path traversal (\"..\") segments")
			break
		}
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
	}
}

// containsControl reports whether s contains any Unicode control character
// (which includes NUL, tab, newline, and carriage return).
func containsControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
