package output

import (
	"regexp"
	"strings"
)

// Sentinel is the literal placeholder substituted in place of a redacted
// secret. Tests and downstream tooling may match on it, so changing the value
// is a public-API change.
const Sentinel = "[REDACTED]"

// minRedactableLen is the threshold below which an explicitly-supplied secret
// is ignored. Tokens shorter than this are almost always test fixtures or
// accidental empty values; redacting them would clobber unrelated punctuation
// in user-facing strings.
const minRedactableLen = 4

// Redactor replaces sensitive substrings with Sentinel before they reach
// human-readable or JSON output. Construct one per command invocation from
// the resolved global flags so the user-supplied --token is always scrubbed,
// and so well-known transport patterns (Authorization header, ?token= query
// param) are scrubbed even when the literal secret is unknown.
type Redactor struct {
	secrets []string
}

// NewRedactor returns a Redactor that removes the supplied secrets. Empty,
// duplicate, and trivially-short entries are dropped so callers can pass raw
// flag values without filtering. The variadic shape lets future config
// surfaces (cookies, refresh tokens) layer additional secrets in without
// changing call sites.
func NewRedactor(secrets ...string) *Redactor {
	out := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if len(s) < minRedactableLen {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return &Redactor{secrets: out}
}

// bearerHeader matches "Authorization: <anything>" (and the X-API-Key /
// X-Auth-Token equivalents) regardless of casing or whitespace, so secrets
// printed inside HTTP error dumps stay scrubbed even when the literal token
// was never registered with the redactor.
var bearerHeader = regexp.MustCompile(`(?i)(authorization|x-api-key|x-auth-token)\s*:\s*[^\r\n]+`)

// queryToken matches token-bearing query parameters in URLs.
var queryToken = regexp.MustCompile(`(?i)([?&](?:token|api[_-]?key|access[_-]?token|x[_-]?auth[_-]?token))=([^&\s"']+)`)

// keyedSecret matches common key=value secret transports that show up in audit
// reasons, error summaries, and provider diagnostics.
var keyedSecret = regexp.MustCompile(`(?i)\b(token|secret|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|credential|database[_-]?url|connection[_-]?(?:string|uri)|dsn)\s*=\s*([^,\s;"']+)`)

// credentialLiteral matches well-known bare secret token prefixes used by
// providers and Yalla credentials. These frequently appear in prose reasons
// without a key=value wrapper.
var credentialLiteral = regexp.MustCompile(`(?i)\b(?:sk_(?:live|test)_[a-z0-9][a-z0-9_-]*|yalla[a-z0-9]{20,})\b`)

// Redact returns s with every known secret pattern replaced by Sentinel. The
// transformation is idempotent and safe to apply to already-redacted text.
func (r *Redactor) Redact(s string) string {
	if s == "" {
		return s
	}
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, Sentinel)
	}
	s = bearerHeader.ReplaceAllStringFunc(s, func(match string) string {
		// Preserve the header name and the colon-space separator; replace
		// only the value with Sentinel so log lines stay readable.
		idx := strings.IndexByte(match, ':')
		if idx < 0 {
			return Sentinel
		}
		return match[:idx] + ": " + Sentinel
	})
	s = queryToken.ReplaceAllString(s, "$1="+Sentinel)
	s = keyedSecret.ReplaceAllString(s, "$1="+Sentinel)
	s = credentialLiteral.ReplaceAllString(s, Sentinel)
	return s
}
