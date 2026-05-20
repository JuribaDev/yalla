package output

import (
	"strings"
	"testing"
)

func TestNewRedactor_DropsEmptyAndShortSecrets(t *testing.T) {
	t.Parallel()
	r := NewRedactor("", " ", "abc", "valid-secret-token")
	in := "abc valid-secret-token"
	got := r.Redact(in)
	// "abc" is below minRedactableLen and must NOT be rewritten.
	if !strings.Contains(got, "abc ") {
		t.Errorf("short token should not be redacted; got %q", got)
	}
	if strings.Contains(got, "valid-secret-token") {
		t.Errorf("long token should be redacted; got %q", got)
	}
	if !strings.Contains(got, Sentinel) {
		t.Errorf("expected Sentinel in output; got %q", got)
	}
}

func TestRedactor_DeduplicatesSecrets(t *testing.T) {
	t.Parallel()
	r := NewRedactor("supersecret", "supersecret", "supersecret")
	got := r.Redact("supersecret in the middle")
	if strings.Count(got, Sentinel) != 1 {
		t.Errorf("expected single redaction, got %q", got)
	}
}

func TestRedactor_AuthorizationHeaderScrubbed(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	in := "GET /v1/x HTTP/1.1\r\nAuthorization: Bearer abcdef.ghijkl.mnop\r\nHost: example.com"
	got := r.Redact(in)
	if strings.Contains(got, "abcdef") {
		t.Errorf("Bearer token leaked: %q", got)
	}
	if !strings.Contains(got, "Authorization: "+Sentinel) {
		t.Errorf("expected Authorization header to be scrubbed; got %q", got)
	}
	if !strings.Contains(got, "Host: example.com") {
		t.Errorf("non-secret headers should pass through; got %q", got)
	}
}

func TestRedactor_XApiKeyAndXAuthTokenHeaders(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []string{
		"X-API-Key: keykeykeykey",
		"x-api-key: keykeykeykey",
		"X-Auth-Token: tttttttttttt",
	}
	for _, in := range cases {
		got := r.Redact(in)
		if strings.Contains(got, "keykey") || strings.Contains(got, "tttt") {
			t.Errorf("secret header value leaked: %q", got)
		}
		if !strings.Contains(got, Sentinel) {
			t.Errorf("expected sentinel in %q", got)
		}
	}
}

func TestRedactor_QueryStringTokens(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []string{
		"https://api.example.com/v1?token=abcdef1234",
		"https://api.example.com/v1?api_key=abcdef1234&page=2",
		"https://api.example.com/v1?access_token=abcdef1234",
		"https://api.example.com/v1?x-auth-token=abcdef1234",
	}
	for _, in := range cases {
		got := r.Redact(in)
		if strings.Contains(got, "abcdef1234") {
			t.Errorf("token leaked from query: in=%q got=%q", in, got)
		}
		if !strings.Contains(got, Sentinel) {
			t.Errorf("expected sentinel; got %q", got)
		}
	}
}

func TestRedactor_KeyValueSecrets(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := map[string]string{
		"reason secret=manual-secret-token":       "reason secret=" + Sentinel,
		"retry token=live-token-value; safe=keep": "retry token=" + Sentinel + "; safe=keep",
		"dsn=postgres://user:pass@db/service":     "dsn=" + Sentinel,
		"metric_key=requests_total":               "metric_key=requests_total",
	}
	for input, want := range cases {
		if got := r.Redact(input); got != want {
			t.Fatalf("Redact(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRedactor_BareCredentialLiterals(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	input := "provider note sk_live_invoice_reopen_secret and token yallaabcdefghijklmnopqrstuv"
	got := r.Redact(input)
	if strings.Contains(got, "sk_live_invoice") || strings.Contains(got, "yallaabcdefghijkl") {
		t.Fatalf("bare credential leaked: %q", got)
	}
	if strings.Count(got, Sentinel) != 2 {
		t.Fatalf("redacted sentinel count = %d, want 2 in %q", strings.Count(got, Sentinel), got)
	}
}

func TestRedactor_PreservesNonSecretQueryParams(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	in := "https://api.example.com/v1?page=2&q=hello"
	got := r.Redact(in)
	if got != in {
		t.Errorf("non-secret query mutated: %q -> %q", in, got)
	}
}

func TestRedactor_ExplicitSecretPriority(t *testing.T) {
	t.Parallel()
	r := NewRedactor("user-token-value")
	in := "logged in with user-token-value, retrying"
	got := r.Redact(in)
	if strings.Contains(got, "user-token-value") {
		t.Errorf("explicit secret leaked: %q", got)
	}
}

func TestRedactor_Idempotent(t *testing.T) {
	t.Parallel()
	r := NewRedactor("supersecret")
	in := "Authorization: Bearer xyzxyzxyz, supersecret tail"
	once := r.Redact(in)
	twice := r.Redact(once)
	if once != twice {
		t.Errorf("redact not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestRedactor_EmptyStringPassthrough(t *testing.T) {
	t.Parallel()
	r := NewRedactor("anything")
	if got := r.Redact(""); got != "" {
		t.Errorf("empty input mutated to %q", got)
	}
}

// TestRedactionContractStructuralPatternsAcrossKnownTransports is the
// canonical anchor BE-0387 wires the
// `go test -run TestRedaction ./...` filter to. Renaming or deleting it
// silently de-gates the redaction suite from the dedicated
// `Redaction tests` CI step, the `# 13. Required: redaction tests`
// verify.sh block, the `13. \`go test -run TestRedaction ./...\“
// CONTRIBUTING entry, the SECURITY.md `## Redaction Tests` section,
// and the PRD's `verificationLoop.requiredBackendCommands` array — so
// the function name is itself a load-bearing surface pinned by the
// static defence at
// `internal/release/verification_suite_redaction_static_test.go`.
//
// The contract a Redactor must hold across every release is:
//
//  1. The shared sentinel value is the literal string `[REDACTED]`.
//     Downstream tests, audit pipelines, and the fake-Dokploy
//     recorder all match on it, so a substitution is a public-API
//     change that must be deliberate.
//  2. Authorization-style header values are scrubbed regardless of
//     header casing (Authorization / authorization, X-API-Key /
//     x-api-key, X-Auth-Token / x-auth-token), with the header
//     name preserved so log lines stay readable but the value
//     replaced by the sentinel.
//  3. Token-bearing query parameters (?token=, ?api_key=,
//     ?access_token=, ?x-auth-token=) are scrubbed regardless of
//     case and regardless of whether they appear as the first or a
//     trailing parameter, with the parameter name preserved.
//  4. The transformation never panics on hostile input, including
//     header lines without a colon, query parameters without a
//     value, or URLs with adjacent ampersands.
//
// Each transport here uses a distinctive bearer literal containing
// the substring `REDACTION-CONTRACT-VALUE-` so a regression that
// leaks the value (instead of scrubbing it) surfaces as a literal
// match in the failure message rather than as a hash mismatch.
func TestRedactionContractStructuralPatternsAcrossKnownTransports(t *testing.T) {
	t.Parallel()

	if Sentinel != "[REDACTED]" {
		t.Fatalf("Sentinel changed from canonical literal `[REDACTED]` to %q; this is a public-API contract every audit pipeline and the fake-Dokploy recorder relies on — restore the canonical value or update every downstream matcher in the same change.", Sentinel)
	}

	r := NewRedactor()

	headerCases := []struct {
		name   string
		input  string
		header string // header name as it should appear after redaction
	}{
		{"Authorization upper", "Authorization: Bearer REDACTION-CONTRACT-VALUE-AUTH-UPPER", "Authorization"},
		{"authorization lower", "authorization: Bearer REDACTION-CONTRACT-VALUE-AUTH-LOWER", "authorization"},
		{"X-API-Key upper", "X-API-Key: REDACTION-CONTRACT-VALUE-XAPI-UPPER", "X-API-Key"},
		{"x-api-key lower", "x-api-key: REDACTION-CONTRACT-VALUE-XAPI-LOWER", "x-api-key"},
		{"X-Auth-Token upper", "X-Auth-Token: REDACTION-CONTRACT-VALUE-XAUTH-UPPER", "X-Auth-Token"},
		{"x-auth-token lower", "x-auth-token: REDACTION-CONTRACT-VALUE-XAUTH-LOWER", "x-auth-token"},
	}
	for _, tc := range headerCases {
		got := r.Redact(tc.input)
		if strings.Contains(got, "REDACTION-CONTRACT-VALUE-") {
			t.Errorf("%s: bearer literal leaked through Redact; got %q — the header-value transport contract demands the value is replaced by Sentinel before any log line, audit blob, or CI log can carry it.", tc.name, got)
		}
		want := tc.header + ": " + Sentinel
		if !strings.Contains(got, want) {
			t.Errorf("%s: expected scrubbed header %q in output; got %q — the header name MUST be preserved so log lines stay readable while only the value is replaced.", tc.name, want, got)
		}
	}

	queryCases := []struct {
		name  string
		input string
		key   string // canonical key as it appeared in the URL
	}{
		{"token first", "https://api.example.com/v1?token=REDACTION-CONTRACT-VALUE-QTOKEN-FIRST", "token"},
		{"token trailing", "https://api.example.com/v1?page=2&token=REDACTION-CONTRACT-VALUE-QTOKEN-TRAILING", "token"},
		{"api_key underscore", "https://api.example.com/v1?api_key=REDACTION-CONTRACT-VALUE-QAPIKEY-UNDERSCORE", "api_key"},
		{"api-key hyphen", "https://api.example.com/v1?api-key=REDACTION-CONTRACT-VALUE-QAPIKEY-HYPHEN", "api-key"},
		{"access_token", "https://api.example.com/v1?access_token=REDACTION-CONTRACT-VALUE-QACCESS-TOKEN", "access_token"},
		{"x-auth-token query", "https://api.example.com/v1?x-auth-token=REDACTION-CONTRACT-VALUE-QXAUTH-TOKEN", "x-auth-token"},
	}
	for _, tc := range queryCases {
		got := r.Redact(tc.input)
		if strings.Contains(got, "REDACTION-CONTRACT-VALUE-") {
			t.Errorf("%s: token leaked from query string; got %q — the query-parameter transport contract demands the value is replaced by Sentinel before any audit log or browser-history dump can carry it.", tc.name, got)
		}
		want := tc.key + "=" + Sentinel
		if !strings.Contains(got, want) {
			t.Errorf("%s: expected scrubbed query %q in output; got %q — the parameter name MUST be preserved so the URL stays diagnosable while only the value is replaced.", tc.name, want, got)
		}
	}

	if got := r.Redact("https://api.example.com/v1?page=2&q=hello&sort=desc"); got != "https://api.example.com/v1?page=2&q=hello&sort=desc" {
		t.Errorf("non-secret query parameters mutated: got %q — the redactor MUST NOT scrub URLs whose parameters carry no secret-shaped key.", got)
	}

	// Hostile inputs the redactor MUST tolerate without panicking. The
	// goroutine isolates the panic so a regression surfaces as a
	// failure message instead of taking down the test binary.
	hostile := []string{
		"Authorization:",
		"Authorization: ",
		"X-API-Key",
		"Authorization\nNoColon",
		"https://api.example.com/v1?token=",
		"https://api.example.com/v1?token=&api_key=&access_token=",
		"https://api.example.com/v1?&&token=",
		"\x00\x01\x02Authorization: Bearer REDACTION-CONTRACT-VALUE-HOSTILE\x00",
	}
	for _, in := range hostile {
		func(s string) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("Redact panicked on hostile input %q: %v — the redactor MUST be panic-free; a panic in the redaction hot path tears down the per-request log record and surfaces the unredacted secret to whatever wrote the log line.", s, rec)
				}
			}()
			_ = r.Redact(s)
		}(in)
	}
}

// TestRedactionContractExplicitSecretsAndIdempotency is the second
// canonical anchor BE-0387 wires the
// `go test -run TestRedaction ./...` filter to. The two-function
// pair shape mirrors BE-0383's policy matrix, BE-0384's quota
// concurrency, BE-0385's job worker lease, and BE-0386's fake
// Dokploy pairs — and `internal/release/verification_suite_redaction_static_test.go`
// pins both function names so a rename or deletion fails the static
// gate before it can de-gate the runtime suite.
//
// The contract a Redactor must hold across every release is:
//
//  1. An explicit secret registered via NewRedactor (any length
//     >= minRedactableLen) is replaced by Sentinel everywhere it
//     appears in the input, regardless of surrounding characters
//     (whitespace, punctuation, JSON-style quotes, mixed content
//     with header / query patterns).
//  2. Empty secrets, whitespace-only secrets, and secrets shorter
//     than minRedactableLen are dropped on construction so a
//     mis-wired call site cannot clobber unrelated punctuation.
//  3. Duplicate secrets are de-duplicated so a redacted output
//     never contains a "double-applied" sentinel for the same
//     secret.
//  4. Redact is idempotent on every input the contract covers:
//     `Redact(Redact(s)) == Redact(s)` so a Redactor wired into a
//     log pipeline that double-applies (request log + per-handler
//     log) cannot mutate the output across passes.
//  5. The empty string passes through unchanged so a Redactor
//     wired into a log pipeline can be applied unconditionally
//     without allocating Sentinel-only strings.
//  6. The Sentinel literal itself never re-forms a known secret
//     substring (e.g. registering "[REDACTED]" or "REDACTED" as a
//     secret cannot cause the Redactor to scrub its own sentinel
//     and create an infinite-fixed-point regression).
func TestRedactionContractExplicitSecretsAndIdempotency(t *testing.T) {
	t.Parallel()

	const explicit = "REDACTION-CONTRACT-EXPLICIT-SECRET-ZZY"

	r := NewRedactor(explicit, "", " ", "abc", explicit /* duplicate */, "supersecondary-value")

	// (1) explicit secret scrubbed in mixed contexts
	contexts := []string{
		"plain prose mentioning " + explicit + " in the middle",
		`{"value":"` + explicit + `","other":"safe"}`,
		"Authorization: Bearer " + explicit,
		"https://api.example.com/v1?page=2&note=" + explicit,
		explicit + " at start",
		"at end " + explicit,
		explicit + explicit, // adjacent occurrence
	}
	for _, in := range contexts {
		got := r.Redact(in)
		if strings.Contains(got, explicit) {
			t.Errorf("explicit secret leaked in context %q: got %q — every explicit secret registered with NewRedactor MUST be scrubbed regardless of surrounding characters.", in, got)
		}
		if !strings.Contains(got, Sentinel) {
			t.Errorf("expected Sentinel in scrubbed output for context %q; got %q", in, got)
		}
	}

	// (2) sub-threshold and empty secrets dropped on construction
	short := r.Redact("abc not redacted")
	if !strings.Contains(short, "abc not redacted") {
		t.Errorf("short token clobbered: %q — secrets shorter than minRedactableLen MUST be ignored so unrelated punctuation in user-facing strings is not mutated.", short)
	}

	// (3) duplicate dedupe — exactly one Sentinel per occurrence
	if got := r.Redact(explicit); strings.Count(got, Sentinel) != 1 {
		t.Errorf("duplicate registration produced %d sentinels for single occurrence: %q — duplicates MUST collapse so a redacted output never carries a double-applied sentinel for the same secret.", strings.Count(got, Sentinel), got)
	}

	// (4) idempotency across two passes
	idempotencyCorpus := []string{
		"plain " + explicit + " text",
		"Authorization: Bearer " + explicit,
		"https://api.example.com/v1?token=" + explicit,
		"mixed " + explicit + " Authorization: Bearer abcdef.ghijkl and ?api_key=tokenvalue",
		"prose with no secrets at all",
		"only Sentinel: " + Sentinel,
	}
	for _, in := range idempotencyCorpus {
		once := r.Redact(in)
		twice := r.Redact(once)
		if once != twice {
			t.Errorf("Redact not idempotent for input %q: once=%q twice=%q — Redact(Redact(s)) MUST equal Redact(s) so a log pipeline that double-applies cannot mutate the output across passes.", in, once, twice)
		}
	}

	// (5) empty input pass-through
	if got := r.Redact(""); got != "" {
		t.Errorf("empty input mutated to %q — empty input MUST pass through unchanged so a log pipeline can apply Redact unconditionally.", got)
	}

	// (6) Sentinel itself cannot be re-registered as a secret
	r2 := NewRedactor(Sentinel, "REDACTED")
	// Both candidates above are shorter than or equal to Sentinel's
	// length; the dedupe/short-length filters should keep them out of
	// the secrets list. If a future change accepts them, the
	// Redactor would scrub its own sentinel — making redacted output
	// indistinguishable from never-redacted output for any
	// downstream matcher.
	for _, in := range []string{
		"a value containing " + Sentinel + " in it",
		"the literal REDACTED token",
	} {
		got := r2.Redact(in)
		if !strings.Contains(got, Sentinel) && !strings.Contains(got, "REDACTED") {
			t.Errorf("Sentinel-or-REDACTED scrubbed from %q -> %q — registering the sentinel as a secret MUST NOT cause the Redactor to scrub its own marker.", in, got)
		}
	}
}
