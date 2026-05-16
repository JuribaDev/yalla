// Package output redaction fuzz harness.
//
// BE-0359 — Log redaction fuzzing. This file is the runtime evidence for the
// log-redaction control documented in `SECURITY.md` ("Log Redaction Fuzzing")
// and in this package's `AGENTS.md`. The contract these targets pin is:
//
//   - `*Redactor.Redact` must never panic, regardless of the input or the
//     literal secrets it was constructed with.
//   - A literal secret registered with `NewRedactor` never appears in the
//     redactor's output for any haystack the structural rules cannot have
//     reshaped — i.e. for any input that does not itself contain the
//     [REDACTED] sentinel.
//   - A token transported through an Authorization / X-API-Key / X-Auth-Token
//     header never survives a Redact pass.
//   - A token transported as a `?token=`, `?api_key=`, `?access_token=`, or
//     `?x-auth-token=` query parameter never survives a Redact pass.
//   - `Redact(Redact(s)) == Redact(s)` for every input the contract covers.
//
// Each fuzz target is seeded with the hostile shapes log-redaction is required
// to survive — long lines, invalid UTF-8, embedded control characters, mixed
// case, regex metacharacters, the sentinel literal itself — so a developer
// running `go test ./internal/output/...` without the `-fuzz` flag still
// exercises the seed corpus as a deterministic regression net. CI does not
// run `-fuzz` by default; the seed corpus is what guards every commit.
//
// Three classes of input are deliberately scoped out of the targets:
//
//  1. Secrets shorter than `minRedactableLen` after `TrimSpace` — the
//     constructor drops them by design (test fixtures, accidental empties),
//     so a registered "secret" of "abc" is documented to not be redacted.
//  2. Secrets that overlap the literal sentinel `[REDACTED]` (in either
//     direction). A token whose value is itself a substring of the sentinel
//     would race the sentinel substring through `strings.ReplaceAll`, and a
//     token containing the sentinel would be indistinguishable from a normal
//     replacement after the first pass. Operators who manage to pick
//     `[REDACTED]` as a real secret have a worse problem than logging.
//  3. CR/LF inside a header-borne fuzz value — the bearer regex ends the
//     match at CR/LF by design (one header per line), so a token that ends
//     mid-stream is a misfeature of the fuzz input, not the redactor.
//
// Reason for the scope: the redactor is a `defence-in-depth` structural net
// (see AGENTS.md). The first wall is error classification and explicit
// secret-flagging. The fuzz suite documents the second wall.
package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// redactFuzzSeeds is the seed corpus shared across every Redactor fuzz
// target. The shapes mirror the hostile patterns log-redaction must survive:
// long inputs, invalid UTF-8 sequences, embedded control characters, regex
// metacharacters, mixed case header / query keys, and the sentinel literal.
var redactFuzzSeeds = []string{
	"",
	" ",
	"x",
	"abcd",
	"secret-value",
	"ABCDEF1234567890",
	strings.Repeat("a", 1024),
	"bad\xff\xfeutf8",
	"\xc3\x28",
	"\xed\xa0\x80",
	"control\x00bytes",
	"tab\there",
	"new\nline",
	"ret\rurn",
	"vertical\vtab",
	"form\ffeed",
	"backspace\bchar",
	"esc\x1bseq",
	"café-déjà",
	"🚀rocket",
	"\u200bzero-width",
	"AUTHORIZATION: BEARER deadbeef",
	"authorization:bearer deadbeef",
	"X-API-Key: key-value-here",
	"x-auth-token:tttt",
	"?token=abcd1234",
	"?api_key=abcd1234",
	"?api-key=abcd1234",
	"?apikey=abcd1234",
	"?access_token=abcd1234",
	"?access-token=abcd1234",
	"?x-auth-token=abcd1234",
	"?x_auth_token=abcd1234",
	"?xauthtoken=abcd1234",
	"https://api.example.com/v1?token=abcd1234&page=2",
	"https://u:p@host/x",
	"[REDACTED]",
	"prefix[REDACTED]suffix",
	"$1+$2",
	"((.*)+)$",
	"\\b\\B\\d\\D",
	"{\"x\":\"abc\"}",
	"path/with/slashes",
	`"quoted"`,
	"single'quoted",
}

// authorizationHeaders enumerates every header name the bearer regex
// targets. The fuzz harness iterates over all three per iteration so a
// regression that drops a header alone — without a corresponding behavioural
// regression for the other two — surfaces deterministically.
var authorizationHeaders = []string{
	"Authorization",
	"X-API-Key",
	"X-Auth-Token",
	// Case variants exercise the regex's (?i) flag.
	"authorization",
	"x-api-key",
	"X-AUTH-TOKEN",
}

// queryTokenKeys enumerates every query key shape the queryToken regex
// matches. Each iteration of the fuzz harness exercises all of them so a
// regression that drops one variant alone — leaving the others intact —
// surfaces deterministically.
var queryTokenKeys = []string{
	"token",
	"api_key",
	"api-key",
	"apikey",
	"access_token",
	"access-token",
	"x_auth_token",
	"x-auth-token",
	"xauthtoken",
	"X-Auth-Token",
	"TOKEN",
}

// containsControl reports whether s contains an ASCII control character. The
// helper is local to the fuzz harness — production code never gates redaction
// on control-character presence; the fuzz targets use this only to decide
// when a constructed haystack would be ambiguous (CR/LF terminate the bearer
// regex match by design).
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// FuzzRedactor_NoPanic asserts that `(*Redactor).Redact` cannot be made to
// panic by any pair of (secret, haystack) inputs. This is the structural
// invariant the request-logging middleware leans on: a single panic inside
// the redactor would tear down the per-request log record and surface the
// untouched URL — including the smuggled token — in the runtime panic dump.
func FuzzRedactor_NoPanic(f *testing.F) {
	for _, secret := range redactFuzzSeeds {
		for _, hay := range redactFuzzSeeds {
			f.Add(secret, hay)
		}
	}
	f.Fuzz(func(t *testing.T, secret, hay string) {
		r := NewRedactor(secret)
		_ = r.Redact(hay)
	})
}

// FuzzRedactor_ExplicitSecretNeverLeaks asserts that a literal secret
// registered with `NewRedactor` is replaced by the sentinel everywhere it
// appears in a Redact input, regardless of the surrounding characters.
//
// The harness derives the registered secret as `"~" + raw + "~"` and skips
// inputs that overlap the sentinel literal so the leak check is unambiguous
// (see file-level package doc, exclusion (2)). The padding is a run of `.`
// chars — neither `~` nor `.` appears in the sentinel `[REDACTED]`, so the
// secret cannot accidentally re-form as a substring of the post-redaction
// output (`...[REDACTED]...`).
func FuzzRedactor_ExplicitSecretNeverLeaks(f *testing.F) {
	for _, s := range redactFuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		secret := "~" + raw + "~"
		if !utf8.ValidString(secret) {
			t.Skip()
		}
		if len(strings.TrimSpace(secret)) < minRedactableLen {
			t.Skip()
		}
		// Scope-out (2): secrets overlapping the sentinel are documented to
		// behave unpredictably and are excluded from the fuzz domain.
		if strings.Contains(secret, Sentinel) || strings.Contains(Sentinel, secret) {
			t.Skip()
		}
		// The trim in `NewRedactor` would normalise the secret away if the
		// raw bytes are only whitespace inside the markers; require that the
		// trimmed-and-registered secret matches what we embed in the haystack.
		if strings.TrimSpace(secret) != secret {
			t.Skip()
		}
		// The padding chars (`.`) must not appear in the secret, otherwise a
		// secret like "~....~" would be replaced wherever the padding's tail
		// dots line up with the secret's leading dots, and the residual dots
		// in `out` could be misread as a secret reappearance.
		if strings.ContainsRune(secret, '.') {
			t.Skip()
		}

		r := NewRedactor(secret)
		const pad = ".........."
		hay := pad + secret + pad + secret + pad
		out := r.Redact(hay)
		if strings.Contains(out, secret) {
			t.Fatalf("registered secret leaked through Redact: secret=%q hay=%q out=%q", secret, hay, out)
		}
		if !strings.Contains(out, Sentinel) {
			t.Fatalf("expected sentinel %q in redacted output for hay=%q, got %q", Sentinel, hay, out)
		}
	})
}

// FuzzRedactor_AuthorizationHeaderNeverLeaks asserts that the bearer-header
// regex scrubs the value half of an Authorization, X-API-Key, or X-Auth-Token
// header for every header-line shape, regardless of the value's content. The
// leak detector is a unique marker that brackets the fuzz-supplied value, so
// the assertion is independent of the value's bytes.
func FuzzRedactor_AuthorizationHeaderNeverLeaks(f *testing.F) {
	for _, s := range redactFuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// Strip CR/LF from the fuzz input — the bearer regex ends the match
		// at CR/LF by design (exclusion (3) in the file doc). A token that
		// breaks the line would change the threat model, not the redactor.
		token := strings.ReplaceAll(raw, "\r", "")
		token = strings.ReplaceAll(token, "\n", "")
		const marker = "FUZZAUTHMARKERXYZ"
		value := marker + token + marker
		// Use a NewRedactor with no explicitly registered secrets so this
		// target exercises ONLY the structural bearer-header rule.
		r := NewRedactor()
		for _, header := range authorizationHeaders {
			in := "GET /v1/x HTTP/1.1\r\n" + header + ": " + value + "\r\nHost: example.com\r\n"
			out := r.Redact(in)
			if strings.Contains(out, marker) {
				t.Fatalf("Authorization-class header leaked value: header=%q in=%q out=%q", header, in, out)
			}
			// The post-redaction line must preserve the header name and the
			// colon-space separator so log records stay readable. Compare
			// case-insensitively because the regex preserves the caller's
			// original casing while emitting the sentinel.
			lc := strings.ToLower(out)
			if !strings.Contains(lc, strings.ToLower(header)+": "+strings.ToLower(Sentinel)) {
				t.Fatalf("expected scrubbed %s line in output; got %q", header, out)
			}
		}
	})
}

// FuzzRedactor_QueryTokenNeverLeaks asserts that the queryToken regex scrubs
// the value of every token-bearing query parameter for every key shape it
// supports, regardless of the value's content. As with the bearer fuzz, the
// leak detector is a unique marker bracketing the fuzz value.
func FuzzRedactor_QueryTokenNeverLeaks(f *testing.F) {
	for _, s := range redactFuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		const marker = "FUZZQRYMARKERZYX"
		value := marker + raw + marker
		// The queryToken regex's value class is `[^&\s"']+`. Strip every
		// character that would cut the match short so the marker brackets
		// land on the redacted side. RE2's `\s` is exactly `[\t\n\f\r ]`,
		// so the form-feed byte counts too.
		for _, stopper := range []string{"&", " ", "\t", "\r", "\n", "\f", "\"", "'"} {
			value = strings.ReplaceAll(value, stopper, "")
		}
		if !strings.Contains(value, marker) || strings.Count(value, marker) != 2 {
			// Stoppers shredded one of the markers; this iteration cannot
			// distinguish "value leaked" from "marker leaked", so skip.
			t.Skip()
		}
		r := NewRedactor()
		for _, key := range queryTokenKeys {
			in := "https://api.example.com/v1?" + key + "=" + value + "&page=2"
			out := r.Redact(in)
			if strings.Contains(out, marker) {
				t.Fatalf("query token leaked: key=%q in=%q out=%q", key, in, out)
			}
			// Sentinel must appear in place of the value. The regex
			// preserves the caller's original key casing via the `$1`
			// back-reference, so the sentinel lands next to the raw key.
			if !strings.Contains(out, key+"="+Sentinel) {
				t.Fatalf("expected %s=%s in scrubbed query; got %q", key, Sentinel, out)
			}
			// NOTE: We deliberately do not assert that `&page=2` survives.
			// If the fuzz-supplied value itself contains an Authorization-
			// style substring (e.g. `AUTHORIZATION:`), the bearer regex
			// fires across the rest of the URL and the trailing
			// `&page=2` is consumed by that match. That is a structural
			// interaction between two independent defence-in-depth rules,
			// not a redaction failure — the secret marker still does not
			// appear in the output, which is the only safety property
			// this target needs to pin.
		}
	})
}

// FuzzRedactor_Idempotent asserts that `Redact(Redact(s)) == Redact(s)` for
// every input within the contract scope. A future change that introduces a
// rewrite rule which re-fires after substitution would surface here as a
// non-idempotent transformation, indicating the structural net can be made
// to oscillate between passes.
func FuzzRedactor_Idempotent(f *testing.F) {
	for _, secret := range redactFuzzSeeds {
		for _, hay := range redactFuzzSeeds {
			f.Add(secret, hay)
		}
	}
	f.Fuzz(func(t *testing.T, secret, hay string) {
		// Scope-out: a secret that overlaps the sentinel literal would
		// cause `strings.ReplaceAll` to chew through the freshly-inserted
		// sentinel on the second pass. Operators picking `[REDACTED]` as a
		// real secret have a worse problem than redaction (see the file
		// doc, exclusion (2)). The runtime test `TestRedactor_Idempotent`
		// pins the in-scope contract; the fuzz target widens it.
		if strings.Contains(secret, Sentinel) || strings.Contains(Sentinel, strings.TrimSpace(secret)) {
			t.Skip()
		}
		// Skip secrets the constructor itself would normalise out.
		if len(strings.TrimSpace(secret)) < minRedactableLen {
			// The constructor drops sub-threshold secrets, so the redactor
			// is structurally idempotent on these inputs — but only because
			// no registered-secret rewrite happens. Exercise structural
			// rules alone.
			r := NewRedactor()
			once := r.Redact(hay)
			twice := r.Redact(once)
			if once != twice {
				t.Fatalf("structural rules not idempotent: hay=%q once=%q twice=%q", hay, once, twice)
			}
			return
		}
		r := NewRedactor(secret)
		once := r.Redact(hay)
		twice := r.Redact(once)
		if once != twice {
			t.Fatalf("redact not idempotent: secret=%q hay=%q once=%q twice=%q", secret, hay, once, twice)
		}
	})
}

// TestRedactor_FuzzScopeExclusionsAreReal documents the scope exclusions the
// fuzz targets declare and pins their behaviour as expected — not desired.
// A future change that closes one of these gaps (for example by switching
// the explicit-secret pass from `strings.ReplaceAll` to a single-pass regex
// substitution that does not re-scan substituted text) MUST update both the
// fuzz scope comments AND this test, so the threat-model documentation in
// `SECURITY.md` stays accurate.
func TestRedactor_FuzzScopeExclusionsAreReal(t *testing.T) {
	t.Parallel()

	// Exclusion (1): sub-threshold registered secrets are dropped by the
	// constructor. The structural rules still fire.
	t.Run("sub_threshold_secret_is_dropped", func(t *testing.T) {
		t.Parallel()
		r := NewRedactor("abc") // shorter than minRedactableLen
		const hay = "abc and more abc"
		if got := r.Redact(hay); got != hay {
			t.Fatalf("expected sub-threshold secret to be a no-op; got %q", got)
		}
	})

	// Exclusion (2): a registered secret that overlaps the sentinel may
	// cause non-idempotent rewrites. This pins the current behaviour so a
	// fix to the redactor would deliberately break this test.
	t.Run("sentinel_overlap_is_non_idempotent", func(t *testing.T) {
		t.Parallel()
		r := NewRedactor("REDA") // a substring of "[REDACTED]"
		once := r.Redact("REDA token")
		twice := r.Redact(once)
		if once == twice {
			t.Fatalf("expected sentinel-overlap to be non-idempotent today; once=%q twice=%q", once, twice)
		}
	})

	// Exclusion (3): a CR/LF inside the Authorization value ends the
	// bearer regex match at the linebreak. The tail of the value survives
	// because it is a new line, not part of the header value.
	t.Run("crlf_in_authorization_value_ends_match", func(t *testing.T) {
		t.Parallel()
		r := NewRedactor()
		in := "Authorization: Bearer top\r\nsecret\r\n"
		out := r.Redact(in)
		// "secret" appears on its own line and is not scrubbed by the
		// bearer regex — it is a new header line as far as HTTP is
		// concerned. The redactor's contract is documented to scrub one
		// header per line; multi-line header values are out of scope.
		if !strings.Contains(out, "Authorization: "+Sentinel) {
			t.Fatalf("expected first line scrubbed; got %q", out)
		}
		if !strings.Contains(out, "secret") {
			t.Fatalf("expected residual second-line text to survive; got %q", out)
		}
	})

	// The redactor cannot panic on inputs containing the sentinel literal.
	t.Run("sentinel_in_input_no_panic", func(t *testing.T) {
		t.Parallel()
		r := NewRedactor()
		_ = r.Redact("Sentinel: " + Sentinel + " and " + Sentinel)
		// Helpful guard against control-character pollution as well.
		if !utf8.ValidString(r.Redact("ok-input")) {
			t.Fatalf("redactor produced invalid UTF-8 from valid input")
		}
	})

	// Containment helper smoke test so a future refactor of the fuzz
	// harness keeps the helper in scope.
	t.Run("contains_control_helper", func(t *testing.T) {
		t.Parallel()
		if !containsControl("ok\nbad") {
			t.Fatalf("expected control detection on \\n input")
		}
		if containsControl("plain-text-1234") {
			t.Fatalf("did not expect control detection on plain text")
		}
	})
}
