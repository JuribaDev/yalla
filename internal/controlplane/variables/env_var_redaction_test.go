// Package variables env-var redaction runtime fuzz harness.
//
// BE-0360 - Security verification: environment variable redaction.
//
// This file is the runtime evidence for the env-var redaction control
// documented in the top-level SECURITY.md section "Environment Variable
// Redaction" and in this package's AGENTS.md. The contract these targets
// pin is:
//
//   - (ScopedVariable).LogValue, (Rendered).LogValue, and
//     (Resolved).LogValue MUST NOT leak the plaintext Value nor the sealed
//     SecretCiphertext bytes into any slog record, for any haystack within
//     the contract scope.
//   - (Resolved).Explain MUST set ExplainedVariable.Value to
//     output.Sentinel for every entry, for every haystack within the
//     contract scope, AND a JSON-marshal of the projection MUST NOT
//     contain the plaintext or the sealed ciphertext bytes.
//   - A customer-controllable Key MAY appear in slog/JSON output (the key
//     is not a secret), but the per-value secret content must be redacted
//     even when the key itself contains hostile bytes (regex
//     metacharacters, control characters, the sentinel literal).
//
// Each fuzz target is seeded with the hostile shapes env-var redaction is
// required to survive - long values, invalid UTF-8, embedded control
// characters, regex metacharacters, the redaction sentinel itself,
// JSON-escape sequences - so a developer running `go test ./...` without
// the `-fuzz` flag still exercises the seed corpus as a deterministic
// regression net. CI does not run `-fuzz` by default; the seed corpus is
// what guards every commit. The marker-bracket pattern is borrowed from
// the BE-0359 log-redaction fuzz suite (internal/output/redact_fuzz_test.go):
// every fuzz-supplied secret is wrapped with a unique fixed marker
// (FUZZENVMARKERLMN) so the leak detector is independent of whether the
// secret bytes happen to equal a substring of the sentinel or the JSON
// envelope's framing characters.
//
// Two classes of input are deliberately scoped out of the targets:
//
//  1. The Key. Variable keys are validated against envVarName at the
//     resolver entry, so a Key carrying control characters never reaches
//     LogValue or Explain in production. The targets fix Key to a
//     POSIX-shell-valid identifier so the contract holds for the value
//     channel.
//  2. A fuzz-supplied raw containing the FUZZENVMARKERLMN marker itself
//     would false-positive every leak detector. The marker is the leak
//     detector; operators who pick the marker as a real value have a
//     worse problem than redaction.
package variables_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/variables"
	"github.com/JuribaDev/yalla/internal/output"
)

// envRedactFuzzSeeds is the seed corpus shared across every env-var
// redaction fuzz target. The shapes mirror the hostile patterns env-var
// redaction must survive: long values, invalid UTF-8, embedded control
// characters, JSON-escape sequences, regex metacharacters, the sentinel
// literal itself, and an empty string.
//
// Every literal uses explicit Go escape sequences (no raw bytes) so the
// file round-trips losslessly through any editor or transport that
// normalises non-ASCII characters.
//
// The marker bracketing is independent of these bytes: every fuzz-supplied
// secret is wrapped with envFuzzMarker so a leak surfaces as the marker
// appearing in the redacted output, regardless of whether the bytes
// themselves happen to overlap with the sentinel or the JSON framing.
var envRedactFuzzSeeds = []string{
	"",
	" ",
	"x",
	"abcd",
	"plaintext-value",
	"sk_live_abcdefghijklmnopqrstuvwxyz0123456789",
	strings.Repeat("A", 8192),
	"\x00\x01\x02\x03\x04",
	"\xff\xfe\xfd",
	"line1\nline2\rline3\r\nline4",
	"tab\there",
	"\xc2\x85nextline-after-NEL",
	"\"quote-and-\\backslash",
	"trailing-null-end\x00",
	"value with $shell `injection`",
	"{\"json\":\"value\",\"nested\":{\"key\":\"deep\"}}",
	".*regex|metacharacters[^a]+(group)?",
	"%s %d %v formatting",
	output.Sentinel,
	"prefix" + output.Sentinel + "suffix",
	"FUZZENVMARKERLMN-static-test-only",
	strings.Repeat("\x00", 64),
	strings.Repeat("\xc3\xa9", 1024),
}

const envFuzzMarker = "FUZZENVMARKERLMN"

// TestRedactionScopedVariableLogValueNeverLeaks asserts that the static
// guard's runtime counterpart holds: a ScopedVariable carrying a hostile
// plaintext and a hostile sealed-ciphertext content never lands either
// byte in a slog record. The leak detector is the marker bracketing the
// fuzz-supplied secret, so a sentinel-overlap, regex-metacharacter, or
// control-character secret cannot accidentally pass.
func TestRedactionScopedVariableLogValueNeverLeaks(t *testing.T) {
	t.Parallel()
	provider := plaintextProvider()
	for _, secret := range envRedactFuzzSeeds {
		secret := secret
		t.Run(seedName(secret), func(t *testing.T) {
			t.Parallel()
			ct, kid, err := provider.Seal([]byte(envFuzzMarker + secret + envFuzzMarker))
			if err != nil {
				t.Fatalf("Seal helper: %v", err)
			}
			v := variables.ScopedVariable{
				ResourceID:       "rsrc-1",
				Key:              "API_KEY",
				IsSecret:         true,
				SecretProvider:   provider.ProviderID(),
				SecretKeyID:      kid,
				SecretCiphertext: ct,
				Value:            envFuzzMarker + secret + envFuzzMarker,
			}
			out := captureSlog(t, "scoped", v)
			if strings.Contains(out, envFuzzMarker) {
				t.Fatalf("plaintext or ciphertext leaked through ScopedVariable.LogValue\n  marker: %q\n  output: %s",
					envFuzzMarker, out)
			}
			if !strings.Contains(out, output.Sentinel) {
				t.Fatalf("redaction sentinel missing from slog output: %s", out)
			}
		})
	}
}

// TestRedactionRenderedLogValueNeverLeaks pins the same invariant on the
// Rendered struct surfaced by Resolver.Resolve. A future regression that
// captured Rendered.Value into a slog field by mistake would surface as
// the marker appearing in the output for any seed.
func TestRedactionRenderedLogValueNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, secret := range envRedactFuzzSeeds {
		secret := secret
		t.Run(seedName(secret), func(t *testing.T) {
			t.Parallel()
			rendered := variables.Rendered{
				Key:      "API_KEY",
				Value:    envFuzzMarker + secret + envFuzzMarker,
				IsSecret: true,
				Source:   variables.SourceService,
				SourceID: "srv-1",
			}
			out := captureSlog(t, "rendered", rendered)
			if strings.Contains(out, envFuzzMarker) {
				t.Fatalf("plaintext leaked through Rendered.LogValue\n  marker: %q\n  output: %s",
					envFuzzMarker, out)
			}
			if !strings.Contains(out, output.Sentinel) {
				t.Fatalf("redaction sentinel missing from slog output: %s", out)
			}
		})
	}
}

// TestRedactionResolvedLogValueNeverLeaks pins the same invariant on the
// full merged set. Even with several distinct secrets contributing to the
// same Resolved value, the slog record must contain no fuzz markers.
func TestRedactionResolvedLogValueNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, secret := range envRedactFuzzSeeds {
		secret := secret
		t.Run(seedName(secret), func(t *testing.T) {
			t.Parallel()
			resolved := variables.Resolved{
				Variables: []variables.Rendered{
					{Key: "ALPHA", Value: envFuzzMarker + secret + envFuzzMarker, IsSecret: true, Source: variables.SourceService, SourceID: "srv-1"},
					{Key: "BETA", Value: "non-secret-" + envFuzzMarker + secret, IsSecret: false, Source: variables.SourceOrganization, SourceID: "org-1"},
				},
				Contributions: map[string][]variables.Contribution{
					"ALPHA": {{Source: variables.SourceService, SourceID: "srv-1", IsSecret: true}},
					"BETA":  {{Source: variables.SourceOrganization, SourceID: "org-1", IsSecret: false}},
				},
			}
			out := captureSlog(t, "resolved", resolved)
			if strings.Contains(out, envFuzzMarker) {
				t.Fatalf("plaintext leaked through Resolved.LogValue\n  marker: %q\n  output: %s",
					envFuzzMarker, out)
			}
			if !strings.Contains(out, output.Sentinel) {
				t.Fatalf("redaction sentinel missing from slog output: %s", out)
			}
		})
	}
}

// TestRedactionExplainProjectionNeverLeaks pins the customer-facing
// projection. For every seed, Resolved.Explain produces ExplainedVariable
// rows whose Value is output.Sentinel exactly - the bytes-equality is
// tighter than a contains check and catches a future regression that
// shortened the sentinel or pre-/post-fixed it with the value. The JSON
// marshalling of the projection must additionally not contain the fuzz
// marker (catches a JSON.Marshal regression that exposes an unexported
// shadow field, or a future addition of a non-redacted leg to
// ExplainedVariable).
func TestRedactionExplainProjectionNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, secret := range envRedactFuzzSeeds {
		secret := secret
		t.Run(seedName(secret), func(t *testing.T) {
			t.Parallel()
			resolved := variables.Resolved{
				Variables: []variables.Rendered{
					{Key: "ALPHA", Value: envFuzzMarker + secret + envFuzzMarker, IsSecret: true, Source: variables.SourceService, SourceID: "srv-1"},
				},
				Contributions: map[string][]variables.Contribution{
					"ALPHA": {{Source: variables.SourceService, SourceID: "srv-1", IsSecret: true}},
				},
			}
			explained := resolved.Explain()
			if len(explained.Variables) != 1 {
				t.Fatalf("expected 1 explained variable, got %d", len(explained.Variables))
			}
			if got := explained.Variables[0].Value; got != output.Sentinel {
				t.Fatalf("ExplainedVariable.Value = %q, want exactly output.Sentinel %q", got, output.Sentinel)
			}
			encoded, err := json.Marshal(explained)
			if err != nil {
				t.Fatalf("json.Marshal Explained: %v", err)
			}
			if bytes.Contains(encoded, []byte(envFuzzMarker)) {
				t.Fatalf("plaintext leaked through JSON projection\n  marker: %q\n  json:   %s",
					envFuzzMarker, encoded)
			}
		})
	}
}

// TestRedactionResolverOpenedSecretValueNeverEntersSlog drives the resolver
// end-to-end with a sealed row, then captures the slog output of the
// returned Resolved. The opened plaintext is recovered through the
// Plaintext provider, so a regression that captured Rendered.Value
// post-Open in a slog field would land the marker in the output.
func TestRedactionResolverOpenedSecretValueNeverEntersSlog(t *testing.T) {
	t.Parallel()
	provider := plaintextProvider()
	resolver, err := variables.NewResolver(provider)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	for _, secret := range envRedactFuzzSeeds {
		secret := secret
		t.Run(seedName(secret), func(t *testing.T) {
			t.Parallel()
			sealed := sealSecret(t, provider, "srv-1", "API_KEY",
				envFuzzMarker+secret+envFuzzMarker)
			in := variables.ResolveInput{
				ServiceVariables: []variables.ScopedVariable{sealed},
			}
			resolved, err := resolver.Resolve(in, variables.Options{})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(resolved.Variables) != 1 {
				t.Fatalf("expected 1 resolved variable, got %d", len(resolved.Variables))
			}
			out := captureSlog(t, "resolved", resolved, "first", resolved.Variables[0])
			if strings.Contains(out, envFuzzMarker) {
				t.Fatalf("plaintext leaked after Resolve+slog\n  marker: %q\n  output: %s",
					envFuzzMarker, out)
			}
			if !strings.Contains(out, output.Sentinel) {
				t.Fatalf("redaction sentinel missing from slog output: %s", out)
			}
			encoded, err := json.Marshal(resolved.Explain())
			if err != nil {
				t.Fatalf("json.Marshal explain: %v", err)
			}
			if bytes.Contains(encoded, []byte(envFuzzMarker)) {
				t.Fatalf("plaintext leaked through Explain after Resolve\n  marker: %q\n  json:   %s",
					envFuzzMarker, encoded)
			}
		})
	}
}

// FuzzRedactionScopedVariableLogValue widens the seed-corpus coverage of
// ScopedVariable.LogValue. Operators opt into the random-mutation stage via
// `go test -fuzz=FuzzRedactionScopedVariableLogValue ./internal/controlplane/variables`;
// CI runs the seed corpus only via `f.Add`.
func FuzzRedactionScopedVariableLogValue(f *testing.F) {
	for _, s := range envRedactFuzzSeeds {
		f.Add(s)
	}
	provider := plaintextProvider()
	f.Fuzz(func(t *testing.T, raw string) {
		// Scope-out: a fuzz-supplied raw containing the marker itself
		// would produce a false-positive leak.
		if strings.Contains(raw, envFuzzMarker) {
			t.Skip()
		}
		ct, kid, err := provider.Seal([]byte(envFuzzMarker + raw + envFuzzMarker))
		if err != nil {
			t.Skip()
		}
		v := variables.ScopedVariable{
			ResourceID:       "rsrc-1",
			Key:              "API_KEY",
			IsSecret:         true,
			SecretProvider:   provider.ProviderID(),
			SecretKeyID:      kid,
			SecretCiphertext: ct,
			Value:            envFuzzMarker + raw + envFuzzMarker,
		}
		out := captureSlog(t, "v", v)
		if strings.Contains(out, envFuzzMarker) {
			t.Fatalf("ScopedVariable.LogValue leaked marker %q for value %q: %s",
				envFuzzMarker, raw, out)
		}
	})
}

// FuzzRedactionExplain widens the seed-corpus coverage of Resolved.Explain.
// CI runs the seed corpus only; -fuzz exercises the mutation stage.
func FuzzRedactionExplain(f *testing.F) {
	for _, s := range envRedactFuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if strings.Contains(raw, envFuzzMarker) {
			t.Skip()
		}
		if !utf8.ValidString(raw) {
			// json.Marshal escapes invalid UTF-8 to U+FFFD which loses
			// the per-byte fidelity needed to detect a leak by substring.
			// The runtime test above covers invalid UTF-8 through the
			// slog path, where the JSON handler preserves the raw bytes
			// via the slog.Value string accessor. Skipping here keeps
			// the fuzz target's domain crisp.
			t.Skip()
		}
		resolved := variables.Resolved{
			Variables: []variables.Rendered{{
				Key:      "API_KEY",
				Value:    envFuzzMarker + raw + envFuzzMarker,
				IsSecret: true,
				Source:   variables.SourceService,
				SourceID: "srv-1",
			}},
			Contributions: map[string][]variables.Contribution{
				"API_KEY": {{Source: variables.SourceService, SourceID: "srv-1", IsSecret: true}},
			},
		}
		explained := resolved.Explain()
		for _, ev := range explained.Variables {
			if ev.Value != output.Sentinel {
				t.Fatalf("ExplainedVariable.Value = %q, want output.Sentinel", ev.Value)
			}
		}
		encoded, err := json.Marshal(explained)
		if err != nil {
			t.Skip()
		}
		if bytes.Contains(encoded, []byte(envFuzzMarker)) {
			t.Fatalf("Explain JSON leaked marker %q for value %q: %s",
				envFuzzMarker, raw, encoded)
		}
	})
}

// TestRedactionFuzzScopeExclusionsAreReal pins the documented scope
// exclusions as the current behaviour. A future change that closes one of
// the gaps MUST deliberately update this test and the matching
// SECURITY.md / AGENTS.md sections so the threat-model documentation
// stays accurate.
func TestRedactionFuzzScopeExclusionsAreReal(t *testing.T) {
	t.Parallel()
	// Exclusion (1): the seed corpus deliberately includes a marker-
	// prefixed literal ("FUZZENVMARKERLMN-static-test-only") to prove the
	// seed-corpus path still exercises the leak detector when the value
	// happens to look like the marker. The runtime targets above bracket
	// every seed with the marker, so a marker-prefixed seed lands two
	// markers in the value (the corpus-seeded one and the bracketing
	// one) - both must be redacted.
	hasMarker := false
	for _, s := range envRedactFuzzSeeds {
		if strings.Contains(s, envFuzzMarker) {
			hasMarker = true
			break
		}
	}
	if !hasMarker {
		t.Fatalf("seed corpus missing a marker-prefixed literal - the marker " +
			"collision exclusion is no longer exercised")
	}
	// Exclusion (2): the resolver validates Key against envVarName. A
	// fuzz-supplied Key with control characters never reaches LogValue
	// or Explain in production. The fuzz targets fix Key to a valid
	// identifier; a regression that allowed an invalid Key into the
	// fixture would surface as a resolver test failure elsewhere, not
	// here. Pin the invariant by asserting hostile-shaped seeds would
	// be rejected if they were used as Keys.
	provider := plaintextProvider()
	resolver, err := variables.NewResolver(provider)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	hostileChecked := 0
	for _, seed := range envRedactFuzzSeeds {
		if seed == "" {
			continue
		}
		if isValidEnvKeyShape(seed) {
			continue
		}
		hostileChecked++
		_, err := resolver.Resolve(variables.ResolveInput{
			ServiceVariables: []variables.ScopedVariable{{
				ResourceID: "srv-1",
				Key:        seed,
				Value:      "value",
			}},
		}, variables.Options{})
		if err == nil {
			t.Errorf("resolver accepted invalid key %q - the Key-shape exclusion is no longer enforced", seed)
		}
	}
	if hostileChecked == 0 {
		t.Fatalf("seed corpus contains no hostile-shaped seeds - the Key-shape exclusion is vacuous")
	}
}

// captureSlog returns the JSON-encoded slog output for one Info record
// with the supplied attrs. Used by every fuzz target above so the leak
// detector matches the redaction path the request logger relies on in
// production.
func captureSlog(t *testing.T, args ...any) string {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("captureSlog: odd number of attrs: %d", len(args))
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("captured", args...)
	return buf.String()
}

// seedName produces a stable, short, file-safe subtest name for a fuzz
// seed. The full seed bytes can be arbitrary (control characters, long
// strings, invalid UTF-8) so a literal name would break go test's name
// parser; a length-prefixed bytes-printable form keeps subtests
// distinguishable.
func seedName(seed string) string {
	switch {
	case seed == "":
		return "empty"
	case seed == " ":
		return "space"
	case len(seed) > 24:
		return "len" + itoa(len(seed))
	default:
		var b strings.Builder
		for _, r := range seed {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
				b.WriteRune(r)
			default:
				b.WriteRune('_')
			}
		}
		if b.Len() == 0 {
			return "ctrl_only"
		}
		return b.String()
	}
}

// isValidEnvKeyShape returns true for a string that matches the resolver's
// envVarName regex. The check is duplicated in the test to avoid exporting
// the regex from the package under test.
func isValidEnvKeyShape(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case (r >= '0' && r <= '9') && i > 0:
		default:
			return false
		}
	}
	return true
}

// itoa is a small int-to-string helper that avoids pulling strconv into
// this test file's import set. The values are always small (seed lengths).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Compile-time assertion that the Plaintext provider's wire id constant
// the test relies on still exists. A future provider rename that left
// this test untouched would fail to build, which is the right signal -
// the harness is not the place to discover an env-var redaction
// regression caused by an unrelated provider rename.
var _ = secrets.PlaintextProviderID
