package auth_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/output"
)

// API key rotation — runtime defence (BE-0352).
//
// Threat model: a long-lived API key in source control, in an exported
// shell history, or in a CI log is a permanent credential leak until it
// is rotated. The mitigation is `POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate`, which atomically
// swaps the row's credential body so every subsequent authentication
// attempt with the OLD token fails as cleanly as one against a non-
// existent key. The credential primitives this depends on live in this
// package — `auth.Generate`, `auth.HashSecret`, `auth.VerifySecret`,
// `auth.ParseToken`, and the redaction contract on `auth.Token`.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350,
// BE-0351) applies here. The static-analysis sibling lives in
// `internal/controlplane/store/api_key_rotation_static_test.go`; it
// pins the SQL UPDATE that swaps both prefix and secret_hash in one
// statement, the lifecycle conflict guards (`IsRevoked` / `IsExpired`),
// and the audit metadata closed-set invariant. This file is the
// runtime half: it drives the credential-primitive rotation lifecycle
// in-process (no database, no HTTP) and pins:
//
//   1. A rotation produces a NEW prefix and a NEW secret hash that are
//      distinct from the old credential body's. Equality on either half
//      would silently leave the old credential authenticating against
//      the row.
//   2. `VerifySecret(old_secret, new_hash) == false` and
//      `VerifySecret(new_secret, old_hash) == false`. This is the
//      strongest end-to-end statement of the "rotation invalidates the
//      old credential" property — independent of any storage layer.
//   3. The redaction contract on `auth.Token` holds for BOTH the old
//      and the new key across every standard rendering (fmt %v/%+v/%#v,
//      slog, json.Marshal) and across the embedding `GeneratedKey`
//      struct. Reveal() is the only escape hatch and is greppable; a
//      slog record that captures both tokens as `slog.Any(...)` must
//      surface only the redaction sentinel for both.
//   4. `Generate` keeps producing unique (prefix, secret, hash) tuples
//      at scale — a 2000-call rotation simulation never repeats any of
//      the three values. This is a smoke test of the entropy budget:
//      24 bytes (192 bits) of secret entropy is far beyond a birthday
//      collision at that scale, so any duplicate here points at a
//      regression in crypto/rand wiring or in the entropy split.

// TestRotationProducesDistinctCredentialPrimitives drives the
// credential-primitive lifecycle of a single rotation: mint k_old, mint
// k_new, then assert that every observable in the credential body has
// changed. The store-layer UPDATE that persists this swap is pinned by
// the static-analysis sibling test; here we prove the auth-layer
// guarantee that backs it.
func TestRotationProducesDistinctCredentialPrimitives(t *testing.T) {
	t.Parallel()

	old, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_old): %v", err)
	}
	new, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_new): %v", err)
	}

	if old.Prefix == "" || new.Prefix == "" {
		t.Fatalf("Generate returned an empty prefix — the rotation surface is broken: old=%q new=%q", old.Prefix, new.Prefix)
	}
	if old.SecretHash == "" || new.SecretHash == "" {
		t.Fatalf("Generate returned an empty secret hash — the rotation surface is broken")
	}

	if old.Prefix == new.Prefix {
		t.Errorf("rotation produced the same prefix twice — the old credential's prefix lookup would silently still hit the row")
	}
	if old.SecretHash == new.SecretHash {
		t.Errorf("rotation produced the same secret hash twice — the old credential's secret would still verify against the rotated row")
	}
	if old.Token.Reveal() == new.Token.Reveal() {
		t.Errorf("rotation produced the same plaintext token twice — the old credential is byte-identical to the new one")
	}
}

// TestRotationOldSecretFailsVerifyAgainstNewHash is the load-bearing
// end-to-end assertion of the rotation property: after a successful
// rotation, the old plaintext credential cannot pass VerifySecret
// against the new SecretHash that the store layer would have written
// to the row, and the new plaintext cannot pass against the old hash.
// A regression that re-uses the same SecretHash on rotation would fail
// this test by silently letting the old credential keep authenticating.
func TestRotationOldSecretFailsVerifyAgainstNewHash(t *testing.T) {
	t.Parallel()

	old, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_old): %v", err)
	}
	new, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_new): %v", err)
	}

	_, oldSecret, err := auth.ParseToken(old.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken (k_old): %v", err)
	}
	_, newSecret, err := auth.ParseToken(new.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken (k_new): %v", err)
	}

	// Sanity: each key must verify against its own hash before we assert
	// the cross-key non-verification. Otherwise a regression in
	// VerifySecret would silently pass the cross-key checks below.
	if !auth.VerifySecret(oldSecret, old.SecretHash) {
		t.Fatalf("VerifySecret(old.secret, old.hash) = false — VerifySecret is broken")
	}
	if !auth.VerifySecret(newSecret, new.SecretHash) {
		t.Fatalf("VerifySecret(new.secret, new.hash) = false — VerifySecret is broken")
	}

	if auth.VerifySecret(oldSecret, new.SecretHash) {
		t.Errorf("OLD secret verified against NEW hash — rotation is silently a no-op: the leaked credential keeps authenticating after the row is rotated")
	}
	if auth.VerifySecret(newSecret, old.SecretHash) {
		t.Errorf("NEW secret verified against OLD hash — rotation produced colliding credentials, which implies a catastrophic entropy regression")
	}
}

// TestRotationRedactionHoldsAcrossBothKeys captures every standard
// rendering of BOTH the old and the new `auth.Token` (fmt verbs %v/%+v/
// %#v, the String method, slog.Any, and json.Marshal) and asserts that
// (1) neither plaintext appears in any rendering and (2) every
// rendering contains the output.Sentinel. The point of running this
// check across both keys is that a regression in the redaction contract
// might affect only freshly-minted tokens (e.g. a refactor that caches
// the rendered form on first call and then leaks it on subsequent
// generations) — pinning the contract across two generations catches
// that class of bug.
func TestRotationRedactionHoldsAcrossBothKeys(t *testing.T) {
	t.Parallel()

	keys := map[string]auth.GeneratedKey{}
	for _, label := range []string{"k_old", "k_new"} {
		gen, err := auth.Generate()
		if err != nil {
			t.Fatalf("Generate (%s): %v", label, err)
		}
		keys[label] = gen
	}

	for label, gen := range keys {
		label, gen := label, gen
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			plaintext := gen.Token.Reveal()
			if plaintext == "" {
				t.Fatalf("%s: Reveal returned an empty token", label)
			}
			_, secret, err := auth.ParseToken(plaintext)
			if err != nil {
				t.Fatalf("%s: ParseToken: %v", label, err)
			}

			renderings := map[string]string{
				"%v":     fmt.Sprintf("%v", gen.Token),
				"%+v":    fmt.Sprintf("%+v", gen.Token),
				"%#v":    fmt.Sprintf("%#v", gen.Token),
				"String": gen.Token.String(),
				"slog":   slog.AnyValue(gen.Token).String(),
			}
			jsonBytes, err := json.Marshal(gen.Token)
			if err != nil {
				t.Fatalf("%s: json.Marshal(Token): %v", label, err)
			}
			renderings["json"] = string(jsonBytes)

			for verb, rendered := range renderings {
				if strings.Contains(rendered, plaintext) {
					t.Errorf("%s %s rendering leaked the plaintext token", label, verb)
				}
				if strings.Contains(rendered, secret) {
					t.Errorf("%s %s rendering leaked the bare secret body", label, verb)
				}
				if !strings.Contains(rendered, output.Sentinel) {
					t.Errorf("%s %s rendering = %q, want it to contain the redaction sentinel", label, verb, rendered)
				}
			}

			// The embedding GeneratedKey struct must redact too — a
			// future refactor that adds a new field carrying secret
			// material is caught by the broad sweep over %+v / %#v
			// / json.
			testutil.AssertRedactedValue(t, gen, plaintext, secret)
		})
	}
}

// TestRotationSlogStructuredRecordRedactsBothTokens drives the realistic
// "an operator logs both the old and new credential for a rotation
// audit" path through a slog JSON handler and asserts that the
// resulting JSON record carries neither plaintext nor secret body for
// either key, while still surfacing the redaction sentinel so a reader
// of the log can confirm the redaction took effect. A regression here
// would be a slog.Any path that bypasses the LogValue contract on
// auth.Token.
func TestRotationSlogStructuredRecordRedactsBothTokens(t *testing.T) {
	t.Parallel()

	old, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_old): %v", err)
	}
	new, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate (k_new): %v", err)
	}

	_, oldSecret, err := auth.ParseToken(old.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken (k_old): %v", err)
	}
	_, newSecret, err := auth.ParseToken(new.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken (k_new): %v", err)
	}

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	logger.Info(
		"api key rotated",
		slog.Any("k_old", old.Token),
		slog.Any("k_new", new.Token),
		slog.String("rotated_prefix", new.Prefix),
	)

	rendered := buf.String()

	secrets := []struct {
		label string
		value string
	}{
		{"old plaintext token", old.Token.Reveal()},
		{"new plaintext token", new.Token.Reveal()},
		{"old secret body", oldSecret},
		{"new secret body", newSecret},
		{"old secret hash", old.SecretHash},
		{"new secret hash", new.SecretHash},
	}
	for _, s := range secrets {
		if s.value == "" {
			t.Fatalf("test setup produced an empty %s — the redaction assertion would be vacuous", s.label)
		}
		if strings.Contains(rendered, s.value) {
			t.Errorf("slog JSON record leaked the %s into the log line: %s", s.label, rendered)
		}
	}

	// Parse the slog record back into a map so we can assert the
	// redaction sentinel landed in the named fields the operator would
	// look for, while the public prefix lookup id IS surfaced for
	// correlation (the rotated_prefix field, public by design, should
	// appear verbatim).
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal slog record: %v\nrendered: %s", err, rendered)
	}
	for _, field := range []string{"k_old", "k_new"} {
		got, ok := record[field]
		if !ok {
			t.Errorf("slog record is missing the %q field — the redacted projection disappeared", field)
			continue
		}
		gotStr, ok := got.(string)
		if !ok {
			t.Errorf("slog record %q field = %T(%v), want string", field, got, got)
			continue
		}
		if !strings.Contains(gotStr, output.Sentinel) {
			t.Errorf("slog record %q field = %q, want it to contain the redaction sentinel — an operator cannot confirm the redaction took effect", field, gotStr)
		}
	}
	gotPrefix, _ := record["rotated_prefix"].(string)
	if gotPrefix != new.Prefix {
		t.Errorf("slog record rotated_prefix = %q, want the NEW key's public prefix %q — operators must be able to correlate the rotation with the row's new lookup id", gotPrefix, new.Prefix)
	}
}

// TestRotationProducesUniqueCredentialsAtScale exercises a 2000-call
// rotation simulation and asserts that no prefix, no plaintext token,
// and no secret hash ever repeats across the simulation. The expected
// collision probability for 2000 draws over a 192-bit secret is far
// below 2^-130, so a repeat here points at a regression in crypto/rand
// wiring (a deterministic stub, a zero-seeded reader, an accidentally
// shared entropy buffer) rather than a real probabilistic collision.
func TestRotationProducesUniqueCredentialsAtScale(t *testing.T) {
	t.Parallel()

	const n = 2000

	prefixes := make(map[string]int, n)
	tokens := make(map[string]int, n)
	hashes := make(map[string]int, n)

	for i := 0; i < n; i++ {
		gen, err := auth.Generate()
		if err != nil {
			t.Fatalf("Generate (iter %d): %v", i, err)
		}
		if prev, dup := prefixes[gen.Prefix]; dup {
			t.Fatalf("rotation produced the same prefix twice across iterations %d and %d — crypto/rand wiring is regressed", prev, i)
		}
		if prev, dup := tokens[gen.Token.Reveal()]; dup {
			t.Fatalf("rotation produced the same plaintext token twice across iterations %d and %d — crypto/rand wiring is regressed", prev, i)
		}
		if prev, dup := hashes[gen.SecretHash]; dup {
			t.Fatalf("rotation produced the same secret hash twice across iterations %d and %d — crypto/rand wiring is regressed", prev, i)
		}
		prefixes[gen.Prefix] = i
		tokens[gen.Token.Reveal()] = i
		hashes[gen.SecretHash] = i
	}
}
