package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/output"
)

// Unit tests for the API key credential primitives: generation, hashing,
// constant-time verification, token parsing, and the redaction contract on the
// plaintext Token type. None of these touch a database.

func TestGenerateProducesAParseableVerifiableKey(t *testing.T) {
	t.Parallel()

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.Prefix == "" || gen.SecretHash == "" {
		t.Fatalf("Generate returned an empty prefix/hash: %+v", gen)
	}

	prefix, secret, err := auth.ParseToken(gen.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken(generated token): %v", err)
	}
	if prefix != gen.Prefix {
		t.Errorf("parsed prefix = %q, want %q", prefix, gen.Prefix)
	}
	if !auth.VerifySecret(secret, gen.SecretHash) {
		t.Error("VerifySecret rejected the secret of a freshly generated key")
	}
	// The hash is not the secret, and the stored prefix is not a usable token.
	if gen.SecretHash == secret {
		t.Error("SecretHash equals the plaintext secret — the secret was stored verbatim")
	}
}

func TestGenerateProducesUniqueKeys(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		gen, err := auth.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		for _, v := range []string{gen.Prefix, gen.Token.Reveal(), gen.SecretHash} {
			if seen[v] {
				t.Fatalf("Generate produced a duplicate value on iteration %d", i)
			}
			seen[v] = true
		}
	}
}

func TestHashSecretIsDeterministic(t *testing.T) {
	t.Parallel()

	if a, b := auth.HashSecret("the-secret"), auth.HashSecret("the-secret"); a != b {
		t.Errorf("HashSecret is not deterministic: %q != %q", a, b)
	}
	if a, b := auth.HashSecret("one"), auth.HashSecret("two"); a == b {
		t.Error("HashSecret produced the same hash for different secrets")
	}
}

func TestVerifySecret(t *testing.T) {
	t.Parallel()

	hash := auth.HashSecret("correct-secret")
	cases := []struct {
		name   string
		secret string
		hash   string
		want   bool
	}{
		{"correct secret", "correct-secret", hash, true},
		{"wrong secret", "wrong-secret", hash, false},
		{"empty secret", "", hash, false},
		{"empty hash", "correct-secret", "", false},
		{"tampered hash", "correct-secret", hash[:len(hash)-1] + "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := auth.VerifySecret(tc.secret, tc.hash); got != tc.want {
				t.Errorf("VerifySecret(%q, hash) = %v, want %v", tc.secret, got, tc.want)
			}
		})
	}
}

func TestParseTokenRejectsMalformedTokens(t *testing.T) {
	t.Parallel()

	good, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	valid := good.Token.Reveal()

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"namespace only", "yk_"},
		{"wrong namespace", "zz_" + valid[3:]},
		{"too short", valid[:len(valid)-1]},
		{"too long", valid + "0"},
		{"missing separator", strings.Replace(valid, "_", "0", 2)},
		{"uppercase in secret", strings.ToUpper(valid)},
		{"invalid char in secret", valid[:len(valid)-1] + "!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := auth.ParseToken(tc.token); !errors.Is(err, auth.ErrMalformedToken) {
				t.Errorf("ParseToken(%q) error = %v, want ErrMalformedToken", tc.name, err)
			}
		})
	}

	// The valid control still parses.
	if _, _, err := auth.ParseToken(valid); err != nil {
		t.Errorf("ParseToken(valid token) = %v, want nil", err)
	}
}

func TestTokenRedactsItselfInEveryRendering(t *testing.T) {
	t.Parallel()

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	plaintext := gen.Token.Reveal()
	if plaintext == "" {
		t.Fatal("Reveal returned an empty token")
	}

	// fmt verbs, slog, and JSON must all yield the sentinel, never the secret.
	renderings := map[string]string{
		"%v":     fmt.Sprintf("%v", gen.Token),
		"%+v":    fmt.Sprintf("%+v", gen.Token),
		"%#v":    fmt.Sprintf("%#v", gen.Token),
		"String": gen.Token.String(),
		"slog":   slog.AnyValue(gen.Token).String(),
	}
	jsonBytes, err := json.Marshal(gen.Token)
	if err != nil {
		t.Fatalf("json.Marshal(Token): %v", err)
	}
	renderings["json"] = string(jsonBytes)

	for verb, rendered := range renderings {
		if strings.Contains(rendered, plaintext) {
			t.Errorf("%s rendering leaked the plaintext token", verb)
		}
		if !strings.Contains(rendered, output.Sentinel) {
			t.Errorf("%s rendering = %q, want it to contain the redaction sentinel", verb, rendered)
		}
	}
}

func TestGeneratedKeyNeverLeaksTheSecret(t *testing.T) {
	t.Parallel()

	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, secret, err := auth.ParseToken(gen.Token.Reveal())
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}

	// Neither the full plaintext token nor the bare secret body may appear in
	// any standard rendering of the GeneratedKey struct (%+v, %#v, JSON).
	testutil.AssertRedactedValue(t, gen, gen.Token.Reveal(), secret)
}
