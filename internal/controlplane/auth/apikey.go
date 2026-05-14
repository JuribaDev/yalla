// Package auth implements the credential primitives for the Yalla Control
// Plane backend: API key generation, hashing, and verification.
//
// The token shape and hashing rules are a public compatibility contract:
//
//   - An API key token has the stable shape
//     "<namespace><prefix-random><separator><secret>". The namespace ("yk_")
//     makes a leaked credential identifiable on sight; the prefix is a public,
//     unguessable lookup key; the secret is the high-entropy credential body.
//   - Only a hash of the secret is ever stored. Generate returns the plaintext
//     token exactly once — to be shown to its owner and never persisted; the
//     persistence layer only ever sees Prefix and SecretHash.
//   - Verification is a constant-time comparison of secret hashes, so a timing
//     side channel cannot reveal the secret.
//   - The plaintext Token type redacts itself in every standard rendering
//     (fmt %v/%+v/%#v, slog, JSON). The plaintext is reachable only through an
//     explicit Reveal call, so it cannot leak into a log line, an error, or a
//     response body by accident.
//
// API key secrets carry 192 bits of cryptographic entropy, so a fast hash
// (SHA-256) is the correct choice here: slow password hashes defend
// low-entropy human secrets, which is not this threat model. The hash is
// unsalted, and therefore deterministic — a key is found by its public prefix,
// never by hashing a guess, and an attacker who reads a hash still faces a
// 192-bit pre-image search.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/JuribaDev/yalla/internal/output"
)

// ErrMalformedToken is returned by ParseToken when a string is not a
// structurally valid API key token. It carries no HTTP semantics on purpose:
// the auth middleware maps it to an Unauthenticated response. The malformed
// input is never echoed back.
var ErrMalformedToken = errors.New("auth: malformed api key token")

const (
	// tokenNamespace prefixes every API key token and its stored prefix, so a
	// leaked credential is identifiable on sight.
	tokenNamespace = "yk_"
	// tokenSeparator joins the public prefix to the secret body.
	tokenSeparator = "_"
	// prefixEntropyBytes is the entropy in a key's public prefix. The prefix
	// only needs to be an unguessable, collision-resistant lookup key;
	// uniqueness is additionally enforced by the database.
	prefixEntropyBytes = 8
	// secretEntropyBytes is the entropy in a key's secret body: 192 bits, far
	// beyond brute-force reach.
	secretEntropyBytes = 24
	// keyAlphabet is a lowercase Crockford base32 alphabet (no i, l, o, u):
	// unambiguous and safe to embed in URLs, shells, and logs.
	keyAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

// keyEncoding encodes random entropy into the key alphabet, without padding.
var keyEncoding = base32.NewEncoding(keyAlphabet).WithPadding(base32.NoPadding)

// Lengths derived once from the entropy budgets and the encoding, so ParseToken
// can validate a token's shape exactly.
var (
	prefixRandomLen = keyEncoding.EncodedLen(prefixEntropyBytes)
	secretLen       = keyEncoding.EncodedLen(secretEntropyBytes)
	prefixLen       = len(tokenNamespace) + prefixRandomLen
	tokenLen        = prefixLen + len(tokenSeparator) + secretLen
)

// Token is a plaintext API key token. It is a credential: every standard
// rendering — fmt's %v/%+v/%#v, slog, and JSON — yields the redaction sentinel
// instead of the secret, so a Token cannot leak into a log line, an error
// string, or a response body by accident. The plaintext is reachable only
// through the explicit Reveal method, which the create-key handler calls once
// to return the token to its owner.
type Token string

// String returns the redaction sentinel, never the plaintext.
func (t Token) String() string { return output.Sentinel }

// GoString returns the redaction sentinel so %#v cannot leak the plaintext.
func (t Token) GoString() string { return output.Sentinel }

// LogValue returns the redaction sentinel so slog never records the plaintext.
func (t Token) LogValue() slog.Value { return slog.StringValue(output.Sentinel) }

// MarshalJSON encodes the redaction sentinel so a Token can never be serialised
// into a response or audit record as plaintext.
func (t Token) MarshalJSON() ([]byte, error) { return json.Marshal(output.Sentinel) }

// Reveal returns the plaintext token. It is the only way to read the secret,
// and exists so that exposing a credential is always an explicit, greppable
// act.
func (t Token) Reveal() string { return string(t) }

// GeneratedKey is the result of Generate: the one-time plaintext Token to hand
// to the caller, plus the Prefix and SecretHash to persist. No usable
// credential is ever stored — only Prefix (public) and SecretHash (one-way)
// reach the database.
type GeneratedKey struct {
	// Token is the plaintext credential. It is shown to the caller exactly
	// once and is never persisted or logged.
	Token Token
	// Prefix is the public, unguessable lookup key. It is safe to store, log,
	// and display.
	Prefix string
	// SecretHash is the hash of the secret body — the only representation of
	// the secret that is ever persisted.
	SecretHash string
}

// Generate mints a fresh API key: a random public prefix and a random secret
// body, returned as a one-time plaintext Token together with the Prefix and
// SecretHash to persist. It surfaces any crypto/rand failure unchanged.
func Generate() (GeneratedKey, error) {
	prefixRandom, err := randomString(prefixEntropyBytes)
	if err != nil {
		return GeneratedKey{}, err
	}
	secret, err := randomString(secretEntropyBytes)
	if err != nil {
		return GeneratedKey{}, err
	}
	prefix := tokenNamespace + prefixRandom
	return GeneratedKey{
		Token:      Token(prefix + tokenSeparator + secret),
		Prefix:     prefix,
		SecretHash: HashSecret(secret),
	}, nil
}

// HashSecret returns the hex-encoded SHA-256 hash of an API key secret body.
// It is deterministic: the same secret always hashes to the same value, which
// is why a key is found by its public prefix and never by hashing a guess.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// VerifySecret reports whether secret hashes to hash. The comparison is
// constant-time, so a caller cannot learn the secret from how long a failed
// verification takes. A mismatch in length also fails in constant time.
func VerifySecret(secret, hash string) bool {
	computed := HashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

// ParseToken splits a plaintext API key token into its public prefix and its
// secret body, validating the token's shape. The prefix is what the
// persistence layer looks a candidate key up by; the secret is what
// VerifySecret checks against the stored hash. A token of the wrong shape —
// wrong namespace, wrong length, wrong separator, or a character outside the
// key alphabet — yields ErrMalformedToken, and the malformed input is never
// echoed back.
func ParseToken(token string) (prefix, secret string, err error) {
	if len(token) != tokenLen {
		return "", "", ErrMalformedToken
	}
	if token[:len(tokenNamespace)] != tokenNamespace {
		return "", "", ErrMalformedToken
	}
	if token[prefixLen:prefixLen+len(tokenSeparator)] != tokenSeparator {
		return "", "", ErrMalformedToken
	}
	prefix = token[:prefixLen]
	secret = token[prefixLen+len(tokenSeparator):]
	if !inAlphabet(prefix[len(tokenNamespace):]) || !inAlphabet(secret) {
		return "", "", ErrMalformedToken
	}
	return prefix, secret, nil
}

// randomString returns n bytes of cryptographic entropy encoded in the key
// alphabet.
func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generating key entropy: %w", err)
	}
	return keyEncoding.EncodeToString(buf), nil
}

// inAlphabet reports whether every byte of s is in the key alphabet.
func inAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(keyAlphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}
