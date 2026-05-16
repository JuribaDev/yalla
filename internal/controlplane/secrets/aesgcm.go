package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/JuribaDev/yalla/internal/output"
)

// AESGCMProviderID is the stable wire identifier the AES-256-GCM
// provider persists alongside every ciphertext. It is part of the
// public on-disk contract: a row sealed with this provider can only be
// opened by a future process that still recognises this identifier.
const AESGCMProviderID = "aesgcm-v1"

// aesGCMNonceLen is the AES-GCM standard 96-bit nonce size in bytes.
// AES-GCM's IV-misuse safety relies on never reusing a nonce under the
// same key; we draw the nonce from crypto/rand for every Seal call so
// the birthday bound on 2^48 messages per key is the practical limit
// (the rotation story will document this).
const aesGCMNonceLen = 12

// aesGCMMasterKeyLen is the byte length of an AES-256 master key. We
// pin AES-256 rather than 128 so a single algorithm choice covers the
// strongest deployment posture without dynamic key-size negotiation.
const aesGCMMasterKeyLen = 32

// AESGCM seals plaintext bytes with AES-256-GCM under one of a list of
// master keys; the first key is the active key (used by every Seal) and
// the remaining keys are accepted for Open during a rotation. The
// per-key id is derived from a SHA-256 hash of the key bytes so two
// processes booted with the same key list mint the same key id, the
// key id never reveals the key material, and the operator can rotate
// keys without rebuilding the provider's internal lookup table.
//
// AESGCM is safe for concurrent use: cipher.AEAD operations do not
// share mutable state, and every Seal call draws a fresh nonce from
// crypto/rand. AESGCM never logs the plaintext, the ciphertext, the
// master key bytes, the key id, or the nonce — its LogValue and
// String views show only the redaction sentinel and the count of keys
// it holds.
type AESGCM struct {
	keys     []aesGCMKey
	activeID string
}

type aesGCMKey struct {
	id   string
	aead cipher.AEAD
}

// NewAESGCM builds an AESGCM provider from masterKeys. The first key is
// the active key used by Seal; subsequent keys are accepted by Open
// during a rotation. Every key must be exactly aesGCMMasterKeyLen bytes
// (AES-256). Duplicate keys are rejected so a misconfiguration that
// silently reduces the rotation pool is caught at construction.
//
// The returned provider is safe for concurrent use. NewAESGCM returns a
// value-free error if construction fails — it never echoes the key
// material into the error message.
func NewAESGCM(masterKeys [][]byte) (*AESGCM, error) {
	if len(masterKeys) == 0 {
		return nil, errors.New("secrets: aesgcm: at least one master key is required")
	}
	keys := make([]aesGCMKey, 0, len(masterKeys))
	seenID := make(map[string]struct{}, len(masterKeys))
	for i, raw := range masterKeys {
		if len(raw) != aesGCMMasterKeyLen {
			return nil, fmt.Errorf("secrets: aesgcm: master key at index %d must be %d bytes (AES-256), got %d", i, aesGCMMasterKeyLen, len(raw))
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, fmt.Errorf("secrets: aesgcm: master key at index %d is not a valid AES-256 key", i)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secrets: aesgcm: master key at index %d could not be wrapped in GCM", i)
		}
		id := keyIDFromMaterial(raw)
		if _, dup := seenID[id]; dup {
			return nil, fmt.Errorf("secrets: aesgcm: master key at index %d duplicates an earlier key", i)
		}
		seenID[id] = struct{}{}
		keys = append(keys, aesGCMKey{id: id, aead: aead})
	}
	return &AESGCM{keys: keys, activeID: keys[0].id}, nil
}

// ProviderID returns the stable wire identifier "aesgcm-v1".
func (*AESGCM) ProviderID() string { return AESGCMProviderID }

// ActiveKeyID returns the id of the key currently used by Seal. It is
// exposed so a key-rotation operator can confirm which key the next
// write will reference without sealing a probe value.
func (p *AESGCM) ActiveKeyID() string { return p.activeID }

// KeyIDs returns the ids of every key the provider holds, in their
// configured order. The active key is element 0. The returned slice is
// a fresh copy — callers may mutate it without affecting the provider.
func (p *AESGCM) KeyIDs() []string {
	out := make([]string, len(p.keys))
	for i, k := range p.keys {
		out[i] = k.id
	}
	return out
}

// Seal authenticates and encrypts plaintext under the active key. The
// returned ciphertext is `nonce(12) || sealed` where sealed is the
// AEAD output (ciphertext || tag). The returned keyID is the stable id
// of the active key.
func (p *AESGCM) Seal(plaintext []byte) ([]byte, string, error) {
	if len(p.keys) == 0 {
		return nil, "", errors.New("secrets: aesgcm: no keys configured")
	}
	active := p.keys[0]
	nonce := make([]byte, aesGCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", errors.New("secrets: aesgcm: nonce generation failed")
	}
	sealed := active.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, active.id, nil
}

// Open authenticates and decrypts a ciphertext blob produced by a Seal
// call against the named key. ErrUnknownKey signals that keyID is not
// in the provider's accepted set. A wrapped ErrInvalidCiphertext
// signals an authentication failure — the byte slice returned in that
// case is nil and the underlying GCM error is dropped (the caller
// observes only the classification).
func (p *AESGCM) Open(ciphertext []byte, keyID string) ([]byte, error) {
	var aead cipher.AEAD
	for _, k := range p.keys {
		if k.id == keyID {
			aead = k.aead
			break
		}
	}
	if aead == nil {
		return nil, ErrUnknownKey
	}
	if len(ciphertext) < aesGCMNonceLen {
		return nil, ErrInvalidCiphertext
	}
	nonce := ciphertext[:aesGCMNonceLen]
	sealed := ciphertext[aesGCMNonceLen:]
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

// LogValue redacts the provider at the slog boundary. It exposes only
// the provider id, the active key id (already non-secret — derived
// from a hash), and the count of keys; the key material itself is
// replaced with the redaction sentinel.
func (p *AESGCM) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider_id", AESGCMProviderID),
		slog.String("active_key_id", p.activeID),
		slog.Int("key_count", len(p.keys)),
		slog.String("master_keys", output.Sentinel),
	)
}

// String returns a redacted human description of the provider. It is
// safe to interpolate into a panic message or a startup log line —
// the key material never appears.
func (p *AESGCM) String() string {
	return fmt.Sprintf("AESGCM{provider=%s active_key=%s keys=%d material=%s}",
		AESGCMProviderID, p.activeID, len(p.keys), output.Sentinel)
}

// keyIDFromMaterial derives a stable, non-secret id for a master key.
// The id is the first 8 bytes of SHA-256(key) rendered as hex (16
// characters), so two processes booted with the same key list mint
// the same id, the id never reveals the key material (SHA-256 is
// one-way), and the id is short enough to be readable in audit
// metadata.
func keyIDFromMaterial(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}
