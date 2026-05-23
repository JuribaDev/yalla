package secrets

import (
	"errors"
	"fmt"
	"log/slog"
)

// PlaintextProviderID is the stable wire identifier the plaintext
// provider persists alongside every "ciphertext". A row sealed by the
// plaintext provider can ONLY be opened by a process that also wired
// the plaintext provider — production wiring refuses to build the
// plaintext provider, so a row carrying this identifier cannot reach
// production.
const PlaintextProviderID = "plaintext-v1"

// PlaintextKeyID is the constant key id the plaintext provider returns
// from Seal. It is a fixed sentinel rather than a generated id so a
// test asserting "Seal returns the expected key id" does not couple to
// a per-process secret.
const PlaintextKeyID = "plaintext"

// Plaintext is a passthrough Provider that performs no encryption. It
// is intended for unit tests and local development only — production
// wiring refuses to build it (see cmd/yalla-api/main.go and
// internal/controlplane/config). Open is still authenticated in the
// trivial sense that an unknown key id is rejected, so a test that
// accidentally hands a Plaintext-sealed value to an AESGCM Open will
// fail with a clear ErrUnsupportedProvider/ErrUnknownKey rather than
// silently returning attacker-controlled bytes.
//
// Plaintext is safe for concurrent use (its methods have no mutable
// state).
type Plaintext struct{}

// NewPlaintext builds the passthrough provider. The zero value works
// too; the constructor exists for symmetry with NewAESGCM.
func NewPlaintext() *Plaintext { return &Plaintext{} }

// ProviderID returns the stable wire identifier "plaintext-v1".
func (*Plaintext) ProviderID() string { return PlaintextProviderID }

// Seal returns plaintext as-is. The returned key id is the constant
// PlaintextKeyID so a future Open can verify routing without depending
// on per-process state.
func (*Plaintext) Seal(plaintext []byte) ([]byte, string, error) {
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, PlaintextKeyID, nil
}

// Open returns the input as-is when keyID matches PlaintextKeyID, and
// ErrUnknownKey otherwise.
func (*Plaintext) Open(ciphertext []byte, keyID string) ([]byte, error) {
	if keyID != PlaintextKeyID {
		return nil, ErrUnknownKey
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

// LogValue exposes only the provider identifier through slog.
func (*Plaintext) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider_id", PlaintextProviderID),
		slog.String("active_key_id", PlaintextKeyID),
	)
}

// String returns a fixed identifier; the plaintext provider has no
// secret material to redact.
func (*Plaintext) String() string {
	return fmt.Sprintf("Plaintext{provider=%s active_key=%s}", PlaintextProviderID, PlaintextKeyID)
}

// guard variable so go vet recognises the package-level errors.As/Is
// idiom that other packages will rely on.
var _ = errors.New
