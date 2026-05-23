package secrets

import "errors"

// ErrInvalidCiphertext signals that an Open call observed a ciphertext
// the provider cannot authenticate — wrong key id, corrupted bytes, or
// a deliberate tampering attempt. The error is value-free: it never
// echoes the ciphertext, the plaintext, the key id, the nonce, or any
// other input bytes. Callers that surface the error to a customer-
// facing channel MUST map it to apierr.Internal and never include the
// underlying cause in the public message — a successful tamper-detection
// is a server-side signal, not a customer instruction.
var ErrInvalidCiphertext = errors.New("secrets: ciphertext failed authentication")

// ErrUnknownKey signals that an Open call named a key id the provider
// does not currently hold. It is the typed signal a key-rotation
// operator looks for when scanning the database for rows that still
// reference a retired key. Like ErrInvalidCiphertext it is value-free.
var ErrUnknownKey = errors.New("secrets: unknown key id")

// ErrUnsupportedProvider signals that an Open call named a provider id
// the current process does not recognise (for example a row sealed by
// a since-retired provider that was not registered at startup). The
// error is value-free and surfaces as apierr.Internal on the customer-
// facing path.
var ErrUnsupportedProvider = errors.New("secrets: unsupported provider id")

// Provider seals plaintext secret bytes into a self-describing ciphertext
// blob and opens a previously sealed blob back into plaintext.
//
// Implementations MUST be safe for concurrent use. Implementations MUST
// authenticate every ciphertext so a tampered blob is detected by Open
// (returning a wrapped ErrInvalidCiphertext). Implementations MUST NOT
// log the plaintext, the ciphertext, the key material, the key id, or
// the nonce through any channel.
type Provider interface {
	// ProviderID is the stable wire identifier persisted alongside the
	// ciphertext. It is used to route Open to the correct provider when
	// multiple providers coexist (for example during a provider
	// migration), and as the value-free classifier the operator sees in
	// audit metadata. The empty string is reserved; production providers
	// MUST return a non-empty stable identifier (e.g. "aesgcm-v1").
	ProviderID() string

	// Seal encrypts plaintext under the provider's current active key.
	// It returns:
	//   - ciphertext: an opaque, authenticated blob the same provider
	//     can later Open. The blob is self-contained — Open does not
	//     require any caller-supplied context beyond the key id.
	//   - keyID: the stable identifier of the key used to seal. A
	//     future key-rotation story can list every row carrying a
	//     retired key id and Seal-then-store its plaintext under the
	//     new active key.
	//   - err: a value-free error if Seal cannot complete. Seal never
	//     panics on a misconfigured provider.
	Seal(plaintext []byte) (ciphertext []byte, keyID string, err error)

	// Open authenticates and decrypts a ciphertext blob previously
	// produced by this provider with the named keyID. It MUST return:
	//   - ErrUnknownKey if keyID is not in the provider's accepted set.
	//   - A wrapped ErrInvalidCiphertext if authentication fails.
	// Open never returns the plaintext on an authentication failure —
	// a tampered blob is never silently returned as plaintext.
	Open(ciphertext []byte, keyID string) (plaintext []byte, err error)
}
