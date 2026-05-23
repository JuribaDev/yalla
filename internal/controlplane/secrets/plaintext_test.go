package secrets_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
)

func TestPlaintextRoundTrip(t *testing.T) {
	t.Parallel()
	p := secrets.NewPlaintext()
	plaintext := []byte("payload")
	ct, kid, err := p.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if kid != secrets.PlaintextKeyID {
		t.Errorf("Seal kid = %q; want %q", kid, secrets.PlaintextKeyID)
	}
	if !bytes.Equal(ct, plaintext) {
		t.Errorf("Seal mutated bytes")
	}
	got, err := p.Open(ct, kid)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open round-trip mismatch")
	}
}

func TestPlaintextOpenRejectsWrongKey(t *testing.T) {
	t.Parallel()
	p := secrets.NewPlaintext()
	_, err := p.Open([]byte("payload"), "wrong-key")
	if !errors.Is(err, secrets.ErrUnknownKey) {
		t.Errorf("Open wrong key error = %v; want ErrUnknownKey", err)
	}
}

func TestPlaintextProviderID(t *testing.T) {
	t.Parallel()
	if got := secrets.NewPlaintext().ProviderID(); got != secrets.PlaintextProviderID {
		t.Errorf("ProviderID = %q; want %q", got, secrets.PlaintextProviderID)
	}
}

func TestPlaintextSealIsolatesInputBuffer(t *testing.T) {
	t.Parallel()
	p := secrets.NewPlaintext()
	src := []byte("payload")
	ct, _, err := p.Seal(src)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	src[0] = 'X'
	if ct[0] == 'X' {
		t.Errorf("Seal returned a slice aliasing the caller's buffer")
	}
}
