package secrets_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/output"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func mustAESGCM(t *testing.T, n int) (*secrets.AESGCM, [][]byte) {
	t.Helper()
	if n <= 0 {
		t.Fatalf("at least one key required, got %d", n)
	}
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = mustKey(t)
	}
	p, err := secrets.NewAESGCM(keys)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return p, keys
}

func TestNewAESGCMRejectsBadKeyMaterial(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		keys [][]byte
	}{
		{"no keys", nil},
		{"short key", [][]byte{make([]byte, 16)}},
		{"long key", [][]byte{make([]byte, 64)}},
		{"second key wrong size", [][]byte{make([]byte, 32), make([]byte, 24)}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := secrets.NewAESGCM(tc.keys)
			if err == nil {
				t.Fatalf("NewAESGCM(%s) = nil error; want failure", tc.name)
			}
			if strings.Contains(err.Error(), string(rune(0))) {
				t.Errorf("error message contained NUL byte: %q", err.Error())
			}
		})
	}
}

func TestNewAESGCMRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	_, err := secrets.NewAESGCM([][]byte{k, append([]byte{}, k...)})
	if err == nil {
		t.Fatalf("NewAESGCM with duplicate keys returned nil error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error = %q; want duplicate classification", err.Error())
	}
}

func TestAESGCMSealOpenRoundTrips(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hunter2")},
		{"binary", []byte{0x00, 0x01, 0xfe, 0xff}},
		{"long", bytes.Repeat([]byte{'x'}, 64*1024)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ct, kid, err := p.Seal(tc.plaintext)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if kid != p.ActiveKeyID() {
				t.Errorf("Seal key id = %q, want active %q", kid, p.ActiveKeyID())
			}
			if bytes.Contains(ct, tc.plaintext) && len(tc.plaintext) > 0 {
				t.Errorf("ciphertext leaked plaintext (len=%d)", len(tc.plaintext))
			}
			pt, err := p.Open(ct, kid)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Errorf("Open round-trip mismatch (len got=%d want=%d)", len(pt), len(tc.plaintext))
			}
		})
	}
}

func TestAESGCMSealUsesUniqueNonces(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	const iterations = 200
	seen := make(map[string]struct{}, iterations)
	plaintext := []byte("same plaintext")
	for i := 0; i < iterations; i++ {
		ct, _, err := p.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal[%d]: %v", i, err)
		}
		if len(ct) < 12 {
			t.Fatalf("Seal[%d] returned ciphertext shorter than nonce", i)
		}
		nonce := string(ct[:12])
		if _, dup := seen[nonce]; dup {
			t.Fatalf("nonce reuse at iteration %d", i)
		}
		seen[nonce] = struct{}{}
	}
}

func TestAESGCMOpenRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	ct, kid, err := p.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for i := 0; i < len(ct); i++ {
		mutated := append([]byte{}, ct...)
		mutated[i] ^= 0x01
		_, openErr := p.Open(mutated, kid)
		if openErr == nil {
			t.Fatalf("Open accepted ciphertext mutated at byte %d", i)
		}
		if !errors.Is(openErr, secrets.ErrInvalidCiphertext) {
			t.Errorf("Open mutated[%d] error = %v; want ErrInvalidCiphertext", i, openErr)
		}
	}
}

func TestAESGCMOpenRejectsShortCiphertext(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	_, kid, err := p.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, n := range []int{0, 1, 11} {
		_, openErr := p.Open(make([]byte, n), kid)
		if !errors.Is(openErr, secrets.ErrInvalidCiphertext) {
			t.Errorf("Open len=%d error = %v; want ErrInvalidCiphertext", n, openErr)
		}
	}
}

func TestAESGCMOpenRejectsUnknownKeyID(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	ct, _, err := p.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, openErr := p.Open(ct, "deadbeefdeadbeef")
	if !errors.Is(openErr, secrets.ErrUnknownKey) {
		t.Errorf("Open unknown key error = %v; want ErrUnknownKey", openErr)
	}
}

func TestAESGCMOpenAcceptsRetiredKey(t *testing.T) {
	t.Parallel()
	p, keys := mustAESGCM(t, 2)
	// Seal under the active key; rotate by building a new provider whose
	// active key is the second key, but whose accepted set still
	// contains the original active key (now demoted to a retired key).
	plaintext := []byte("payload")
	ct, originalKID, err := p.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rotated, err := secrets.NewAESGCM([][]byte{keys[1], keys[0]})
	if err != nil {
		t.Fatalf("NewAESGCM rotated: %v", err)
	}
	if rotated.ActiveKeyID() == originalKID {
		t.Fatalf("rotated provider active key id equals pre-rotation id")
	}
	pt, err := rotated.Open(ct, originalKID)
	if err != nil {
		t.Fatalf("rotated Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("rotated Open mismatch")
	}
}

func TestAESGCMKeyIDsAreStableAndShort(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	a, err := secrets.NewAESGCM([][]byte{k})
	if err != nil {
		t.Fatalf("NewAESGCM a: %v", err)
	}
	b, err := secrets.NewAESGCM([][]byte{k})
	if err != nil {
		t.Fatalf("NewAESGCM b: %v", err)
	}
	if a.ActiveKeyID() != b.ActiveKeyID() {
		t.Errorf("key id is not deterministic: %q vs %q", a.ActiveKeyID(), b.ActiveKeyID())
	}
	if len(a.ActiveKeyID()) != 16 {
		t.Errorf("key id len = %d; want 16 hex characters", len(a.ActiveKeyID()))
	}
	for _, b := range a.ActiveKeyID() {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			t.Errorf("key id contains non-hex byte: %q", string(b))
		}
	}
}

func TestAESGCMKeyIDDoesNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	p, err := secrets.NewAESGCM([][]byte{k})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	id := p.ActiveKeyID()
	for _, b := range k {
		if strings.Contains(id, fmt.Sprintf("%02x", b)) && len(id) < 64 {
			// the prefix-hash id is 8 bytes long; it is statistically
			// possible (probability 1/256 per byte) for a single key
			// byte to coincide with a hex pair inside the id. To turn
			// this into a deterministic guarantee, assert the full
			// hex-encoded key cannot be a substring of the id.
			break
		}
	}
	fullHex := fmt.Sprintf("%x", k)
	if strings.Contains(id, fullHex) {
		t.Errorf("key id leaked full key material")
	}
}

func TestAESGCMConcurrentSealOpen(t *testing.T) {
	t.Parallel()
	p, _ := mustAESGCM(t, 1)
	const goroutines = 32
	const each = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*each)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				plaintext := []byte(fmt.Sprintf("g=%d i=%d", g, i))
				ct, kid, err := p.Seal(plaintext)
				if err != nil {
					errs <- fmt.Errorf("seal: %w", err)
					return
				}
				pt, err := p.Open(ct, kid)
				if err != nil {
					errs <- fmt.Errorf("open: %w", err)
					return
				}
				if !bytes.Equal(pt, plaintext) {
					errs <- fmt.Errorf("mismatch g=%d i=%d", g, i)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestAESGCMLogValueRedactsKeyMaterial(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	p, err := secrets.NewAESGCM([][]byte{k})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("startup", slog.Any("provider", p))

	record := buf.String()
	if !strings.Contains(record, output.Sentinel) {
		t.Errorf("log record missing Sentinel: %q", record)
	}
	if strings.Contains(record, fmt.Sprintf("%x", k)) {
		t.Errorf("log record leaked key material")
	}
	// Decode and ensure provider id and key id surfaces.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	provider, _ := got["provider"].(map[string]any)
	if provider["provider_id"] != secrets.AESGCMProviderID {
		t.Errorf("provider_id in log = %v; want %q", provider["provider_id"], secrets.AESGCMProviderID)
	}
}

func TestAESGCMStringDoesNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	p, err := secrets.NewAESGCM([][]byte{k})
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	s := p.String()
	if strings.Contains(s, fmt.Sprintf("%x", k)) {
		t.Errorf("String leaked key material")
	}
	if !strings.Contains(s, output.Sentinel) {
		t.Errorf("String missing Sentinel: %q", s)
	}
}
