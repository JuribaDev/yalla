package secrets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/output"
)

// Runtime verification of the secret encryption key rotation contract
// (BE-0351). The static half lives in `key_rotation_static_test.go` and
// pins the rotation surface methods exist with the documented shape.
// This file pins the runtime behaviour: the full three-phase lifecycle
// (pre-rotation, mid-rotation, post-retirement) actually decrypts an
// old ciphertext, actually seals new ciphertext under the new active
// key, and actually surfaces `ErrUnknownKey` for a row missed by the
// re-seal worker after the retired key is dropped — AND the structured
// log boundary stays redacted at every phase. The runbook and threat
// model are documented in this package's AGENTS.md.

// freshKey returns a 32-byte AES-256 master key drawn from crypto/rand.
// The helper is local so the rotation tests do not depend on the
// other test files' helpers (`mustKey`, `mustAESGCM`) — each rotation
// phase rebuilds its provider from raw bytes so the test reads as the
// operator runbook does.
func freshKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

// TestAESGCMRotationLifecycle drives the full three-phase rotation
// lifecycle and asserts the load-bearing invariants at each phase. The
// test mirrors the operator runbook line-for-line so a future reader
// can compare the runbook in AGENTS.md against the executable contract
// here.
//
// Phase 1 (pre-rotation): provider holds [k_old]. Seal a payload, capture
// the (ciphertext, key id) pair the source-of-truth row would persist.
//
// Phase 2 (mid-rotation): a fresh provider holds [k_new, k_old]. The new
// provider's ActiveKeyID is the id of k_new (every new Seal lands under
// k_new), but the pre-rotation ciphertext sealed under k_old still
// decrypts because Open walks the configured keys slice. The re-seal
// worker can now drain the routing-index backlog: Open(ct, k_old_id) ->
// Seal(plaintext) -> (ct_new, k_new_id). The freshly sealed ciphertext
// references the new active key id and decrypts under that id with the
// original plaintext intact.
//
// Phase 3 (post-retirement): a fresh provider holds [k_new] only. Open
// of a row the re-seal worker missed (the pre-rotation ciphertext that
// still names k_old's id) surfaces ErrUnknownKey — the typed operator
// signal that step 3 of the runbook missed something. A row the
// re-seal worker did process (the (ct_new, k_new_id) tuple) opens
// cleanly with the original plaintext.
//
// If any of the four invariants below regress, the rotation contract
// breaks in a way the static analyser cannot catch and customer data
// becomes either inaccessible (k_old dropped before the re-seal
// finishes) or silently mis-attributed (Open ignored the named key id
// and decrypted under the wrong key).
func TestAESGCMRotationLifecycle(t *testing.T) {
	t.Parallel()

	plaintext := []byte("organization-variable-secret-value")

	// Phase 1: pre-rotation provider seals under k_old.
	kOld := freshKey(t)
	preRotation, err := secrets.NewAESGCM([][]byte{kOld})
	if err != nil {
		t.Fatalf("NewAESGCM pre-rotation: %v", err)
	}
	preActiveID := preRotation.ActiveKeyID()
	if preActiveID == "" {
		t.Fatalf("pre-rotation ActiveKeyID is empty — operators cannot record the key id of the row's ciphertext")
	}
	if ids := preRotation.KeyIDs(); len(ids) != 1 || ids[0] != preActiveID {
		t.Fatalf("pre-rotation KeyIDs = %v; want [%q]", ids, preActiveID)
	}
	ctOld, ctOldKID, err := preRotation.Seal(plaintext)
	if err != nil {
		t.Fatalf("pre-rotation Seal: %v", err)
	}
	if ctOldKID != preActiveID {
		t.Fatalf("pre-rotation Seal kid = %q; want active %q", ctOldKID, preActiveID)
	}

	// Phase 2: mid-rotation provider holds [k_new, k_old]. The new key
	// is active for Seal, the old key stays accepted for Open until the
	// routing-index backlog drains.
	kNew := freshKey(t)
	midRotation, err := secrets.NewAESGCM([][]byte{kNew, kOld})
	if err != nil {
		t.Fatalf("NewAESGCM mid-rotation: %v", err)
	}
	midActiveID := midRotation.ActiveKeyID()
	if midActiveID == preActiveID {
		t.Fatalf("mid-rotation ActiveKeyID = %q matches pre-rotation %q — the rotation did not take effect; new Seals would still land under the old key", midActiveID, preActiveID)
	}
	midAccepted := midRotation.KeyIDs()
	if len(midAccepted) != 2 {
		t.Fatalf("mid-rotation KeyIDs len = %d; want 2 (new active + retired)", len(midAccepted))
	}
	if midAccepted[0] != midActiveID {
		t.Fatalf("mid-rotation KeyIDs[0] = %q; want active %q — KeyIDs[0] is part of the public contract: the rotation worker reads it as the seal target", midAccepted[0], midActiveID)
	}
	if midAccepted[1] != preActiveID {
		t.Fatalf("mid-rotation KeyIDs[1] = %q; want retired %q — the retired key id must stay in the accepted set during the rotation window", midAccepted[1], preActiveID)
	}

	// Load-bearing rotation invariant #1: the pre-rotation ciphertext
	// still decrypts under the mid-rotation provider via its original
	// (retired) key id. A regression here means existing rows become
	// undecryptable the moment a new key is rolled in.
	gotPlain, err := midRotation.Open(ctOld, ctOldKID)
	if err != nil {
		t.Fatalf("mid-rotation Open(ct_old, k_old_id): %v — the multi-key accept window is broken; existing rows are now undecryptable", err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("mid-rotation Open returned wrong plaintext: got %q, want %q", gotPlain, plaintext)
	}

	// Load-bearing rotation invariant #2: a fresh Seal under the
	// mid-rotation provider references the new active key id. A
	// regression here means rotations never advance — every new write
	// keeps landing under the retired key.
	ctMidProbe, ctMidProbeKID, err := midRotation.Seal([]byte("probe"))
	if err != nil {
		t.Fatalf("mid-rotation Seal probe: %v", err)
	}
	if ctMidProbeKID != midActiveID {
		t.Fatalf("mid-rotation Seal kid = %q; want active %q — new writes are not landing under the rotated key", ctMidProbeKID, midActiveID)
	}
	// The probe ciphertext is openable under the new active key id and
	// NOT under the retired one (its nonce is fresh; the retired key
	// has no relationship to the new ciphertext).
	if _, err := midRotation.Open(ctMidProbe, midActiveID); err != nil {
		t.Fatalf("mid-rotation Open(ct_probe, k_new_id): %v", err)
	}
	if _, err := midRotation.Open(ctMidProbe, preActiveID); !errors.Is(err, secrets.ErrInvalidCiphertext) {
		t.Fatalf("mid-rotation Open(ct_probe, k_old_id) error = %v; want ErrInvalidCiphertext — a fresh ciphertext under k_new must NOT decrypt under k_old's id", err)
	}

	// Re-seal pass: the rotation worker's loop body. Open the row's
	// ciphertext under its recorded key id, Seal the plaintext under the
	// new active key, persist the new (ct, kid). The store-layer UPDATE
	// is not exercised here — this test owns the cryptographic seam.
	reOpened, err := midRotation.Open(ctOld, ctOldKID)
	if err != nil {
		t.Fatalf("re-seal Open: %v", err)
	}
	ctRotated, ctRotatedKID, err := midRotation.Seal(reOpened)
	if err != nil {
		t.Fatalf("re-seal Seal: %v", err)
	}
	if ctRotatedKID != midActiveID {
		t.Fatalf("re-seal Seal kid = %q; want active %q", ctRotatedKID, midActiveID)
	}
	if bytes.Equal(ctRotated, ctOld) {
		t.Fatalf("re-seal Seal produced the same ciphertext as pre-rotation — the nonce or key did not advance, which means the rotation worker's UPDATE would be a no-op")
	}
	roundTrip, err := midRotation.Open(ctRotated, ctRotatedKID)
	if err != nil {
		t.Fatalf("re-seal Open(ct_rotated, k_new_id): %v", err)
	}
	if !bytes.Equal(roundTrip, plaintext) {
		t.Fatalf("re-seal round-trip mismatch: got %q, want %q — the rotation step would corrupt the row", roundTrip, plaintext)
	}

	// Phase 3: post-retirement provider holds [k_new] only. The retired
	// key id is now outside the accepted set.
	postRotation, err := secrets.NewAESGCM([][]byte{kNew})
	if err != nil {
		t.Fatalf("NewAESGCM post-rotation: %v", err)
	}
	if postRotation.ActiveKeyID() != midActiveID {
		t.Fatalf("post-rotation ActiveKeyID = %q; want stable across drop %q", postRotation.ActiveKeyID(), midActiveID)
	}
	if ids := postRotation.KeyIDs(); len(ids) != 1 || ids[0] != midActiveID {
		t.Fatalf("post-rotation KeyIDs = %v; want [%q] — the retired key id must NOT linger in the accepted set after the operator drops it", ids, midActiveID)
	}

	// Load-bearing rotation invariant #3: a row the re-seal worker
	// processed (ctRotated under k_new) still opens cleanly. The
	// rotation completes without invalidating data the worker touched.
	gotRotated, err := postRotation.Open(ctRotated, ctRotatedKID)
	if err != nil {
		t.Fatalf("post-rotation Open(ct_rotated, k_new_id): %v — re-sealed rows are now undecryptable", err)
	}
	if !bytes.Equal(gotRotated, plaintext) {
		t.Fatalf("post-rotation Open returned wrong plaintext: got %q, want %q", gotRotated, plaintext)
	}

	// Load-bearing rotation invariant #4: a row the re-seal worker
	// MISSED (the pre-rotation ciphertext still naming k_old's id)
	// surfaces ErrUnknownKey — NOT ErrInvalidCiphertext, NOT a silent
	// plaintext recovery, NOT a panic. ErrUnknownKey is the typed
	// operator signal that the routing-index backlog drained before
	// every row was rotated. A regression that returns
	// ErrInvalidCiphertext instead would let the missed row look
	// indistinguishable from a tampered row to the audit pipeline; a
	// regression that returns plaintext would silently re-decrypt under
	// the wrong key.
	if _, err := postRotation.Open(ctOld, ctOldKID); !errors.Is(err, secrets.ErrUnknownKey) {
		t.Fatalf("post-rotation Open(ct_old, k_old_id) error = %v; want ErrUnknownKey — the operator signal for a row missed by the re-seal worker is broken", err)
	}
}

// TestAESGCMRotationDoesNotLeak drives the same three-phase rotation
// lifecycle as TestAESGCMRotationLifecycle and asserts the redacted-
// projection contract holds at every phase. The structured-log
// boundary (LogValue) and the fmt.Stringer boundary (String) are the
// only channels through which a provider can land in operator-visible
// logs; both MUST expose only the non-secret rotation metadata
// (provider id, active key id, key count) and never the master key
// material, the plaintext that just flowed through Seal, or the
// ciphertext bytes that just flowed through Open.
//
// The redaction invariant is necessary even though the static analyser
// pins the LogValue / String shapes by name — a future refactor could
// add a new field to the LogValue group (a debug field, a metric, an
// internal counter) that accidentally exposes secret bytes. This test
// pins the invariant at runtime by capturing the JSON record and
// asserting no master key byte appears anywhere in it, for every
// provider shape across the rotation.
func TestAESGCMRotationDoesNotLeak(t *testing.T) {
	t.Parallel()

	plaintext := []byte("rotation-redaction-plaintext-probe")

	kOld := freshKey(t)
	kNew := freshKey(t)

	pre, err := secrets.NewAESGCM([][]byte{kOld})
	if err != nil {
		t.Fatalf("NewAESGCM pre: %v", err)
	}
	mid, err := secrets.NewAESGCM([][]byte{kNew, kOld})
	if err != nil {
		t.Fatalf("NewAESGCM mid: %v", err)
	}
	post, err := secrets.NewAESGCM([][]byte{kNew})
	if err != nil {
		t.Fatalf("NewAESGCM post: %v", err)
	}

	ctOld, ctOldKID, err := pre.Seal(plaintext)
	if err != nil {
		t.Fatalf("pre Seal: %v", err)
	}
	ctMid, ctMidKID, err := mid.Seal(plaintext)
	if err != nil {
		t.Fatalf("mid Seal: %v", err)
	}

	// Open under every provider so any cached buffer (a recent Open's
	// plaintext, a recent Seal's nonce) has a chance to leak into the
	// LogValue projection on its next call.
	if _, err := mid.Open(ctOld, ctOldKID); err != nil {
		t.Fatalf("mid Open pre-rotation ct: %v", err)
	}
	if _, err := post.Open(ctMid, ctMidKID); err != nil {
		t.Fatalf("post Open mid-rotation ct: %v", err)
	}

	phases := []struct {
		name     string
		provider *secrets.AESGCM
		// allowedIDs lists the key ids that are LEGITIMATELY visible in
		// this provider's redacted projection (the active key id is
		// always exposed; KeyIDs() is too). Their hex bytes might
		// coincidentally collide with master-key hex bytes in the
		// substring search below, so the substring check skips inputs
		// drawn from those ids.
		allowedIDs []string
	}{
		{name: "pre-rotation", provider: pre, allowedIDs: pre.KeyIDs()},
		{name: "mid-rotation", provider: mid, allowedIDs: mid.KeyIDs()},
		{name: "post-rotation", provider: post, allowedIDs: post.KeyIDs()},
	}

	for _, ph := range phases {
		ph := ph
		t.Run(ph.name, func(t *testing.T) {
			t.Parallel()

			// LogValue projection: render the provider through a real
			// slog.Handler with the sink set to a bytes.Buffer so the
			// assertion sees exactly what an operator would see.
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logger.LogAttrs(context.Background(), slog.LevelInfo, "rotation_check",
				slog.Any("provider", ph.provider),
			)
			record := buf.String()

			// Validate the JSON parses and contains the redaction
			// sentinel in the documented field. A regression that
			// changes the LogValue shape would fail this even before
			// the leak check below.
			var parsed map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(record)), &parsed); err != nil {
				t.Fatalf("log record not valid JSON: %v\nrecord: %s", err, record)
			}
			provider, ok := parsed["provider"].(map[string]any)
			if !ok {
				t.Fatalf("log record provider field is not an object: %v", parsed["provider"])
			}
			if got := provider["master_keys"]; got != output.Sentinel {
				t.Errorf("provider.master_keys = %v; want sentinel %q", got, output.Sentinel)
			}

			// Leak check: every master key byte rendered as a hex pair
			// must NOT appear in the record EXCEPT inside a key id (the
			// id is a SHA-256 prefix so collisions with key bytes are
			// statistically inevitable for a few bytes; the structural
			// guarantee is that the FULL key never appears, never the
			// non-collision of individual bytes).
			leakProbes := [][]byte{kOld, kNew, plaintext, ctOld, ctMid}
			for i, probe := range leakProbes {
				if len(probe) == 0 {
					continue
				}
				fullHex := fmt.Sprintf("%x", probe)
				if strings.Contains(record, fullHex) {
					t.Errorf("log record leaks probe[%d] full hex (probe class = %s)", i, leakProbeName(i))
				}
				// Raw bytes: probes that happen to be valid UTF-8 (the
				// plaintext) must not appear verbatim either.
				if strings.Contains(record, string(probe)) {
					t.Errorf("log record leaks probe[%d] raw bytes (probe class = %s)", i, leakProbeName(i))
				}
			}

			// String() projection: same invariants on a different
			// channel. provider.String() is the path a panic message
			// would take through fmt.Stringer.
			stringProjection := ph.provider.String()
			for i, probe := range leakProbes {
				if len(probe) == 0 {
					continue
				}
				fullHex := fmt.Sprintf("%x", probe)
				if strings.Contains(stringProjection, fullHex) {
					t.Errorf("String() leaks probe[%d] full hex (probe class = %s)", i, leakProbeName(i))
				}
				if strings.Contains(stringProjection, string(probe)) {
					t.Errorf("String() leaks probe[%d] raw bytes (probe class = %s)", i, leakProbeName(i))
				}
			}
			// String() must contain the redaction sentinel.
			if !strings.Contains(stringProjection, output.Sentinel) {
				t.Errorf("String() projection missing redaction sentinel: %q", stringProjection)
			}
			// And it must reference at least one of the accepted key ids
			// (the test setup ensures non-empty allowedIDs); this pins
			// the rotation-observability contract on the fmt.Stringer
			// channel.
			var sawAllowed bool
			for _, id := range ph.allowedIDs {
				if id != "" && strings.Contains(stringProjection, id) {
					sawAllowed = true
					break
				}
			}
			if !sawAllowed {
				t.Errorf("String() projection does not contain any accepted key id; an operator cannot confirm the rotation from this channel: %q", stringProjection)
			}
		})
	}
}

func leakProbeName(i int) string {
	switch i {
	case 0:
		return "retired master key"
	case 1:
		return "new active master key"
	case 2:
		return "plaintext"
	case 3:
		return "pre-rotation ciphertext"
	case 4:
		return "mid-rotation ciphertext"
	default:
		return fmt.Sprintf("probe[%d]", i)
	}
}
