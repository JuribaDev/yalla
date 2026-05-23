package pagination

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCursorIsZero(t *testing.T) {
	t.Parallel()
	if !(Cursor{}).IsZero() {
		t.Fatal("zero-value cursor must be IsZero")
	}
	if (Cursor{Position: "p"}).IsZero() {
		t.Fatal("cursor with position must not be IsZero")
	}
}

func TestEncodeDecodeCursorRoundTrip(t *testing.T) {
	t.Parallel()

	original := Cursor{
		Position:  "01HZX_anchor:abc",
		Sort:      "created_at",
		Direction: DirectionDescending,
	}
	encoded := EncodeCursor(original)
	if encoded == "" {
		t.Fatal("EncodeCursor returned empty for non-zero cursor")
	}

	decoded, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor unexpected error: %v", err)
	}
	if decoded != original {
		t.Fatalf("round trip mismatch: encoded %+v -> decoded %+v", original, decoded)
	}
}

func TestEncodeCursorEmptyForZero(t *testing.T) {
	t.Parallel()
	if got := EncodeCursor(Cursor{}); got != "" {
		t.Fatalf("expected empty encoding for zero cursor, got %q", got)
	}
}

func TestDecodeCursorEmptyIsZeroNoError(t *testing.T) {
	t.Parallel()
	c, err := DecodeCursor("")
	if err != nil {
		t.Fatalf("expected nil error for empty cursor, got %v", err)
	}
	if !c.IsZero() {
		t.Fatalf("expected zero cursor for empty input, got %+v", c)
	}
}

func TestEncodeCursorIsDeterministic(t *testing.T) {
	t.Parallel()
	// Recorded HTTP exchanges must diff byte-for-byte when the cursor
	// input is the same — protects test fixtures and snapshot
	// assertions against map-iteration randomness.
	c := Cursor{Position: "p", Sort: "s", Direction: DirectionDescending}
	first := EncodeCursor(c)
	for i := 0; i < 16; i++ {
		if again := EncodeCursor(c); again != first {
			t.Fatalf("EncodeCursor not deterministic: %q vs %q", first, again)
		}
	}
}

func TestEncodeCursorIsURLSafe(t *testing.T) {
	t.Parallel()
	// next_cursor is round-tripped through query strings; the encoded
	// form must use the URL-safe base64 alphabet so it does not need
	// percent-encoding.
	encoded := EncodeCursor(Cursor{Position: strings.Repeat("\xff", 32), Sort: "s", Direction: DirectionDescending})
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("encoded cursor must be URL-safe (no '+', '/', or padding), got %q", encoded)
	}
}

func TestEncodeCursorIsOpaque(t *testing.T) {
	t.Parallel()
	// An agent should not be able to read the plaintext position out
	// of the encoded value with a naive substring check — base64url
	// satisfies "opaque" for the purposes of the wire contract.
	c := Cursor{Position: "PLAINTEXT_POSITION_MARKER", Sort: "s", Direction: DirectionDescending}
	encoded := EncodeCursor(c)
	if strings.Contains(encoded, c.Position) {
		t.Fatalf("encoded cursor must not include plaintext position substring: %q", encoded)
	}
}

func TestDecodeCursorRejectsMalformedBase64(t *testing.T) {
	t.Parallel()
	_, err := DecodeCursor("***not-base64***")
	if err == nil {
		t.Fatal("expected error for non-base64 cursor")
	}
}

func TestDecodeCursorRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	// Base64-encoded "not json" is not a valid cursor payload.
	bad := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := DecodeCursor(bad)
	if err == nil {
		t.Fatal("expected error for non-JSON cursor payload")
	}
}

func TestDecodeCursorRejectsUnknownSchemaVersion(t *testing.T) {
	t.Parallel()
	payload := cursorPayload{V: "yalla.cursor.v999", P: "p", S: "s", D: string(DirectionDescending)}
	buf, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	_, err := DecodeCursor(encoded)
	if err == nil {
		t.Fatal("expected error for unknown schema version")
	}
}

func TestDecodeCursorRejectsEmptyPosition(t *testing.T) {
	t.Parallel()
	payload := cursorPayload{V: cursorSchemaVersion, P: ""}
	buf, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	_, err := DecodeCursor(encoded)
	if err == nil {
		t.Fatal("expected error for empty position")
	}
}

func TestDecodeCursorRejectsBadDirection(t *testing.T) {
	t.Parallel()
	payload := cursorPayload{V: cursorSchemaVersion, P: "p", D: "sideways"}
	buf, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	_, err := DecodeCursor(encoded)
	if err == nil {
		t.Fatal("expected error for malformed direction")
	}
}

func TestDecodeCursorAcceptsBothPaddingForms(t *testing.T) {
	t.Parallel()
	c := Cursor{Position: "p1", Sort: "created_at", Direction: DirectionDescending}
	raw := EncodeCursor(c) // no padding (RawURLEncoding)

	if _, err := DecodeCursor(raw); err != nil {
		t.Fatalf("expected to decode unpadded cursor, got %v", err)
	}

	// Build a padded equivalent and ensure it also decodes — some
	// pipelines (log shippers, URL shorteners) add padding.
	payload, _ := json.Marshal(cursorPayload{V: cursorSchemaVersion, P: c.Position, S: c.Sort, D: string(c.Direction)})
	padded := base64.URLEncoding.EncodeToString(payload)
	if !strings.HasSuffix(padded, "=") {
		t.Skip("padded form coincidentally aligned to no '=' — test does not apply for this payload size")
	}
	if _, err := DecodeCursor(padded); err != nil {
		t.Fatalf("expected to decode padded cursor, got %v", err)
	}
}

func TestDecodeCursorTenantIsolationCannotBeBypassed(t *testing.T) {
	t.Parallel()
	// Tenant-isolation guarantee: the cursor payload only carries a
	// Position string. An attacker who hand-crafts a valid cursor for
	// another tenant's row id still hits the store layer's
	// tenant-scoped WHERE clause (organization_id = principal_home),
	// so the row is invisible. This test guards the contract by
	// asserting the cursor schema NEVER includes an organization or
	// tenant field — adding one would silently turn a forged cursor
	// into a tenant-spoof.
	buf, err := json.Marshal(cursorPayload{V: cursorSchemaVersion, P: "p", S: "s", D: string(DirectionDescending)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"organization_id", "org_id", "tenant", "tenant_id", "principal", "principal_id"} {
		if _, has := raw[forbidden]; has {
			t.Fatalf("cursor payload must not carry tenant field %q (would enable a forged-cursor tenant spoof)", forbidden)
		}
	}
}
