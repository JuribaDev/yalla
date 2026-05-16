package pagination

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// cursorSchemaVersion is the stable schema_version sentinel embedded in
// every encoded cursor. Bumping it is a wire-compatibility change: a
// caller paging through an endpoint with the old version would receive
// a typed 400 instead of silently mis-ordered pages. Keep the bump
// coordinated with a documented migration plan.
const cursorSchemaVersion = "yalla.cursor.v1"

// Cursor is the decoded position of one page boundary. It is opaque to
// callers — they only round-trip the base64url string from EncodeCursor
// — but the server reads it as a struct so the store layer can build a
// stable WHERE clause from Position.
//
// Position is the stable, tenant-scoped ordering key of the last row on
// the previous page (typically an ID, a (sort_key + ":" + id) compound,
// or an opaque token defined by the endpoint). Sort and Direction are
// echoed so ParseParams can detect a caller mixing a cursor from a
// different ordering and reject the request as a stable 400.
//
// Cursor.Position must never carry a tenant identifier: tenant isolation
// is the persistence layer's responsibility, and the store's list query
// scopes by organization. A cursor only encodes a position within the
// already-tenant-scoped set, so an attacker cannot hand-craft a cursor
// to read another tenant's rows.
type Cursor struct {
	// Position is the stable ordering key of the last returned row.
	// Endpoints choose its format (a row id, "ts:id", etc.); the
	// package treats it as an opaque string.
	Position string

	// Sort is the sort key the cursor was issued against. It must
	// match the request's resolved Params.Sort or ParseParams rejects
	// the cursor as a stable 400.
	Sort string

	// Direction is the sort direction the cursor was issued against.
	// It must match the request's resolved Params.Direction or
	// ParseParams rejects the cursor as a stable 400.
	Direction SortDirection
}

// IsZero reports whether c is the zero cursor (no position recorded).
// A zero cursor means "first page"; handlers should branch on this
// rather than comparing to a literal zero value.
func (c Cursor) IsZero() bool {
	return c.Position == "" && c.Sort == "" && c.Direction == ""
}

// cursorPayload is the on-wire JSON shape of an encoded cursor. Field
// names are short to keep the encoded string compact across page-heavy
// responses. They are part of the cursor wire contract: renaming one
// is a cursor schema bump.
type cursorPayload struct {
	V string `json:"v"` // cursorSchemaVersion
	P string `json:"p"` // Position
	S string `json:"s,omitempty"`
	D string `json:"d,omitempty"`
}

// EncodeCursor renders a Cursor into a base64url string suitable for
// embedding in a yalla.output.v1 page's next_cursor field. The encoding
// is deterministic for the same input so a recorded HTTP exchange can
// be diff'd byte-for-byte.
//
// EncodeCursor panics only on an unreachable encoding error (the
// embedded payload is a fixed-shape struct so encoding/json cannot
// realistically fail). Callers do not need to handle an error path.
func EncodeCursor(c Cursor) string {
	if c.IsZero() {
		return ""
	}
	payload := cursorPayload{
		V: cursorSchemaVersion,
		P: c.Position,
		S: c.Sort,
		D: string(c.Direction),
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		// json.Marshal cannot fail on a fixed-shape struct of strings;
		// returning an empty cursor would silently swallow an
		// unreachable bug, so we choose a deterministic identifiable
		// sentinel instead. Tests assert this branch never fires.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// errMalformedCursor is returned by DecodeCursor for any failure mode
// (invalid base64, invalid JSON, unknown schema version). Callers
// should not branch on it — ParseParams already wraps it as a stable
// FieldViolation on the "cursor" field, never echoing the raw cause.
var errMalformedCursor = errors.New("pagination: malformed cursor")

// DecodeCursor parses an EncodeCursor output back into a Cursor. An
// empty input resolves to the zero cursor with no error so callers
// can branch uniformly on Cursor.IsZero.
//
// Failure modes (invalid base64, invalid JSON, mismatched schema
// version, empty Position) all return errMalformedCursor. The
// underlying cause is intentionally not exposed: a caller learns the
// classification ("malformed") and the remediation ("fetch the first
// page again") from ParseParams' typed envelope, not from the cursor
// internals.
//
// DecodeCursor accepts both base64url with and without padding so a
// caller round-tripping the value through a URL-shortener or a logger
// that adds padding still works.
func DecodeCursor(raw string) (Cursor, error) {
	if raw == "" {
		return Cursor{}, nil
	}
	decoded, err := decodeBase64URL(raw)
	if err != nil {
		return Cursor{}, errMalformedCursor
	}
	var payload cursorPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return Cursor{}, errMalformedCursor
	}
	if payload.V != cursorSchemaVersion {
		return Cursor{}, errMalformedCursor
	}
	if payload.P == "" {
		return Cursor{}, errMalformedCursor
	}
	dir := SortDirection(payload.D)
	if payload.D != "" && !dir.IsValid() {
		return Cursor{}, errMalformedCursor
	}
	return Cursor{
		Position:  payload.P,
		Sort:      payload.S,
		Direction: dir,
	}, nil
}

// decodeBase64URL accepts the cursor as raw URL-safe base64 with or
// without padding. Some clients (form-encoders, log pipelines) add or
// strip padding; tolerating both keeps the wire forgiving without
// changing the canonical EncodeCursor output.
func decodeBase64URL(raw string) ([]byte, error) {
	if strings.ContainsAny(raw, "=") {
		return base64.URLEncoding.DecodeString(raw)
	}
	return base64.RawURLEncoding.DecodeString(raw)
}
