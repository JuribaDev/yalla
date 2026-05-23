package validate

import (
	"encoding/json"
	stderrors "errors"
	"io"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// DefaultMaxBodyBytes is the request-body size cap used when DecodeJSON is
// called with a non-positive maxBytes.
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// errBodyTooLarge is the sentinel a limitedReader returns once the byte cap is
// exceeded, so DecodeJSON can distinguish "body too large" from a genuine JSON
// syntax error.
var errBodyTooLarge = stderrors.New("validate: request body exceeds the maximum allowed size")

// limitedReader is an io.Reader that fails with errBodyTooLarge once more than
// a fixed number of bytes have been read. Unlike io.LimitReader, which simply
// reports io.EOF at the cap (indistinguishable from a truncated body), this
// reader makes the over-size condition explicit and recoverable.
type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// DecodeJSON strictly decodes a single JSON value from r into dst. It caps the
// read at maxBytes (DefaultMaxBodyBytes when maxBytes <= 0), rejects unknown
// fields, and rejects trailing data after the first value, so a malformed,
// oversized, truncated, or ambiguous body becomes a typed apierr.Invalid error
// rather than a partial or surprising decode.
//
// Every failure maps to apierr.Invalid (HTTP 400) with a fixed, generic
// message: the error never echoes the request body, so a secret pasted into a
// malformed body cannot leak through the decode error.
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	// Read one byte past the cap so an exactly-at-cap body still decodes while
	// anything larger trips errBodyTooLarge.
	dec := json.NewDecoder(&limitedReader{r: r, remaining: maxBytes + 1})
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if dec.More() {
		return apierr.Invalid("request body must contain a single JSON value")
	}
	return nil
}

// decodeError maps a json decode failure onto a typed, body-free
// apierr.Invalid error.
func decodeError(err error) error {
	switch {
	case stderrors.Is(err, errBodyTooLarge):
		return apierr.Invalid("request body exceeds the maximum allowed size")
	case stderrors.Is(err, io.EOF):
		return apierr.Invalid("request body must not be empty")
	case stderrors.Is(err, io.ErrUnexpectedEOF):
		return apierr.Invalid("request body is truncated or not valid JSON")
	}

	var syntaxErr *json.SyntaxError
	if stderrors.As(err, &syntaxErr) {
		return apierr.Invalid("request body is not valid JSON")
	}
	var typeErr *json.UnmarshalTypeError
	if stderrors.As(err, &typeErr) {
		// typeErr.Field is a field path from the schema, never a submitted
		// value, so it is safe to surface.
		if typeErr.Field != "" {
			return apierr.InvalidInput(apierr.FieldViolation{
				Field:  typeErr.Field,
				Reason: "has the wrong JSON type",
			})
		}
		return apierr.Invalid("request body has a field of the wrong JSON type")
	}
	// encoding/json reports an unknown field as a plain error whose message is
	// `json: unknown field "<name>"`. The name is a caller-chosen key, not a
	// secret value, but surface it as a generic message to stay conservative.
	if strings.HasPrefix(err.Error(), "json: unknown field") {
		return apierr.Invalid("request body contains an unknown field")
	}
	return apierr.Invalid("request body is not valid JSON")
}
