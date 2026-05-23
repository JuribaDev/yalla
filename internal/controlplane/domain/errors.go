package domain

import "errors"

// Sentinel errors returned by the domain primitives. They carry no HTTP
// semantics on purpose: the HTTP layer maps them to apierr.InvalidInput (with
// a FieldViolation naming the offending field) so the domain package stays
// free of transport concerns. Callers compare with errors.Is.
var (
	// ErrUnknownKind is returned when a Kind is not one of the canonical
	// resource kinds.
	ErrUnknownKind = errors.New("domain: unknown resource kind")

	// ErrInvalidID is returned when a string is not a canonical resource ID:
	// wrong shape, unknown kind prefix, or malformed suffix.
	ErrInvalidID = errors.New("domain: invalid resource id")

	// ErrInvalidSlug is returned when a slug is not in canonical form, is
	// empty, exceeds the length limit, or when an input normalises to nothing.
	ErrInvalidSlug = errors.New("domain: invalid slug")

	// ErrInvalidDokployName is returned when a constructed Dokploy name is not
	// safe for use as a Dokploy / Docker resource name.
	ErrInvalidDokployName = errors.New("domain: invalid dokploy name")
)
