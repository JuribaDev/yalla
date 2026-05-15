// Package domain defines the stable identity, slug, and naming primitives
// shared by every Yalla control-plane resource.
//
// These primitives are a public compatibility contract. Resource ID prefixes
// (org_, usr_, sa_, key_, proj_, env_, svc_, dep_, job_, ovar_), the ID
// encoding, the slug normalisation rules, and the Dokploy-name layout are all
// treated as stable: changing them is a breaking change for stored data,
// audit records, and any agent or CLI that parses them.
//
// IDs are non-guessable: a typed kind prefix joined to 128 bits of
// cryptographically random entropy, encoded with a lowercase Crockford base32
// alphabet. The prefix makes an ID self-describing in logs and audit trails
// without ever revealing tenant data; the entropy makes IDs unenumerable.
//
// Slugs are human-authored labels normalised to a canonical, DNS-label-shaped
// form that is safe to embed in Dokploy / Docker names. Uniqueness of a slug
// within its parent scope is a database constraint owned by the persistence
// layer — this package only guarantees a slug is well formed.
//
// Validation failures are returned as the package's sentinel errors
// (ErrInvalidID, ErrUnknownKind, ErrInvalidSlug, ErrInvalidDokployName) so the
// HTTP layer can map them to apierr.InvalidInput. This package deliberately
// does not import the HTTP error taxonomy: domain primitives have no HTTP
// concerns. IDs and slugs are not secrets, so nothing here is redacted; error
// messages still avoid echoing untrusted input verbatim.
package domain

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// Kind identifies a Yalla resource type. Every Kind has a stable, non-guessable
// ID prefix; the set of kinds is a public compatibility contract.
type Kind string

// The canonical resource kinds. The string value of each Kind is also its ID
// prefix (the text before the underscore separator).
const (
	KindOrganization Kind = "org"
	KindUser         Kind = "usr"
	// KindServiceAccount is a non-human principal: a CI/automation identity
	// scoped to a single organization.
	KindServiceAccount Kind = "sa"
	KindAPIKey         Kind = "key"
	KindProject        Kind = "proj"
	KindEnvironment    Kind = "env"
	KindService        Kind = "svc"
	KindDeployment     Kind = "dep"
	KindJob            Kind = "job"
	// KindOrganizationVariable is one row in the organization-scoped variables
	// surface — the lowest-precedence layer of the
	// Organization -> Project -> Environment -> Service variable hierarchy the
	// Dokploy renderer composes. A variable is not a tenant root; the audit
	// layer still files variable mutations under the parent organization's
	// audit scope (resource_kind=org), but a variable row carries its own
	// stable, non-guessable id so a per-row PATCH / DELETE story has an
	// addressable resource later.
	KindOrganizationVariable Kind = "ovar"
	// KindProjectGrant is one row in the project-scoped grants surface — a
	// scoped grant that confers a built-in role on a principal at a specific
	// (project, optional environment, optional service) target. Project
	// grants narrow or widen a principal's authority below the organization
	// level: a developer with a project-scoped Viewer grant for one project
	// can read it, and a viewer with a project-scoped Admin grant for one
	// project can mutate it without becoming an admin of the whole
	// organization. Like KindOrganizationVariable, a grant is not a tenant
	// root — its audit events are filed under the parent project's
	// organization — but it carries its own stable, non-guessable id so
	// PUT / DELETE stories have an addressable resource.
	KindProjectGrant Kind = "pgrnt"
	// KindEnvironmentGrant is one row in the environment-scoped grants surface —
	// a scoped grant that confers a built-in role on a principal at a specific
	// (environment, optional service) target. Environment grants narrow or
	// widen a principal's authority below the project level: a developer with
	// an environment-scoped Viewer grant for one environment can read it, and
	// a viewer with an environment-scoped Admin grant for one environment can
	// mutate it without becoming an admin of the whole project. Like
	// KindProjectGrant, a grant is not a tenant root — its audit events are
	// filed under the parent environment's organization — but it carries its
	// own stable, non-guessable id so PUT / DELETE stories have an addressable
	// resource.
	KindEnvironmentGrant Kind = "egrnt"
	// KindProjectVariable is one row in the project-scoped variables surface —
	// the second-from-lowest precedence layer of the
	// Organization -> Project -> Environment -> Service variable hierarchy the
	// Dokploy renderer composes. A project-scoped variable shadows any
	// organization-scoped variable of the same key for services inside the
	// project. Like KindOrganizationVariable, a variable is not a tenant root;
	// the audit layer files variable mutations under the parent organization's
	// audit scope (resource_kind=org), but a variable row carries its own
	// stable, non-guessable id so a per-row PATCH / DELETE story has an
	// addressable resource later.
	KindProjectVariable Kind = "pvar"
	// KindEnvironmentVariable is one row in the environment-scoped variables
	// surface — the third-from-lowest precedence layer of the
	// Organization -> Project -> Environment -> Service variable hierarchy the
	// Dokploy renderer composes. An environment-scoped variable shadows any
	// project-scoped variable of the same key for services inside the
	// environment, which in turn shadows the organization-scoped variable of
	// the same key. Like KindProjectVariable, a variable is not a tenant root;
	// the audit layer files variable mutations under the parent environment's
	// audit scope (resource_kind=env), but a variable row carries its own
	// stable, non-guessable id so a per-row PATCH / DELETE story has an
	// addressable resource later.
	KindEnvironmentVariable Kind = "evar"
)

// kinds is the authoritative set of valid resource kinds. It backs Kind.Valid
// and the ID parser; adding a Kind constant requires adding it here too.
var kinds = map[Kind]struct{}{
	KindOrganization:         {},
	KindUser:                 {},
	KindServiceAccount:       {},
	KindAPIKey:               {},
	KindProject:              {},
	KindEnvironment:          {},
	KindService:              {},
	KindDeployment:           {},
	KindJob:                  {},
	KindOrganizationVariable: {},
	KindProjectGrant:         {},
	KindEnvironmentGrant:     {},
	KindProjectVariable:      {},
	KindEnvironmentVariable:  {},
}

// Valid reports whether k is one of the canonical resource kinds.
func (k Kind) Valid() bool {
	_, ok := kinds[k]
	return ok
}

// String returns the kind's stable string value (also its ID prefix).
func (k Kind) String() string { return string(k) }

const (
	// idSeparator joins an ID's kind prefix to its random suffix.
	idSeparator = "_"
	// idEntropyBytes is the amount of cryptographically random entropy in
	// every ID: 128 bits, which is unenumerable in practice.
	idEntropyBytes = 16
	// idSuffixLen is the length of the encoded random suffix. base32 encodes
	// 5 bytes to 8 characters, so 16 bytes encode (with no padding) to 26.
	idSuffixLen = 26
	// crockfordLowerAlphabet is the Crockford base32 alphabet in lowercase:
	// digits and letters with the visually ambiguous i, l, o, u removed.
	crockfordLowerAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

// idEncoding encodes ID entropy with the lowercase Crockford alphabet and no
// padding, so an ID suffix is a fixed-length, URL-safe, case-stable token.
var idEncoding = base32.NewEncoding(crockfordLowerAlphabet).WithPadding(base32.NoPadding)

// ID is a stable, non-guessable identifier for a Yalla resource. Its canonical
// form is "<kind><separator><suffix>", e.g. "svc_3p9k...". The zero value is
// the empty string and is never valid.
type ID string

// NewID generates a fresh, non-guessable ID for the given resource kind. It
// returns ErrUnknownKind if k is not a canonical kind, and surfaces any
// crypto/rand failure unchanged.
func NewID(k Kind) (ID, error) {
	if !k.Valid() {
		return "", fmt.Errorf("%w: %q", ErrUnknownKind, k)
	}
	var buf [idEntropyBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("domain: generating id entropy: %w", err)
	}
	return ID(string(k) + idSeparator + idEncoding.EncodeToString(buf[:])), nil
}

// MustNewID is NewID for package-level initialisation and tests. It panics on
// any error, so it must only be used where an error is genuinely impossible
// (a hard-coded valid kind) or where a panic is acceptable.
func MustNewID(k Kind) ID {
	id, err := NewID(k)
	if err != nil {
		panic(err)
	}
	return id
}

// ParseID validates s as a canonical resource ID and returns it as an ID. It
// returns ErrInvalidID for any structural problem: a missing separator, an
// unknown kind prefix, a wrong-length suffix, or a suffix character outside
// the Crockford alphabet. The bad input is not echoed verbatim.
func ParseID(s string) (ID, error) {
	prefix, suffix, ok := strings.Cut(s, idSeparator)
	if !ok {
		return "", fmt.Errorf("%w: missing %q separator", ErrInvalidID, idSeparator)
	}
	if !Kind(prefix).Valid() {
		return "", fmt.Errorf("%w: unknown kind prefix %q", ErrInvalidID, prefix)
	}
	if len(suffix) != idSuffixLen {
		return "", fmt.Errorf("%w: suffix must be %d characters, got %d", ErrInvalidID, idSuffixLen, len(suffix))
	}
	for i := 0; i < len(suffix); i++ {
		if !isCrockfordLower(suffix[i]) {
			return "", fmt.Errorf("%w: suffix contains an invalid character at position %d", ErrInvalidID, i)
		}
	}
	return ID(s), nil
}

// MustParseID is ParseID for tests and package-level constants. It panics if s
// is not a valid ID.
func MustParseID(s string) ID {
	id, err := ParseID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// Valid reports whether the ID is in canonical form.
func (id ID) Valid() bool {
	_, err := ParseID(string(id))
	return err == nil
}

// Kind returns the resource kind encoded in the ID, or the empty Kind if the
// ID is not valid.
func (id ID) Kind() Kind {
	prefix, _, ok := strings.Cut(string(id), idSeparator)
	if !ok || !Kind(prefix).Valid() {
		return ""
	}
	return Kind(prefix)
}

// IsKind reports whether the ID is valid and of the given kind. It is the
// safe way to assert "this ID belongs to a service" before trusting it.
func (id ID) IsKind(k Kind) bool {
	return id.Valid() && id.Kind() == k
}

// suffix returns the random portion of the ID (the text after the separator).
// It assumes the ID is valid; callers parse first.
func (id ID) suffix() string {
	_, s, _ := strings.Cut(string(id), idSeparator)
	return s
}

// String returns the ID's canonical string form.
func (id ID) String() string { return string(id) }

// isCrockfordLower reports whether b is a byte in the lowercase Crockford
// base32 alphabet used by ID suffixes.
func isCrockfordLower(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'a' && b <= 'z':
		// i, l, o, and u are excluded from the Crockford alphabet.
		return b != 'i' && b != 'l' && b != 'o' && b != 'u'
	default:
		return false
	}
}
