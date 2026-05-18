// Package pagination is the canonical list-response contract for every
// Yalla Control Plane list endpoint. It owns the parsing of limit, cursor,
// sort, and filter query parameters, the opaque cursor encoding, and the
// stable Page envelope shape (items + next_cursor + total_estimate) that
// every list endpoint embeds in its yalla.output.v1 success payload.
//
// The contract is deliberately small and explicit so AI agents can rely on
// it across endpoints:
//
//   - Limit is parsed once with stable defaults and a hard server-side
//     ceiling; out-of-range or malformed limits return a typed
//     apierr.InvalidInput (HTTP 400 E_VALIDATION) before any database
//     work runs. The submitted string is never echoed back, only the
//     classification and accepted range, so a typo cannot become a
//     reflection-style content channel.
//   - Cursors are opaque to clients — a base64url-encoded JSON blob with a
//     stable internal schema and a schema_version sentinel — so the server
//     can evolve the cursor without breaking callers and a caller cannot
//     hand-craft a cursor that escapes tenant scoping. Tenant isolation is
//     enforced by the store layer: the cursor only carries a position
//     within the already-tenant-scoped result set, never the tenant id.
//   - Sort and filter accept-lists are caller-defined: an endpoint passes
//     the explicit set of sort keys and filter keys it supports, and any
//     other key is rejected as a stable 400. Endpoints that have no need
//     for sort or filter simply leave the accept-list empty.
//   - Pages are stable under concurrent inserts: an endpoint that orders
//     by (sort_key, id DESC) and over-fetches limit+1 rows passes the
//     last returned row's position into a Cursor; the next page query
//     uses the cursor as a strict upper bound, so a row inserted between
//     two page fetches never appears in both pages and never silently
//     pushes a row off the next page boundary.
//
// The package is intentionally framework-free: it has no dependency on
// net/http, the store layer, or any specific resource type. Handlers and
// repositories compose it through small typed adapters.
package pagination

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// DefaultLimit is the page size a list endpoint serves when the caller
// omits ?limit=. It is deliberately lower than MaxLimit so a typical
// agent fetch stays small while the explicit ?limit= escape hatch
// remains available for an operator paging the full window.
const DefaultLimit = 50

// MaxLimit is the hard server-side ceiling on ?limit=. A larger value is
// rejected as a stable 400 E_VALIDATION before any database work
// runs. Endpoints may pick a lower ceiling via ParseOptions.MaxLimit but
// never a higher one — the package clamps MaxLimit to this value.
const MaxLimit = 200

// MinLimit is the smallest accepted ?limit= value. Zero or negative
// limits are rejected as a stable 400 before any database work runs.
const MinLimit = 1

// SortDirection identifies the ordering direction a cursor was issued
// against. It is part of the cursor payload so the server can detect a
// caller mixing a cursor from a different sort direction and reject it
// as a stable 400 instead of silently serving overlapping pages.
type SortDirection string

const (
	// DirectionDescending is newest-first / largest-first, the default
	// for time-based list endpoints (audit events, deployments, etc).
	DirectionDescending SortDirection = "desc"

	// DirectionAscending is oldest-first / smallest-first.
	DirectionAscending SortDirection = "asc"
)

// IsValid reports whether d is a recognised sort direction.
func (d SortDirection) IsValid() bool {
	switch d {
	case DirectionAscending, DirectionDescending:
		return true
	default:
		return false
	}
}

// ParseOptions tunes ParseParams for an endpoint. An endpoint constructs
// one ParseOptions value at handler construction time (cheap, no
// allocations on the request path) and reuses it for every request.
//
// All fields are optional. Zero values resolve to safe defaults:
//
//   - DefaultLimit zero  -> DefaultLimit (50)
//   - MaxLimit zero      -> MaxLimit (200); a non-zero value is clamped
//     into [MinLimit, MaxLimit]
//   - DefaultSort empty  -> no default sort (Params.Sort stays empty)
//   - DefaultDirection   -> DirectionDescending unless overridden
//   - SortAllowList nil  -> any ?sort= value is rejected as
//     E_VALIDATION
//   - FilterAllowList nil -> any ?filter.* query is rejected as
//     E_VALIDATION
type ParseOptions struct {
	DefaultLimit     int
	MaxLimit         int
	DefaultSort      string
	DefaultDirection SortDirection
	SortAllowList    []string
	FilterAllowList  []string
}

// effectiveDefaultLimit returns the DefaultLimit clamped into the
// accepted range. A zero or negative value resolves to the package
// default, and a value above the effective max resolves to that max.
func (o ParseOptions) effectiveDefaultLimit() int {
	def := o.DefaultLimit
	if def <= 0 {
		def = DefaultLimit
	}
	max := o.effectiveMaxLimit()
	if def > max {
		def = max
	}
	if def < MinLimit {
		def = MinLimit
	}
	return def
}

// effectiveMaxLimit returns the configured MaxLimit clamped into
// [MinLimit, MaxLimit]. A zero or negative value resolves to MaxLimit.
func (o ParseOptions) effectiveMaxLimit() int {
	max := o.MaxLimit
	if max <= 0 {
		max = MaxLimit
	}
	if max > MaxLimit {
		max = MaxLimit
	}
	if max < MinLimit {
		max = MinLimit
	}
	return max
}

// effectiveDefaultDirection returns the configured default direction or
// DirectionDescending when unset.
func (o ParseOptions) effectiveDefaultDirection() SortDirection {
	if o.DefaultDirection.IsValid() {
		return o.DefaultDirection
	}
	return DirectionDescending
}

// Params is the parsed pagination input for one request. It is produced
// by ParseParams and consumed by store-layer queries. The struct fields
// are stable identifiers — adding a field is forward-compatible, but
// renaming or removing one is a public API change.
type Params struct {
	// Limit is the resolved page size in [1, effective max]. It is the
	// value the store should pass to its LIMIT clause; an over-fetch
	// strategy adds the +1 separately.
	Limit int

	// Cursor is the decoded opaque cursor, or the zero value when the
	// caller did not supply ?cursor=. A zero cursor means "first page";
	// callers should branch on Cursor.IsZero rather than comparing to a
	// literal.
	Cursor Cursor

	// Sort is the resolved sort key. Empty when the endpoint does not
	// declare any sort keys. Always one of ParseOptions.SortAllowList or
	// ParseOptions.DefaultSort.
	Sort string

	// Direction is the resolved sort direction (asc or desc).
	Direction SortDirection

	// Filter is the decoded filter map. Keys are the bare filter names
	// (the "filter." prefix is stripped) and values are the trimmed
	// caller-supplied strings. Only keys in
	// ParseOptions.FilterAllowList may appear; any other key was
	// rejected during parsing.
	Filter map[string]string
}

// ParseParams parses pagination query parameters from q into a Params
// value, returning a typed apierr error for any validation failure.
//
// Recognised query keys:
//
//   - limit     : optional positive integer; defaults to opts.DefaultLimit
//   - cursor    : optional opaque cursor produced by EncodeCursor
//   - sort      : optional sort key; must appear in opts.SortAllowList
//   - direction : optional "asc" or "desc"; defaults to opts.DefaultDirection
//   - filter.<k>: zero or more filter keys; each <k> must appear in
//     opts.FilterAllowList
//
// Every validation failure returns apierr.InvalidInput with a
// FieldViolation naming the offending field. The submitted value is
// never echoed back — only the classification and accepted range — so a
// caller cannot reflect arbitrary content into the error message.
//
// Cursor decoding errors are wrapped as a FieldViolation on the
// "cursor" field, not surfaced as the underlying DecodeCursor error, so
// the wire contract stays stable even if cursor internals evolve. A
// cursor whose Sort or Direction disagrees with the request is rejected
// as a stable mismatch so the caller learns "you switched sort, fetch
// the first page again" instead of silently getting overlapping pages.
func ParseParams(q url.Values, opts ParseOptions) (Params, error) {
	out := Params{
		Limit:     opts.effectiveDefaultLimit(),
		Direction: opts.effectiveDefaultDirection(),
		Sort:      opts.DefaultSort,
	}

	violations := make([]apierr.FieldViolation, 0, 4)

	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		max := opts.effectiveMaxLimit()
		switch {
		case err != nil:
			violations = append(violations, apierr.FieldViolation{
				Field:  "limit",
				Reason: "must be a positive integer",
			})
		case n < MinLimit || n > max:
			violations = append(violations, apierr.FieldViolation{
				Field:  "limit",
				Reason: "must be between " + strconv.Itoa(MinLimit) + " and " + strconv.Itoa(max),
			})
		default:
			out.Limit = n
		}
	}

	if raw := q.Get("sort"); raw != "" {
		if !containsString(opts.SortAllowList, raw) {
			violations = append(violations, apierr.FieldViolation{
				Field:  "sort",
				Reason: "must be one of " + joinAllowList(opts.SortAllowList),
			})
		} else {
			out.Sort = raw
		}
	}

	if raw := q.Get("direction"); raw != "" {
		d := SortDirection(strings.ToLower(strings.TrimSpace(raw)))
		if !d.IsValid() {
			violations = append(violations, apierr.FieldViolation{
				Field:  "direction",
				Reason: `must be "asc" or "desc"`,
			})
		} else {
			out.Direction = d
		}
	}

	filter, filterViolations := parseFilter(q, opts.FilterAllowList)
	violations = append(violations, filterViolations...)
	out.Filter = filter

	if raw := q.Get("cursor"); raw != "" {
		c, err := DecodeCursor(raw)
		if err != nil {
			violations = append(violations, apierr.FieldViolation{
				Field:  "cursor",
				Reason: "is malformed or expired; fetch the first page again",
			})
		} else {
			out.Cursor = c
		}
	}

	if !out.Cursor.IsZero() && len(violations) == 0 {
		if out.Cursor.Sort != out.Sort {
			violations = append(violations, apierr.FieldViolation{
				Field:  "cursor",
				Reason: "was issued for a different sort key; fetch the first page again",
			})
		} else if out.Cursor.Direction != out.Direction {
			violations = append(violations, apierr.FieldViolation{
				Field:  "cursor",
				Reason: "was issued for a different direction; fetch the first page again",
			})
		}
	}

	if len(violations) > 0 {
		return Params{}, apierr.InvalidInput(violations...)
	}

	return out, nil
}

// parseFilter extracts every "filter.<k>" query key from q. Unknown
// filter keys (not in allow) produce one FieldViolation each; empty
// values are rejected so a deliberately blank filter does not silently
// become a no-op match.
func parseFilter(q url.Values, allow []string) (map[string]string, []apierr.FieldViolation) {
	out := make(map[string]string)
	var violations []apierr.FieldViolation

	keys := make([]string, 0, len(q))
	for k := range q {
		if strings.HasPrefix(k, "filter.") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		name := strings.TrimPrefix(k, "filter.")
		if name == "" {
			violations = append(violations, apierr.FieldViolation{
				Field:  k,
				Reason: "is not a recognised filter key",
			})
			continue
		}
		if !containsString(allow, name) {
			violations = append(violations, apierr.FieldViolation{
				Field:  k,
				Reason: "is not a recognised filter key",
			})
			continue
		}
		v := strings.TrimSpace(q.Get(k))
		if v == "" {
			violations = append(violations, apierr.FieldViolation{
				Field:  k,
				Reason: "must not be empty",
			})
			continue
		}
		out[name] = v
	}
	return out, violations
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func joinAllowList(values []string) string {
	if len(values) == 0 {
		return "the empty set"
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}
	return strings.Join(quoted, ", ")
}
