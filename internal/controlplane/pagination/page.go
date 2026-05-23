package pagination

// Page is the canonical paginated response shape every list endpoint
// embeds in its yalla.output.v1 success payload. The field names are
// part of the public wire contract: renaming one is a public API
// change.
//
//   - Items is always a non-nil slice (BuildPage guarantees this) so an
//     agent can iterate without a nil check. An empty page yields [].
//   - NextCursor is the opaque cursor for the page after this one,
//     omitted from the wire (omitempty) when there is no next page.
//     Agents detect end-of-stream by NextCursor == "" rather than by
//     comparing len(Items) to the requested limit.
//   - TotalEstimate is an optional, cheap-to-compute approximation of
//     the total row count. It is a pointer so absent (nil, omitted on
//     the wire) is distinguishable from "zero rows" on endpoints that
//     do not compute it cheaply. Endpoints that do not provide an
//     estimate must leave it nil; they must not fabricate a value.
type Page[T any] struct {
	Items         []T    `json:"items"`
	NextCursor    string `json:"next_cursor,omitempty"`
	TotalEstimate *int64 `json:"total_estimate,omitempty"`
}

// PositionFunc resolves the stable cursor position of a single row.
// BuildPage calls it on the last row of the page to encode next_cursor.
// The returned Cursor's Sort and Direction must match the request's
// resolved Params so a subsequent ParseParams call on the encoded
// cursor does not fail the sort/direction mismatch check.
type PositionFunc[T any] func(T) Cursor

// BuildPage assembles a Page[T] from a slice of rows fetched with the
// over-fetch strategy: the caller requests Params.Limit + 1 rows and
// passes the result here. If the slice contains more rows than Limit,
// BuildPage trims it to Limit and encodes next_cursor from the last
// retained row's position.
//
// The over-fetch strategy is the cursor-stability guarantee on the
// store side: the cursor encodes a strict upper bound on the next
// query (WHERE position < cursor.Position, ORDER BY position DESC), so
// a row inserted between two page fetches never causes a row to be
// duplicated on the next page or pushed off the previous page.
//
// totalEstimate is optional; pass nil when the endpoint cannot compute
// it cheaply.
//
// BuildPage never returns a nil Items slice. An empty input resolves
// to Page{Items: []T{}, NextCursor: ""}.
func BuildPage[T any](rows []T, limit int, position PositionFunc[T], totalEstimate *int64) Page[T] {
	if limit < MinLimit {
		limit = MinLimit
	}
	page := Page[T]{
		Items:         make([]T, 0, min(len(rows), limit)),
		TotalEstimate: totalEstimate,
	}
	if len(rows) == 0 {
		return page
	}

	hasMore := len(rows) > limit
	keep := len(rows)
	if hasMore {
		keep = limit
	}
	page.Items = append(page.Items, rows[:keep]...)

	if hasMore && position != nil {
		c := position(rows[keep-1])
		page.NextCursor = EncodeCursor(c)
	}

	return page
}
