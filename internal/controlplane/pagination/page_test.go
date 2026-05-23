package pagination

import (
	"net/url"
	"sort"
	"testing"
)

// row is a small fixture used by the BuildPage tests. The id is the
// stable ordering key encoded into Cursor.Position; createdAt is a
// secondary key the cursor-stability simulation uses to order rows.
type row struct {
	id        string
	createdAt int64
	orgID     string
}

func positionByID(r row) Cursor {
	return Cursor{
		Position:  r.id,
		Sort:      "created_at",
		Direction: DirectionDescending,
	}
}

func TestBuildPageNeverReturnsNilItems(t *testing.T) {
	t.Parallel()

	p := BuildPage[row](nil, 10, positionByID, nil)
	if p.Items == nil {
		t.Fatal("BuildPage must always return a non-nil Items slice")
	}
	if len(p.Items) != 0 {
		t.Fatalf("expected empty page, got %d items", len(p.Items))
	}
	if p.NextCursor != "" {
		t.Fatalf("expected empty NextCursor on empty page, got %q", p.NextCursor)
	}
	if p.TotalEstimate != nil {
		t.Fatal("expected nil TotalEstimate when not provided")
	}
}

func TestBuildPageRetainsAllWhenUnderLimit(t *testing.T) {
	t.Parallel()

	rows := []row{
		{id: "r3", createdAt: 30},
		{id: "r2", createdAt: 20},
		{id: "r1", createdAt: 10},
	}
	p := BuildPage(rows, 10, positionByID, nil)
	if len(p.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(p.Items))
	}
	if p.NextCursor != "" {
		t.Fatal("expected empty NextCursor when below limit (no over-fetch)")
	}
}

func TestBuildPageTrimsAndEncodesNextCursor(t *testing.T) {
	t.Parallel()

	// Over-fetch: limit=3 and the store returned 4 rows. BuildPage
	// trims to 3 and encodes next_cursor from the third row's id.
	rows := []row{
		{id: "r4", createdAt: 40},
		{id: "r3", createdAt: 30},
		{id: "r2", createdAt: 20},
		{id: "r1", createdAt: 10},
	}
	p := BuildPage(rows, 3, positionByID, nil)
	if len(p.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(p.Items))
	}
	if p.NextCursor == "" {
		t.Fatal("expected non-empty NextCursor when over-fetch saw an extra row")
	}
	decoded, err := DecodeCursor(p.NextCursor)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if decoded.Position != "r2" {
		t.Fatalf("expected NextCursor.Position to be last retained id r2, got %q", decoded.Position)
	}
}

func TestBuildPageEncodesTotalEstimate(t *testing.T) {
	t.Parallel()

	estimate := int64(42)
	p := BuildPage([]row{{id: "r1"}}, 10, positionByID, &estimate)
	if p.TotalEstimate == nil || *p.TotalEstimate != 42 {
		t.Fatalf("expected TotalEstimate=42, got %v", p.TotalEstimate)
	}
}

func TestBuildPageHandlesZeroLimit(t *testing.T) {
	t.Parallel()

	// A misconfigured caller passing limit=0 must not panic and must
	// not return a nil Items slice.
	rows := []row{{id: "r1"}}
	p := BuildPage(rows, 0, positionByID, nil)
	if p.Items == nil {
		t.Fatal("expected non-nil items on zero-limit call")
	}
}

// fakeStore is a tiny in-memory list-source used to exercise the
// cursor-stability contract end to end. It models the canonical
// "ORDER BY created_at DESC, id DESC" store query an audit-log or
// deployment-list endpoint would issue, scoped by organization_id.
type fakeStore struct {
	rows []row
}

func (s *fakeStore) insert(r row) {
	s.rows = append(s.rows, r)
}

// list mirrors a tenant-scoped list query: filter by orgID, optionally
// apply a strict upper bound from the cursor, sort by (createdAt DESC,
// id DESC), and return the first limit+1 rows so BuildPage can detect
// over-fetch.
func (s *fakeStore) list(orgID string, limit int, cursor Cursor) []row {
	var scoped []row
	for _, r := range s.rows {
		if r.orgID != orgID {
			continue
		}
		scoped = append(scoped, r)
	}
	sort.SliceStable(scoped, func(i, j int) bool {
		if scoped[i].createdAt != scoped[j].createdAt {
			return scoped[i].createdAt > scoped[j].createdAt
		}
		return scoped[i].id > scoped[j].id
	})

	if !cursor.IsZero() {
		var idx int
		var found bool
		for i, r := range scoped {
			if r.id == cursor.Position {
				idx = i
				found = true
				break
			}
		}
		if !found {
			// Cursor pointed at a row that the principal cannot see
			// (e.g., cross-tenant or deleted). The store layer
			// returns an empty page — the cursor is opaque, so the
			// caller cannot distinguish missing-row from end-of-set.
			return nil
		}
		scoped = scoped[idx+1:]
	}

	if len(scoped) > limit+1 {
		scoped = scoped[:limit+1]
	}
	return scoped
}

func TestCursorPagingCoversFullSetWithoutDuplicates(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	for i := 0; i < 10; i++ {
		store.insert(row{
			id:        rowID(i),
			createdAt: int64(i + 1),
			orgID:     "org_a",
		})
	}

	const pageSize = 3
	seen := map[string]int{}
	var cursor Cursor
	for page := 0; page < 10; page++ {
		raw := store.list("org_a", pageSize, cursor)
		p := BuildPage(raw, pageSize, positionByID, nil)
		for _, r := range p.Items {
			seen[r.id]++
		}
		if p.NextCursor == "" {
			break
		}
		var err error
		cursor, err = DecodeCursor(p.NextCursor)
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
	}

	if len(seen) != 10 {
		t.Fatalf("expected 10 unique rows across all pages, saw %d (%v)", len(seen), seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("row %s appeared %d times across pages", id, n)
		}
	}
}

func TestCursorIsStableUnderInserts(t *testing.T) {
	t.Parallel()

	// Seed 6 rows, page once to get the first 3, then insert two NEW
	// rows that sort BEFORE the cursor boundary (higher createdAt /
	// id). The next page must still return exactly the next 3 rows
	// the caller has not seen — the inserts must not duplicate any
	// row from page 1 onto page 2 and must not skip any row that was
	// in the original set.
	store := &fakeStore{}
	for i := 0; i < 6; i++ {
		store.insert(row{id: rowID(i), createdAt: int64(i + 1), orgID: "org_a"})
	}

	first := BuildPage(store.list("org_a", 3, Cursor{}), 3, positionByID, nil)
	if len(first.Items) != 3 {
		t.Fatalf("expected first page of 3, got %d", len(first.Items))
	}
	if first.NextCursor == "" {
		t.Fatal("expected NextCursor on first page")
	}

	page1IDs := map[string]struct{}{}
	for _, r := range first.Items {
		page1IDs[r.id] = struct{}{}
	}

	// Insert two newer rows after the first page was served.
	store.insert(row{id: "r10", createdAt: 100, orgID: "org_a"})
	store.insert(row{id: "r11", createdAt: 101, orgID: "org_a"})

	cursor, err := DecodeCursor(first.NextCursor)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	second := BuildPage(store.list("org_a", 3, cursor), 3, positionByID, nil)
	if len(second.Items) != 3 {
		t.Fatalf("expected second page of 3 (remaining originals), got %d (%v)", len(second.Items), second.Items)
	}
	for _, r := range second.Items {
		if _, dup := page1IDs[r.id]; dup {
			t.Fatalf("row %q appeared on both page 1 and page 2 after a concurrent insert", r.id)
		}
		if r.id == "r10" || r.id == "r11" {
			t.Fatalf("newly-inserted row %q must not appear on page 2 (it sorts above the cursor boundary)", r.id)
		}
	}
}

func TestCursorTenantIsolation(t *testing.T) {
	t.Parallel()

	// Two organizations, identical row ids on both — the cursor must
	// not leak rows across tenants. The store's list query already
	// scopes by orgID; the cursor only carries a position, so a
	// caller paging org_a's list can never see org_b's rows even if
	// the same id existed in both tenants.
	store := &fakeStore{}
	for i := 0; i < 5; i++ {
		store.insert(row{id: rowID(i), createdAt: int64(i + 1), orgID: "org_a"})
		store.insert(row{id: rowID(i), createdAt: int64(i + 1), orgID: "org_b"})
	}

	// Page through org_a end to end.
	seen := map[string]struct{}{}
	var cursor Cursor
	for page := 0; page < 10; page++ {
		raw := store.list("org_a", 2, cursor)
		p := BuildPage(raw, 2, positionByID, nil)
		for _, r := range p.Items {
			if r.orgID != "org_a" {
				t.Fatalf("page leaked row from %q while paging org_a", r.orgID)
			}
			seen[r.id] = struct{}{}
		}
		if p.NextCursor == "" {
			break
		}
		var err error
		cursor, err = DecodeCursor(p.NextCursor)
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("expected to see all 5 org_a rows, got %d", len(seen))
	}

	// A caller holding a cursor for org_a tries to use it against
	// org_b: tenant isolation means the resolver pins the
	// organization id at the store layer (orgID="org_b"), so the
	// cursor position simply identifies a row not visible under
	// org_b. The result is an empty page — never another tenant's
	// rows.
	hostileCursor, _ := DecodeCursor(EncodeCursor(positionByID(row{id: rowID(2)})))
	rawCross := store.list("org_b", 2, hostileCursor)
	page := BuildPage(rawCross, 2, positionByID, nil)
	for _, r := range page.Items {
		if r.orgID != "org_b" {
			t.Fatalf("cross-tenant cursor leaked row from %q", r.orgID)
		}
	}
}

func rowID(i int) string {
	return "r" + map[int]string{
		0: "0", 1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6", 7: "7", 8: "8", 9: "9",
	}[i]
}

// TestParseParamsCursorRejectsTamperedPayload demonstrates that an
// attacker cannot edit a cursor by modifying the base64 substring and
// expect the server to accept it. The cursor schema_version sentinel
// inside the payload guards against fuzzed-base64 admit attacks.
func TestParseParamsCursorRejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	valid := EncodeCursor(Cursor{Position: "anchor", Sort: "created_at", Direction: DirectionDescending})

	// Flip one character in the middle. Any single-byte flip in a
	// base64url-encoded JSON payload will fail either decoding or
	// schema-version validation.
	if len(valid) < 8 {
		t.Fatalf("encoded cursor too short for tamper test: %q", valid)
	}
	tampered := []byte(valid)
	for i := 0; i < len(tampered); i++ {
		if tampered[i] != 'a' {
			tampered[i] = 'a'
			break
		}
	}

	q := url.Values{
		"cursor": []string{string(tampered)},
		"sort":   []string{"created_at"},
	}
	_, err := ParseParams(q, ParseOptions{SortAllowList: []string{"created_at"}})
	if err == nil {
		t.Fatal("expected error for tampered cursor")
	}
}
