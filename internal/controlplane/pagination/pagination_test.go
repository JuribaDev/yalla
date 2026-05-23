package pagination

import (
	stderrors "errors"
	"net/url"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// asAPIErr unwraps err to the underlying *yerr.Error returned by the
// apierr package. It is the canonical assertion shape across the
// control-plane test suites and keeps the test bodies focused on the
// code and violations under test.
func asAPIErr(t *testing.T, err error) *yerr.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("expected *yerr.Error, got %T (%v)", err, err)
	}
	return ye
}

func requireInvalidInput(t *testing.T, err error, expectField string) {
	t.Helper()
	ye := asAPIErr(t, err)
	if ye.Code != yerr.CodeValidation {
		t.Fatalf("expected code %s, got %s", yerr.CodeValidation, ye.Code)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok || len(violations) == 0 {
		t.Fatalf("expected field violations, got none")
	}
	if expectField == "" {
		return
	}
	for _, v := range violations {
		if v.Field == expectField {
			return
		}
	}
	t.Fatalf("expected violation on field %q, got %+v", expectField, violations)
}

func TestParseParamsDefaultsWhenAbsent(t *testing.T) {
	t.Parallel()

	p, err := ParseParams(url.Values{}, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit != DefaultLimit {
		t.Fatalf("expected limit %d, got %d", DefaultLimit, p.Limit)
	}
	if p.Direction != DirectionDescending {
		t.Fatalf("expected default direction %q, got %q", DirectionDescending, p.Direction)
	}
	if !p.Cursor.IsZero() {
		t.Fatalf("expected zero cursor, got %+v", p.Cursor)
	}
	if p.Sort != "" {
		t.Fatalf("expected empty sort, got %q", p.Sort)
	}
}

func TestParseParamsAppliesEndpointDefaults(t *testing.T) {
	t.Parallel()

	p, err := ParseParams(url.Values{}, ParseOptions{
		DefaultLimit:     25,
		DefaultSort:      "created_at",
		DefaultDirection: DirectionAscending,
		SortAllowList:    []string{"created_at"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit != 25 {
		t.Fatalf("expected limit 25, got %d", p.Limit)
	}
	if p.Sort != "created_at" {
		t.Fatalf("expected sort created_at, got %q", p.Sort)
	}
	if p.Direction != DirectionAscending {
		t.Fatalf("expected direction asc, got %q", p.Direction)
	}
}

func TestParseParamsHonoursMaxLimitCeiling(t *testing.T) {
	t.Parallel()

	// An endpoint requesting MaxLimit*2 is clamped to MaxLimit by the
	// effectiveMaxLimit helper, so a misconfigured endpoint cannot ask
	// for more than the package ceiling.
	p, err := ParseParams(url.Values{}, ParseOptions{MaxLimit: MaxLimit * 2, DefaultLimit: MaxLimit + 50})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit != MaxLimit {
		t.Fatalf("expected effective limit %d, got %d", MaxLimit, p.Limit)
	}
}

func TestParseParamsRejectsBadLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{"non-numeric", "abc"},
		{"zero", "0"},
		{"negative", "-5"},
		{"too-large", "10000"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			q := url.Values{"limit": []string{c.raw}}
			_, err := ParseParams(q, ParseOptions{})
			requireInvalidInput(t, err, "limit")
			// The submitted value is never echoed back, only the
			// classification — protects against reflection-style
			// content channels.
			msg := err.Error()
			if c.raw != "" && c.raw != "0" && strings.Contains(msg, c.raw) {
				t.Fatalf("error message %q must not echo submitted value %q", msg, c.raw)
			}
		})
	}
}

func TestParseParamsAcceptsValidLimit(t *testing.T) {
	t.Parallel()

	p, err := ParseParams(url.Values{"limit": []string{"7"}}, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit != 7 {
		t.Fatalf("expected limit 7, got %d", p.Limit)
	}
}

func TestParseParamsRejectsUnknownSort(t *testing.T) {
	t.Parallel()

	q := url.Values{"sort": []string{"injected"}}
	_, err := ParseParams(q, ParseOptions{SortAllowList: []string{"created_at"}})
	requireInvalidInput(t, err, "sort")
}

func TestParseParamsAcceptsAllowListedSort(t *testing.T) {
	t.Parallel()

	q := url.Values{"sort": []string{"created_at"}}
	p, err := ParseParams(q, ParseOptions{SortAllowList: []string{"created_at", "name"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Sort != "created_at" {
		t.Fatalf("expected sort created_at, got %q", p.Sort)
	}
}

func TestParseParamsRejectsBadDirection(t *testing.T) {
	t.Parallel()

	q := url.Values{"direction": []string{"sideways"}}
	_, err := ParseParams(q, ParseOptions{})
	requireInvalidInput(t, err, "direction")
}

func TestParseParamsRejectsUnknownFilterKey(t *testing.T) {
	t.Parallel()

	q := url.Values{"filter.unknown": []string{"x"}}
	_, err := ParseParams(q, ParseOptions{FilterAllowList: []string{"status"}})
	requireInvalidInput(t, err, "filter.unknown")
}

func TestParseParamsRejectsEmptyFilterValue(t *testing.T) {
	t.Parallel()

	q := url.Values{"filter.status": []string{"   "}}
	_, err := ParseParams(q, ParseOptions{FilterAllowList: []string{"status"}})
	requireInvalidInput(t, err, "filter.status")
}

func TestParseParamsAcceptsAllowListedFilter(t *testing.T) {
	t.Parallel()

	q := url.Values{"filter.status": []string{" ready "}}
	p, err := ParseParams(q, ParseOptions{FilterAllowList: []string{"status"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Filter["status"] != "ready" {
		t.Fatalf("expected filter.status=ready (trimmed), got %q", p.Filter["status"])
	}
}

func TestParseParamsRejectsMalformedCursor(t *testing.T) {
	t.Parallel()

	q := url.Values{"cursor": []string{"::::not-base64::::"}}
	_, err := ParseParams(q, ParseOptions{})
	requireInvalidInput(t, err, "cursor")
}

func TestParseParamsRejectsCursorWithMismatchedSort(t *testing.T) {
	t.Parallel()

	cursor := EncodeCursor(Cursor{Position: "p1", Sort: "name", Direction: DirectionDescending})
	q := url.Values{
		"cursor": []string{cursor},
		"sort":   []string{"created_at"},
	}
	_, err := ParseParams(q, ParseOptions{SortAllowList: []string{"created_at", "name"}})
	requireInvalidInput(t, err, "cursor")
}

func TestParseParamsRejectsCursorWithMismatchedDirection(t *testing.T) {
	t.Parallel()

	cursor := EncodeCursor(Cursor{Position: "p1", Sort: "", Direction: DirectionAscending})
	q := url.Values{
		"cursor":    []string{cursor},
		"direction": []string{"desc"},
	}
	_, err := ParseParams(q, ParseOptions{})
	requireInvalidInput(t, err, "cursor")
}

func TestParseParamsAccumulatesViolations(t *testing.T) {
	t.Parallel()

	q := url.Values{
		"limit":     []string{"0"},
		"direction": []string{"sideways"},
	}
	_, err := ParseParams(q, ParseOptions{})
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("expected violations, got %v", err)
	}
	seen := map[string]bool{}
	for _, v := range violations {
		seen[v.Field] = true
	}
	if !seen["limit"] || !seen["direction"] {
		t.Fatalf("expected violations on limit and direction, got %+v", violations)
	}
}

func TestParseParamsAcceptsValidCursor(t *testing.T) {
	t.Parallel()

	cursor := EncodeCursor(Cursor{
		Position:  "01HZX_anchor",
		Sort:      "created_at",
		Direction: DirectionDescending,
	})
	q := url.Values{
		"cursor": []string{cursor},
		"sort":   []string{"created_at"},
	}
	p, err := ParseParams(q, ParseOptions{SortAllowList: []string{"created_at"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Cursor.Position != "01HZX_anchor" {
		t.Fatalf("expected decoded position, got %+v", p.Cursor)
	}
}

func TestSortDirectionIsValid(t *testing.T) {
	t.Parallel()
	if !DirectionAscending.IsValid() {
		t.Fatal("asc must be valid")
	}
	if !DirectionDescending.IsValid() {
		t.Fatal("desc must be valid")
	}
	if SortDirection("sideways").IsValid() {
		t.Fatal("non-canonical direction must not be valid")
	}
}

func TestEffectiveDefaultLimitClampsToMaxAndMin(t *testing.T) {
	t.Parallel()

	// DefaultLimit above the configured MaxLimit is clamped down.
	opts := ParseOptions{DefaultLimit: 500, MaxLimit: 25}
	if got := opts.effectiveDefaultLimit(); got != 25 {
		t.Fatalf("expected default clamped to 25, got %d", got)
	}

	// A zero DefaultLimit but a low MaxLimit clamps the package
	// default down to the endpoint ceiling.
	opts = ParseOptions{MaxLimit: 5}
	if got := opts.effectiveDefaultLimit(); got != 5 {
		t.Fatalf("expected default clamped to 5, got %d", got)
	}

	// Negative MaxLimit resolves to MinLimit.
	opts = ParseOptions{MaxLimit: -1}
	if got := opts.effectiveMaxLimit(); got != MaxLimit {
		t.Fatalf("expected fallback to package max %d, got %d", MaxLimit, got)
	}
}
