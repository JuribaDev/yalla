package retention_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/retention"
)

// fixedNow is the reference instant every duration in the suite is measured
// from. The value is opaque; the tests assert offsets, never absolute clocks.
var fixedNow = time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

// TestAllKinds_IsClosedAndSorted pins the universe of ResourceKind values
// the rest of the suite ranges over. Adding a new kind without updating
// AllKinds is a deliberate sweep; the policy must keep its closed set in
// lock-step with the schema.
func TestAllKinds_IsClosedAndSorted(t *testing.T) {
	t.Parallel()
	got := retention.AllKinds()
	want := []retention.ResourceKind{
		retention.KindAPIKey,
		retention.KindEnvironment,
		retention.KindMembership,
		retention.KindOrganization,
		retention.KindProject,
		retention.KindService,
	}
	if len(got) != len(want) {
		t.Fatalf("AllKinds length = %d; want %d (kinds: %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllKinds[%d] = %q; want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	// The slice must be a copy: mutating it cannot affect the next caller.
	got[0] = retention.ResourceKind("mutated")
	again := retention.AllKinds()
	if again[0] == "mutated" {
		t.Fatalf("AllKinds returned shared slice; second call observed mutation")
	}
}

// TestResourceKind_Valid asserts the closed set rejects strangers and
// accepts every canonical value.
func TestResourceKind_Valid(t *testing.T) {
	t.Parallel()
	for _, k := range retention.AllKinds() {
		if !k.Valid() {
			t.Fatalf("Valid(%q) = false; want true", k)
		}
	}
	for _, k := range []retention.ResourceKind{"", "deployment", "ORGANIZATION", "org"} {
		if k.Valid() {
			t.Fatalf("Valid(%q) = true; want false", k)
		}
	}
}

// TestSoftDeleteColumn pins the schema mapping: callers compose SQL fragments
// against these strings, so a typo here is an SQL bug.
func TestSoftDeleteColumn(t *testing.T) {
	t.Parallel()
	cases := map[retention.ResourceKind]string{
		retention.KindOrganization: "deletion_scheduled_at",
		retention.KindProject:      "deletion_scheduled_at",
		retention.KindEnvironment:  "deletion_scheduled_at",
		retention.KindService:      "deletion_scheduled_at",
		retention.KindAPIKey:       "revoked_at",
		retention.KindMembership:   "",
	}
	for k, want := range cases {
		if got := k.SoftDeleteColumn(); got != want {
			t.Fatalf("%s.SoftDeleteColumn() = %q; want %q", k, got, want)
		}
	}
	if got := retention.ResourceKind("unknown").SoftDeleteColumn(); got != "" {
		t.Fatalf("unknown.SoftDeleteColumn() = %q; want empty", got)
	}
}

// TestDefaultPolicy_Shape asserts the customer-facing retention shape:
// tenant resources are restorable for 30 days and reaped at 90; api_keys are
// terminal but kept 90 days for audit; memberships are not retention-managed.
func TestDefaultPolicy_Shape(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	cases := []struct {
		kind     retention.ResourceKind
		want     retention.Window
		softable bool
		restore  bool
	}{
		{retention.KindOrganization, retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}, true, true},
		{retention.KindProject, retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}, true, true},
		{retention.KindEnvironment, retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}, true, true},
		{retention.KindService, retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}, true, true},
		{retention.KindAPIKey, retention.Window{Restorable: false, RestoreWindow: 0, ReapAfter: 90 * day}, true, false},
		{retention.KindMembership, retention.Window{}, false, false},
	}
	for _, tc := range cases {
		w, ok := p.Window(tc.kind)
		if !ok {
			t.Fatalf("Window(%s) missing", tc.kind)
		}
		if w != tc.want {
			t.Fatalf("Window(%s) = %+v; want %+v", tc.kind, w, tc.want)
		}
		if got := p.SupportsSoftDelete(tc.kind); got != tc.softable {
			t.Fatalf("SupportsSoftDelete(%s) = %v; want %v", tc.kind, got, tc.softable)
		}
		if got := p.Restorable(tc.kind); got != tc.restore {
			t.Fatalf("Restorable(%s) = %v; want %v", tc.kind, got, tc.restore)
		}
	}
}

// TestZeroPolicy_AnswersFalse asserts the zero Policy answers every query
// safely: no panics on nil maps, no false positives.
func TestZeroPolicy_AnswersFalse(t *testing.T) {
	t.Parallel()
	var p retention.Policy
	stampedAt := fixedNow.Add(-time.Hour)
	for _, k := range retention.AllKinds() {
		if _, ok := p.Window(k); ok {
			t.Fatalf("zero policy Window(%s) ok=true; want false", k)
		}
		if p.Restorable(k) {
			t.Fatalf("zero policy Restorable(%s) = true; want false", k)
		}
		if p.RestorableAt(k, stampedAt, fixedNow) {
			t.Fatalf("zero policy RestorableAt(%s) = true; want false", k)
		}
		if p.ReapableAt(k, stampedAt, fixedNow) {
			t.Fatalf("zero policy ReapableAt(%s) = true; want false", k)
		}
		if _, ok := p.RestoreDeadline(k, stampedAt); ok {
			t.Fatalf("zero policy RestoreDeadline(%s) ok=true; want false", k)
		}
		if _, ok := p.ReapDeadline(k, stampedAt); ok {
			t.Fatalf("zero policy ReapDeadline(%s) ok=true; want false", k)
		}
		if p.AllowsSlugReuse(k, stampedAt, fixedNow) {
			t.Fatalf("zero policy AllowsSlugReuse(%s) = true; want false", k)
		}
		if got := p.RemainingRestore(k, stampedAt, fixedNow); got != 0 {
			t.Fatalf("zero policy RemainingRestore(%s) = %s; want 0", k, got)
		}
	}
}

// TestNewPolicy_Validation pins NewPolicy's contract: every kind must be
// supplied, every window must validate, and the constructor returns the zero
// Policy on error.
func TestNewPolicy_Validation(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	good := retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}
	hardDelete := retention.Window{Restorable: false, RestoreWindow: 0, ReapAfter: 0}

	full := func() map[retention.ResourceKind]retention.Window {
		return map[retention.ResourceKind]retention.Window{
			retention.KindOrganization: good,
			retention.KindProject:      good,
			retention.KindEnvironment:  good,
			retention.KindService:      good,
			retention.KindAPIKey:       hardDelete,
			retention.KindMembership:   hardDelete,
		}
	}

	// Happy path: a complete, valid map round-trips through NewPolicy.
	if _, err := retention.NewPolicy(full()); err != nil {
		t.Fatalf("NewPolicy(full) err = %v; want nil", err)
	}

	cases := []struct {
		name    string
		windows map[retention.ResourceKind]retention.Window
		want    string
	}{
		{"nil map", nil, "must not be nil"},
		{"missing org", func() map[retention.ResourceKind]retention.Window {
			m := full()
			delete(m, retention.KindOrganization)
			return m
		}(), "missing window"},
		{"unknown kind", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.ResourceKind("widget")] = good
			return m
		}(), "unknown kind"},
		{"negative restore window", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.KindOrganization] = retention.Window{Restorable: true, RestoreWindow: -1, ReapAfter: 90 * day}
			return m
		}(), "RestoreWindow must not be negative"},
		{"restorable but zero window", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.KindProject] = retention.Window{Restorable: true, RestoreWindow: 0, ReapAfter: 90 * day}
			return m
		}(), "require a positive RestoreWindow"},
		{"non-restorable with window", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.KindAPIKey] = retention.Window{Restorable: false, RestoreWindow: 5 * day, ReapAfter: 90 * day}
			return m
		}(), "non-Restorable kinds must have zero RestoreWindow"},
		{"reap before restore", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.KindEnvironment] = retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 5 * day}
			return m
		}(), "ReapAfter"},
		{"negative reap", func() map[retention.ResourceKind]retention.Window {
			m := full()
			m[retention.KindService] = retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: -1}
			return m
		}(), "ReapAfter must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := retention.NewPolicy(tc.windows)
			if err == nil {
				t.Fatalf("NewPolicy(%s) err = nil; want %q", tc.name, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewPolicy(%s) err = %q; want substring %q", tc.name, err.Error(), tc.want)
			}
			if _, ok := p.Window(retention.KindOrganization); ok {
				t.Fatalf("NewPolicy(%s) returned non-zero Policy on error", tc.name)
			}
		})
	}
}

// TestNewPolicy_CopiesInput proves the constructor defends against later
// caller mutation: a Policy returned by NewPolicy is independent of the map
// passed in.
func TestNewPolicy_CopiesInput(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	good := retention.Window{Restorable: true, RestoreWindow: 30 * day, ReapAfter: 90 * day}
	hardDelete := retention.Window{Restorable: false, RestoreWindow: 0, ReapAfter: 0}
	in := map[retention.ResourceKind]retention.Window{
		retention.KindOrganization: good,
		retention.KindProject:      good,
		retention.KindEnvironment:  good,
		retention.KindService:      good,
		retention.KindAPIKey:       {Restorable: false, RestoreWindow: 0, ReapAfter: 90 * day},
		retention.KindMembership:   hardDelete,
	}
	p, err := retention.NewPolicy(in)
	if err != nil {
		t.Fatalf("NewPolicy err = %v", err)
	}
	in[retention.KindOrganization] = retention.Window{Restorable: false, RestoreWindow: 0, ReapAfter: 0}
	w, ok := p.Window(retention.KindOrganization)
	if !ok {
		t.Fatal("Window(org) missing after caller mutation")
	}
	if w != good {
		t.Fatalf("Window(org) = %+v after caller mutation; want %+v", w, good)
	}
}

// TestRestorableAt_Window_OrgFamily covers the restore-window predicate for
// every customer-facing tenant kind. The same Window applies, so a single
// case loop locks every kind to the same edges: before stamp, at stamp,
// mid-window, at the boundary, just past, and far past.
func TestRestorableAt_Window_OrgFamily(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	restoreWindow := 30 * day
	stampedAt := fixedNow

	kinds := []retention.ResourceKind{
		retention.KindOrganization,
		retention.KindProject,
		retention.KindEnvironment,
		retention.KindService,
	}
	type tc struct {
		name string
		now  time.Time
		want bool
	}
	cases := []tc{
		{"before stamp", stampedAt.Add(-time.Minute), false},
		{"exactly at stamp", stampedAt, true},
		{"one second after stamp", stampedAt.Add(time.Second), true},
		{"mid window", stampedAt.Add(15 * day), true},
		{"one nanosecond before boundary", stampedAt.Add(restoreWindow - time.Nanosecond), true},
		{"exactly at boundary", stampedAt.Add(restoreWindow), false},
		{"one nanosecond past boundary", stampedAt.Add(restoreWindow + time.Nanosecond), false},
		{"a day past boundary", stampedAt.Add(restoreWindow + day), false},
	}
	for _, k := range kinds {
		for _, c := range cases {
			t.Run(string(k)+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				if got := p.RestorableAt(k, stampedAt, c.now); got != c.want {
					t.Fatalf("RestorableAt(%s, stamp, now=%s) = %v; want %v", k, c.now, got, c.want)
				}
			})
		}
	}
}

// TestRestorableAt_ZeroStamp asserts a NULL deletion_scheduled_at is never
// restorable: the row is live, not soft-deleted, so the restore endpoint
// must refuse.
func TestRestorableAt_ZeroStamp(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	for _, k := range retention.AllKinds() {
		if p.RestorableAt(k, time.Time{}, fixedNow) {
			t.Fatalf("RestorableAt(%s, zero stamp) = true; want false", k)
		}
	}
}

// TestRestorableAt_TerminalKinds asserts the policy refuses to restore api
// keys and memberships even within the conceptual window. The schema makes
// api_keys terminal (revoked_at is one-way) and hard-deletes memberships;
// the policy must agree with both.
func TestRestorableAt_TerminalKinds(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	stampedAt := fixedNow
	for _, k := range []retention.ResourceKind{retention.KindAPIKey, retention.KindMembership} {
		if p.Restorable(k) {
			t.Fatalf("Restorable(%s) = true; want false", k)
		}
		for _, offset := range []time.Duration{0, time.Second, time.Hour, 24 * time.Hour, 90 * 24 * time.Hour} {
			if p.RestorableAt(k, stampedAt, stampedAt.Add(offset)) {
				t.Fatalf("RestorableAt(%s, +%s) = true; want false (kind is terminal)", k, offset)
			}
		}
	}
}

// TestRestoreDeadline_AndRemaining pins the two convenience getters against
// the same window: RestoreDeadline equals stampedAt + RestoreWindow, and
// RemainingRestore is the clamped delta from now.
func TestRestoreDeadline_AndRemaining(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	stampedAt := fixedNow

	deadline, ok := p.RestoreDeadline(retention.KindProject, stampedAt)
	if !ok {
		t.Fatal("RestoreDeadline(project) missing")
	}
	want := stampedAt.Add(30 * day)
	if !deadline.Equal(want) {
		t.Fatalf("RestoreDeadline(project) = %s; want %s", deadline, want)
	}

	// Terminal kinds have no deadline.
	for _, k := range []retention.ResourceKind{retention.KindAPIKey, retention.KindMembership} {
		if _, ok := p.RestoreDeadline(k, stampedAt); ok {
			t.Fatalf("RestoreDeadline(%s) ok=true; want false", k)
		}
	}
	// Zero stamp yields no deadline.
	if _, ok := p.RestoreDeadline(retention.KindProject, time.Time{}); ok {
		t.Fatal("RestoreDeadline(project, zero) ok=true; want false")
	}

	cases := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{"before stamp clamps to zero", stampedAt.Add(-time.Hour), 0},
		{"at stamp full window", stampedAt, 30 * day},
		{"after some time", stampedAt.Add(10 * day), 20 * day},
		{"one nanosecond before deadline", deadline.Add(-time.Nanosecond), time.Nanosecond},
		{"exactly at deadline clamps to zero", deadline, 0},
		{"past deadline clamps to zero", deadline.Add(time.Hour), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := p.RemainingRestore(retention.KindProject, stampedAt, c.now); got != c.want {
				t.Fatalf("RemainingRestore(%s, now=%s) = %s; want %s", c.name, c.now, got, c.want)
			}
		})
	}
}

// TestReapableAt_TeardownWorker exercises the predicate the teardown worker
// will pivot on. Tenant-family kinds (org/proj/env/svc) become reapable at
// stamp + 90 days; api_keys also become reapable at 90 days; memberships
// never become reapable through this surface.
func TestReapableAt_TeardownWorker(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	stampedAt := fixedNow

	reapable := []retention.ResourceKind{
		retention.KindOrganization,
		retention.KindProject,
		retention.KindEnvironment,
		retention.KindService,
		retention.KindAPIKey,
	}
	for _, k := range reapable {
		cases := []struct {
			name string
			now  time.Time
			want bool
		}{
			{"before stamp", stampedAt.Add(-time.Hour), false},
			{"at stamp", stampedAt, false},
			{"mid restore window", stampedAt.Add(10 * day), false},
			{"past restore window inside grace", stampedAt.Add(60 * day), false},
			{"one nanosecond before reap", stampedAt.Add(90*day - time.Nanosecond), false},
			{"exactly at reap deadline", stampedAt.Add(90 * day), true},
			{"one nanosecond past reap", stampedAt.Add(90*day + time.Nanosecond), true},
			{"a year past reap", stampedAt.Add(365 * day), true},
		}
		for _, c := range cases {
			t.Run(string(k)+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				if got := p.ReapableAt(k, stampedAt, c.now); got != c.want {
					t.Fatalf("ReapableAt(%s, +%s) = %v; want %v", k, c.now.Sub(stampedAt), got, c.want)
				}
			})
		}
	}

	// Memberships have ReapAfter == 0; the customer-facing teardown worker
	// must never pick one up.
	for _, offset := range []time.Duration{0, time.Hour, 30 * day, 365 * day} {
		if p.ReapableAt(retention.KindMembership, stampedAt, stampedAt.Add(offset)) {
			t.Fatalf("ReapableAt(membership, +%s) = true; want false", offset)
		}
	}

	// Zero stamp is never reapable on any kind.
	for _, k := range retention.AllKinds() {
		if p.ReapableAt(k, time.Time{}, fixedNow) {
			t.Fatalf("ReapableAt(%s, zero stamp) = true; want false", k)
		}
	}
}

// TestReapDeadline matches ReapableAt's boundary: the deadline is
// stampedAt + ReapAfter, and membership/zero-stamp queries return ok=false.
func TestReapDeadline(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	stampedAt := fixedNow

	if deadline, ok := p.ReapDeadline(retention.KindOrganization, stampedAt); !ok || !deadline.Equal(stampedAt.Add(90*day)) {
		t.Fatalf("ReapDeadline(org) = (%s, %v); want (%s, true)", deadline, ok, stampedAt.Add(90*day))
	}
	if _, ok := p.ReapDeadline(retention.KindMembership, stampedAt); ok {
		t.Fatal("ReapDeadline(membership) ok=true; want false")
	}
	if _, ok := p.ReapDeadline(retention.KindProject, time.Time{}); ok {
		t.Fatal("ReapDeadline(project, zero) ok=true; want false")
	}
}

// TestAllowsSlugReuse_HeldUntilReap is the name-reuse rule: the slug is
// held until the row is reaped, and only kinds that carry a slug ever flip
// to true.
func TestAllowsSlugReuse_HeldUntilReap(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	stampedAt := fixedNow

	slugged := []retention.ResourceKind{
		retention.KindOrganization,
		retention.KindProject,
		retention.KindEnvironment,
		retention.KindService,
	}
	for _, k := range slugged {
		cases := []struct {
			name string
			now  time.Time
			want bool
		}{
			{"held during restore window", stampedAt.Add(10 * day), false},
			{"held during grace", stampedAt.Add(60 * day), false},
			{"held one nanosecond before reap", stampedAt.Add(90*day - time.Nanosecond), false},
			{"free at reap deadline", stampedAt.Add(90 * day), true},
			{"free past reap deadline", stampedAt.Add(91 * day), true},
		}
		for _, c := range cases {
			t.Run(string(k)+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				if got := p.AllowsSlugReuse(k, stampedAt, c.now); got != c.want {
					t.Fatalf("AllowsSlugReuse(%s, +%s) = %v; want %v", k, c.now.Sub(stampedAt), got, c.want)
				}
			})
		}
	}

	// Non-slug-namespaced kinds always return false.
	for _, k := range []retention.ResourceKind{retention.KindAPIKey, retention.KindMembership} {
		for _, offset := range []time.Duration{0, 30 * day, 90 * day, 365 * day} {
			if p.AllowsSlugReuse(k, stampedAt, stampedAt.Add(offset)) {
				t.Fatalf("AllowsSlugReuse(%s, +%s) = true; want false (kind is not slug-namespaced)", k, offset)
			}
		}
	}
}

// TestPolicy_Coherence proves the three time-based predicates compose into a
// coherent lifecycle: a row is restorable, then held, then reapable; the
// transitions are monotone and non-overlapping for restorable kinds.
func TestPolicy_Coherence(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	day := 24 * time.Hour
	stampedAt := fixedNow

	for _, k := range []retention.ResourceKind{retention.KindOrganization, retention.KindProject, retention.KindEnvironment, retention.KindService} {
		w, _ := p.Window(k)
		restoreEnd := stampedAt.Add(w.RestoreWindow)
		reapStart := stampedAt.Add(w.ReapAfter)

		// During restore window: restorable, not reapable, slug held.
		mid := stampedAt.Add(w.RestoreWindow / 2)
		if !p.RestorableAt(k, stampedAt, mid) {
			t.Fatalf("%s: expected RestorableAt mid-window true", k)
		}
		if p.ReapableAt(k, stampedAt, mid) {
			t.Fatalf("%s: expected ReapableAt mid-window false", k)
		}
		if p.AllowsSlugReuse(k, stampedAt, mid) {
			t.Fatalf("%s: expected AllowsSlugReuse mid-window false", k)
		}

		// In the grace period: not restorable, not reapable, slug held.
		grace := restoreEnd.Add(time.Hour)
		if p.RestorableAt(k, stampedAt, grace) {
			t.Fatalf("%s: expected RestorableAt grace false", k)
		}
		if p.ReapableAt(k, stampedAt, grace) {
			t.Fatalf("%s: expected ReapableAt grace false", k)
		}
		if p.AllowsSlugReuse(k, stampedAt, grace) {
			t.Fatalf("%s: expected AllowsSlugReuse grace false", k)
		}

		// At reap deadline: not restorable, reapable, slug free.
		if p.RestorableAt(k, stampedAt, reapStart) {
			t.Fatalf("%s: expected RestorableAt at reap false", k)
		}
		if !p.ReapableAt(k, stampedAt, reapStart) {
			t.Fatalf("%s: expected ReapableAt at reap true", k)
		}
		if !p.AllowsSlugReuse(k, stampedAt, reapStart) {
			t.Fatalf("%s: expected AllowsSlugReuse at reap true", k)
		}

		// Far in the future: same as at reap deadline.
		far := reapStart.Add(30 * day)
		if !p.ReapableAt(k, stampedAt, far) {
			t.Fatalf("%s: expected ReapableAt far true", k)
		}
		if !p.AllowsSlugReuse(k, stampedAt, far) {
			t.Fatalf("%s: expected AllowsSlugReuse far true", k)
		}
	}
}

// TestUnknownKinds_AnswerFalse asserts every predicate refuses to answer
// truthy on an unrecognised kind. The retention policy is a closed contract:
// a string the caller invents must never look like a configured kind.
func TestUnknownKinds_AnswerFalse(t *testing.T) {
	t.Parallel()
	p := retention.DefaultPolicy()
	stampedAt := fixedNow
	for _, k := range []retention.ResourceKind{"", "Org", "deployment", "secret"} {
		if p.Restorable(k) {
			t.Fatalf("Restorable(%q) = true; want false", k)
		}
		if p.RestorableAt(k, stampedAt, fixedNow) {
			t.Fatalf("RestorableAt(%q) = true; want false", k)
		}
		if p.ReapableAt(k, stampedAt, fixedNow) {
			t.Fatalf("ReapableAt(%q) = true; want false", k)
		}
		if p.AllowsSlugReuse(k, stampedAt, fixedNow) {
			t.Fatalf("AllowsSlugReuse(%q) = true; want false", k)
		}
		if p.SupportsSoftDelete(k) {
			t.Fatalf("SupportsSoftDelete(%q) = true; want false", k)
		}
	}
}

// ensureErrorsImport keeps a reference to the errors package so future
// additions (e.g. errors.Is checks against retention sentinels) compile
// without a churn-only import edit. Pin the contract that NewPolicy returns
// a non-nil error on a malformed window.
func TestNewPolicy_ReturnsNonNilError(t *testing.T) {
	t.Parallel()
	_, err := retention.NewPolicy(nil)
	if err == nil {
		t.Fatal("NewPolicy(nil) err = nil; want non-nil")
	}
	if errors.Unwrap(err) != nil {
		// retention errors are intentionally flat strings; wrapping is not
		// part of the contract. If a future change wraps an underlying
		// reason this test fails and the contract needs an explicit update.
		t.Fatalf("NewPolicy(nil) returned a wrapped error %v; the contract is a flat error string", err)
	}
}
