package retention

import (
	"fmt"
	"sort"
	"time"
)

// ResourceKind names a customer-data resource family whose lifecycle the
// retention package governs. The set is closed; callers switch on it
// exhaustively in tests, so a new kind is a deliberate, reviewed addition.
type ResourceKind string

// The canonical resource kinds. Values are stable wire identifiers and are
// used in audit metadata, telemetry, and operator runbooks.
const (
	KindOrganization ResourceKind = "organization"
	KindProject      ResourceKind = "project"
	KindEnvironment  ResourceKind = "environment"
	KindService      ResourceKind = "service"
	KindAPIKey       ResourceKind = "api_key"
	KindMembership   ResourceKind = "membership"
)

// allKinds is the closed enumeration of ResourceKind values. AllKinds returns
// a stable, sorted copy so callers can range over the universe of kinds (for
// example, a teardown worker that scans every soft-delete table in turn)
// without taking a dependency on map iteration order.
var allKinds = []ResourceKind{
	KindOrganization,
	KindProject,
	KindEnvironment,
	KindService,
	KindAPIKey,
	KindMembership,
}

// AllKinds returns a sorted copy of the closed set of ResourceKind values.
func AllKinds() []ResourceKind {
	out := make([]ResourceKind, len(allKinds))
	copy(out, allKinds)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid reports whether k is one of the recognised resource kinds.
func (k ResourceKind) Valid() bool {
	switch k {
	case KindOrganization, KindProject, KindEnvironment, KindService, KindAPIKey, KindMembership:
		return true
	default:
		return false
	}
}

// SoftDeleteColumn returns the database column that records the soft-delete
// stamp for k, or the empty string if k is hard-deleted at the SQL layer.
// The mapping is informational; the retention package itself never reads or
// writes the database.
func (k ResourceKind) SoftDeleteColumn() string {
	switch k {
	case KindOrganization, KindProject, KindEnvironment, KindService:
		return "deletion_scheduled_at"
	case KindAPIKey:
		return "revoked_at"
	case KindMembership:
		return ""
	default:
		return ""
	}
}

// Window is the per-kind retention configuration.
//
//   - Restorable controls whether a soft-deleted row can be brought back at
//     all. API keys are revocation-only (terminal) and memberships are hard
//     deleted, so both carry Restorable=false.
//   - RestoreWindow names how long after the lifecycle stamp a Restorable
//     kind may be brought back. Outside the window the row physically remains
//     but the restore endpoint refuses.
//   - ReapAfter names how long after the lifecycle stamp the destructive
//     teardown worker may hard-delete the row. ReapAfter must be at least as
//     large as RestoreWindow; the gap is the operator's grace period for an
//     out-of-band restore. ReapAfter == 0 means the kind is never reaped by
//     a customer-facing worker — it remains until its tenant is purged.
type Window struct {
	Restorable    bool
	RestoreWindow time.Duration
	ReapAfter     time.Duration
}

// validate reports a configuration error in w for kind k.
func (w Window) validate(k ResourceKind) error {
	if w.RestoreWindow < 0 {
		return fmt.Errorf("retention: %s window: RestoreWindow must not be negative, got %s", k, w.RestoreWindow)
	}
	if w.ReapAfter < 0 {
		return fmt.Errorf("retention: %s window: ReapAfter must not be negative, got %s", k, w.ReapAfter)
	}
	if w.Restorable && w.RestoreWindow <= 0 {
		return fmt.Errorf("retention: %s window: Restorable kinds require a positive RestoreWindow, got %s", k, w.RestoreWindow)
	}
	if !w.Restorable && w.RestoreWindow != 0 {
		return fmt.Errorf("retention: %s window: non-Restorable kinds must have zero RestoreWindow, got %s", k, w.RestoreWindow)
	}
	if w.ReapAfter != 0 && w.ReapAfter < w.RestoreWindow {
		return fmt.Errorf("retention: %s window: ReapAfter (%s) must be >= RestoreWindow (%s)", k, w.ReapAfter, w.RestoreWindow)
	}
	return nil
}

// Policy maps every ResourceKind to its Window. The zero value of Policy is
// invalid; use DefaultPolicy or NewPolicy to construct one. Policy values are
// immutable: lookups return values, not pointers, and there is no Set method
// — a different policy is a different Policy.
type Policy struct {
	windows map[ResourceKind]Window
}

// DefaultPolicy returns the production retention policy:
//
//   - Customer-facing tenant resources (organization, project, environment,
//     service) carry a 30-day restore window plus a 60-day grace before the
//     teardown worker is allowed to hard-delete. The 90-day total is the
//     same horizon SOC 2 incident-response runbooks reference and gives
//     operators a comfortable margin for an out-of-band restore.
//   - API keys are revocation-only: once revoked they are not restorable
//     (Restorable=false, RestoreWindow=0). The revoked row is held for
//     90 days so audit lookups by prefix still resolve, then the teardown
//     worker may purge it.
//   - Memberships are hard-deleted: SupportsSoftDelete returns false and the
//     Window reports zero on every duration. The membership.role_version
//     counter invalidates outstanding session tokens and the audit_events
//     row carries the historical trail; the retention worker has nothing to
//     do.
func DefaultPolicy() Policy {
	restorable := Window{
		Restorable:    true,
		RestoreWindow: 30 * 24 * time.Hour,
		ReapAfter:     90 * 24 * time.Hour,
	}
	return Policy{windows: map[ResourceKind]Window{
		KindOrganization: restorable,
		KindProject:      restorable,
		KindEnvironment:  restorable,
		KindService:      restorable,
		KindAPIKey: {
			Restorable:    false,
			RestoreWindow: 0,
			ReapAfter:     90 * 24 * time.Hour,
		},
		KindMembership: {
			Restorable:    false,
			RestoreWindow: 0,
			ReapAfter:     0,
		},
	}}
}

// NewPolicy constructs a Policy from the supplied windows. Every ResourceKind
// in AllKinds() must be present and every Window must validate; otherwise
// NewPolicy returns an error and a zero Policy. The map is copied, so later
// mutation by the caller does not affect the Policy.
func NewPolicy(windows map[ResourceKind]Window) (Policy, error) {
	if windows == nil {
		return Policy{}, fmt.Errorf("retention: NewPolicy: windows must not be nil")
	}
	for k := range windows {
		if !k.Valid() {
			return Policy{}, fmt.Errorf("retention: NewPolicy: unknown kind %q", k)
		}
	}
	copied := make(map[ResourceKind]Window, len(allKinds))
	for _, k := range allKinds {
		w, ok := windows[k]
		if !ok {
			return Policy{}, fmt.Errorf("retention: NewPolicy: missing window for kind %q", k)
		}
		if err := w.validate(k); err != nil {
			return Policy{}, err
		}
		copied[k] = w
	}
	return Policy{windows: copied}, nil
}

// Window returns the Window configured for kind k. The second return value is
// false if k is not a recognised kind or if the policy was zero-initialised
// (the zero Policy has no windows).
func (p Policy) Window(k ResourceKind) (Window, bool) {
	if p.windows == nil {
		return Window{}, false
	}
	w, ok := p.windows[k]
	return w, ok
}

// SupportsSoftDelete reports whether the schema for kind k carries a
// soft-delete column (deletion_scheduled_at or revoked_at). Returns false for
// memberships and for unknown kinds.
func (p Policy) SupportsSoftDelete(k ResourceKind) bool {
	return k.SoftDeleteColumn() != ""
}

// Restorable reports whether a soft-deleted row of kind k can ever be brought
// back through a customer-facing restore endpoint. Returns false for kinds
// the policy was not configured with.
func (p Policy) Restorable(k ResourceKind) bool {
	w, ok := p.Window(k)
	if !ok {
		return false
	}
	return w.Restorable
}

// RestorableAt reports whether a row of kind k whose lifecycle stamp is
// stampedAt can be restored at now. Returns false when:
//
//   - the kind is not Restorable,
//   - stampedAt is the zero value (no soft-delete recorded),
//   - now is before stampedAt (clock skew or a malformed stamp), or
//   - now is at or past stampedAt + RestoreWindow.
//
// The strict less-than comparison at the upper bound means the customer can
// restore right up to but not at the expiry instant — symmetric with the
// strict comparison ReapableAt uses.
func (p Policy) RestorableAt(k ResourceKind, stampedAt, now time.Time) bool {
	w, ok := p.Window(k)
	if !ok || !w.Restorable {
		return false
	}
	if stampedAt.IsZero() {
		return false
	}
	if now.Before(stampedAt) {
		return false
	}
	return now.Sub(stampedAt) < w.RestoreWindow
}

// RestoreDeadline returns the instant at which RestorableAt flips from true
// to false for stampedAt under kind k. The second return value is false if
// the kind is not Restorable, if stampedAt is the zero value, or if the
// policy is not configured for k.
func (p Policy) RestoreDeadline(k ResourceKind, stampedAt time.Time) (time.Time, bool) {
	w, ok := p.Window(k)
	if !ok || !w.Restorable || stampedAt.IsZero() {
		return time.Time{}, false
	}
	return stampedAt.Add(w.RestoreWindow), true
}

// RemainingRestore returns the duration left for the customer to restore a
// row of kind k stamped at stampedAt, measured from now. The result is
// clamped to zero and is zero whenever RestorableAt would be false.
func (p Policy) RemainingRestore(k ResourceKind, stampedAt, now time.Time) time.Duration {
	deadline, ok := p.RestoreDeadline(k, stampedAt)
	if !ok {
		return 0
	}
	if now.Before(stampedAt) {
		return 0
	}
	if !now.Before(deadline) {
		return 0
	}
	return deadline.Sub(now)
}

// ReapableAt reports whether the teardown worker is permitted to hard-delete
// a row of kind k whose lifecycle stamp is stampedAt at now. Returns false
// when:
//
//   - the policy is not configured for k,
//   - the kind has ReapAfter == 0 (never reaped on the customer-facing path
//     — e.g. memberships, which are already hard-deleted at write time),
//   - stampedAt is the zero value,
//   - now is before stampedAt, or
//   - now is strictly less than stampedAt + ReapAfter.
//
// The strict less-than comparison means a row becomes reapable at the exact
// instant ReapAfter elapses, so a worker that wakes up every minute will
// pick it up on the first tick at or after the deadline.
func (p Policy) ReapableAt(k ResourceKind, stampedAt, now time.Time) bool {
	w, ok := p.Window(k)
	if !ok {
		return false
	}
	if w.ReapAfter == 0 {
		return false
	}
	if stampedAt.IsZero() {
		return false
	}
	if now.Before(stampedAt) {
		return false
	}
	return now.Sub(stampedAt) >= w.ReapAfter
}

// ReapDeadline returns the instant at which ReapableAt flips from false to
// true for stampedAt under kind k. The second return value is false if the
// kind has ReapAfter == 0, if stampedAt is the zero value, or if the policy
// is not configured for k.
func (p Policy) ReapDeadline(k ResourceKind, stampedAt time.Time) (time.Time, bool) {
	w, ok := p.Window(k)
	if !ok || w.ReapAfter == 0 || stampedAt.IsZero() {
		return time.Time{}, false
	}
	return stampedAt.Add(w.ReapAfter), true
}

// AllowsSlugReuse reports whether a customer may create a new resource of
// kind k with a slug that matches a previously soft-deleted row stamped at
// stampedAt, at now. The schema does not carry a partial unique index
// excluding soft-deleted rows, so the slug stays reserved for the lifetime
// of the row. AllowsSlugReuse therefore returns true only at the exact
// moment ReapableAt becomes true: the earliest instant the teardown worker
// is permitted to remove the row and free the slug.
//
// Kinds whose schema does not slug-namespace (api_keys identifies by prefix,
// memberships by user_id) always return false: there is no slug to reuse.
func (p Policy) AllowsSlugReuse(k ResourceKind, stampedAt, now time.Time) bool {
	switch k {
	case KindOrganization, KindProject, KindEnvironment, KindService:
		return p.ReapableAt(k, stampedAt, now)
	default:
		return false
	}
}
