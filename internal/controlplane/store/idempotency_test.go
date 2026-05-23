package store_test

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for IdempotencyRepository — the durable record that makes
// mutating endpoints safe to retry. They prove the claim protocol (fresh
// claim, replay of a completed claim, an in-flight pending claim, a
// same-key-different-request collision, and takeover of an expired claim),
// completion and release, and that a key can never observe or collide with
// another tenant's or another principal's claim. They run against an isolated,
// freshly migrated Postgres database and skip when YALLA_TEST_DATABASE_URL is
// unset.

// idemFixture builds a valid, minimal store.IdempotencyRecord for orgID and
// principalID under key, with the given request hash and a far-future expiry.
func idemFixture(orgID, principalID, key, hash string) store.IdempotencyRecord {
	return store.IdempotencyRecord{
		OrganizationID: orgID,
		PrincipalID:    principalID,
		Key:            key,
		Route:          "POST /v1/projects",
		RequestHash:    hash,
		RequestID:      "req-idem-1",
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	}
}

// claimIdem runs IdempotencyRepository.Claim through Store.Write and returns
// the resulting record and whether the caller now owns the claim.
func claimIdem(ctx context.Context, t *testing.T, s *store.Store, repo *store.IdempotencyRepository, rec store.IdempotencyRecord) (store.IdempotencyRecord, bool) {
	t.Helper()
	var (
		out     store.IdempotencyRecord
		claimed bool
	)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, c, e := repo.Claim(ctx, tx, rec)
		if e != nil {
			return e
		}
		out, claimed = r, c
		return nil
	}); err != nil {
		t.Fatalf("claim idempotency key: %v", err)
	}
	return out, claimed
}

// completeIdem runs IdempotencyRepository.Complete through Store.Write.
func completeIdem(ctx context.Context, t *testing.T, s *store.Store, repo *store.IdempotencyRepository, ref store.IdempotencyKeyRef, status int, body []byte) store.IdempotencyRecord {
	t.Helper()
	var out store.IdempotencyRecord
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, e := repo.Complete(ctx, tx, ref, status, body, time.Time{})
		if e != nil {
			return e
		}
		out = r
		return nil
	}); err != nil {
		t.Fatalf("complete idempotency claim: %v", err)
	}
	return out
}

// findIdem runs IdempotencyRepository.Find through Store.Read.
func findIdem(ctx context.Context, t *testing.T, s *store.Store, repo *store.IdempotencyRepository, ref store.IdempotencyKeyRef) (store.IdempotencyRecord, bool) {
	t.Helper()
	var (
		out store.IdempotencyRecord
		ok  bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		r, found, e := repo.Find(ctx, q, ref)
		if e != nil {
			return e
		}
		out, ok = r, found
		return nil
	}); err != nil {
		t.Fatalf("find idempotency key: %v", err)
	}
	return out, ok
}

// wantErrCode asserts err carries the expected stable error code.
func wantErrCode(t *testing.T, err error, code yerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", code)
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("error %v is not a *yerr.Error", err)
	}
	if ye.Code != code {
		t.Fatalf("error code = %s, want %s", ye.Code, code)
	}
}

func newIdempotencyStore(ctx context.Context, t *testing.T) (*store.Store, *store.IdempotencyRepository, *testutil.DB, *testutil.Factory) {
	t.Helper()
	db := testutil.RequireMigratedDB(t)
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("build store: %v", err)
	}
	return s, store.NewIdempotencyRepository(), db, testutil.NewFactory(t)
}

func TestIdempotencyClaimAndComplete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-abc", "hash-1")
	claimed, owned := claimIdem(ctx, t, s, repo, rec)
	if !owned {
		t.Fatal("first Claim must report the caller owns the claim")
	}
	if claimed.Status != store.IdempotencyStatusPending {
		t.Errorf("claim status = %q, want pending", claimed.Status)
	}
	if claimed.ID == "" {
		t.Error("Claim must mint an id for a blank-id record")
	}
	if claimed.RequestHash != "hash-1" || claimed.Route != "POST /v1/projects" {
		t.Errorf("claim did not persist the request identity: %+v", claimed)
	}

	body := []byte(`{"schema_version":"yalla.output.v1","ok":true,"data":{"job_id":"job_1"},"request_id":"req-idem-1"}`)
	completed := completeIdem(ctx, t, s, repo, rec.Ref(), 202, body)
	if completed.Status != store.IdempotencyStatusCompleted {
		t.Errorf("completed status = %q, want completed", completed.Status)
	}
	if completed.ResponseStatus != 202 {
		t.Errorf("completed response status = %d, want 202", completed.ResponseStatus)
	}
	if string(completed.ResponseBody) != string(body) {
		t.Errorf("completed response body = %q, want %q", completed.ResponseBody, body)
	}
	if completed.CompletedAt.IsZero() {
		t.Error("completed record must carry a completion timestamp")
	}

	found, ok := findIdem(ctx, t, s, repo, rec.Ref())
	if !ok {
		t.Fatal("Find must return the completed claim")
	}
	if found.Status != store.IdempotencyStatusCompleted || string(found.ResponseBody) != string(body) {
		t.Errorf("Find returned %+v, want the completed claim with its recorded body", found)
	}
}

func TestIdempotencyReplayAfterCompletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-replay", "hash-1")
	claimIdem(ctx, t, s, repo, rec)
	body := []byte(`{"ok":true}`)
	completeIdem(ctx, t, s, repo, rec.Ref(), 200, body)

	// A retry with the same key and the same request hash, after the original
	// completed, must not re-claim: it returns the completed record so the
	// middleware can replay the recorded response.
	replay, owned := claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-replay", "hash-1"))
	if owned {
		t.Fatal("a retry of a completed claim must not report ownership")
	}
	if replay.Status != store.IdempotencyStatusCompleted {
		t.Errorf("replay status = %q, want completed", replay.Status)
	}
	if replay.ResponseStatus != 200 || string(replay.ResponseBody) != string(body) {
		t.Errorf("replay returned %+v, want the recorded 200 response", replay)
	}
}

func TestIdempotencyClaimWhilePending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-inflight", "hash-1")
	claimIdem(ctx, t, s, repo, rec)

	// A retry that arrives while the original is still pending must not
	// re-claim: it returns the pending record so the middleware can answer
	// "already in progress" rather than running the handler twice.
	again, owned := claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-inflight", "hash-1"))
	if owned {
		t.Fatal("a retry of a pending claim must not report ownership")
	}
	if again.Status != store.IdempotencyStatusPending {
		t.Errorf("in-flight retry status = %q, want pending", again.Status)
	}
}

func TestIdempotencyClaimDifferentRequestSameKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	first := idemFixture(org.ID, "usr_principal_a", "key-collision", "hash-original")
	claimIdem(ctx, t, s, repo, first)

	// Reusing the key for a different request (a different hash) must not
	// re-claim and must return the ORIGINAL record unchanged, so the
	// middleware can compare hashes and reject the retry as a conflict.
	existing, owned := claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-collision", "hash-different"))
	if owned {
		t.Fatal("reusing a key for a different request must not report ownership")
	}
	if existing.RequestHash != "hash-original" {
		t.Errorf("returned request hash = %q, want the original %q", existing.RequestHash, "hash-original")
	}
}

func TestIdempotencyExpiredClaimTakenOver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	// An already-expired claim.
	expired := idemFixture(org.ID, "usr_principal_a", "key-expired", "hash-old")
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	claimIdem(ctx, t, s, repo, expired)

	// A fresh request under the same key takes the expired claim over: it
	// reports ownership and the row now carries the new request identity.
	fresh := idemFixture(org.ID, "usr_principal_a", "key-expired", "hash-new")
	taken, owned := claimIdem(ctx, t, s, repo, fresh)
	if !owned {
		t.Fatal("an expired claim must be taken over by a fresh claim")
	}
	if taken.RequestHash != "hash-new" {
		t.Errorf("taken-over request hash = %q, want %q", taken.RequestHash, "hash-new")
	}
	if taken.Status != store.IdempotencyStatusPending {
		t.Errorf("taken-over status = %q, want pending", taken.Status)
	}
}

func TestIdempotencyReleaseAllowsReclaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-release", "hash-1")
	claimIdem(ctx, t, s, repo, rec)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Release(ctx, tx, rec.Ref())
	}); err != nil {
		t.Fatalf("release pending claim: %v", err)
	}
	if _, ok := findIdem(ctx, t, s, repo, rec.Ref()); ok {
		t.Fatal("a released claim must no longer be found")
	}

	// The key is free again: a new claim owns it fresh.
	reclaimed, owned := claimIdem(ctx, t, s, repo, idemFixture(org.ID, "usr_principal_a", "key-release", "hash-2"))
	if !owned {
		t.Fatal("a released key must be reclaimable")
	}
	if reclaimed.RequestHash != "hash-2" {
		t.Errorf("reclaimed request hash = %q, want %q", reclaimed.RequestHash, "hash-2")
	}
}

func TestIdempotencyCompleteRejectsNonPendingClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	rec := idemFixture(org.ID, "usr_principal_a", "key-double-complete", "hash-1")
	claimIdem(ctx, t, s, repo, rec)
	completeIdem(ctx, t, s, repo, rec.Ref(), 200, []byte(`{"ok":true}`))

	// Completing an already-completed claim matches no pending row and is a
	// typed conflict, never a silent no-op.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := repo.Complete(ctx, tx, rec.Ref(), 200, []byte(`{"ok":true}`), time.Time{})
		return e
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestIdempotencyTenantIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	// The same principal id string and the same key in two organizations are
	// two independent claims.
	recA := idemFixture(orgA.ID, "usr_shared", "shared-key", "hash-a")
	recB := idemFixture(orgB.ID, "usr_shared", "shared-key", "hash-b")
	if _, owned := claimIdem(ctx, t, s, repo, recA); !owned {
		t.Fatal("org A claim must be owned")
	}
	if _, owned := claimIdem(ctx, t, s, repo, recB); !owned {
		t.Fatal("org B claim of the same key must be independent and owned")
	}

	// A lookup scoped to org A never observes org B's claim.
	crossRef := store.IdempotencyKeyRef{OrganizationID: orgA.ID, PrincipalID: "usr_shared", Key: "shared-key"}
	got, ok := findIdem(ctx, t, s, repo, crossRef)
	if !ok || got.RequestHash != "hash-a" {
		t.Errorf("org A lookup = %+v ok=%v, want org A's own claim", got, ok)
	}
	// A ref naming org B's id but org A's tenant context cannot exist; a ref
	// with a foreign org id simply matches nothing.
	if _, ok := findIdem(ctx, t, s, repo, store.IdempotencyKeyRef{OrganizationID: "org_does_not_exist", PrincipalID: "usr_shared", Key: "shared-key"}); ok {
		t.Error("a lookup under an unknown organization must match nothing")
	}
}

func TestIdempotencyCrossPrincipalIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	// Two principals in the same organization may independently use the same
	// key string without colliding.
	recA := idemFixture(org.ID, "usr_principal_a", "same-key", "hash-a")
	recB := idemFixture(org.ID, "usr_principal_b", "same-key", "hash-b")
	if _, owned := claimIdem(ctx, t, s, repo, recA); !owned {
		t.Fatal("principal A claim must be owned")
	}
	if _, owned := claimIdem(ctx, t, s, repo, recB); !owned {
		t.Fatal("principal B claim of the same key must be independent and owned")
	}

	a, okA := findIdem(ctx, t, s, repo, recA.Ref())
	b, okB := findIdem(ctx, t, s, repo, recB.Ref())
	if !okA || !okB || a.RequestHash != "hash-a" || b.RequestHash != "hash-b" {
		t.Errorf("per-principal claims not isolated: a=%+v b=%+v", a, b)
	}
}

func TestIdempotencyClaimValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	t.Run("nil transaction is internal", func(t *testing.T) {
		_, _, err := repo.Claim(ctx, nil, idemFixture(org.ID, "usr_a", "k", "h"))
		wantErrCode(t, err, yerr.CodeInternal)
	})

	t.Run("missing required fields are invalid input", func(t *testing.T) {
		err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, _, e := repo.Claim(ctx, tx, store.IdempotencyRecord{OrganizationID: org.ID})
			return e
		})
		wantErrCode(t, err, yerr.CodeValidation)
	})

	t.Run("complete with a nil transaction is internal", func(t *testing.T) {
		_, err := repo.Complete(ctx, nil, store.IdempotencyKeyRef{}, 200, nil, time.Time{})
		wantErrCode(t, err, yerr.CodeInternal)
	})

	t.Run("complete with an out-of-range status is internal", func(t *testing.T) {
		err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, e := repo.Complete(ctx, tx, store.IdempotencyKeyRef{
				OrganizationID: org.ID, PrincipalID: "usr_a", Key: "k",
			}, 7, nil, time.Time{})
			return e
		})
		wantErrCode(t, err, yerr.CodeInternal)
	})
}

func TestIdempotencyFindMissingKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db, f := newIdempotencyStore(ctx, t)
	org := seedOrg(t, db, f, "Acme")

	if _, ok := findIdem(ctx, t, s, repo, store.IdempotencyKeyRef{
		OrganizationID: org.ID, PrincipalID: "usr_a", Key: "never-claimed",
	}); ok {
		t.Error("Find of a never-claimed key must report not found")
	}
}
