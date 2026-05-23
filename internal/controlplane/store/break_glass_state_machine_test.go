package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestBreakGlassSessionStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.BreakGlassSessionStatus][]store.BreakGlassSessionStatus{
		store.BreakGlassSessionStatusActive: {
			store.BreakGlassSessionStatusRevoked,
			store.BreakGlassSessionStatusExpired,
		},
		store.BreakGlassSessionStatusRevoked: {},
		store.BreakGlassSessionStatusExpired: {},
	}

	all := []store.BreakGlassSessionStatus{
		store.BreakGlassSessionStatusActive,
		store.BreakGlassSessionStatusRevoked,
		store.BreakGlassSessionStatusExpired,
	}
	for _, from := range all {
		for _, to := range all {
			want := false
			for _, candidate := range allowed[from] {
				if candidate == to {
					want = true
					break
				}
			}
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s.CanTransitionTo(%s) = %v, want %v", from, to, got, want)
			}
		}
	}
	if store.BreakGlassSessionStatus("bogus").CanTransitionTo(store.BreakGlassSessionStatusActive) {
		t.Error("BreakGlassSessionStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestBreakGlassRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	st := newStore(t, db)
	sessions := store.NewBreakGlassRepository()
	events := store.NewBreakGlassSessionEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actorOrg := twoOrgs(t, db, f, "break-glass-transition")
	started := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	created := seedBreakGlassSession(ctx, t, st, sessions, breakGlassSessionFixture(target, actorOrg, "transition", started, time.Hour))

	var transitioned store.BreakGlassSession
	if err := st.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := sessions.Transition(ctx, tx, store.BreakGlassSessionTransition{
			OrganizationID: target.ID,
			SessionID:      created.ID,
			NextStatus:     store.BreakGlassSessionStatusRevoked,
			ActorID:        "usr_transition_actor",
			ActorKind:      "usr",
			RequestID:      "req_transition",
			CorrelationID:  "corr_transition",
			Reason:         "operator ended early token=secret",
			Now:            started.Add(10 * time.Minute),
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(active->revoked): %v", err)
	}

	if transitioned.Status != store.BreakGlassSessionStatusRevoked {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.BreakGlassSessionStatusRevoked)
	}
	if transitioned.RevokedAt == nil {
		t.Fatal("transitioned.RevokedAt = nil, want revoke timestamp for revoked lifecycle state")
	}

	var timeline []store.BreakGlassSessionEvent
	if err := st.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListBySession(ctx, q, target.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListBySession: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.BreakGlassSessionEventTypeRevoked {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.BreakGlassSessionEventTypeRevoked)
	}
	if event.RequestID != "req_transition" || event.CorrelationID != "corr_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_transition, corr_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_transition_actor",
		"actor_kind":     "usr",
		"previous_state": "active",
		"next_state":     "revoked",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
	testutil.AssertRedactedValue(t, event.Message, "secret")
	testutil.AssertRedactedValue(t, event.Metadata["reason"], "secret")
}

func TestBreakGlassRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	st := newStore(t, db)
	sessions := store.NewBreakGlassRepository()
	events := store.NewBreakGlassSessionEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target, actorOrg := twoOrgs(t, db, f, "break-glass-invalid-transition")
	started := time.Date(2026, 5, 18, 13, 0, 0, 0, time.UTC)
	created := seedBreakGlassSession(ctx, t, st, sessions, breakGlassSessionFixture(target, actorOrg, "invalid_transition", started, time.Hour))

	err := st.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := sessions.Transition(ctx, tx, store.BreakGlassSessionTransition{
			OrganizationID: target.ID,
			SessionID:      created.ID,
			NextStatus:     store.BreakGlassSessionStatusActive,
			ActorID:        "usr_transition_actor",
			ActorKind:      "usr",
			RequestID:      "req_invalid_transition",
			CorrelationID:  "corr_invalid_transition",
			Reason:         "already active",
			Now:            started.Add(10 * time.Minute),
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(active->active) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(active->active) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	var after store.BreakGlassSession
	if err := st.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		after, err = sessions.Get(ctx, q, target.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("Get after invalid transition: %v", err)
	}
	if after.Status != store.BreakGlassSessionStatusActive {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.BreakGlassSessionStatusActive)
	}
	if after.RevokedAt != nil {
		t.Fatalf("after.RevokedAt = %v, want nil", after.RevokedAt)
	}

	if err := st.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListBySession(ctx, q, target.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListBySession after invalid transition: %v", err)
	}
}
