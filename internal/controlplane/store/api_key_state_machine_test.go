package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestAPIKeyStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.APIKeyStatus][]store.APIKeyStatus{
		store.APIKeyStatusActive: {
			store.APIKeyStatusRevoked,
			store.APIKeyStatusExpired,
		},
		store.APIKeyStatusRevoked: {},
		store.APIKeyStatusExpired: {},
	}

	all := []store.APIKeyStatus{
		store.APIKeyStatusActive,
		store.APIKeyStatusRevoked,
		store.APIKeyStatusExpired,
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
	if store.APIKeyStatus("bogus").CanTransitionTo(store.APIKeyStatusActive) {
		t.Error("APIKeyStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestAPIKeyRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	keys := store.NewAPIKeyRepository()
	events := store.NewAPIKeyEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	fixture, _ := newAPIKey(t, f, org.ID, createdBy)
	created := insertAPIKey(ctx, t, s, keys, fixture)

	var transitioned store.APIKey
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := keys.Transition(ctx, tx, store.APIKeyTransition{
			OrganizationID: org.ID,
			KeyID:          created.ID,
			NextStatus:     store.APIKeyStatusRevoked,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_transition",
			CorrelationID:  "corr_transition",
			Reason:         "rotation complete password=secret",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(active->revoked): %v", err)
	}

	if transitioned.Status != store.APIKeyStatusRevoked {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.APIKeyStatusRevoked)
	}
	if transitioned.RevokedAt == nil {
		t.Fatal("transitioned.RevokedAt = nil, want revoke timestamp for revoked lifecycle state")
	}

	var timeline []store.APIKeyEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByAPIKey(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByAPIKey: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.APIKeyEventTypeRevoked {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.APIKeyEventTypeRevoked)
	}
	if event.RequestID != "req_transition" || event.CorrelationID != "corr_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_transition, corr_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_transition_actor",
		"actor_kind":     "user",
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

func TestAPIKeyRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	keys := store.NewAPIKeyRepository()
	events := store.NewAPIKeyEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	fixture, _ := newAPIKey(t, f, org.ID, createdBy)
	created := insertAPIKey(ctx, t, s, keys, fixture)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := keys.Transition(ctx, tx, store.APIKeyTransition{
			OrganizationID: org.ID,
			KeyID:          created.ID,
			NextStatus:     store.APIKeyStatusActive,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_invalid_transition",
			CorrelationID:  "corr_invalid_transition",
			Reason:         "already active",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(active->active) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(active->active) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	after := getAPIKeyOrFail(ctx, t, s, keys, org.ID, created.ID, "after invalid transition")
	if after.Status != store.APIKeyStatusActive {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.APIKeyStatusActive)
	}
	if after.RevokedAt != nil {
		t.Fatalf("after.RevokedAt = %v, want nil", after.RevokedAt)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByAPIKey(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByAPIKey after invalid transition: %v", err)
	}
}
