package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestEnvironmentStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.EnvironmentStatus][]store.EnvironmentStatus{
		store.EnvironmentStatusPending: {
			store.EnvironmentStatusActive,
			store.EnvironmentStatusDeleting,
		},
		store.EnvironmentStatusActive: {
			store.EnvironmentStatusSuspended,
			store.EnvironmentStatusDeleting,
		},
		store.EnvironmentStatusSuspended: {
			store.EnvironmentStatusActive,
			store.EnvironmentStatusDeleting,
		},
		store.EnvironmentStatusDeleting: {
			store.EnvironmentStatusActive,
			store.EnvironmentStatusDeleted,
		},
		store.EnvironmentStatusDeleted: {},
	}

	all := []store.EnvironmentStatus{
		store.EnvironmentStatusPending,
		store.EnvironmentStatusActive,
		store.EnvironmentStatusSuspended,
		store.EnvironmentStatusDeleting,
		store.EnvironmentStatusDeleted,
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
	if store.EnvironmentStatus("bogus").CanTransitionTo(store.EnvironmentStatusActive) {
		t.Error("EnvironmentStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestEnvironmentRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	environments := store.NewEnvironmentRepository()
	events := store.NewEnvironmentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	fixture := seedEnvironment(t, db, f, proj, "prod")
	created := getEnvironmentOrFail(ctx, t, s, environments, org.ID, fixture.ID, "created")

	var transitioned store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := environments.Transition(ctx, tx, store.EnvironmentTransition{
			OrganizationID: org.ID,
			EnvironmentID:  created.ID,
			NextStatus:     store.EnvironmentStatusSuspended,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_transition",
			CorrelationID:  "corr_transition",
			Reason:         "maintenance window password=secret",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(active->suspended): %v", err)
	}

	if transitioned.Status != store.EnvironmentStatusSuspended {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.EnvironmentStatusSuspended)
	}
	if transitioned.Version != created.Version+1 {
		t.Fatalf("transitioned.Version = %d, want %d", transitioned.Version, created.Version+1)
	}

	var timeline []store.EnvironmentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByEnvironment(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.EnvironmentEventTypeSuspended {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.EnvironmentEventTypeSuspended)
	}
	if event.RequestID != "req_transition" || event.CorrelationID != "corr_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_transition, corr_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_transition_actor",
		"actor_kind":     "user",
		"previous_state": "active",
		"next_state":     "suspended",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
	testutil.AssertRedactedValue(t, event.Message, "secret")
	testutil.AssertRedactedValue(t, event.Metadata["reason"], "secret")
}

func TestEnvironmentRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	environments := store.NewEnvironmentRepository()
	events := store.NewEnvironmentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	fixture := seedEnvironment(t, db, f, proj, "prod")
	created := getEnvironmentOrFail(ctx, t, s, environments, org.ID, fixture.ID, "created")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := environments.Transition(ctx, tx, store.EnvironmentTransition{
			OrganizationID: org.ID,
			EnvironmentID:  created.ID,
			NextStatus:     store.EnvironmentStatusDeleted,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_invalid_transition",
			CorrelationID:  "corr_invalid_transition",
			Reason:         "cannot delete active directly",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(active->deleted) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(active->deleted) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	after := getEnvironmentOrFail(ctx, t, s, environments, org.ID, created.ID, "after invalid transition")
	if after.Status != store.EnvironmentStatusActive {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.EnvironmentStatusActive)
	}
	if after.Version != created.Version {
		t.Fatalf("after.Version = %d, want unchanged %d", after.Version, created.Version)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByEnvironment(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByEnvironment after invalid transition: %v", err)
	}
}
