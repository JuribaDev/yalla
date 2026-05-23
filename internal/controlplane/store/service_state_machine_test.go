package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestServiceStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.ServiceStatus][]store.ServiceStatus{
		store.ServiceStatusPending: {
			store.ServiceStatusActive,
			store.ServiceStatusDeleting,
		},
		store.ServiceStatusActive: {
			store.ServiceStatusSuspended,
			store.ServiceStatusDeleting,
		},
		store.ServiceStatusSuspended: {
			store.ServiceStatusActive,
			store.ServiceStatusDeleting,
		},
		store.ServiceStatusDeleting: {
			store.ServiceStatusActive,
			store.ServiceStatusDeleted,
		},
		store.ServiceStatusDeleted: {},
	}

	all := []store.ServiceStatus{
		store.ServiceStatusPending,
		store.ServiceStatusActive,
		store.ServiceStatusSuspended,
		store.ServiceStatusDeleting,
		store.ServiceStatusDeleted,
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
	if store.ServiceStatus("bogus").CanTransitionTo(store.ServiceStatusActive) {
		t.Error("ServiceStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestServiceRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	services := store.NewServiceRepository()
	events := store.NewServiceEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	fixture := seedService(t, db, f, env, "web")
	created := getServiceOrFail(ctx, t, s, services, org.ID, fixture.ID, "created")

	var transitioned store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := services.Transition(ctx, tx, store.ServiceTransition{
			OrganizationID: org.ID,
			ServiceID:      created.ID,
			NextStatus:     store.ServiceStatusSuspended,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_transition",
			CorrelationID:  "corr_transition",
			Reason:         "maintenance window",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(active->suspended): %v", err)
	}

	if transitioned.Status != store.ServiceStatusSuspended {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.ServiceStatusSuspended)
	}
	if transitioned.Version != created.Version+1 {
		t.Fatalf("transitioned.Version = %d, want %d", transitioned.Version, created.Version+1)
	}

	var timeline []store.ServiceEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByService(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByService: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.ServiceEventTypeSuspended {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.ServiceEventTypeSuspended)
	}
	if event.RequestID != "req_transition" || event.CorrelationID != "corr_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_transition, corr_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_transition_actor",
		"actor_kind":     "user",
		"previous_state": "active",
		"next_state":     "suspended",
		"reason":         "maintenance window",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestServiceRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	services := store.NewServiceRepository()
	events := store.NewServiceEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	fixture := seedService(t, db, f, env, "web")
	created := getServiceOrFail(ctx, t, s, services, org.ID, fixture.ID, "created")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := services.Transition(ctx, tx, store.ServiceTransition{
			OrganizationID: org.ID,
			ServiceID:      created.ID,
			NextStatus:     store.ServiceStatusDeleted,
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

	after := getServiceOrFail(ctx, t, s, services, org.ID, created.ID, "after invalid transition")
	if after.Status != store.ServiceStatusActive {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.ServiceStatusActive)
	}
	if after.Version != created.Version {
		t.Fatalf("after.Version = %d, want unchanged %d", after.Version, created.Version)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByService(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByService after invalid transition: %v", err)
	}
}
