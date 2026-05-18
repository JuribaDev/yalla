package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestProjectStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.ProjectStatus][]store.ProjectStatus{
		store.ProjectStatusPending: {
			store.ProjectStatusActive,
			store.ProjectStatusDeleting,
		},
		store.ProjectStatusActive: {
			store.ProjectStatusSuspended,
			store.ProjectStatusDeleting,
		},
		store.ProjectStatusSuspended: {
			store.ProjectStatusActive,
			store.ProjectStatusDeleting,
		},
		store.ProjectStatusDeleting: {
			store.ProjectStatusActive,
			store.ProjectStatusDeleted,
		},
		store.ProjectStatusDeleted: {},
	}

	all := []store.ProjectStatus{
		store.ProjectStatusPending,
		store.ProjectStatusActive,
		store.ProjectStatusSuspended,
		store.ProjectStatusDeleting,
		store.ProjectStatusDeleted,
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
	if store.ProjectStatus("bogus").CanTransitionTo(store.ProjectStatusActive) {
		t.Error("ProjectStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestProjectRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projects := store.NewProjectRepository()
	events := store.NewProjectEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	fixture := seedProject(t, db, f, org, "api")
	created := getProjectOrFail(ctx, t, s, projects, org.ID, fixture.ID, "created")

	var transitioned store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := projects.Transition(ctx, tx, store.ProjectTransition{
			OrganizationID: org.ID,
			ProjectID:      created.ID,
			NextStatus:     store.ProjectStatusSuspended,
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

	if transitioned.Status != store.ProjectStatusSuspended {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.ProjectStatusSuspended)
	}
	if transitioned.Version != created.Version+1 {
		t.Fatalf("transitioned.Version = %d, want %d", transitioned.Version, created.Version+1)
	}

	var timeline []store.ProjectEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByProject(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.ProjectEventTypeSuspended {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.ProjectEventTypeSuspended)
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

func TestProjectRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projects := store.NewProjectRepository()
	events := store.NewProjectEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	fixture := seedProject(t, db, f, org, "api")
	created := getProjectOrFail(ctx, t, s, projects, org.ID, fixture.ID, "created")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := projects.Transition(ctx, tx, store.ProjectTransition{
			OrganizationID: org.ID,
			ProjectID:      created.ID,
			NextStatus:     store.ProjectStatusDeleted,
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

	after := getProjectOrFail(ctx, t, s, projects, org.ID, created.ID, "after invalid transition")
	if after.Status != store.ProjectStatusActive {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.ProjectStatusActive)
	}
	if after.Version != created.Version {
		t.Fatalf("after.Version = %d, want unchanged %d", after.Version, created.Version)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByProject(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByProject after invalid transition: %v", err)
	}
}

func TestProjectRepositoryTransitionNotFoundIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projects := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	orgB := seedOrg(t, db, f, "globex")
	projectB := seedProject(t, db, f, orgB, "api")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := projects.Transition(ctx, tx, store.ProjectTransition{
			OrganizationID: orgA.ID,
			ProjectID:      projectB.ID,
			NextStatus:     store.ProjectStatusSuspended,
			RequestID:      "req_cross_tenant",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(cross-tenant project) error = nil, want not found")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Transition(cross-tenant project) error = %v, want %s", err, yerr.CodeNotFound)
	}
}
