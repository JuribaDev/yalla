package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestDeploymentStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.DeploymentStatus][]store.DeploymentStatus{
		store.DeploymentStatusQueued: {
			store.DeploymentStatusRunning,
			store.DeploymentStatusCancelled,
		},
		store.DeploymentStatusRunning: {
			store.DeploymentStatusSucceeded,
			store.DeploymentStatusFailed,
			store.DeploymentStatusCancelled,
			store.DeploymentStatusRolledBack,
		},
		store.DeploymentStatusSucceeded:  {},
		store.DeploymentStatusFailed:     {},
		store.DeploymentStatusCancelled:  {},
		store.DeploymentStatusRolledBack: {},
	}

	for from, next := range allowed {
		for _, to := range next {
			if !from.CanTransitionTo(to) {
				t.Errorf("%s.CanTransitionTo(%s) = false, want true", from, to)
			}
		}
	}

	all := []store.DeploymentStatus{
		store.DeploymentStatusQueued,
		store.DeploymentStatusRunning,
		store.DeploymentStatusSucceeded,
		store.DeploymentStatusFailed,
		store.DeploymentStatusCancelled,
		store.DeploymentStatusRolledBack,
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
}

func TestDeploymentRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	deployments := store.NewDeploymentRepository()
	events := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, deployments, org, proj, env, svc, "transition_event")

	var transitioned store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := deployments.Transition(ctx, tx, store.DeploymentTransition{
			OrganizationID: org.ID,
			DeploymentID:   created.ID,
			NextStatus:     store.DeploymentStatusRunning,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_transition",
			CorrelationID:  "corr_transition",
			Reason:         "worker accepted deployment",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(queued->running): %v", err)
	}

	if transitioned.Status != store.DeploymentStatusRunning {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.DeploymentStatusRunning)
	}
	if transitioned.StartedAt == nil {
		t.Fatal("transitioned.StartedAt = nil, want timestamp for running transition")
	}

	var timeline []store.DeploymentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByDeployment(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByDeployment: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.DeploymentEventTypeRunning {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.DeploymentEventTypeRunning)
	}
	if event.RequestID != "req_transition" || event.CorrelationID != "corr_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_transition, corr_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_transition_actor",
		"actor_kind":     "user",
		"previous_state": "queued",
		"next_state":     "running",
		"reason":         "worker accepted deployment",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestDeploymentRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	deployments := store.NewDeploymentRepository()
	events := store.NewDeploymentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, deployments, org, proj, env, svc, "invalid_transition")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := deployments.Transition(ctx, tx, store.DeploymentTransition{
			OrganizationID: org.ID,
			DeploymentID:   created.ID,
			NextStatus:     store.DeploymentStatusSucceeded,
			ActorID:        "usr_transition_actor",
			ActorKind:      "user",
			RequestID:      "req_invalid_transition",
			CorrelationID:  "corr_invalid_transition",
			Reason:         "cannot skip running",
		})
		return tErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(queued->succeeded) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, gErr := deployments.GetByID(ctx, q, org.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		if got.Status != store.DeploymentStatusQueued {
			t.Errorf("deployment status after denied transition = %q, want queued", got.Status)
		}
		timeline, lErr := events.ListByDeployment(ctx, q, org.ID, created.ID)
		if lErr != nil {
			return lErr
		}
		if len(timeline) != 0 {
			t.Errorf("timeline len after denied transition = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("post-denial read: %v", err)
	}
}
