package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestJobRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobs := store.NewJobRepository()
	events := store.NewJobEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, jobs, jobFixture(org.ID, "idem-job-transition-event"))

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Transition(ctx, tx, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
			LeaseOwner:    "worker-transition-1",
			LeaseDuration: 30 * time.Second,
			ActorID:       "worker-transition-1",
			ActorKind:     "worker",
			RequestID:     "req-transition-event",
			CorrelationID: "corr-transition-event",
			Reason:        "worker claimed job",
		})
		return err
	}); err != nil {
		t.Fatalf("Transition(queued->running): %v", err)
	}

	var timeline []store.JobEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByJob(ctx, q, org.ID, job.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByJob: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.JobEventTypeRunning {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.JobEventTypeRunning)
	}
	if event.RequestID != "req-transition-event" || event.CorrelationID != "corr-transition-event" {
		t.Errorf("event correlation = (%q, %q), want (req-transition-event, corr-transition-event)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "worker-transition-1",
		"actor_kind":     "worker",
		"previous_state": "queued",
		"next_state":     "running",
		"reason":         "worker claimed job",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestJobRepositoryTransitionRejectsInvalidWithStateCodeAndNoEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobs := store.NewJobRepository()
	events := store.NewJobEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, jobs, jobFixture(org.ID, "idem-job-invalid-state"))

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, tErr := jobs.Transition(ctx, tx, org.ID, job.ID, store.JobStatusSucceeded, store.JobTransition{
			ActorID:       "worker-transition-1",
			ActorKind:     "worker",
			RequestID:     "req-invalid-state",
			CorrelationID: "corr-invalid-state",
			Reason:        "cannot skip running",
		})
		return tErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(queued->succeeded) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, gErr := jobs.Get(ctx, q, org.ID, job.ID)
		if gErr != nil {
			return gErr
		}
		if got.Status != store.JobStatusQueued {
			t.Errorf("job status after denied transition = %q, want queued", got.Status)
		}
		timeline, lErr := events.ListByJob(ctx, q, org.ID, job.ID)
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
