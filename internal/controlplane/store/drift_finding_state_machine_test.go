package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestDriftFindingStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.DriftFindingStatus][]store.DriftFindingStatus{
		store.DriftFindingStatusOpen: {
			store.DriftFindingStatusResolved,
		},
		store.DriftFindingStatusResolved: {},
	}

	all := []store.DriftFindingStatus{
		store.DriftFindingStatusOpen,
		store.DriftFindingStatusResolved,
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
	if store.DriftFindingStatus("bogus").CanTransitionTo(store.DriftFindingStatusResolved) {
		t.Error("DriftFindingStatus(\"bogus\").CanTransitionTo(resolved) = true, want false")
	}
}

func TestDriftFindingRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	findings := store.NewDriftFindingRepository()
	events := store.NewDriftFindingEventRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")
	created := seedDriftFinding(ctx, t, s, findings, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))

	resolvedAt := time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Minute)
	var transitioned store.DriftFinding
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := findings.Transition(ctx, tx, store.DriftFindingTransition{
			OrganizationID: org.ID,
			FindingID:      created.ID,
			NextStatus:     store.DriftFindingStatusResolved,
			ActorID:        "usr_drift_actor",
			ActorKind:      "user",
			RequestID:      "req_drift_transition",
			CorrelationID:  "corr_drift_transition",
			Reason:         "manual acknowledgement password=secret",
			ResolvedAt:     resolvedAt,
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(open->resolved): %v", err)
	}

	if transitioned.Status != store.DriftFindingStatusResolved {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.DriftFindingStatusResolved)
	}
	if transitioned.ResolvedAt == nil || !transitioned.ResolvedAt.Equal(resolvedAt) {
		t.Fatalf("transitioned.ResolvedAt = %v, want %s", transitioned.ResolvedAt, resolvedAt)
	}
	if transitioned.ResolvedByActorID != "usr_drift_actor" {
		t.Fatalf("transitioned.ResolvedByActorID = %q, want usr_drift_actor", transitioned.ResolvedByActorID)
	}

	var timeline []store.DriftFindingEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByFinding(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByFinding: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.DriftFindingEventTypeResolved {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.DriftFindingEventTypeResolved)
	}
	if event.RequestID != "req_drift_transition" || event.CorrelationID != "corr_drift_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_drift_transition, corr_drift_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_drift_actor",
		"actor_kind":     "user",
		"previous_state": "open",
		"next_state":     "resolved",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
	testutil.AssertRedactedValue(t, event.Message, "secret")
	testutil.AssertRedactedValue(t, event.Metadata["reason"], "secret")
}

func TestDriftFindingRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	findings := store.NewDriftFindingRepository()
	events := store.NewDriftFindingEventRepository()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")
	created := seedDriftFinding(ctx, t, s, findings, driftFindingFixture(org, svc, time.Now().UTC().Truncate(time.Microsecond)))
	baseline := loadDriftFindingRowByID(ctx, t, db, created.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := findings.Transition(ctx, tx, store.DriftFindingTransition{
			OrganizationID: org.ID,
			FindingID:      created.ID,
			NextStatus:     store.DriftFindingStatusOpen,
			ActorID:        "usr_drift_actor",
			ActorKind:      "user",
			RequestID:      "req_invalid_drift_transition",
			CorrelationID:  "corr_invalid_drift_transition",
			Reason:         "cannot transition open to open",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(open->open) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(open->open) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	after := loadDriftFindingRowByID(ctx, t, db, created.ID)
	assertDriftFindingByteIdentical(t, "invalid transition leaves finding unchanged", baseline, after)

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByFinding(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByFinding after invalid transition: %v", err)
	}
}
