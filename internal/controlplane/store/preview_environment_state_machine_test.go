package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestPreviewEnvironmentStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.PreviewEnvironmentStatus][]store.PreviewEnvironmentStatus{
		store.PreviewEnvironmentStatusPending: {
			store.PreviewEnvironmentStatusProvisioning,
			store.PreviewEnvironmentStatusDeleting,
			store.PreviewEnvironmentStatusFailed,
		},
		store.PreviewEnvironmentStatusProvisioning: {
			store.PreviewEnvironmentStatusReady,
			store.PreviewEnvironmentStatusDeleting,
			store.PreviewEnvironmentStatusFailed,
		},
		store.PreviewEnvironmentStatusReady: {
			store.PreviewEnvironmentStatusDeleting,
			store.PreviewEnvironmentStatusFailed,
		},
		store.PreviewEnvironmentStatusDeleting: {
			store.PreviewEnvironmentStatusDeleted,
			store.PreviewEnvironmentStatusFailed,
		},
		store.PreviewEnvironmentStatusFailed: {
			store.PreviewEnvironmentStatusProvisioning,
			store.PreviewEnvironmentStatusDeleting,
		},
		store.PreviewEnvironmentStatusDeleted: {},
	}

	all := []store.PreviewEnvironmentStatus{
		store.PreviewEnvironmentStatusPending,
		store.PreviewEnvironmentStatusProvisioning,
		store.PreviewEnvironmentStatusReady,
		store.PreviewEnvironmentStatusDeleting,
		store.PreviewEnvironmentStatusDeleted,
		store.PreviewEnvironmentStatusFailed,
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
	if store.PreviewEnvironmentStatus("bogus").CanTransitionTo(store.PreviewEnvironmentStatusReady) {
		t.Error("PreviewEnvironmentStatus(\"bogus\").CanTransitionTo(ready) = true, want false")
	}
}

func TestPreviewEnvironmentRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	previews := store.NewPreviewEnvironmentRepository()
	events := store.NewPreviewEnvironmentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-transition")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	previewEnv := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	created := insertPreviewEnvironment(ctx, t, s, previews, previewEnvironmentFixture(org.ID, proj.ID, previewEnv.ID, source.ID, "Preview 42"))

	var transitioned store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := previews.Transition(ctx, tx, store.PreviewEnvironmentTransition{
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			PreviewID:      created.ID,
			NextStatus:     store.PreviewEnvironmentStatusProvisioning,
			ActorID:        "usr_preview_actor",
			ActorKind:      "user",
			RequestID:      "req_preview_transition",
			CorrelationID:  "corr_preview_transition",
			Reason:         "start provisioning token=secret",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(pending->provisioning): %v", err)
	}

	if transitioned.Status != store.PreviewEnvironmentStatusProvisioning {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.PreviewEnvironmentStatusProvisioning)
	}
	if transitioned.Version != created.Version+1 {
		t.Fatalf("transitioned.Version = %d, want %d", transitioned.Version, created.Version+1)
	}

	var timeline []store.PreviewEnvironmentEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByPreviewEnvironment(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByPreviewEnvironment: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.PreviewEnvironmentEventTypeProvisioning {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.PreviewEnvironmentEventTypeProvisioning)
	}
	if event.RequestID != "req_preview_transition" || event.CorrelationID != "corr_preview_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_preview_transition, corr_preview_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_preview_actor",
		"actor_kind":     "user",
		"previous_state": "pending",
		"next_state":     "provisioning",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
	testutil.AssertRedactedValue(t, event.Message, "secret")
	testutil.AssertRedactedValue(t, event.Metadata["reason"], "secret")
}

func TestPreviewEnvironmentRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	previews := store.NewPreviewEnvironmentRepository()
	events := store.NewPreviewEnvironmentEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-invalid")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	previewEnv := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	created := insertPreviewEnvironment(ctx, t, s, previews, previewEnvironmentFixture(org.ID, proj.ID, previewEnv.ID, source.ID, "Preview 42"))

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := previews.Transition(ctx, tx, store.PreviewEnvironmentTransition{
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			PreviewID:      created.ID,
			NextStatus:     store.PreviewEnvironmentStatusDeleted,
			ActorID:        "usr_preview_actor",
			ActorKind:      "user",
			RequestID:      "req_invalid_preview_transition",
			CorrelationID:  "corr_invalid_preview_transition",
			Reason:         "cannot delete pending directly",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(pending->deleted) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(pending->deleted) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	after := getPreviewEnvironment(ctx, t, s, previews, org.ID, proj.ID, created.ID)
	if after.Status != store.PreviewEnvironmentStatusPending {
		t.Fatalf("after.Status = %q, want %q", after.Status, store.PreviewEnvironmentStatusPending)
	}
	if after.Version != created.Version {
		t.Fatalf("after.Version = %d, want unchanged %d", after.Version, created.Version)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByPreviewEnvironment(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByPreviewEnvironment after invalid transition: %v", err)
	}
}

func TestPreviewEnvironmentRepositoryTransitionCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	previews := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "preview-alpha")
	projA := seedProject(t, db, f, orgA, "web")
	sourceA := seedEnvironment(t, db, f, projA, "staging")
	previewEnvA := seedEnvironmentWithKind(t, db, f, projA, "preview", store.EnvironmentKindPreview)
	createdA := insertPreviewEnvironment(ctx, t, s, previews, previewEnvironmentFixture(orgA.ID, projA.ID, previewEnvA.ID, sourceA.ID, "Preview A"))

	orgB := seedOrg(t, db, f, "preview-beta")
	projB := seedProject(t, db, f, orgB, "web")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := previews.Transition(ctx, tx, store.PreviewEnvironmentTransition{
			OrganizationID: orgB.ID,
			ProjectID:      projB.ID,
			PreviewID:      createdA.ID,
			NextStatus:     store.PreviewEnvironmentStatusDeleting,
			ActorID:        domain.MustNewID(domain.KindUser).String(),
			ActorKind:      "user",
			RequestID:      "req_cross_preview_transition",
			Reason:         "cross tenant probe",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(cross-tenant preview) error = nil, want not found")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Transition(cross-tenant preview) error = %v, want %s", err, yerr.CodeNotFound)
	}

	after := getPreviewEnvironment(ctx, t, s, previews, orgA.ID, projA.ID, createdA.ID)
	if after.Status != store.PreviewEnvironmentStatusPending || after.Version != createdA.Version {
		t.Fatalf("cross-tenant transition mutated orgA row: after=%+v before=%+v", after, createdA)
	}
}
