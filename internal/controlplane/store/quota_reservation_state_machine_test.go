package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestQuotaReservationStatusTransitionTable(t *testing.T) {
	t.Parallel()

	allowed := map[store.ReservationStatus][]store.ReservationStatus{
		store.ReservationStatusActive: {
			store.ReservationStatusCommitted,
			store.ReservationStatusReleased,
			store.ReservationStatusExpired,
		},
		store.ReservationStatusCommitted: {},
		store.ReservationStatusReleased:  {},
		store.ReservationStatusExpired:   {},
	}

	all := []store.ReservationStatus{
		store.ReservationStatusActive,
		store.ReservationStatusCommitted,
		store.ReservationStatusReleased,
		store.ReservationStatusExpired,
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
	if store.ReservationStatus("bogus").CanTransitionTo(store.ReservationStatusActive) {
		t.Error("ReservationStatus(\"bogus\").CanTransitionTo(active) = true, want false")
	}
}

func TestQuotaRepositoryTransitionAllowsEveryTerminalState(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	targets := []store.ReservationStatus{
		store.ReservationStatusCommitted,
		store.ReservationStatusReleased,
		store.ReservationStatusExpired,
	}
	for _, target := range targets {
		target := target
		t.Run(target.String(), func(t *testing.T) {
			var created store.QuotaReservation
			if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				var err error
				created, err = repo.InsertReservation(ctx, tx, store.QuotaReservation{
					OrganizationID: org.ID,
					Resource:       store.QuotaResourceServices,
					Amount:         1,
					ExpiresAt:      time.Now().UTC().Add(time.Hour),
				})
				return err
			}); err != nil {
				t.Fatalf("InsertReservation: %v", err)
			}

			var transitioned store.QuotaReservation
			if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				var err error
				transitioned, _, err = repo.Transition(ctx, tx, store.QuotaReservationTransition{
					OrganizationID: org.ID,
					ReservationID:  created.ID,
					NextStatus:     target,
					RequestID:      "req_quota_terminal",
				})
				return err
			}); err != nil {
				t.Fatalf("Transition(active->%s): %v", target, err)
			}
			if store.ReservationStatus(transitioned.Status) != target {
				t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, target)
			}
			if transitioned.SettledAt.IsZero() {
				t.Fatalf("transitioned.SettledAt is zero; terminal reservations must be settled")
			}
		})
	}
}

func TestQuotaRepositoryTransitionRecordsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	events := store.NewQuotaReservationEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	var created store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		created, err = repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceProjects,
			Amount:         2,
			RequestID:      "req_original_reservation",
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
		return err
	}); err != nil {
		t.Fatalf("InsertReservation: %v", err)
	}

	var transitioned store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		next, _, err := repo.Transition(ctx, tx, store.QuotaReservationTransition{
			OrganizationID: org.ID,
			ReservationID:  created.ID,
			NextStatus:     store.ReservationStatusCommitted,
			ActorID:        "usr_quota_actor",
			ActorKind:      "user",
			RequestID:      "req_quota_transition",
			CorrelationID:  "corr_quota_transition",
			Reason:         "provisioned with token=secret",
		})
		transitioned = next
		return err
	}); err != nil {
		t.Fatalf("Transition(active->committed): %v", err)
	}
	if transitioned.Status != store.ReservationStatusCommitted {
		t.Fatalf("transitioned.Status = %q, want %q", transitioned.Status, store.ReservationStatusCommitted)
	}
	if transitioned.RequestID != "req_original_reservation" {
		t.Fatalf("transitioned.RequestID = %q, want original reservation request id", transitioned.RequestID)
	}

	var timeline []store.QuotaReservationEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		timeline, err = events.ListByReservation(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByReservation: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(timeline))
	}
	event := timeline[0]
	if event.EventType != store.QuotaReservationEventTypeCommitted {
		t.Errorf("event.EventType = %q, want %q", event.EventType, store.QuotaReservationEventTypeCommitted)
	}
	if event.RequestID != "req_quota_transition" || event.CorrelationID != "corr_quota_transition" {
		t.Errorf("event correlation = (%q, %q), want (req_quota_transition, corr_quota_transition)", event.RequestID, event.CorrelationID)
	}
	for key, want := range map[string]string{
		"actor_id":       "usr_quota_actor",
		"actor_kind":     "user",
		"previous_state": "active",
		"next_state":     "committed",
	} {
		if got := event.Metadata[key]; got != want {
			t.Errorf("event.Metadata[%q] = %q, want %q", key, got, want)
		}
	}
	testutil.AssertRedactedValue(t, event.Message, "secret")
	testutil.AssertRedactedValue(t, event.Metadata["reason"], "secret")
}

func TestQuotaRepositoryTransitionRejectsInvalidWithoutMutation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	events := store.NewQuotaReservationEventRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	var created store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		created, err = repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: org.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
		return err
	}); err != nil {
		t.Fatalf("InsertReservation: %v", err)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := repo.Transition(ctx, tx, store.QuotaReservationTransition{
			OrganizationID: org.ID,
			ReservationID:  created.ID,
			NextStatus:     store.ReservationStatusActive,
			RequestID:      "req_invalid_quota_transition",
			Reason:         "cannot remain active",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(active->active) error = nil, want invalid state transition")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidStateTransition {
		t.Fatalf("Transition(active->active) error = %v, want %s", err, yerr.CodeInvalidStateTransition)
	}

	row := loadQuotaReservationStatus(t, db, org.ID, created.ID)
	if row.status != store.ReservationStatusActive {
		t.Fatalf("reservation status = %q, want %q", row.status, store.ReservationStatusActive)
	}
	if !row.settledAt.IsZero() {
		t.Fatalf("reservation settled_at = %v, want zero", row.settledAt)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		timeline, listErr := events.ListByReservation(ctx, q, org.ID, created.ID)
		if listErr != nil {
			return listErr
		}
		if len(timeline) != 0 {
			t.Fatalf("timeline len = %d, want 0", len(timeline))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListByReservation after invalid transition: %v", err)
	}
}

func TestQuotaRepositoryTransitionNotFoundIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewQuotaRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	orgB := seedOrg(t, db, f, "globex")
	var reservationB store.QuotaReservation
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		reservationB, err = repo.InsertReservation(ctx, tx, store.QuotaReservation{
			OrganizationID: orgB.ID,
			Resource:       store.QuotaResourceServices,
			Amount:         1,
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
		return err
	}); err != nil {
		t.Fatalf("InsertReservation(orgB): %v", err)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, _, tErr := repo.Transition(ctx, tx, store.QuotaReservationTransition{
			OrganizationID: orgA.ID,
			ReservationID:  reservationB.ID,
			NextStatus:     store.ReservationStatusReleased,
			RequestID:      "req_cross_tenant_quota_reservation",
		})
		return tErr
	})
	if err == nil {
		t.Fatal("Transition(cross-tenant reservation) error = nil, want not found")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Transition(cross-tenant reservation) error = %v, want %s", err, yerr.CodeNotFound)
	}
}

type quotaReservationStatusRow struct {
	status    string
	settledAt time.Time
}

func loadQuotaReservationStatus(t *testing.T, db *testutil.DB, organizationID, reservationID string) quotaReservationStatusRow {
	t.Helper()
	var (
		status    string
		settledAt *time.Time
	)
	if err := db.QueryRow(context.Background(),
		`SELECT status, settled_at
		   FROM quota_reservations
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, reservationID).Scan(&status, &settledAt); err != nil {
		t.Fatalf("load quota reservation status: %v", err)
	}
	row := quotaReservationStatusRow{status: status}
	if settledAt != nil {
		row.settledAt = *settledAt
	}
	return row
}
