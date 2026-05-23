package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the optimistic-concurrency contract on the
// organizations source-of-truth: two writers reading the same row at version
// N race to update it; the first wins (the row is now at version N+1) and
// the second sees a typed apierr.ConflictStale carrying the row's
// authoritative version, so the loser can rebuild its If-Match header
// without an extra GET. They run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.

// TestOrganizationServiceUpdateRejectsStaleIfMatchVersion proves the second
// of two concurrent updates against the same organization fails with a
// typed E_CONFLICT carrying the row's current version, the row's slug ends
// up at the value the winner wrote, and the row's version has advanced by
// exactly one — the loser's mutation is discarded.
func TestOrganizationServiceUpdateRejectsStaleIfMatchVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	svc := newOrganizationService(t, s)

	org := seedOrg(t, db, f, "acme-co")
	baseline := readOrg(t, s, org.ID)
	if baseline.Version != 1 {
		t.Fatalf("baseline Version = %d, want 1", baseline.Version)
	}

	winnerSlug := "acme-winner"
	winnerVersion := baseline.Version
	winner, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           &winnerSlug,
		IfMatchVersion: &winnerVersion,
		ActorID:        "usr_winner",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("winner Update returned %v, want nil", err)
	}
	if winner.Version != baseline.Version+1 {
		t.Errorf("winner Version = %d, want %d", winner.Version, baseline.Version+1)
	}
	if winner.Slug != "acme-winner" {
		t.Errorf("winner Slug = %q, want acme-winner", winner.Slug)
	}

	// The loser holds the pre-write view of the row; its If-Match still
	// names the baseline version, which is now stale.
	loserSlug := "acme-loser"
	loserVersion := baseline.Version
	_, loserErr := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           &loserSlug,
		IfMatchVersion: &loserVersion,
		ActorID:        "usr_loser",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if loserErr == nil {
		t.Fatal("loser Update returned nil, want a typed conflict")
	}
	if ye := yerr.From(loserErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("loser Update error = %v, want %s", loserErr, yerr.CodeConflict)
	}
	gotVer, ok := apierr.CurrentVersionOf(loserErr)
	if !ok {
		t.Fatal("loser Update error carries no current_version detail")
	}
	if gotVer != winner.Version {
		t.Errorf("loser current_version = %d, want %d (the winner's bumped version)", gotVer, winner.Version)
	}

	// The row reflects the winner's write only.
	final := readOrg(t, s, org.ID)
	if final.Slug != "acme-winner" {
		t.Errorf("final Slug = %q, want acme-winner — the loser must not have overwritten", final.Slug)
	}
	if final.Version != winner.Version {
		t.Errorf("final Version = %d, want %d — a rejected update must not bump the version", final.Version, winner.Version)
	}
}

// TestOrganizationServiceUpdateWithoutIfMatchAcceptsAnyVersion proves a nil
// IfMatchVersion preserves the legacy next-write-wins behaviour: the second
// of two concurrent updates succeeds and bumps the version, since the
// caller did not supply a precondition.
func TestOrganizationServiceUpdateWithoutIfMatchAcceptsAnyVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	svc := newOrganizationService(t, s)

	org := seedOrg(t, db, f, "acme-co")

	first := "acme-one"
	second := "acme-two"
	if _, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           &first,
		ActorID:        "usr_a",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("first Update returned %v, want nil", err)
	}
	got, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           &second,
		ActorID:        "usr_b",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("second Update returned %v, want nil — no precondition supplied", err)
	}
	if got.Slug != "acme-two" {
		t.Errorf("Slug = %q, want acme-two", got.Slug)
	}
	if got.Version != 3 {
		t.Errorf("Version = %d, want 3 (1 -> 2 -> 3 across two unchecked updates)", got.Version)
	}
}

// TestOrganizationServiceScheduleDeletionRejectsStaleIfMatchVersion proves
// the same precondition is enforced on DELETE: a stale If-Match against a
// row that was concurrently updated returns a typed E_CONFLICT carrying the
// current version, and the row is left un-scheduled.
func TestOrganizationServiceScheduleDeletionRejectsStaleIfMatchVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	svc := newOrganizationService(t, s)

	org := seedOrg(t, db, f, "acme-co")
	baseline := readOrg(t, s, org.ID)
	staleVersion := baseline.Version

	// A concurrent update bumps the row's version while the would-be
	// deleter still holds the baseline view.
	winnerSlug := "acme-renamed"
	if _, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           &winnerSlug,
		IfMatchVersion: &staleVersion,
		ActorID:        "usr_winner",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("winner Update returned %v, want nil", err)
	}

	_, deleteErr := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: org.ID,
		IfMatchVersion: &staleVersion,
		ActorID:        "usr_loser",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if deleteErr == nil {
		t.Fatal("ScheduleDeletion returned nil, want a typed conflict")
	}
	if ye := yerr.From(deleteErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("ScheduleDeletion error = %v, want %s", deleteErr, yerr.CodeConflict)
	}
	gotVer, ok := apierr.CurrentVersionOf(deleteErr)
	if !ok {
		t.Fatal("ScheduleDeletion error carries no current_version detail")
	}
	if gotVer != staleVersion+1 {
		t.Errorf("current_version = %d, want %d (the winner's bumped version)", gotVer, staleVersion+1)
	}

	final := readOrg(t, s, org.ID)
	if final.DeletionScheduledAt != nil {
		t.Errorf("DeletionScheduledAt = %v, want nil — a rejected schedule must not stamp the row", final.DeletionScheduledAt)
	}
}

// TestProjectRepositoryUpdateDisplayNameRejectsStaleIfMatchVersion proves
// the same optimistic-concurrency contract is enforced at the projects
// table: two concurrent UpdateDisplayName calls against the same row leave
// the first winning and the second receiving a typed conflict carrying the
// row's authoritative version. This proves the mechanism extends beyond
// organizations even before projects/environments/services have HTTP
// endpoints — the schema and the repository contract are both exercised.
func TestProjectRepositoryUpdateDisplayNameRejectsStaleIfMatchVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()

	org := seedOrg(t, db, f, "acme-co")
	proj := seedProject(t, db, f, org, "billing")

	// Read the baseline version through the store layer so the test
	// observes the persistence contract, not test-fixture state.
	var baseline store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, getErr := repo.Get(ctx, q, org.ID, proj.ID)
		if getErr != nil {
			return getErr
		}
		baseline = got
		return nil
	}); err != nil {
		t.Fatalf("Get baseline project: %v", err)
	}
	if baseline.Version != 1 {
		t.Fatalf("baseline Project.Version = %d, want 1", baseline.Version)
	}

	expected := baseline.Version
	var winner store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, updErr := repo.UpdateDisplayName(ctx, tx, org.ID, proj.ID, "Billing v2", &expected)
		if updErr != nil {
			return updErr
		}
		winner = got
		return nil
	}); err != nil {
		t.Fatalf("winner UpdateDisplayName returned %v, want nil", err)
	}
	if winner.Version != baseline.Version+1 {
		t.Errorf("winner Version = %d, want %d", winner.Version, baseline.Version+1)
	}
	if winner.DisplayName != "Billing v2" {
		t.Errorf("winner DisplayName = %q, want Billing v2", winner.DisplayName)
	}

	loserExpected := baseline.Version
	loserErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateDisplayName(ctx, tx, org.ID, proj.ID, "Billing Pwned", &loserExpected)
		return updErr
	})
	if loserErr == nil {
		t.Fatal("loser UpdateDisplayName returned nil, want a typed conflict")
	}
	if ye := yerr.From(loserErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("loser UpdateDisplayName error = %v, want %s", loserErr, yerr.CodeConflict)
	}
	gotVer, ok := apierr.CurrentVersionOf(loserErr)
	if !ok {
		t.Fatal("loser UpdateDisplayName error carries no current_version detail")
	}
	if gotVer != winner.Version {
		t.Errorf("loser current_version = %d, want %d", gotVer, winner.Version)
	}

	// The row reflects the winner's write only — the loser's mutation must
	// have rolled back, leaving a tenant-scoped read that returns the
	// winner's display_name.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, getErr := repo.Get(ctx, q, org.ID, proj.ID)
		if getErr != nil {
			return getErr
		}
		if got.DisplayName != "Billing v2" {
			return errors.New("loser overwrote the winner's display_name")
		}
		if got.Version != winner.Version {
			return errors.New("rejected update advanced the version")
		}
		return nil
	}); err != nil {
		t.Fatalf("read-back: %v", err)
	}
}

// readOrg returns the live organization row through the store-backed reader,
// so each test reads through the same path the HTTP layer uses.
func readOrg(t *testing.T, s *store.Store, organizationID string) store.Organization {
	t.Helper()
	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	got, err := reader.GetOrganization(context.Background(), organizationID)
	if err != nil {
		t.Fatalf("GetOrganization(%q) returned %v, want the row", organizationID, err)
	}
	return got
}
