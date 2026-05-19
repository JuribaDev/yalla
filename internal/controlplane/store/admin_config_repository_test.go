package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestAdminConfigRepositoryDraftPublishArchiveRollbackAndActiveRuntime(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAdminConfigRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	future := now.Add(2 * time.Hour)

	var set store.AdminConfigSet
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		set, err = repo.CreateSet(ctx, tx, store.CreateAdminConfigSetInput{
			Slug:   "pricing-runtime",
			Domain: store.AdminConfigDomainPricing,
			Name:   "Pricing Runtime",
		})
		return err
	}); err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	if set.ID == "" || set.Revision != 1 {
		t.Fatalf("created set = %+v, want id and revision 1", set)
	}

	draftPayload := []byte(`{"plans":["starter"]}`)
	var draft store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		draft, err = repo.CreateDraft(ctx, tx, store.CreateAdminConfigDraftInput{
			ConfigSetID: set.ID,
			Payload:     draftPayload,
		})
		return err
	}); err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if draft.Version != 1 || draft.Status != store.AdminConfigStatusDraft || !bytes.Equal(draft.Payload, draftPayload) {
		t.Fatalf("draft = %+v, want version 1 draft with payload", draft)
	}

	var active []store.AdminConfigVersion
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		active, err = repo.ListActivePublished(ctx, q, now)
		return err
	}); err != nil {
		t.Fatalf("ListActivePublished before publish: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active before publish = %+v, want none", active)
	}

	var published store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		published, err = repo.Publish(ctx, tx, draft.ID, store.PublishAdminConfigVersionInput{
			EffectiveAt: now,
			PublishedBy: "usr_admin",
		})
		return err
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if published.Status != store.AdminConfigStatusPublished || published.PublishedAt == nil || published.PublishedBy == nil || *published.PublishedBy != "usr_admin" {
		t.Fatalf("published = %+v, want published stamp", published)
	}

	secondPayload := []byte(`{"plans":["starter","pro"]}`)
	var secondDraft, futurePublished store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		secondDraft, err = repo.CreateDraft(ctx, tx, store.CreateAdminConfigDraftInput{
			ConfigSetID: set.ID,
			Payload:     secondPayload,
		})
		if err != nil {
			return err
		}
		futurePublished, err = repo.Publish(ctx, tx, secondDraft.ID, store.PublishAdminConfigVersionInput{
			EffectiveAt: future,
			PublishedBy: "usr_admin",
		})
		return err
	}); err != nil {
		t.Fatalf("create and publish future version: %v", err)
	}
	if futurePublished.Version != 2 {
		t.Fatalf("future version number = %d, want 2", futurePublished.Version)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		active, err = repo.ListActivePublished(ctx, q, now)
		return err
	}); err != nil {
		t.Fatalf("ListActivePublished at now: %v", err)
	}
	if len(active) != 1 || active[0].ID != published.ID {
		t.Fatalf("active at now = %+v, want first published version only", active)
	}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		active, err = repo.ListActivePublished(ctx, q, future.Add(time.Second))
		return err
	}); err != nil {
		t.Fatalf("ListActivePublished after future effective: %v", err)
	}
	if len(active) != 1 || active[0].ID != futurePublished.ID {
		t.Fatalf("active after future = %+v, want future-published version", active)
	}

	var rollback store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		rollback, err = repo.Rollback(ctx, tx, set.ID, published.ID, store.RollbackAdminConfigInput{
			EffectiveAt:     future.Add(time.Hour),
			PublishedBy:     "usr_admin",
			RollbackReason:  "restore previous pricing",
			RollbackVersion: futurePublished.ID,
		})
		return err
	}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rollback.Version != 3 || rollback.Status != store.AdminConfigStatusPublished || rollback.RollbackOfVersionID == nil || *rollback.RollbackOfVersionID != futurePublished.ID {
		t.Fatalf("rollback = %+v, want published version 3 pointing at rolled-back version", rollback)
	}
	if !bytes.Equal(rollback.Payload, published.Payload) {
		t.Fatalf("rollback payload = %s, want %s", rollback.Payload, published.Payload)
	}

	var archived store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		archived, err = repo.Archive(ctx, tx, futurePublished.ID)
		return err
	}); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if archived.Status != store.AdminConfigStatusArchived || archived.ArchivedAt == nil {
		t.Fatalf("archived = %+v, want archived stamp", archived)
	}
}

func TestAdminConfigRepositoryRevisionInvalidatesOnVersionChanges(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAdminConfigRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)

	var set store.AdminConfigSet
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		set, err = repo.CreateSet(ctx, tx, store.CreateAdminConfigSetInput{
			Slug:   "features-runtime",
			Domain: store.AdminConfigDomainFeatures,
			Name:   "Feature Flags",
		})
		return err
	}); err != nil {
		t.Fatalf("CreateSet: %v", err)
	}
	revisions := []int64{set.Revision}

	var draft store.AdminConfigVersion
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		draft, err = repo.CreateDraft(ctx, tx, store.CreateAdminConfigDraftInput{ConfigSetID: set.ID, Payload: []byte(`{"flags":[]}`)})
		return err
	}); err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	revisions = append(revisions, readAdminConfigRevision(t, ctx, s, repo, set.ID))

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Publish(ctx, tx, draft.ID, store.PublishAdminConfigVersionInput{EffectiveAt: now, PublishedBy: "usr_admin"})
		return err
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	revisions = append(revisions, readAdminConfigRevision(t, ctx, s, repo, set.ID))

	if !(revisions[0] < revisions[1] && revisions[1] < revisions[2]) {
		t.Fatalf("revisions = %v, want monotonic invalidation token increments", revisions)
	}
}

func TestAdminConfigRepositoryValidationAndNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAdminConfigRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.CreateSet(ctx, tx, store.CreateAdminConfigSetInput{
			Slug:   "Invalid Slug",
			Domain: store.AdminConfigDomainPricing,
			Name:   "Pricing",
		})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("invalid CreateSet err code = %s, want %s (err=%v)", ye.Code, yerr.CodeInvalidInput, err)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.CreateDraft(ctx, tx, store.CreateAdminConfigDraftInput{
			ConfigSetID: "cfg_missing",
			Payload:     []byte(`{}`),
		})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("missing CreateDraft set err code = %s, want %s (err=%v)", ye.Code, yerr.CodeNotFound, err)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Publish(ctx, tx, "cfgver_missing", store.PublishAdminConfigVersionInput{
			EffectiveAt: time.Now().UTC(),
			PublishedBy: "usr_admin",
		})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("missing Publish err code = %s, want %s (err=%v)", ye.Code, yerr.CodeNotFound, err)
	}
}

func readAdminConfigRevision(t *testing.T, ctx context.Context, s *store.Store, repo *store.AdminConfigRepository, setID string) int64 {
	t.Helper()
	var revision int64
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		revision, err = repo.Revision(ctx, q, setID)
		return err
	}); err != nil {
		t.Fatalf("Revision(%q): %v", setID, err)
	}
	return revision
}
