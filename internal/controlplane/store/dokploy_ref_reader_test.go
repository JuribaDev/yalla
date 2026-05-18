package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestDokployRefReaderListsOnlyVerifiedOrganizationRefs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	repo := store.NewDokployRefRepository()
	reader, err := store.NewDokployRefReader(s)
	if err != nil {
		t.Fatalf("NewDokployRefReader: %v", err)
	}

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	projA := seedProject(t, db, f, orgA, "Web")
	projB := seedProject(t, db, f, orgB, "API")

	refA := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  orgA.ID,
		YallaKind:       store.YallaKindProject,
		YallaID:         projA.ID,
		DokployResource: store.DokployResourceProject,
		DokployID:       mintDokployID(t, "reader-a"),
	})
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  orgB.ID,
		YallaKind:       store.YallaKindProject,
		YallaID:         projB.ID,
		DokployResource: store.DokployResourceProject,
		DokployID:       mintDokployID(t, "reader-b"),
	})

	got, err := reader.ListDokployRefs(ctx, orgA.ID)
	if err != nil {
		t.Fatalf("ListDokployRefs(%q): %v", orgA.ID, err)
	}
	if len(got) != 1 {
		t.Fatalf("ListDokployRefs(%q) returned %d rows, want 1", orgA.ID, len(got))
	}
	if got[0].ID != refA.ID || got[0].OrganizationID != orgA.ID || got[0].YallaID != projA.ID {
		t.Fatalf("ListDokployRefs(%q)[0] = %+v, want orgA project ref %+v", orgA.ID, got[0], refA)
	}
}

func TestDokployRefReaderMissingOrganizationIsNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	reader, err := store.NewDokployRefReader(s)
	if err != nil {
		t.Fatalf("NewDokployRefReader: %v", err)
	}

	_, err = reader.ListDokployRefs(ctx, "org_missing_reader")
	if err == nil {
		t.Fatal("ListDokployRefs for missing organization returned nil, want NotFound")
	}
	ye := yerr.From(err)
	if ye == nil || ye.Code != yerr.CodeNotFound {
		t.Fatalf("error = %v, want code %s", err, yerr.CodeNotFound)
	}
}
