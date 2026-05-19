package metering

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestStoreTraefikResolverUsesDokployRefsAndServiceState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	f := testutil.NewFactory(t)
	org := f.Organization("alpha")
	proj := f.Project(org, "alpha")
	env := f.Environment(proj, "prod")
	active := f.Service(env, "api")
	withoutRef := f.Service(env, "no-ref")
	deleted := f.Service(env, "deleted")
	seedTraefikResolverFixture(ctx, t, s, org, proj, env, active, withoutRef, deleted)

	resolver, err := NewStoreTraefikResolver(s)
	if err != nil {
		t.Fatalf("NewStoreTraefikResolver: %v", err)
	}
	attr, err := resolver.ResolveTraefikService(ctx, TraefikResolveInput{
		ServiceID: active.ID,
		Service:   "api-renamed-" + active.ID,
		Labels:    map[string]string{"yalla_service_id": active.ID},
	})
	if err != nil {
		t.Fatalf("ResolveTraefikService(active): %v", err)
	}
	if attr.OrganizationID != org.ID || attr.ProjectID != proj.ID || attr.EnvironmentID != env.ID || attr.ServiceID != active.ID {
		t.Fatalf("resolved scope = (%q,%q,%q,%q), want seeded hierarchy", attr.OrganizationID, attr.ProjectID, attr.EnvironmentID, attr.ServiceID)
	}
	if attr.Deleted {
		t.Fatal("active service resolved as deleted")
	}

	_, err = resolver.ResolveTraefikService(ctx, TraefikResolveInput{ServiceID: withoutRef.ID})
	if !errors.Is(err, ErrTraefikAttributionNotFound) {
		t.Fatalf("ResolveTraefikService(without ref) = %v, want ErrTraefikAttributionNotFound", err)
	}

	attr, err = resolver.ResolveTraefikService(ctx, TraefikResolveInput{ServiceID: deleted.ID})
	if err != nil {
		t.Fatalf("ResolveTraefikService(deleted): %v", err)
	}
	if !attr.Deleted || attr.ServiceID != deleted.ID {
		t.Fatalf("deleted attr = %#v, want deleted service attribution", attr)
	}
}

func seedTraefikResolverFixture(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	org testutil.Organization,
	proj testutil.Project,
	env testutil.Environment,
	active testutil.Service,
	withoutRef testutil.Service,
	deleted testutil.Service,
) {
	t.Helper()

	orgs := store.NewOrganizationRepository()
	projects := store.NewProjectRepository()
	envs := store.NewEnvironmentRepository()
	services := store.NewServiceRepository()
	refs := store.NewDokployRefRepository()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := orgs.Insert(ctx, tx, store.Organization{ID: org.ID, Slug: org.Slug, DisplayName: org.Name}); err != nil {
			return err
		}
		if _, err := projects.Insert(ctx, tx, store.Project{ID: proj.ID, OrganizationID: org.ID, Slug: proj.Slug, DisplayName: proj.Name}); err != nil {
			return err
		}
		if _, err := envs.Insert(ctx, tx, store.Environment{ID: env.ID, OrganizationID: org.ID, ProjectID: proj.ID, Slug: env.Slug, DisplayName: env.Name, Kind: store.EnvironmentKindStandard}); err != nil {
			return err
		}
		for _, svc := range []testutil.Service{active, withoutRef, deleted} {
			if _, err := services.Insert(ctx, tx, store.Service{
				ID:             svc.ID,
				OrganizationID: org.ID,
				ProjectID:      proj.ID,
				EnvironmentID:  env.ID,
				Slug:           svc.Slug,
				DisplayName:    svc.Name,
				Kind:           svc.Kind,
			}); err != nil {
				return err
			}
		}
		if _, err := refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         active.ID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       "dokploy-app-" + active.ID,
		}); err != nil {
			return err
		}
		if _, err := refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  org.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         deleted.ID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       "dokploy-app-" + deleted.ID,
		}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE services
			    SET status = $3
			  WHERE organization_id = $1 AND id = $2`,
			org.ID, deleted.ID, store.ServiceStatusDeleted)
		return err
	}); err != nil {
		t.Fatalf("seed Traefik resolver fixture: %v", err)
	}
}
