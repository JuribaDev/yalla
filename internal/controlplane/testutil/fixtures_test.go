package testutil_test

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestFactoryBuildsLinkedHierarchy(t *testing.T) {
	t.Parallel()

	f := testutil.NewFactory(t)
	org := f.Organization("Acme")
	user := f.User(org, "Ada")
	key := f.APIKey(org, user, "ci")
	proj := f.Project(org, "Web")
	env := f.Environment(proj, "Prod")
	svc := f.Service(env, "API")

	if user.OrganizationID != org.ID {
		t.Errorf("user.OrganizationID = %q, want %q", user.OrganizationID, org.ID)
	}
	if key.OrganizationID != org.ID || key.UserID != user.ID {
		t.Errorf("key links = {org:%q user:%q}, want {org:%q user:%q}",
			key.OrganizationID, key.UserID, org.ID, user.ID)
	}
	if proj.OrganizationID != org.ID {
		t.Errorf("project.OrganizationID = %q, want %q", proj.OrganizationID, org.ID)
	}
	if env.ProjectID != proj.ID || env.OrganizationID != org.ID {
		t.Errorf("env links = {project:%q org:%q}, want {project:%q org:%q}",
			env.ProjectID, env.OrganizationID, proj.ID, org.ID)
	}
	if svc.EnvironmentID != env.ID || svc.ProjectID != proj.ID || svc.OrganizationID != org.ID {
		t.Errorf("service links = {env:%q project:%q org:%q}, want {env:%q project:%q org:%q}",
			svc.EnvironmentID, svc.ProjectID, svc.OrganizationID, env.ID, proj.ID, org.ID)
	}
	if svc.Kind != testutil.ServiceKindApplication {
		t.Errorf("service.Kind = %q, want default %q", svc.Kind, testutil.ServiceKindApplication)
	}
}

func TestFactoryProducesUniqueValuesWithinAFactory(t *testing.T) {
	t.Parallel()

	f := testutil.NewFactory(t)
	seen := map[string]string{}
	mark := func(kind, value string) {
		if value == "" {
			t.Fatalf("%s fixture produced an empty identifier", kind)
		}
		if prev, dup := seen[value]; dup {
			t.Fatalf("identifier %q reused by %s (previously %s)", value, kind, prev)
		}
		seen[value] = kind
	}

	for i := 0; i < 100; i++ {
		org := f.Organization("org")
		user := f.User(org, "user")
		key := f.APIKey(org, user, "key")
		proj := f.Project(org, "project")
		env := f.Environment(proj, "env")
		svc := f.Service(env, "svc")
		mark("org.ID", org.ID)
		mark("org.Slug", org.Slug)
		mark("user.ID", user.ID)
		mark("user.Email", user.Email)
		mark("key.ID", key.ID)
		mark("key.Secret", key.Secret)
		mark("project.ID", proj.ID)
		mark("project.Slug", proj.Slug)
		mark("env.ID", env.ID)
		mark("service.ID", svc.ID)
		mark("service.Slug", svc.Slug)
	}
}

// Two factories model two parallel tests: their fixtures must never collide, so
// one test can never observe another test's tenant.
func TestFactoriesNeverCollide(t *testing.T) {
	t.Parallel()

	f1 := testutil.NewFactory(t)
	f2 := testutil.NewFactory(t)

	seen := map[string]bool{}
	collect := func(f *testutil.Factory) {
		for i := 0; i < 50; i++ {
			org := f.Organization("shared-label")
			user := f.User(org, "shared-label")
			key := f.APIKey(org, user, "shared-label")
			proj := f.Project(org, "shared-label")
			env := f.Environment(proj, "shared-label")
			svc := f.Service(env, "shared-label")
			for _, id := range []string{
				org.ID, org.Slug, user.ID, user.Email, key.ID, key.Secret,
				key.Prefix, proj.ID, proj.Slug, env.ID, env.Slug, svc.ID, svc.Slug,
			} {
				// Prefix is intentionally shared within a factory (every key of
				// one factory shares it) but must differ between factories.
				if id == key.Prefix {
					continue
				}
				if seen[id] {
					t.Fatalf("fixture identifier reused across factories: %q", id)
				}
				seen[id] = true
			}
		}
	}
	collect(f1)
	collect(f2)
}

func TestFactoryHandlesEmptyAndMessyLabels(t *testing.T) {
	t.Parallel()

	f := testutil.NewFactory(t)

	blank := f.Organization("   ")
	if strings.TrimSpace(blank.Name) == "" {
		t.Error("empty label should fall back to a generated name")
	}
	if !strings.HasPrefix(blank.Slug, "org-") {
		t.Errorf("empty-label slug = %q, want it to fall back to the 'org-' prefix", blank.Slug)
	}

	messy := f.Project(blank, "My Cool Project!!!")
	if !strings.HasPrefix(messy.Slug, "my-cool-project-") {
		t.Errorf("messy-label slug = %q, want a slugified prefix", messy.Slug)
	}

	user := f.User(blank, "Ada Lovelace")
	if !strings.Contains(user.Email, "@") || strings.ContainsAny(user.Email, " ") {
		t.Errorf("user email = %q, want a space-free address", user.Email)
	}
}

func TestServiceKindCanBeOverridden(t *testing.T) {
	t.Parallel()

	f := testutil.NewFactory(t)
	org := f.Organization("o")
	proj := f.Project(org, "p")
	env := f.Environment(proj, "e")
	svc := f.Service(env, "db")
	svc.Kind = testutil.ServiceKindDatabase
	if svc.Kind != testutil.ServiceKindDatabase {
		t.Errorf("service.Kind = %q, want %q", svc.Kind, testutil.ServiceKindDatabase)
	}
}
