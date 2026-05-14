package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/jackc/pgx/v5/pgconn"
)

// The tenant-hierarchy schema (migration 0002) is exercised here as an
// integration test: it runs against an isolated, freshly migrated Postgres
// database and skips when YALLA_TEST_DATABASE_URL is unset. The tests prove
// the database — not just the application — enforces the
// Organization -> Project -> Environment -> Service hierarchy, tenant scoping,
// slug uniqueness within a parent, and cascade behaviour.

// seedOrg inserts an organization row built from f and returns it.
func seedOrg(t *testing.T, db *testutil.DB, f *testutil.Factory, label string) testutil.Organization {
	t.Helper()
	org := f.Organization(label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		org.ID, org.Slug, org.Name); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	return org
}

// seedProject inserts a project row owned by org and returns it.
func seedProject(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label string) testutil.Project {
	t.Helper()
	proj := f.Project(org, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		proj.ID, proj.OrganizationID, proj.Slug, proj.Name); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return proj
}

// seedEnvironment inserts an environment row owned by proj and returns it.
func seedEnvironment(t *testing.T, db *testutil.DB, f *testutil.Factory, proj testutil.Project, label string) testutil.Environment {
	t.Helper()
	env := f.Environment(proj, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
		 VALUES ($1, $2, $3, $4, $5)`,
		env.ID, env.OrganizationID, env.ProjectID, env.Slug, env.Name); err != nil {
		t.Fatalf("seed environment: %v", err)
	}
	return env
}

// seedService inserts a service row owned by env and returns it.
func seedService(t *testing.T, db *testutil.DB, f *testutil.Factory, env testutil.Environment, label string) testutil.Service {
	t.Helper()
	svc := f.Service(env, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		svc.ID, svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.Slug, svc.Name, svc.Kind); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	return svc
}

// isConstraintViolation reports whether err is a Postgres integrity-constraint
// error (foreign key, unique, check, not-null).
func isConstraintViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	// Class 23 — Integrity Constraint Violation.
	return len(pgErr.Code) == 5 && pgErr.Code[:2] == "23"
}

func TestTenantHierarchyTablesExist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()

	want := []string{
		"organizations", "users", "memberships",
		"projects", "environments", "services", "dokploy_refs",
	}
	for _, table := range want {
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM information_schema.tables
			   WHERE table_schema = 'public' AND table_name = $1
			 )`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %q: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q does not exist after migration", table)
		}
	}
}

func TestTenantHierarchyFullChainInsert(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	// The child rows resolve back up the hierarchy by parent ID, scoped by
	// organization ID first as every query must be.
	var (
		gotProjOrg string
		gotEnvProj string
		gotSvcEnv  string
	)
	if err := db.QueryRow(ctx,
		`SELECT p.organization_id, e.project_id, s.environment_id
		   FROM services s
		   JOIN environments e ON e.organization_id = s.organization_id AND e.id = s.environment_id
		   JOIN projects p     ON p.organization_id = e.organization_id AND p.id = e.project_id
		  WHERE s.organization_id = $1 AND s.id = $2`,
		org.ID, svc.ID).Scan(&gotProjOrg, &gotEnvProj, &gotSvcEnv); err != nil {
		t.Fatalf("walk hierarchy: %v", err)
	}
	if gotProjOrg != org.ID {
		t.Errorf("project organization_id = %q, want %q", gotProjOrg, org.ID)
	}
	if gotEnvProj != proj.ID {
		t.Errorf("environment project_id = %q, want %q", gotEnvProj, proj.ID)
	}
	if gotSvcEnv != env.ID {
		t.Errorf("service environment_id = %q, want %q", gotSvcEnv, env.ID)
	}
}

func TestTenantHierarchyForeignKeysEnforced(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")

	t.Run("project requires an existing organization", func(t *testing.T) {
		orphan := f.Project(testutil.Organization{ID: "org_does_not_exist"}, "Orphan")
		_, err := db.Exec(ctx,
			`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
			orphan.ID, orphan.OrganizationID, orphan.Slug, orphan.Name)
		if !isConstraintViolation(err) {
			t.Fatalf("insert project with missing org: err = %v, want constraint violation", err)
		}
	})

	t.Run("environment cannot cross the tenant boundary", func(t *testing.T) {
		// The environment names a real project but claims a different
		// organization than the project actually belongs to. The composite
		// foreign key (organization_id, project_id) must reject it.
		other := seedOrg(t, db, f, "Other")
		env := f.Environment(proj, "Production")
		_, err := db.Exec(ctx,
			`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
			 VALUES ($1, $2, $3, $4, $5)`,
			env.ID, other.ID, proj.ID, env.Slug, env.Name)
		if !isConstraintViolation(err) {
			t.Fatalf("insert environment with mismatched org: err = %v, want constraint violation", err)
		}
	})

	t.Run("service cannot cross the tenant boundary", func(t *testing.T) {
		env := seedEnvironment(t, db, f, proj, "Staging")
		other := seedOrg(t, db, f, "Other2")
		svc := f.Service(env, "API")
		_, err := db.Exec(ctx,
			`INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			svc.ID, other.ID, svc.ProjectID, svc.EnvironmentID, svc.Slug, svc.Name, svc.Kind)
		if !isConstraintViolation(err) {
			t.Fatalf("insert service with mismatched org: err = %v, want constraint violation", err)
		}
	})
}

func TestTenantHierarchySlugUniqueWithinParent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	// A project slug is unique within its organization.
	const slug = "shared-slug"
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		f.Project(orgA, "P").ID, orgA.ID, slug, "Project A"); err != nil {
		t.Fatalf("first project: %v", err)
	}
	// Same slug, same organization — rejected.
	_, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		f.Project(orgA, "P").ID, orgA.ID, slug, "Project A dup")
	if !isConstraintViolation(err) {
		t.Fatalf("duplicate slug within org: err = %v, want constraint violation", err)
	}
	// Same slug, different organization — allowed: slugs are scoped, not global.
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		f.Project(orgB, "P").ID, orgB.ID, slug, "Project B"); err != nil {
		t.Fatalf("same slug in a different org should be allowed: %v", err)
	}

	// citext makes slug uniqueness case-insensitive within the parent.
	_, err = db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		f.Project(orgA, "P").ID, orgA.ID, "SHARED-SLUG", "Project A case dup")
	if !isConstraintViolation(err) {
		t.Fatalf("case-variant slug within org: err = %v, want constraint violation", err)
	}
}

func TestTenantHierarchyCascadeDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	seedService(t, db, f, env, "API")

	// A membership and a dokploy_ref scoped to the organization.
	user := f.User(org, "Dana")
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		user.ID, user.Email, user.Name); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')`,
		org.ID, user.ID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
		 VALUES ($1, 'organization', $2, 'organization', $3)`,
		org.ID, org.ID, "dokploy-org-1"); err != nil {
		t.Fatalf("seed dokploy_ref: %v", err)
	}

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	// Every descendant row is gone; the global users row survives.
	for _, table := range []string{"projects", "environments", "services", "memberships", "dokploy_refs"} {
		var count int
		if err := db.QueryRow(ctx,
			`SELECT count(*) FROM `+table+` WHERE organization_id = $1`, org.ID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s rows after org delete = %d, want 0", table, count)
		}
	}
	var userCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, user.ID).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Errorf("users row after org delete = %d, want 1 (users are global)", userCount)
	}
}

func TestTenantHierarchyCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	seedProject(t, db, f, orgA, "A1")
	seedProject(t, db, f, orgA, "A2")
	seedProject(t, db, f, orgB, "B1")

	// A query scoped by organization ID only ever sees that tenant's rows.
	var countA, countB int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM projects WHERE organization_id = $1`, orgA.ID).Scan(&countA); err != nil {
		t.Fatalf("count org A projects: %v", err)
	}
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM projects WHERE organization_id = $1`, orgB.ID).Scan(&countB); err != nil {
		t.Fatalf("count org B projects: %v", err)
	}
	if countA != 2 {
		t.Errorf("org A projects = %d, want 2", countA)
	}
	if countB != 1 {
		t.Errorf("org B projects = %d, want 1", countB)
	}
}

func TestDokployRefsConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Production")
	svc := seedService(t, db, f, env, "API")

	// A service maps to one Dokploy application.
	if _, err := db.Exec(ctx,
		`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
		 VALUES ($1, 'service', $2, 'application', $3)`,
		org.ID, svc.ID, "dokploy-app-1"); err != nil {
		t.Fatalf("map service to application: %v", err)
	}
	// The same service may own several domains — distinct dokploy_id values.
	for _, dokployID := range []string{"dokploy-domain-1", "dokploy-domain-2"} {
		if _, err := db.Exec(ctx,
			`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
			 VALUES ($1, 'service', $2, 'domain', $3)`,
			org.ID, svc.ID, dokployID); err != nil {
			t.Fatalf("map service to domain %s: %v", dokployID, err)
		}
	}

	t.Run("a Dokploy object cannot be claimed twice", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
			 VALUES ($1, 'service', $2, 'application', $3)`,
			org.ID, env.ID, "dokploy-app-1")
		if !isConstraintViolation(err) {
			t.Fatalf("reuse dokploy_id: err = %v, want constraint violation", err)
		}
	})

	t.Run("duplicate mapping rows are rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
			 VALUES ($1, 'service', $2, 'domain', $3)`,
			org.ID, svc.ID, "dokploy-domain-1")
		if !isConstraintViolation(err) {
			t.Fatalf("duplicate mapping row: err = %v, want constraint violation", err)
		}
	})

	t.Run("unknown dokploy_resource is rejected", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
			 VALUES ($1, 'service', $2, 'not-a-real-kind', $3)`,
			org.ID, svc.ID, "dokploy-x-1")
		if !isConstraintViolation(err) {
			t.Fatalf("invalid dokploy_resource: err = %v, want constraint violation", err)
		}
	})

	t.Run("dokploy_ref requires an existing organization", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO dokploy_refs (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
			 VALUES ($1, 'service', $2, 'application', $3)`,
			"org_does_not_exist", svc.ID, "dokploy-app-2")
		if !isConstraintViolation(err) {
			t.Fatalf("dokploy_ref with missing org: err = %v, want constraint violation", err)
		}
	})
}

func TestMembershipConstraints(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "Acme")
	user := f.User(org, "Dana")
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		user.ID, user.Email, user.Name); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')`,
		org.ID, user.ID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	t.Run("a user has at most one membership per organization", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')`,
			org.ID, user.ID)
		if !isConstraintViolation(err) {
			t.Fatalf("duplicate membership: err = %v, want constraint violation", err)
		}
	})

	t.Run("an unknown role is rejected", func(t *testing.T) {
		other := f.User(org, "Eli")
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
			other.ID, other.Email, other.Name); err != nil {
			t.Fatalf("seed other user: %v", err)
		}
		_, err := db.Exec(ctx,
			`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'superuser')`,
			org.ID, other.ID)
		if !isConstraintViolation(err) {
			t.Fatalf("invalid role: err = %v, want constraint violation", err)
		}
	})

	t.Run("membership requires an existing user", func(t *testing.T) {
		_, err := db.Exec(ctx,
			`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')`,
			org.ID, "usr_does_not_exist")
		if !isConstraintViolation(err) {
			t.Fatalf("membership with missing user: err = %v, want constraint violation", err)
		}
	})
}
