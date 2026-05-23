package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestJobRepositoryListFiltersByScopeAndStatus(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	serviceJob := jobFixture(org.ID, "idem_service")
	serviceJob.ProjectID = proj.ID
	serviceJob.EnvironmentID = env.ID
	serviceJob.ServiceID = svc.ID
	serviceJob.Status = ""
	serviceJob = insertJob(ctx, t, s, repo, serviceJob)

	projectJob := jobFixture(org.ID, "idem_project")
	projectJob.ProjectID = proj.ID
	projectJob = insertJob(ctx, t, s, repo, projectJob)

	got, err := repo.List(ctx, db, store.ListProvisioningJobsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Status:         store.JobStatusQueued,
		Limit:          50,
	})
	if err != nil {
		t.Fatalf("List filtered jobs: %v", err)
	}
	if len(got) != 1 || got[0].ID != serviceJob.ID {
		t.Fatalf("filtered jobs = %+v, want only service job %s (project sibling %s must be excluded)", got, serviceJob.ID, projectJob.ID)
	}
}

func TestJobReaderGetJobIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	reader, err := store.NewJobReader(s)
	if err != nil {
		t.Fatalf("NewJobReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Bravo")
	projA := seedProject(t, db, f, orgA, "api")
	projB := seedProject(t, db, f, orgB, "api")

	jobA := jobFixture(orgA.ID, "idem-reader-get-alpha")
	jobA.ProjectID = projA.ID
	jobA = insertJob(ctx, t, s, repo, jobA)
	jobB := jobFixture(orgB.ID, "idem-reader-get-bravo")
	jobB.ProjectID = projB.ID
	jobB = insertJob(ctx, t, s, repo, jobB)

	got, err := reader.GetJob(ctx, orgA.ID, jobA.ID)
	if err != nil {
		t.Fatalf("GetJob(alpha, alpha job): %v", err)
	}
	if got.ID != jobA.ID || got.OrganizationID != orgA.ID || got.ProjectID != projA.ID {
		t.Fatalf("GetJob(alpha, alpha job) = %+v, want alpha job scoped to project", got)
	}

	if _, err := reader.GetJob(ctx, orgA.ID, jobB.ID); err == nil {
		t.Fatalf("GetJob(alpha, bravo job %s) succeeded, want NotFound", jobB.ID)
	}
}
