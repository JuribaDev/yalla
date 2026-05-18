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
