package jobs_test

import (
	"context"
	"maps"
	"strconv"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/jobs"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
)

func TestEnqueuerEnqueuesOrganizationJob(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
			OrganizationID: " " + org.ID + " ",
			JobKind:        " " + jobs.TypeEnsureDokployOrganization + " ",
			ResourceID:     " " + org.ID + " ",
			RequestID:      " req_test ",
			CorrelationID:  " corr_test ",
		})
	}); err != nil {
		t.Fatalf("enqueue organization job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	assertJob(t, job, jobExpectation{
		OrganizationID: org.ID,
		JobType:        jobs.TypeEnsureDokployOrganization,
		DesiredVersion: org.Version,
		IdempotencyKey: jobs.TypeEnsureDokployOrganization + ":" + org.ID + ":v" + strconv.FormatInt(org.Version, 10),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
		Payload: map[string]string{
			"organization_id": org.ID,
		},
	})
	if _, err := worker.ParseEnsureDokployOrganizationPayload(job); err != nil {
		t.Fatalf("worker rejected organization payload: %v", err)
	}
}

func TestEnqueuerEnqueuesProjectJob(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	var project store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		project = insertJobsTestProject(ctx, t, tx, org, "api")
		return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
			OrganizationID: org.ID,
			JobKind:        "project.provision",
			ResourceID:     project.ID,
			RequestID:      "req_test",
			CorrelationID:  "corr_test",
		})
	}); err != nil {
		t.Fatalf("enqueue project job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	assertJob(t, job, jobExpectation{
		OrganizationID: org.ID,
		JobType:        jobs.TypeEnsureProject,
		ProjectID:      project.ID,
		DesiredVersion: project.Version,
		IdempotencyKey: "project.provision:" + project.ID + ":v" + strconv.FormatInt(project.Version, 10),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
		},
	})
	if _, err := worker.ParseEnsureProjectPayload(job); err != nil {
		t.Fatalf("worker rejected project payload: %v", err)
	}
}

func TestEnqueuerEnqueuesEnvironmentJob(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	var project store.Project
	var env store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		project = insertJobsTestProject(ctx, t, tx, org, "api")
		env = insertJobsTestEnvironment(ctx, t, tx, org, project, "prod", store.EnvironmentKindStandard)
		return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
			OrganizationID: org.ID,
			JobKind:        "environment.provision",
			ResourceID:     env.ID,
			RequestID:      "req_test",
			CorrelationID:  "corr_test",
		})
	}); err != nil {
		t.Fatalf("enqueue environment job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	assertJob(t, job, jobExpectation{
		OrganizationID: org.ID,
		JobType:        jobs.TypeEnsureEnvironment,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		DesiredVersion: env.Version,
		IdempotencyKey: "environment.provision:" + env.ID + ":v" + strconv.FormatInt(env.Version, 10),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
			"environment_id":  env.ID,
		},
	})
	if _, err := worker.ParseEnsureEnvironmentPayload(job); err != nil {
		t.Fatalf("worker rejected environment payload: %v", err)
	}
}

func TestEnqueuerEnqueuesServiceProvisioningJobs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		kind      string
		wantType  string
		wantParse func(store.ProvisioningJob) error
		wantExtra map[string]string
	}{
		{
			name:     "application",
			kind:     store.ServiceKindApplication,
			wantType: jobs.TypeEnsureApplicationService,
			wantParse: func(job store.ProvisioningJob) error {
				_, err := worker.ParseEnsureApplicationServicePayload(job)
				return err
			},
		},
		{
			name:     "compose",
			kind:     store.ServiceKindCompose,
			wantType: jobs.TypeEnsureComposeService,
			wantParse: func(job store.ProvisioningJob) error {
				_, err := worker.ParseEnsureComposeServicePayload(job)
				return err
			},
		},
		{
			name:     "database",
			kind:     store.ServiceKindDatabase,
			wantType: jobs.TypeEnsureDatabaseService,
			wantParse: func(job store.ProvisioningJob) error {
				_, err := worker.ParseEnsureDatabaseServicePayload(job)
				return err
			},
			wantExtra: map[string]string{"engine": dokploy.EnginePostgres},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := testutil.RequireMigratedDB(t)
			s := newJobsTestStore(t, db)
			enq := jobs.NewEnqueuer()
			ctx := context.Background()

			var org store.Organization
			var project store.Project
			var env store.Environment
			var svc store.Service
			if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				org = insertJobsTestOrganization(ctx, t, tx, "acme")
				project = insertJobsTestProject(ctx, t, tx, org, "api")
				env = insertJobsTestEnvironment(ctx, t, tx, org, project, "prod", store.EnvironmentKindStandard)
				svc = insertJobsTestService(ctx, t, tx, org, project, env, tc.name, tc.kind)
				return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
					OrganizationID: org.ID,
					JobKind:        "service.provision",
					ResourceID:     svc.ID,
					RequestID:      "req_test",
					CorrelationID:  "corr_test",
				})
			}); err != nil {
				t.Fatalf("enqueue service job: %v", err)
			}

			payload := map[string]string{
				"organization_id": org.ID,
				"project_id":      project.ID,
				"environment_id":  env.ID,
				"service_id":      svc.ID,
			}
			for k, v := range tc.wantExtra {
				payload[k] = v
			}
			job := readOnlyJob(t, s, org.ID)
			assertJob(t, job, jobExpectation{
				OrganizationID: org.ID,
				JobType:        tc.wantType,
				ProjectID:      project.ID,
				EnvironmentID:  env.ID,
				ServiceID:      svc.ID,
				DesiredVersion: svc.Version,
				IdempotencyKey: "service.provision:" + svc.ID + ":v" + strconv.FormatInt(svc.Version, 10),
				RequestID:      "req_test",
				CorrelationID:  "corr_test",
				Payload:        payload,
			})
			if err := tc.wantParse(job); err != nil {
				t.Fatalf("worker rejected %s service payload: %v", tc.name, err)
			}
		})
	}
}

func TestEnqueuerEnqueuesServiceRuntimeJob(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	var project store.Project
	var env store.Environment
	var svc store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		project = insertJobsTestProject(ctx, t, tx, org, "api")
		env = insertJobsTestEnvironment(ctx, t, tx, org, project, "prod", store.EnvironmentKindStandard)
		svc = insertJobsTestService(ctx, t, tx, org, project, env, "api", store.ServiceKindApplication)
		return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
			OrganizationID: org.ID,
			JobKind:        jobs.TypeRestartService,
			ResourceID:     svc.ID,
			RequestID:      "req_test",
			CorrelationID:  "corr_test",
		})
	}); err != nil {
		t.Fatalf("enqueue service runtime job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	assertJob(t, job, jobExpectation{
		OrganizationID: org.ID,
		JobType:        jobs.TypeRestartService,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		DesiredVersion: svc.Version,
		IdempotencyKey: jobs.TypeRestartService + ":" + svc.ID + ":v" + strconv.FormatInt(svc.Version, 10),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
			"environment_id":  env.ID,
			"service_id":      svc.ID,
		},
	})
	if _, err := worker.ParseRestartServicePayload(job); err != nil {
		t.Fatalf("worker rejected restart payload: %v", err)
	}
}

func TestEnqueuerEnqueuesDeploymentJob(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	var project store.Project
	var env store.Environment
	var svc store.Service
	var deployment store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		project = insertJobsTestProject(ctx, t, tx, org, "api")
		env = insertJobsTestEnvironment(ctx, t, tx, org, project, "prod", store.EnvironmentKindStandard)
		svc = insertJobsTestService(ctx, t, tx, org, project, env, "api", store.ServiceKindApplication)
		deployment = insertJobsTestDeployment(ctx, t, tx, org, project, env, svc)
		return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
			OrganizationID: org.ID,
			JobKind:        jobs.TypeDeployService,
			ResourceID:     deployment.ID,
			RequestID:      "req_test",
			CorrelationID:  "corr_test",
		})
	}); err != nil {
		t.Fatalf("enqueue deployment job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	assertJob(t, job, jobExpectation{
		OrganizationID: org.ID,
		JobType:        jobs.TypeDeployService,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		DesiredVersion: deployment.Version,
		IdempotencyKey: jobs.TypeDeployService + ":" + deployment.ID + ":v" + strconv.FormatInt(deployment.Version, 10),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
			"environment_id":  env.ID,
			"service_id":      svc.ID,
			"deployment_id":   deployment.ID,
		},
	})
	if _, err := worker.ParseDeployServicePayload(job); err != nil {
		t.Fatalf("worker rejected deployment payload: %v", err)
	}
}

func TestEnqueuerEnqueuesPreviewJobs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		kind       string
		wantParse  func(store.ProvisioningJob) error
		transition bool
	}{
		{
			name: "create",
			kind: jobs.TypeCreatePreviewEnvironment,
			wantParse: func(job store.ProvisioningJob) error {
				_, err := worker.ParseCreatePreviewEnvironmentPayload(job)
				return err
			},
		},
		{
			name:       "delete",
			kind:       jobs.TypeDeletePreviewEnvironment,
			transition: true,
			wantParse: func(job store.ProvisioningJob) error {
				_, err := worker.ParseDeletePreviewEnvironmentPayload(job)
				return err
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := testutil.RequireMigratedDB(t)
			s := newJobsTestStore(t, db)
			enq := jobs.NewEnqueuer()
			ctx := context.Background()

			var org store.Organization
			var project store.Project
			var previewEnv store.Environment
			var preview store.PreviewEnvironment
			if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				org = insertJobsTestOrganization(ctx, t, tx, "acme")
				project = insertJobsTestProject(ctx, t, tx, org, "api")
				source := insertJobsTestEnvironment(ctx, t, tx, org, project, "prod", store.EnvironmentKindStandard)
				previewEnv = insertJobsTestEnvironment(ctx, t, tx, org, project, "pr-42", store.EnvironmentKindPreview)
				preview = insertJobsTestPreview(ctx, t, tx, org, project, previewEnv, source)
				if tc.transition {
					row, _, err := store.NewPreviewEnvironmentRepository().Transition(ctx, tx, store.PreviewEnvironmentTransition{
						OrganizationID: org.ID,
						ProjectID:      project.ID,
						PreviewID:      preview.ID,
						NextStatus:     store.PreviewEnvironmentStatusDeleting,
						Reason:         "test deletion",
					})
					if err != nil {
						return err
					}
					preview = row
				}
				return enq.Enqueue(ctx, tx, store.EnqueueJobInput{
					OrganizationID: org.ID,
					JobKind:        tc.kind,
					ResourceID:     preview.ID,
					RequestID:      "req_test",
					CorrelationID:  "corr_test",
				})
			}); err != nil {
				t.Fatalf("enqueue preview job: %v", err)
			}

			job := readOnlyJob(t, s, org.ID)
			assertJob(t, job, jobExpectation{
				OrganizationID: org.ID,
				JobType:        tc.kind,
				ProjectID:      project.ID,
				EnvironmentID:  previewEnv.ID,
				DesiredVersion: preview.Version,
				IdempotencyKey: tc.kind + ":" + preview.ID + ":v" + strconv.FormatInt(preview.Version, 10),
				RequestID:      "req_test",
				CorrelationID:  "corr_test",
				Payload: map[string]string{
					"organization_id": org.ID,
					"project_id":      project.ID,
					"environment_id":  previewEnv.ID,
					"preview_id":      preview.ID,
				},
			})
			if err := tc.wantParse(job); err != nil {
				t.Fatalf("worker rejected %s preview payload: %v", tc.name, err)
			}
		})
	}
}

func TestEnqueuerTreatsDuplicateVersionedInputAsIdempotent(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newJobsTestStore(t, db)
	enq := jobs.NewEnqueuer()
	ctx := context.Background()

	var org store.Organization
	var project store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org = insertJobsTestOrganization(ctx, t, tx, "acme")
		project = insertJobsTestProject(ctx, t, tx, org, "api")
		in := store.EnqueueJobInput{
			OrganizationID: org.ID,
			JobKind:        "project.provision",
			ResourceID:     project.ID,
			RequestID:      "req_test",
			CorrelationID:  "corr_test",
		}
		if err := enq.Enqueue(ctx, tx, in); err != nil {
			return err
		}
		return enq.Enqueue(ctx, tx, in)
	}); err != nil {
		t.Fatalf("enqueue duplicate project job: %v", err)
	}

	job := readOnlyJob(t, s, org.ID)
	if job.IdempotencyKey != "project.provision:"+project.ID+":v"+strconv.FormatInt(project.Version, 10) {
		t.Fatalf("idempotency key = %q, want project provision key for version %d", job.IdempotencyKey, project.Version)
	}
}

type jobExpectation struct {
	OrganizationID string
	JobType        string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	DesiredVersion int64
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
	Payload        map[string]string
}

func assertJob(t *testing.T, got store.ProvisioningJob, want jobExpectation) {
	t.Helper()
	if got.OrganizationID != want.OrganizationID {
		t.Errorf("organization_id = %q, want %q", got.OrganizationID, want.OrganizationID)
	}
	if got.JobType != want.JobType {
		t.Errorf("job_type = %q, want %q", got.JobType, want.JobType)
	}
	if got.ProjectID != want.ProjectID {
		t.Errorf("project_id = %q, want %q", got.ProjectID, want.ProjectID)
	}
	if got.EnvironmentID != want.EnvironmentID {
		t.Errorf("environment_id = %q, want %q", got.EnvironmentID, want.EnvironmentID)
	}
	if got.ServiceID != want.ServiceID {
		t.Errorf("service_id = %q, want %q", got.ServiceID, want.ServiceID)
	}
	if got.DesiredVersion != want.DesiredVersion {
		t.Errorf("desired_version = %d, want %d", got.DesiredVersion, want.DesiredVersion)
	}
	if got.IdempotencyKey != want.IdempotencyKey {
		t.Errorf("idempotency_key = %q, want %q", got.IdempotencyKey, want.IdempotencyKey)
	}
	if got.RequestID != want.RequestID || got.CorrelationID != want.CorrelationID {
		t.Errorf("correlation = %q/%q, want %q/%q", got.RequestID, got.CorrelationID, want.RequestID, want.CorrelationID)
	}
	if !maps.Equal(got.Payload, want.Payload) {
		t.Errorf("payload = %+v, want %+v", got.Payload, want.Payload)
	}
}

func readOnlyJob(t *testing.T, s *store.Store, organizationID string) store.ProvisioningJob {
	t.Helper()

	var rows []store.ProvisioningJob
	if err := s.Read(context.Background(), func(ctx context.Context, q store.Querier) error {
		var err error
		rows, err = store.NewJobRepository().ListByOrganization(ctx, q, organizationID, 10)
		return err
	}); err != nil {
		t.Fatalf("read provisioning jobs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("job rows = %d, want exactly one", len(rows))
	}
	return rows[0]
}

func newJobsTestStore(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

func insertJobsTestOrganization(ctx context.Context, t *testing.T, tx *store.Tx, slug string) store.Organization {
	t.Helper()
	row, err := store.NewOrganizationRepository().Insert(ctx, tx, store.Organization{
		ID:          domain.MustNewID(domain.KindOrganization).String(),
		Slug:        slug,
		DisplayName: slug + " organization",
	})
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	return row
}

func insertJobsTestProject(ctx context.Context, t *testing.T, tx *store.Tx, org store.Organization, slug string) store.Project {
	t.Helper()
	row, err := store.NewProjectRepository().Insert(ctx, tx, store.Project{
		ID:             domain.MustNewID(domain.KindProject).String(),
		OrganizationID: org.ID,
		Slug:           slug,
		DisplayName:    slug + " project",
	})
	if err != nil {
		t.Fatalf("insert project: %v", err)
	}
	return row
}

func insertJobsTestEnvironment(ctx context.Context, t *testing.T, tx *store.Tx, org store.Organization, project store.Project, slug, kind string) store.Environment {
	t.Helper()
	row, err := store.NewEnvironmentRepository().Insert(ctx, tx, store.Environment{
		ID:             domain.MustNewID(domain.KindEnvironment).String(),
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		Slug:           slug,
		DisplayName:    slug + " environment",
		Kind:           kind,
	})
	if err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	return row
}

func insertJobsTestService(ctx context.Context, t *testing.T, tx *store.Tx, org store.Organization, project store.Project, env store.Environment, slug, kind string) store.Service {
	t.Helper()
	row, err := store.NewServiceRepository().Insert(ctx, tx, store.Service{
		ID:             domain.MustNewID(domain.KindService).String(),
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		Slug:           slug,
		DisplayName:    slug + " service",
		Kind:           kind,
	})
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	return row
}

func insertJobsTestDeployment(ctx context.Context, t *testing.T, tx *store.Tx, org store.Organization, project store.Project, env store.Environment, svc store.Service) store.Deployment {
	t.Helper()
	row, err := store.NewDeploymentRepository().Insert(ctx, tx, store.Deployment{
		ID:             domain.MustNewID(domain.KindDeployment).String(),
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      "main",
		RequestedBy:    "usr_ada",
		IdempotencyKey: "deployment-" + svc.ID,
		RequestID:      "req_deployment",
		CorrelationID:  "corr_deployment",
	})
	if err != nil {
		t.Fatalf("insert deployment: %v", err)
	}
	return row
}

func insertJobsTestPreview(ctx context.Context, t *testing.T, tx *store.Tx, org store.Organization, project store.Project, previewEnv, sourceEnv store.Environment) store.PreviewEnvironment {
	t.Helper()
	row, err := store.NewPreviewEnvironmentRepository().Insert(ctx, tx, store.PreviewEnvironment{
		ID:                  domain.MustNewID(domain.KindPreviewEnvironment).String(),
		OrganizationID:      org.ID,
		ProjectID:           project.ID,
		EnvironmentID:       previewEnv.ID,
		SourceEnvironmentID: sourceEnv.ID,
		DisplayName:         "Pull request 42",
		ChangeRef:           "refs/pull/42/head",
	})
	if err != nil {
		t.Fatalf("insert preview: %v", err)
	}
	return row
}
