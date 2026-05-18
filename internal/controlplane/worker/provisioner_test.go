package worker_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestEnsureDokployOrganizationPayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeEnsureDokployOrganization,
				Payload:        map[string]string{"organization_id": "org_valid"},
			},
		},
		{
			name: "missing payload organization",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeEnsureDokployOrganization,
				Payload:        map[string]string{},
			},
			wantErr: true,
		},
		{
			name: "cross tenant payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeEnsureDokployOrganization,
				Payload:        map[string]string{"organization_id": "org_other"},
			},
			wantErr: true,
		},
		{
			name: "resource scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_forbidden",
				JobType:        worker.JobTypeEnsureDokployOrganization,
				Payload:        map[string]string{"organization_id": "org_valid"},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseEnsureDokployOrganizationPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureDokployOrganizationPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureDokployOrganizationPayload returned %v, want nil", err)
			}
		})
	}
}

func TestEnsureProjectPayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				JobType:        worker.JobTypeEnsureProject,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
				},
			},
		},
		{
			name: "missing payload project",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				JobType:        worker.JobTypeEnsureProject,
				Payload:        map[string]string{"organization_id": "org_valid"},
			},
			wantErr: true,
		},
		{
			name: "cross tenant payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				JobType:        worker.JobTypeEnsureProject,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross project payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				JobType:        worker.JobTypeEnsureProject,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_other",
				},
			},
			wantErr: true,
		},
		{
			name: "lower resource scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_forbidden",
				JobType:        worker.JobTypeEnsureProject,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseEnsureProjectPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureProjectPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureProjectPayload returned %v, want nil", err)
			}
		})
	}
}

func TestEnsureEnvironmentPayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
				},
			},
		},
		{
			name: "missing payload environment",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross tenant payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross project payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_other",
					"environment_id":  "env_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross environment payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_other",
				},
			},
			wantErr: true,
		},
		{
			name: "lower resource scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_forbidden",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseEnsureEnvironmentPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureEnvironmentPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureEnvironmentPayload returned %v, want nil", err)
			}
		})
	}
}

func TestProvisionerEnsuresDokployOrganizationAndPersistsMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureOrgJob(org)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_dokploy_organization: %v", err)
	}

	refs := listOrgRefs(ctx, t, dataStore, org.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindOrganization ||
		refs[0].YallaID != org.ID ||
		refs[0].DokployResource != store.DokployResourceOrganization ||
		refs[0].DokployID != "org_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/api/organizations" {
		t.Fatalf("fake requests = %+v, want one POST /api/organizations", reqs)
	}
	if reqs[0].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[0].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_dokploy_organization: %v", err)
	}
	refs = listOrgRefs(ctx, t, dataStore, org.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 2 || reqs[1].Method != http.MethodGet || reqs[1].Path != "/api/organizations/org_1" {
		t.Fatalf("after replay fake requests = %+v, want second GET /api/organizations/org_1", reqs)
	}
}

func TestProvisionerEnsuresProjectAndPersistsMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureOrg(ctx, t, dataStore, client, org); err != nil {
		t.Fatalf("seed parent dokploy organization: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureProjectJob(project)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_project: %v", err)
	}

	refs := listProjectRefs(ctx, t, dataStore, project.OrganizationID, project.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindProject ||
		refs[0].YallaID != project.ID ||
		refs[0].DokployResource != store.DokployResourceProject ||
		refs[0].DokployID != "proj_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 2 || reqs[1].Method != http.MethodPost || reqs[1].Path != "/api/projects" {
		t.Fatalf("fake requests = %+v, want org seed then POST /api/projects", reqs)
	}
	if reqs[1].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[1].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_project: %v", err)
	}
	refs = listProjectRefs(ctx, t, dataStore, project.OrganizationID, project.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 3 || reqs[2].Method != http.MethodGet || reqs[2].Path != "/api/projects/proj_1" {
		t.Fatalf("after replay fake requests = %+v, want third GET /api/projects/proj_1", reqs)
	}
}

func TestProvisionerEnsuresEnvironmentAndPersistsMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, org, project); err != nil {
		t.Fatalf("seed parent dokploy project: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureEnvironmentJob(env)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_environment: %v", err)
	}

	refs := listEnvironmentRefs(ctx, t, dataStore, env.OrganizationID, env.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindEnvironment ||
		refs[0].YallaID != env.ID ||
		refs[0].DokployResource != store.DokployResourceEnvironment ||
		refs[0].DokployID != "env_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 3 || reqs[2].Method != http.MethodPost || reqs[2].Path != "/api/environments" {
		t.Fatalf("fake requests = %+v, want org/project seeds then POST /api/environments", reqs)
	}
	if reqs[2].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[2].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_environment: %v", err)
	}
	refs = listEnvironmentRefs(ctx, t, dataStore, env.OrganizationID, env.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodGet || reqs[3].Path != "/api/environments/env_1" {
		t.Fatalf("after replay fake requests = %+v, want fourth GET /api/environments/env_1", reqs)
	}
}

func TestProvisionerEnsureProjectRetryableFailureDoesNotPersistMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureOrg(ctx, t, dataStore, client, org); err != nil {
		t.Fatalf("seed parent dokploy organization: %v", err)
	}
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, ensureProjectJob(project))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listProjectRefs(ctx, t, dataStore, project.OrganizationID, project.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestEnsureProjectRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureOrg(ctx, t, dataStore, client, org); err != nil {
		t.Fatalf("seed parent dokploy organization: %v", err)
	}
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	jobs := store.NewJobRepository()
	enqueued := ensureProjectJob(project)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert ensure_project job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}
	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if lease == nil {
		t.Fatal("Claim returned nil lease")
	}
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run: %v", err)
	}

	var persisted store.ProvisioningJob
	if err := dataStore.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		persisted, getErr = jobs.Get(ctx, q, enqueued.OrganizationID, enqueued.ID)
		return getErr
	}); err != nil {
		t.Fatalf("read persisted job: %v", err)
	}
	if persisted.Status != store.JobStatusRetrying {
		t.Fatalf("persisted status = %s, want retrying", persisted.Status)
	}
	if persisted.ErrorSummary == "" {
		t.Fatal("persisted error summary is empty")
	}
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("persisted error summary leaked Dokploy token: %q", persisted.ErrorSummary)
	}
	if strings.Contains(persisted.ErrorSummary, "Authorization") {
		t.Fatalf("persisted error summary leaked auth header name: %q", persisted.ErrorSummary)
	}
	if refs := listProjectRefs(ctx, t, dataStore, project.OrganizationID, project.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestProvisionerEnsureEnvironmentRetryableFailureDoesNotPersistMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, org, project); err != nil {
		t.Fatalf("seed parent dokploy project: %v", err)
	}
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, ensureEnvironmentJob(env))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, env.OrganizationID, env.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestEnsureEnvironmentRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, org, project); err != nil {
		t.Fatalf("seed parent dokploy project: %v", err)
	}
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	jobs := store.NewJobRepository()
	enqueued := ensureEnvironmentJob(env)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert ensure_environment job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-env-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}
	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if lease == nil {
		t.Fatal("Claim returned nil lease")
	}
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run: %v", err)
	}

	var persisted store.ProvisioningJob
	if err := dataStore.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		persisted, getErr = jobs.Get(ctx, q, enqueued.OrganizationID, enqueued.ID)
		return getErr
	}); err != nil {
		t.Fatalf("read persisted job: %v", err)
	}
	if persisted.Status != store.JobStatusRetrying {
		t.Fatalf("persisted status = %s, want retrying", persisted.Status)
	}
	if persisted.ErrorSummary == "" {
		t.Fatal("persisted error summary is empty")
	}
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("persisted error summary leaked Dokploy token: %q", persisted.ErrorSummary)
	}
	if strings.Contains(persisted.ErrorSummary, "Authorization") {
		t.Fatalf("persisted error summary leaked auth header name: %q", persisted.ErrorSummary)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, env.OrganizationID, env.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestProvisionerEnsureProjectRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureOrg(ctx, t, dataStore, client, org); err != nil {
		t.Fatalf("seed parent dokploy organization: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureProjectJob(project)
	job.DesiredVersion = project.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listProjectRefs(ctx, t, dataStore, project.OrganizationID, project.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 1 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureEnvironmentRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, org, project); err != nil {
		t.Fatalf("seed parent dokploy project: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureEnvironmentJob(env)
	job.DesiredVersion = env.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, env.OrganizationID, env.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureProjectMissingProjectIsTerminalNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureOrg(ctx, t, dataStore, client, org); err != nil {
		t.Fatalf("seed parent dokploy organization: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	missingID, err := domain.NewID(domain.KindProject)
	if err != nil {
		t.Fatalf("domain.NewID(project): %v", err)
	}
	missingProjectID := missingID.String()
	err = p.Run(ctx, store.ProvisioningJob{
		ID:             "job_missing_project",
		OrganizationID: org.ID,
		ProjectID:      missingProjectID,
		JobType:        worker.JobTypeEnsureProject,
		DesiredVersion: 1,
		IdempotencyKey: "ensure-project-" + missingProjectID,
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      missingProjectID,
		},
	})
	if err == nil {
		t.Fatal("Run returned nil, want not-found")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("not-found error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 1 {
		t.Fatalf("missing project called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureEnvironmentMissingEnvironmentIsTerminalNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, org, project); err != nil {
		t.Fatalf("seed parent dokploy project: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	missingID, err := domain.NewID(domain.KindEnvironment)
	if err != nil {
		t.Fatalf("domain.NewID(environment): %v", err)
	}
	missingEnvironmentID := missingID.String()
	err = p.Run(ctx, store.ProvisioningJob{
		ID:             "job_missing_environment",
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  missingEnvironmentID,
		JobType:        worker.JobTypeEnsureEnvironment,
		DesiredVersion: 1,
		IdempotencyKey: "ensure-environment-" + missingEnvironmentID,
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
			"environment_id":  missingEnvironmentID,
		},
	})
	if err == nil {
		t.Fatal("Run returned nil, want not-found")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("not-found error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("missing environment called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureProjectCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, store.ProvisioningJob{
		OrganizationID: "org_valid",
		ProjectID:      "proj_valid",
		JobType:        worker.JobTypeEnsureProject,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerEnsureEnvironmentCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, store.ProvisioningJob{
		OrganizationID: "org_valid",
		ProjectID:      "proj_valid",
		EnvironmentID:  "env_valid",
		JobType:        worker.JobTypeEnsureEnvironment,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerEnsureDokployOrganizationRetryableFailureDoesNotPersistMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")

	fake := dokployfake.New()
	defer fake.Close()
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))
	client := newWorkerDokployClient(t, fake)

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, ensureOrgJob(org))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listOrgRefs(ctx, t, dataStore, org.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestProvisionerEnsureDokployOrganizationRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureOrgJob(org)
	job.DesiredVersion = org.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listOrgRefs(ctx, t, dataStore, org.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 0 {
		t.Fatalf("stale job called Dokploy: %+v", reqs)
	}
}

func TestProvisionerEnsureDokployOrganizationCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, store.ProvisioningJob{
		OrganizationID: "org_valid",
		JobType:        worker.JobTypeEnsureDokployOrganization,
		Payload:        map[string]string{"organization_id": "org_valid"},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

type canceledClient struct{}

func (canceledClient) EnsureOrganization(context.Context, dokploy.EnsureOrganizationInput) (dokploy.Organization, error) {
	return dokploy.Organization{}, context.Canceled
}

func (canceledClient) EnsureProject(context.Context, dokploy.EnsureProjectInput) (dokploy.Project, error) {
	return dokploy.Project{}, context.Canceled
}

func (canceledClient) EnsureEnvironment(context.Context, dokploy.EnsureEnvironmentInput) (dokploy.Environment, error) {
	return dokploy.Environment{}, context.Canceled
}

func newWorkerDokployClient(t *testing.T, fake *dokployfake.Server) *dokploy.Client {
	t.Helper()
	client, err := dokploy.New(dokploy.Config{
		BaseURL: fake.URL(),
		Token:   fake.Token(),
	})
	if err != nil {
		t.Fatalf("dokploy.New: %v", err)
	}
	return client
}

func insertWorkerOrg(ctx context.Context, t *testing.T, s *store.Store, label string) store.Organization {
	t.Helper()
	f := testutil.NewFactory(t)
	fixture := f.Organization(label)
	repo := store.NewOrganizationRepository()
	var org store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		org, err = repo.Insert(ctx, tx, store.Organization{
			ID:          fixture.ID,
			Slug:        fixture.Slug,
			DisplayName: fixture.Name,
		})
		return err
	}); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	return org
}

func ensureOrgJob(org store.Organization) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_test",
		OrganizationID: org.ID,
		JobType:        worker.JobTypeEnsureDokployOrganization,
		DesiredVersion: org.Version,
		IdempotencyKey: "ensure-org-" + org.ID,
		Payload:        map[string]string{"organization_id": org.ID},
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}
}

func ensureProjectJob(project store.Project) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_project_test",
		OrganizationID: project.OrganizationID,
		ProjectID:      project.ID,
		JobType:        worker.JobTypeEnsureProject,
		DesiredVersion: project.Version,
		IdempotencyKey: "ensure-project-" + project.ID,
		Payload: map[string]string{
			"organization_id": project.OrganizationID,
			"project_id":      project.ID,
		},
		RequestID:     "req_project_test",
		CorrelationID: "corr_project_test",
	}
}

func ensureEnvironmentJob(env store.Environment) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_environment_test",
		OrganizationID: env.OrganizationID,
		ProjectID:      env.ProjectID,
		EnvironmentID:  env.ID,
		JobType:        worker.JobTypeEnsureEnvironment,
		DesiredVersion: env.Version,
		IdempotencyKey: "ensure-environment-" + env.ID,
		Payload: map[string]string{
			"organization_id": env.OrganizationID,
			"project_id":      env.ProjectID,
			"environment_id":  env.ID,
		},
		RequestID:     "req_environment_test",
		CorrelationID: "corr_environment_test",
	}
}

func pRunEnsureOrg(ctx context.Context, t *testing.T, s *store.Store, client *dokploy.Client, org store.Organization) error {
	t.Helper()
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  s,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		return err
	}
	return p.Run(ctx, ensureOrgJob(org))
}

func pRunEnsureProjectWithParent(ctx context.Context, t *testing.T, s *store.Store, client *dokploy.Client, org store.Organization, project store.Project) error {
	t.Helper()
	if err := pRunEnsureOrg(ctx, t, s, client, org); err != nil {
		return err
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  s,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		return err
	}
	return p.Run(ctx, ensureProjectJob(project))
}

func insertWorkerProject(ctx context.Context, t *testing.T, s *store.Store, org store.Organization, label string) store.Project {
	t.Helper()
	f := testutil.NewFactory(t)
	fixture := f.Project(testutil.Organization{ID: org.ID}, label)
	repo := store.NewProjectRepository()
	var project store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		project, err = repo.Insert(ctx, tx, store.Project{
			ID:             fixture.ID,
			OrganizationID: org.ID,
			Slug:           fixture.Slug,
			DisplayName:    fixture.Name,
		})
		return err
	}); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	return project
}

func insertWorkerEnvironment(ctx context.Context, t *testing.T, s *store.Store, project store.Project, label string) store.Environment {
	t.Helper()
	f := testutil.NewFactory(t)
	fixture := f.Environment(testutil.Project{ID: project.ID, OrganizationID: project.OrganizationID}, label)
	repo := store.NewEnvironmentRepository()
	var env store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		env, err = repo.Insert(ctx, tx, store.Environment{
			ID:             fixture.ID,
			OrganizationID: project.OrganizationID,
			ProjectID:      project.ID,
			Slug:           fixture.Slug,
			DisplayName:    fixture.Name,
			Kind:           store.EnvironmentKindStandard,
		})
		return err
	}); err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	return env
}

func listOrgRefs(ctx context.Context, t *testing.T, s *store.Store, organizationID string) []store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var refs []store.DokployRef
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = repo.ListByYallaResource(ctx, q, organizationID, store.YallaKindOrganization, organizationID)
		return err
	}); err != nil {
		t.Fatalf("list dokploy refs: %v", err)
	}
	return refs
}

func listProjectRefs(ctx context.Context, t *testing.T, s *store.Store, organizationID, projectID string) []store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var refs []store.DokployRef
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = repo.ListByYallaResource(ctx, q, organizationID, store.YallaKindProject, projectID)
		return err
	}); err != nil {
		t.Fatalf("list project dokploy refs: %v", err)
	}
	return refs
}

func listEnvironmentRefs(ctx context.Context, t *testing.T, s *store.Store, organizationID, environmentID string) []store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var refs []store.DokployRef
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = repo.ListByYallaResource(ctx, q, organizationID, store.YallaKindEnvironment, environmentID)
		return err
	}); err != nil {
		t.Fatalf("list environment dokploy refs: %v", err)
	}
	return refs
}
