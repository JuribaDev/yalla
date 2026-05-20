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
	"github.com/JuribaDev/yalla/internal/controlplane/migrateimport"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
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

func TestImportDokployResourcePayloadValidation(t *testing.T) {
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
				JobType:        worker.JobTypeImportDokployResource,
				Payload: map[string]string{
					"organization_id":           "org_valid",
					"yalla_organization_id":     "org_valid",
					"dokploy_organization_id":   "dokploy_org_valid",
					"assignment_dokploy_org_id": "dokploy_org_valid",
				},
			},
		},
		{
			name: "missing dokploy organization",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeImportDokployResource,
				Payload: map[string]string{
					"organization_id":       "org_valid",
					"yalla_organization_id": "org_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross tenant payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeImportDokployResource,
				Payload: map[string]string{
					"organization_id":         "org_other",
					"yalla_organization_id":   "org_valid",
					"dokploy_organization_id": "dokploy_org_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross yalla owner",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				JobType:        worker.JobTypeImportDokployResource,
				Payload: map[string]string{
					"organization_id":         "org_valid",
					"yalla_organization_id":   "org_other",
					"dokploy_organization_id": "dokploy_org_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "resource scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_forbidden",
				JobType:        worker.JobTypeImportDokployResource,
				Payload: map[string]string{
					"organization_id":         "org_valid",
					"yalla_organization_id":   "org_valid",
					"dokploy_organization_id": "dokploy_org_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseImportDokployResourcePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseImportDokployResourcePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseImportDokployResourcePayload returned %v, want nil", err)
			}
		})
	}
}

func TestProvisionerImportDokployResourceImportsHierarchyAndIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "import owner")
	scanner := &fakeImportScanner{snapshot: importSnapshot("dokploy_org_import")}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:         dataStore,
		Client:        canceledClient{},
		ImportScanner: scanner,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := importDokployResourceJob(org, "dokploy_org_import")
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run import: %v", err)
	}
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run import replay: %v", err)
	}
	if scanner.calls != 2 {
		t.Fatalf("scanner calls = %d, want 2", scanner.calls)
	}
	projects := listWorkerProjects(ctx, t, dataStore, org.ID)
	if len(projects) != 1 {
		t.Fatalf("imported projects = %d, want 1", len(projects))
	}
	envs := listWorkerEnvironments(ctx, t, dataStore, org.ID, projects[0].ID)
	if len(envs) != 1 {
		t.Fatalf("imported environments = %d, want 1", len(envs))
	}
	services := listWorkerServices(ctx, t, dataStore, org.ID, envs[0].ID)
	if len(services) != 1 {
		t.Fatalf("imported services = %d, want 1", len(services))
	}
	if got := len(listProjectRefs(ctx, t, dataStore, org.ID, projects[0].ID)); got != 1 {
		t.Fatalf("project refs = %d, want 1", got)
	}
	if got := len(listEnvironmentRefs(ctx, t, dataStore, org.ID, envs[0].ID)); got != 1 {
		t.Fatalf("environment refs = %d, want 1", got)
	}
	if got := len(listServiceRefs(ctx, t, dataStore, org.ID, services[0].ID)); got != 1 {
		t.Fatalf("service refs = %d, want 1", got)
	}
}

func TestProvisionerImportDokployResourceRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "import stale")
	scanner := &fakeImportScanner{snapshot: importSnapshot("dokploy_org_stale")}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:         dataStore,
		Client:        canceledClient{},
		ImportScanner: scanner,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	job := importDokployResourceJob(org, "dokploy_org_stale")
	job.DesiredVersion = org.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if scanner.calls != 0 {
		t.Fatalf("stale job called scanner %d times, want 0", scanner.calls)
	}
	if projects := listWorkerProjects(ctx, t, dataStore, org.ID); len(projects) != 0 {
		t.Fatalf("projects after stale import = %d, want 0", len(projects))
	}
}

func TestProvisionerImportDokployResourceRetryableScannerFailureDoesNotPersist(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "import retry")
	scanner := &fakeImportScanner{err: apierr.DokployUnavailable(errors.New("upstream token dkp_secret_0123456789abcdef unavailable"))}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:         dataStore,
		Client:        canceledClient{},
		ImportScanner: scanner,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, importDokployResourceJob(org, "dokploy_org_retry"))
	if err == nil {
		t.Fatal("Run returned nil, want retryable scanner error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("scanner failure is terminal: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("scanner failure is not retryable: %v", err)
	}
	if strings.Contains(err.Error(), "dkp_secret_0123456789abcdef") {
		t.Fatalf("scanner error leaked secret: %v", err)
	}
	if projects := listWorkerProjects(ctx, t, dataStore, org.ID); len(projects) != 0 {
		t.Fatalf("projects after failed import = %d, want 0", len(projects))
	}
}

func TestProvisionerImportDokployResourceCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:         dataStore,
		Client:        canceledClient{},
		ImportScanner: &fakeImportScanner{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, store.ProvisioningJob{
		OrganizationID: "org_valid",
		JobType:        worker.JobTypeImportDokployResource,
		Payload: map[string]string{
			"organization_id":         "org_valid",
			"yalla_organization_id":   "org_valid",
			"dokploy_organization_id": "dokploy_org_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
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

func TestCreatePreviewEnvironmentPayloadValidation(t *testing.T) {
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
				JobType:        worker.JobTypeCreatePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
		},
		{
			name: "missing preview id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeCreatePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				JobType:        worker.JobTypeCreatePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "service scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_forbidden",
				JobType:        worker.JobTypeCreatePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseCreatePreviewEnvironmentPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseCreatePreviewEnvironmentPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCreatePreviewEnvironmentPayload returned error: %v", err)
			}
		})
	}
}

func TestDeletePreviewEnvironmentPayloadValidation(t *testing.T) {
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
				JobType:        worker.JobTypeDeletePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
		},
		{
			name: "missing preview id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeDeletePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				JobType:        worker.JobTypeDeletePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "service scoped job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_forbidden",
				JobType:        worker.JobTypeDeletePreviewEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"preview_id":      "penv_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseDeletePreviewEnvironmentPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseDeletePreviewEnvironmentPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDeletePreviewEnvironmentPayload returned %v, want nil", err)
			}
		})
	}
}

func TestEnsureApplicationServicePayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing payload service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_other",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_other",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross service payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_other",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseEnsureApplicationServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureApplicationServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureApplicationServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestEnsureComposeServicePayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing payload service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_other",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_other",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross service payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureComposeService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_other",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeEnsureApplicationService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseEnsureComposeServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureComposeServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureComposeServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestEnsureDatabaseServicePayloadValidation(t *testing.T) {
	t.Parallel()

	validJob := store.ProvisioningJob{
		OrganizationID: "org_valid",
		ProjectID:      "proj_valid",
		EnvironmentID:  "env_valid",
		ServiceID:      "svc_valid",
		JobType:        worker.JobTypeEnsureDatabaseService,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"service_id":      "svc_valid",
			"engine":          dokploy.EnginePostgres,
		},
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*store.ProvisioningJob)
		wantErr bool
	}{
		{name: "valid"},
		{
			name: "missing payload service",
			mutate: func(job *store.ProvisioningJob) {
				delete(job.Payload, "service_id")
			},
			wantErr: true,
		},
		{
			name: "cross tenant payload",
			mutate: func(job *store.ProvisioningJob) {
				job.Payload["organization_id"] = "org_other"
			},
			wantErr: true,
		},
		{
			name: "cross project payload",
			mutate: func(job *store.ProvisioningJob) {
				job.Payload["project_id"] = "proj_other"
			},
			wantErr: true,
		},
		{
			name: "cross environment payload",
			mutate: func(job *store.ProvisioningJob) {
				job.Payload["environment_id"] = "env_other"
			},
			wantErr: true,
		},
		{
			name: "cross service payload",
			mutate: func(job *store.ProvisioningJob) {
				job.Payload["service_id"] = "svc_other"
			},
			wantErr: true,
		},
		{
			name: "missing engine",
			mutate: func(job *store.ProvisioningJob) {
				delete(job.Payload, "engine")
			},
			wantErr: true,
		},
		{
			name: "unsupported engine",
			mutate: func(job *store.ProvisioningJob) {
				job.Payload["engine"] = "sqlite"
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			mutate: func(job *store.ProvisioningJob) {
				job.JobType = worker.JobTypeEnsureComposeService
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			job := validJob
			job.Payload = map[string]string{}
			for k, v := range validJob.Payload {
				job.Payload[k] = v
			}
			if tc.mutate != nil {
				tc.mutate(&job)
			}
			_, err := worker.ParseEnsureDatabaseServicePayload(job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseEnsureDatabaseServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnsureDatabaseServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestDeployServicePayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid service deploy job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeployService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"deployment_id":   "dep_valid",
				},
			},
		},
		{
			name: "valid prd alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeployServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"deployment_id":   "dep_valid",
				},
			},
		},
		{
			name: "missing deployment id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeployService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeployService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"deployment_id":   "dep_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseDeployServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseDeployServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDeployServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestRestartServicePayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid service restart job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestartService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "valid prd alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestartServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing service id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeRestartService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestartService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseRestartServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseRestartServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRestartServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestDeleteServicePayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeleteService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeleteServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing payload service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeleteService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeDeleteService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseDeleteServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseDeleteServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDeleteServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestDeleteEnvironmentPayloadValidation(t *testing.T) {
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
				JobType:        worker.JobTypeDeleteEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
				},
			},
		},
		{
			name: "alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeDeleteEnvironmentAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
				},
			},
		},
		{
			name: "service id must be empty",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_invalid",
				JobType:        worker.JobTypeDeleteEnvironment,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				JobType:        worker.JobTypeDeleteEnvironment,
				Payload: map[string]string{
					"organization_id": "org_other",
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
			_, err := worker.ParseDeleteEnvironmentPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseDeleteEnvironmentPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDeleteEnvironmentPayload returned %v, want nil", err)
			}
		})
	}
}

func TestDeleteProjectPayloadValidation(t *testing.T) {
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
				JobType:        worker.JobTypeDeleteProject,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
				},
			},
		},
		{
			name: "alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				JobType:        worker.JobTypeDeleteProjectAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
				},
			},
		},
		{
			name: "environment id must be empty",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_invalid",
				JobType:        worker.JobTypeDeleteProject,
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
				JobType:        worker.JobTypeDeleteProject,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseDeleteProjectPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseDeleteProjectPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDeleteProjectPayload returned %v, want nil", err)
			}
		})
	}
}

func TestRollbackServicePayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRollbackService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRollbackServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing payload service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRollbackService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRollbackService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseRollbackServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseRollbackServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRollbackServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestStopServicePayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid service stop job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStopService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "valid prd alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStopServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing service id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeStopService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStopService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseStopServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseStopServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStopServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestStartServicePayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid service start job",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStartService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "valid prd alias",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStartServiceAlias,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing service id",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				JobType:        worker.JobTypeStartService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeStartService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseStartServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseStartServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStartServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestSyncVariablesPayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeSyncVariables,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "missing payload service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeSyncVariables,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeSyncVariables,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeSyncDomains,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseSyncVariablesPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseSyncVariablesPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSyncVariablesPayload returned %v, want nil", err)
			}
		})
	}
}

func TestRunBackupPayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRunBackup,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
		},
		{
			name: "missing backup",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRunBackup,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRunBackup,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeSyncVariables,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseRunBackupPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseRunBackupPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRunBackupPayload returned %v, want nil", err)
			}
		})
	}
}

func TestRestoreBackupPayloadValidation(t *testing.T) {
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestoreBackup,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
		},
		{
			name: "missing backup",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestoreBackup,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRestoreBackup,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "wrong job type",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeRunBackup,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"backup_id":       "bkp_valid",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseRestoreBackupPayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseRestoreBackupPayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRestoreBackupPayload returned %v, want nil", err)
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

func TestProvisionerCreatesPreviewEnvironmentAndPersistsMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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

	job := createPreviewEnvironmentJob(preview)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run create_preview_environment: %v", err)
	}

	refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID)
	if len(refs) != 1 {
		t.Fatalf("preview environment dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindEnvironment ||
		refs[0].YallaID != preview.EnvironmentID ||
		refs[0].DokployResource != store.DokployResourceEnvironment ||
		refs[0].DokployID != "env_1" {
		t.Fatalf("unexpected preview environment dokploy ref: %+v", refs[0])
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, source.OrganizationID, source.ID); len(refs) != 0 {
		t.Fatalf("source environment refs count = %d, want 0", len(refs))
	}

	reqs := fake.Requests()
	if len(reqs) != 3 || reqs[2].Method != http.MethodPost || reqs[2].Path != "/api/environments" {
		t.Fatalf("fake requests = %+v, want org/project seeds then POST /api/environments", reqs)
	}
	if reqs[2].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[2].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run create_preview_environment: %v", err)
	}
	refs = listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID)
	if len(refs) != 1 {
		t.Fatalf("after replay preview environment dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodGet || reqs[3].Path != "/api/environments/env_1" {
		t.Fatalf("after replay fake requests = %+v, want fourth GET /api/environments/env_1", reqs)
	}
}

func TestProvisionerCreatePreviewEnvironmentRetryableFailureDoesNotPersistMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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

	err = p.Run(ctx, createPreviewEnvironmentJob(preview))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 0 {
		t.Fatalf("preview environment dokploy refs count after failed create = %d, want 0", len(refs))
	}
}

func TestCreatePreviewEnvironmentRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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
	enqueued := createPreviewEnvironmentJob(preview)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert create_preview_environment job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-preview-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 0 {
		t.Fatalf("preview environment dokploy refs count after failed create = %d, want 0", len(refs))
	}
}

func TestProvisionerCreatePreviewEnvironmentRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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

	job := createPreviewEnvironmentJob(preview)
	job.DesiredVersion = preview.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 0 {
		t.Fatalf("preview environment dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerCreatePreviewEnvironmentCrossTenantPayloadIsTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	orgA := insertWorkerOrg(ctx, t, dataStore, "acme")
	projectA := insertWorkerProject(ctx, t, dataStore, orgA, "api")
	orgB := insertWorkerOrg(ctx, t, dataStore, "other")
	projectB := insertWorkerProject(ctx, t, dataStore, orgB, "api")
	sourceB := insertWorkerEnvironment(ctx, t, dataStore, projectB, "production")
	previewB := insertWorkerPreviewEnvironment(ctx, t, dataStore, projectB, sourceB, "pr-42")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, orgA, projectA); err != nil {
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

	job := store.ProvisioningJob{
		ID:             "job_cross_tenant_preview",
		OrganizationID: orgA.ID,
		ProjectID:      projectA.ID,
		EnvironmentID:  previewB.EnvironmentID,
		JobType:        worker.JobTypeCreatePreviewEnvironment,
		DesiredVersion: previewB.Version,
		IdempotencyKey: "create-preview-environment-cross-tenant",
		Payload: map[string]string{
			"organization_id": orgA.ID,
			"project_id":      projectA.ID,
			"environment_id":  previewB.EnvironmentID,
			"preview_id":      previewB.ID,
		},
	}
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want cross-tenant not-found")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant error is not terminal: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, previewB.OrganizationID, previewB.EnvironmentID); len(refs) != 0 {
		t.Fatalf("foreign preview environment refs count = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("cross-tenant job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerCreatePreviewEnvironmentCancellationIsNotTerminal(t *testing.T) {
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
		JobType:        worker.JobTypeCreatePreviewEnvironment,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"preview_id":      "penv_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerCreatePreviewEnvironmentSucceededJobIsNoop(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(context.Background(), store.ProvisioningJob{
		Status:  store.JobStatusSucceeded,
		JobType: worker.JobTypeCreatePreviewEnvironment,
	})
	if err != nil {
		t.Fatalf("succeeded create_preview_environment job returned error: %v", err)
	}
}

func TestProvisionerDeletesPreviewEnvironmentAndCleansMapping(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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
	if err := p.Run(ctx, createPreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("Run create_preview_environment: %v", err)
	}
	preview = scheduleWorkerPreviewDeletion(ctx, t, dataStore, preview)

	if err := p.Run(ctx, deletePreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("Run delete_preview_environment: %v", err)
	}

	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 0 {
		t.Fatalf("preview environment dokploy refs count after delete = %d, want 0", len(refs))
	}
	assertPreviewEnvironmentMissing(ctx, t, dataStore, preview)

	reqs := fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodDelete || reqs[3].Path != "/api/environments/env_1" {
		t.Fatalf("fake requests = %+v, want org/project/create then DELETE /api/environments/env_1", reqs)
	}
	if reqs[3].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[3].AuthHeader)
	}

	if err := p.Run(ctx, deletePreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("replayed Run delete_preview_environment: %v", err)
	}
	if reqs = fake.Requests(); len(reqs) != 4 {
		t.Fatalf("replayed delete called Dokploy again: %+v", reqs)
	}
}

func TestProvisionerDeletePreviewEnvironmentRetryableFailureDoesNotCleanup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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
	if err := p.Run(ctx, createPreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("Run create_preview_environment: %v", err)
	}
	preview = scheduleWorkerPreviewDeletion(ctx, t, dataStore, preview)
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	err = p.Run(ctx, deletePreviewEnvironmentJob(preview))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 1 {
		t.Fatalf("preview environment dokploy refs count after failed delete = %d, want 1", len(refs))
	}
	if _, err := getWorkerPreviewEnvironment(ctx, dataStore, preview); err != nil {
		t.Fatalf("preview row after failed delete: %v", err)
	}
}

func TestDeletePreviewEnvironmentRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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
	if err := p.Run(ctx, createPreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("Run create_preview_environment: %v", err)
	}
	preview = scheduleWorkerPreviewDeletion(ctx, t, dataStore, preview)
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	jobs := store.NewJobRepository()
	enqueued := deletePreviewEnvironmentJob(preview)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert delete_preview_environment job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-delete-preview-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("error summary leaked token: %q", persisted.ErrorSummary)
	}
	if !strings.Contains(persisted.ErrorSummary, "Dokploy") {
		t.Fatalf("error summary = %q, want redacted Dokploy failure context", persisted.ErrorSummary)
	}
}

func TestProvisionerDeletePreviewEnvironmentRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	source := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	preview := insertWorkerPreviewEnvironment(ctx, t, dataStore, project, source, "pr-42")

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
	if err := p.Run(ctx, createPreviewEnvironmentJob(preview)); err != nil {
		t.Fatalf("Run create_preview_environment: %v", err)
	}
	preview = scheduleWorkerPreviewDeletion(ctx, t, dataStore, preview)

	job := deletePreviewEnvironmentJob(preview)
	job.DesiredVersion = preview.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listEnvironmentRefs(ctx, t, dataStore, preview.OrganizationID, preview.EnvironmentID); len(refs) != 1 {
		t.Fatalf("preview environment dokploy refs count after stale job = %d, want 1", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale job called Dokploy beyond create seed: %+v", reqs)
	}
}

func TestProvisionerDeletePreviewEnvironmentCrossTenantPayloadIsTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	orgA := insertWorkerOrg(ctx, t, dataStore, "acme")
	projectA := insertWorkerProject(ctx, t, dataStore, orgA, "api")
	orgB := insertWorkerOrg(ctx, t, dataStore, "other")
	projectB := insertWorkerProject(ctx, t, dataStore, orgB, "api")
	sourceB := insertWorkerEnvironment(ctx, t, dataStore, projectB, "production")
	previewB := insertWorkerPreviewEnvironment(ctx, t, dataStore, projectB, sourceB, "pr-42")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureProjectWithParent(ctx, t, dataStore, client, orgA, projectA); err != nil {
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

	job := store.ProvisioningJob{
		ID:             "job_cross_tenant_delete_preview",
		OrganizationID: orgA.ID,
		ProjectID:      projectA.ID,
		EnvironmentID:  previewB.EnvironmentID,
		JobType:        worker.JobTypeDeletePreviewEnvironment,
		DesiredVersion: previewB.Version,
		IdempotencyKey: "delete-preview-environment-cross-tenant",
		Payload: map[string]string{
			"organization_id": orgA.ID,
			"project_id":      projectA.ID,
			"environment_id":  previewB.EnvironmentID,
			"preview_id":      previewB.ID,
		},
	}
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want cross-tenant not-found")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant error is not terminal: %v", err)
	}
	if _, err := getWorkerPreviewEnvironment(ctx, dataStore, previewB); err != nil {
		t.Fatalf("foreign preview row after cross-tenant job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("cross-tenant job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerDeletePreviewEnvironmentCancellationIsNotTerminal(t *testing.T) {
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
		JobType:        worker.JobTypeDeletePreviewEnvironment,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"preview_id":      "penv_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerDeletePreviewEnvironmentSucceededJobIsNoop(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(context.Background(), store.ProvisioningJob{
		Status:  store.JobStatusSucceeded,
		JobType: worker.JobTypeDeletePreviewEnvironment,
	})
	if err != nil {
		t.Fatalf("succeeded delete_preview_environment job returned error: %v", err)
	}
}

func TestProvisionerEnsuresApplicationServiceAndPersistsMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureApplicationServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_application_service: %v", err)
	}

	refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindService ||
		refs[0].YallaID != svc.ID ||
		refs[0].DokployResource != store.DokployResourceApplication ||
		refs[0].DokployID != "app_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodPost || reqs[3].Path != "/api/applications" {
		t.Fatalf("fake requests = %+v, want org/project/environment seeds then POST /api/applications", reqs)
	}
	if reqs[3].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[3].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_application_service: %v", err)
	}
	refs = listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodGet || reqs[4].Path != "/api/applications/app_1" {
		t.Fatalf("after replay fake requests = %+v, want fifth GET /api/applications/app_1", reqs)
	}
}

func TestProvisionerEnsuresComposeServiceAndPersistsMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "stack", store.ServiceKindCompose)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureComposeServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_compose_service: %v", err)
	}

	refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindService ||
		refs[0].YallaID != svc.ID ||
		refs[0].DokployResource != store.DokployResourceCompose ||
		refs[0].DokployID != "compose_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodPost || reqs[3].Path != "/api/compose" {
		t.Fatalf("fake requests = %+v, want org/project/environment seeds then POST /api/compose", reqs)
	}
	if reqs[3].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[3].AuthHeader)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_compose_service: %v", err)
	}
	refs = listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodGet || reqs[4].Path != "/api/compose/compose_1" {
		t.Fatalf("after replay fake requests = %+v, want fifth GET /api/compose/compose_1", reqs)
	}
}

func TestProvisionerEnsuresDatabaseServiceAndPersistsMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "primary", store.ServiceKindDatabase)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureDatabaseServiceJob(svc, dokploy.EnginePostgres)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run ensure_database_service: %v", err)
	}

	refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("dokploy refs count = %d, want 1", len(refs))
	}
	if refs[0].YallaKind != store.YallaKindService ||
		refs[0].YallaID != svc.ID ||
		refs[0].DokployResource != store.DokployResourceDatabase ||
		refs[0].DokployID != "db_1" {
		t.Fatalf("unexpected dokploy ref: %+v", refs[0])
	}

	reqs := fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodPost || reqs[3].Path != "/api/databases" {
		t.Fatalf("fake requests = %+v, want org/project/environment seeds then POST /api/databases", reqs)
	}
	if reqs[3].AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", reqs[3].AuthHeader)
	}
	if !strings.Contains(reqs[3].Body, `"engine":"postgres"`) {
		t.Fatalf("database create body did not carry postgres engine: %s", reqs[3].Body)
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run ensure_database_service: %v", err)
	}
	refs = listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 {
		t.Fatalf("after replay dokploy refs count = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodGet || reqs[4].Path != "/api/databases/db_1" {
		t.Fatalf("after replay fake requests = %+v, want fifth GET /api/databases/db_1", reqs)
	}
}

func TestProvisionerSyncDomainsEnsuresDomainsAndPersistsMappings(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	domainA := insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")
	domainB := insertWorkerServiceDomain(ctx, t, dataStore, svc, "app.acme.test")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := syncDomainsJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run sync_domains: %v", err)
	}

	refsA := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainA.ID)
	refsB := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainB.ID)
	if len(refsA) != 1 || refsA[0].DokployResource != store.DokployResourceDomain || refsA[0].DokployID != "domain_1" {
		t.Fatalf("domain A refs = %+v, want one domain_1 mapping", refsA)
	}
	if len(refsB) != 1 || refsB[0].DokployResource != store.DokployResourceDomain || refsB[0].DokployID != "domain_2" {
		t.Fatalf("domain B refs = %+v, want one domain_2 mapping", refsB)
	}

	reqs := fake.Requests()
	if len(reqs) != 6 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/domains" ||
		reqs[5].Method != http.MethodPost || reqs[5].Path != "/api/domains" {
		t.Fatalf("fake requests = %+v, want service seed then two POST /api/domains", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("domain request recording leaked credentials: %+v", reqs[4])
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run sync_domains: %v", err)
	}
	reqs = fake.Requests()
	if len(reqs) != 8 || reqs[6].Method != http.MethodGet || reqs[6].Path != "/api/domains/domain_1" ||
		reqs[7].Method != http.MethodGet || reqs[7].Path != "/api/domains/domain_2" {
		t.Fatalf("replayed sync_domains fake requests = %+v, want GETs for existing domain refs", reqs)
	}
	if got := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainA.ID); len(got) != 1 {
		t.Fatalf("after replay domain A refs = %d, want 1", len(got))
	}
}

func TestProvisionerSyncDomainsRetryableFailureDoesNotPersistMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	domainRow := insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, syncDomainsJob(svc))
	if err == nil {
		t.Fatal("Run sync_domains returned nil, want retryable error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run sync_domains error is terminal, want retryable: %v", err)
	}
	if refs := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainRow.ID); len(refs) != 0 {
		t.Fatalf("domain refs after retryable failure = %+v, want none", refs)
	}
}

func TestProvisionerSyncDomainsRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	_ = insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := syncDomainsJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil || !worker.IsTerminal(err) {
		t.Fatalf("Run stale sync_domains = %v, want terminal error", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale sync_domains issued Dokploy requests: %+v", reqs)
	}
}

func TestProvisionerSyncDomainsCancellationIsNotTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	_ = insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_cancelled")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, syncDomainsJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run sync_domains cancellation = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run sync_domains cancellation is terminal: %v", err)
	}
}

func TestProvisionerSyncVariablesRendersEffectiveVariablesAndRedactsRequestRecording(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	provider := secrets.NewPlaintext()
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerOrganizationVariable(ctx, t, dataStore, org, "REGION", "us-east-1", false, provider)
	insertWorkerProjectVariable(ctx, t, dataStore, project, "LOG_LEVEL", "info", false, provider)
	insertWorkerEnvironmentVariable(ctx, t, dataStore, env, "LOG_LEVEL", "debug", false, provider)
	insertWorkerServiceVariable(ctx, t, dataStore, svc, "DATABASE_URL", "postgres://sync-variable-secret", true, provider)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:   dataStore,
		Client:  client,
		Mapper:  dokploy.NewMapper(),
		Secrets: provider,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := syncVariablesJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run sync_variables: %v", err)
	}

	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/application.saveEnvironment" {
		t.Fatalf("fake requests = %+v, want service seed then POST /application.saveEnvironment", reqs)
	}
	if strings.Contains(reqs[4].Body, "postgres://sync-variable-secret") || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("sync_variables request recording leaked secret material: %+v", reqs[4])
	}

	gotEnv := fake.ApplicationEnv("app_1")
	for _, want := range []string{"DATABASE_URL=postgres://sync-variable-secret", "LOG_LEVEL=debug", "REGION=us-east-1"} {
		if !strings.Contains(gotEnv, want) {
			t.Fatalf("synced env = %q, missing %q", gotEnv, want)
		}
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run sync_variables: %v", err)
	}
	reqs = fake.Requests()
	if len(reqs) != 6 || reqs[5].Method != http.MethodPost || reqs[5].Path != "/application.saveEnvironment" {
		t.Fatalf("replayed sync_variables fake requests = %+v, want idempotent second saveEnvironment", reqs)
	}
}

func TestProvisionerSyncVariablesRetryableFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	provider := secrets.NewPlaintext()
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerServiceVariable(ctx, t, dataStore, svc, "DATABASE_URL", "postgres://sync-variable-secret", true, provider)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:   dataStore,
		Client:  client,
		Mapper:  dokploy.NewMapper(),
		Secrets: provider,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, syncVariablesJob(svc))
	if err == nil {
		t.Fatal("Run sync_variables returned nil, want retryable error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run sync_variables error is terminal, want retryable: %v", err)
	}
	if gotEnv := fake.ApplicationEnv("app_1"); gotEnv != "" {
		t.Fatalf("application env after retryable failure = %q, want empty", gotEnv)
	}
}

func TestProvisionerSyncVariablesRefusesStaleDesiredVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	provider := secrets.NewPlaintext()
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerServiceVariable(ctx, t, dataStore, svc, "DATABASE_URL", "postgres://sync-variable-secret", true, provider)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:   dataStore,
		Client:  client,
		Mapper:  dokploy.NewMapper(),
		Secrets: provider,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := syncVariablesJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil || !worker.IsTerminal(err) {
		t.Fatalf("Run stale sync_variables = %v, want terminal error", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale sync_variables issued Dokploy requests: %+v", reqs)
	}
}

func TestProvisionerSyncVariablesCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	provider := secrets.NewPlaintext()
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerServiceVariable(ctx, t, dataStore, svc, "DATABASE_URL", "postgres://sync-variable-secret", true, provider)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_cancelled")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:   dataStore,
		Client:  canceledClient{},
		Mapper:  dokploy.NewMapper(),
		Secrets: provider,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, syncVariablesJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run sync_variables cancellation = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run sync_variables cancellation is terminal: %v", err)
	}
}

func TestReconcileServicePayloadValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		job     store.ProvisioningJob
		wantErr bool
	}{
		{
			name: "valid application",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeReconcileService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
		},
		{
			name: "valid database",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeReconcileService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
					"engine":          dokploy.EnginePostgres,
				},
			},
		},
		{
			name: "missing service",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeReconcileService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
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
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeReconcileService,
				Payload: map[string]string{
					"organization_id": "org_other",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_valid",
				},
			},
			wantErr: true,
		},
		{
			name: "cross service payload",
			job: store.ProvisioningJob{
				OrganizationID: "org_valid",
				ProjectID:      "proj_valid",
				EnvironmentID:  "env_valid",
				ServiceID:      "svc_valid",
				JobType:        worker.JobTypeReconcileService,
				Payload: map[string]string{
					"organization_id": "org_valid",
					"project_id":      "proj_valid",
					"environment_id":  "env_valid",
					"service_id":      "svc_other",
				},
			},
			wantErr: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.ParseReconcileServicePayload(tc.job)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseReconcileServicePayload returned nil, want validation error")
				}
				if !worker.IsTerminal(err) {
					t.Fatalf("validation error is not terminal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseReconcileServicePayload returned %v, want nil", err)
			}
		})
	}
}

func TestProvisionerReconcileServiceEnsuresServiceVariablesAndDomains(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	provider := secrets.NewPlaintext()
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	env := insertWorkerEnvironment(ctx, t, dataStore, project, "production")
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	domainRow := insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")
	insertWorkerOrganizationVariable(ctx, t, dataStore, org, "REGION", "us-east-1", false, provider)
	insertWorkerServiceVariable(ctx, t, dataStore, svc, "DATABASE_URL", "postgres://reconcile-service-secret", true, provider)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:   dataStore,
		Client:  client,
		Mapper:  dokploy.NewMapper(),
		Secrets: provider,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := reconcileServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run reconcile_service: %v", err)
	}

	refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID)
	if len(refs) != 1 || refs[0].DokployResource != store.DokployResourceApplication || refs[0].DokployID != "app_1" {
		t.Fatalf("service refs = %+v, want one app_1 mapping", refs)
	}
	domainRefs := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainRow.ID)
	if len(domainRefs) != 1 || domainRefs[0].DokployResource != store.DokployResourceDomain || domainRefs[0].DokployID != "domain_1" {
		t.Fatalf("domain refs = %+v, want one domain_1 mapping", domainRefs)
	}
	gotEnv := fake.ApplicationEnv("app_1")
	for _, want := range []string{"DATABASE_URL=postgres://reconcile-service-secret", "REGION=us-east-1"} {
		if !strings.Contains(gotEnv, want) {
			t.Fatalf("reconciled env = %q, missing %q", gotEnv, want)
		}
	}

	reqs := fake.Requests()
	if len(reqs) != 6 ||
		reqs[3].Method != http.MethodPost || reqs[3].Path != "/api/applications" ||
		reqs[4].Method != http.MethodPost || reqs[4].Path != "/application.saveEnvironment" ||
		reqs[5].Method != http.MethodPost || reqs[5].Path != "/api/domains" {
		t.Fatalf("fake requests = %+v, want parent seeds then service/env/domain reconciliation", reqs)
	}
	if strings.Contains(reqs[4].Body, "postgres://reconcile-service-secret") || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("reconcile_service request recording leaked secret material: %+v", reqs[4])
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run reconcile_service: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 1 {
		t.Fatalf("after replay service refs = %d, want 1", len(refs))
	}
	if refs := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainRow.ID); len(refs) != 1 {
		t.Fatalf("after replay domain refs = %d, want 1", len(refs))
	}
	reqs = fake.Requests()
	if len(reqs) != 9 ||
		reqs[6].Method != http.MethodGet || reqs[6].Path != "/api/applications/app_1" ||
		reqs[7].Method != http.MethodPost || reqs[7].Path != "/application.saveEnvironment" ||
		reqs[8].Method != http.MethodGet || reqs[8].Path != "/api/domains/domain_1" {
		t.Fatalf("replayed reconcile_service fake requests = %+v, want idempotent GET/sync/GET", reqs)
	}
}

func TestProvisionerReconcileServiceRetryableFailureDoesNotPersistMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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

	err = p.Run(ctx, reconcileServiceJob(svc))
	if err == nil {
		t.Fatal("Run reconcile_service returned nil, want retryable error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run reconcile_service error is terminal, want retryable: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("service refs after retryable failure = %+v, want none", refs)
	}
}

func TestProvisionerReconcileServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := reconcileServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil || !worker.IsTerminal(err) {
		t.Fatalf("Run stale reconcile_service = %v, want terminal error", err)
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale reconcile_service issued Dokploy requests: %+v", reqs)
	}
}

func TestProvisionerReconcileServiceCancellationIsNotTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerEnvironmentRef(ctx, t, dataStore, env, "env_cancelled")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, reconcileServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run reconcile_service cancellation = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run reconcile_service cancellation is terminal: %v", err)
	}
}

func TestReconcileServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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
	enqueued := reconcileServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert reconcile_service job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-reconcile-service-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("service refs after failed reconcile = %+v, want none", refs)
	}
}

func TestProvisionerRunBackupMarksBackupSucceeded(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	dokployServiceID := seedFakeDokployApplicationService(ctx, t, client)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, dokployServiceID)

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := runBackupJob(svc, backup)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run run_backup: %v", err)
	}
	updated := getWorkerServiceBackup(ctx, t, dataStore, svc, backup.ID)
	if updated.Status != store.ServiceBackupStatusSucceeded {
		t.Fatalf("backup status = %q, want %q", updated.Status, store.ServiceBackupStatusSucceeded)
	}
	if updated.LastRunAt == nil || updated.LastSucceededAt == nil {
		t.Fatalf("backup timestamps after run = last_run_at %v last_succeeded_at %v, want both populated", updated.LastRunAt, updated.LastSucceededAt)
	}

	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/services/app_1/backups" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/services/app_1/backups", reqs)
	}
	if reqs[4].AuthHeader != output.Sentinel || strings.Contains(reqs[4].Body, fake.Token()) {
		t.Fatalf("backup request recording leaked credentials: %+v", reqs[4])
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run run_backup: %v", err)
	}
	reqs = fake.Requests()
	if len(reqs) != 5 {
		t.Fatalf("replayed run_backup fake requests = %+v, want no additional Dokploy call", reqs)
	}
}

func TestProvisionerRunBackupRetryableFailureMarksBackupFailed(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	dokployServiceID := seedFakeDokployApplicationService(ctx, t, client)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, dokployServiceID)
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, runBackupJob(svc, backup))
	if err == nil {
		t.Fatal("Run run_backup returned nil, want retryable error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run run_backup error is terminal, want retryable: %v", err)
	}
	updated := getWorkerServiceBackup(ctx, t, dataStore, svc, backup.ID)
	if updated.Status != store.ServiceBackupStatusFailed {
		t.Fatalf("backup status after retryable failure = %q, want %q", updated.Status, store.ServiceBackupStatusFailed)
	}
	if updated.LastRunAt == nil {
		t.Fatalf("backup last_run_at after retryable failure is nil, want populated")
	}
}

func TestProvisionerRunBackupRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_stale")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	job := runBackupJob(svc, backup)
	job.DesiredVersion = backup.Version + 1
	err = p.Run(ctx, job)
	if err == nil || !worker.IsTerminal(err) {
		t.Fatalf("Run stale run_backup = %v, want terminal error", err)
	}
}

func TestProvisionerRunBackupCancellationIsNotTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_cancelled")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, runBackupJob(svc, backup))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run run_backup cancellation = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run run_backup cancellation is terminal: %v", err)
	}
}

func TestProvisionerRestoreBackupSucceedsAndReplaysFromSucceededJob(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	backup = markWorkerServiceBackupSucceeded(ctx, t, dataStore, svc, backup.ID)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	dokployServiceID := seedFakeDokployApplicationService(ctx, t, client)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, dokployServiceID)

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := restoreBackupJob(svc, backup)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run restore_backup: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/services/app_1/backups/"+backup.ID+"/restore" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/services/app_1/backups/{backup_id}/restore", reqs)
	}
	if reqs[4].AuthHeader != output.Sentinel || strings.Contains(reqs[4].Body, fake.Token()) {
		t.Fatalf("restore request recording leaked credentials: %+v", reqs[4])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded restore_backup: %v", err)
	}
	reqs = fake.Requests()
	if len(reqs) != 5 {
		t.Fatalf("replayed restore_backup fake requests = %+v, want no additional Dokploy call", reqs)
	}
}

func TestProvisionerRestoreBackupRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	backup = markWorkerServiceBackupSucceeded(ctx, t, dataStore, svc, backup.ID)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	dokployServiceID := seedFakeDokployApplicationService(ctx, t, client)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, dokployServiceID)
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, restoreBackupJob(svc, backup))
	if err == nil {
		t.Fatal("Run restore_backup returned nil, want retryable error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run restore_backup error is terminal, want retryable: %v", err)
	}
}

func TestProvisionerRestoreBackupRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	backup = markWorkerServiceBackupSucceeded(ctx, t, dataStore, svc, backup.ID)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_stale")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	job := restoreBackupJob(svc, backup)
	job.DesiredVersion = backup.Version + 1
	err = p.Run(ctx, job)
	if err == nil || !worker.IsTerminal(err) {
		t.Fatalf("Run stale restore_backup = %v, want terminal error", err)
	}
}

func TestProvisionerRestoreBackupCancellationIsNotTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	backup = markWorkerServiceBackupSucceeded(ctx, t, dataStore, svc, backup.ID)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_cancelled")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	err = p.Run(ctx, restoreBackupJob(svc, backup))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run restore_backup cancellation = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run restore_backup cancellation is terminal: %v", err)
	}
}

func TestProvisionerDeploysServiceAndMarksDeploymentSucceeded(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	deployment := insertWorkerDeployment(ctx, t, dataStore, svc)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deployServiceJob(deployment)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run deploy service: %v", err)
	}

	got := getWorkerDeployment(ctx, t, dataStore, deployment.OrganizationID, deployment.ID)
	if got.Status != store.DeploymentStatusSucceeded {
		t.Fatalf("deployment status = %q, want succeeded", got.Status)
	}
	if got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("deployment timestamps = started %v finished %v, want both stamped", got.StartedAt, got.FinishedAt)
	}
	if got.ErrorCode != "" || got.ErrorMessage != "" {
		t.Fatalf("deployment error = (%q, %q), want empty", got.ErrorCode, got.ErrorMessage)
	}

	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/deployments" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/deployments", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("deployment request recording leaked credentials: %+v", reqs[4])
	}

	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed Run deploy service: %v", err)
	}
	reqs = fake.Requests()
	if len(reqs) != 5 {
		t.Fatalf("replayed deploy issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerDeployServiceRetryableFailureKeepsDeploymentRetryable(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	deployment := insertWorkerDeployment(ctx, t, dataStore, svc)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, deployServiceJob(deployment))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	got := getWorkerDeployment(ctx, t, dataStore, deployment.OrganizationID, deployment.ID)
	if got.Status != store.DeploymentStatusRunning || got.FinishedAt != nil {
		t.Fatalf("deployment after retryable failure = status %q finished %v, want running without finished_at", got.Status, got.FinishedAt)
	}
}

func TestProvisionerRestartServiceCallsDokployAndIsTerminalReplaySafe(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := restartServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run restart service: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/services/app_1/restart" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/services/app_1/restart", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("restart request recording leaked credentials: %+v", reqs[4])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded restart job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 5 {
		t.Fatalf("replayed succeeded restart issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerRestartServiceRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, restartServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerRestartServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := restartServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale restart called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerRestartServiceCrossTenantPayloadIsTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := restartServiceJob(svc)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("cross-tenant restart called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerDeleteServiceSuccessAndReplay(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run delete service: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodDelete || reqs[4].Path != "/api/services/app_1" {
		t.Fatalf("fake requests = %+v, want service seed then DELETE /api/services/app_1", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("delete request recording leaked credentials: %+v", reqs[4])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded delete job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 5 {
		t.Fatalf("replayed succeeded delete issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerDeleteEnvironmentSuccessAndReplay(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed environment dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteEnvironmentJob(env)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run delete environment: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 4 || reqs[3].Method != http.MethodDelete || reqs[3].Path != "/api/environments/env_1" {
		t.Fatalf("fake requests = %+v, want env seed then DELETE /api/environments/env_1", reqs)
	}
	if strings.Contains(reqs[3].Body, fake.Token()) || reqs[3].AuthHeader != output.Sentinel {
		t.Fatalf("delete request recording leaked credentials: %+v", reqs[3])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded delete environment job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("replayed succeeded delete issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerDeleteProjectSuccessAndReplay(t *testing.T) {
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
		t.Fatalf("seed project dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteProjectJob(project)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run delete project: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 3 || reqs[2].Method != http.MethodDelete || reqs[2].Path != "/api/projects/proj_1" {
		t.Fatalf("fake requests = %+v, want project seed then DELETE /api/projects/proj_1", reqs)
	}
	if strings.Contains(reqs[2].Body, fake.Token()) || reqs[2].AuthHeader != output.Sentinel {
		t.Fatalf("delete request recording leaked credentials: %+v", reqs[2])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded delete project job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("replayed succeeded delete issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerDeleteServiceRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, deleteServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerDeleteProjectRetryableFailure(t *testing.T) {
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
		t.Fatalf("seed project dokploy mapping: %v", err)
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

	err = p.Run(ctx, deleteProjectJob(project))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerDeleteEnvironmentRetryableFailure(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed environment dokploy mapping: %v", err)
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

	err = p.Run(ctx, deleteEnvironmentJob(env))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerDeleteServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale delete called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerDeleteEnvironmentRefusesStaleDesiredVersion(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed environment dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteEnvironmentJob(env)
	job.DesiredVersion = env.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale delete called Dokploy beyond environment seed: %+v", reqs)
	}
}

func TestProvisionerDeleteProjectRefusesStaleDesiredVersion(t *testing.T) {
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
		t.Fatalf("seed project dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteProjectJob(project)
	job.DesiredVersion = project.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("stale delete called Dokploy beyond project seed: %+v", reqs)
	}
}

func TestProvisionerDeleteServiceCrossTenantPayloadIsTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteServiceJob(svc)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("cross-tenant delete called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerDeleteProjectCrossTenantPayloadIsTerminal(t *testing.T) {
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
		t.Fatalf("seed project dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteProjectJob(project)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 2 {
		t.Fatalf("cross-tenant delete called Dokploy beyond project seed: %+v", reqs)
	}
}

func TestProvisionerDeleteEnvironmentCrossTenantPayloadIsTerminal(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed environment dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deleteEnvironmentJob(env)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("cross-tenant delete called Dokploy beyond environment seed: %+v", reqs)
	}
}

func TestProvisionerDeleteServiceCancellationIsNotTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, "app_cancel")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, deleteServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerDeleteProjectCancellationIsNotTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	org := insertWorkerOrg(ctx, t, dataStore, "acme")
	project := insertWorkerProject(ctx, t, dataStore, org, "api")
	insertWorkerProjectRef(ctx, t, dataStore, project, "proj_cancel")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, deleteProjectJob(project))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerDeleteEnvironmentCancellationIsNotTerminal(t *testing.T) {
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
	insertWorkerEnvironmentRef(ctx, t, dataStore, env, "env_cancel")

	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: canceledClient{},
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, deleteEnvironmentJob(env))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestDeleteServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := deleteServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert delete_service job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-delete-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("error summary leaked token: %q", persisted.ErrorSummary)
	}
	if !strings.Contains(persisted.ErrorSummary, "Dokploy") {
		t.Fatalf("error summary = %q, want redacted Dokploy failure context", persisted.ErrorSummary)
	}
}

func TestDeleteEnvironmentRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed environment dokploy mapping: %v", err)
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
	enqueued := deleteEnvironmentJob(env)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert delete_environment job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-delete-environment-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("error summary leaked token: %q", persisted.ErrorSummary)
	}
	if !strings.Contains(persisted.ErrorSummary, "Dokploy") {
		t.Fatalf("error summary = %q, want redacted Dokploy failure context", persisted.ErrorSummary)
	}
}

func TestDeleteProjectRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
		t.Fatalf("seed project dokploy mapping: %v", err)
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
	enqueued := deleteProjectJob(project)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert delete_project job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-delete-project-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if strings.Contains(persisted.ErrorSummary, fake.Token()) {
		t.Fatalf("error summary leaked token: %q", persisted.ErrorSummary)
	}
	if !strings.Contains(persisted.ErrorSummary, "Dokploy") {
		t.Fatalf("error summary = %q, want redacted Dokploy failure context", persisted.ErrorSummary)
	}
}

func TestRestartServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := restartServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert service.restart job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-restart-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
}

func TestRestoreBackupRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	backup := insertWorkerServiceBackup(ctx, t, dataStore, svc, "nightly")
	backup = markWorkerServiceBackupSucceeded(ctx, t, dataStore, svc, backup.ID)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	dokployServiceID := seedFakeDokployApplicationService(ctx, t, client)
	insertWorkerServiceRef(ctx, t, dataStore, svc, store.DokployResourceApplication, dokployServiceID)
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
	enqueued := restoreBackupJob(svc, backup)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert restore_backup job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-restore-backup-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
}

func TestProvisionerRestartServiceHonorsCanceledContext(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = p.Run(canceled, restartServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("canceled restart called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerRollbackServiceCallsDokployAndIsTerminalReplaySafe(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	if ok := fake.SetServiceStatus("app_1", "bad-release"); !ok {
		t.Fatal("SetServiceStatus(app_1) returned false")
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := rollbackServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run rollback service: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/services/app_1/rollback" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/services/app_1/rollback", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("rollback request recording leaked credentials: %+v", reqs[4])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded rollback job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 5 {
		t.Fatalf("replayed succeeded rollback issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerRollbackServiceRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, rollbackServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerRollbackServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := rollbackServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale rollback called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerRollbackServiceCrossTenantPayloadIsTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := rollbackServiceJob(svc)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("cross-tenant rollback called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestRollbackServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := rollbackServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert service.rollback job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-rollback-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
}

func TestProvisionerRollbackServiceHonorsCanceledContext(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = p.Run(canceled, rollbackServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("canceled rollback called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerStopServiceCallsDokployAndIsTerminalReplaySafe(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := stopServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run stop service: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 5 || reqs[4].Method != http.MethodPost || reqs[4].Path != "/api/services/app_1/stop" {
		t.Fatalf("fake requests = %+v, want service seed then POST /api/services/app_1/stop", reqs)
	}
	if strings.Contains(reqs[4].Body, fake.Token()) || reqs[4].AuthHeader != output.Sentinel {
		t.Fatalf("stop request recording leaked credentials: %+v", reqs[4])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded stop job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 5 {
		t.Fatalf("replayed succeeded stop issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerStopServiceRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, stopServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerStopServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := stopServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale stop called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerStopServiceCrossTenantPayloadIsTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := stopServiceJob(svc)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("cross-tenant stop called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestStopServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := stopServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert service.stop job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-stop-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
}

func TestProvisionerStopServiceHonorsCanceledContext(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = p.Run(canceled, stopServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("canceled stop called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerStartServiceCallsDokployAndIsTerminalReplaySafe(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	if _, err := client.StopService(ctx, dokploy.StopServiceInput{ServiceID: "app_1"}); err != nil {
		t.Fatalf("seed stopped Dokploy service: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := startServiceJob(svc)
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("Run start service: %v", err)
	}
	reqs := fake.Requests()
	if len(reqs) != 6 || reqs[5].Method != http.MethodPost || reqs[5].Path != "/api/services/app_1/start" {
		t.Fatalf("fake requests = %+v, want service seed, stop seed, then POST /api/services/app_1/start", reqs)
	}
	if strings.Contains(reqs[5].Body, fake.Token()) || reqs[5].AuthHeader != output.Sentinel {
		t.Fatalf("start request recording leaked credentials: %+v", reqs[5])
	}

	job.Status = store.JobStatusSucceeded
	if err := p.Run(ctx, job); err != nil {
		t.Fatalf("replayed succeeded start job: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 6 {
		t.Fatalf("replayed succeeded start issued another Dokploy request: %+v", reqs)
	}
}

func TestProvisionerStartServiceRetryableFailure(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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

	err = p.Run(ctx, startServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
}

func TestProvisionerStartServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := startServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale start called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestProvisionerStartServiceCrossTenantPayloadIsTerminal(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := startServiceJob(svc)
	job.Payload["organization_id"] = "org_other"
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want terminal validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("cross-tenant payload error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("cross-tenant start called Dokploy beyond service seed: %+v", reqs)
	}
}

func TestStartServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := startServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert service.start job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-start-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
}

func TestProvisionerStartServiceHonorsCanceledContext(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	err = p.Run(canceled, startServiceJob(svc))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("canceled start called Dokploy beyond service seed: %+v", reqs)
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
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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

func TestProvisionerEnsureApplicationServiceRetryableFailureDoesNotPersistMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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

	err = p.Run(ctx, ensureApplicationServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestProvisionerEnsureComposeServiceRetryableFailureDoesNotPersistMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "stack", store.ServiceKindCompose)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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

	err = p.Run(ctx, ensureComposeServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestProvisionerEnsureDatabaseServiceRetryableFailureDoesNotPersistMapping(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "primary", store.ServiceKindDatabase)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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

	err = p.Run(ctx, ensureDatabaseServiceJob(svc, dokploy.EnginePostgres))
	if err == nil {
		t.Fatal("Run returned nil, want retryable Dokploy error")
	}
	if worker.IsTerminal(err) {
		t.Fatalf("Run returned terminal error for retryable upstream failure: %v", err)
	}
	if !apierr.Retryable(err) {
		t.Fatalf("Run error is not marked retryable: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestEnsureApplicationServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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
	enqueued := ensureApplicationServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert ensure_application_service job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-app-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestSyncDomainsRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	domainRow := insertWorkerServiceDomain(ctx, t, dataStore, svc, "api.acme.test")

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
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
	enqueued := syncDomainsJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert sync_domains job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-domains-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listServiceDomainRefs(ctx, t, dataStore, svc.OrganizationID, domainRow.ID); len(refs) != 0 {
		t.Fatalf("domain refs after failed sync = %+v, want none", refs)
	}
}

func TestEnsureComposeServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "stack", store.ServiceKindCompose)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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
	enqueued := ensureComposeServiceJob(svc)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert ensure_compose_service job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-compose-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after failed ensure = %d, want 0", len(refs))
	}
}

func TestEnsureDatabaseServiceRetryableFailurePersistsRedactedErrorSummary(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "primary", store.ServiceKindDatabase)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
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
	enqueued := ensureDatabaseServiceJob(svc, dokploy.EnginePostgres)
	if err := dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := jobs.Insert(ctx, tx, enqueued)
		return err
	}); err != nil {
		t.Fatalf("insert ensure_database_service job: %v", err)
	}

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:         dataStore,
		Runner:        p,
		Owner:         "worker-database-redaction-test",
		LeaseDuration: time.Minute,
		Backoff:       worker.Backoff{Base: time.Second, Max: time.Second},
		Now:           func() time.Time { return time.Now().UTC().Add(time.Hour) },
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
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
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

func TestProvisionerEnsureApplicationServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureApplicationServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureComposeServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "stack", store.ServiceKindCompose)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureComposeServiceJob(svc)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureDatabaseServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "primary", store.ServiceKindDatabase)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := ensureDatabaseServiceJob(svc, dokploy.EnginePostgres)
	job.DesiredVersion = svc.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after stale job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("stale job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerDeployServiceRefusesStaleDesiredVersion(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)
	deployment := insertWorkerDeployment(ctx, t, dataStore, svc)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureApplicationServiceWithParent(ctx, t, dataStore, client, org, project, env, svc); err != nil {
		t.Fatalf("seed service dokploy mapping: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	job := deployServiceJob(deployment)
	job.DesiredVersion = deployment.Version - 1
	err = p.Run(ctx, job)
	if err == nil {
		t.Fatal("Run returned nil, want stale deployment desired-state error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("stale desired-state error is not terminal: %v", err)
	}
	got := getWorkerDeployment(ctx, t, dataStore, deployment.OrganizationID, deployment.ID)
	if got.Status != store.DeploymentStatusQueued {
		t.Fatalf("deployment status after stale job = %q, want queued", got.Status)
	}
	if reqs := fake.Requests(); len(reqs) != 4 {
		t.Fatalf("stale deploy called Dokploy beyond service seed: %+v", reqs)
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

func TestProvisionerEnsureApplicationServiceMissingServiceIsTerminalNotFound(t *testing.T) {
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
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	missingID, err := domain.NewID(domain.KindService)
	if err != nil {
		t.Fatalf("domain.NewID(service): %v", err)
	}
	missingServiceID := missingID.String()
	err = p.Run(ctx, store.ProvisioningJob{
		ID:             "job_missing_application_service",
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		ServiceID:      missingServiceID,
		JobType:        worker.JobTypeEnsureApplicationService,
		DesiredVersion: 1,
		IdempotencyKey: "ensure-application-service-" + missingServiceID,
		Payload: map[string]string{
			"organization_id": org.ID,
			"project_id":      project.ID,
			"environment_id":  env.ID,
			"service_id":      missingServiceID,
		},
	})
	if err == nil {
		t.Fatal("Run returned nil, want not-found")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("not-found error is not terminal: %v", err)
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("missing service called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureComposeServiceWrongKindIsTerminalValidation(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, ensureComposeServiceJob(svc))
	if err == nil {
		t.Fatal("Run returned nil, want wrong-kind validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("wrong-kind error is not terminal: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after wrong-kind job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("wrong-kind job called Dokploy beyond parent seed: %+v", reqs)
	}
}

func TestProvisionerEnsureDatabaseServiceWrongKindIsTerminalValidation(t *testing.T) {
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
	svc := insertWorkerService(ctx, t, dataStore, env, "api", store.ServiceKindApplication)

	fake := dokployfake.New()
	defer fake.Close()
	client := newWorkerDokployClient(t, fake)
	if err := pRunEnsureEnvironmentWithParent(ctx, t, dataStore, client, org, project, env); err != nil {
		t.Fatalf("seed parent dokploy environment: %v", err)
	}
	p, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: client,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	err = p.Run(ctx, ensureDatabaseServiceJob(svc, dokploy.EnginePostgres))
	if err == nil {
		t.Fatal("Run returned nil, want wrong-kind validation error")
	}
	if !worker.IsTerminal(err) {
		t.Fatalf("wrong-kind error is not terminal: %v", err)
	}
	if refs := listServiceRefs(ctx, t, dataStore, svc.OrganizationID, svc.ID); len(refs) != 0 {
		t.Fatalf("dokploy refs count after wrong-kind job = %d, want 0", len(refs))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Fatalf("wrong-kind job called Dokploy beyond parent seed: %+v", reqs)
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

func TestProvisionerEnsureApplicationServiceCancellationIsNotTerminal(t *testing.T) {
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
		ServiceID:      "svc_valid",
		JobType:        worker.JobTypeEnsureApplicationService,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"service_id":      "svc_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerEnsureComposeServiceCancellationIsNotTerminal(t *testing.T) {
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
		ServiceID:      "svc_valid",
		JobType:        worker.JobTypeEnsureComposeService,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"service_id":      "svc_valid",
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerEnsureDatabaseServiceCancellationIsNotTerminal(t *testing.T) {
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
		ServiceID:      "svc_valid",
		JobType:        worker.JobTypeEnsureDatabaseService,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"service_id":      "svc_valid",
			"engine":          dokploy.EnginePostgres,
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if worker.IsTerminal(err) {
		t.Fatalf("cancellation error is terminal: %v", err)
	}
}

func TestProvisionerDeployServiceCancellationIsNotTerminal(t *testing.T) {
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
		ServiceID:      "svc_valid",
		JobType:        worker.JobTypeDeployService,
		Payload: map[string]string{
			"organization_id": "org_valid",
			"project_id":      "proj_valid",
			"environment_id":  "env_valid",
			"service_id":      "svc_valid",
			"deployment_id":   "dep_valid",
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

func (canceledClient) EnsureService(context.Context, dokploy.EnsureServiceInput) (dokploy.Service, error) {
	return dokploy.Service{}, context.Canceled
}

func (canceledClient) EnsureDomain(context.Context, dokploy.EnsureDomainInput) (dokploy.Domain, error) {
	return dokploy.Domain{}, context.Canceled
}

func (canceledClient) SyncVariables(context.Context, dokploy.SyncVariablesInput) error {
	return context.Canceled
}

func (canceledClient) DeployService(context.Context, dokploy.DeployServiceInput) (dokploy.Deployment, error) {
	return dokploy.Deployment{}, context.Canceled
}

func (canceledClient) RunBackup(context.Context, dokploy.RunBackupInput) (dokploy.BackupRun, error) {
	return dokploy.BackupRun{}, context.Canceled
}

func (canceledClient) RestoreBackup(context.Context, dokploy.RestoreBackupInput) (dokploy.BackupRun, error) {
	return dokploy.BackupRun{}, context.Canceled
}

func (canceledClient) RestartService(context.Context, dokploy.RestartServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{}, context.Canceled
}

func (canceledClient) RollbackService(context.Context, dokploy.RollbackServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{}, context.Canceled
}

func (canceledClient) StopService(context.Context, dokploy.StopServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{}, context.Canceled
}

func (canceledClient) StartService(context.Context, dokploy.StartServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{}, context.Canceled
}

func (canceledClient) RemoveProject(context.Context, dokploy.RemoveProjectInput) error {
	return context.Canceled
}

func (canceledClient) RemoveService(context.Context, dokploy.RemoveServiceInput) error {
	return context.Canceled
}

func (canceledClient) RemoveEnvironment(context.Context, dokploy.RemoveEnvironmentInput) error {
	return context.Canceled
}

func newWorkerDokployClient(t *testing.T, fake *dokployfake.Server) *dokploy.Client {
	t.Helper()
	client, err := dokploy.New(dokploy.Config{
		BaseURL:    fake.URL(),
		Token:      fake.Token(),
		MaxRetries: -1,
	})
	if err != nil {
		t.Fatalf("dokploy.New: %v", err)
	}
	return client
}

func seedFakeDokployApplicationService(ctx context.Context, t *testing.T, client *dokploy.Client) string {
	t.Helper()
	org, err := client.EnsureOrganization(ctx, dokploy.EnsureOrganizationInput{Name: "worker-test-org"})
	if err != nil {
		t.Fatalf("seed fake Dokploy organization: %v", err)
	}
	project, err := client.EnsureProject(ctx, dokploy.EnsureProjectInput{
		OrganizationID: org.ID,
		Name:           "worker-test-project",
	})
	if err != nil {
		t.Fatalf("seed fake Dokploy project: %v", err)
	}
	env, err := client.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{
		ProjectID: project.ID,
		Name:      "worker-test-environment",
	})
	if err != nil {
		t.Fatalf("seed fake Dokploy environment: %v", err)
	}
	svc, err := client.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID,
		Name:          "worker-test-service",
		Type:          dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("seed fake Dokploy application service: %v", err)
	}
	return svc.ID
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

func createPreviewEnvironmentJob(preview store.PreviewEnvironment) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_create_preview_environment_test",
		OrganizationID: preview.OrganizationID,
		ProjectID:      preview.ProjectID,
		EnvironmentID:  preview.EnvironmentID,
		JobType:        worker.JobTypeCreatePreviewEnvironment,
		DesiredVersion: preview.Version,
		IdempotencyKey: "create-preview-environment-" + preview.ID,
		Payload: map[string]string{
			"organization_id": preview.OrganizationID,
			"project_id":      preview.ProjectID,
			"environment_id":  preview.EnvironmentID,
			"preview_id":      preview.ID,
		},
		RequestID:     "req_create_preview_environment_test",
		CorrelationID: "corr_create_preview_environment_test",
	}
}

func deletePreviewEnvironmentJob(preview store.PreviewEnvironment) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_delete_preview_environment_test",
		OrganizationID: preview.OrganizationID,
		ProjectID:      preview.ProjectID,
		EnvironmentID:  preview.EnvironmentID,
		JobType:        worker.JobTypeDeletePreviewEnvironment,
		DesiredVersion: preview.Version,
		IdempotencyKey: "delete-preview-environment-" + preview.ID,
		Payload: map[string]string{
			"organization_id": preview.OrganizationID,
			"project_id":      preview.ProjectID,
			"environment_id":  preview.EnvironmentID,
			"preview_id":      preview.ID,
		},
		RequestID:     "req_delete_preview_environment_test",
		CorrelationID: "corr_delete_preview_environment_test",
	}
}

func ensureApplicationServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_application_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeEnsureApplicationService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "ensure-application-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_application_service_test",
		CorrelationID: "corr_application_service_test",
	}
}

func ensureComposeServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_compose_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeEnsureComposeService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "ensure-compose-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_compose_service_test",
		CorrelationID: "corr_compose_service_test",
	}
}

func ensureDatabaseServiceJob(svc store.Service, engine string) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_database_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeEnsureDatabaseService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "ensure-database-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
			"engine":          engine,
		},
		RequestID:     "req_database_service_test",
		CorrelationID: "corr_database_service_test",
	}
}

func deployServiceJob(dep store.Deployment) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_deploy_service_test",
		OrganizationID: dep.OrganizationID,
		ProjectID:      dep.ProjectID,
		EnvironmentID:  dep.EnvironmentID,
		ServiceID:      dep.ServiceID,
		JobType:        worker.JobTypeDeployService,
		DesiredVersion: dep.Version,
		IdempotencyKey: "deploy-service-" + dep.ID,
		Payload: map[string]string{
			"organization_id": dep.OrganizationID,
			"project_id":      dep.ProjectID,
			"environment_id":  dep.EnvironmentID,
			"service_id":      dep.ServiceID,
			"deployment_id":   dep.ID,
		},
		RequestID:     "req_deploy_service_test",
		CorrelationID: "corr_deploy_service_test",
	}
}

func syncDomainsJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_sync_domains_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeSyncDomains,
		DesiredVersion: svc.Version,
		IdempotencyKey: "sync-domains-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_sync_domains_test",
		CorrelationID: "corr_sync_domains_test",
	}
}

func syncVariablesJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_sync_variables_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeSyncVariables,
		DesiredVersion: svc.Version,
		IdempotencyKey: "sync-variables-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_sync_variables_test",
		CorrelationID: "corr_sync_variables_test",
	}
}

func reconcileServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_reconcile_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeReconcileService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "reconcile-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_reconcile_service_test",
		CorrelationID: "corr_reconcile_service_test",
	}
}

func runBackupJob(svc store.Service, backup store.ServiceBackup) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_run_backup_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeRunBackup,
		DesiredVersion: backup.Version,
		IdempotencyKey: "run-backup-" + backup.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
			"backup_id":       backup.ID,
		},
		RequestID:     "req_run_backup_test",
		CorrelationID: "corr_run_backup_test",
	}
}

func restoreBackupJob(svc store.Service, backup store.ServiceBackup) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_restore_backup_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeRestoreBackup,
		DesiredVersion: backup.Version,
		IdempotencyKey: "restore-backup-" + backup.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
			"backup_id":       backup.ID,
		},
		RequestID:     "req_restore_backup_test",
		CorrelationID: "corr_restore_backup_test",
	}
}

func restartServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_restart_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeRestartService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "restart-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_restart_service_test",
		CorrelationID: "corr_restart_service_test",
	}
}

func rollbackServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_rollback_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeRollbackService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "rollback-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_rollback_service_test",
		CorrelationID: "corr_rollback_service_test",
	}
}

func stopServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_stop_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeStopService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "stop-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_stop_service_test",
		CorrelationID: "corr_stop_service_test",
	}
}

func startServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_start_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeStartService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "start-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_start_service_test",
		CorrelationID: "corr_start_service_test",
	}
}

func deleteServiceJob(svc store.Service) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_delete_service_test",
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		JobType:        worker.JobTypeDeleteService,
		DesiredVersion: svc.Version,
		IdempotencyKey: "delete-service-" + svc.ID,
		Payload: map[string]string{
			"organization_id": svc.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
		},
		RequestID:     "req_delete_service_test",
		CorrelationID: "corr_delete_service_test",
	}
}

func deleteEnvironmentJob(env store.Environment) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_delete_environment_test",
		OrganizationID: env.OrganizationID,
		ProjectID:      env.ProjectID,
		EnvironmentID:  env.ID,
		JobType:        worker.JobTypeDeleteEnvironment,
		DesiredVersion: env.Version,
		IdempotencyKey: "delete-environment-" + env.ID,
		Payload: map[string]string{
			"organization_id": env.OrganizationID,
			"project_id":      env.ProjectID,
			"environment_id":  env.ID,
		},
		RequestID:     "req_delete_environment_test",
		CorrelationID: "corr_delete_environment_test",
	}
}

func deleteProjectJob(project store.Project) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_delete_project_test",
		OrganizationID: project.OrganizationID,
		ProjectID:      project.ID,
		JobType:        worker.JobTypeDeleteProject,
		DesiredVersion: project.Version,
		IdempotencyKey: "delete-project-" + project.ID,
		Payload: map[string]string{
			"organization_id": project.OrganizationID,
			"project_id":      project.ID,
		},
		RequestID:     "req_delete_project_test",
		CorrelationID: "corr_delete_project_test",
	}
}

func importDokployResourceJob(org store.Organization, dokployOrgID string) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_import_dokploy_resource_test",
		OrganizationID: org.ID,
		JobType:        worker.JobTypeImportDokployResource,
		DesiredVersion: org.Version,
		IdempotencyKey: "import-dokploy-resource-" + org.ID,
		Payload: map[string]string{
			"organization_id":           org.ID,
			"yalla_organization_id":     org.ID,
			"dokploy_organization_id":   dokployOrgID,
			"assignment_dokploy_org_id": dokployOrgID,
		},
		RequestID:     "req_import_dokploy_resource_test",
		CorrelationID: "corr_import_dokploy_resource_test",
	}
}

type fakeImportScanner struct {
	snapshot migrateimport.Snapshot
	err      error
	calls    int
}

func (f *fakeImportScanner) Scan(ctx context.Context, dokployOrganizationID string) (migrateimport.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return migrateimport.Snapshot{}, err
	}
	f.calls++
	if f.err != nil {
		return migrateimport.Snapshot{}, f.err
	}
	out := f.snapshot
	if out.Organization.DokployID == "" {
		out.Organization.DokployID = dokployOrganizationID
	}
	return out, nil
}

func importSnapshot(dokployOrgID string) migrateimport.Snapshot {
	return migrateimport.Snapshot{
		Organization: migrateimport.SnapshotOrganization{
			DokployID: dokployOrgID,
			Name:      "Imported Organization",
		},
		Projects: []migrateimport.SnapshotProject{
			{
				DokployID:             "dokploy_project_import",
				DokployOrganizationID: dokployOrgID,
				Name:                  "Imported Project",
			},
		},
		Environments: []migrateimport.SnapshotEnvironment{
			{
				DokployID:        "dokploy_environment_import",
				DokployProjectID: "dokploy_project_import",
				Name:             "Imported Environment",
			},
		},
		Services: []migrateimport.SnapshotService{
			{
				DokployID:            "dokploy_service_import",
				DokployEnvironmentID: "dokploy_environment_import",
				Name:                 "Imported API",
				Type:                 string(dokploy.ServiceApplication),
			},
		},
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

func pRunEnsureEnvironmentWithParent(ctx context.Context, t *testing.T, s *store.Store, client *dokploy.Client, org store.Organization, project store.Project, env store.Environment) error {
	t.Helper()
	if err := pRunEnsureProjectWithParent(ctx, t, s, client, org, project); err != nil {
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
	return p.Run(ctx, ensureEnvironmentJob(env))
}

func pRunEnsureApplicationServiceWithParent(ctx context.Context, t *testing.T, s *store.Store, client *dokploy.Client, org store.Organization, project store.Project, env store.Environment, svc store.Service) error {
	t.Helper()
	if err := pRunEnsureEnvironmentWithParent(ctx, t, s, client, org, project, env); err != nil {
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
	return p.Run(ctx, ensureApplicationServiceJob(svc))
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

func listWorkerProjects(ctx context.Context, t *testing.T, s *store.Store, organizationID string) []store.Project {
	t.Helper()
	repo := store.NewProjectRepository()
	var projects []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		projects, err = repo.ListByOrganization(ctx, q, organizationID)
		return err
	}); err != nil {
		t.Fatalf("list projects: %v", err)
	}
	return projects
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

func listWorkerEnvironments(ctx context.Context, t *testing.T, s *store.Store, organizationID, projectID string) []store.Environment {
	t.Helper()
	repo := store.NewEnvironmentRepository()
	var envs []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		envs, err = repo.ListByProject(ctx, q, organizationID, projectID)
		return err
	}); err != nil {
		t.Fatalf("list environments: %v", err)
	}
	return envs
}

func insertWorkerPreviewEnvironment(ctx context.Context, t *testing.T, s *store.Store, project store.Project, source store.Environment, label string) store.PreviewEnvironment {
	t.Helper()
	f := testutil.NewFactory(t)
	fixture := f.Environment(testutil.Project{ID: project.ID, OrganizationID: project.OrganizationID}, label)
	previewID, err := domain.NewID(domain.KindPreviewEnvironment)
	if err != nil {
		t.Fatalf("domain.NewID(preview environment): %v", err)
	}
	envRepo := store.NewEnvironmentRepository()
	previewRepo := store.NewPreviewEnvironmentRepository()
	var preview store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		env, err := envRepo.Insert(ctx, tx, store.Environment{
			ID:             fixture.ID,
			OrganizationID: project.OrganizationID,
			ProjectID:      project.ID,
			Slug:           fixture.Slug,
			DisplayName:    fixture.Name,
			Kind:           store.EnvironmentKindPreview,
		})
		if err != nil {
			return err
		}
		preview, err = previewRepo.Insert(ctx, tx, store.PreviewEnvironment{
			ID:                  previewID.String(),
			OrganizationID:      project.OrganizationID,
			ProjectID:           project.ID,
			EnvironmentID:       env.ID,
			SourceEnvironmentID: source.ID,
			DisplayName:         fixture.Name,
			ChangeRef:           "refs/pull/42/head",
		})
		return err
	}); err != nil {
		t.Fatalf("insert preview environment: %v", err)
	}
	return preview
}

func scheduleWorkerPreviewDeletion(ctx context.Context, t *testing.T, s *store.Store, preview store.PreviewEnvironment) store.PreviewEnvironment {
	t.Helper()
	repo := store.NewPreviewEnvironmentRepository()
	var scheduled store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		scheduled, err = repo.ScheduleDeletion(ctx, tx, preview.OrganizationID, preview.ProjectID, preview.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("schedule preview deletion: %v", err)
	}
	return scheduled
}

func getWorkerPreviewEnvironment(ctx context.Context, s *store.Store, preview store.PreviewEnvironment) (store.PreviewEnvironment, error) {
	repo := store.NewPreviewEnvironmentRepository()
	var got store.PreviewEnvironment
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetByID(ctx, q, preview.OrganizationID, preview.ProjectID, preview.ID)
		return err
	})
	return got, err
}

func assertPreviewEnvironmentMissing(ctx context.Context, t *testing.T, s *store.Store, preview store.PreviewEnvironment) {
	t.Helper()
	if _, err := getWorkerPreviewEnvironment(ctx, s, preview); err == nil {
		t.Fatal("preview row still exists after delete")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("preview row lookup error = %v, want not found", err)
	}
}

func insertWorkerService(ctx context.Context, t *testing.T, s *store.Store, env store.Environment, label, kind string) store.Service {
	t.Helper()
	f := testutil.NewFactory(t)
	fixture := f.Service(testutil.Environment{
		ID:             env.ID,
		ProjectID:      env.ProjectID,
		OrganizationID: env.OrganizationID,
	}, label)
	repo := store.NewServiceRepository()
	var svc store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		svc, err = repo.Insert(ctx, tx, store.Service{
			ID:             fixture.ID,
			OrganizationID: env.OrganizationID,
			ProjectID:      env.ProjectID,
			EnvironmentID:  env.ID,
			Slug:           fixture.Slug,
			DisplayName:    fixture.Name,
			Kind:           kind,
		})
		return err
	}); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	return svc
}

func listWorkerServices(ctx context.Context, t *testing.T, s *store.Store, organizationID, environmentID string) []store.Service {
	t.Helper()
	repo := store.NewServiceRepository()
	var services []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		services, err = repo.ListByEnvironment(ctx, q, organizationID, environmentID)
		return err
	}); err != nil {
		t.Fatalf("list services: %v", err)
	}
	return services
}

func insertWorkerDeployment(ctx context.Context, t *testing.T, s *store.Store, svc store.Service) store.Deployment {
	t.Helper()
	repo := store.NewDeploymentRepository()
	var dep store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		dep, err = repo.Insert(ctx, tx, store.Deployment{
			ID:             domain.MustNewID(domain.KindDeployment).String(),
			OrganizationID: svc.OrganizationID,
			ProjectID:      svc.ProjectID,
			EnvironmentID:  svc.EnvironmentID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceManual,
			SourceRef:      "manual worker test",
			RequestedBy:    "usr_worker_test",
			IdempotencyKey: "idem-worker-" + svc.ID,
			RequestID:      "req_worker_deployment_test",
			CorrelationID:  "corr_worker_deployment_test",
		})
		return err
	}); err != nil {
		t.Fatalf("insert deployment: %v", err)
	}
	return dep
}

func insertWorkerServiceBackup(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, label string) store.ServiceBackup {
	t.Helper()
	repo := store.NewServiceBackupRepository()
	var backup store.ServiceBackup
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		backup, err = repo.Insert(ctx, tx, store.ServiceBackup{
			ID:             domain.MustNewID(domain.KindServiceBackup).String(),
			OrganizationID: svc.OrganizationID,
			ServiceID:      svc.ID,
			DisplayName:    label,
			Schedule:       "0 2 * * *",
			RetentionCount: 7,
			Enabled:        true,
		})
		return err
	}); err != nil {
		t.Fatalf("insert service backup: %v", err)
	}
	return backup
}

func markWorkerServiceBackupSucceeded(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, backupID string) store.ServiceBackup {
	t.Helper()
	repo := store.NewServiceBackupRepository()
	var backup store.ServiceBackup
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		backup, err = repo.MarkSucceeded(ctx, tx, svc.OrganizationID, svc.ID, backupID)
		return err
	}); err != nil {
		t.Fatalf("mark service backup succeeded: %v", err)
	}
	return backup
}

func insertWorkerServiceDomain(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, hostname string) store.ServiceDomain {
	t.Helper()
	repo := store.NewServiceDomainRepository()
	var d store.ServiceDomain
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		d, err = repo.Insert(ctx, tx, store.ServiceDomain{
			ID:              domain.MustNewID(domain.KindServiceDomain).String(),
			OrganizationID:  svc.OrganizationID,
			ServiceID:       svc.ID,
			Hostname:        hostname,
			Path:            "/",
			Port:            8080,
			HTTPS:           true,
			CertificateType: store.ServiceDomainCertificateLetsEncrypt,
		})
		return err
	}); err != nil {
		t.Fatalf("insert service domain: %v", err)
	}
	return d
}

func insertWorkerOrganizationVariable(ctx context.Context, t *testing.T, s *store.Store, org store.Organization, key, value string, secret bool, provider secrets.Provider) store.OrganizationVariable {
	t.Helper()
	repo := store.NewOrganizationVariableRepository()
	upsert := organizationVariableUpsertForTest(t, value, secret, provider)
	var v store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		v, err = repo.Upsert(ctx, tx, domain.MustNewID(domain.KindOrganizationVariable).String(), org.ID, key, upsert)
		return err
	}); err != nil {
		t.Fatalf("insert organization variable: %v", err)
	}
	return v
}

func insertWorkerProjectVariable(ctx context.Context, t *testing.T, s *store.Store, project store.Project, key, value string, secret bool, provider secrets.Provider) store.ProjectVariable {
	t.Helper()
	repo := store.NewProjectVariableRepository()
	upsert := projectVariableUpsertForTest(t, value, secret, provider)
	var v store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		v, err = repo.Upsert(ctx, tx, domain.MustNewID(domain.KindProjectVariable).String(), project.OrganizationID, project.ID, key, upsert)
		return err
	}); err != nil {
		t.Fatalf("insert project variable: %v", err)
	}
	return v
}

func insertWorkerEnvironmentVariable(ctx context.Context, t *testing.T, s *store.Store, env store.Environment, key, value string, secret bool, provider secrets.Provider) store.EnvironmentVariable {
	t.Helper()
	repo := store.NewEnvironmentVariableRepository()
	upsert := environmentVariableUpsertForTest(t, value, secret, provider)
	var v store.EnvironmentVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		v, err = repo.Upsert(ctx, tx, domain.MustNewID(domain.KindEnvironmentVariable).String(), env.OrganizationID, env.ID, key, upsert)
		return err
	}); err != nil {
		t.Fatalf("insert environment variable: %v", err)
	}
	return v
}

func insertWorkerServiceVariable(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, key, value string, secret bool, provider secrets.Provider) store.ServiceVariable {
	t.Helper()
	repo := store.NewServiceVariableRepository()
	upsert := serviceVariableUpsertForTest(t, value, secret, provider)
	var v store.ServiceVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		v, err = repo.Upsert(ctx, tx, domain.MustNewID(domain.KindServiceVariable).String(), svc.OrganizationID, svc.ID, key, upsert)
		return err
	}); err != nil {
		t.Fatalf("insert service variable: %v", err)
	}
	return v
}

func organizationVariableUpsertForTest(t *testing.T, value string, secret bool, provider secrets.Provider) store.OrganizationVariableUpsert {
	t.Helper()
	if !secret {
		return store.OrganizationVariableUpsert{Value: value}
	}
	ct, keyID, err := provider.Seal([]byte(value))
	if err != nil {
		t.Fatalf("seal organization variable: %v", err)
	}
	return store.OrganizationVariableUpsert{IsSecret: true, SecretProvider: provider.ProviderID(), SecretKeyID: keyID, SecretCiphertext: ct}
}

func projectVariableUpsertForTest(t *testing.T, value string, secret bool, provider secrets.Provider) store.ProjectVariableUpsert {
	t.Helper()
	if !secret {
		return store.ProjectVariableUpsert{Value: value}
	}
	ct, keyID, err := provider.Seal([]byte(value))
	if err != nil {
		t.Fatalf("seal project variable: %v", err)
	}
	return store.ProjectVariableUpsert{IsSecret: true, SecretProvider: provider.ProviderID(), SecretKeyID: keyID, SecretCiphertext: ct}
}

func environmentVariableUpsertForTest(t *testing.T, value string, secret bool, provider secrets.Provider) store.EnvironmentVariableUpsert {
	t.Helper()
	if !secret {
		return store.EnvironmentVariableUpsert{Value: value}
	}
	ct, keyID, err := provider.Seal([]byte(value))
	if err != nil {
		t.Fatalf("seal environment variable: %v", err)
	}
	return store.EnvironmentVariableUpsert{IsSecret: true, SecretProvider: provider.ProviderID(), SecretKeyID: keyID, SecretCiphertext: ct}
}

func serviceVariableUpsertForTest(t *testing.T, value string, secret bool, provider secrets.Provider) store.ServiceVariableUpsert {
	t.Helper()
	if !secret {
		return store.ServiceVariableUpsert{Value: value}
	}
	ct, keyID, err := provider.Seal([]byte(value))
	if err != nil {
		t.Fatalf("seal service variable: %v", err)
	}
	return store.ServiceVariableUpsert{IsSecret: true, SecretProvider: provider.ProviderID(), SecretKeyID: keyID, SecretCiphertext: ct}
}

func insertWorkerServiceRef(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, resource store.DokployResource, dokployID string) store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var ref store.DokployRef
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ref, err = repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  svc.OrganizationID,
			YallaKind:       store.YallaKindService,
			YallaID:         svc.ID,
			DokployResource: resource,
			DokployID:       dokployID,
		})
		return err
	}); err != nil {
		t.Fatalf("insert service dokploy ref: %v", err)
	}
	return ref
}

func insertWorkerProjectRef(ctx context.Context, t *testing.T, s *store.Store, project store.Project, dokployID string) store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var ref store.DokployRef
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ref, err = repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  project.OrganizationID,
			YallaKind:       store.YallaKindProject,
			YallaID:         project.ID,
			DokployResource: store.DokployResourceProject,
			DokployID:       dokployID,
		})
		return err
	}); err != nil {
		t.Fatalf("insert project dokploy ref: %v", err)
	}
	return ref
}

func insertWorkerEnvironmentRef(ctx context.Context, t *testing.T, s *store.Store, env store.Environment, dokployID string) store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var ref store.DokployRef
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ref, err = repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  env.OrganizationID,
			YallaKind:       store.YallaKindEnvironment,
			YallaID:         env.ID,
			DokployResource: store.DokployResourceEnvironment,
			DokployID:       dokployID,
		})
		return err
	}); err != nil {
		t.Fatalf("insert environment dokploy ref: %v", err)
	}
	return ref
}

func getWorkerDeployment(ctx context.Context, t *testing.T, s *store.Store, organizationID, deploymentID string) store.Deployment {
	t.Helper()
	repo := store.NewDeploymentRepository()
	var dep store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		dep, err = repo.GetByID(ctx, q, organizationID, deploymentID)
		return err
	}); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	return dep
}

func getWorkerServiceBackup(ctx context.Context, t *testing.T, s *store.Store, svc store.Service, backupID string) store.ServiceBackup {
	t.Helper()
	repo := store.NewServiceBackupRepository()
	var backup store.ServiceBackup
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		backup, err = repo.GetByID(ctx, q, svc.OrganizationID, svc.ID, backupID)
		return err
	}); err != nil {
		t.Fatalf("get service backup: %v", err)
	}
	return backup
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

func listServiceRefs(ctx context.Context, t *testing.T, s *store.Store, organizationID, serviceID string) []store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var refs []store.DokployRef
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = repo.ListByYallaResource(ctx, q, organizationID, store.YallaKindService, serviceID)
		return err
	}); err != nil {
		t.Fatalf("list service dokploy refs: %v", err)
	}
	return refs
}

func listServiceDomainRefs(ctx context.Context, t *testing.T, s *store.Store, organizationID, domainID string) []store.DokployRef {
	t.Helper()
	repo := store.NewDokployRefRepository()
	var refs []store.DokployRef
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = repo.ListByYallaResource(ctx, q, organizationID, store.YallaKindServiceDomain, domainID)
		return err
	}); err != nil {
		t.Fatalf("list service domain dokploy refs: %v", err)
	}
	return refs
}
