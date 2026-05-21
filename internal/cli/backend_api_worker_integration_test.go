package cli

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/httpapi"
	"github.com/JuribaDev/yalla/internal/controlplane/jobs"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
)

type integrationAuthenticator struct {
	identity auth.Identity
}

func (a integrationAuthenticator) Authenticate(context.Context, string) (auth.Identity, error) {
	return a.identity, nil
}

type integrationAuthorizer struct{}

func (integrationAuthorizer) Authorize(context.Context, store.Querier, string, string) error {
	return nil
}

type integrationQuota struct{}

func (integrationQuota) Reserve(context.Context, *store.Tx, string, string) error { return nil }

func (integrationQuota) ReserveAmount(context.Context, *store.Tx, string, string, int64) error {
	return nil
}

type integrationDokployClient struct {
	ensuredServices []dokploy.EnsureServiceInput
	deploys         []dokploy.DeployServiceInput
}

func (c *integrationDokployClient) EnsureOrganization(_ context.Context, in dokploy.EnsureOrganizationInput) (dokploy.Organization, error) {
	return dokploy.Organization{ID: firstNonEmpty(in.ExistingID, "dkp_org"), Name: in.Name}, nil
}

func (c *integrationDokployClient) EnsureProject(_ context.Context, in dokploy.EnsureProjectInput) (dokploy.Project, error) {
	return dokploy.Project{ID: firstNonEmpty(in.ExistingID, "dkp_project"), OrganizationID: in.OrganizationID, Name: in.Name}, nil
}

func (c *integrationDokployClient) EnsureEnvironment(_ context.Context, in dokploy.EnsureEnvironmentInput) (dokploy.Environment, error) {
	return dokploy.Environment{ID: firstNonEmpty(in.ExistingID, "dkp_env"), ProjectID: in.ProjectID, Name: in.Name}, nil
}

func (c *integrationDokployClient) EnsureService(_ context.Context, in dokploy.EnsureServiceInput) (dokploy.Service, error) {
	c.ensuredServices = append(c.ensuredServices, in)
	id := firstNonEmpty(in.ExistingID, "dkp_service_"+strings.TrimSpace(in.Name))
	return dokploy.Service{ID: id, EnvironmentID: in.EnvironmentID, Name: in.Name, Type: string(in.Type), Engine: in.Engine, Status: "running"}, nil
}

func (c *integrationDokployClient) EnsureDomain(_ context.Context, in dokploy.EnsureDomainInput) (dokploy.Domain, error) {
	return dokploy.Domain{ID: firstNonEmpty(in.ExistingID, "dkp_domain"), ServiceID: in.ServiceID, Host: in.Host, HTTPS: in.HTTPS}, nil
}

func (c *integrationDokployClient) SyncVariables(context.Context, dokploy.SyncVariablesInput) error {
	return nil
}

func (c *integrationDokployClient) DeployService(_ context.Context, in dokploy.DeployServiceInput) (dokploy.Deployment, error) {
	c.deploys = append(c.deploys, in)
	return dokploy.Deployment{ID: "dkp_deployment", ServiceID: in.ServiceID, Status: dokploy.DeploymentSucceeded}, nil
}

func (c *integrationDokployClient) RunBackup(_ context.Context, in dokploy.RunBackupInput) (dokploy.BackupRun, error) {
	return dokploy.BackupRun{ID: "dkp_backup_run", ServiceID: in.ServiceID, Status: dokploy.DeploymentSucceeded}, nil
}

func (c *integrationDokployClient) RestoreBackup(_ context.Context, in dokploy.RestoreBackupInput) (dokploy.BackupRun, error) {
	return dokploy.BackupRun{ID: "dkp_backup_restore", ServiceID: in.ServiceID, Status: dokploy.DeploymentSucceeded}, nil
}

func (c *integrationDokployClient) RestartService(_ context.Context, in dokploy.RestartServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{ServiceID: in.ServiceID, Status: "running"}, nil
}

func (c *integrationDokployClient) RollbackService(_ context.Context, in dokploy.RollbackServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{ServiceID: in.ServiceID, Status: "running"}, nil
}

func (c *integrationDokployClient) StopService(_ context.Context, in dokploy.StopServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{ServiceID: in.ServiceID, Status: "stopped"}, nil
}

func (c *integrationDokployClient) StartService(_ context.Context, in dokploy.StartServiceInput) (dokploy.ServiceStatus, error) {
	return dokploy.ServiceStatus{ServiceID: in.ServiceID, Status: "running"}, nil
}

func (c *integrationDokployClient) RemoveProject(context.Context, dokploy.RemoveProjectInput) error {
	return nil
}

func (c *integrationDokployClient) RemoveEnvironment(context.Context, dokploy.RemoveEnvironmentInput) error {
	return nil
}

func (c *integrationDokployClient) RemoveService(context.Context, dokploy.RemoveServiceInput) error {
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func TestCLIBackendAPIWorkerDatabaseDeployIntegration(t *testing.T) {
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	dataStore, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	orgID, projectID, environmentID := seedBackendIntegrationHierarchy(t, ctx, dataStore, db)
	authn := integrationAuthenticator{identity: auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_cli_integration",
			Kind:           domain.KindUser,
			OrganizationID: orgID,
			Role:           policy.RoleDeveloper,
		},
		Method: auth.MethodSession,
	}}

	jobReader, err := store.NewJobReader(dataStore)
	if err != nil {
		t.Fatalf("NewJobReader: %v", err)
	}
	deploymentReader, err := store.NewDeploymentReader(dataStore)
	if err != nil {
		t.Fatalf("NewDeploymentReader: %v", err)
	}
	serviceService, deploymentService := buildBackendIntegrationServices(t, dataStore)
	handler := httpapi.NewHandler(runtime.BuildInfo{Version: "test"}, nil, nil, nil, authn, policy.NewEngine(),
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil,
		nil, serviceService,
		nil, nil, nil, nil, nil, nil, nil,
		nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		nil, nil,
		deploymentService, deploymentReader, deploymentReader, nil, nil,
		nil, nil, nil,
		jobReader)
	apiServer := httptest.NewServer(handler)
	t.Cleanup(apiServer.Close)
	t.Setenv(config.EnvBaseURL, apiServer.URL)
	t.Setenv(config.EnvToken, "test-yalla-token")

	serviceID := domain.MustNewID(domain.KindService).String()
	stdout, stderr, err := runRootArgs(t, "--json", "database", "create",
		"--environment-id", environmentID,
		"--service-id", serviceID,
		"--name", "postgres",
		"--display-name", "Postgres",
		"--deploy")
	if err != nil {
		t.Fatalf("database create --deploy: %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, serviceID) {
		t.Fatalf("CLI output missing created service id %q: %s", serviceID, stdout)
	}

	fakeDokploy := &integrationDokployClient{}
	provisioner, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: fakeDokploy,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	jobsForService := listBackendIntegrationJobs(t, ctx, dataStore, orgID, serviceID)
	if len(jobsForService) != 2 {
		t.Fatalf("jobs for service = %d, want ensure database + deploy: %#v", len(jobsForService), jobsForService)
	}
	for _, job := range jobsForService {
		runBackendIntegrationJob(t, ctx, dataStore, provisioner, job)
	}
	if len(fakeDokploy.ensuredServices) != 1 || fakeDokploy.ensuredServices[0].Type != dokploy.ServiceDatabase {
		t.Fatalf("fake Dokploy ensured services = %+v, want one database service", fakeDokploy.ensuredServices)
	}
	if len(fakeDokploy.deploys) != 1 {
		t.Fatalf("fake Dokploy deploy calls = %+v, want one", fakeDokploy.deploys)
	}

	deploymentID := latestDeploymentIDForService(t, ctx, dataStore, orgID, serviceID)
	stdout, stderr, err = runRootArgs(t, "--json", "wait", "deployment",
		"--deployment-id", deploymentID,
		"--status", "succeeded",
		"--interval", "1ms",
		"--timeout", "1s")
	if err != nil {
		t.Fatalf("wait deployment: %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, `"succeeded"`) {
		t.Fatalf("wait deployment output missing success: %s", stdout)
	}

	stdout, stderr, err = runRootArgs(t, "--json", "wait", "job",
		"--job-id", jobsForService[len(jobsForService)-1].ID,
		"--status", "succeeded",
		"--interval", "1ms",
		"--timeout", "1s")
	if err != nil {
		t.Fatalf("wait job: %v stderr=%s", err, stderr)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil || !strings.Contains(string(env.Data), `"succeeded"`) {
		t.Fatalf("wait job payload = %s decodeErr=%v", stdout, err)
	}

	_ = projectID
}

func buildBackendIntegrationServices(t *testing.T, s *store.Store) (*store.ServiceService, *store.DeploymentService) {
	t.Helper()
	authorizer := integrationAuthorizer{}
	quota := integrationQuota{}
	enqueuer := jobs.NewEnqueuer()
	audit := store.NewAuditRepository()
	serviceService, err := store.NewServiceService(
		s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		store.NewServiceRepository(),
		authorizer,
		quota,
		enqueuer,
		audit,
	)
	if err != nil {
		t.Fatalf("NewServiceService: %v", err)
	}
	deploymentService, err := store.NewDeploymentService(
		s,
		store.NewServiceRepository(),
		store.NewDeploymentRepository(),
		authorizer,
		quota,
		enqueuer,
		audit,
	)
	if err != nil {
		t.Fatalf("NewDeploymentService: %v", err)
	}
	return serviceService, deploymentService
}

func seedBackendIntegrationHierarchy(t *testing.T, ctx context.Context, s *store.Store, db *testutil.DB) (string, string, string) {
	t.Helper()
	orgID := domain.MustNewID(domain.KindOrganization).String()
	projectID := domain.MustNewID(domain.KindProject).String()
	environmentID := domain.MustNewID(domain.KindEnvironment).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		orgID, "org-"+orgID[len(orgID)-12:], "CLI Integration Org"); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		projectID, orgID, "proj-"+projectID[len(projectID)-12:], "CLI Integration Project"); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
		 VALUES ($1, $2, $3, $4, $5)`,
		environmentID, orgID, projectID, "production", "Production"); err != nil {
		t.Fatalf("seed environment: %v", err)
	}

	refs := store.NewDokployRefRepository()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, ref := range []store.DokployRef{{
			OrganizationID:  orgID,
			YallaKind:       store.YallaKindOrganization,
			YallaID:         orgID,
			DokployResource: store.DokployResourceOrganization,
			DokployID:       "dkp_org",
		}, {
			OrganizationID:  orgID,
			YallaKind:       store.YallaKindProject,
			YallaID:         projectID,
			DokployResource: store.DokployResourceProject,
			DokployID:       "dkp_project",
		}, {
			OrganizationID:  orgID,
			YallaKind:       store.YallaKindEnvironment,
			YallaID:         environmentID,
			DokployResource: store.DokployResourceEnvironment,
			DokployID:       "dkp_environment",
		}} {
			if _, err := refs.Insert(ctx, tx, ref); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed dokploy refs: %v", err)
	}
	return orgID, projectID, environmentID
}

func listBackendIntegrationJobs(t *testing.T, ctx context.Context, s *store.Store, orgID, serviceID string) []store.ProvisioningJob {
	t.Helper()
	repo := store.NewJobRepository()
	var out []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		out, err = repo.List(ctx, q, store.ListProvisioningJobsInput{
			OrganizationID: orgID,
			ServiceID:      serviceID,
			Limit:          20,
		})
		return err
	}); err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func runBackendIntegrationJob(t *testing.T, ctx context.Context, s *store.Store, provisioner *worker.Provisioner, job store.ProvisioningJob) {
	t.Helper()
	repo := store.NewJobRepository()
	var running store.ProvisioningJob
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		running, err = repo.Transition(ctx, tx, job.OrganizationID, job.ID, store.JobStatusRunning, store.JobTransition{
			LeaseOwner:    "integration-worker",
			LeaseDuration: time.Minute,
			ActorID:       "integration-worker",
			ActorKind:     "worker",
		})
		return err
	}); err != nil {
		t.Fatalf("claim job %s: %v", job.ID, err)
	}
	if err := provisioner.Run(ctx, running); err != nil {
		t.Fatalf("run job %s (%s): %v", running.ID, running.JobType, err)
	}
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Transition(ctx, tx, running.OrganizationID, running.ID, store.JobStatusSucceeded, store.JobTransition{
			ExpectedLeaseOwner: "integration-worker",
			ActorID:            "integration-worker",
			ActorKind:          "worker",
			Reason:             "integration worker completed job",
		})
		return err
	}); err != nil {
		t.Fatalf("complete job %s: %v", running.ID, err)
	}
}

func latestDeploymentIDForService(t *testing.T, ctx context.Context, s *store.Store, orgID, serviceID string) string {
	t.Helper()
	repo := store.NewDeploymentRepository()
	var deployments []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		deployments, err = repo.ListByService(ctx, q, orgID, serviceID)
		return err
	}); err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	if len(deployments) == 0 {
		t.Fatalf("no deployments found for service %s", serviceID)
	}
	return deployments[0].ID
}
