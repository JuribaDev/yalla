package worker_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
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
