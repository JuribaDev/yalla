package migrateimport_test

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/migrateimport"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Fixture IDs are the canonical kinded form (Crockford base32, lowercase, 26
// suffix chars). They are reused across the suite so a planner that confuses
// kinds or normalises wrong will fail loudly.
const (
	fixtureYallaOrg  = "org_01hz00000000000000000000yz"
	fixtureYallaOrg2 = "org_01hz00000000000000000000yy"
	fixtureProj1     = "proj_01hz00000000000000000000pa"
	fixtureProj2     = "proj_01hz00000000000000000000pb"
	fixtureEnv1      = "env_01hz00000000000000000000ea"
	fixtureEnv2      = "env_01hz00000000000000000000eb"
	fixtureSvc1      = "svc_01hz00000000000000000000sa"

	dokployOrg     = "dkp-org-1"
	dokployProj1   = "dkp-proj-1"
	dokployProj2   = "dkp-proj-2"
	dokployProjX   = "dkp-proj-missing-parent"
	dokployEnv1    = "dkp-env-1"
	dokployEnv2    = "dkp-env-2"
	dokployEnvX    = "dkp-env-missing-parent"
	dokploySvc1    = "dkp-svc-1"
	dokploySvcBad  = "dkp-svc-bad-type"
	dokploySvcMiss = "dkp-svc-no-parent"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeScanner returns a fixed Snapshot or a fixed error. When err is non-nil
// it always returns the error; otherwise it returns snapshot.
type fakeScanner struct {
	mu       sync.Mutex
	snapshot migrateimport.Snapshot
	err      error
	calls    int
	lastOrg  string
}

func (f *fakeScanner) Scan(_ context.Context, dokployOrganizationID string) (migrateimport.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastOrg = dokployOrganizationID
	if f.err != nil {
		return migrateimport.Snapshot{}, f.err
	}
	return f.snapshot, nil
}

// fakeRepo is a tracked, in-memory implementation of the Repository port. It
// records every Create call (for ordering / partial-failure assertions) and
// lets a test pre-seed existing rows or inject create-time failures.
type fakeRepo struct {
	mu sync.Mutex

	organizations    map[domain.ID]struct{}
	projectsByDok    map[string]domain.ID // (orgID|dokployID) -> yallaID
	projectsBySlug   map[string]existingProject
	envByDok         map[string]domain.ID // (projID|dokployID) -> yallaID
	envBySlug        map[string]existingEnvironment
	svcByDok         map[string]domain.ID // (envID|dokployID) -> yallaID
	svcBySlug        map[string]existingService
	createProjectErr error
	createEnvErr     error
	createSvcErr     error
	// failServiceByDokployID injects a failure when CreateService is called
	// for the named Dokploy service ID. Used to prove partial imports.
	failServiceByDokployID map[string]error

	calls []string
	// nextID is the monotonically incrementing counter behind issued Yalla
	// IDs. Tests can read it to check ordering.
	nextProj int
	nextEnv  int
	nextSvc  int
}

type existingProject struct {
	yallaID  domain.ID
	dokploy  string
	parentID domain.ID
}
type existingEnvironment struct {
	yallaID  domain.ID
	dokploy  string
	parentID domain.ID
}
type existingService struct {
	yallaID  domain.ID
	dokploy  string
	parentID domain.ID
}

func newRepo() *fakeRepo {
	return &fakeRepo{
		organizations:          map[domain.ID]struct{}{},
		projectsByDok:          map[string]domain.ID{},
		projectsBySlug:         map[string]existingProject{},
		envByDok:               map[string]domain.ID{},
		envBySlug:              map[string]existingEnvironment{},
		svcByDok:               map[string]domain.ID{},
		svcBySlug:              map[string]existingService{},
		failServiceByDokployID: map[string]error{},
	}
}

func (r *fakeRepo) seedOrg(id domain.ID) { r.organizations[id] = struct{}{} }

func (r *fakeRepo) seedProject(orgID domain.ID, slug, dokployID string, yallaID domain.ID) {
	r.projectsByDok[string(orgID)+"|"+dokployID] = yallaID
	r.projectsBySlug[string(orgID)+"|"+slug] = existingProject{
		yallaID: yallaID, dokploy: dokployID, parentID: orgID,
	}
}

func notFound(resource, id string) error { return apierr.NotFound(resource, id) }

func (r *fakeRepo) FindOrganization(_ context.Context, id domain.ID) (migrateimport.ExistingOrganization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindOrganization:"+string(id))
	if _, ok := r.organizations[id]; !ok {
		return migrateimport.ExistingOrganization{}, notFound("organization", string(id))
	}
	return migrateimport.ExistingOrganization{ID: id}, nil
}

func (r *fakeRepo) FindProjectByDokployID(_ context.Context, orgID domain.ID, dokployID string) (migrateimport.ExistingProject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindProjectByDokployID:"+string(orgID)+"|"+dokployID)
	id, ok := r.projectsByDok[string(orgID)+"|"+dokployID]
	if !ok {
		return migrateimport.ExistingProject{}, notFound("project", dokployID)
	}
	// Find the linked record for full reporting.
	for _, p := range r.projectsBySlug {
		if p.yallaID == id {
			return migrateimport.ExistingProject{ID: id, DokployID: p.dokploy}, nil
		}
	}
	return migrateimport.ExistingProject{ID: id, DokployID: dokployID}, nil
}

func (r *fakeRepo) FindProjectBySlug(_ context.Context, orgID domain.ID, slug string) (migrateimport.ExistingProject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindProjectBySlug:"+string(orgID)+"|"+slug)
	p, ok := r.projectsBySlug[string(orgID)+"|"+slug]
	if !ok {
		return migrateimport.ExistingProject{}, notFound("project", slug)
	}
	return migrateimport.ExistingProject{ID: p.yallaID, DokployID: p.dokploy}, nil
}

func (r *fakeRepo) CreateProject(_ context.Context, in migrateimport.CreateProjectInput) (domain.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CreateProject:"+string(in.OrganizationID)+"|"+in.Slug+"|"+in.DokployID)
	if r.createProjectErr != nil {
		return "", r.createProjectErr
	}
	r.nextProj++
	id := domain.ID("proj_01hz0000000000000000fake0" + indexLetter(r.nextProj))
	r.projectsByDok[string(in.OrganizationID)+"|"+in.DokployID] = id
	r.projectsBySlug[string(in.OrganizationID)+"|"+in.Slug] = existingProject{
		yallaID: id, dokploy: in.DokployID, parentID: in.OrganizationID,
	}
	return id, nil
}

func (r *fakeRepo) FindEnvironmentByDokployID(_ context.Context, projID domain.ID, dokployID string) (migrateimport.ExistingEnvironment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindEnvironmentByDokployID:"+string(projID)+"|"+dokployID)
	id, ok := r.envByDok[string(projID)+"|"+dokployID]
	if !ok {
		return migrateimport.ExistingEnvironment{}, notFound("environment", dokployID)
	}
	return migrateimport.ExistingEnvironment{ID: id, ProjectID: projID, DokployID: dokployID}, nil
}

func (r *fakeRepo) FindEnvironmentBySlug(_ context.Context, projID domain.ID, slug string) (migrateimport.ExistingEnvironment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindEnvironmentBySlug:"+string(projID)+"|"+slug)
	e, ok := r.envBySlug[string(projID)+"|"+slug]
	if !ok {
		return migrateimport.ExistingEnvironment{}, notFound("environment", slug)
	}
	return migrateimport.ExistingEnvironment{ID: e.yallaID, ProjectID: projID, DokployID: e.dokploy}, nil
}

func (r *fakeRepo) CreateEnvironment(_ context.Context, in migrateimport.CreateEnvironmentInput) (domain.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CreateEnvironment:"+string(in.ProjectID)+"|"+in.Slug+"|"+in.DokployID)
	if r.createEnvErr != nil {
		return "", r.createEnvErr
	}
	r.nextEnv++
	id := domain.ID("env_01hz0000000000000000fakee0" + indexLetter(r.nextEnv))
	r.envByDok[string(in.ProjectID)+"|"+in.DokployID] = id
	r.envBySlug[string(in.ProjectID)+"|"+in.Slug] = existingEnvironment{
		yallaID: id, dokploy: in.DokployID, parentID: in.ProjectID,
	}
	return id, nil
}

func (r *fakeRepo) FindServiceByDokployID(_ context.Context, envID domain.ID, dokployID string) (migrateimport.ExistingService, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindServiceByDokployID:"+string(envID)+"|"+dokployID)
	id, ok := r.svcByDok[string(envID)+"|"+dokployID]
	if !ok {
		return migrateimport.ExistingService{}, notFound("service", dokployID)
	}
	return migrateimport.ExistingService{ID: id, EnvironmentID: envID, DokployID: dokployID}, nil
}

func (r *fakeRepo) FindServiceBySlug(_ context.Context, envID domain.ID, slug string) (migrateimport.ExistingService, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "FindServiceBySlug:"+string(envID)+"|"+slug)
	s, ok := r.svcBySlug[string(envID)+"|"+slug]
	if !ok {
		return migrateimport.ExistingService{}, notFound("service", slug)
	}
	return migrateimport.ExistingService{ID: s.yallaID, EnvironmentID: envID, DokployID: s.dokploy}, nil
}

func (r *fakeRepo) CreateService(_ context.Context, in migrateimport.CreateServiceInput) (domain.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CreateService:"+string(in.EnvironmentID)+"|"+in.Slug+"|"+in.DokployID)
	if injected, ok := r.failServiceByDokployID[in.DokployID]; ok {
		return "", injected
	}
	if r.createSvcErr != nil {
		return "", r.createSvcErr
	}
	r.nextSvc++
	id := domain.ID("svc_01hz0000000000000000fakes0" + indexLetter(r.nextSvc))
	r.svcByDok[string(in.EnvironmentID)+"|"+in.DokployID] = id
	r.svcBySlug[string(in.EnvironmentID)+"|"+in.Slug] = existingService{
		yallaID: id, dokploy: in.DokployID, parentID: in.EnvironmentID,
	}
	return id, nil
}

// indexLetter is a 1-based index expressed as a single Crockford32 lowercase
// letter used only to mint distinct fake Yalla IDs. Tests never index past
// the alphabet end. Skips Crockford-excluded characters (i, l, o, u).
func indexLetter(n int) string {
	const alphabet = "23456789abcdefghjkmnpqrstvwxyz"
	if n < 1 || n > len(alphabet) {
		return "z"
	}
	return string(alphabet[n-1])
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNew_RequiresPorts(t *testing.T) {
	t.Parallel()
	if _, err := migrateimport.New(migrateimport.Config{
		Scanner: &fakeScanner{}, Repository: newRepo(),
	}); err != nil {
		t.Fatalf("New(full) = %v; want nil", err)
	}

	cases := []struct {
		name string
		cfg  migrateimport.Config
	}{
		{"no scanner", migrateimport.Config{Repository: newRepo()}},
		{"no repository", migrateimport.Config{Scanner: &fakeScanner{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			imp, err := migrateimport.New(tc.cfg)
			if err == nil {
				t.Fatalf("New() = %+v; want error", imp)
			}
			var ye *yerr.Error
			if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInternal {
				t.Fatalf("New() err = %v; want CodeInternal", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Plan: input validation
// ---------------------------------------------------------------------------

func TestPlan_RejectsBlankDokployOrganization(t *testing.T) {
	t.Parallel()
	imp := mustImporter(t, &fakeScanner{}, newRepo())
	if _, err := imp.Plan(context.Background(), migrateimport.PlanInput{}); !isInvalidInput(err, "dokploy_organization_id") {
		t.Fatalf("Plan(blank) err = %v; want InvalidInput on dokploy_organization_id", err)
	}
}

func TestPlan_RejectsAssignmentMismatch(t *testing.T) {
	t.Parallel()
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: "different-org",
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if !isInvalidInput(err, "assignment.dokploy_organization_id") {
		t.Fatalf("Plan(mismatch) err = %v; want InvalidInput on assignment.dokploy_organization_id", err)
	}
}

func TestPlan_RejectsAssignmentWithoutDokployOrg(t *testing.T) {
	t.Parallel()
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			YallaOrganizationID: fixtureYallaOrg,
		},
	})
	if !isInvalidInput(err, "assignment.dokploy_organization_id") {
		t.Fatalf("Plan(no dokploy) err = %v; want InvalidInput on assignment.dokploy_organization_id", err)
	}
}

func TestPlan_RejectsMalformedYallaOrg(t *testing.T) {
	t.Parallel()
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   "not-a-valid-id",
		},
	})
	if !isInvalidInput(err, "assignment.yalla_organization_id") {
		t.Fatalf("Plan(malformed yalla) err = %v; want InvalidInput on assignment.yalla_organization_id", err)
	}
}

func TestPlan_RejectsWrongKindYallaOrg(t *testing.T) {
	t.Parallel()
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureProj1, // proj, not org
		},
	})
	if !isInvalidInput(err, "assignment.yalla_organization_id") {
		t.Fatalf("Plan(wrong kind) err = %v; want InvalidInput on assignment.yalla_organization_id", err)
	}
}

// ---------------------------------------------------------------------------
// Plan: pending-owner dry run
// ---------------------------------------------------------------------------

func TestPlan_PendingOwner_ListsItemsAndSkipsRepository(t *testing.T) {
	t.Parallel()
	snap := simpleSnapshot()
	scanner := &fakeScanner{snapshot: snap}
	repo := newRepo()
	imp := mustImporter(t, scanner, repo)

	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
	})
	if err != nil {
		t.Fatalf("Plan(no assignment) err = %v; want nil", err)
	}
	if plan.YallaOrganizationID != "" {
		t.Fatalf("plan.YallaOrganizationID = %q; want empty", plan.YallaOrganizationID)
	}
	for _, item := range plan.Items {
		// Service-level unsupported / missing-parent items still classify
		// structurally — but no project / env / supported-service should be
		// StatusReady in the absence of an owner.
		if item.Status == migrateimport.StatusReady {
			t.Errorf("item %+v was StatusReady without an owner", item)
		}
	}
	if len(repo.calls) != 0 {
		t.Fatalf("Repository was queried %d times in dry run; want 0", len(repo.calls))
	}
}

// ---------------------------------------------------------------------------
// Plan: classification
// ---------------------------------------------------------------------------

func TestPlan_ClassifiesDuplicateMissingParentAndUnsupported(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	// Pre-seed an existing Yalla project that COLLIDES on slug with one of
	// the snapshot projects: the snapshot's first project is named "Web"
	// (slug "web"); seed an existing "web" with a *different* Dokploy ID.
	repo.seedProject(fixtureYallaOrg, "web", "some-other-dokploy-proj", fixtureProj1)

	snap := simpleSnapshot()
	imp := mustImporter(t, &fakeScanner{snapshot: snap}, repo)

	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}

	dup := findItemByDokployID(plan.Items, dokployProj1)
	if dup == nil || dup.Status != migrateimport.StatusSkipDuplicate ||
		dup.Reason != migrateimport.ReasonDuplicateName ||
		dup.ExistingYallaID != fixtureProj1 {
		t.Fatalf("dup item = %+v; want StatusSkipDuplicate with existing %q", dup, fixtureProj1)
	}

	missing := findItemByDokployID(plan.Items, dokployEnvX)
	if missing == nil || missing.Status != migrateimport.StatusSkipMissingParent ||
		missing.Reason != migrateimport.ReasonMissingParentImport {
		t.Fatalf("missing-parent env = %+v; want StatusSkipMissingParent", missing)
	}

	unsup := findItemByDokployID(plan.Items, dokploySvcBad)
	if unsup == nil || unsup.Status != migrateimport.StatusSkipUnsupported ||
		unsup.Reason != migrateimport.ReasonUnsupportedServiceType {
		t.Fatalf("unsupported svc = %+v; want StatusSkipUnsupported", unsup)
	}

	// The second project should still be ready (slug "api" doesn't clash).
	api := findItemByDokployID(plan.Items, dokployProj2)
	if api == nil || api.Status != migrateimport.StatusReady ||
		api.ProposedSlug != "api" {
		t.Fatalf("ready project = %+v; want StatusReady slug 'api'", api)
	}

	// A missing-parent service is also classified, even though its env was
	// skipped or absent.
	missSvc := findItemByDokployID(plan.Items, dokploySvcMiss)
	if missSvc == nil || missSvc.Status != migrateimport.StatusSkipMissingParent {
		t.Fatalf("missing-parent svc = %+v; want StatusSkipMissingParent", missSvc)
	}
}

func TestPlan_ClassifiesAlreadyLinkedAsIdempotentSkip(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	// Pre-seed a Yalla project ALREADY linked to dokployProj2 — its slug
	// matches what NormalizeSlug would produce for "Api" too.
	repo.seedProject(fixtureYallaOrg, "api", dokployProj2, fixtureProj2)

	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, repo)
	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}

	api := findItemByDokployID(plan.Items, dokployProj2)
	if api == nil || api.Status != migrateimport.StatusSkipAlreadyImported ||
		api.ExistingYallaID != fixtureProj2 {
		t.Fatalf("already-linked api = %+v; want StatusSkipAlreadyImported with %q", api, fixtureProj2)
	}
}

func TestPlan_NotFoundOwnerSurfacesAsApierr(t *testing.T) {
	t.Parallel()
	// repo intentionally does NOT seed the org → owner missing.
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if !hasCode(err, yerr.CodeNotFound) {
		t.Fatalf("Plan(unknown owner) err = %v; want CodeNotFound", err)
	}
}

func TestPlan_ScannerFailureSurfacesAsDokployUnavailable(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	scanErr := stderrors.New("dokploy network unreachable")
	imp := mustImporter(t, &fakeScanner{err: scanErr}, repo)

	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
	})
	if !hasCode(err, yerr.CodeServer) {
		t.Fatalf("Plan(scanner fail) err = %v; want CodeServer", err)
	}
}

func TestPlan_ScannerReturningWrongOrganizationIsInternal(t *testing.T) {
	t.Parallel()
	snap := simpleSnapshot()
	snap.Organization.DokployID = "a-different-org"
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	imp := mustImporter(t, &fakeScanner{snapshot: snap}, repo)

	_, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if !hasCode(err, yerr.CodeInternal) {
		t.Fatalf("Plan(wrong-org scanner) err = %v; want CodeInternal", err)
	}
}

// ---------------------------------------------------------------------------
// Plan: redaction
// ---------------------------------------------------------------------------

func TestPlan_RedactsSecretsInScannerErrors(t *testing.T) {
	t.Parallel()
	const secret = "dkp_token_supersecret_123456789"
	redactor := output.NewRedactor(secret)

	scanErr := stderrors.New("dokploy upstream rejected token=" + secret)
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)

	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    &fakeScanner{err: scanErr},
		Repository: repo,
		Redactor:   redactor,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New() = %v; want nil", err)
	}

	_, err = imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
	})
	if err == nil {
		t.Fatalf("Plan(scanner err) = nil; want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Plan error leaked secret %q: %v", secret, err)
	}
}

// ---------------------------------------------------------------------------
// Apply: success / partial / skip
// ---------------------------------------------------------------------------

func TestApply_PersistsReadyItemsInHierarchyOrder(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, repo)

	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}
	res, err := imp.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply = %v; want nil", err)
	}
	if res.Imported < 1 {
		t.Fatalf("Apply imported 0 items; expected at least one ready import")
	}
	if len(res.Failures) != 0 {
		t.Fatalf("Apply failures = %v; want none", res.Failures)
	}

	// Hierarchy order: every CreateProject precedes every CreateEnvironment;
	// every CreateEnvironment precedes every CreateService.
	lastProj, lastEnv := -1, -1
	for i, call := range repo.calls {
		switch {
		case strings.HasPrefix(call, "CreateProject:"):
			lastProj = i
		case strings.HasPrefix(call, "CreateEnvironment:"):
			if lastProj == -1 || i < lastProj {
				t.Fatalf("CreateEnvironment %d preceded a CreateProject: %v", i, repo.calls)
			}
			lastEnv = i
		case strings.HasPrefix(call, "CreateService:"):
			if lastEnv == -1 || i < lastEnv {
				t.Fatalf("CreateService %d preceded a CreateEnvironment: %v", i, repo.calls)
			}
		}
	}
}

func TestApply_PartialFailureContinuesAndCollectsFailure(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	// Inject a failure on the service create so only the service fails; the
	// project+env still import.
	repo.failServiceByDokployID[dokploySvc1] = stderrors.New("disk full")

	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, repo)
	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}

	res, err := imp.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply = %v; want nil", err)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("Apply failures = %d; want 1: %+v", len(res.Failures), res.Failures)
	}
	if res.Failures[0].Item.DokployResourceID != dokploySvc1 {
		t.Fatalf("failure was on %q; want %q", res.Failures[0].Item.DokployResourceID, dokploySvc1)
	}
	if res.Imported < 1 {
		t.Fatalf("Apply imported %d items; want at least one", res.Imported)
	}
}

func TestApply_NoReadyItemsIsValidNoop(t *testing.T) {
	t.Parallel()
	// Snapshot that has only unsupported / missing-parent / pending-owner
	// items: no StatusReady can result. Build by passing no assignment, so
	// every item is StatusPendingOwner.
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, newRepo())
	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}
	res, err := imp.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply(no ready) = %v; want nil", err)
	}
	if res.Imported != 0 {
		t.Fatalf("Imported = %d; want 0", res.Imported)
	}
	if res.Skipped == 0 {
		t.Fatalf("Skipped = 0; want > 0")
	}
}

func TestApply_RedactsFailureErrors(t *testing.T) {
	t.Parallel()
	const secret = "dkp_failure_token_abcdef0123456789"
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	repo.createProjectErr = stderrors.New("upstream rejected token=" + secret)

	redactor := output.NewRedactor(secret)
	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    &fakeScanner{snapshot: simpleSnapshot()},
		Repository: repo,
		Redactor:   redactor,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New = %v; want nil", err)
	}

	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}
	res, err := imp.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply = %v; want nil", err)
	}
	if len(res.Failures) == 0 {
		t.Fatalf("Apply failures = 0; want >= 1 (createProjectErr was injected)")
	}
	for _, f := range res.Failures {
		if strings.Contains(f.Err.Error(), secret) {
			t.Fatalf("failure leaked secret %q: %v", secret, f.Err)
		}
	}
}

func TestApply_ContextCancellationStopsLoop(t *testing.T) {
	t.Parallel()
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	imp := mustImporter(t, &fakeScanner{snapshot: simpleSnapshot()}, repo)

	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := imp.Apply(ctx, plan); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("Apply(cancelled) err = %v; want context.Canceled", err)
	}
}

func TestApply_LogsFailuresWithoutLeakingSecrets(t *testing.T) {
	t.Parallel()
	const secret = "dkp_log_secret_0xdeadbeefcafe"
	repo := newRepo()
	repo.seedOrg(fixtureYallaOrg)
	repo.createProjectErr = stderrors.New("token=" + secret)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    &fakeScanner{snapshot: simpleSnapshot()},
		Repository: repo,
		Redactor:   output.NewRedactor(secret),
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("New = %v; want nil", err)
	}
	plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
		DokployOrganizationID: dokployOrg,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: dokployOrg,
			YallaOrganizationID:   fixtureYallaOrg,
		},
	})
	if err != nil {
		t.Fatalf("Plan = %v; want nil", err)
	}
	if _, err := imp.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply = %v; want nil", err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("log buffer leaked secret %q: %q", secret, buf.String())
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustImporter(t *testing.T, scanner migrateimport.Scanner, repo migrateimport.Repository) *migrateimport.Importer {
	t.Helper()
	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    scanner,
		Repository: repo,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New = %v; want nil", err)
	}
	return imp
}

func simpleSnapshot() migrateimport.Snapshot {
	return migrateimport.Snapshot{
		Organization: migrateimport.SnapshotOrganization{
			DokployID: dokployOrg,
			Name:      "Acme",
		},
		Projects: []migrateimport.SnapshotProject{
			{DokployID: dokployProj1, DokployOrganizationID: dokployOrg, Name: "Web"},
			{DokployID: dokployProj2, DokployOrganizationID: dokployOrg, Name: "Api"},
			// foreign project — different org → filtered out by the indexer
			{DokployID: "foreign-1", DokployOrganizationID: "other-org", Name: "Should not appear"},
		},
		Environments: []migrateimport.SnapshotEnvironment{
			{DokployID: dokployEnv1, DokployProjectID: dokployProj1, Name: "Prod"},
			{DokployID: dokployEnv2, DokployProjectID: dokployProj2, Name: "Stage"},
			{DokployID: dokployEnvX, DokployProjectID: dokployProjX, Name: "Orphan"},
		},
		Services: []migrateimport.SnapshotService{
			{DokployID: dokploySvc1, DokployEnvironmentID: dokployEnv1, Name: "web", Type: "application"},
			{DokployID: dokploySvcBad, DokployEnvironmentID: dokployEnv2, Name: "weird", Type: "weird-type"},
			{DokployID: dokploySvcMiss, DokployEnvironmentID: "ghost-env", Name: "orphan-svc", Type: "application"},
		},
	}
}

func findItemByDokployID(items []migrateimport.PlanItem, id string) *migrateimport.PlanItem {
	for i := range items {
		if items[i].DokployResourceID == id {
			return &items[i]
		}
	}
	return nil
}

func isInvalidInput(err error, wantField string) bool {
	if err == nil {
		return false
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		return false
	}
	if ye.Code != yerr.CodeValidation {
		return false
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		// Field-less InvalidInput (e.g. Invalid(message)) still counts as a
		// match on wantField == "" but never on a named field.
		return wantField == ""
	}
	for _, v := range violations {
		if v.Field == wantField {
			return true
		}
	}
	return false
}

func hasCode(err error, want yerr.Code) bool {
	if err == nil {
		return false
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		return false
	}
	return ye.Code == want
}
