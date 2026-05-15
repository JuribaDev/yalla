package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract, authorization, and tenant-isolation coverage for GET /v1/projects
// (BE-0118 / BE-0119). The endpoint lists the projects visible to the
// authenticated principal — by reading every project the principal's home
// organization owns through the ProjectReader port. The tests drive it
// through NewHandler with a fake Authenticator, the real policy engine, and a
// fake reader — the same wiring a request hits in production, minus the
// database. The store-backed reader has its own isolated-Postgres integration
// coverage in store/project_test.go.
//
// This endpoint has no path parameter, no request body, and no query
// parameters: its only input is the authenticated principal's home
// organization id. There is therefore no syntactic request to reject — the
// "validation" coverage for this story is the deterministic empty list a
// principal whose organization owns no projects receives.

// fakeProjectReader is a canned ProjectReader for httpapi tests. The zero
// value returns an empty slice and no error from ListProjects and a
// zero-value store.Project from GetProject, which is all the tests that
// never reach the handler (the public-surface, /v1/me, and other-route
// suites) need. List tests set projects/err and read gotOrgID back to
// prove the read is scoped to the principal's own home organization id and
// never to a caller-controlled value; by-id tests set project/getErr to
// drive the happy / not-found / dependency-failure branches and read
// gotGetOrgID + gotGetProjectID back to prove the (org, project) pair
// forwarded to the store is the principal's home org plus the path
// project_id — never a caller-controlled organization id.
type fakeProjectReader struct {
	projects        []store.Project
	err             error
	gotOrgID        *string
	project         store.Project
	getErr          error
	gotGetOrgID     *string
	gotGetProjectID *string
}

func (f fakeProjectReader) ListProjects(_ context.Context, organizationID string) ([]store.Project, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	return f.projects, f.err
}

func (f fakeProjectReader) GetProject(_ context.Context, organizationID, projectID string) (store.Project, error) {
	if f.gotGetOrgID != nil {
		*f.gotGetOrgID = organizationID
	}
	if f.gotGetProjectID != nil {
		*f.gotGetProjectID = projectID
	}
	return f.project, f.getErr
}

// listProjectsSuccessEnvelope is the decoded shape of the GET /v1/projects
// success envelope.
type listProjectsSuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          listProjectsPayload `json:"data"`
}

// listProjectsHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectReader. It is the production request path: the /v1/projects route
// is wrapped in RequireAuth for action project.read.
func listProjectsHandlerFor(id auth.Identity, authErr error, reader ProjectReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		reader, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, nil)
}

// getProjects issues GET /v1/projects against handler, optionally with a
// bearer token.
func getProjects(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListProjects(t *testing.T, rec *httptest.ResponseRecorder) listProjectsSuccessEnvelope {
	t.Helper()
	var env listProjectsSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// seedProject builds a store.Project fixture for the fakeProjectReader. It
// is a plain literal helper — no database — so the tests stay pure unit
// tests of the HTTP wire path.
func seedProject(id, orgID, slug, displayName string, version int64, created, updated time.Time) store.Project {
	return store.Project{
		ID:             id,
		OrganizationID: orgID,
		Slug:           slug,
		DisplayName:    displayName,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListProjectsReturnsVisibleProjects is the happy path: an authenticated
// principal receives every project the source-of-truth database lists for
// the principal's home organization, in a stable yalla.output.v1 envelope,
// with every column projected onto the wire shape.
func TestListProjectsReturnsVisibleProjects(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	first := seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha service", 1, created, updated)
	second := seedProject("prj_acme_beta", "org_acme", "beta", "Beta service", 4, created, updated)
	reader := fakeProjectReader{projects: []store.Project{first, second}}

	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjects(handler, "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjects(t, rec)
	if got, want := len(env.Data.Projects), 2; got != want {
		t.Fatalf("len(projects) = %d, want %d; body %s", got, want, rec.Body.String())
	}
	got := env.Data.Projects[0]
	want := projectResource{
		ProjectID:      first.ID,
		OrganizationID: first.OrganizationID,
		Slug:           first.Slug,
		DisplayName:    first.DisplayName,
		Version:        first.Version,
		CreatedAt:      created.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      updated.UTC().Format(time.RFC3339Nano),
	}
	if got != want {
		t.Errorf("projects[0] = %+v, want %+v", got, want)
	}
	if env.Data.Projects[1].ProjectID != second.ID {
		t.Errorf("projects[1].project_id = %q, want %q", env.Data.Projects[1].ProjectID, second.ID)
	}
}

// TestListProjectsScopesToPrincipalHomeOrganization proves the reader is
// always called with the authenticated principal's own home organization id
// — never the result of caller-supplied input — so the tenant boundary is
// structural and a request can never point the read at another tenant.
func TestListProjectsScopesToPrincipalHomeOrganization(t *testing.T) {
	t.Parallel()

	var got string
	reader := fakeProjectReader{gotOrgID: &got}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjects(handler, "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got != "org_acme" {
		t.Errorf("reader called with organizationID = %q, want %q", got, "org_acme")
	}
}

// TestListProjectsReturnsEmptyArrayWhenOrganizationHasNoProjects proves the
// payload is always a non-nil JSON array (never null and never missing), so
// agents can iterate without a nil check.
func TestListProjectsReturnsEmptyArrayWhenOrganizationHasNoProjects(t *testing.T) {
	t.Parallel()

	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, fakeProjectReader{})
	rec := getProjects(handler, "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"projects":[]`) {
		t.Errorf("body does not contain empty projects array; body %s", rec.Body.String())
	}
	env := decodeListProjects(t, rec)
	if env.Data.Projects == nil {
		t.Error("projects is nil, want a non-nil empty array")
	}
	if got := len(env.Data.Projects); got != 0 {
		t.Errorf("len(projects) = %d, want 0", got)
	}
}

// TestListProjectsRequiresAuthentication proves an anonymous caller is
// rejected with the canonical 401 — RequireAuth gates the route, the
// handler never runs, and the reader is never consulted.
func TestListProjectsRequiresAuthentication(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{err: stderrors.New("reader must not be called")}
	handler := listProjectsHandlerFor(auth.Identity{}, nil, reader)
	rec := getProjects(handler, "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestListProjectsRejectsInvalidCredentials proves a credential the
// authenticator rejects yields the canonical 401 — RequireAuth gates the
// route, the handler never runs, and the reader is never consulted.
func TestListProjectsRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{err: stderrors.New("reader must not be called")}
	handler := listProjectsHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials, reader)
	rec := getProjects(handler, "tok-bad")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestListProjectsForwardsReaderStoreOutage proves a typed datastore
// failure from the reader is propagated as a typed 5xx envelope — never
// disguised as an empty success.
func TestListProjectsForwardsReaderStoreOutage(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjects(handler, "tok-ada")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
}

// TestListProjectsForRoleAdmitsCapReadRoles enumerates each
// organization-wide role the policy engine treats as CapRead — owner,
// admin, developer, viewer, ci — and proves it can list its home
// organization's projects through the wire endpoint, never another
// tenant's. The fake reader returns one project so we can also assert the
// wire-shape projection survives every role.
func TestListProjectsForRoleAdmitsCapReadRoles(t *testing.T) {
	t.Parallel()

	roles := []policy.Role{
		policy.RoleOwner,
		policy.RoleAdmin,
		policy.RoleDeveloper,
		policy.RoleViewer,
		policy.RoleCI,
	}
	for _, role := range roles {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			project := seedProject("prj_role", "org_acme", "ledger", "Ledger", 1,
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			var got string
			reader := fakeProjectReader{projects: []store.Project{project}, gotOrgID: &got}
			handler := listProjectsHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", role), Method: auth.MethodSession},
				nil, reader)
			rec := getProjects(handler, "tok-ada")

			if rec.Code != http.StatusOK {
				t.Fatalf("role %s: status = %d, want 200; body %s", role, rec.Code, rec.Body.String())
			}
			if got != "org_acme" {
				t.Errorf("role %s: reader called with %q, want org_acme", role, got)
			}
			env := decodeListProjects(t, rec)
			if got, want := len(env.Data.Projects), 1; got != want {
				t.Errorf("role %s: len(projects) = %d, want %d", role, got, want)
			}
		})
	}
}

// TestListProjectsCrossTenantPrincipalSeesOwnOrgProjects proves a principal
// in orgA and a principal in orgB each see their own organization's
// projects — never each other's. The fake reader echoes the
// organization-id it was called with, so the assertion is on which scope
// the reader received.
func TestListProjectsCrossTenantPrincipalSeesOwnOrgProjects(t *testing.T) {
	t.Parallel()

	var gotA, gotB string
	readerA := fakeProjectReader{
		projects: []store.Project{seedProject("prj_a", "org_acme", "alpha", "Alpha", 1, time.Now(), time.Now())},
		gotOrgID: &gotA,
	}
	handlerA := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_a", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, readerA)
	recA := getProjects(handlerA, "tok-a")
	if recA.Code != http.StatusOK || gotA != "org_acme" {
		t.Errorf("orgA: code=%d gotOrgID=%q want 200/org_acme", recA.Code, gotA)
	}

	readerB := fakeProjectReader{
		projects: []store.Project{seedProject("prj_b", "org_other", "beta", "Beta", 1, time.Now(), time.Now())},
		gotOrgID: &gotB,
	}
	handlerB := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_b", "org_other", policy.RoleAdmin), Method: auth.MethodSession},
		nil, readerB)
	recB := getProjects(handlerB, "tok-b")
	if recB.Code != http.StatusOK || gotB != "org_other" {
		t.Errorf("orgB: code=%d gotOrgID=%q want 200/org_other", recB.Code, gotB)
	}
}

// TestListProjectsHandlerRejectsMissingReader proves the handler closure
// fails defensively (typed internal error) if the wired ProjectReader is
// nil — a programming/wiring error, not a client error, so the response is
// a typed 5xx and never an empty 200.
func TestListProjectsHandlerRejectsMissingReader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)))
	rec := run(listProjectsHandler(nil), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), errNoProjectReader.Error()) {
		t.Errorf("body leaks internal sentinel: %s", rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestListProjectsHandlerRejectsMissingPrincipal proves the handler closure
// fails defensively (typed internal error) if it is ever invoked without an
// authenticated principal on the request context — RequireAuth would
// normally reject the request before the handler runs, so this path is a
// wiring guarantee, never a client outcome.
func TestListProjectsHandlerRejectsMissingPrincipal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	rec := run(listProjectsHandler(fakeProjectReader{}), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}
