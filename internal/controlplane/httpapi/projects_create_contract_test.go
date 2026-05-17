package httpapi

import (
	"bytes"
	stderrors "errors"
	"log/slog"
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

// Public-API contract coverage for POST /v1/projects (BE-0122).
//
// projects_create_test.go already proves the 201 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the principal-scoped forwarding of CreateProjectInput, the
// strict-decoder rejection of unknown organization_id smuggling, the
// malformed-body / unauthenticated / viewer-forbidden / invalid-input /
// conflict / store-unavailable / nil-creator wiring paths, and the OpenAPI
// operation registration (TestCreateProjectRouteIsDocumented). This file
// closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// Structural twin of api_keys_create_contract_test.go (BE-0080), adapted to
// the projects POST request shape (no path parameter, ProjectCreator port,
// createProjectPayload response data block).

// createProjectContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const createProjectContractSecret = "yk_live_supersecret_projects_create_DEADBEEF0123456789"

// createProjectHandlerForWithLogger builds the production POST /v1/projects
// request path (real policy engine, fake Authenticator, caller-supplied
// ProjectCreator) with a caller-supplied logger so a test can inspect the
// structured request log. It mirrors createProjectHandlerFor for the
// projects CREATE endpoint, with the logger threaded into NewHandler so the
// per-request slog record lands in the caller's buffer.
func createProjectHandlerForWithLogger(
	id auth.Identity, authErr error, creator ProjectCreator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, creator, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{},
		fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{},
		fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{},
		fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{},
		fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{},
		fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{},
		fakeServiceLogReader{}, fakeServiceMetricsReader{},
		fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{},
		fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{},
		fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{},
		fakeBreakGlassController{}, logger, nil)
}

// TestCreateProjectServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone: a
// served POST /v1/projects writes nothing to the process stdout/stderr, and
// the created-project payload is carried by the response body.
func TestCreateProjectServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	row := store.Project{
		ID:             "prj_acme_alpha",
		OrganizationID: "org_acme",
		Slug:           "alpha",
		DisplayName:    "Alpha service",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	creator := fakeProjectCreator{project: row}
	handler := createProjectHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postProjects(handler, createProjectContractSecret,
			createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha service"))
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing — response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing — response data must go through the ResponseWriter", stderr)
	}

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProject(t, rec)
	if env.Data.Project.ProjectID != "prj_acme_alpha" {
		t.Errorf("project.project_id = %q, want prj_acme_alpha — the data must be carried by the response body",
			env.Data.Project.ProjectID)
	}
	if env.Data.Project.Slug != "alpha" {
		t.Errorf("project.slug = %q, want alpha — the data must be carried by the response body",
			env.Data.Project.Slug)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCreateProjectRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials.
func TestCreateProjectRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	developer := orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper)
	viewer := orgPrincipal("usr_eve", "org_acme", policy.RoleViewer)

	created := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	successCreator := fakeProjectCreator{project: store.Project{
		ID:             "prj_acme_alpha",
		OrganizationID: "org_acme",
		Slug:           "alpha",
		DisplayName:    "Alpha service",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      created,
	}}
	// The viewer request must never reach the creator. A creator that would
	// error if invoked proves the deny path short-circuits at policy, so any
	// logged "creator error" can't be the leak source.
	denyCreator := fakeProjectCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    ProjectCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: developer, Method: auth.MethodSession},
			creator:    successCreator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: viewer, Method: auth.MethodSession},
			creator:    denyCreator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createProjectHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postProjects(handler, createProjectContractSecret,
				createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha service"))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createProjectContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createProjectContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateProjectErrorEnvelopeDoesNotLeakDependencyCause proves a
// creator-store outage surfaces as a typed 5xx whose error envelope carries
// a stable generic message — the wrapped driver cause (host, port,
// "connection refused") is kept for server-side logs only and never reaches
// the client. projects_create_test.go pins the typed-status part of this
// contract (TestCreateProjectStoreUnavailablePropagates); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries.
func TestCreateProjectErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	creator := fakeProjectCreator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator,
	)

	rec := postProjects(handler, createProjectContractSecret,
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha service"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if env.Error.Message == "" {
		t.Error("error.message is empty, want a stable generic message")
	}
	if strings.Contains(rec.Body.String(), cause) {
		t.Errorf("error envelope leaked the wrapped dependency cause %q: %s", cause, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("error envelope leaked the datastore address: %s", rec.Body.String())
	}
}
