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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for GET
// /v1/projects/{project_id}/grants (BE-0137).
//
// project_grants_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / not-found / dependency-failure rejection space, the
// "empty project is a stable [] shape" invariant, the "store outage
// surfaces as a typed 503" invariant, the "reader receives the
// principal's home org plus the path {project_id}" wiring invariant,
// and the "missing reader is a typed 500" invariant.
// projects_grants_policy_test.go pins the full policy matrix
// (viewer/developer/owner roles plus the support principal's
// cross-tenant CapRead exception for the project.grants.read action).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries.
//
// GET /v1/projects/{project_id}/grants accepts a single opaque
// {project_id} path parameter and no body and no query parameters. The
// store-backed reader treats an unknown or cross-tenant project_id as a
// deterministic 404, which is the contract project_grants_test.go's
// TestListProjectGrantsForwardsNotFoundFromReader pins. Structural twin
// of variables_get_contract_test.go (BE-0107) and
// projects_get_contract_test.go, adapted to the project grants read
// request shape ({project_id} path parameter, ProjectGrantReader port,
// no query parameters).

// listProjectGrantsContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails.
const listProjectGrantsContractSecret = "yk_live_supersecret_project_grants_get_DEADBEEF0123456789"

// listProjectGrantsHandlerForWithLogger builds the production GET
// /v1/projects/{project_id}/grants request path (real policy engine,
// fake Authenticator, caller-supplied ProjectGrantReader) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors listOrgVariablesHandlerForWithLogger for the project
// grants READ endpoint.
func listProjectGrantsHandlerForWithLogger(
	id auth.Identity, authErr error, reader ProjectGrantReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		reader, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestListProjectGrantsServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served GET
// /v1/projects/{project_id}/grants writes nothing to the process
// stdout/stderr, and the grants payload is carried by the response
// body. The structured logger is the only sanctioned out-of-band writer
// and it goes to its own buffer, never to the process streams.
func TestListProjectGrantsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeProjectGrantReader{
		grants: []store.ProjectGrant{
			seedProjectGrantWire(
				"grnt_001", orgID, projectID,
				"usr_member", string(domain.KindUser), string(policy.RoleDeveloper),
				nil, nil, 1, created, created,
			),
		},
	}
	handler := listProjectGrantsHandlerForWithLogger(
		principalForGrants("usr_owner", orgID), nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getProjectGrants(handler, projectID, listProjectGrantsContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing — response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing — response data must go through the ResponseWriter", stderr)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectGrants(t, rec)
	if len(env.Data.Grants) != 1 {
		t.Fatalf("grants = %+v, want exactly the seeded entry", env.Data.Grants)
	}
	if env.Data.Grants[0].GrantID != "grnt_001" {
		t.Errorf("grants[0].grant_id = %q, want %q — the data must be carried by the response body",
			env.Data.Grants[0].GrantID, "grnt_001")
	}
	if env.Data.Grants[0].ProjectID != projectID {
		t.Errorf("grants[0].project_id = %q, want %q — the data must be carried by the response body",
			env.Data.Grants[0].ProjectID, projectID)
	}
	// The structured logger is the only sanctioned writer, and it goes to
	// its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListProjectGrantsRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny leg
// uses a disabled principal so policy short-circuits before the reader
// runs, and the reader's ListProjectGrants returns an error if invoked,
// proving that a logged "reader error" cannot be the leak source.
func TestListProjectGrantsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	allowed := principalForGrants("usr_ada", orgID)
	denied := principalForGrants("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successReader := fakeProjectGrantReader{
		grants: []store.ProjectGrant{
			seedProjectGrantWire(
				"grnt_001", orgID, projectID,
				"usr_member", string(domain.KindUser), string(policy.RoleDeveloper),
				nil, nil, 1, created, created,
			),
		},
	}
	// The disabled-principal request must never reach the reader. A reader
	// whose ListProjectGrants path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "reader error" can't be the
	// leak source.
	denyReader := fakeProjectGrantReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     ProjectGrantReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
			reader:     denyReader,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := listProjectGrantsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getProjectGrants(handler, projectID, listProjectGrantsContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listProjectGrantsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listProjectGrantsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListProjectGrantsErrorEnvelopeDoesNotLeakDependencyCause proves a
// reader-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. project_grants_test.go pins the typed-status
// part of this contract
// (TestListProjectGrantsSurfacesStoreOutage); this test pins the "the
// wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries (a
// datastore address is exactly the kind of internal-network detail an
// error envelope must never leak).
func TestListProjectGrantsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	reader := fakeProjectGrantReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listProjectGrantsHandlerFor(
		principalForGrants("usr_owner", orgID), nil, reader,
	)

	rec := getProjectGrants(handler, projectID, listProjectGrantsContractSecret)
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
