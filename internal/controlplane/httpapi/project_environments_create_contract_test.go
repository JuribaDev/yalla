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

// Public-API contract coverage for POST
// /v1/projects/{project_id}/environments (BE-0152).
//
// project_environments_create_test.go already proves the 201 success
// envelope, the stable yalla.output.v1 / yalla.error.v1 schema
// versions, the request_id propagation, the OpenAPI operation
// registration, the unauthenticated / malformed-body / unknown-field /
// body-supplied-organization-id-ignored / body-supplied-project-id-
// ignored / viewer-forbidden / store-typed-invalid-input / conflict /
// not-found / quota-exceeded / dependency-failure / nil-creator
// rejection space, and the "creator receives the principal's home org
// plus the path {project_id} plus the decoded body fields plus the
// actor identity" wiring invariant.
// projects_environments_create_policy_test.go pins the full policy
// matrix (viewer / developer / owner / admin / CI / support roles plus
// the deliberate absence of the support cross-tenant exception for the
// environment.create CapWrite action, plus revoked / expired key
// handling and scoped-grant containment).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - the per-request structured log never carries caller-supplied request
//     body material (the headers-not-logged / body-not-logged contract applies
//     symmetrically to the decoded request body for write endpoints), and the
//     deny-path response body never echoes that material either;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries.
//
// Structural twin of project_variables_put_contract_test.go (BE-0146),
// adapted to the project environments WRITE request shape ({project_id}
// path parameter, EnvironmentCreator port, environment.create CapWrite
// action, body that carries caller-supplied environment_id, slug, and
// display_name). The endpoint mutates state and provisions a Dokploy
// job in the same transaction, so a rejected request that nonetheless
// reaches the handler is materially worse than the read-only sibling:
// every deny-leg assertion here is also a "creator was not invoked"
// assertion, so a regression that wires up the creator behind the
// policy gate fails this story in two places.

// createProjectEnvironmentContractSecret is a recognisable bearer
// credential used by the redaction tests: if any byte of it reaches a
// log record or a response body, the test fails. Suffix is distinct
// from replaceProjectVariablesContractSecret (BE-0146),
// listProjectEnvironmentsContractSecret (BE-0149), and every other
// in-tree contract-test bearer so a regression that swaps any of those
// surfaces fails loudly.
const createProjectEnvironmentContractSecret = "yk_live_supersecret_project_environments_post_CAFED00D0123456789"

// createProjectEnvironmentContractSubmittedDisplayName is a
// recognisable caller-supplied display_name value the customer submits
// in the request body. It must never reach the per-request structured
// log — that is the body-not-logged half of the headers-not-logged /
// body-not-logged contract — and it must never reach the response
// body on the authorization-failure path (the deny response is a
// typed error envelope that has no field for caller-supplied display
// names; a leak there would mean the handler decoded the body before
// short-circuiting at the policy gate, which would also mean the
// creator could have been driven). On the success path the response
// body legitimately echoes display_name back, so the body-echo
// assertion in the body-material-redaction test fires only on the
// deny leg. The marker is distinct from every natural value the test
// fixtures produce so a substring match in either surface is decisive.
const createProjectEnvironmentContractSubmittedDisplayName = "yallaprojectenvsubmittedbodyMARKER0123456789F00DCAFE"

// createProjectEnvironmentContractBody is the canonical create body
// used by the contract tests. The shape is deliberately the happy-path
// shape so a failure can never be blamed on body validation.
const createProjectEnvironmentContractBody = `{` +
	`"environment_id":"env_acme_prod",` +
	`"slug":"production",` +
	`"display_name":"yallaprojectenvsubmittedbodyMARKER0123456789F00DCAFE"` +
	`}`

// createProjectEnvironmentHandlerForWithLogger builds the production POST
// /v1/projects/{project_id}/environments request path (real policy
// engine, fake Authenticator, caller-supplied EnvironmentCreator) with
// a caller-supplied logger so a test can inspect the structured
// request log. It mirrors createProjectEnvironmentHandlerFor with the
// final two NewHandler positional args swapped from (nil, nil) to
// (logger, nil).
func createProjectEnvironmentHandlerForWithLogger(
	id auth.Identity, authErr error, creator EnvironmentCreator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, creator, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestCreateProjectEnvironmentServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served POST
// /v1/projects/{project_id}/environments writes nothing to the process
// stdout/stderr, and the created-environment payload is carried by the
// response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestCreateProjectEnvironmentServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		projectID = "prj_acme_alpha"
		envID     = "env_acme_prod"
	)
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	row := store.Environment{
		ID:             envID,
		OrganizationID: orgID,
		ProjectID:      projectID,
		Slug:           "production",
		DisplayName:    createProjectEnvironmentContractSubmittedDisplayName,
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.CreateEnvironmentInput
	creator := fakeEnvironmentCreator{env: row, gotInput: &captured}
	handler := createProjectEnvironmentHandlerForWithLogger(
		principalForProjectEnvironments("usr_owner", orgID), nil, creator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postProjectEnvironments(handler, projectID, createProjectEnvironmentContractSecret,
			strings.NewReader(createProjectEnvironmentContractBody))
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
	env := decodeCreateProjectEnvironment(t, rec)
	if env.Data.Environment.ID != envID {
		t.Errorf("environment.id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ID, envID)
	}
	if env.Data.Environment.ProjectID != projectID {
		t.Errorf("environment.project_id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ProjectID, projectID)
	}
	// The creator must have actually been driven — the success body
	// proves the wire shape, but the captured input proves the
	// {project_id} path parameter reached the store layer, so a future
	// refactor that bypasses the EnvironmentCreator path fails this
	// story (in addition to project_environments_create_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("creator received org_id %q, want the principal's home org %q", captured.OrganizationID, orgID)
	}
	if captured.ProjectID != projectID {
		t.Errorf("creator received project_id %q, want the path parameter %q", captured.ProjectID, projectID)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCreateProjectEnvironmentRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny
// leg uses a disabled principal so policy short-circuits before the
// creator runs, and the creator's Create path errors if invoked,
// proving that a logged "creator error" cannot be the leak source.
// The pin covers both the structured log buffer AND the response body
// so a regression that echoes the Authorization header into either
// surface fails fast.
func TestCreateProjectEnvironmentRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_acme_alpha"
		envID     = "env_acme_prod"
	)
	allowed := principalForProjectEnvironments("usr_ada", orgID)
	denied := principalForProjectEnvironments("usr_revoked", orgID)
	denied.Principal.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	successCreator := fakeEnvironmentCreator{
		env: store.Environment{
			ID:             envID,
			OrganizationID: orgID,
			ProjectID:      projectID,
			Slug:           "production",
			DisplayName:    createProjectEnvironmentContractSubmittedDisplayName,
			Version:        1,
			CreatedAt:      created,
			UpdatedAt:      created,
		},
	}
	// The disabled-principal request must never reach the creator. A
	// creator whose Create path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "creator error" can't be
	// the leak source.
	denyCreator := fakeEnvironmentCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    EnvironmentCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			creator:    successCreator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
			creator:    denyCreator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createProjectEnvironmentHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postProjectEnvironments(handler, projectID, createProjectEnvironmentContractSecret,
				strings.NewReader(createProjectEnvironmentContractBody))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createProjectEnvironmentContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createProjectEnvironmentContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateProjectEnvironmentRequestLogRedactsSubmittedBodyMaterial is
// the POST-write-specific extra pin: the per-request structured log
// never carries caller-supplied request-body material, on the happy
// path AND on the authorization-failure path alike. The headers-not-
// logged / body-not-logged contract applies symmetrically to the
// request body for write endpoints — a regression that starts
// dumping the raw decoded body into the log would silently spill
// every customer-submitted display_name (and any field a future
// endpoint revision adds to the request shape) into the operational
// log surface. The pin guards against that regression on both legs.
//
// The success leg legitimately echoes display_name back in the
// response body (the created row), so the response-body assertion
// fires only on the deny leg — where echoing decoded body material
// would prove the handler decoded the body before short-circuiting
// at the policy gate. A leak in the deny path is even more dangerous:
// the value never reached the store, but it still reaches the
// operator log and the client.
func TestCreateProjectEnvironmentRequestLogRedactsSubmittedBodyMaterial(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_acme_alpha"
		envID     = "env_acme_prod"
	)
	allowed := principalForProjectEnvironments("usr_ada", orgID)
	denied := principalForProjectEnvironments("usr_revoked", orgID)
	denied.Principal.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	successCreator := fakeEnvironmentCreator{
		env: store.Environment{
			ID:             envID,
			OrganizationID: orgID,
			ProjectID:      projectID,
			Slug:           "production",
			DisplayName:    createProjectEnvironmentContractSubmittedDisplayName,
			Version:        1,
			CreatedAt:      created,
			UpdatedAt:      created,
		},
	}
	denyCreator := fakeEnvironmentCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name         string
		identity     auth.Identity
		creator      EnvironmentCreator
		wantStatus   int
		assertInBody bool
	}{
		{
			name:       "success path",
			identity:   allowed,
			creator:    successCreator,
			wantStatus: http.StatusCreated,
			// Success leg legitimately echoes display_name back in the
			// response; only the log assertion fires here.
			assertInBody: false,
		},
		{
			name:         "authorization failure path",
			identity:     denied,
			creator:      denyCreator,
			wantStatus:   http.StatusForbidden,
			assertInBody: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createProjectEnvironmentHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postProjectEnvironments(handler, projectID, createProjectEnvironmentContractSecret,
				strings.NewReader(createProjectEnvironmentContractBody))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createProjectEnvironmentContractSubmittedDisplayName) {
				t.Errorf("request log leaked submitted body material: %s", logBuf.String())
			}
			if tc.assertInBody && strings.Contains(rec.Body.String(), createProjectEnvironmentContractSubmittedDisplayName) {
				t.Errorf("deny-path response body echoed submitted body material: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateProjectEnvironmentErrorEnvelopeDoesNotLeakDependencyCause
// proves a creator-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message — the wrapped driver cause
// (host, port, "connection refused") is kept for server-side logs only
// and never reaches the client. project_environments_create_test.go
// pins the typed-status part of this contract; this test pins the
// "the wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries
// (a datastore address is exactly the kind of internal-network detail
// an error envelope must never leak).
func TestCreateProjectEnvironmentErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_acme_alpha"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	creator := fakeEnvironmentCreator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := createProjectEnvironmentHandlerFor(
		principalForProjectEnvironments("usr_owner", orgID), nil, creator,
	)

	rec := postProjectEnvironments(handler, projectID, createProjectEnvironmentContractSecret,
		strings.NewReader(createProjectEnvironmentContractBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_DB_UNAVAILABLE")
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
