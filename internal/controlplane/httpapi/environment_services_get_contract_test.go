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

// Public-API contract coverage for GET
// /v1/environments/{environment_id}/services (BE-0179).
//
// environment_services_test.go (BE-0178) already proves the 200 success
// envelope, the stable yalla.output.v1 / yalla.error.v1 schema versions,
// the request_id propagation, the OpenAPI operation registration, the
// unauthenticated / not-found / dependency-failure rejection space, the
// "empty environment is a stable [] shape" invariant, the "store outage
// surfaces as a typed 503" invariant, the "reader receives the
// principal's home org plus the path {environment_id}" wiring invariant,
// and the "missing reader is a typed 500" invariant.
// environment_services_policy_test.go (BE-0180) pins the full policy
// matrix (viewer/developer/owner roles plus the support principal's
// cross-tenant CapRead exception for the service.read action).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success
//     path AND the authorization-failure path, so a bearer credential
//     is never logged;
//   - an error envelope built from a wrapped dependency cause never
//     leaks that cause onto the wire, including the bare datastore
//     address that the cause string typically carries.
//
// GET /v1/environments/{environment_id}/services accepts a single
// opaque {environment_id} path parameter, no body, and no query
// parameters. The store-backed reader treats an unknown or cross-tenant
// environment_id as a deterministic 404, which is the contract
// environment_services_test.go's TestListEnvironmentServicesNotFoundFromReader
// pins. Structural twin of environment_variables_get_contract_test.go
// (BE-0173) and environment_grants_get_contract_test.go (BE-0151),
// adapted to the environment services read request shape
// ({environment_id} path parameter, EnvironmentServiceReader port,
// no query parameters).

// listEnvironmentServicesContractSecret is a recognisable bearer
// credential used by the redaction tests: if any byte of it reaches a
// log record or a response body, the test fails.
const listEnvironmentServicesContractSecret = "yk_live_supersecret_environment_services_get_DEADBEEF0123456789"

// listEnvironmentServicesHandlerForWithLogger builds the production
// GET /v1/environments/{environment_id}/services request path (real
// policy engine, fake Authenticator, caller-supplied
// EnvironmentServiceReader) with a caller-supplied logger so a test
// can inspect the structured request log. It mirrors
// listEnvironmentVariablesHandlerForWithLogger for the environment
// services READ endpoint.
func listEnvironmentServicesHandlerForWithLogger(
	id auth.Identity, authErr error, reader EnvironmentServiceReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, reader, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestListEnvironmentServicesServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served GET
// /v1/environments/{environment_id}/services writes nothing to the
// process stdout/stderr, and the services payload is carried by the
// response body. The structured logger is the only sanctioned out-of-
// band writer and it goes to its own buffer, never to the process
// streams.
func TestListEnvironmentServicesServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID  = "org_acme"
		projID = "prj_web"
		envID  = "env_prod"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeEnvironmentServiceReader{
		services: []store.Service{
			seedServiceWire(
				"svc_api", orgID, projID, envID,
				"api", "API service", "application",
				1, created, created,
			),
		},
	}
	handler := listEnvironmentServicesHandlerForWithLogger(
		principalForEnvironmentServices("usr_dev", orgID), nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getEnvironmentServices(handler, envID, listEnvironmentServicesContractSecret)
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
	env := decodeListEnvironmentServices(t, rec)
	if len(env.Data.Services) != 1 {
		t.Fatalf("services = %+v, want exactly the seeded entry", env.Data.Services)
	}
	if env.Data.Services[0].ID != "svc_api" {
		t.Errorf("services[0].id = %q, want %q — the data must be carried by the response body",
			env.Data.Services[0].ID, "svc_api")
	}
	if env.Data.Services[0].EnvironmentID != envID {
		t.Errorf("services[0].environment_id = %q, want %q — the data must be carried by the response body",
			env.Data.Services[0].EnvironmentID, envID)
	}
	// The structured logger is the only sanctioned writer, and it goes to
	// its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListEnvironmentServicesRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny leg
// uses a disabled principal so policy short-circuits before the reader
// runs, and the reader's ListEnvironmentServices returns an error if
// invoked, proving that a logged "reader error" cannot be the leak
// source.
func TestListEnvironmentServicesRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID  = "org_acme"
		projID = "prj_web"
		envID  = "env_prod"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	allowed := principalForEnvironmentServices("usr_ada", orgID)
	denied := principalForEnvironmentServices("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successReader := fakeEnvironmentServiceReader{
		services: []store.Service{
			seedServiceWire(
				"svc_api", orgID, projID, envID,
				"api", "API service", "application",
				1, created, created,
			),
		},
	}
	// The disabled-principal request must never reach the reader. A
	// reader whose ListEnvironmentServices path errors if invoked proves
	// the deny path short-circuits at policy, so any logged "reader
	// error" can't be the leak source.
	denyReader := fakeEnvironmentServiceReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     EnvironmentServiceReader
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
			handler := listEnvironmentServicesHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getEnvironmentServices(handler, envID, listEnvironmentServicesContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listEnvironmentServicesContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listEnvironmentServicesContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListEnvironmentServicesErrorEnvelopeDoesNotLeakDependencyCause
// proves a reader-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message — the wrapped driver cause
// (host, port, "connection refused") is kept for server-side logs only
// and never reaches the client. environment_services_test.go pins the
// typed-status part of this contract; this test pins the "the wrapped
// cause stays server-side" half that lives on the wire, including the
// bare datastore address that the cause string carries (a datastore
// address is exactly the kind of internal-network detail an error
// envelope must never leak).
func TestListEnvironmentServicesErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		envID = "env_prod"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	reader := fakeEnvironmentServiceReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listEnvironmentServicesHandlerFor(
		principalForEnvironmentServices("usr_dev", orgID), nil, reader,
	)

	rec := getEnvironmentServices(handler, envID, listEnvironmentServicesContractSecret)
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
