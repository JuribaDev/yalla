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
// /v1/services/{service_id}/variables (BE-0200).
//
// service_variables_test.go already proves the 200 success envelope,
// the stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / not-found / dependency-failure rejection space,
// the "empty service is a stable [] shape" invariant, the "store
// outage surfaces as a typed 503" invariant, the "reader receives the
// principal's home org plus the path {service_id}" wiring invariant,
// the secret-value redaction at the projection boundary, and the
// "missing reader is a typed 500" invariant.
// service_variables_policy_test.go pins the full policy matrix
// (viewer/developer/owner roles plus grant containment and denied
// disabled credentials).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter, never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success
//     path and the authorization-failure path, so a bearer credential is
//     never logged;
//   - an error envelope built from a wrapped dependency cause never
//     leaks that cause onto the wire, including the bare datastore
//     address that the cause string typically carries.
//
// GET /v1/services/{service_id}/variables accepts one opaque
// {service_id} path parameter, no body, and no query parameters. The
// store-backed reader treats an unknown or cross-tenant service_id as a
// deterministic 404, pinned in service_variables_test.go.

// listServiceVariablesContractSecret is a recognisable bearer
// credential used by the redaction tests: if any byte of it reaches a
// log record or a response body, the test fails.
const listServiceVariablesContractSecret = "yk_live_supersecret_service_variables_get_DEADBEEF0123456789"

// listServiceVariablesHandlerForWithLogger builds the production GET
// /v1/services/{service_id}/variables request path (real policy
// engine, fake Authenticator, caller-supplied ServiceVariableReader)
// with a caller-supplied logger so a test can inspect the structured
// request log.
func listServiceVariablesHandlerForWithLogger(
	id auth.Identity, authErr error, reader ServiceVariableReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{},
		fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{},
		fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{},
		fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{},
		fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{},
		fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, reader,
		fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{},
		fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestListServiceVariablesServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served GET
// /v1/services/{service_id}/variables writes nothing to the process
// stdout/stderr, and the variables payload is carried by the response
// body. The structured logger is the only sanctioned out-of-band writer
// and it goes to its own buffer, never to the process streams.
func TestListServiceVariablesServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		serviceID = "svc_api"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeServiceVariableReader{
		vars: []store.ServiceVariable{
			seedServiceVariableWire(
				"svar_001", orgID, serviceID,
				"REGION", "us-east-1", false,
				1, created, created,
			),
		},
	}
	handler := listServiceVariablesHandlerForWithLogger(
		principalForServiceVariables("usr_dev", orgID), nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getServiceVariables(handler, serviceID, listServiceVariablesContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing - response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing - response data must go through the ResponseWriter", stderr)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListServiceVariables(t, rec)
	if len(env.Data.Variables) != 1 {
		t.Fatalf("variables = %+v, want exactly the seeded entry", env.Data.Variables)
	}
	if env.Data.Variables[0].ID != "svar_001" {
		t.Errorf("variables[0].id = %q, want %q - the data must be carried by the response body",
			env.Data.Variables[0].ID, "svar_001")
	}
	if env.Data.Variables[0].ServiceID != serviceID {
		t.Errorf("variables[0].service_id = %q, want %q - the data must be carried by the response body",
			env.Data.Variables[0].ServiceID, serviceID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListServiceVariablesRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential on the
// happy path and authorization-failure path alike. Headers are not
// logged at all; this test pins that contract so a future logging
// change cannot quietly start leaking credentials.
func TestListServiceVariablesRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		serviceID = "svc_api"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	allowed := principalForServiceVariables("usr_ada", orgID)
	denied := principalForServiceVariables("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successReader := fakeServiceVariableReader{
		vars: []store.ServiceVariable{
			seedServiceVariableWire(
				"svar_001", orgID, serviceID,
				"REGION", "us-east-1", false,
				1, created, created,
			),
		},
	}
	denyReader := fakeServiceVariableReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     ServiceVariableReader
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
			handler := listServiceVariablesHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getServiceVariables(handler, serviceID, listServiceVariablesContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listServiceVariablesContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listServiceVariablesContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListServiceVariablesErrorEnvelopeDoesNotLeakDependencyCause
// proves a reader-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message. The wrapped driver cause
// is kept for server-side logs only and never reaches the client.
func TestListServiceVariablesErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		serviceID = "svc_api"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	reader := fakeServiceVariableReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listServiceVariablesHandlerFor(
		principalForServiceVariables("usr_dev", orgID), nil, reader,
	)

	rec := getServiceVariables(handler, serviceID, listServiceVariablesContractSecret)
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
