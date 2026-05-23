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
)

// Public-API contract coverage for POST
// /v1/environments/{environment_id}/services (BE-0182).
//
// environment_services_create_test.go (BE-0181) already proves the 201
// success envelope, the stable yalla.output.v1 / yalla.error.v1 schema
// versions, the request_id propagation, the OpenAPI operation
// registration, the unauthenticated / authorization-denied / validation-
// failure / cross-tenant-not-found / dependency-failure rejection
// space, and the "creator receives the principal's home org plus the
// path {environment_id} plus the request body resource fields plus the
// actor identity" wiring invariant. The "no caller-supplied org id"
// invariant is also pinned there.
// environment_services_create_policy_test.go (BE-0183) pins the full
// policy matrix (viewer / developer / owner / admin / CI / support
// roles plus the deliberate absence of the support cross-tenant
// exception for the service.create CapWrite action, plus revoked /
// expired key handling and scoped-grant containment across org /
// project / environment / service grant scopes).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success
//     path AND the authorization-failure path, so a bearer credential
//     is never logged and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never
//     leaks that cause onto the wire, including the bare datastore
//     address that the cause string typically carries.
//
// POST /v1/environments/{environment_id}/services accepts a single
// opaque {environment_id} path parameter and a small JSON body
// (service_id, slug, display_name, kind). The store-backed creator
// treats an unknown or cross-tenant environment_id as a deterministic
// 404 (the parent-environment existence check fires first); the
// success path returns a 201 carrying the persisted store.Service
// projection. Structural twin of environment_services_get_contract_test.go
// (BE-0179) and environment_variables_put_contract_test.go (BE-0176),
// adapted to the environment services CREATE request shape
// ({environment_id} path parameter, EnvironmentServiceCreator port,
// service.create CapWrite action, request body that carries no secret
// values — the redaction surface is therefore the bearer credential
// alone).

// createEnvironmentServiceContractSecret is a recognisable bearer
// credential used by the redaction tests: if any byte of it reaches a
// log record or a response body, the test fails.
const createEnvironmentServiceContractSecret = "yk_live_supersecret_environment_services_post_DEADBEEF0123456789"

// createEnvironmentServiceContractBody is the canonical request body
// the contract tests issue. It mirrors the body BE-0181's happy-path
// test uses, so the redaction and stream-isolation contracts are
// proved against the same on-the-wire shape the success suite already
// exercises.
const createEnvironmentServiceContractBody = `{"service_id":"svc_api","slug":"api","display_name":"API service","kind":"application"}`

// createEnvironmentServiceHandlerForWithLogger builds the production
// POST /v1/environments/{environment_id}/services request path (real
// policy engine, fake Authenticator, caller-supplied
// EnvironmentServiceCreator) with a caller-supplied logger so a test
// can inspect the structured request log. It mirrors
// listEnvironmentServicesHandlerForWithLogger for the environment
// services CREATE endpoint.
func createEnvironmentServiceHandlerForWithLogger(
	id auth.Identity, authErr error, creator EnvironmentServiceCreator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, creator, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestCreateEnvironmentServiceServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served POST
// /v1/environments/{environment_id}/services writes nothing to the
// process stdout/stderr, and the freshly-created service payload is
// carried by the response body. The structured logger is the only
// sanctioned out-of-band writer and it goes to its own buffer, never
// to the process streams.
func TestCreateEnvironmentServiceServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID  = "org_acme"
		projID = "prj_web"
		envID  = "env_prod"
		svcID  = "svc_api"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	creator := fakeEnvironmentServiceCreator{
		service: seedServiceWire(
			svcID, orgID, projID, envID,
			"api", "API service", "application",
			1, created, created,
		),
	}
	handler := createEnvironmentServiceHandlerForWithLogger(
		principalForCreateService("usr_dev", orgID), nil, creator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postEnvironmentService(handler, envID, createEnvironmentServiceContractBody, createEnvironmentServiceContractSecret)
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
	env := decodeCreateEnvironmentService(t, rec)
	if env.Data.Service.ID != svcID {
		t.Errorf("service.id = %q, want %q — the data must be carried by the response body",
			env.Data.Service.ID, svcID)
	}
	if env.Data.Service.EnvironmentID != envID {
		t.Errorf("service.environment_id = %q, want %q — the data must be carried by the response body",
			env.Data.Service.EnvironmentID, envID)
	}
	// The structured logger is the only sanctioned writer, and it goes to
	// its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCreateEnvironmentServiceRequestLogRedactsBearerToken proves the
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
func TestCreateEnvironmentServiceRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID  = "org_acme"
		projID = "prj_web"
		envID  = "env_prod"
		svcID  = "svc_api"
	)
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	allowed := principalForCreateService("usr_ada", orgID)
	denied := principalForCreateService("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successCreator := fakeEnvironmentServiceCreator{
		service: seedServiceWire(
			svcID, orgID, projID, envID,
			"api", "API service", "application",
			1, created, created,
		),
	}
	// The disabled-principal request must never reach the creator. A
	// creator whose Create path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "creator error" can't be
	// the leak source.
	denyCreator := fakeEnvironmentServiceCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    EnvironmentServiceCreator
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
			handler := createEnvironmentServiceHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postEnvironmentService(handler, envID, createEnvironmentServiceContractBody, createEnvironmentServiceContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createEnvironmentServiceContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createEnvironmentServiceContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateEnvironmentServiceErrorEnvelopeDoesNotLeakDependencyCause
// proves a creator-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message — the wrapped driver cause
// (host, port, "connection refused") is kept for server-side logs only
// and never reaches the client. environment_services_create_test.go's
// TestCreateEnvironmentServiceCreatorOutage pins the typed-status part
// of this contract and a coarse "connection refused" body check; this
// test pins the "the wrapped cause stays server-side" half precisely,
// including the bare datastore address that the cause string carries
// (a datastore address is exactly the kind of internal-network detail
// an error envelope must never leak), and pins the explicit error-code
// envelope shape.
func TestCreateEnvironmentServiceErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		envID = "env_prod"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	creator := fakeEnvironmentServiceCreator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := createEnvironmentServiceHandlerFor(
		principalForCreateService("usr_dev", orgID), nil, creator,
	)

	rec := postEnvironmentService(handler, envID, createEnvironmentServiceContractBody, createEnvironmentServiceContractSecret)
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
