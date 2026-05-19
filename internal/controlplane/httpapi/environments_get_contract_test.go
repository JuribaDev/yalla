package httpapi

import (
	"bytes"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

// Public-API contract coverage for GET /v1/environments/{environment_id}
// (BE-0155).
//
// environments_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / not-found / cross-tenant / dependency-failure
// rejection space, the "the handler reads exactly the principal's home
// org plus the path {environment_id}" wiring invariant, and the
// "missing reader is a typed 500" invariant.
// environments_get_policy_test.go pins the full policy matrix (org-wide
// reader roles admitted; viewer admitted because environment.read is a
// CapRead action; org-, project-, environment-, and service-scoped
// grant covers() behavior; the support principal pinned to its own
// home organization on the resource scope so it cannot read another
// tenant's environment through the bare /v1/environments/{env_id}
// route). This file closes the remaining contract-test criteria those
// tests do not assert directly:
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
// GET /v1/environments/{environment_id} accepts a single opaque
// {environment_id} path parameter and no body and no query parameters.
// The store-backed reader treats an unknown or cross-tenant
// environment_id as a deterministic 404, which is the contract
// environments_test.go's TestGetEnvironmentNotFound and
// TestGetEnvironmentCrossTenantNotFound pin. Structural twin of
// project_environments_get_contract_test.go (BE-0152) and
// api_keys_get_contract_test.go (BE-0083), adapted to the
// /v1/environments/{environment_id} request shape (single
// {environment_id} path parameter, EnvironmentReader port, no query
// parameters, no secret-bearing fields on the wire shape).

// getEnvironmentContractSecret is a recognisable bearer credential used
// by the redaction tests: if any byte of it reaches a log record or a
// response body, the test fails.
const getEnvironmentContractSecret = "yk_live_supersecret_environments_get_DEADBEEF0123456789"

// getEnvironmentHandlerForWithLogger builds the production GET
// /v1/environments/{environment_id} request path (real policy engine,
// fake Authenticator, caller-supplied EnvironmentReader) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors listProjectEnvironmentsHandlerForWithLogger for the
// GET-environment endpoint and is the only helper in this file that
// uses fakeAuthenticator (so the bearer can be the contract secret —
// the package-default authForEnvGet only accepts "a-valid-token").
func getEnvironmentHandlerForWithLogger(
	id auth.Identity, authErr error, reader EnvironmentReader, logger *slog.Logger,
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, reader, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestGetEnvironmentServerWritesResponseDataOnlyToResponseWriter proves
// the HTTP server renders the response through the http.ResponseWriter
// alone: a served GET /v1/environments/{environment_id} writes nothing
// to the process stdout/stderr, and the environment payload is carried
// by the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestGetEnvironmentServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeEnvironmentReader{env: canonicalEnvForGet}
	handler := getEnvironmentHandlerForWithLogger(
		auth.Identity{Principal: principalForEnvGet, Method: auth.MethodAPIKey},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getEnvironment(handler, canonicalEnvForGet.ID, getEnvironmentContractSecret)
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
	got := decodeGetEnvironmentBody(t, rec)
	if got.ID != canonicalEnvForGet.ID {
		t.Errorf("environment.id = %q, want %q — the data must be carried by the response body",
			got.ID, canonicalEnvForGet.ID)
	}
	if got.ProjectID != canonicalEnvForGet.ProjectID {
		t.Errorf("environment.project_id = %q, want %q — the data must be carried by the response body",
			got.ProjectID, canonicalEnvForGet.ProjectID)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestGetEnvironmentRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy
// path and on the authorization-failure path alike. Headers are not
// logged at all; this test pins that contract so a future logging
// change cannot quietly start leaking credentials. The deny leg uses a
// disabled principal so policy short-circuits before the reader runs,
// and the reader's GetEnvironment returns an error if invoked, proving
// that a logged "reader error" cannot be the leak source.
func TestGetEnvironmentRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	allowed := principalForEnvGet
	disabled := principalForEnvGet
	disabled.ID = "usr_revoked"
	disabled.Disabled = true

	successReader := fakeEnvironmentReader{env: canonicalEnvForGet}
	// The disabled-principal request must never reach the reader. A
	// reader whose GetEnvironment path errors if invoked proves the
	// deny path short-circuits at policy, so any logged "reader
	// error" can't be the leak source.
	denyReader := fakeEnvironmentReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     EnvironmentReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: allowed, Method: auth.MethodAPIKey},
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodAPIKey},
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
			handler := getEnvironmentHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getEnvironment(handler, canonicalEnvForGet.ID, getEnvironmentContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getEnvironmentContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getEnvironmentContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestGetEnvironmentErrorEnvelopeDoesNotLeakDependencyCause proves a
// reader-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. environments_test.go pins the typed-status
// part of this contract; this test pins the "the wrapped cause stays
// server-side" half that lives on the wire, including the bare
// datastore address that the cause string carries (a datastore address
// is exactly the kind of internal-network detail an error envelope must
// never leak).
func TestGetEnvironmentErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeEnvironmentReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := getEnvironmentHandlerForWithLogger(
		auth.Identity{Principal: principalForEnvGet, Method: auth.MethodAPIKey},
		nil, reader, nil,
	)

	rec := getEnvironment(handler, canonicalEnvForGet.ID, getEnvironmentContractSecret)
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
