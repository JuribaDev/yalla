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

// Public-API contract coverage for PATCH /v1/environments/{environment_id}
// (BE-0158).
//
// environments_update_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the principal-scoped forwarding of UpdateEnvironmentInput
// (TestUpdateEnvironmentHappyPathForwardsBodyAndPrincipal), the partial-
// body nil-pointer semantics, the optional If-Match strong-ETag matrix,
// the strict-decoder rejection of an unknown organization_id smuggling,
// the malformed-body / missing-credentials / forbidden-for-viewer /
// not-found / stale-If-Match / store-invalid-input / missing-updater
// rejection space, the ETag response header pinning, and the OpenAPI
// operation registration. The fuller "every principal class × every
// authorization edge" matrix lives in environments_update_policy_test.go
// (BE-0159). This file closes the remaining contract-test criteria those
// tests do not assert directly:
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
// Structural twin of projects_update_contract_test.go (BE-0128) and
// environments_get_contract_test.go (BE-0155), adapted to the PATCH
// single-environment request shape ({environment_id} path parameter,
// JSON body, EnvironmentUpdater port, CapWrite action environment.update,
// no secret-bearing fields on the wire shape — display_name and slug
// are public).

// updateEnvironmentContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails.
const updateEnvironmentContractSecret = "yk_live_supersecret_environments_update_DEADBEEF0123456789"

// updateEnvironmentContractBody is a syntactically valid PATCH body.
// The contract tests reach the updater (success path) or short-circuit
// at auth/policy (authorization-failure path); either way the body is
// parsed strictly so a valid JSON keeps the failure axis pinned to the
// contract being tested, not to the decoder.
const updateEnvironmentContractBody = `{"display_name":"Preview","slug":"preview"}`

// updateEnvironmentHandlerForWithLogger builds the production
// PATCH /v1/environments/{environment_id} request path (real policy
// engine, fake Authenticator, caller-supplied EnvironmentUpdater) with
// a caller-supplied logger so a test can inspect the structured
// request log. It mirrors updateEnvironmentHandlerFor for the
// environments UPDATE endpoint, with the logger threaded into
// NewHandler so the per-request slog record lands in the caller's
// buffer.
func updateEnvironmentHandlerForWithLogger(
	id auth.Identity, authErr error, updater EnvironmentUpdater, logger *slog.Logger,
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, updater, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestUpdateEnvironmentServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served PATCH
// /v1/environments/{environment_id} writes nothing to the process
// stdout/stderr, and the updated environment payload is carried by
// the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestUpdateEnvironmentServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	updater := fakeEnvironmentUpdater{env: canonicalUpdatedEnv}
	handler := updateEnvironmentHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = patchEnvironment(handler, canonicalUpdatedEnv.ID, updateEnvironmentContractSecret, updateEnvironmentContractBody)
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
	env := decodeUpdateEnvironment(t, rec)
	if env.Data.Environment.ID != canonicalUpdatedEnv.ID {
		t.Errorf("environment.id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ID, canonicalUpdatedEnv.ID)
	}
	if env.Data.Environment.ProjectID != canonicalUpdatedEnv.ProjectID {
		t.Errorf("environment.project_id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ProjectID, canonicalUpdatedEnv.ProjectID)
	}
	// The structured logger is the only sanctioned writer, and it
	// goes to its own sink — never to the response and never to the
	// process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestUpdateEnvironmentRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The
// response body is also asserted credential-free, closing the
// symmetric leak axis (an error envelope must never echo the bearer
// back to the client either). The deny leg uses a disabled principal
// so policy short-circuits before the updater runs, and the updater's
// Update would error if invoked, proving that a logged "updater
// error" cannot be the leak source.
func TestUpdateEnvironmentRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	successUpdater := fakeEnvironmentUpdater{env: canonicalUpdatedEnv}
	// The disabled-principal request must never reach the updater. An
	// updater whose Update path errors if invoked proves the deny
	// path short-circuits at policy, so any logged "updater error"
	// can't be the leak source.
	denyUpdater := fakeEnvironmentUpdater{err: stderrors.New("updater must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		updater    EnvironmentUpdater
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			updater:    successUpdater,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			updater:    denyUpdater,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := updateEnvironmentHandlerForWithLogger(tc.identity, nil, tc.updater, logger)

			rec := patchEnvironment(handler, canonicalUpdatedEnv.ID, updateEnvironmentContractSecret, updateEnvironmentContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), updateEnvironmentContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), updateEnvironmentContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestUpdateEnvironmentErrorEnvelopeDoesNotLeakDependencyCause proves
// an updater-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message — the wrapped driver
// cause (host, port, "connection refused") is kept for server-side
// logs only and never reaches the client.
// environments_update_test.go pins the typed-status part of this
// contract via the not-found / conflict / invalid-input matrix; this
// test pins the "the wrapped cause stays server-side" half that lives
// on the wire, including the bare datastore address that the cause
// string carries (a datastore address is exactly the kind of
// internal-network detail an error envelope must never leak).
func TestUpdateEnvironmentErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	updater := fakeEnvironmentUpdater{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := updateEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater,
	)

	rec := patchEnvironment(handler, canonicalUpdatedEnv.ID, updateEnvironmentContractSecret, updateEnvironmentContractBody)
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
