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

// Public-API contract coverage for GET /v1/organizations/{org_id}/api-keys
// (BE-0077).
//
// api_keys_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the stable empty-array
// shape for an organization with no keys, the nullable-timestamp projection
// rules, the secret-hash redaction at the wire, the
// unauthenticated / invalid-credentials / disabled-principal / cross-tenant /
// viewer-denied / dependency-failure rejection space, the "support reads
// another tenant" policy-matrix exception, and the "reader receives exactly
// the {org_id} path parameter" wiring invariant. This file closes the
// remaining contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// GET /v1/organizations/{org_id}/api-keys has no request body and no query
// parameters: its only input is the {org_id} path parameter, an opaque
// identifier. There is therefore no syntactic request to reject as
// "invalid input" beyond the rejection paths already covered in
// api_keys_test.go (a malformed or unknown id surfaces as the deterministic
// 403 the policy engine returns through organizationIDResolver for ids
// outside the principal's tenant, or as the empty list for ids inside the
// tenant with no rows). The endpoint has no per-row "not found" path of its
// own — the list read deterministically maps an unknown id to an empty list
// rather than to a 404, which is the contract the empty-list pin in
// api_keys_test.go proves. Structural twin of members_list_contract_test.go
// (BE-0062), adapted to the api-keys LIST request shape ({org_id} path
// parameter, APIKeyReader port).

// listAPIKeysContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const listAPIKeysContractSecret = "yk_live_supersecret_api_keys_list_DEADBEEF0123456789"

// listAPIKeysHandlerForWithLogger builds the production GET
// /v1/organizations/{org_id}/api-keys request path (real policy engine, fake
// Authenticator, caller-supplied APIKeyReader) with a caller-supplied logger
// so a test can inspect the structured request log. It mirrors
// listAPIKeysHandlerFor for the api-keys LIST endpoint, with the logger
// threaded into NewHandler so the per-request slog record lands in the
// caller's buffer.
func listAPIKeysHandlerForWithLogger(
	id auth.Identity, authErr error, reader APIKeyReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		reader, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
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

// TestListAPIKeysServerWritesResponseDataOnlyToResponseWriter proves the HTTP
// server renders the response through the http.ResponseWriter alone: a served
// GET /v1/organizations/{org_id}/api-keys writes nothing to the process
// stdout/stderr, and the api-keys payload is carried by the response body.
func TestListAPIKeysServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeAPIKeyReader{keys: []store.APIKey{
		seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
			[]string{"projects:read", "services:deploy"},
			"usr_ada", "", created, updated),
	}}
	handler := listAPIKeysHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getAPIKeys(handler, "org_acme", listAPIKeysContractSecret)
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
	env := decodeListAPIKeys(t, rec)
	if len(env.Data.APIKeys) != 1 {
		t.Fatalf("api_keys = %+v, want exactly the seeded key", env.Data.APIKeys)
	}
	if env.Data.APIKeys[0].KeyID != "key_ada" {
		t.Errorf("api_keys[0].key_id = %q, want key_ada — the data must be carried by the response body",
			env.Data.APIKeys[0].KeyID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListAPIKeysRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all; this
// test pins that contract so a future logging change cannot quietly start
// leaking credentials.
func TestListAPIKeysRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	admin := orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleAdmin)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	successReader := fakeAPIKeyReader{keys: []store.APIKey{
		seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
			[]string{"projects:read"}, "usr_ada", "", created, updated),
	}}
	// The disabled-principal request must never reach the reader. A reader
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeAPIKeyReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     APIKeyReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: admin, Method: auth.MethodSession},
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			reader:     denyReader,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := listAPIKeysHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getAPIKeys(handler, "org_acme", listAPIKeysContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listAPIKeysContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listAPIKeysContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListAPIKeysErrorEnvelopeDoesNotLeakDependencyCause proves a reader-store
// outage surfaces as a typed 5xx whose error envelope carries a stable
// generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
// api_keys_test.go pins the typed-status part of this contract
// (TestListAPIKeysReaderUnavailable); this test pins the "the wrapped cause
// stays server-side" half that lives on the wire, including the bare
// datastore address that the cause string carries.
func TestListAPIKeysErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeAPIKeyReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, reader,
	)

	rec := getAPIKeys(handler, "org_acme", listAPIKeysContractSecret)
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
