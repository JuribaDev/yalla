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

// Public-API contract coverage for DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} (BE-0089).
//
// api_keys_delete_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id and
// correlation_id propagation, the OpenAPI operation registration (both
// {org_id} and {key_id} path parameters, the documented DELETE operation),
// the revoked-at projection onto the wire, the secret_hash redaction, the
// not-found / already-revoked-conflict / store-validation / store-outage
// forwarding paths, the unauthenticated / invalid-credentials /
// disabled-principal / cross-tenant / viewer-denied authorization-failure
// space, and the "missing revoker is a typed 500" wiring invariant. This
// file closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire.
//
// Structural twin of api_keys_get_contract_test.go (BE-0083) and
// api_keys_update_contract_test.go (BE-0086), adapted to the api-keys DELETE
// request shape ({org_id} + {key_id} path parameters, no body, APIKeyRevoker
// port through the same NewHandler wiring).

// deleteAPIKeyContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const deleteAPIKeyContractSecret = "yk_live_supersecret_api_keys_delete_DEADBEEF0123456789"

// revokeAPIKeyHandlerForWithLogger builds the production DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} request path (real policy
// engine, fake Authenticator, caller-supplied APIKeyRevoker) with a
// caller-supplied logger so a test can inspect the structured request log.
// It mirrors revokeAPIKeyHandlerFor for the api-keys DELETE endpoint, with
// the logger threaded into NewHandler so the per-request slog record lands
// in the caller's buffer.
func revokeAPIKeyHandlerForWithLogger(
	id auth.Identity, authErr error, revoker APIKeyRevoker, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, revoker, fakeAPIKeyRotator{},
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

// TestRevokeAPIKeyServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone: a
// served DELETE /v1/organizations/{org_id}/api-keys/{key_id} writes nothing
// to the process stdout/stderr, and the revoked-api-key payload is carried
// by the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the process
// streams.
func TestRevokeAPIKeyServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	revokedAt := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", created, updated,
	)
	persisted.RevokedAt = &revokedAt
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	revoker := fakeAPIKeyRevoker{key: persisted}
	handler := revokeAPIKeyHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteAPIKey(handler, "org_acme", "key_ada", deleteAPIKeyContractSecret)
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
	env := decodeRevokeAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada — the data must be carried by the response body",
			env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.RevokedAt != revokedAt.Format(time.RFC3339Nano) {
		t.Errorf("api_key.revoked_at = %q, want the resolved revocation timestamp — the data must be carried by the response body",
			env.Data.APIKey.RevokedAt)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestRevokeAPIKeyRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials. The deny-leg uses a revoker whose Revoke path
// errors if invoked, so a logged "revoker error" cannot be the leak source —
// the deny must short-circuit at policy.
func TestRevokeAPIKeyRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	admin := orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleAdmin)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	revokedAt := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", created, updated,
	)
	persisted.RevokedAt = &revokedAt
	successRevoker := fakeAPIKeyRevoker{key: persisted}
	// The disabled-principal request must never reach the revoker. A revoker
	// whose Revoke path errors if invoked proves the deny path short-circuits
	// at policy, so any logged "revoker error" can't be the leak source.
	denyRevoker := fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		revoker    APIKeyRevoker
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: admin, Method: auth.MethodSession},
			revoker:    successRevoker,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			revoker:    denyRevoker,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := revokeAPIKeyHandlerForWithLogger(tc.identity, nil, tc.revoker, logger)

			rec := deleteAPIKey(handler, "org_acme", "key_ada", deleteAPIKeyContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), deleteAPIKeyContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), deleteAPIKeyContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestRevokeAPIKeyErrorEnvelopeDoesNotLeakDependencyCause proves a
// revoker-store outage surfaces as a typed 5xx whose error envelope carries
// a stable generic message — the wrapped driver cause (host, port,
// "connection refused") is kept for server-side logs only and never reaches
// the client. api_keys_delete_test.go's TestRevokeAPIKeyForwardsStoreOutage
// pins the typed-status part of this contract; this test pins the "the
// wrapped cause stays server-side" half across the whole response body,
// including the bare datastore address that the cause string carries (a
// datastore address is exactly the kind of internal-network detail an error
// envelope must never leak).
func TestRevokeAPIKeyErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	revoker := fakeAPIKeyRevoker{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker,
	)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", deleteAPIKeyContractSecret)
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
