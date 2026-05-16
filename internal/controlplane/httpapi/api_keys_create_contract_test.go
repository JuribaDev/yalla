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

// Public-API contract coverage for POST /v1/organizations/{org_id}/api-keys
// (BE-0080).
//
// api_keys_create_test.go already proves the 201 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the one-time-plaintext
// surface, the persisted-projection redaction of secret_hash, the
// expires_at + service-account variant, the malformed-body /
// malformed-expires_at / store-validation / org-not-found /
// service-account-not-found / unauthenticated / invalid-credentials /
// cross-tenant / disabled-principal / dependency-failure rejection space,
// the "two requests mint distinct credentials" non-determinism pin, the
// "the token is not persisted" wiring invariant, and the
// "service-account actor has empty created_by" wiring invariant. This file
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
// Structural twin of members_create_contract_test.go (BE-0065) and
// api_keys_list_contract_test.go (BE-0077), adapted to the api-keys POST
// request shape ({org_id} path parameter, APIKeyCreator port,
// createAPIKeyPayload response data block).

// createAPIKeyContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const createAPIKeyContractSecret = "yk_live_supersecret_api_keys_create_DEADBEEF0123456789"

// createAPIKeyHandlerForWithLogger builds the production POST
// /v1/organizations/{org_id}/api-keys request path (real policy engine, fake
// Authenticator, caller-supplied APIKeyCreator) with a caller-supplied logger
// so a test can inspect the structured request log. It mirrors
// createAPIKeyHandlerFor for the api-keys CREATE endpoint, with the logger
// threaded into NewHandler so the per-request slog record lands in the
// caller's buffer.
func createAPIKeyHandlerForWithLogger(
	id auth.Identity, authErr error, creator APIKeyCreator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, creator, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
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

// TestCreateAPIKeyServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone: a
// served POST /v1/organizations/{org_id}/api-keys writes nothing to the
// process stdout/stderr, and the minted-api-key payload is carried by the
// response body.
func TestCreateAPIKeyServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", now, now)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	creator := fakeAPIKeyCreator{key: persisted}
	handler := createAPIKeyHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postAPIKey(handler, "org_acme", createAPIKeyContractSecret,
			`{"name":"Ada CLI","scopes":["projects:read","services:deploy"]}`)
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
	env := decodeCreateAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada — the data must be carried by the response body",
			env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.Name != "Ada CLI" {
		t.Errorf("api_key.name = %q, want Ada CLI — the data must be carried by the response body",
			env.Data.APIKey.Name)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCreateAPIKeyRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials.
func TestCreateAPIKeyRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	successCreator := fakeAPIKeyCreator{key: seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", now, now)}
	// The disabled-principal request must never reach the creator. A creator
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "creator error" can't be the leak source.
	denyCreator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    APIKeyCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			creator:    successCreator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			creator:    denyCreator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createAPIKeyHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postAPIKey(handler, "org_acme", createAPIKeyContractSecret,
				`{"name":"Ada CLI","scopes":["projects:read"]}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createAPIKeyContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createAPIKeyContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateAPIKeyErrorEnvelopeDoesNotLeakDependencyCause proves a
// creator-store outage surfaces as a typed 5xx whose error envelope carries
// a stable generic message — the wrapped driver cause (host, port,
// "connection refused") is kept for server-side logs only and never reaches
// the client. api_keys_create_test.go pins the typed-status part of this
// contract (TestCreateAPIKeyDependencyFailureIsTyped5xx); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries.
func TestCreateAPIKeyErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	creator := fakeAPIKeyCreator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator,
	)

	rec := postAPIKey(handler, "org_acme", createAPIKeyContractSecret,
		`{"name":"Ada CLI","scopes":["projects:read"]}`)
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
