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
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate (BE-0092).
//
// api_keys_rotate_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// and correlation_id propagation, the OpenAPI operation registration, the
// NEW-prefix and plaintext-token projection onto the wire, the secret_hash
// redaction, the not-found / revoked-conflict / expired-conflict /
// store-validation / store-outage forwarding paths, the unauthenticated /
// invalid-credentials / disabled-principal / cross-tenant
// authorization-failure space, and the "missing rotator is a typed 500"
// wiring invariant. This file closes the remaining contract-test criteria
// those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so the inbound bearer credential is
//     never logged;
//   - the per-request structured log stays redacted against the OUTBOUND
//     plaintext token the rotate handler mints — a future log-format
//     regression that started capturing the response body would leak a
//     brand-new credential. Rotate is the only api-keys endpoint after
//     Create where the server response carries a plaintext credential at
//     all, which makes this assertion rotate-specific;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire.
//
// Structural twin of api_keys_get_contract_test.go (BE-0083),
// api_keys_update_contract_test.go (BE-0086), and
// api_keys_delete_contract_test.go (BE-0089), adapted to the api-keys
// rotate request shape ({org_id} + {key_id} path parameters, no body,
// APIKeyRotator port through the same NewHandler wiring). The unique
// rotate-specific contract probe is the "plaintext token must not leak
// into the structured log" assertion in
// TestRotateAPIKeyRequestLogRedactsPlaintextToken — every other handler
// in the api-keys family is single-secret (the inbound bearer); rotate is
// dual-secret (inbound bearer plus outbound plaintext token).

// rotateAPIKeyContractSecret is a recognisable bearer credential used by
// the redaction tests: if any byte of it reaches a log record or a
// response body, the test fails.
const rotateAPIKeyContractSecret = "yk_live_supersecret_api_keys_rotate_DEADBEEF0123456789"

// rotateAPIKeyHandlerForWithLogger builds the production POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate request path (real
// policy engine, fake Authenticator, caller-supplied APIKeyRotator) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors rotateAPIKeyHandlerFor for the api-keys rotate endpoint,
// with the logger threaded into NewHandler so the per-request slog record
// lands in the caller's buffer.
func rotateAPIKeyHandlerForWithLogger(
	id auth.Identity, authErr error, rotator APIKeyRotator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, rotator,
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

// TestRotateAPIKeyServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone:
// a served POST /v1/organizations/{org_id}/api-keys/{key_id}/rotate writes
// nothing to the process stdout/stderr, and both the rotated api_key
// payload (NEW prefix) and the freshly-minted plaintext token are carried
// by the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the process
// streams.
func TestRotateAPIKeyServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(
		"org_acme", "key_ada", "yk_new_prefix_after_rotate", "Ada CLI",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", created, updated,
	)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rotator := fakeAPIKeyRotator{key: persisted}
	handler := rotateAPIKeyHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = rotateAPIKey(handler, "org_acme", "key_ada", rotateAPIKeyContractSecret)
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
	env := decodeRotateAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada — the data must be carried by the response body",
			env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.Prefix != "yk_new_prefix_after_rotate" {
		t.Errorf("api_key.prefix = %q, want the NEW prefix the row now serves — the data must be carried by the response body",
			env.Data.APIKey.Prefix)
	}
	if env.Data.Token == "" {
		t.Error("response token is empty; the freshly-minted plaintext credential must be carried by the response body")
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestRotateAPIKeyRequestLogRedactsBearerToken proves the per-request
// structured log never carries the inbound bearer credential — on the
// happy path and on the authorization-failure path alike. Headers are not
// logged at all; this test pins that contract so a future logging change
// cannot quietly start leaking credentials. The deny-leg uses a rotator
// whose Rotate path errors if invoked, so a logged "rotator error" cannot
// be the leak source — the deny must short-circuit at policy.
func TestRotateAPIKeyRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	admin := orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleAdmin)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(
		"org_acme", "key_ada", "yk_new_prefix_after_rotate", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", created, updated,
	)
	successRotator := fakeAPIKeyRotator{key: persisted}
	// The disabled-principal request must never reach the rotator. A rotator
	// whose Rotate path errors if invoked proves the deny path short-circuits
	// at policy, so any logged "rotator error" can't be the leak source.
	denyRotator := fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		rotator    APIKeyRotator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: admin, Method: auth.MethodSession},
			rotator:    successRotator,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			rotator:    denyRotator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := rotateAPIKeyHandlerForWithLogger(tc.identity, nil, tc.rotator, logger)

			rec := rotateAPIKey(handler, "org_acme", "key_ada", rotateAPIKeyContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), rotateAPIKeyContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), rotateAPIKeyContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestRotateAPIKeyRequestLogRedactsPlaintextToken proves the
// freshly-minted plaintext credential the handler returns in the response
// body never appears in the per-request structured log. Rotate is the
// only api-keys endpoint after Create where the server response carries a
// plaintext credential, so a logging change that started capturing the
// response body would leak a brand-new credential — this test pins the
// "the plaintext token stays in the response body" half of the contract
// across the structured-log buffer. The success path is the only path
// that mints a token; deny/error paths never reach the credential
// generator. The test extracts the actual minted token from the response
// envelope so a future change to auth.Generate (different alphabet,
// different length) is automatically respected — there is no hardcoded
// token shape this test would silently miss.
func TestRotateAPIKeyRequestLogRedactsPlaintextToken(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey(
		"org_acme", "key_ada", "yk_new_prefix_after_rotate", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", created, updated,
	)
	rotator := fakeAPIKeyRotator{key: persisted}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := rotateAPIKeyHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator, logger,
	)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", rotateAPIKeyContractSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRotateAPIKey(t, rec)
	if env.Data.Token == "" {
		t.Fatal("response token is empty; the test cannot assert non-leakage of an empty value")
	}
	if logBuf.Len() == 0 {
		t.Fatal("structured request log is empty, want one record for the served request")
	}
	if strings.Contains(logBuf.String(), env.Data.Token) {
		t.Errorf("request log leaked the freshly-minted plaintext token %q: %s", env.Data.Token, logBuf.String())
	}
}

// TestRotateAPIKeyErrorEnvelopeDoesNotLeakDependencyCause proves a
// rotator-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and never
// reaches the client. api_keys_rotate_test.go's
// TestRotateAPIKeyForwardsStoreOutage pins the typed-status part of this
// contract; this test pins the "the wrapped cause stays server-side" half
// across the whole response body, including the bare datastore address
// that the cause string carries (a datastore address is exactly the kind
// of internal-network detail an error envelope must never leak).
func TestRotateAPIKeyErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	rotator := fakeAPIKeyRotator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator,
	)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", rotateAPIKeyContractSecret)
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
