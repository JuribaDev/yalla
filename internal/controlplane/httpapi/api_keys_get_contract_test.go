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
)

// Public-API contract coverage for GET
// /v1/organizations/{org_id}/api-keys/{key_id} (BE-0083).
//
// api_keys_get_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration (both {org_id} and
// {key_id} path parameters, x-required-action=keys.read, the security
// requirement, a documented 200), the nullable-timestamp / scopes projection
// rules, the secret-hash and service-account-id redaction at the wire, the
// "the handler reads exactly the {org_id} and {key_id} path parameters"
// wiring invariant, the deterministic not-found vs cross-tenant key id
// behavior (both surface as 404 so the endpoint can never reveal whether
// another tenant owns that key), the cross-tenant {org_id} 403, the
// viewer-denied / developer-denied / support-denied (CapAdmin) policy
// matrix, the unauthenticated / invalid-credentials / disabled-principal
// rejection space, and the reader-store outage path. This file closes the
// remaining contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// GET /v1/organizations/{org_id}/api-keys/{key_id} has no request body and
// no query parameters: its only inputs are two opaque path parameters. There
// is therefore no syntactic request to reject as "invalid input" beyond the
// rejection paths already covered in api_keys_get_test.go (a malformed or
// unknown {org_id} surfaces as the deterministic 403 the policy engine
// returns through organizationIDResolver for ids outside the principal's
// tenant; a malformed or unknown {key_id} surfaces as the deterministic 404
// the tenant-scoped reader returns for a missing or cross-tenant row). The
// endpoint has no per-field "validation" path of its own — there are no
// fields to validate. Structural twin of api_keys_list_contract_test.go
// (BE-0077) and api_keys_create_contract_test.go (BE-0080), adapted to the
// api-keys GET-by-id request shape ({org_id} + {key_id} path parameters,
// shared APIKeyReader port through the same listAPIKeysHandlerForWithLogger
// wiring).

// getAPIKeyContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const getAPIKeyContractSecret = "yk_live_supersecret_api_keys_get_DEADBEEF0123456789"

// TestGetAPIKeyServerWritesResponseDataOnlyToResponseWriter proves the HTTP
// server renders the response through the http.ResponseWriter alone: a served
// GET /v1/organizations/{org_id}/api-keys/{key_id} writes nothing to the
// process stdout/stderr, and the api-key payload is carried by the response
// body. The structured logger is the only sanctioned out-of-band writer and
// it goes to its own buffer, never to the process streams.
func TestGetAPIKeyServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeAPIKeyReader{key: seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", created, updated,
	)}
	handler := listAPIKeysHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getAPIKey(handler, "org_acme", "key_ada", getAPIKeyContractSecret)
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
	env := decodeGetAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada — the data must be carried by the response body",
			env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.Name != "Ada's CLI key" {
		t.Errorf("api_key.name = %q, want Ada's CLI key — the data must be carried by the response body",
			env.Data.APIKey.Name)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestGetAPIKeyRequestLogRedactsBearerToken proves the per-request structured
// log never carries the bearer credential — on the happy path and on the
// authorization-failure path alike. Headers are not logged at all; this test
// pins that contract so a future logging change cannot quietly start leaking
// credentials. The deny-leg uses a reader whose Get path errors if invoked,
// so a logged "reader error" cannot be the leak source — the deny must
// short-circuit at policy.
func TestGetAPIKeyRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	admin := orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleAdmin)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	successReader := fakeAPIKeyReader{key: seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
		[]string{"projects:read"}, "usr_ada", "", created, updated,
	)}
	// The disabled-principal request must never reach the reader. A reader
	// whose Get path errors if invoked proves the deny path short-circuits at
	// policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeAPIKeyReader{getErr: stderrors.New("reader must not be called")}

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

			rec := getAPIKey(handler, "org_acme", "key_ada", getAPIKeyContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getAPIKeyContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getAPIKeyContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestGetAPIKeyErrorEnvelopeDoesNotLeakDependencyCause proves a reader-store
// outage surfaces as a typed 5xx whose error envelope carries a stable
// generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
// api_keys_get_test.go's TestGetAPIKeyReaderUnavailable pins the
// typed-status part of this contract and asserts the cause string does not
// appear in the user-facing message; this test pins the "the wrapped cause
// stays server-side" half across the whole response body, including the
// bare datastore address that the cause string carries (a datastore address
// is exactly the kind of internal-network detail an error envelope must
// never leak).
func TestGetAPIKeyErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeAPIKeyReader{getErr: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, reader,
	)

	rec := getAPIKey(handler, "org_acme", "key_ada", getAPIKeyContractSecret)
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
