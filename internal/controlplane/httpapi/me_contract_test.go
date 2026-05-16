package httpapi

import (
	"bytes"
	stderrors "errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

// Public-API contract coverage for GET /v1/me (BE-0041). me_test.go already
// proves the success/error envelopes, request_id propagation, OpenAPI
// registration, and the unauthenticated / invalid-credential / disabled /
// dependency-failure rejection space. This file closes the remaining
// contract-test criteria that those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// GET /v1/me has no request body, no path parameters, and no query parameters,
// so there is no caller input to validate and no resource to look up — the
// "invalid input" and "not found" rows of the contract checklist are satisfied
// structurally and covered by the rejection tests in me_test.go.

// meContractSecret is a recognisable bearer credential used by the redaction
// tests: if any byte of it reaches a log record or a response body, the test
// fails.
const meContractSecret = "yk_live_supersecret_DEADBEEF0123456789"

// meHandlerWithLogger builds the production GET /v1/me request path (real
// policy engine, fake Authenticator) with a caller-supplied logger so a test
// can inspect the structured request log.
func meHandlerWithLogger(id auth.Identity, authErr error, logger *slog.Logger) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a,
		policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// captureProcessOutput redirects the process stdout and stderr around fn and
// returns whatever was written to each. It mutates package-global os.Stdout /
// os.Stderr, so a test that uses it must not run in parallel.
func captureProcessOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, outR)
		outCh <- b.String()
	}()
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, errR)
		errCh <- b.String()
	}()

	fn()

	os.Stdout, os.Stderr = origOut, origErr
	_ = outW.Close()
	_ = errW.Close()
	return <-outCh, <-errCh
}

// TestMeServerWritesResponseDataOnlyToResponseWriter proves the HTTP server
// renders the response through the http.ResponseWriter alone: a served GET
// /v1/me writes nothing to the process stdout/stderr, and the identity data is
// carried by the response body.
func TestMeServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleOwner,
	}
	handler := meHandlerWithLogger(auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getMe(handler, meContractSecret)
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
	env := decodeMe(t, rec)
	if env.Data.PrincipalID != "usr_ada" {
		t.Errorf("principal_id = %q, want usr_ada — the identity must be carried by the response body", env.Data.PrincipalID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestMeRequestLogRedactsBearerToken proves the per-request structured log
// never carries the bearer credential — on the happy path and on the
// authorization-failure path alike. Headers are not logged at all; this test
// pins that contract so a future logging change cannot quietly start leaking
// credentials.
func TestMeRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleOwner,
	}
	disabled := policy.Principal{
		ID: "usr_revoked", Kind: domain.KindUser, OrganizationID: "org_acme",
		Role: policy.RoleOwner, Disabled: true,
	}

	tests := []struct {
		name       string
		identity   auth.Identity
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := meHandlerWithLogger(tc.identity, nil, logger)

			rec := getMe(handler, meContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), meContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), meContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestMeErrorEnvelopeDoesNotLeakDependencyCause proves a credential-store
// outage surfaces as a typed 5xx whose error envelope carries a generic
// message — the wrapped driver cause (host, port, "connection refused") is
// kept for server-side logs only and never reaches the client.
func TestMeErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	handler := meHandlerFor(auth.Identity{}, apierr.StoreUnavailable(stderrors.New(cause)))

	rec := getMe(handler, meContractSecret)
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
