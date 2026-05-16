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
// /v1/organizations/{org_id}/members/{member_id} (BE-0074).
//
// members_delete_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the
// unauthenticated / invalid-credentials / cross-tenant / disabled-principal
// / not-found / dependency-failure rejection space, the "the handler
// forwards both path parameters and the authenticated principal — never
// caller-controlled actor fields — to the MembershipRemover port
// unchanged" wiring invariant, and the defensive nil-remover /
// no-principal internal errors. This file closes the remaining
// contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path
//     AND on the authorization-failure path, so a bearer credential is
//     never logged;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire.
//
// Structural twin of members_update_contract_test.go (BE-0071), adapted to
// the DELETE single-member request shape ({org_id} + {member_id} path
// parameters, no request body, 200 success status carrying the
// audit-grade record of what was removed, MembershipRemover port).

// removeMemberContractSecret is a recognisable bearer credential used by
// the redaction tests: if any byte of it reaches a log record or a
// response body, the test fails.
const removeMemberContractSecret = "yk_live_supersecret_members_delete_DEADBEEF0123456789"

// removeMemberHandlerForWithLogger builds the production DELETE
// /v1/organizations/{org_id}/members/{member_id} request path (real
// policy engine, fake Authenticator, caller-supplied membership remover)
// with a caller-supplied logger so a test can inspect the structured
// request log. It mirrors removeMemberHandlerFor for the remove-membership
// endpoint, with the logger threaded into NewHandler so the per-request
// slog record lands in the caller's buffer.
func removeMemberHandlerForWithLogger(
	id auth.Identity, authErr error, remover MembershipRemover, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, remover,
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
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

// TestRemoveMemberServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone:
// a served DELETE /v1/organizations/{org_id}/members/{member_id} writes
// nothing to the process stdout/stderr, and the removed-member payload is
// carried by the response body.
func TestRemoveMemberServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	remover := fakeMembershipRemover{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := removeMemberHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteMember(handler, "org_acme", "usr_grace", removeMemberContractSecret)
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
	env := decodeRemoveMember(t, rec)
	if env.Data.Member.UserID != "usr_grace" || env.Data.Member.Role != "admin" {
		t.Errorf("member = %+v, want user usr_grace with role admin — the data must be carried by the response body",
			env.Data.Member)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestRemoveMemberRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path
// and on the authorization-failure path alike. Headers are not logged at
// all; this test pins that contract so a future logging change cannot
// quietly start leaking credentials.
func TestRemoveMemberRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	successRemover := fakeMembershipRemover{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	// The disabled-principal request must never reach the remover. A remover
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "remover error" can't be the leak source.
	denyRemover := fakeMembershipRemover{err: stderrors.New("remover must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		remover    MembershipRemover
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			remover:    successRemover,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			remover:    denyRemover,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := removeMemberHandlerForWithLogger(tc.identity, nil, tc.remover, logger)

			rec := deleteMember(handler, "org_acme", "usr_grace", removeMemberContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), removeMemberContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), removeMemberContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestRemoveMemberErrorEnvelopeDoesNotLeakDependencyCause proves a
// remover-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and never
// reaches the client. members_delete_test.go pins the typed-status part
// of this contract (TestRemoveMemberDependencyFailureIsTyped5xx); this
// test pins the "the wrapped cause stays server-side" half that lives on
// the wire, including the bare datastore address that the cause string
// carries.
func TestRemoveMemberErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	remover := fakeMembershipRemover{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := removeMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, remover,
	)

	rec := deleteMember(handler, "org_acme", "usr_grace", removeMemberContractSecret)
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
