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

// Public-API contract coverage for PATCH
// /v1/organizations/{org_id}/members/{member_id} (BE-0071).
//
// members_update_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the malformed-body /
// unknown-field / missing-role / invalid-role / unauthenticated /
// invalid-credentials / disabled-principal / cross-tenant / not-found /
// dependency-failure rejection space, the "the handler forwards the decoded
// role, both path parameters, and the authenticated principal — never
// caller-controlled actor fields — to the MembershipUpdater port unchanged"
// wiring invariant, and the defensive nil-updater / no-principal internal
// errors. This file closes the remaining contract-test criteria those tests
// do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// Structural twin of members_create_contract_test.go (BE-0065) and
// members_get_contract_test.go (BE-0068), adapted to the PATCH single-member
// request shape ({org_id} + {member_id} path parameters, body-bearing
// request, 200 success status, MembershipUpdater port).

// updateMemberContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const updateMemberContractSecret = "yk_live_supersecret_members_update_DEADBEEF0123456789"

// updateMemberHandlerForWithLogger builds the production PATCH
// /v1/organizations/{org_id}/members/{member_id} request path (real policy
// engine, fake Authenticator, caller-supplied membership updater) with a
// caller-supplied logger so a test can inspect the structured request log.
// It mirrors updateMemberHandlerFor for the update-membership endpoint, with
// the logger threaded into NewHandler so the per-request slog record lands
// in the caller's buffer.
func updateMemberHandlerForWithLogger(
	id auth.Identity, authErr error, updater MembershipUpdater, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, updater, fakeMembershipRemover{},
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

// TestUpdateMemberServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone: a
// served PATCH /v1/organizations/{org_id}/members/{member_id} writes nothing
// to the process stdout/stderr, and the updated-member payload is carried by
// the response body.
func TestUpdateMemberServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	updater := fakeMembershipUpdater{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	handler := updateMemberHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = patchMember(handler, "org_acme", "usr_grace", updateMemberContractSecret,
			`{"role":"admin"}`)
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
	env := decodeUpdateMember(t, rec)
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

// TestUpdateMemberRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials.
func TestUpdateMemberRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	successUpdater := fakeMembershipUpdater{member: seedMember(
		"org_acme", "usr_grace", "grace@acme.example", "Grace Hopper", "admin", 4, created, updated)}
	// The disabled-principal request must never reach the updater. An updater
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "updater error" can't be the leak source.
	denyUpdater := fakeMembershipUpdater{err: stderrors.New("updater must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		updater    MembershipUpdater
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := updateMemberHandlerForWithLogger(tc.identity, nil, tc.updater, logger)

			rec := patchMember(handler, "org_acme", "usr_grace", updateMemberContractSecret,
				`{"role":"admin"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), updateMemberContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), updateMemberContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestUpdateMemberErrorEnvelopeDoesNotLeakDependencyCause proves an
// updater-store outage surfaces as a typed 5xx whose error envelope carries
// a stable generic message — the wrapped driver cause (host, port,
// "connection refused") is kept for server-side logs only and never reaches
// the client. members_update_test.go pins the typed-status part of this
// contract (TestUpdateMemberDependencyFailureIsTyped5xx); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries.
func TestUpdateMemberErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	updater := fakeMembershipUpdater{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := updateMemberHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater,
	)

	rec := patchMember(handler, "org_acme", "usr_grace", updateMemberContractSecret,
		`{"role":"admin"}`)
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
