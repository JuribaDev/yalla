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

// Public-API contract coverage for GET
// /v1/organizations/{org_id}/members/{member_id} (BE-0068).
//
// members_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the unauthenticated /
// invalid-credentials / disabled-principal / cross-tenant / not-found /
// dependency-failure rejection space, the "support reads another tenant"
// policy-matrix exception, and the "reader receives exactly the {org_id} +
// {member_id} path parameters" wiring invariant. This file closes the
// remaining contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// GET /v1/organizations/{org_id}/members/{member_id} has no request body and
// no query parameters: its only input is the {org_id} and {member_id} path
// parameters, both opaque identifiers. There is therefore no syntactic
// request to reject as "invalid input" beyond the rejection paths already
// covered in members_test.go (a malformed or unknown {member_id} surfaces as
// the typed NotFound the reader produces, and an {org_id} outside the
// principal's tenant surfaces as a deterministic 403 — both pinned by
// members_test.go). Structural twin of organizations_get_contract_test.go
// (BE-0053) and members_list_contract_test.go (BE-0062), adapted to the GET
// single-membership request shape ({org_id} + {member_id} path parameters,
// 200 success status, MembershipReader port).

// getMemberContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const getMemberContractSecret = "yk_live_supersecret_members_get_DEADBEEF0123456789"

// getMemberHandlerForWithLogger builds the production GET
// /v1/organizations/{org_id}/members/{member_id} request path (real policy
// engine, fake Authenticator, caller-supplied membership reader) with a
// caller-supplied logger so a test can inspect the structured request log.
// It mirrors listMembersHandlerForWithLogger for the single-member endpoint.
func getMemberHandlerForWithLogger(
	id auth.Identity, authErr error, reader MembershipReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		reader, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
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

// TestGetMemberServerWritesResponseDataOnlyToResponseWriter proves the HTTP
// server renders the response through the http.ResponseWriter alone: a
// served GET /v1/organizations/{org_id}/members/{member_id} writes nothing
// to the process stdout/stderr, and the member payload is carried by the
// response body.
func TestGetMemberServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeMembershipReader{
		member: seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 3, created, updated),
	}
	handler := getMemberHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getMember(handler, "org_acme", "usr_ada", getMemberContractSecret)
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
	env := decodeGetMember(t, rec)
	if env.Data.Member.UserID != "usr_ada" {
		t.Errorf("user_id = %q, want usr_ada — the data must be carried by the response body",
			env.Data.Member.UserID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestGetMemberRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials.
func TestGetMemberRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	successReader := fakeMembershipReader{
		member: seedMember("org_acme", "usr_ada", "ada@acme.example", "Ada Lovelace", "owner", 3, created, updated),
	}
	// The disabled-principal request must never reach the reader. A reader
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeMembershipReader{getErr: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     MembershipReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
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
			handler := getMemberHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getMember(handler, "org_acme", "usr_ada", getMemberContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getMemberContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getMemberContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestGetMemberErrorEnvelopeDoesNotLeakDependencyCause proves a reader-store
// outage surfaces as a typed 5xx whose error envelope carries a stable
// generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
// members_test.go pins the typed-status part of this contract
// (TestGetMemberReaderUnavailable); this test pins the "the wrapped cause
// stays server-side" half that lives on the wire, including the bare
// datastore address that the cause string carries.
func TestGetMemberErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeMembershipReader{getErr: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listMembersHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader,
	)

	rec := getMember(handler, "org_acme", "usr_ada", getMemberContractSecret)
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
