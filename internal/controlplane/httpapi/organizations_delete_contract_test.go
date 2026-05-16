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
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for DELETE /v1/organizations/{org_id} (BE-0059).
//
// organizations_delete_test.go already proves the 202 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the unauthenticated /
// invalid-credentials / disabled-principal / cross-tenant / insufficient-role
// / not-found / already-scheduled-conflict / dependency-failure rejection
// space, and the "the handler forwards the {org_id} path parameter and the
// authenticated actor to the deleter port unchanged" wiring invariant. This
// file closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// Structural twin of organizations_patch_contract_test.go (BE-0056) and
// organizations_get_contract_test.go (BE-0053), adapted to the DELETE
// single-organization request shape ({org_id} path parameter, no request body,
// 202 success status — schedule-not-purge — OrganizationDeleter port).

// deleteOrganizationContractSecret is a recognisable bearer credential used by
// the redaction tests: if any byte of it reaches a log record or a response
// body, the test fails. Distinct per file so a false positive in a sibling
// contract test cannot quietly satisfy the redaction assertion here.
const deleteOrganizationContractSecret = "yk_live_supersecret_orgs_delete_DEADBEEF0123456789"

// deleteOrganizationHandlerForWithLogger builds the production DELETE
// /v1/organizations/{org_id} request path (real policy engine, fake
// Authenticator, caller-supplied deleter) with a caller-supplied logger so a
// test can inspect the structured request log. It mirrors
// updateOrganizationHandlerForWithLogger and getOrganizationHandlerForWithLogger
// for the delete endpoint.
func deleteOrganizationHandlerForWithLogger(
	id auth.Identity, authErr error, deleter OrganizationDeleter, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, deleter,
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
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

// TestDeleteOrganizationServerWritesResponseDataOnlyToResponseWriter proves
// the HTTP server renders the response through the http.ResponseWriter alone:
// a served DELETE /v1/organizations/{org_id} writes nothing to the process
// stdout/stderr, and the scheduled-organization payload is carried by the
// response body.
func TestDeleteOrganizationServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	deleter := fakeOrganizationDeleter{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	handler := deleteOrganizationHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteOrganization(handler, "org_acme", deleteOrganizationContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing — response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing — response data must go through the ResponseWriter", stderr)
	}

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteOrganization(t, rec)
	if env.Data.Organization.OrganizationID != "org_acme" {
		t.Errorf("organization_id = %q, want org_acme — the data must be carried by the response body",
			env.Data.Organization.OrganizationID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestDeleteOrganizationRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all; this
// test pins that contract so a future logging change cannot quietly start
// leaking credentials.
func TestDeleteOrganizationRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	successDeleter := fakeOrganizationDeleter{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	// The disabled-principal request must never reach the deleter. A deleter
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "deleter error" can't be the leak source.
	denyDeleter := fakeOrganizationDeleter{err: stderrors.New("deleter must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		deleter    OrganizationDeleter
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			deleter:    successDeleter,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			deleter:    denyDeleter,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := deleteOrganizationHandlerForWithLogger(tc.identity, nil, tc.deleter, logger)

			rec := deleteOrganization(handler, "org_acme", deleteOrganizationContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), deleteOrganizationContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), deleteOrganizationContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestDeleteOrganizationErrorEnvelopeDoesNotLeakDependencyCause proves a
// deleter-store outage surfaces as a typed 5xx whose error envelope carries a
// stable generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
// organizations_delete_test.go pins the typed-status part of this contract
// (TestDeleteOrganizationDependencyFailureIsTyped5xx); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire.
func TestDeleteOrganizationErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	deleter := fakeOrganizationDeleter{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter,
	)

	rec := deleteOrganization(handler, "org_acme", deleteOrganizationContractSecret)
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
