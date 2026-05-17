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

// Public-API contract coverage for DELETE
// /v1/organizations/{org_id}/variables/{key} (BE-0116).
//
// variables_delete_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration
// (operationId deleteOrganizationVariable + env.write required action +
// variables tag + {key} path parameter), the unauthenticated /
// cross-tenant / not-found / store-outage / nil-deleter rejection
// space, the wire-level redaction of the deleted variable's secret
// value (the customer that previously stored a secret MUST NOT see it
// echoed back through the deletion response), and the "deleter
// receives the {org_id} and {key} path parameters plus the actor
// identity and correlation identifiers" wiring invariant.
// variables_delete_policy_test.go (BE-0117) pins the full policy
// matrix (viewer / developer / owner / admin / CI / support roles
// plus the deliberate absence of the support cross-tenant exception
// for CapWrite actions). This file closes the remaining contract-
// test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including bare datastore addresses the
//     cause string carries.
//
// Structural twin of variables_patch_contract_test.go (BE-0113) and
// variables_put_contract_test.go (BE-0110), adapted to the DELETE
// /v1/organizations/{org_id}/variables/{key} request shape
// (OrganizationVariableDeleter port, {key} path parameter, NO request
// body — and therefore no "submitted secret" pin: a DELETE never
// carries a customer-supplied value, so the variables-specific extra
// surface that BE-0110/BE-0113 cover does not apply here). The
// endpoint mutates state, so a rejected request that nonetheless
// reaches the handler is materially worse than a read-only sibling:
// every deny-leg assertion here is also a "deleter was not invoked"
// assertion, so a regression that wires up the deleter behind the
// policy gate fails this story in two places.

// deleteOrgVariableContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails. Suffix is distinct from
// replaceOrgVariablesContractSecret (BE-0110),
// patchOrgVariableContractSecret (BE-0113), and
// listOrgVariablesContractSecret (BE-0107) so a regression that swaps
// any of those surfaces fails loudly.
const deleteOrgVariableContractSecret = "yk_live_supersecret_org_variables_delete_FACEFEED0123456789"

// deleteOrgVariableHandlerForWithLogger builds the production DELETE
// /v1/organizations/{org_id}/variables/{key} request path (real policy
// engine, fake Authenticator, caller-supplied OrganizationVariableDeleter)
// with a caller-supplied logger so a test can inspect the structured
// request log. It mirrors patchOrgVariableHandlerForWithLogger for the
// single-key variables DELETE endpoint.
func deleteOrgVariableHandlerForWithLogger(
	id auth.Identity, authErr error, deleter OrganizationVariableDeleter, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, deleter,
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestDeleteOrgVariableServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served DELETE
// /v1/organizations/{org_id}/variables/{key} writes nothing to the
// process stdout/stderr, and the deleted-variable payload is carried
// by the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestDeleteOrgVariableServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.DeleteOrganizationVariableInput
	deleter := fakeOrgVariableDeleter{
		v: store.OrganizationVariable{
			ID: "ovar_db", OrganizationID: orgID, Key: key,
			Value: "postgres://user:hunter2@db/app", IsSecret: true, Version: 3,
		},
		got: &captured,
	}
	handler := deleteOrgVariableHandlerForWithLogger(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteOrgVariable(handler, orgID, key, deleteOrgVariableContractSecret)
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
	env := decodeDeleteOrgVariable(t, rec)
	if env.Data.Variable.Key != key {
		t.Errorf("variable.key = %q, want %q — the data must be carried by the response body",
			env.Data.Variable.Key, key)
	}
	// The deleter must have actually been driven — the success body
	// proves the wire shape, but the captured input proves the {org_id}
	// and {key} path parameters reached the store layer, so a future
	// refactor that bypasses the OrganizationVariableDeleter path fails
	// this story (in addition to variables_delete_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("deleter received org_id %q, want the path parameter %q", captured.OrganizationID, orgID)
	}
	if captured.Key != key {
		t.Errorf("deleter received key %q, want the path parameter %q", captured.Key, key)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestDeleteOrgVariableRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny
// leg uses a deleter whose Delete path errors if invoked, so a logged
// "deleter error" cannot be the leak source — the deny must
// short-circuit at policy. The pin covers both the structured log
// buffer AND the response body so a regression that echoes the
// Authorization header into either surface fails fast.
func TestDeleteOrgVariableRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successDeleter := fakeOrgVariableDeleter{
		v: store.OrganizationVariable{
			ID: "ovar_db", OrganizationID: orgID, Key: key,
			Value: "postgres://user:hunter2@db/app", IsSecret: true, Version: 3,
		},
	}
	// The disabled-principal request must never reach the deleter. A
	// deleter whose Delete path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "deleter error" can't be
	// the leak source.
	denyDeleter := fakeOrgVariableDeleter{err: stderrors.New("deleter must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		deleter    OrganizationVariableDeleter
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			deleter:    successDeleter,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			deleter:    denyDeleter,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := deleteOrgVariableHandlerForWithLogger(tc.identity, nil, tc.deleter, logger)

			rec := deleteOrgVariable(handler, orgID, key, deleteOrgVariableContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), deleteOrgVariableContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), deleteOrgVariableContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestDeleteOrgVariableErrorEnvelopeDoesNotLeakDependencyCause proves
// a deleter-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. variables_delete_test.go pins the
// typed-status part of this contract
// (TestDeleteOrgVariableStoreOutageIsTypedFailure); this test pins
// the "the wrapped cause stays server-side" half that lives on the
// wire, including the bare datastore address that the cause string
// carries (a datastore address is exactly the kind of internal-network
// detail an error envelope must never leak).
func TestDeleteOrgVariableErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		key   = "DATABASE_URL"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	deleter := fakeOrgVariableDeleter{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := deleteOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, deleter,
	)

	rec := deleteOrgVariable(handler, orgID, key, deleteOrgVariableContractSecret)
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
