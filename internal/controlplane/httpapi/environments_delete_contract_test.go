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
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for DELETE /v1/environments/{environment_id}
// (BE-0161).
//
// environments_delete_test.go already proves the 202 Accepted success
// envelope (destructive teardown is scheduled, not immediate), the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the principal-scoped forwarding of
// DeleteEnvironmentInput (TestDeleteEnvironmentHappyPathForwardsPrincipalAndScheduling),
// the optional If-Match strong-ETag parsing/forwarding, the
// malformed-If-Match rejection, the not-found / already-scheduled /
// stale-If-Match / missing-deleter / unauthenticated rejection space,
// the ETag response header pinning, and the OpenAPI operation
// registration (operationId, RequiredAction, RequiresAuth, success
// status 202, path params). The fuller "every principal class × every
// authorization edge" matrix lives in environments_delete_policy_test.go
// (BE-0162). This file closes the remaining contract-test criteria
// those tests do not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success
//     path AND the authorization-failure path, so a bearer credential
//     is never logged and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never
//     leaks that cause onto the wire, including the bare datastore
//     address that the cause string typically carries.
//
// Structural twin of environments_update_contract_test.go (BE-0158)
// and environments_get_contract_test.go (BE-0155), adapted to the
// DELETE single-environment request shape ({environment_id} path
// parameter, no JSON body, EnvironmentDeleter port, CapWrite action
// environment.delete, scheduled-deletion semantics that surface as a
// 202 Accepted with the row's deletion_scheduled_at stamp and a
// version-pinned ETag header). The delete wire shape has no
// secret-bearing fields (display_name / slug / version /
// deletion_scheduled_at are all public).

// deleteEnvironmentContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails.
const deleteEnvironmentContractSecret = "yk_live_supersecret_environments_delete_DEADBEEF0123456789"

// deleteEnvironmentHandlerForWithLogger builds the production
// DELETE /v1/environments/{environment_id} request path (real policy
// engine, fake Authenticator, caller-supplied EnvironmentDeleter) with
// a caller-supplied logger so a test can inspect the structured
// request log. It mirrors deleteEnvironmentHandlerFor for the
// environments DELETE endpoint, with the logger threaded into
// NewHandler so the per-request slog record lands in the caller's
// buffer.
func deleteEnvironmentHandlerForWithLogger(
	id auth.Identity, authErr error, deleter EnvironmentDeleter, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, deleter, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// canonicalDeletedEnv is a fully-populated environment row used by the
// contract tests as the deleter's return value. The deletion is
// scheduled (DeletionScheduledAt set), the version is non-zero so the
// ETag header path renders deterministically, and every field on the
// wire shape is public (no secret-bearing fields).
func canonicalDeletedEnv() store.Environment {
	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	scheduled := updated.Add(time.Minute)
	return store.Environment{
		ID:                  "env_acme_prod",
		OrganizationID:      "org_acme",
		ProjectID:           "prj_acme_web",
		Slug:                "production",
		DisplayName:         "Production",
		Version:             4,
		CreatedAt:           created,
		UpdatedAt:           updated,
		DeletionScheduledAt: &scheduled,
	}
}

// TestDeleteEnvironmentServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served DELETE
// /v1/environments/{environment_id} writes nothing to the process
// stdout/stderr, and the scheduled-deletion environment payload is
// carried by the response body. The structured logger is the only
// sanctioned out-of-band writer and it goes to its own buffer, never
// to the process streams.
func TestDeleteEnvironmentServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	row := canonicalDeletedEnv()
	deleter := fakeEnvironmentDeleter{env: row}
	handler := deleteEnvironmentHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteEnvironment(handler, row.ID, deleteEnvironmentContractSecret)
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
	env := decodeDeleteEnvironment(t, rec)
	if env.Data.Environment.ID != row.ID {
		t.Errorf("environment.id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ID, row.ID)
	}
	if env.Data.Environment.ProjectID != row.ProjectID {
		t.Errorf("environment.project_id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ProjectID, row.ProjectID)
	}
	if env.Data.Environment.DeletionScheduledAt == nil {
		t.Error("environment.deletion_scheduled_at is nil, want the scheduled stamp carried by the response body")
	}
	// The structured logger is the only sanctioned writer, and it
	// goes to its own sink — never to the response and never to the
	// process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestDeleteEnvironmentRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The
// response body is also asserted credential-free, closing the
// symmetric leak axis (an error envelope must never echo the bearer
// back to the client either). The deny leg uses a disabled principal
// so policy short-circuits before the deleter runs, and the deleter's
// ScheduleDeletion would error if invoked, proving that a logged
// "deleter error" cannot be the leak source.
func TestDeleteEnvironmentRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	row := canonicalDeletedEnv()
	successDeleter := fakeEnvironmentDeleter{env: row}
	// The disabled-principal request must never reach the deleter. A
	// deleter whose ScheduleDeletion path errors if invoked proves the
	// deny path short-circuits at policy, so any logged "deleter
	// error" can't be the leak source.
	denyDeleter := fakeEnvironmentDeleter{err: stderrors.New("deleter must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		deleter    EnvironmentDeleter
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := deleteEnvironmentHandlerForWithLogger(tc.identity, nil, tc.deleter, logger)

			rec := deleteEnvironment(handler, row.ID, deleteEnvironmentContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), deleteEnvironmentContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), deleteEnvironmentContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestDeleteEnvironmentErrorEnvelopeDoesNotLeakDependencyCause proves
// a deleter-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client.
// environments_delete_test.go pins the typed-status part of this
// contract via the not-found / already-scheduled / stale-If-Match /
// missing-deleter matrix; this test pins the "the wrapped cause stays
// server-side" half that lives on the wire, including the bare
// datastore address that the cause string carries (a datastore
// address is exactly the kind of internal-network detail an error
// envelope must never leak).
func TestDeleteEnvironmentErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	deleter := fakeEnvironmentDeleter{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := deleteEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter,
	)

	rec := deleteEnvironment(handler, "env_acme_prod", deleteEnvironmentContractSecret)
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
