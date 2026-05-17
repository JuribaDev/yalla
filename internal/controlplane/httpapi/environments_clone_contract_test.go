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

// Public-API contract coverage for POST /v1/environments/{environment_id}/clone
// (BE-0164).
//
// environments_clone_test.go already proves the 201 Created success
// envelope, the stable yalla.output.v1 / yalla.error.v1 schema
// versions, the request_id propagation, the principal-scoped
// forwarding of CloneEnvironmentInput (the new environment inherits
// project_id from the source, the source environment_id comes from
// the path, the new id/slug/display_name come from the body, the
// actor is the resolved principal), the strict body decoder
// (malformed-400, unknown-field-400) rejection, the not-found /
// slug-conflict / invalid-input / missing-cloner / unauthenticated
// rejection space, the ETag response header pinning, and the
// OpenAPI operation registration (operationId, RequiredAction,
// RequiresAuth, success status 201, path params). The fuller "every
// principal class × every authorization edge" matrix lives in
// environments_clone_policy_test.go (BE-0165). This file closes the
// remaining contract-test criteria those tests do not assert
// directly:
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
// Structural twin of environments_delete_contract_test.go (BE-0161)
// and environments_update_contract_test.go (BE-0158), adapted to the
// POST clone-environment request shape ({environment_id} path
// parameter naming the source, JSON body carrying the
// caller-minted new id / slug / display name, EnvironmentCloner
// port, CapWrite action environment.create, fresh-row semantics
// that surface as a 201 Created with the new row's version-1
// ETag header and no deletion_scheduled_at). The clone wire shape
// has no secret-bearing fields (display_name / slug / version are
// all public, and the environments table itself stores no secrets;
// the environment-scoped variable surface is provisioned through
// its own endpoints).

// cloneEnvironmentContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails.
const cloneEnvironmentContractSecret = "yk_live_supersecret_environments_clone_DEADBEEF0123456789"

// cloneEnvironmentHandlerForWithLogger builds the production
// POST /v1/environments/{environment_id}/clone request path (real
// policy engine, fake Authenticator, caller-supplied
// EnvironmentCloner) with a caller-supplied logger so a test can
// inspect the structured request log. It mirrors
// cloneEnvironmentHandlerFor for the environments clone endpoint,
// with the logger threaded into NewHandler so the per-request slog
// record lands in the caller's buffer.
func cloneEnvironmentHandlerForWithLogger(
	id auth.Identity, authErr error, cloner EnvironmentCloner, logger *slog.Logger,
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, cloner, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// canonicalClonedEnv is a fully-populated environment row used by the
// contract tests as the cloner's return value. The row is a freshly
// minted live environment — no deletion_scheduled_at, version 1
// (the authoritative version for a brand-new row), and project_id
// inherited from the source environment. Every field on the wire
// shape is public (no secret-bearing fields).
func canonicalClonedEnv() store.Environment {
	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	return store.Environment{
		ID:             "env_acme_preview",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_web",
		Slug:           "preview",
		DisplayName:    "Preview",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      created,
	}
}

// canonicalCloneContractRequestBody is the canonical request body used by
// the contract tests as the happy-path input. The agent-minted new id
// matches the cloner's return row so the success envelope carries
// the same identifier the caller proposed.
const canonicalCloneContractRequestBody = `{"environment_id":"env_acme_preview","slug":"preview","display_name":"Preview"}`

// TestCloneEnvironmentServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served POST
// /v1/environments/{environment_id}/clone writes nothing to the
// process stdout/stderr, and the cloned environment payload is
// carried by the response body. The structured logger is the only
// sanctioned out-of-band writer and it goes to its own buffer, never
// to the process streams.
func TestCloneEnvironmentServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	row := canonicalClonedEnv()
	cloner := fakeEnvironmentCloner{env: row}
	handler := cloneEnvironmentHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, cloner, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = cloneEnvironment(handler, "env_acme_prod", cloneEnvironmentContractSecret, canonicalCloneContractRequestBody)
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
	env := decodeCloneEnvironment(t, rec)
	if env.Data.Environment.ID != row.ID {
		t.Errorf("environment.id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ID, row.ID)
	}
	if env.Data.Environment.ProjectID != row.ProjectID {
		t.Errorf("environment.project_id = %q, want %q — the data must be carried by the response body",
			env.Data.Environment.ProjectID, row.ProjectID)
	}
	if env.Data.Environment.DeletionScheduledAt != nil {
		t.Error("environment.deletion_scheduled_at is non-nil, want nil for a freshly-cloned live row")
	}
	// The structured logger is the only sanctioned writer, and it
	// goes to its own sink — never to the response and never to the
	// process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCloneEnvironmentRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The
// response body is also asserted credential-free, closing the
// symmetric leak axis (an error envelope must never echo the bearer
// back to the client either). The deny leg uses a disabled principal
// so policy short-circuits before the cloner runs, and the cloner's
// Clone path would error if invoked, proving that a logged "cloner
// error" cannot be the leak source.
func TestCloneEnvironmentRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	row := canonicalClonedEnv()
	successCloner := fakeEnvironmentCloner{env: row}
	// The disabled-principal request must never reach the cloner. A
	// cloner whose Clone path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "cloner error" can't
	// be the leak source.
	denyCloner := fakeEnvironmentCloner{err: stderrors.New("cloner must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		cloner     EnvironmentCloner
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			cloner:     successCloner,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			cloner:     denyCloner,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := cloneEnvironmentHandlerForWithLogger(tc.identity, nil, tc.cloner, logger)

			rec := cloneEnvironment(handler, row.ID, cloneEnvironmentContractSecret, canonicalCloneContractRequestBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), cloneEnvironmentContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), cloneEnvironmentContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCloneEnvironmentErrorEnvelopeDoesNotLeakDependencyCause proves
// a cloner-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client.
// environments_clone_test.go pins the typed-status part of this
// contract via the not-found / slug-conflict / invalid-input /
// missing-cloner matrix; this test pins the "the wrapped cause stays
// server-side" half that lives on the wire, including the bare
// datastore address that the cause string carries (a datastore
// address is exactly the kind of internal-network detail an error
// envelope must never leak).
func TestCloneEnvironmentErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	cloner := fakeEnvironmentCloner{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := cloneEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, cloner,
	)

	rec := cloneEnvironment(handler, "env_acme_prod", cloneEnvironmentContractSecret, canonicalCloneContractRequestBody)
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
