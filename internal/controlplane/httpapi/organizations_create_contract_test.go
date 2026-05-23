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

// Public-API contract coverage for POST /v1/organizations (BE-0050).
//
// organizations_create_test.go already proves the 201 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the malformed-body /
// unknown-field / invalid-input / unauthenticated / invalid-credentials /
// disabled-principal / conflict / dependency-failure rejection space, and the
// "the handler forwards the validated request and the authenticated actor to
// the store layer unchanged" wiring invariant. This file closes the remaining
// contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// Structural twin of organizations_contract_test.go (BE-0047) and
// me_organizations_contract_test.go (BE-0044), adapted to the POST request
// shape (request body, 201 success status, OrganizationCreator port).

// createOrganizationContractSecret is a recognisable bearer credential used by
// the redaction tests: if any byte of it reaches a log record or a response
// body, the test fails.
const createOrganizationContractSecret = "yk_live_supersecret_orgs_create_DEADBEEF0123456789"

// createOrganizationHandlerForWithLogger builds the production POST
// /v1/organizations request path (real policy engine, fake Authenticator,
// caller-supplied creator) with a caller-supplied logger so a test can inspect
// the structured request log. It mirrors organizationsHandlerForWithLogger for
// the create endpoint.
func createOrganizationHandlerForWithLogger(
	id auth.Identity, authErr error, creator OrganizationCreator, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(), fakeOrganizationReader{}, creator, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
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

// TestCreateOrganizationServerWritesResponseDataOnlyToResponseWriter proves
// the HTTP server renders the response through the http.ResponseWriter alone:
// a served POST /v1/organizations writes nothing to the process stdout/stderr,
// and the created-organization payload is carried by the response body.
func TestCreateOrganizationServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	creator := fakeOrganizationCreator{org: store.Organization{
		ID: "org_new", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	handler := createOrganizationHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postOrganizations(handler, createOrganizationContractSecret, `{"slug":"acme","display_name":"Acme, Inc."}`)
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
	env := decodeCreateOrganization(t, rec)
	if env.Data.Organization.OrganizationID != "org_new" {
		t.Errorf("organization_id = %q, want org_new — the data must be carried by the response body",
			env.Data.Organization.OrganizationID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestCreateOrganizationRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all; this
// test pins that contract so a future logging change cannot quietly start
// leaking credentials.
func TestCreateOrganizationRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	successCreator := fakeOrganizationCreator{org: store.Organization{
		ID: "org_new", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	// The disabled-principal request must never reach the creator. A creator
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "creator error" can't be the leak source.
	denyCreator := fakeOrganizationCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    OrganizationCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			creator:    successCreator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			creator:    denyCreator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createOrganizationHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postOrganizations(handler, createOrganizationContractSecret, `{"slug":"acme","display_name":"Acme, Inc."}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createOrganizationContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createOrganizationContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateOrganizationErrorEnvelopeDoesNotLeakDependencyCause proves a
// creator-store outage surfaces as a typed 5xx whose error envelope carries a
// stable generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
// organizations_create_test.go pins the typed-status part of this contract
// (TestCreateOrganizationDependencyFailureIsTyped5xx); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire.
func TestCreateOrganizationErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	creator := fakeOrganizationCreator{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator,
	)

	rec := postOrganizations(handler, createOrganizationContractSecret, `{"slug":"acme","display_name":"Acme, Inc."}`)
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
