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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for GET /v1/organizations (BE-0047).
//
// organizations_test.go already proves the success/error envelopes, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / invalid-credential / disabled-principal /
// home-organization-not-found / dependency-failure rejection space, and the
// "reader is scoped to the caller's own home organization" tenant invariant.
// This file closes the remaining contract-test criteria that those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks that
//     cause onto the wire.
//
// GET /v1/organizations has no request body, no path parameters, and no query
// parameters, so there is no caller input to validate as "invalid" beyond the
// rejection paths already covered in organizations_test.go (the "invalid
// input" row of the contract checklist is satisfied structurally). The
// "not found" row is satisfied by TestOrganizationsHomeOrganizationNotFound
// in organizations_test.go.

// organizationsContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const organizationsContractSecret = "yk_live_supersecret_orgs_list_DEADBEEF0123456789"

// organizationsHandlerForWithLogger builds the production GET /v1/organizations
// request path (real policy engine, fake Authenticator, caller-supplied
// reader) with a caller-supplied logger so a test can inspect the structured
// request log. It mirrors meHandlerWithLogger for the organizations endpoint.
func organizationsHandlerForWithLogger(
	id auth.Identity, authErr error, reader OrganizationReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(), reader, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
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

// TestOrganizationsServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone: a
// served GET /v1/organizations writes nothing to the process stdout/stderr,
// and the organization payload is carried by the response body.
func TestOrganizationsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeOrganizationReader{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	handler := organizationsHandlerForWithLogger(
		auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getOrganizations(handler, organizationsContractSecret)
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
	env := decodeOrganizations(t, rec)
	if len(env.Data.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want exactly the principal's home org", env.Data.Organizations)
	}
	if env.Data.Organizations[0].OrganizationID != "org_acme" {
		t.Errorf("organization_id = %q, want org_acme — the data must be carried by the response body",
			env.Data.Organizations[0].OrganizationID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestOrganizationsRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all; this
// test pins that contract so a future logging change cannot quietly start
// leaking credentials.
func TestOrganizationsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	disabled := policy.Principal{
		ID: "usr_revoked", Kind: domain.KindUser, OrganizationID: "org_acme",
		Role: policy.RoleOwner, Disabled: true,
	}
	successReader := fakeOrganizationReader{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme, Inc.",
	}}
	// The disabled-principal request must never reach the reader. A reader
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeOrganizationReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     OrganizationReader
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
			handler := organizationsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getOrganizations(handler, organizationsContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), organizationsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), organizationsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestOrganizationsErrorEnvelopeDoesNotLeakDependencyCause proves a
// reader-store outage surfaces as a typed 5xx whose error envelope carries a
// stable generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the client.
func TestOrganizationsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeOrganizationReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	principal := policy.Principal{
		ID: "usr_ada", Kind: domain.KindUser, OrganizationID: "org_acme", Role: policy.RoleViewer,
	}
	handler := organizationsHandlerFor(
		auth.Identity{Principal: principal, Method: auth.MethodSession}, nil, reader,
	)

	rec := getOrganizations(handler, organizationsContractSecret)
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
