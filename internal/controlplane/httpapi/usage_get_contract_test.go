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

// Public-API contract coverage for GET /v1/organizations/{org_id}/usage
// (BE-0101).
//
// usage_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the
// unauthenticated / invalid-credentials / cross-tenant / dependency-failure
// rejection space, the "empty list is a stable [] shape" invariant, the
// "store outage surfaces as a typed 503" invariant, and the "reader
// receives exactly the {org_id} path parameter" wiring invariant.
// usage_policy_test.go pins the full policy matrix (viewer/developer/owner
// roles plus the support principal's cross-tenant CapRead exception). This
// file closes the remaining contract-test criteria those tests do not
// assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries.
//
// GET /v1/organizations/{org_id}/usage has no request body and no query
// parameters: its only input is the {org_id} path parameter, an opaque
// identifier. There is therefore no syntactic request to reject as
// "invalid input" beyond the rejection paths already covered in
// usage_test.go (a malformed or unknown id surfaces as the deterministic
// 403 the policy engine returns through organizationIDResolver for ids
// outside the principal's tenant, or as the empty list for ids inside
// the tenant with no rows). The endpoint has no per-row "not found" path
// of its own — the read deterministically maps an unknown id to an empty
// list rather than to a 404, which is the contract the empty-list pin in
// usage_test.go proves. Structural twin of limits_get_contract_test.go
// (BE-0095), adapted to the usage read request shape ({org_id} path
// parameter, UsageReader port).

// listUsageContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response
// body, the test fails.
const listUsageContractSecret = "yk_live_supersecret_usage_get_DEADBEEF0123456789"

// listUsageHandlerForWithLogger builds the production GET
// /v1/organizations/{org_id}/usage request path (real policy engine, fake
// Authenticator, caller-supplied UsageReader) with a caller-supplied
// logger so a test can inspect the structured request log. It mirrors
// listLimitsHandlerForWithLogger for the usage READ endpoint.
func listUsageHandlerForWithLogger(
	id auth.Identity, authErr error, reader UsageReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, reader, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestListUsageServerWritesResponseDataOnlyToResponseWriter proves the HTTP
// server renders the response through the http.ResponseWriter alone: a
// served GET /v1/organizations/{org_id}/usage writes nothing to the
// process stdout/stderr, and the usage payload is carried by the response
// body. The structured logger is the only sanctioned out-of-band writer
// and it goes to its own buffer, never to the process streams.
func TestListUsageServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeUsageReader{
		usage: []store.OrganizationResourceUsage{
			{
				Resource:  store.QuotaResourceProjects,
				UsedValue: 3,
			},
		},
	}
	handler := listUsageHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleOwner), Method: auth.MethodSession},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getUsage(handler, orgID, listUsageContractSecret)
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
	payload := decodeUsageList(t, rec.Body.Bytes())
	if len(payload.Data.Usage) != 1 {
		t.Fatalf("usage = %+v, want exactly the seeded entry", payload.Data.Usage)
	}
	if payload.Data.Usage[0].Resource != "projects" {
		t.Errorf("usage[0].resource = %q, want projects — the data must be carried by the response body",
			payload.Data.Usage[0].Resource)
	}
	if payload.Data.Usage[0].UsedValue != 3 {
		t.Errorf("usage[0].used_value = %d, want 3 — the data must be carried by the response body",
			payload.Data.Usage[0].UsedValue)
	}
	// The structured logger is the only sanctioned writer, and it goes to
	// its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListUsageRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path
// and on the authorization-failure path alike. Headers are not logged at
// all; this test pins that contract so a future logging change cannot
// quietly start leaking credentials. The deny leg uses a reader whose
// ListOrganizationUsage path errors if invoked, so a logged "reader
// error" cannot be the leak source — the deny must short-circuit at
// policy.
func TestListUsageRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successReader := fakeUsageReader{
		usage: []store.OrganizationResourceUsage{
			{
				Resource:  store.QuotaResourceProjects,
				UsedValue: 3,
			},
		},
	}
	// The disabled-principal request must never reach the reader. A reader
	// whose List path errors if invoked proves the deny path short-circuits
	// at policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeUsageReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     UsageReader
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
			handler := listUsageHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getUsage(handler, orgID, listUsageContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listUsageContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listUsageContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListUsageErrorEnvelopeDoesNotLeakDependencyCause proves a reader-store
// outage surfaces as a typed 5xx whose error envelope carries a stable
// generic message — the wrapped driver cause (host, port, "connection
// refused") is kept for server-side logs only and never reaches the
// client. usage_test.go pins the typed-status part of this contract
// (TestListUsageForwardsStoreUnavailableAsTypedFiveHundred); this test
// pins the "the wrapped cause stays server-side" half that lives on the
// wire, including the bare datastore address that the cause string
// carries (a datastore address is exactly the kind of internal-network
// detail an error envelope must never leak).
func TestListUsageErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	reader := fakeUsageReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listUsageHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleOwner), Method: auth.MethodSession},
		nil, reader,
	)

	rec := getUsage(handler, orgID, listUsageContractSecret)
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
