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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for GET
// /v1/organizations/{org_id}/audit-events (BE-0104).
//
// audit_events_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / cross-tenant / invalid-input / out-of-range /
// dependency-failure rejection space, the "empty list is a stable []
// shape" invariant, the "store outage surfaces as a typed 503"
// invariant, and the "reader receives exactly the {org_id} path
// parameter and the resolved limit" wiring invariant.
// audit_events_policy_test.go pins the full policy matrix
// (viewer/developer/owner roles plus the support principal's
// cross-tenant CapRead exception for the audit.read action). This file
// closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries.
//
// GET /v1/organizations/{org_id}/audit-events accepts a single opaque
// {org_id} path parameter plus an optional ?limit= query parameter.
// Both the malformed-limit and out-of-range-limit invalid-input paths
// are pinned by audit_events_test.go (TestListAuditEventsRejectsMalformedLimit,
// TestListAuditEventsRejectsOutOfRangeLimit), and the endpoint has no
// per-row "not found" path of its own — an unknown id inside the
// tenant resolves to an empty list rather than a 404, which is the
// contract the empty-list pin in audit_events_test.go proves.
// Structural twin of usage_get_contract_test.go (BE-0101) adapted to
// the audit-events read request shape ({org_id} path parameter,
// AuditEventReader port, optional ?limit= query parameter).

// listAuditEventsContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails.
const listAuditEventsContractSecret = "yk_live_supersecret_audit_events_get_DEADBEEF0123456789"

// listAuditEventsHandlerForWithLogger builds the production GET
// /v1/organizations/{org_id}/audit-events request path (real policy
// engine, fake Authenticator, caller-supplied AuditEventReader) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors listUsageHandlerForWithLogger for the audit-events
// READ endpoint.
func listAuditEventsHandlerForWithLogger(
	id auth.Identity, authErr error, reader AuditEventReader, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, reader, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestListAuditEventsServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served GET
// /v1/organizations/{org_id}/audit-events writes nothing to the process
// stdout/stderr, and the audit-events payload is carried by the
// response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestListAuditEventsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	occurred := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeAuditEventReader{
		events: []store.AuditEvent{
			{
				ID:             "aud_001",
				OrganizationID: orgID,
				ActorID:        "usr_admin",
				ActorKind:      domain.KindUser.String(),
				Action:         "limits.write",
				Decision:       store.AuditDecisionAllowed,
				OccurredAt:     occurred,
				RequestID:      "req_abc",
			},
		},
	}
	handler := listAuditEventsHandlerForWithLogger(
		auditEventActorIdentity(orgID, "usr_owner"), nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getAuditEvents(handler, orgID, "", listAuditEventsContractSecret)
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
	env := decodeAuditEventList(t, rec.Body.Bytes())
	if len(env.Data.Events) != 1 {
		t.Fatalf("events = %+v, want exactly the seeded entry", env.Data.Events)
	}
	if env.Data.Events[0].ID != "aud_001" {
		t.Errorf("events[0].id = %q, want %q — the data must be carried by the response body",
			env.Data.Events[0].ID, "aud_001")
	}
	if env.Data.Events[0].Action != "limits.write" {
		t.Errorf("events[0].action = %q, want %q — the data must be carried by the response body",
			env.Data.Events[0].Action, "limits.write")
	}
	// The structured logger is the only sanctioned writer, and it goes to
	// its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestListAuditEventsRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny leg
// uses a reader whose ListByOrganization path errors if invoked, so a
// logged "reader error" cannot be the leak source — the deny must
// short-circuit at policy.
func TestListAuditEventsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	occurred := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successReader := fakeAuditEventReader{
		events: []store.AuditEvent{
			{
				ID:             "aud_001",
				OrganizationID: orgID,
				ActorID:        "usr_admin",
				ActorKind:      domain.KindUser.String(),
				Action:         "limits.write",
				Decision:       store.AuditDecisionAllowed,
				OccurredAt:     occurred,
				RequestID:      "req_abc",
			},
		},
	}
	// The disabled-principal request must never reach the reader. A reader
	// whose ListByOrganization path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "reader error" can't be the
	// leak source.
	denyReader := fakeAuditEventReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     AuditEventReader
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := listAuditEventsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getAuditEvents(handler, orgID, "", listAuditEventsContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listAuditEventsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listAuditEventsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestListAuditEventsErrorEnvelopeDoesNotLeakDependencyCause proves a
// reader-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. audit_events_test.go pins the typed-status
// part of this contract
// (TestListAuditEventsForwardsStoreUnavailableAsTypedFiveHundred); this
// test pins the "the wrapped cause stays server-side" half that lives
// on the wire, including the bare datastore address that the cause
// string carries (a datastore address is exactly the kind of
// internal-network detail an error envelope must never leak).
func TestListAuditEventsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	reader := fakeAuditEventReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listAuditEventsHandlerFor(
		auditEventActorIdentity(orgID, "usr_owner"), nil, reader,
	)

	rec := getAuditEvents(handler, orgID, "", listAuditEventsContractSecret)
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
