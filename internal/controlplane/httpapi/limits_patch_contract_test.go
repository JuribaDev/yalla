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

// Public-API contract coverage for PATCH /v1/organizations/{org_id}/limits
// (BE-0098).
//
// limits_patch_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration (route requires_auth +
// limits.write + has resource resolver), the unauthenticated /
// unauthorized-viewer / cross-tenant / not-found / malformed-body /
// empty-limits / missing-limit-value / dependency-failure / nil-updater
// rejection space, and the "updater receives the {org_id} path parameter,
// the decoded items, and the actor identity" wiring invariant.
// limits_patch_policy_test.go pins the full policy matrix (viewer /
// developer / support / owner / admin roles plus the deliberate absence of
// the support cross-tenant exception for CapAdmin actions). This file
// closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including bare datastore addresses the cause
//     string carries.
//
// Structural twin of limits_get_contract_test.go (BE-0095), adapted to the
// PATCH request shape ({org_id} path parameter, JSON body, LimitsUpdater
// port, mutating audit-emitting handler). The endpoint mutates state, so a
// rejected request that nonetheless reaches the handler is materially worse
// than the read-only sibling: every deny-leg assertion here is also a
// "updater was not invoked" assertion, so a regression that wires up the
// updater behind the policy gate fails this story in two places.

// updateLimitsContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response
// body, the test fails. Suffix is distinct from listLimitsContractSecret so
// a regression that swaps the two surfaces fails loudly.
const updateLimitsContractSecret = "yk_live_supersecret_limits_patch_FEEDFACE0123456789"

// updateLimitsContractBody is the canonical patch body used by the
// contract tests: a single closed-set resource with a non-zero limit_value
// and an explicit enforcement_mode. The shape is deliberately the
// happy-path shape so a failure can never be blamed on body validation.
const updateLimitsContractBody = `{"limits":[{"resource":"projects","limit_value":25,"enforcement_mode":"hard"}]}`

// updateLimitsHandlerForWithLogger builds the production PATCH
// /v1/organizations/{org_id}/limits request path (real policy engine, fake
// Authenticator, caller-supplied LimitsUpdater) with a caller-supplied
// logger so a test can inspect the structured request log. It mirrors
// listLimitsHandlerForWithLogger for the limits WRITE endpoint.
func updateLimitsHandlerForWithLogger(
	id auth.Identity, authErr error, updater LimitsUpdater, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a,
		policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, updater, fakeUsageReader{}, fakeAuditEventReader{},
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

// TestUpdateLimitsServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone:
// a served PATCH /v1/organizations/{org_id}/limits writes nothing to the
// process stdout/stderr, and the post-write effective limits payload is
// carried by the response body. The structured logger is the only
// sanctioned out-of-band writer and it goes to its own buffer, never to
// the process streams.
func TestUpdateLimitsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.UpdateLimitsInput
	updater := fakeLimitsUpdater{
		limits: []store.EffectiveQuotaLimit{
			{
				Resource:        store.QuotaResourceProjects,
				LimitValue:      25,
				EnforcementMode: store.EnforcementModeHard,
				Scope:           store.QuotaScopeOrganization,
			},
		},
		got: &captured,
	}
	handler := updateLimitsHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = patchLimits(handler, orgID, updateLimitsContractSecret, updateLimitsContractBody)
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
	env := decodeUpdateLimits(t, rec)
	if len(env.Data.Limits) != 1 {
		t.Fatalf("limits = %+v, want exactly the post-write limit", env.Data.Limits)
	}
	if env.Data.Limits[0].Resource != "projects" {
		t.Errorf("limits[0].resource = %q, want projects — the data must be carried by the response body",
			env.Data.Limits[0].Resource)
	}
	if env.Data.Limits[0].LimitValue != 25 {
		t.Errorf("limits[0].limit_value = %d, want 25 — the data must be carried by the response body",
			env.Data.Limits[0].LimitValue)
	}
	// The updater must have actually been driven — the success body proves
	// the wire shape, but the captured input proves the {org_id} path
	// parameter reached the store layer, so a future refactor that bypasses
	// the LimitsUpdater path fails this story (in addition to limits_patch_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("updater received org_id %q, want the path parameter %q", captured.OrganizationID, orgID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestUpdateLimitsRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path
// and on the authorization-failure path alike. Headers are not logged at
// all; this test pins that contract so a future logging change cannot
// quietly start leaking credentials. The deny leg uses an updater whose
// UpdateLimits path errors if invoked, so a logged "updater error" cannot
// be the leak source — the deny must short-circuit at policy. The pin
// covers both the structured log buffer AND the response body so a
// regression that echoes the Authorization header into either surface
// fails fast.
func TestUpdateLimitsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	admin := orgPrincipal("usr_ada", orgID, policy.RoleAdmin)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleAdmin)
	disabled.Disabled = true

	successUpdater := fakeLimitsUpdater{
		limits: []store.EffectiveQuotaLimit{
			{
				Resource:        store.QuotaResourceProjects,
				LimitValue:      25,
				EnforcementMode: store.EnforcementModeHard,
				Scope:           store.QuotaScopeOrganization,
			},
		},
	}
	// The disabled-principal request must never reach the updater. An
	// updater whose UpdateLimits path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "updater error" can't be the
	// leak source.
	denyUpdater := fakeLimitsUpdater{err: stderrors.New("updater must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		updater    LimitsUpdater
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: admin, Method: auth.MethodSession},
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
			handler := updateLimitsHandlerForWithLogger(tc.identity, nil, tc.updater, logger)

			rec := patchLimits(handler, orgID, updateLimitsContractSecret, updateLimitsContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), updateLimitsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), updateLimitsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestUpdateLimitsErrorEnvelopeDoesNotLeakDependencyCause proves an
// updater-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and never
// reaches the client. limits_patch_test.go pins the typed-status part of
// this contract (TestUpdateLimitsUpdaterErrorMapsToTypedStatus); this test
// pins the "the wrapped cause stays server-side" half that lives on the
// wire, including the bare datastore address that the cause string carries
// (a datastore address is exactly the kind of internal-network detail an
// error envelope must never leak).
func TestUpdateLimitsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	updater := fakeLimitsUpdater{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := updateLimitsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", orgID, policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater,
	)

	rec := patchLimits(handler, orgID, updateLimitsContractSecret, updateLimitsContractBody)
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
