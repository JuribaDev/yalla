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

// Public-API contract coverage for PUT /v1/organizations/{org_id}/variables
// (BE-0110).
//
// variables_put_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration (operationId
// replaceOrganizationVariables + env.write required action + variables
// tag), the unauthenticated / cross-tenant / malformed-body /
// missing-variables-field / unknown-field / not-found /
// store-typed-invalid-input / dependency-failure / nil-replacer rejection
// space, the empty-array-as-explicit-clear semantics, the
// wire-level redaction of every is_secret=true value (the customer that
// just submitted the secret value MUST NOT see it echoed back in the
// response body), and the "replacer receives the {org_id} path parameter,
// the decoded items, and the actor identity" wiring invariant.
// variables_put_policy_test.go pins the full policy matrix
// (viewer / developer / owner / admin / CI / support roles plus the
// deliberate absence of the support cross-tenant exception for CapWrite
// actions). This file closes the remaining contract-test criteria those
// tests do not assert directly:
//
//   - the HTTP server writes response data only through the
//     http.ResponseWriter — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including bare datastore addresses the
//     cause string carries;
//   - a submitted is_secret=true value never reaches the per-request
//     structured log — the headers-not-logged / body-not-logged contract
//     applies symmetrically to the request body for write endpoints, so a
//     future logging change cannot quietly start spilling customer-
//     submitted secrets into the operational log surface.
//
// Structural twin of limits_patch_contract_test.go (BE-0098), adapted to
// the PUT /v1/organizations/{org_id}/variables request shape
// (OrganizationVariableReplacer port, env.write action, body that carries
// is_secret=true values which are the variables-specific extra surface
// the limits sibling does not cover). The endpoint mutates state, so a
// rejected request that nonetheless reaches the handler is materially
// worse than the read-only sibling: every deny-leg assertion here is also
// a "replacer was not invoked" assertion, so a regression that wires up
// the replacer behind the policy gate fails this story in two places.

// replaceOrgVariablesContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record or
// a response body, the test fails. Suffix is distinct from
// listOrgVariablesContractSecret (BE-0107) and updateLimitsContractSecret
// (BE-0098) so a regression that swaps the three surfaces fails loudly.
const replaceOrgVariablesContractSecret = "yk_live_supersecret_org_variables_put_CAFEBABE0123456789"

// replaceOrgVariablesContractSubmittedSecret is a recognisable secret
// value the customer submits in the request body. It must never reach
// the per-request structured log, even on the happy path. The marker is
// the leak detector — distinct from any natural value the test fixtures
// produce, so a substring match in the log is decisive.
const replaceOrgVariablesContractSubmittedSecret = "yallasubmittedsecretMARKER0123456789FACEFEED"

// replaceOrgVariablesContractBody is the canonical replace body used by
// the contract tests: a single non-secret variable plus a single secret
// variable carrying replaceOrgVariablesContractSubmittedSecret. The
// shape is deliberately the happy-path shape so a failure can never be
// blamed on body validation.
const replaceOrgVariablesContractBody = `{"variables":[` +
	`{"key":"REGION","value":"us-east-1"},` +
	`{"key":"DATABASE_URL","value":"yallasubmittedsecretMARKER0123456789FACEFEED","is_secret":true}` +
	`]}`

// replaceOrgVariablesHandlerForWithLogger builds the production PUT
// /v1/organizations/{org_id}/variables request path (real policy engine,
// fake Authenticator, caller-supplied OrganizationVariableReplacer) with
// a caller-supplied logger so a test can inspect the structured request
// log. It mirrors updateLimitsHandlerForWithLogger for the organization
// variables WRITE endpoint.
func replaceOrgVariablesHandlerForWithLogger(
	id auth.Identity, authErr error, replacer OrganizationVariableReplacer, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, replacer, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestReplaceOrgVariablesServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served PUT
// /v1/organizations/{org_id}/variables writes nothing to the process
// stdout/stderr, and the post-write variables payload is carried by the
// response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestReplaceOrgVariablesServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{
		vars: []store.OrganizationVariable{
			{
				ID: "ovar_region", OrganizationID: orgID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "ovar_db", OrganizationID: orgID, Key: "DATABASE_URL",
				Value: replaceOrgVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
		got: &captured,
	}
	handler := replaceOrgVariablesHandlerForWithLogger(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = putOrgVariables(handler, orgID, replaceOrgVariablesContractSecret, replaceOrgVariablesContractBody)
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
	env := decodeUpdateOrgVariables(t, rec)
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables = %+v, want exactly the two post-write entries", env.Data.Variables)
	}
	if env.Data.Variables[0].Key != "REGION" {
		t.Errorf("variables[0].key = %q, want REGION — the data must be carried by the response body",
			env.Data.Variables[0].Key)
	}
	if env.Data.Variables[1].Key != "DATABASE_URL" {
		t.Errorf("variables[1].key = %q, want DATABASE_URL — the data must be carried by the response body",
			env.Data.Variables[1].Key)
	}
	// The replacer must have actually been driven — the success body
	// proves the wire shape, but the captured input proves the {org_id}
	// path parameter reached the store layer, so a future refactor that
	// bypasses the OrganizationVariableReplacer path fails this story
	// (in addition to variables_put_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want the path parameter %q", captured.OrganizationID, orgID)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestReplaceOrgVariablesRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny leg
// uses a replacer whose Replace path errors if invoked, so a logged
// "replacer error" cannot be the leak source — the deny must
// short-circuit at policy. The pin covers both the structured log
// buffer AND the response body so a regression that echoes the
// Authorization header into either surface fails fast.
func TestReplaceOrgVariablesRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successReplacer := fakeOrgVariableReplacer{
		vars: []store.OrganizationVariable{
			{
				ID: "ovar_region", OrganizationID: orgID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "ovar_db", OrganizationID: orgID, Key: "DATABASE_URL",
				Value: replaceOrgVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
	}
	// The disabled-principal request must never reach the replacer. A
	// replacer whose Replace path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "replacer error" can't be
	// the leak source.
	denyReplacer := fakeOrgVariableReplacer{err: stderrors.New("replacer must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		replacer   OrganizationVariableReplacer
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			replacer:   successReplacer,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			replacer:   denyReplacer,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := replaceOrgVariablesHandlerForWithLogger(tc.identity, nil, tc.replacer, logger)

			rec := putOrgVariables(handler, orgID, replaceOrgVariablesContractSecret, replaceOrgVariablesContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), replaceOrgVariablesContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), replaceOrgVariablesContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestReplaceOrgVariablesRequestLogRedactsSubmittedSecretValue is the
// variables-specific extra pin: the per-request structured log never
// carries an is_secret=true value the customer just submitted, on the
// happy path AND on the authorization-failure path alike. The
// headers-not-logged / body-not-logged contract applies symmetrically
// to the request body for write endpoints — a regression that starts
// dumping the raw decoded body into the log would silently spill every
// secret variable through this endpoint, so the contract pin guards
// against that regression on both legs (a leak in the deny path is even
// more dangerous: the value never reached the store, but it still
// reaches the operator log). variables_put_test.go pins the wire-level
// redaction half (the response body never echoes a submitted secret);
// this test pins the operational log half.
func TestReplaceOrgVariablesRequestLogRedactsSubmittedSecretValue(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successReplacer := fakeOrgVariableReplacer{
		vars: []store.OrganizationVariable{
			{
				ID: "ovar_region", OrganizationID: orgID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "ovar_db", OrganizationID: orgID, Key: "DATABASE_URL",
				Value: replaceOrgVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
	}
	denyReplacer := fakeOrgVariableReplacer{err: stderrors.New("replacer must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		replacer   OrganizationVariableReplacer
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			replacer:   successReplacer,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			replacer:   denyReplacer,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := replaceOrgVariablesHandlerForWithLogger(tc.identity, nil, tc.replacer, logger)

			rec := putOrgVariables(handler, orgID, replaceOrgVariablesContractSecret, replaceOrgVariablesContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), replaceOrgVariablesContractSubmittedSecret) {
				t.Errorf("request log leaked a submitted secret value: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), replaceOrgVariablesContractSubmittedSecret) {
				t.Errorf("response body echoed a submitted secret value: %s", rec.Body.String())
			}
		})
	}
}

// TestReplaceOrgVariablesErrorEnvelopeDoesNotLeakDependencyCause proves
// a replacer-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. variables_put_test.go pins the typed-status
// part of this contract
// (TestReplaceOrgVariablesForwardsStoreUnavailableAsTypedFiveHundred);
// this test pins the "the wrapped cause stays server-side" half that
// lives on the wire, including the bare datastore address that the
// cause string carries (a datastore address is exactly the kind of
// internal-network detail an error envelope must never leak).
func TestReplaceOrgVariablesErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	replacer := fakeOrgVariableReplacer{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer,
	)

	rec := putOrgVariables(handler, orgID, replaceOrgVariablesContractSecret, replaceOrgVariablesContractBody)
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
