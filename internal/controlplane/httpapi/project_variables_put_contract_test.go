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

// Public-API contract coverage for PUT
// /v1/projects/{project_id}/variables (BE-0146).
//
// project_variables_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration, the
// unauthenticated / cross-tenant / malformed-body / missing-variables-field /
// unknown-field / not-found / store-typed-invalid-input /
// dependency-failure / nil-replacer rejection space, the
// empty-array-as-explicit-clear semantics, the "replacer receives the
// principal's home org plus the path {project_id} plus the decoded
// items plus the actor identity" wiring invariant, and the wire-level
// redaction of every is_secret=true value (the customer that just
// submitted the secret value MUST NOT see it echoed back in the
// response body).
// projects_variables_put_policy_test.go pins the full policy matrix
// (viewer / developer / owner / admin / CI / support roles plus the
// deliberate absence of the support cross-tenant exception for the
// env.write CapWrite action, plus revoked / expired key handling and
// scoped-grant containment).
// This file closes the remaining contract-test criteria those tests do
// not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries;
//   - a submitted is_secret=true value never reaches the per-request
//     structured log — the headers-not-logged / body-not-logged contract
//     applies symmetrically to the request body for write endpoints, so a
//     future logging change cannot quietly start spilling customer-
//     submitted secrets into the operational log surface.
//
// Structural twin of variables_put_contract_test.go (BE-0110) and
// project_variables_get_contract_test.go (BE-0143), adapted to the
// project variables WRITE request shape ({project_id} path parameter,
// ProjectVariableReplacer port, env.write CapWrite action, body that
// carries is_secret=true values which are the variables-specific extra
// surface the read sibling does not cover). The endpoint mutates state,
// so a rejected request that nonetheless reaches the handler is
// materially worse than the read-only sibling: every deny-leg assertion
// here is also a "replacer was not invoked" assertion, so a regression
// that wires up the replacer behind the policy gate fails this story in
// two places.

// replaceProjectVariablesContractSecret is a recognisable bearer
// credential used by the redaction tests: if any byte of it reaches a
// log record or a response body, the test fails. Suffix is distinct
// from listProjectVariablesContractSecret (BE-0143),
// replaceOrgVariablesContractSecret (BE-0110), and
// updateLimitsContractSecret (BE-0098) so a regression that swaps any
// of those surfaces fails loudly.
const replaceProjectVariablesContractSecret = "yk_live_supersecret_project_variables_put_BAADF00D0123456789"

// replaceProjectVariablesContractSubmittedSecret is a recognisable
// secret value the customer submits in the request body. It must never
// reach the per-request structured log, even on the happy path. The
// marker is the leak detector — distinct from any natural value the
// test fixtures produce, so a substring match in the log is decisive.
const replaceProjectVariablesContractSubmittedSecret = "yallaprojectsubmittedsecretMARKER0123456789C0FFEE"

// replaceProjectVariablesContractBody is the canonical replace body
// used by the contract tests: a single non-secret variable plus a
// single secret variable carrying
// replaceProjectVariablesContractSubmittedSecret. The shape is
// deliberately the happy-path shape so a failure can never be blamed on
// body validation.
const replaceProjectVariablesContractBody = `{"variables":[` +
	`{"key":"REGION","value":"us-east-1"},` +
	`{"key":"DATABASE_URL","value":"yallaprojectsubmittedsecretMARKER0123456789C0FFEE","is_secret":true}` +
	`]}`

// replaceProjectVariablesHandlerForWithLogger builds the production PUT
// /v1/projects/{project_id}/variables request path (real policy engine,
// fake Authenticator, caller-supplied ProjectVariableReplacer) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors listProjectVariablesHandlerForWithLogger (BE-0143)
// for the project variables WRITE endpoint.
func replaceProjectVariablesHandlerForWithLogger(
	id auth.Identity, authErr error, replacer ProjectVariableReplacer, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, replacer, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestReplaceProjectVariablesServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served PUT
// /v1/projects/{project_id}/variables writes nothing to the process
// stdout/stderr, and the post-write variables payload is carried by
// the response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestReplaceProjectVariablesServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.ReplaceProjectVariablesInput
	replacer := fakeProjectVariableReplacer{
		vars: []store.ProjectVariable{
			{
				ID: "pvar_region", OrganizationID: orgID, ProjectID: projectID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "pvar_db", OrganizationID: orgID, ProjectID: projectID, Key: "DATABASE_URL",
				Value: replaceProjectVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
		got: &captured,
	}
	handler := replaceProjectVariablesHandlerForWithLogger(
		principalForProjectVariables("usr_owner", orgID), nil, replacer, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = putProjectVariables(handler, projectID, replaceProjectVariablesContractSecret, replaceProjectVariablesContractBody)
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
	env := decodeReplaceProjectVariables(t, rec)
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
	// proves the wire shape, but the captured input proves the
	// {project_id} path parameter reached the store layer, so a future
	// refactor that bypasses the ProjectVariableReplacer path fails
	// this story (in addition to project_variables_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want the principal's home org %q", captured.OrganizationID, orgID)
	}
	if captured.ProjectID != projectID {
		t.Errorf("replacer received project_id %q, want the path parameter %q", captured.ProjectID, projectID)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestReplaceProjectVariablesRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny
// leg uses a disabled principal so policy short-circuits before the
// replacer runs, and the replacer's Replace path errors if invoked,
// proving that a logged "replacer error" cannot be the leak source.
// The pin covers both the structured log buffer AND the response body
// so a regression that echoes the Authorization header into either
// surface fails fast.
func TestReplaceProjectVariablesRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	allowed := principalForProjectVariables("usr_ada", orgID)
	denied := principalForProjectVariables("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successReplacer := fakeProjectVariableReplacer{
		vars: []store.ProjectVariable{
			{
				ID: "pvar_region", OrganizationID: orgID, ProjectID: projectID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "pvar_db", OrganizationID: orgID, ProjectID: projectID, Key: "DATABASE_URL",
				Value: replaceProjectVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
	}
	// The disabled-principal request must never reach the replacer. A
	// replacer whose Replace path errors if invoked proves the deny
	// path short-circuits at policy, so any logged "replacer error"
	// can't be the leak source.
	denyReplacer := fakeProjectVariableReplacer{err: stderrors.New("replacer must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		replacer   ProjectVariableReplacer
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			replacer:   successReplacer,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
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
			handler := replaceProjectVariablesHandlerForWithLogger(tc.identity, nil, tc.replacer, logger)

			rec := putProjectVariables(handler, projectID, replaceProjectVariablesContractSecret, replaceProjectVariablesContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), replaceProjectVariablesContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), replaceProjectVariablesContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestReplaceProjectVariablesRequestLogRedactsSubmittedSecretValue is
// the variables-specific extra pin: the per-request structured log
// never carries an is_secret=true value the customer just submitted,
// on the happy path AND on the authorization-failure path alike. The
// headers-not-logged / body-not-logged contract applies symmetrically
// to the request body for write endpoints — a regression that starts
// dumping the raw decoded body into the log would silently spill every
// secret variable through this endpoint, so the contract pin guards
// against that regression on both legs (a leak in the deny path is
// even more dangerous: the value never reached the store, but it still
// reaches the operator log). project_variables_test.go pins the
// wire-level redaction half (the response body renders is_secret=true
// values as the sentinel); this test pins the operational log half.
func TestReplaceProjectVariablesRequestLogRedactsSubmittedSecretValue(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	allowed := principalForProjectVariables("usr_ada", orgID)
	denied := principalForProjectVariables("usr_revoked", orgID)
	denied.Principal.Disabled = true

	successReplacer := fakeProjectVariableReplacer{
		vars: []store.ProjectVariable{
			{
				ID: "pvar_region", OrganizationID: orgID, ProjectID: projectID, Key: "REGION",
				Value: "us-east-1", IsSecret: false, Version: 1,
			},
			{
				ID: "pvar_db", OrganizationID: orgID, ProjectID: projectID, Key: "DATABASE_URL",
				Value: replaceProjectVariablesContractSubmittedSecret, IsSecret: true, Version: 1,
			},
		},
	}
	denyReplacer := fakeProjectVariableReplacer{err: stderrors.New("replacer must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		replacer   ProjectVariableReplacer
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			replacer:   successReplacer,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
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
			handler := replaceProjectVariablesHandlerForWithLogger(tc.identity, nil, tc.replacer, logger)

			rec := putProjectVariables(handler, projectID, replaceProjectVariablesContractSecret, replaceProjectVariablesContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), replaceProjectVariablesContractSubmittedSecret) {
				t.Errorf("request log leaked a submitted secret value: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), replaceProjectVariablesContractSubmittedSecret) {
				t.Errorf("response body echoed a submitted secret value: %s", rec.Body.String())
			}
		})
	}
}

// TestReplaceProjectVariablesErrorEnvelopeDoesNotLeakDependencyCause
// proves a replacer-store outage surfaces as a typed 5xx whose error
// envelope carries a stable generic message — the wrapped driver cause
// (host, port, "connection refused") is kept for server-side logs only
// and never reaches the client. project_variables_test.go pins the
// typed-status part of this contract; this test pins the "the wrapped
// cause stays server-side" half that lives on the wire, including the
// bare datastore address that the cause string carries (a datastore
// address is exactly the kind of internal-network detail an error
// envelope must never leak).
func TestReplaceProjectVariablesErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	replacer := fakeProjectVariableReplacer{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := replaceProjectVariablesHandlerFor(
		principalForProjectVariables("usr_owner", orgID), nil, replacer,
	)

	rec := putProjectVariables(handler, projectID, replaceProjectVariablesContractSecret, replaceProjectVariablesContractBody)
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
