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
// /v1/projects/{project_id}/grants (BE-0140).
//
// project_grants_put_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the empty-array-as-
// explicit-clear semantics, the unauthenticated / cross-tenant /
// malformed-body / missing-grants-field / unknown-field /
// not-found-project / store-typed-invalid-input / dependency-failure /
// nil-replacer rejection space, and the "replacer receives the
// {project_id} path parameter, the decoded items, and the actor
// identity" wiring invariant.
// projects_grants_put_policy_test.go pins the full policy matrix
// (viewer/developer/ci roles deny, owner/admin allow, plus the deliberate
// absence of the support cross-tenant exception for the
// project.grants.write CapAdmin action). This file closes the remaining
// contract-test criteria those tests do not assert directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including the bare datastore address that
//     the cause string typically carries.
//
// PUT /v1/projects/{project_id}/grants accepts a single opaque
// {project_id} path parameter and a body whose only field is
// "grants" — a list of principal_id / principal_kind / role / optional
// environment_id / optional service_id tuples. The store-backed replacer
// treats an unknown or cross-tenant project_id as a deterministic 404,
// which is the contract project_grants_put_test.go's
// TestReplaceProjectGrantsPropagatesNotFoundProject pins. Structural twin
// of variables_put_contract_test.go (BE-0110) and
// project_grants_get_contract_test.go (BE-0137), adapted to the project
// grants WRITE endpoint request shape ({project_id} path parameter,
// ProjectGrantReplacer port, project.grants.write CapAdmin action). The
// "submitted-secret-value redaction" pin from variables_put_contract_test.go
// is omitted: a project grant body carries no customer-submitted secret
// values — only opaque identifiers and a role — so the variables-specific
// fourth contract assertion has no analogue here. The endpoint mutates
// state, so every deny-leg assertion in this file is also a "replacer
// was not invoked" assertion: a regression that wires the replacer
// behind the policy gate fails this story.

// replaceProjectGrantsContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record or
// a response body, the test fails. Suffix is distinct from
// listProjectGrantsContractSecret (BE-0137) so a regression that swaps
// the two surfaces fails loudly.
const replaceProjectGrantsContractSecret = "yk_live_supersecret_project_grants_put_CAFEBABE0123456789"

// replaceProjectGrantsContractBody is the canonical replace body used by
// the contract tests: a developer-role user grant plus a ci-role service
// account grant narrowed to an environment+service tuple. The shape is
// deliberately the happy-path shape so a failure can never be blamed on
// body validation. Grants carry no customer-submitted secret values, so
// the body does not need a leak-marker like
// replaceOrgVariablesContractSubmittedSecret — the contract reduces to
// the three-test triple of BE-0137.
const replaceProjectGrantsContractBody = `{"grants":[` +
	`{"principal_id":"usr_one","principal_kind":"usr","role":"developer"},` +
	`{"principal_id":"sa_one","principal_kind":"sa","role":"ci","environment_id":"env_prod","service_id":"svc_web"}` +
	`]}`

// replaceProjectGrantsHandlerForWithLogger builds the production PUT
// /v1/projects/{project_id}/grants request path (real policy engine,
// fake Authenticator, caller-supplied ProjectGrantReplacer) with a
// caller-supplied logger so a test can inspect the structured request
// log. It mirrors replaceOrgVariablesHandlerForWithLogger for the
// project grants WRITE endpoint and listProjectGrantsHandlerForWithLogger
// for the project grants READ endpoint.
func replaceProjectGrantsHandlerForWithLogger(
	id auth.Identity, authErr error, replacer ProjectGrantReplacer, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, replacer, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestReplaceProjectGrantsServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served PUT
// /v1/projects/{project_id}/grants writes nothing to the process
// stdout/stderr, and the post-write grants payload is carried by the
// response body. The structured logger is the only sanctioned
// out-of-band writer and it goes to its own buffer, never to the
// process streams.
func TestReplaceProjectGrantsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	envID := "env_prod"
	svcID := "svc_web"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.ReplaceProjectGrantsInput
	replacer := fakeProjectGrantReplacer{
		grants: []store.ProjectGrant{
			{
				ID: "pgrnt_one", OrganizationID: orgID, ProjectID: projectID,
				PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer",
				Version: 1,
			},
			{
				ID: "pgrnt_two", OrganizationID: orgID, ProjectID: projectID,
				PrincipalID: "sa_one", PrincipalKind: "sa", Role: "ci",
				EnvironmentID: &envID, ServiceID: &svcID, Version: 1,
			},
		},
		got: &captured,
	}
	handler := replaceProjectGrantsHandlerForWithLogger(
		projectGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = putProjectGrants(handler, projectID, replaceProjectGrantsContractSecret, replaceProjectGrantsContractBody)
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
	env := decodeReplaceProjectGrants(t, rec)
	if len(env.Data.Grants) != 2 {
		t.Fatalf("grants = %+v, want exactly the two post-write entries", env.Data.Grants)
	}
	if env.Data.Grants[0].GrantID != "pgrnt_one" {
		t.Errorf("grants[0].grant_id = %q, want pgrnt_one — the data must be carried by the response body",
			env.Data.Grants[0].GrantID)
	}
	if env.Data.Grants[1].GrantID != "pgrnt_two" {
		t.Errorf("grants[1].grant_id = %q, want pgrnt_two — the data must be carried by the response body",
			env.Data.Grants[1].GrantID)
	}
	// The replacer must have actually been driven — the success body
	// proves the wire shape, but the captured input proves the
	// {project_id} path parameter reached the store layer, so a future
	// refactor that bypasses the ProjectGrantReplacer path fails this
	// story (in addition to project_grants_put_test.go).
	if captured.ProjectID != projectID {
		t.Errorf("replacer received project_id %q, want the path parameter %q", captured.ProjectID, projectID)
	}
	if captured.OrganizationID != orgID {
		t.Errorf("replacer received organization_id %q, want the actor's home org %q", captured.OrganizationID, orgID)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestReplaceProjectGrantsRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny leg
// uses a disabled principal so policy short-circuits before the replacer
// runs, and the replacer's Replace path returns an error if invoked,
// proving that a logged "replacer error" cannot be the leak source. The
// pin covers both the structured log buffer AND the response body so a
// regression that echoes the Authorization header into either surface
// fails fast. Because the endpoint mutates state, the deny leg also
// proves the replacer was not invoked: a denied request that
// nonetheless reaches the store layer is materially worse than the
// read-only sibling, so the deny-fixture replacer is wired to error.
func TestReplaceProjectGrantsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
	)
	allowed := projectGrantsAdminIdentity(orgID, "usr_admin")
	denied := projectGrantsAdminIdentity(orgID, "usr_revoked")
	denied.Principal.Disabled = true

	successReplacer := fakeProjectGrantReplacer{
		grants: []store.ProjectGrant{
			{
				ID: "pgrnt_one", OrganizationID: orgID, ProjectID: projectID,
				PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer",
				Version: 1,
			},
		},
	}
	// The disabled-principal request must never reach the replacer. A
	// replacer whose Replace path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "replacer error" can't be
	// the leak source.
	denyReplacer := fakeProjectGrantReplacer{err: stderrors.New("replacer must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		replacer   ProjectGrantReplacer
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
			handler := replaceProjectGrantsHandlerForWithLogger(tc.identity, nil, tc.replacer, logger)

			rec := putProjectGrants(handler, projectID, replaceProjectGrantsContractSecret, replaceProjectGrantsContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), replaceProjectGrantsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), replaceProjectGrantsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestReplaceProjectGrantsErrorEnvelopeDoesNotLeakDependencyCause proves
// a replacer-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. project_grants_put_test.go pins the
// typed-status part of this contract
// (TestReplaceProjectGrantsForwardsStoreUnavailableAsTypedFiveHundred);
// this test pins the "the wrapped cause stays server-side" half that
// lives on the wire, including the bare datastore address that the
// cause string carries (a datastore address is exactly the kind of
// internal-network detail an error envelope must never leak).
func TestReplaceProjectGrantsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "prj_widgets"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	replacer := fakeProjectGrantReplacer{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := replaceProjectGrantsHandlerFor(
		projectGrantsAdminIdentity(orgID, "usr_admin"), nil, replacer,
	)

	rec := putProjectGrants(handler, projectID, replaceProjectGrantsContractSecret, replaceProjectGrantsContractBody)
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
