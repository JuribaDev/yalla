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

// Public-API contract coverage for PATCH
// /v1/organizations/{org_id}/variables/{key} (BE-0113).
//
// variables_patch_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, the
// request_id propagation, the OpenAPI operation registration
// (operationId patchOrganizationVariable + env.write required action +
// variables tag + {key} path parameter), the unauthenticated /
// cross-tenant / malformed-body / empty-body / unknown-field /
// not-found / store-outage / nil-patcher rejection space, the
// "value-only forwards a nil IsSecret" and "is_secret-only forwards a
// nil Value" partial-field invariants, the wire-level redaction of
// the submitted secret value (the customer that just submitted a
// is_secret=true value MUST NOT see it echoed back in the response
// body), and the "patcher receives the {org_id} and {key} path
// parameters, the decoded pointers, and the actor identity" wiring
// invariant. variables_patch_policy_test.go (BE-0114) pins the full
// policy matrix (viewer / developer / owner / admin / CI / support
// roles plus the deliberate absence of the support cross-tenant
// exception for CapWrite actions). This file closes the remaining
// contract-test criteria those tests do not assert directly:
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
// Structural twin of variables_put_contract_test.go (BE-0110), adapted
// to the PATCH /v1/organizations/{org_id}/variables/{key} request shape
// (OrganizationVariablePatcher port, {key} path parameter, body that
// carries an is_secret=true value which is the variables-specific
// extra surface a generic write endpoint does not cover). The endpoint
// mutates state, so a rejected request that nonetheless reaches the
// handler is materially worse than a read-only sibling: every
// deny-leg assertion here is also a "patcher was not invoked"
// assertion, so a regression that wires up the patcher behind the
// policy gate fails this story in two places.

// patchOrgVariableContractSecret is a recognisable bearer credential
// used by the redaction tests: if any byte of it reaches a log record
// or a response body, the test fails. Suffix is distinct from
// replaceOrgVariablesContractSecret (BE-0110) and
// listOrgVariablesContractSecret (BE-0107) so a regression that swaps
// the three surfaces fails loudly.
const patchOrgVariableContractSecret = "yk_live_supersecret_org_variables_patch_BEEFDEAD0123456789"

// patchOrgVariableContractSubmittedSecret is a recognisable secret
// value the customer submits in the request body. It must never reach
// the per-request structured log, even on the happy path. The marker
// is the leak detector — distinct from any natural value the test
// fixtures produce, so a substring match in the log is decisive.
const patchOrgVariableContractSubmittedSecret = "yallapatchedsecretMARKER0123456789CAFEBABE"

// patchOrgVariableContractBody is the canonical patch body used by the
// contract tests: a single secret value promotion carrying
// patchOrgVariableContractSubmittedSecret. The shape is deliberately
// the happy-path shape so a failure can never be blamed on body
// validation.
const patchOrgVariableContractBody = `{"value":"yallapatchedsecretMARKER0123456789CAFEBABE","is_secret":true}`

// patchOrgVariableHandlerForWithLogger builds the production PATCH
// /v1/organizations/{org_id}/variables/{key} request path (real policy
// engine, fake Authenticator, caller-supplied OrganizationVariablePatcher)
// with a caller-supplied logger so a test can inspect the structured
// request log. It mirrors replaceOrgVariablesHandlerForWithLogger for
// the single-key variables WRITE endpoint.
func patchOrgVariableHandlerForWithLogger(
	id auth.Identity, authErr error, patcher OrganizationVariablePatcher, logger *slog.Logger,
) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, patcher, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// TestPatchOrgVariableServerWritesResponseDataOnlyToResponseWriter
// proves the HTTP server renders the response through the
// http.ResponseWriter alone: a served PATCH
// /v1/organizations/{org_id}/variables/{key} writes nothing to the
// process stdout/stderr, and the post-write variable payload is
// carried by the response body. The structured logger is the only
// sanctioned out-of-band writer and it goes to its own buffer, never
// to the process streams.
func TestPatchOrgVariableServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var captured store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{
		v: store.OrganizationVariable{
			ID: "ovar_db", OrganizationID: orgID, Key: key,
			Value: patchOrgVariableContractSubmittedSecret, IsSecret: true, Version: 2,
		},
		got: &captured,
	}
	handler := patchOrgVariableHandlerForWithLogger(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = patchOrgVariable(handler, orgID, key, patchOrgVariableContractSecret, patchOrgVariableContractBody)
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
	env := decodePatchOrgVariable(t, rec)
	if env.Data.Variable.Key != key {
		t.Errorf("variable.key = %q, want %q — the data must be carried by the response body",
			env.Data.Variable.Key, key)
	}
	// The patcher must have actually been driven — the success body
	// proves the wire shape, but the captured input proves the {org_id}
	// and {key} path parameters reached the store layer, so a future
	// refactor that bypasses the OrganizationVariablePatcher path fails
	// this story (in addition to variables_patch_test.go).
	if captured.OrganizationID != orgID {
		t.Errorf("patcher received org_id %q, want the path parameter %q", captured.OrganizationID, orgID)
	}
	if captured.Key != key {
		t.Errorf("patcher received key %q, want the path parameter %q", captured.Key, key)
	}
	// The structured logger is the only sanctioned writer, and it goes
	// to its own sink — never to the response and never to the process
	// streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestPatchOrgVariableRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential — on
// the happy path and on the authorization-failure path alike. Headers
// are not logged at all; this test pins that contract so a future
// logging change cannot quietly start leaking credentials. The deny
// leg uses a patcher whose Patch path errors if invoked, so a logged
// "patcher error" cannot be the leak source — the deny must
// short-circuit at policy. The pin covers both the structured log
// buffer AND the response body so a regression that echoes the
// Authorization header into either surface fails fast.
func TestPatchOrgVariableRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successPatcher := fakeOrgVariablePatcher{
		v: store.OrganizationVariable{
			ID: "ovar_db", OrganizationID: orgID, Key: key,
			Value: patchOrgVariableContractSubmittedSecret, IsSecret: true, Version: 2,
		},
	}
	// The disabled-principal request must never reach the patcher. A
	// patcher whose Patch path errors if invoked proves the deny path
	// short-circuits at policy, so any logged "patcher error" can't be
	// the leak source.
	denyPatcher := fakeOrgVariablePatcher{err: stderrors.New("patcher must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		patcher    OrganizationVariablePatcher
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			patcher:    successPatcher,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			patcher:    denyPatcher,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := patchOrgVariableHandlerForWithLogger(tc.identity, nil, tc.patcher, logger)

			rec := patchOrgVariable(handler, orgID, key, patchOrgVariableContractSecret, patchOrgVariableContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), patchOrgVariableContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), patchOrgVariableContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestPatchOrgVariableRequestLogRedactsSubmittedSecretValue is the
// variables-specific extra pin: the per-request structured log never
// carries an is_secret=true value the customer just submitted, on the
// happy path AND on the authorization-failure path alike. The
// headers-not-logged / body-not-logged contract applies symmetrically
// to the request body for write endpoints — a regression that starts
// dumping the raw decoded body into the log would silently spill every
// secret variable through this endpoint, so the contract pin guards
// against that regression on both legs (a leak in the deny path is
// even more dangerous: the value never reached the store, but it still
// reaches the operator log). variables_patch_test.go pins the
// wire-level redaction half (the response body never echoes a
// submitted secret); this test pins the operational log half.
func TestPatchOrgVariableRequestLogRedactsSubmittedSecretValue(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	owner := orgPrincipal("usr_ada", orgID, policy.RoleOwner)
	disabled := orgPrincipal("usr_revoked", orgID, policy.RoleOwner)
	disabled.Disabled = true

	successPatcher := fakeOrgVariablePatcher{
		v: store.OrganizationVariable{
			ID: "ovar_db", OrganizationID: orgID, Key: key,
			Value: patchOrgVariableContractSubmittedSecret, IsSecret: true, Version: 2,
		},
	}
	denyPatcher := fakeOrgVariablePatcher{err: stderrors.New("patcher must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		patcher    OrganizationVariablePatcher
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			patcher:    successPatcher,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
			patcher:    denyPatcher,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := patchOrgVariableHandlerForWithLogger(tc.identity, nil, tc.patcher, logger)

			rec := patchOrgVariable(handler, orgID, key, patchOrgVariableContractSecret, patchOrgVariableContractBody)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), patchOrgVariableContractSubmittedSecret) {
				t.Errorf("request log leaked a submitted secret value: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), patchOrgVariableContractSubmittedSecret) {
				t.Errorf("response body echoed a submitted secret value: %s", rec.Body.String())
			}
		})
	}
}

// TestPatchOrgVariableErrorEnvelopeDoesNotLeakDependencyCause proves
// a patcher-store outage surfaces as a typed 5xx whose error envelope
// carries a stable generic message — the wrapped driver cause (host,
// port, "connection refused") is kept for server-side logs only and
// never reaches the client. variables_patch_test.go pins the
// typed-status part of this contract
// (TestPatchOrgVariableStoreOutageIsTypedFailure); this test pins the
// "the wrapped cause stays server-side" half that lives on the wire,
// including the bare datastore address that the cause string carries
// (a datastore address is exactly the kind of internal-network detail
// an error envelope must never leak).
func TestPatchOrgVariableErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID = "org_acme"
		key   = "DATABASE_URL"
		cause = "connection refused dialing 10.0.0.5:5432"
	)
	patcher := fakeOrgVariablePatcher{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher,
	)

	rec := patchOrgVariable(handler, orgID, key, patchOrgVariableContractSecret, patchOrgVariableContractBody)
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
