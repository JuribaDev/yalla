package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
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
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract, authorization, and tenant-isolation coverage for POST
// /v1/services/{service_id}/backups/{backup_id}/run (BE-0253 +
// BE-0254). The endpoint records a manual-run intent against the
// backup-policy row named by the {service_id} and {backup_id} path
// parameters through the ServiceBackupRunner port. The tests drive
// it through NewHandler with a fake Authenticator, the real policy
// engine, and a fake runner — the same wiring a request hits in
// production, minus the database. The store-backed runner
// (ServiceBackupService.Run) has its own isolated-Postgres
// integration coverage in store/service_backup_test.go; this file
// exercises the HTTP surface in isolation. The full role x tenant x
// grant-scope matrix lives in service_backups_run_policy_test.go
// (BE-0255).
//
// backup.run is a CapDeploy action: viewer and support principals
// in the tenant cannot trigger a run, but a CI key DOES — the
// load-bearing distinction from backup.create (CapWrite). The
// happy-path tests authenticate as RoleDeveloper to keep the role
// matrix focused on the policy suite.

// fakeServiceBackupRunner is the test double for the
// ServiceBackupRunner port: it captures the RunServiceBackupInput
// a test passed in, the call count, and returns a canned
// ServiceBackup / error. The captured input is the single
// load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity to the audit record.
type fakeServiceBackupRunner struct {
	backup    store.ServiceBackup
	err       error
	gotInput  *store.RunServiceBackupInput
	callCount *int
}

func (f fakeServiceBackupRunner) Run(_ context.Context, in store.RunServiceBackupInput) (store.ServiceBackup, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.backup, f.err
}

// runServiceBackupSuccessEnvelope is the decoded shape of the POST
// /v1/services/{service_id}/backups/{backup_id}/run success
// envelope.
type runServiceBackupSuccessEnvelope struct {
	SchemaVersion string                  `json:"schema_version"`
	OK            bool                    `json:"ok"`
	RequestID     string                  `json:"request_id"`
	Data          runServiceBackupPayload `json:"data"`
}

// runServiceBackupHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and
// the given ServiceBackupRunner. It is the production request
// path: the POST /v1/services/{service_id}/backups/{backup_id}/run
// route is wrapped in RequireAuth for action backup.run.
func runServiceBackupHandlerFor(id auth.Identity, authErr error, runner ServiceBackupRunner) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, runner, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postRunServiceBackup issues POST
// /v1/services/{service_id}/backups/{backup_id}/run against handler
// with the given body and optional bearer token. The body is
// typically empty; backup.run is a fire-and-forget signal that
// carries no caller-supplied parameters.
func postRunServiceBackup(handler http.Handler, serviceID, backupID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/services/"+serviceID+"/backups/"+backupID+"/run", strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeRunServiceBackup(t *testing.T, rec *httptest.ResponseRecorder) runServiceBackupSuccessEnvelope {
	t.Helper()
	var env runServiceBackupSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// principalForRunBackup returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// backup.run is a CapDeploy action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0255's job).
func principalForRunBackup(principalID, organizationID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           domain.KindUser,
			OrganizationID: organizationID,
			Role:           policy.RoleDeveloper,
		},
		Method: auth.MethodSession,
	}
}

// TestRunServiceBackupHappyPath drives the production request path:
// an organization-wide Developer principal triggers a manual run on
// a backup-policy row owned by its home organization. The handler
// must forward the principal's home org id and the {service_id} /
// {backup_id} path parameters to the runner (never a
// caller-supplied org id), and must echo the persisted row through
// the canonical wire projection in a 202 envelope (status flipped
// to pending so the worker picks it up).
func TestRunServiceBackupHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)
	created := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	var gotIn store.RunServiceBackupInput
	callCount := 0
	runner := fakeServiceBackupRunner{
		backup: seedServiceBackupWire(
			bkpID, org, svcID, "nightly", "0 2 * * *", 14, true,
			store.ServiceBackupStatusPending, 3, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("runner call count = %d, want 1", callCount)
	}
	if gotIn.OrganizationID != org {
		t.Errorf("runner received organization id %q, want the principal's home org %q",
			gotIn.OrganizationID, org)
	}
	if gotIn.ServiceID != svcID {
		t.Errorf("runner received service id %q, want the {service_id} path parameter %q",
			gotIn.ServiceID, svcID)
	}
	if gotIn.BackupID != bkpID {
		t.Errorf("runner received backup id %q, want the {backup_id} path parameter %q",
			gotIn.BackupID, bkpID)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org {
		t.Errorf("runner received actor = (%q, org=%q), want (usr_dev, org=%s) — actor identity must be plumbed for the audit record",
			gotIn.ActorID, gotIn.ActorOrgID, org)
	}
	if gotIn.ActorKind != string(domain.KindUser) {
		t.Errorf("runner received actor kind %q, want %q", gotIn.ActorKind, domain.KindUser)
	}

	envelope := decodeRunServiceBackup(t, rec)
	b := envelope.Data.Backup
	if b.ID != bkpID {
		t.Errorf("backup.id = %q, want %q", b.ID, bkpID)
	}
	if b.ServiceID != svcID {
		t.Errorf("backup.service_id = %q, want %q", b.ServiceID, svcID)
	}
	if b.Status != store.ServiceBackupStatusPending {
		t.Errorf("backup.status = %q, want pending after a manual run flip", b.Status)
	}
	if b.Version != 3 {
		t.Errorf("backup.Version = %d, want the version returned by the runner", b.Version)
	}
}

// TestRunServiceBackupRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field. The
// telemetry.Correlate middleware generates a fresh request id when
// the request carries none, so the envelope's request_id must be
// non-empty regardless of whether the caller supplied an
// X-Request-Id header.
func TestRunServiceBackupRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)
	runner := fakeServiceBackupRunner{
		backup: seedServiceBackupWire(bkpID, org, svcID, "nightly", "0 2 * * *", 7, true,
			store.ServiceBackupStatusPending, 2, time.Now().UTC(), time.Now().UTC()),
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRunServiceBackup(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestRunServiceBackupEmptyBodyAccepted proves an empty body is
// accepted: backup.run is a fire-and-forget signal that carries no
// caller-supplied parameters. The handler must not require a
// Content-Type header or a JSON body.
func TestRunServiceBackupEmptyBodyAccepted(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)
	runner := fakeServiceBackupRunner{
		backup: seedServiceBackupWire(bkpID, org, svcID, "nightly", "0 2 * * *", 7, true,
			store.ServiceBackupStatusPending, 2, time.Now().UTC(), time.Now().UTC()),
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
}

// TestRunServiceBackupValidationFailure proves a validation error
// returned by the runner (for example, an id whose Kind prefix is
// invalid) surfaces as a typed 400 with code E_INVALID_INPUT and a
// stable yalla.error.v1 envelope. The handler must propagate it
// without echoing the submitted id.
func TestRunServiceBackupValidationFailure(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	callCount := 0
	runner := fakeServiceBackupRunner{
		err:       apierr.InvalidInput(apierr.FieldViolation{Field: "backup_id", Reason: "must be a valid id"}),
		callCount: &callCount,
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("runner call count = %d, want 1 (handler delegates validation to the orchestrator)",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestRunServiceBackupUnauthenticated proves a request with no
// bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The runner is set up
// with a callCount; it must remain untouched.
func TestRunServiceBackupUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	runner := fakeServiceBackupRunner{callCount: &callCount}

	handler := runServiceBackupHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), runner)

	rec := postRunServiceBackup(handler, "svc_api", "sbkp_nightly", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("runner call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestRunServiceBackupAuthorizationDenied proves a principal whose
// role does not admit action backup.run (a viewer carrying no
// scoped grant) is rejected at the policy gate with a typed 403
// BEFORE the runner is touched. The viewer's CapRead capability
// does not authorize a CapDeploy action.
func TestRunServiceBackupAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	callCount := 0
	runner := fakeServiceBackupRunner{callCount: &callCount}
	viewer := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: org,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := runServiceBackupHandlerFor(viewer, nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("runner call count = %d, want 0 (policy denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestRunServiceBackupNotFoundCrossTenant proves a cross-tenant or
// unknown service_id / backup_id reaches the persistence layer
// with the principal's home organization id and surfaces as a
// deterministic 404 — never disguised as a 200 or a 403 that would
// confirm the foreign id's existence. The runner receives the
// principal's home org id (never a caller-controlled value).
func TestRunServiceBackupNotFoundCrossTenant(t *testing.T) {
	t.Parallel()

	const (
		homeOrg = "org_acme"
		svcID   = "svc_owned_by_globex"
		bkpID   = "sbkp_owned_by_globex"
	)

	var gotIn store.RunServiceBackupInput
	callCount := 0
	runner := fakeServiceBackupRunner{
		err:       apierr.NotFound("service backup", bkpID),
		gotInput:  &gotIn,
		callCount: &callCount,
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", homeOrg), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("runner call count = %d, want 1 (handler must call runner; the store-layer enforces tenant isolation)",
			callCount)
	}
	if gotIn.OrganizationID != homeOrg {
		t.Errorf("runner received org id %q, want the principal's home org %q — handler must never trust caller-controlled org ids",
			gotIn.OrganizationID, homeOrg)
	}
	if gotIn.ServiceID != svcID || gotIn.BackupID != bkpID {
		t.Errorf("runner received (service=%q, backup=%q), want the path parameters (%q, %q)",
			gotIn.ServiceID, gotIn.BackupID, svcID, bkpID)
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestRunServiceBackupConflictDisabled proves a backup whose
// enabled flag is false rejected by the store layer surfaces as a
// typed 409 Conflict. A disabled policy cannot be manually run —
// the customer must PATCH the row to enabled=true first.
func TestRunServiceBackupConflictDisabled(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	runner := fakeServiceBackupRunner{err: apierr.Conflict("backup is disabled")}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeConflict))
}

// TestRunServiceBackupConflictAlreadyRunning proves a backup whose
// current status is 'running' rejected by the store layer surfaces
// as a typed 409 Conflict. A concurrent run would double-enqueue
// work the worker has already accepted.
func TestRunServiceBackupConflictAlreadyRunning(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	runner := fakeServiceBackupRunner{err: apierr.Conflict("backup is already running")}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeConflict))
}

// TestRunServiceBackupStoreUnavailable proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a validation
// or a 200 with no side effect.
func TestRunServiceBackupStoreUnavailable(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	runner := fakeServiceBackupRunner{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, runner)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}

// TestRunServiceBackupNilRunner proves a wiring error (no runner
// wired into NewHandler) surfaces as a typed Internal failure
// rather than a misleading 2xx with no side effect. The route
// still authorizes successfully — the typed-internal guard runs
// inside the handler after RequireAuth admits the request.
func TestRunServiceBackupNilRunner(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)

	// Drive NewHandler with a literal nil ServiceBackupRunner to
	// reach the typed-internal guard.
	a := fakeAuthenticator{identity: principalForRunBackup("usr_dev", org), err: nil}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, nil, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := postRunServiceBackup(handler, svcID, bkpID, "", "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}
