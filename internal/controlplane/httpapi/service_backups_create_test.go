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
// /v1/services/{service_id}/backups (BE-0250 + BE-0251). The endpoint
// creates a backup-policy row bound to the service named by the
// {service_id} path parameter through the ServiceBackupCreator port.
// The tests drive it through NewHandler with a fake Authenticator,
// the real policy engine, and a fake creator — the same wiring a
// request hits in production, minus the database. The store-backed
// creator (ServiceBackupService.Create) has its own isolated-Postgres
// integration coverage in store/service_backup_test.go; this file
// exercises the HTTP surface in isolation. The full role x tenant x
// grant-scope matrix lives in service_backups_create_policy_test.go
// (BE-0252).
//
// backup.create is a CapWrite action: viewer and support principals
// in the tenant cannot create backups (the CI key DOES write — the
// load-bearing distinction from service.read). The happy-path tests
// authenticate as RoleDeveloper to keep the role matrix focused on
// the policy suite.
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON
// contract). Field-level validation of the backup id, display_name,
// schedule, and retention bounds is the store-layer's job and is
// asserted through the creator error path here, not by re-validating
// in the handler.

// fakeServiceBackupCreator is the test double for the
// ServiceBackupCreator port: it captures the
// CreateServiceBackupInput a test passed in, the call count, and
// returns a canned ServiceBackup / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity to the audit record.
type fakeServiceBackupCreator struct {
	backup    store.ServiceBackup
	err       error
	gotInput  *store.CreateServiceBackupInput
	callCount *int
}

func (f fakeServiceBackupCreator) Create(_ context.Context, in store.CreateServiceBackupInput) (store.ServiceBackup, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.backup, f.err
}

// createServiceBackupSuccessEnvelope is the decoded shape of the POST
// /v1/services/{service_id}/backups success envelope.
type createServiceBackupSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          createServiceBackupPayload `json:"data"`
}

// seedServiceBackupWire is the helper every contract / policy test
// uses to seed a canonical ServiceBackup for the fake creator to
// return. The timestamps and structural ids are deterministic so leak
// guards can needle for them and assertions can compare verbatim.
func seedServiceBackupWire(id, orgID, serviceID, displayName, schedule string, retentionCount int, enabled bool, status string, version int64, created, updated time.Time) store.ServiceBackup {
	return store.ServiceBackup{
		ID:             id,
		OrganizationID: orgID,
		ServiceID:      serviceID,
		DisplayName:    displayName,
		Schedule:       schedule,
		RetentionCount: retentionCount,
		Enabled:        enabled,
		Status:         status,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// createServiceBackupHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceBackupCreator. It is the production request path: the
// POST /v1/services/{service_id}/backups route is wrapped in
// RequireAuth for action backup.create.
func createServiceBackupHandlerFor(id auth.Identity, authErr error, creator ServiceBackupCreator) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, creator, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postServiceBackup issues POST /v1/services/{service_id}/backups
// against handler with the given body and optional bearer token.
func postServiceBackup(handler http.Handler, serviceID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/services/"+serviceID+"/backups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateServiceBackup(t *testing.T, rec *httptest.ResponseRecorder) createServiceBackupSuccessEnvelope {
	t.Helper()
	var env createServiceBackupSuccessEnvelope
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

// principalForCreateBackup returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// backup.create is a CapWrite action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0252's job).
func principalForCreateBackup(principalID, organizationID string) auth.Identity {
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

// TestCreateServiceBackupHappyPath drives the production request
// path: an organization-wide Developer principal creates a backup
// policy against a service owned by its home organization. The
// handler must forward the principal's home org id and the
// {service_id} path parameter to the creator (never a caller-
// supplied org id from the body), and must echo the persisted row
// through the canonical wire projection in a 201 envelope.
func TestCreateServiceBackupHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_abc123"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	updated := created

	var gotIn store.CreateServiceBackupInput
	callCount := 0
	creator := fakeServiceBackupCreator{
		backup: seedServiceBackupWire(
			bkpID, org, svcID, "nightly", "0 2 * * *", 14, true,
			store.ServiceBackupStatusPending, 1, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_abc123","display_name":"nightly","schedule":"0 2 * * *","retention_count":14,"enabled":true}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1", callCount)
	}
	if gotIn.OrganizationID != org {
		t.Errorf("creator received organization id %q, want the principal's home org %q",
			gotIn.OrganizationID, org)
	}
	if gotIn.ServiceID != svcID {
		t.Errorf("creator received service id %q, want the path parameter %q",
			gotIn.ServiceID, svcID)
	}
	if gotIn.BackupID != bkpID || gotIn.DisplayName != "nightly" || gotIn.Schedule != "0 2 * * *" || gotIn.RetentionCount != 14 || !gotIn.Enabled {
		t.Errorf("creator received intent = (id=%q, name=%q, sched=%q, retention=%d, enabled=%v), want (sbkp_abc123, nightly, 0 2 * * *, 14, true)",
			gotIn.BackupID, gotIn.DisplayName, gotIn.Schedule, gotIn.RetentionCount, gotIn.Enabled)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org {
		t.Errorf("creator received actor = (%q, org=%q), want (usr_dev, org=%s) — actor identity must be plumbed for the audit record",
			gotIn.ActorID, gotIn.ActorOrgID, org)
	}

	envelope := decodeCreateServiceBackup(t, rec)
	b := envelope.Data.Backup
	if b.ID != bkpID {
		t.Errorf("backup.id = %q, want %q", b.ID, bkpID)
	}
	if b.ServiceID != svcID {
		t.Errorf("backup.service_id = %q, want %q", b.ServiceID, svcID)
	}
	if b.DisplayName != "nightly" || b.Schedule != "0 2 * * *" || b.RetentionCount != 14 || !b.Enabled || b.Status != store.ServiceBackupStatusPending {
		t.Errorf("backup wire = (name=%q, sched=%q, retention=%d, enabled=%v, status=%q), want (nightly, 0 2 * * *, 14, true, pending)",
			b.DisplayName, b.Schedule, b.RetentionCount, b.Enabled, b.Status)
	}
	if b.Version != 1 {
		t.Errorf("backup.Version = %d, want 1", b.Version)
	}
	if b.LastRunAt != "" || b.LastSucceededAt != "" {
		t.Errorf("last_run_at/last_succeeded_at = (%q, %q), want empty on a fresh row", b.LastRunAt, b.LastSucceededAt)
	}
}

// TestCreateServiceBackupDefaultEnabledTrue proves an omitted
// `enabled` field defaults to true at the handler seam. The store
// layer receives Enabled=true and never sees an absent-vs-explicit
// distinction because the boolean is collapsed at the HTTP boundary.
func TestCreateServiceBackupDefaultEnabledTrue(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	var gotIn store.CreateServiceBackupInput
	creator := fakeServiceBackupCreator{
		backup: seedServiceBackupWire("sbkp_def", org, svcID, "nightly", "0 2 * * *", 7, true,
			store.ServiceBackupStatusPending, 1, time.Now().UTC(), time.Now().UTC()),
		gotInput: &gotIn,
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	// `enabled` is intentionally omitted.
	body := `{"id":"sbkp_def","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if !gotIn.Enabled {
		t.Errorf("Enabled defaulted to false; want true when the field is omitted")
	}
}

// TestCreateServiceBackupExplicitEnabledFalse proves an explicit
// `"enabled":false` rides through to the creator unchanged — the
// pointer-shaped wire field preserves the absent-vs-explicit
// distinction at the seam.
func TestCreateServiceBackupExplicitEnabledFalse(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	var gotIn store.CreateServiceBackupInput
	creator := fakeServiceBackupCreator{
		backup: seedServiceBackupWire("sbkp_off", org, svcID, "weekly", "0 0 * * 0", 4, false,
			store.ServiceBackupStatusPending, 1, time.Now().UTC(), time.Now().UTC()),
		gotInput: &gotIn,
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_off","display_name":"weekly","schedule":"0 0 * * 0","retention_count":4,"enabled":false}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if gotIn.Enabled {
		t.Errorf("Enabled = true; want false for an explicit false body")
	}
}

// TestCreateServiceBackupRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field. The
// telemetry.Correlate middleware generates a fresh request id when
// the request carries none, so the envelope's request_id must be
// non-empty regardless of whether the caller supplied an
// X-Request-Id header.
func TestCreateServiceBackupRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	creator := fakeServiceBackupCreator{
		backup: seedServiceBackupWire("sbkp_xyz", org, svcID, "nightly", "0 2 * * *", 7, true,
			store.ServiceBackupStatusPending, 1, time.Now().UTC(), time.Now().UTC()),
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7,"enabled":true}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateServiceBackup(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestCreateServiceBackupValidationFailure proves a malformed
// schedule value surfaces as a typed 400 with code E_VALIDATION
// and a stable yalla.error.v1 envelope. The fake creator returns the
// store-layer's validation error so the test verifies the handler
// propagates it as the correct envelope without touching the
// orchestrator semantics.
func TestCreateServiceBackupValidationFailure(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceBackupCreator{
		err:       apierr.InvalidInput(apierr.FieldViolation{Field: "schedule", Reason: "must not be blank"}),
		callCount: &callCount,
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 (the handler delegates validation to the orchestrator)",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeValidation))
}

// TestCreateServiceBackupMalformedJSON proves an unknown-field body
// is rejected by the strict decoder before the creator is touched.
// The endpoint never echoes the caller's input back in the error
// envelope.
func TestCreateServiceBackupMalformedJSON(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceBackupCreator{callCount: &callCount}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_xyz","unknown_field":"x"}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (strict JSON decoder); body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 — strict-decode failures must precede the creator",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeValidation))
}

// TestCreateServiceBackupUnauthenticated proves a request with no
// bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The creator is set up
// with a callCount; it must remain untouched.
func TestCreateServiceBackupUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	creator := fakeServiceBackupCreator{callCount: &callCount}

	handler := createServiceBackupHandlerFor(
		auth.Identity{}, apierr.AuthenticationRequired(), creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, "svc_api", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuthenticationRequired))
}

// TestCreateServiceBackupAuthorizationDenied proves a principal
// whose role does not admit action backup.create (a viewer carrying
// no scoped grant) is rejected at the policy gate with a typed 403
// BEFORE the creator is touched. The viewer's CapRead capability
// does not authorize a CapWrite action.
func TestCreateServiceBackupAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceBackupCreator{callCount: &callCount}
	viewer := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: org,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := createServiceBackupHandlerFor(viewer, nil, creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (policy denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestCreateServiceBackupNotFoundCrossTenant proves a cross-tenant
// or unknown service_id reaches the persistence layer with the
// principal's home organization id and surfaces as a deterministic
// 404 — never disguised as a 200 or a 403 that would confirm the
// foreign service's existence. The creator receives the principal's
// home org id (never a caller-controlled value).
func TestCreateServiceBackupNotFoundCrossTenant(t *testing.T) {
	t.Parallel()

	const (
		homeOrg = "org_acme"
		svcID   = "svc_owned_by_globex"
	)

	var gotIn store.CreateServiceBackupInput
	callCount := 0
	creator := fakeServiceBackupCreator{
		err:       apierr.NotFound("service", svcID),
		gotInput:  &gotIn,
		callCount: &callCount,
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", homeOrg), nil, creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 (handler must call creator; the store-layer enforces tenant isolation)",
			callCount)
	}
	if gotIn.OrganizationID != homeOrg {
		t.Errorf("creator received org id %q, want the principal's home org %q — handler must never trust caller-controlled org ids",
			gotIn.OrganizationID, homeOrg)
	}
	if gotIn.ServiceID != svcID {
		t.Errorf("creator received service id %q, want the path parameter %q",
			gotIn.ServiceID, svcID)
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestCreateServiceBackupConflictDuplicateID proves a duplicate
// backup id (the table's PRIMARY KEY) rejected by the store layer
// surfaces as a typed 409 Conflict — never disguised as a 5xx or a
// 200 with no side effect.
func TestCreateServiceBackupConflictDuplicateID(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeServiceBackupCreator{
		err: apierr.Conflict("a service backup with this id already exists"),
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_dup","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeConflict))
}

// TestCreateServiceBackupStoreUnavailable proves a datastore outage
// surfaces as its own typed 5xx, never disguised as a validation or
// a 200 with no side effect.
func TestCreateServiceBackupStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeServiceBackupCreator{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}
	handler := createServiceBackupHandlerFor(
		principalForCreateBackup("usr_dev", org), nil, creator)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}

// TestCreateServiceBackupNilCreator proves a wiring error (no
// creator wired into NewHandler) surfaces as a typed Internal
// failure rather than a misleading 2xx with no side effect. The
// route still authorizes successfully — the typed-internal guard
// runs inside the handler after RequireAuth admits the request.
func TestCreateServiceBackupNilCreator(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	// Drive NewHandler with a literal nil ServiceBackupCreator to
	// reach the typed-internal guard.
	a := fakeAuthenticator{identity: principalForCreateBackup("usr_dev", org), err: nil}
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, nil, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	body := `{"id":"sbkp_xyz","display_name":"nightly","schedule":"0 2 * * *","retention_count":7}`
	rec := postServiceBackup(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}
