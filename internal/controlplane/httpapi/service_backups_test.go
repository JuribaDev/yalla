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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract and tenant-isolation coverage for GET
// /v1/services/{service_id}/backups (BE-0247 + BE-0248). The endpoint
// returns the backup-policy rows bound to the service named by the
// {service_id} path parameter through the ServiceBackupReader port.
// The tests drive it through NewHandler with a fake Authenticator,
// the real policy engine, and a fake reader — the same wiring a
// request hits in production, minus the database. The full role x
// tenant x grant-scope policy matrix lives in
// service_backups_policy_test.go (BE-0249).
//
// backup.read is a CapRead action: every built-in role holds CapRead,
// so the happy-path tests authenticate as RoleOwner and the deny
// paths matrix-cover the other failure modes (unauthenticated, store
// outage, missing wiring). The role matrix is exhaustively covered
// in the policy test file.

// fakeServiceBackupReader is a canned ServiceBackupReader for
// httpapi-layer tests. The zero value returns an empty ServiceBackups
// and no error, which is all the test helpers that never reach the
// handler need; the backup tests set backups/err and read got back to
// prove the handler forwards the principal's home organization and
// the path service id to the store layer unchanged.
type fakeServiceBackupReader struct {
	backups store.ServiceBackups
	err     error
	got     *store.ListServiceBackupsInput
}

func (f fakeServiceBackupReader) ListBackups(_ context.Context, in store.ListServiceBackupsInput) (store.ServiceBackups, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.backups, f.err
}

// listServiceBackupsSuccessEnvelope is the typed shape of the
// success envelope the assertions decode into. It is a test-only
// projection of apienvelope.Envelope; the production code never
// types the data block, so the wire schema lives in
// listServiceBackupsPayload (in service_backups.go) and the test
// shape mirrors it.
type listServiceBackupsSuccessEnvelope struct {
	SchemaVersion string                 `json:"schema_version"`
	OK            bool                   `json:"ok"`
	Data          listServiceBackupsData `json:"data"`
	RequestID     string                 `json:"request_id"`
}

type listServiceBackupsData struct {
	ServiceID string                 `json:"service_id"`
	Backups   []serviceBackupTestRow `json:"backups"`
}

type serviceBackupTestRow struct {
	ID              string `json:"id"`
	ServiceID       string `json:"service_id"`
	DisplayName     string `json:"display_name"`
	Schedule        string `json:"schedule"`
	RetentionCount  int    `json:"retention_count"`
	Enabled         bool   `json:"enabled"`
	Status          string `json:"status"`
	LastRunAt       string `json:"last_run_at"`
	LastSucceededAt string `json:"last_succeeded_at"`
	Version         int64  `json:"version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// listServiceBackupsHandlerFor wires NewHandler with a fake
// authenticator and the supplied reader. It is the canonical
// test-side constructor for the GET /v1/services/{service_id}/backups
// handler.
func listServiceBackupsHandlerFor(id auth.Identity, authErr error, reader ServiceBackupReader) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, reader, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// listServiceBackups issues GET /v1/services/{service_id}/backups
// against handler. An empty token omits the Authorization header so
// the unauthenticated path is exercised.
func listServiceBackups(handler http.Handler, serviceID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/services/"+serviceID+"/backups", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListServiceBackups(t *testing.T, rec *httptest.ResponseRecorder) listServiceBackupsSuccessEnvelope {
	t.Helper()
	var env listServiceBackupsSuccessEnvelope
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
		t.Error("request_id is empty")
	}
	return env
}

// canonicalServiceBackups is the canned ServiceBackups the
// happy-path tests render. The display_name strings, schedule
// strings, and status values are deliberately distinctive so
// deny-path leak guards can needle for them.
func canonicalServiceBackups() store.ServiceBackups {
	t1 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 16, 13, 0, 0, 0, time.UTC)
	return store.ServiceBackups{
		ServiceID: "svc_canonical_backups",
		Backups: []store.ServiceBackup{
			{
				ID:              "sbkp_alpha",
				OrganizationID:  "org_acme",
				ServiceID:       "svc_canonical_backups",
				DisplayName:     "nightly",
				Schedule:        "0 2 * * *",
				RetentionCount:  7,
				Enabled:         true,
				Status:          store.ServiceBackupStatusSucceeded,
				LastRunAt:       &t2,
				LastSucceededAt: &t2,
				Version:         2,
				CreatedAt:       t1,
				UpdatedAt:       t2,
			},
			{
				ID:              "sbkp_beta",
				OrganizationID:  "org_acme",
				ServiceID:       "svc_canonical_backups",
				DisplayName:     "weekly",
				Schedule:        "0 3 * * 0",
				RetentionCount:  30,
				Enabled:         false,
				Status:          store.ServiceBackupStatusDisabled,
				LastRunAt:       nil,
				LastSucceededAt: nil,
				Version:         1,
				CreatedAt:       t1,
				UpdatedAt:       t1,
			},
		},
	}
}

// TestListServiceBackupsSuccess proves the happy path renders 200
// OK, uses the yalla.output.v1 envelope, projects the canned backup
// rows in deterministic order, forwards the principal's home
// organization id and the path service_id to the ServiceBackupReader
// port, and echoes the service id in the response.
func TestListServiceBackupsSuccess(t *testing.T) {
	t.Parallel()

	backups := canonicalServiceBackups()
	var captured store.ListServiceBackupsInput
	reader := fakeServiceBackupReader{backups: backups, got: &captured}
	handler := listServiceBackupsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceBackups(handler, backups.ServiceID, "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeListServiceBackups(t, rec)
	if env.Data.ServiceID != backups.ServiceID {
		t.Errorf("data.service_id = %q, want %q", env.Data.ServiceID, backups.ServiceID)
	}
	if len(env.Data.Backups) != len(backups.Backups) {
		t.Fatalf("backups len = %d, want %d", len(env.Data.Backups), len(backups.Backups))
	}
	first := env.Data.Backups[0]
	if first.ID != "sbkp_alpha" || first.DisplayName != "nightly" || first.Schedule != "0 2 * * *" ||
		first.RetentionCount != 7 || !first.Enabled || first.Status != "succeeded" ||
		first.LastRunAt == "" || first.LastSucceededAt == "" {
		t.Errorf("backups[0] = %+v, mismatched projection", first)
	}
	second := env.Data.Backups[1]
	if second.ID != "sbkp_beta" || second.DisplayName != "weekly" || second.Enabled ||
		second.Status != "disabled" || second.LastRunAt != "" || second.LastSucceededAt != "" {
		t.Errorf("backups[1] = %+v, mismatched projection", second)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want %q (principal home)", captured.OrganizationID, "org_acme")
	}
	if captured.ServiceID != backups.ServiceID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, backups.ServiceID)
	}
}

// TestListServiceBackupsEmptyBackupsAreSliceNotNull proves the wire
// shape renders an empty Backups slice as "backups": [] rather than
// "backups": null, so an agent does not need to special-case the
// absent-vs-empty distinction.
func TestListServiceBackupsEmptyBackupsAreSliceNotNull(t *testing.T) {
	t.Parallel()

	reader := fakeServiceBackupReader{backups: store.ServiceBackups{ServiceID: "svc_empty_backups", Backups: nil}}
	handler := listServiceBackupsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceBackups(handler, "svc_empty_backups", "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"backups":[]`) {
		t.Errorf("response body %s does not contain \"backups\":[]; an empty list must marshal as [] not null", rec.Body.String())
	}
}

// TestListServiceBackupsUnauthenticated proves a missing bearer
// token is rejected by RequireAuth before the reader runs.
func TestListServiceBackupsUnauthenticated(t *testing.T) {
	t.Parallel()

	reader := fakeServiceBackupReader{
		backups: canonicalServiceBackups(),
		err:     stderrors.New("reader must not be called"),
	}
	handler := listServiceBackupsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)

	rec := listServiceBackups(handler, "svc_acme_api", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestListServiceBackupsNotFound proves the typed store-layer
// NotFound — the disposition for a cross-tenant or unknown
// service_id — is rendered as a 404, never as a silent empty success
// that would mask a tenant-isolation failure.
func TestListServiceBackupsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeServiceBackupReader{err: apierr.NotFound("service", "svc_missing")}
	handler := listServiceBackupsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceBackups(handler, "svc_missing", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestListServiceBackupsStoreUnavailable proves a typed
// store-unavailable error is rendered as a 503 — the datastore
// outage surfaces as the typed 503, never disguised as a 500 leaking
// the pgx cause.
func TestListServiceBackupsStoreUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceBackupReader{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := listServiceBackupsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceBackups(handler, "svc_acme_api", "valid-key")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListServiceBackupsCrossTenantNoForeignEcho proves the handler
// never trusts the path service_id to override the principal's home
// organization id: a cross-tenant service_id is reported as 404 (the
// store's tenant-scoped existence check) — never disguised as a 200
// with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's
// home org, not the foreign tenant.
func TestListServiceBackupsCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns_backups"
		victimOrg   = "org_victim"
	)
	var captured store.ListServiceBackupsInput
	reader := fakeServiceBackupReader{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}
	handler := listServiceBackupsHandlerFor(ownerIdentity(attackerOrg, "usr_attacker"), nil, reader)

	rec := listServiceBackups(handler, victimSvc, "valid-key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if captured.OrganizationID != attackerOrg {
		t.Errorf("reader received org id %q, want the attacker's home org %q (path service_id must never override)",
			captured.OrganizationID, attackerOrg)
	}
	if body := rec.Body.String(); strings.Contains(body, victimOrg) {
		t.Errorf("response body %s echoed the cross-tenant organization id", body)
	}
}

// TestListServiceBackupsMissingReader proves a wiring error (nil
// reader reaching the handler) is reported as a typed internal error
// rather than a misleading empty success. The wiring goes through
// NewHandler so the request reaches the typed-internal guard inside
// listServiceBackupsHandler.
func TestListServiceBackupsMissingReader(t *testing.T) {
	t.Parallel()

	var nilReader ServiceBackupReader
	handler := listServiceBackupsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nilReader)

	rec := listServiceBackups(handler, "svc_acme_api", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestListServiceBackupsOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/services/{service_id}/backups
// operation with the stable operationId, the backup.read required
// action, the services tag, and 200 OK success status — every detail
// an agent reads to discover the endpoint.
func TestListServiceBackupsOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/backups" {
			found = true
			if rt.endpoint.OperationID != "listServiceBackups" {
				t.Errorf("operation_id = %q, want listServiceBackups", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionBackupRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, string(policy.ActionBackupRead))
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			break
		}
	}
	if !found {
		t.Fatalf("GET /v1/services/{service_id}/backups not found in route table")
	}
}
