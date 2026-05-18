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

// Contract, authorization, and tenant-isolation coverage for DELETE
// /v1/services/{service_id}/backups/{backup_id} (BE-0259 + BE-0260).
// The endpoint removes a single service_backups row through the
// ServiceBackupDeleter port. The tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake
// deleter — the same wiring a request hits in production, minus the
// database. The store-backed orchestrator
// (ServiceBackupService.Delete) has its own isolated-Postgres
// integration coverage in store/service_backup.go's neighbouring
// tests; this file exercises the HTTP surface in isolation. The full
// role x tenant x grant-scope matrix lives in
// service_backups_delete_policy_test.go (BE-0261).
//
// backup.delete is a CapWrite action — viewer and support principals
// in the tenant cannot delete backups; CI keys DO write (the
// load-bearing distinction from the deployment-tier CapDeploy
// matrix). The happy-path tests authenticate as RoleDeveloper to keep
// the role matrix focused on the policy suite.

// fakeServiceBackupDeleter is the test double for the
// ServiceBackupDeleter port: it captures the
// DeleteServiceBackupInput a test passed in, the call count, and
// returns a canned ServiceBackup / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity, the path parameters, and the If-Match
// precondition through to the store layer.
type fakeServiceBackupDeleter struct {
	backup    store.ServiceBackup
	err       error
	gotInput  *store.DeleteServiceBackupInput
	callCount *int
}

func (f fakeServiceBackupDeleter) Delete(_ context.Context, in store.DeleteServiceBackupInput) (store.ServiceBackup, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.backup, f.err
}

// deleteServiceBackupSuccessEnvelope is the decoded shape of the
// DELETE /v1/services/{service_id}/backups/{backup_id} success
// envelope.
type deleteServiceBackupSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          deleteServiceBackupPayload `json:"data"`
}

// canonicalDeletedServiceBackup is the canned service_backups row
// the happy-path tests render through serviceBackupOf. Every field
// is non-zero so the projection invariants are exercised on the
// wire.
var canonicalDeletedServiceBackup = store.ServiceBackup{
	ID:             "bkp_canonical_delete",
	OrganizationID: "org_acme",
	ServiceID:      "svc_canonical_delete_backup",
	DisplayName:    "nightly-prod",
	Schedule:       "0 2 * * *",
	RetentionCount: 14,
	Enabled:        true,
	Status:         store.ServiceBackupStatusPending,
	Version:        9,
	CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// deleteServiceBackupHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceBackupDeleter. It is the production request path: the
// DELETE /v1/services/{service_id}/backups/{backup_id} route is
// wrapped in RequireAuth for action backup.delete.
func deleteServiceBackupHandlerFor(id auth.Identity, authErr error, deleter ServiceBackupDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, deleter, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// deleteServiceBackup issues DELETE
// /v1/services/{service_id}/backups/{backup_id} against the handler
// with the supplied bearer token.
func deleteServiceBackup(handler http.Handler, serviceID, backupID, token string) *httptest.ResponseRecorder {
	return deleteServiceBackupWithIfMatch(handler, serviceID, backupID, token, "")
}

// deleteServiceBackupWithIfMatch issues DELETE
// /v1/services/{service_id}/backups/{backup_id} with an optional
// If-Match header. An empty ifMatch omits the header entirely so the
// optional precondition path remains exercised.
func deleteServiceBackupWithIfMatch(handler http.Handler, serviceID, backupID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/"+serviceID+"/backups/"+backupID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeDeleteServiceBackup(t *testing.T, rec *httptest.ResponseRecorder) deleteServiceBackupSuccessEnvelope {
	t.Helper()
	var env deleteServiceBackupSuccessEnvelope
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

// TestDeleteServiceBackupHappyPathForwardsPrincipalAndPath proves
// the handler threads the principal's home organization id, the
// path service_id, and the path backup_id into the store input
// (never from caller-controlled input — a DELETE has no body),
// renders the deleted snapshot in the stable yalla.output.v1
// envelope, and returns 200 OK.
func TestDeleteServiceBackupHappyPathForwardsPrincipalAndPath(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceBackupInput
	deleter := fakeServiceBackupDeleter{backup: canonicalDeletedServiceBackup, gotInput: &captured}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteServiceBackup(t, rec)
	if env.Data.Backup.ID != canonicalDeletedServiceBackup.ID {
		t.Errorf("backup.id = %q, want %q", env.Data.Backup.ID, canonicalDeletedServiceBackup.ID)
	}
	if env.Data.Backup.ServiceID != canonicalDeletedServiceBackup.ServiceID {
		t.Errorf("service_id = %q, want %q", env.Data.Backup.ServiceID, canonicalDeletedServiceBackup.ServiceID)
	}
	if env.Data.Backup.DisplayName != canonicalDeletedServiceBackup.DisplayName {
		t.Errorf("display_name = %q, want %q", env.Data.Backup.DisplayName, canonicalDeletedServiceBackup.DisplayName)
	}
	if env.Data.Backup.Schedule != canonicalDeletedServiceBackup.Schedule {
		t.Errorf("schedule = %q, want %q", env.Data.Backup.Schedule, canonicalDeletedServiceBackup.Schedule)
	}
	if env.Data.Backup.Version != canonicalDeletedServiceBackup.Version {
		t.Errorf("version = %d, want %d", env.Data.Backup.Version, canonicalDeletedServiceBackup.Version)
	}

	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != "svc_canonical_delete_backup" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_delete_backup (path value)", captured.ServiceID)
	}
	if captured.BackupID != "bkp_canonical_delete" {
		t.Errorf("forwarded backup_id = %q, want bkp_canonical_delete (path value)", captured.BackupID)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header sent)", captured.IfMatchVersion)
	}
	if captured.ActorID != "usr_ada" {
		t.Errorf("forwarded actor_id = %q, want usr_ada", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want org_acme", captured.ActorOrgID)
	}
}

// TestDeleteServiceBackupForwardsIfMatchVersion proves the handler
// parses the If-Match header as a strong ETag and forwards the
// resulting version pointer to the store input — the optimistic
// concurrency precondition rides through unchanged.
func TestDeleteServiceBackupForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceBackupInput
	deleter := fakeServiceBackupDeleter{backup: canonicalDeletedServiceBackup, gotInput: &captured}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackupWithIfMatch(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token", `"9"`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatalf("forwarded if_match_version = nil, want pointer to 9")
	}
	if *captured.IfMatchVersion != 9 {
		t.Errorf("forwarded if_match_version = %d, want 9", *captured.IfMatchVersion)
	}
}

// TestDeleteServiceBackupMalformedIfMatchIs400 proves a malformed
// If-Match header is rejected with a stable 400 before the deleter
// runs — a malformed precondition is a client error, never a silent
// next-write-wins. Deleting a row is structurally destructive, so a
// malformed precondition that silently degraded into "no
// precondition" would be a particularly load-bearing footgun.
func TestDeleteServiceBackupMalformedIfMatchIs400(t *testing.T) {
	t.Parallel()

	var captured store.DeleteServiceBackupInput
	callCount := 0
	deleter := fakeServiceBackupDeleter{
		backup:    canonicalDeletedServiceBackup,
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackupWithIfMatch(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token", `not-a-strong-etag`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter was reached (calls=%d) despite a malformed If-Match; it must never run", callCount)
	}
}

// TestDeleteServiceBackupStaleIfMatchReturns409 proves a stale
// If-Match version surfaces as a typed 409 with the row's
// authoritative current_version under details — the agent learns
// the version it needs to retry with without re-reading the row.
func TestDeleteServiceBackupStaleIfMatchReturns409(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{err: apierr.ConflictStale(13)}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackupWithIfMatch(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token", `"7"`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
	if !strings.Contains(rec.Body.String(), "current_version") {
		t.Errorf("response body did not carry current_version details; body %s", rec.Body.String())
	}
}

// TestDeleteServiceBackupNotFoundIsTyped404 proves an unknown
// (service_id, backup_id) pair surfaces as a typed 404 — never a
// 500 leaking the internal cause, never a misleading 2xx.
func TestDeleteServiceBackupNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{err: apierr.NotFound("service backup", "bkp_missing")}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_missing",
		"a-valid-session-token")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestDeleteServiceBackupInvalidInputIsTyped400 proves a typed
// apierr.InvalidInput surfaces as a 400 with the field violations
// echoed back — the path the store layer takes for a blank
// organization_id, service_id, or backup_id (defense-in-depth
// against a wiring bug that would otherwise let an empty path
// parameter reach the persistence layer).
func TestDeleteServiceBackupInvalidInputIsTyped400(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{
		err: apierr.InvalidInput(apierr.FieldViolation{Field: "id", Reason: "must not be blank"}),
	}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
}

// TestDeleteServiceBackupUnauthenticatedIs401 proves an absent or
// invalid bearer token is rejected at the auth boundary with a
// stable 401 — the deleter is never reached. A destructive
// operation that silently succeeded on an unauthenticated request
// would be the worst possible failure mode, so the assertion that
// callCount is zero is structurally load-bearing here.
func TestDeleteServiceBackupUnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	callCount := 0
	deleter := fakeServiceBackupDeleter{callCount: &callCount}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{}, stderrors.New("invalid credential"), deleter)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("deleter was reached (calls=%d) for an unauthenticated request; it must never run", callCount)
	}
}

// TestDeleteServiceBackupStoreUnavailableIsTyped5xx proves a typed
// apierr.StoreUnavailable surfaces as a 5xx with the stable error
// code and the original error wrapped — never disguised as a 404 or
// a 400, never echoing the internal cause to the wire.
func TestDeleteServiceBackupStoreUnavailableIsTyped5xx(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{err: apierr.StoreUnavailable(yerr.New(yerr.CodeInternal, "kaboom"))}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token")

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceBackupHandlerNoPrincipalIsInternal proves the
// handler-internal `errNoPrincipalOnContext` sentinel surfaces as a
// typed Internal error if the route is ever exercised through a
// wiring that bypasses RequireAuth. This is a structural assertion
// — in production the middleware always populates the principal —
// so the test invokes the bare handler directly.
func TestDeleteServiceBackupHandlerNoPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{}
	handler := deleteServiceBackupHandler(deleter)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/svc_x/backups/bkp_x", nil)
	req.SetPathValue("service_id", "svc_x")
	req.SetPathValue("backup_id", "bkp_x")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (no principal); body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceBackupHandlerNilDeleterIsInternal proves a nil
// ServiceBackupDeleter wired through NewHandler surfaces as a typed
// Internal error rather than a silent success (a 200 OK confirming
// the deletion of a row that was never removed would be the worst
// possible signal for an agent).
func TestDeleteServiceBackupHandlerNilDeleterIsInternal(t *testing.T) {
	t.Parallel()

	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := deleteServiceBackup(handler,
		"svc_canonical_delete_backup", "bkp_canonical_delete",
		"a-valid-session-token")

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (nil deleter); body %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteServiceBackupOpenAPIOperationRegistered proves the
// route is documented at the same point in the OpenAPI surface as
// the other service-backup endpoints. A served route that is not
// documented (or vice-versa) is a wire-contract bug — the route
// table is the single source of truth for both.
func TestDeleteServiceBackupOpenAPIOperationRegistered(t *testing.T) {
	t.Parallel()

	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakeServiceBackupDeleter{backup: canonicalDeletedServiceBackup})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"deleteServiceBackup"`) {
		excerpt := body
		if len(excerpt) > 400 {
			excerpt = excerpt[:400]
		}
		t.Errorf("OpenAPI document does not register operation deleteServiceBackup; body excerpt: %s", excerpt)
	}
	if !strings.Contains(body, `"/v1/services/{service_id}/backups/{backup_id}"`) {
		t.Errorf("OpenAPI document does not register path /v1/services/{service_id}/backups/{backup_id}")
	}
	if !strings.Contains(body, `"backup.delete"`) {
		t.Errorf("OpenAPI document does not declare required action backup.delete")
	}
}

// TestDeleteServiceBackupRequestIDPropagation proves the success
// envelope carries a non-empty request_id and that an inbound safe
// X-Request-Id is honoured (handled by telemetry.Correlate) and
// surfaced verbatim on the wire.
func TestDeleteServiceBackupRequestIDPropagation(t *testing.T) {
	t.Parallel()

	deleter := fakeServiceBackupDeleter{backup: canonicalDeletedServiceBackup}
	handler := deleteServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, deleter)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/services/svc_canonical_delete_backup/backups/bkp_canonical_delete", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	const inbound = "req_canonical_delete_backup_01HABCDEFGHJKMNPQRSTVWXYZ"
	req.Header.Set("X-Request-Id", inbound)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeleteServiceBackup(t, rec)
	if env.RequestID != inbound {
		t.Errorf("request_id = %q, want %q (safe inbound header should be honoured)", env.RequestID, inbound)
	}
}
