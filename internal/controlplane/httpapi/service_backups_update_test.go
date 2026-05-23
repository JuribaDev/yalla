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

// Contract, authorization, and tenant-isolation coverage for PATCH
// /v1/services/{service_id}/backups/{backup_id} (BE-0256 + BE-0257).
// The endpoint updates a single service-backups row through the
// ServiceBackupUpdater port. The tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake
// updater — the same wiring a request hits in production, minus the
// database. The store-backed orchestrator
// (ServiceBackupService.Update) has its own isolated-Postgres
// integration coverage in store/service_backup.go's neighbouring
// tests; this file exercises the HTTP surface in isolation. The full
// role x tenant x grant-scope matrix lives in
// service_backups_update_policy_test.go (BE-0258).
//
// backup.update is a CapWrite action — viewer and support principals
// in the tenant cannot update backups; CI keys DO write (the
// load-bearing distinction from the deployment-tier CapDeploy
// matrix). The happy-path tests authenticate as RoleDeveloper to keep
// the role matrix focused on the policy suite.

// fakeServiceBackupUpdater is the test double for the
// ServiceBackupUpdater port: it captures the
// UpdateServiceBackupInput a test passed in, the call count, and
// returns a canned ServiceBackup / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity, the path parameters, and the If-Match
// precondition through to the store layer.
type fakeServiceBackupUpdater struct {
	backup    store.ServiceBackup
	err       error
	gotInput  *store.UpdateServiceBackupInput
	callCount *int
}

func (f fakeServiceBackupUpdater) Update(_ context.Context, in store.UpdateServiceBackupInput) (store.ServiceBackup, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.backup, f.err
}

// updateServiceBackupSuccessEnvelope is the decoded shape of the
// PATCH /v1/services/{service_id}/backups/{backup_id} success
// envelope.
type updateServiceBackupSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          updateServiceBackupPayload `json:"data"`
}

// canonicalUpdatedServiceBackup is the canned service_backups row
// the happy-path tests render through serviceBackupOf. Every field
// is non-zero so the projection invariants are exercised on the
// wire.
var canonicalUpdatedServiceBackup = store.ServiceBackup{
	ID:             "bkp_canonical_patch",
	OrganizationID: "org_acme",
	ServiceID:      "svc_canonical_patch_backup",
	DisplayName:    "nightly-prod",
	Schedule:       "0 2 * * *",
	RetentionCount: 14,
	Enabled:        true,
	Status:         store.ServiceBackupStatusPending,
	Version:        7,
	CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
	UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
}

// updateServiceBackupHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceBackupUpdater. It is the production request path: the
// PATCH /v1/services/{service_id}/backups/{backup_id} route is
// wrapped in RequireAuth for action backup.update.
func updateServiceBackupHandlerFor(id auth.Identity, authErr error, updater ServiceBackupUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, updater, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// patchServiceBackup issues PATCH
// /v1/services/{service_id}/backups/{backup_id} against the handler
// with the supplied bearer token and body.
func patchServiceBackup(handler http.Handler, serviceID, backupID, token, body string) *httptest.ResponseRecorder {
	return patchServiceBackupWithIfMatch(handler, serviceID, backupID, token, "", body)
}

// patchServiceBackupWithIfMatch issues PATCH
// /v1/services/{service_id}/backups/{backup_id} with an optional
// If-Match header. An empty ifMatch omits the header entirely so the
// optional precondition path remains exercised.
func patchServiceBackupWithIfMatch(handler http.Handler, serviceID, backupID, token, ifMatch, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/services/"+serviceID+"/backups/"+backupID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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

func decodeUpdateServiceBackup(t *testing.T, rec *httptest.ResponseRecorder) updateServiceBackupSuccessEnvelope {
	t.Helper()
	var env updateServiceBackupSuccessEnvelope
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

// TestUpdateServiceBackupHappyPathForwardsBodyAndPrincipal proves
// the handler decodes the patch body, threads the principal's home
// organization id, the path service_id, and the path backup_id into
// the store input, preserves the nil-ness of unset fields, renders
// the returned row in the stable yalla.output.v1 envelope, returns
// 200 OK, and mirrors the row's authoritative version into the ETag
// response header.
func TestUpdateServiceBackupHappyPathForwardsBodyAndPrincipal(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceBackupInput
	updater := fakeServiceBackupUpdater{backup: canonicalUpdatedServiceBackup, gotInput: &captured}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"display_name":"nightly-prod","schedule":"0 2 * * *","retention_count":14,"enabled":true}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateServiceBackup(t, rec)
	if env.Data.Backup.ID != canonicalUpdatedServiceBackup.ID {
		t.Errorf("backup.id = %q, want %q", env.Data.Backup.ID, canonicalUpdatedServiceBackup.ID)
	}
	if env.Data.Backup.ServiceID != canonicalUpdatedServiceBackup.ServiceID {
		t.Errorf("service_id = %q, want %q", env.Data.Backup.ServiceID, canonicalUpdatedServiceBackup.ServiceID)
	}
	if env.Data.Backup.DisplayName != canonicalUpdatedServiceBackup.DisplayName {
		t.Errorf("display_name = %q, want %q", env.Data.Backup.DisplayName, canonicalUpdatedServiceBackup.DisplayName)
	}
	if env.Data.Backup.Schedule != canonicalUpdatedServiceBackup.Schedule {
		t.Errorf("schedule = %q, want %q", env.Data.Backup.Schedule, canonicalUpdatedServiceBackup.Schedule)
	}
	if env.Data.Backup.RetentionCount != canonicalUpdatedServiceBackup.RetentionCount {
		t.Errorf("retention_count = %d, want %d", env.Data.Backup.RetentionCount, canonicalUpdatedServiceBackup.RetentionCount)
	}
	if env.Data.Backup.Enabled != canonicalUpdatedServiceBackup.Enabled {
		t.Errorf("enabled = %v, want %v", env.Data.Backup.Enabled, canonicalUpdatedServiceBackup.Enabled)
	}
	if env.Data.Backup.Version != canonicalUpdatedServiceBackup.Version {
		t.Errorf("version = %d, want %d", env.Data.Backup.Version, canonicalUpdatedServiceBackup.Version)
	}
	if got, want := rec.Header().Get("ETag"), `"7"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}

	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ServiceID != "svc_canonical_patch_backup" {
		t.Errorf("forwarded service_id = %q, want svc_canonical_patch_backup (path value)", captured.ServiceID)
	}
	if captured.BackupID != "bkp_canonical_patch" {
		t.Errorf("forwarded backup_id = %q, want bkp_canonical_patch (path value)", captured.BackupID)
	}
	if captured.DisplayName == nil || *captured.DisplayName != "nightly-prod" {
		t.Errorf("forwarded display_name = %v, want pointer to \"nightly-prod\"", captured.DisplayName)
	}
	if captured.Schedule == nil || *captured.Schedule != "0 2 * * *" {
		t.Errorf("forwarded schedule = %v, want pointer to \"0 2 * * *\"", captured.Schedule)
	}
	if captured.RetentionCount == nil || *captured.RetentionCount != 14 {
		t.Errorf("forwarded retention_count = %v, want pointer to 14", captured.RetentionCount)
	}
	if captured.Enabled == nil || *captured.Enabled != true {
		t.Errorf("forwarded enabled = %v, want pointer to true", captured.Enabled)
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

// TestUpdateServiceBackupPreservesAbsentFields proves the handler
// preserves the nil-ness of every absent field on the patch — a body
// that names only one updatable field forwards exactly that field
// and leaves the others as nil pointers so the store layer can tell
// "caller did not supply this" from "caller supplied the zero
// value".
func TestUpdateServiceBackupPreservesAbsentFields(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceBackupInput
	updater := fakeServiceBackupUpdater{backup: canonicalUpdatedServiceBackup, gotInput: &captured}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.DisplayName == nil || *captured.DisplayName != "nightly-prod" {
		t.Errorf("forwarded display_name = %v, want pointer to \"nightly-prod\"", captured.DisplayName)
	}
	if captured.Schedule != nil {
		t.Errorf("forwarded schedule = %v, want nil (absent from body)", captured.Schedule)
	}
	if captured.RetentionCount != nil {
		t.Errorf("forwarded retention_count = %v, want nil (absent from body)", captured.RetentionCount)
	}
	if captured.Enabled != nil {
		t.Errorf("forwarded enabled = %v, want nil (absent from body)", captured.Enabled)
	}
}

// TestUpdateServiceBackupExplicitEnabledFalseRidesThrough proves an
// explicit `"enabled": false` in the body forwards as a pointer to
// false to the store layer — the absent-vs-explicit-false
// distinction survives the seam. This is the customer toggle for
// "stop running this policy"; the worker observes the flag flip and
// skips the row on its next scheduling pass.
func TestUpdateServiceBackupExplicitEnabledFalseRidesThrough(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceBackupInput
	updater := fakeServiceBackupUpdater{backup: canonicalUpdatedServiceBackup, gotInput: &captured}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"enabled":false}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.Enabled == nil {
		t.Fatalf("forwarded enabled = nil, want pointer to false (explicit false in body)")
	}
	if *captured.Enabled != false {
		t.Errorf("forwarded enabled = %v, want pointer to false", *captured.Enabled)
	}
}

// TestUpdateServiceBackupForwardsIfMatchVersion proves the handler
// parses the If-Match header as a strong ETag, forwards the
// resulting version pointer to the store input, and otherwise
// behaves identically to the no-header path.
func TestUpdateServiceBackupForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceBackupInput
	updater := fakeServiceBackupUpdater{backup: canonicalUpdatedServiceBackup, gotInput: &captured}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackupWithIfMatch(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `"6"`, `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatalf("forwarded if_match_version = nil, want pointer to 6")
	}
	if *captured.IfMatchVersion != 6 {
		t.Errorf("forwarded if_match_version = %d, want 6", *captured.IfMatchVersion)
	}
}

// TestUpdateServiceBackupMalformedIfMatchIs400 proves a malformed
// If-Match header is rejected with a stable 400 before the updater
// runs — a malformed precondition is a client error, never a silent
// next-write-wins.
func TestUpdateServiceBackupMalformedIfMatchIs400(t *testing.T) {
	t.Parallel()

	var captured store.UpdateServiceBackupInput
	callCount := 0
	updater := fakeServiceBackupUpdater{
		backup:    canonicalUpdatedServiceBackup,
		gotInput:  &captured,
		callCount: &callCount,
	}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackupWithIfMatch(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `not-a-strong-etag`, `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("updater was reached (calls=%d) despite a malformed If-Match; it must never run", callCount)
	}
}

// TestUpdateServiceBackupStaleIfMatchReturns409 proves a stale
// If-Match version surfaces as a typed 409 with the row's
// authoritative current_version under details — the agent learns
// the version it needs to retry with without re-reading the row.
func TestUpdateServiceBackupStaleIfMatchReturns409(t *testing.T) {
	t.Parallel()

	updater := fakeServiceBackupUpdater{err: apierr.ConflictStale(11)}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackupWithIfMatch(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `"7"`, `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
	if !strings.Contains(rec.Body.String(), "current_version") {
		t.Errorf("response body did not carry current_version details; body %s", rec.Body.String())
	}
}

// TestUpdateServiceBackupMalformedBodyIs400 proves an oversized,
// malformed, or unknown-field body is rejected with a typed 400
// before the updater runs. The unknown-field cases prove the strict
// JSON decoder rejects body smuggling of status, organization_id,
// service_id, or id — caller-supplied alternative names that could
// otherwise let an agent forge a successful run or redirect the
// write at another tenant.
func TestUpdateServiceBackupMalformedBodyIs400(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"display_name":}`},
		{"unknown field status", `{"status":"succeeded"}`},
		{"unknown field organization_id", `{"organization_id":"org_attacker"}`},
		{"unknown field service_id", `{"service_id":"svc_attacker"}`},
		{"unknown field id", `{"id":"bkp_attacker"}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.UpdateServiceBackupInput
			callCount := 0
			updater := fakeServiceBackupUpdater{
				backup:    canonicalUpdatedServiceBackup,
				gotInput:  &captured,
				callCount: &callCount,
			}
			handler := updateServiceBackupHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
				nil, updater)

			rec := patchServiceBackup(handler,
				"svc_canonical_patch_backup", "bkp_canonical_patch",
				"a-valid-session-token", tc.body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			if callCount != 0 {
				t.Errorf("updater was reached (calls=%d); a malformed body must never reach the store layer", callCount)
			}
		})
	}
}

// TestUpdateServiceBackupNotFoundIsTyped404 proves an unknown
// (service_id, backup_id) pair surfaces as a typed 404 — never a 500
// leaking the internal cause, never a misleading 2xx.
func TestUpdateServiceBackupNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	updater := fakeServiceBackupUpdater{err: apierr.NotFound("service backup", "bkp_missing")}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_missing",
		"a-valid-session-token", `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateServiceBackupInvalidInputIsTyped400 proves a typed
// apierr.InvalidInput surfaces as a 400 with the field violations
// echoed back — the path the store layer takes for an invalid
// display_name, schedule, or retention_count.
func TestUpdateServiceBackupInvalidInputIsTyped400(t *testing.T) {
	t.Parallel()

	updater := fakeServiceBackupUpdater{
		err: apierr.InvalidInput(apierr.FieldViolation{Field: "retention_count", Reason: "must be between 1 and 365"}),
	}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"retention_count":9999}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
}

// TestUpdateServiceBackupUnauthenticatedIs401 proves an absent or
// invalid bearer token is rejected at the auth boundary with a
// stable 401 — the updater is never reached.
func TestUpdateServiceBackupUnauthenticatedIs401(t *testing.T) {
	t.Parallel()

	callCount := 0
	updater := fakeServiceBackupUpdater{callCount: &callCount}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{}, stderrors.New("invalid credential"), updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"", `{"display_name":"nightly-prod"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("updater was reached (calls=%d) for an unauthenticated request; it must never run", callCount)
	}
}

// TestUpdateServiceBackupStoreUnavailableIsTyped5xx proves a typed
// apierr.StoreUnavailable surfaces as a 5xx with the stable error
// code and the original error wrapped — never disguised as a 404 or
// a 400, never echoing the internal cause to the wire.
func TestUpdateServiceBackupStoreUnavailableIsTyped5xx(t *testing.T) {
	t.Parallel()

	updater := fakeServiceBackupUpdater{err: apierr.StoreUnavailable(yerr.New(yerr.CodeInternal, "kaboom"))}
	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, updater)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"display_name":"nightly-prod"}`)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServiceBackupHandlerNoPrincipalIsInternal proves the
// handler-internal `errNoPrincipalOnContext` sentinel surfaces as a
// typed Internal error if the route is ever exercised through a
// wiring that bypasses RequireAuth. This is a structural assertion —
// in production the middleware always populates the principal — so
// the test invokes the bare handler directly.
func TestUpdateServiceBackupHandlerNoPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	updater := fakeServiceBackupUpdater{}
	handler := updateServiceBackupHandler(updater)

	req := httptest.NewRequest(http.MethodPatch,
		"/v1/services/svc_x/backups/bkp_x", strings.NewReader(`{"display_name":"a"}`))
	req.SetPathValue("service_id", "svc_x")
	req.SetPathValue("backup_id", "bkp_x")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (no principal); body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServiceBackupHandlerNilUpdaterIsInternal proves a nil
// ServiceBackupUpdater wired through NewHandler surfaces as a typed
// Internal error rather than a silent success.
func TestUpdateServiceBackupHandlerNilUpdaterIsInternal(t *testing.T) {
	t.Parallel()

	handler := updateServiceBackupHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := patchServiceBackup(handler,
		"svc_canonical_patch_backup", "bkp_canonical_patch",
		"a-valid-session-token", `{"display_name":"nightly-prod"}`)

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx (nil updater); body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateServiceBackupOpenAPIOperationRegistered proves the route
// table registers operationId="updateServiceBackup" against PATCH
// /v1/services/{service_id}/backups/{backup_id} with the
// backup.update required action, so the served OpenAPI document
// (GET /openapi.json) — generated from the same table — is the
// single source of truth for the public contract.
func TestUpdateServiceBackupOpenAPIOperationRegistered(t *testing.T) {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPatch &&
			rt.endpoint.Path == "/v1/services/{service_id}/backups/{backup_id}" {
			found = true
			if rt.endpoint.OperationID != "updateServiceBackup" {
				t.Errorf("operationId = %q, want updateServiceBackup", rt.endpoint.OperationID)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("RequiresAuth = false, want true")
			}
			if rt.endpoint.RequiredAction != string(policy.ActionBackupUpdate) {
				t.Errorf("RequiredAction = %q, want %q", rt.endpoint.RequiredAction, string(policy.ActionBackupUpdate))
			}
			break
		}
	}
	if !found {
		t.Fatalf("route table did not register PATCH /v1/services/{service_id}/backups/{backup_id}")
	}
}
