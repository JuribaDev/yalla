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

// Contract and tenant-isolation coverage for GET
// /v1/services/{service_id}/logs (BE-0229 + BE-0230). The endpoint
// returns the most recent log lines for the service named by the
// {service_id} path parameter through the ServiceLogReader port. The
// tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake reader — the same wiring a request
// hits in production, minus the database. The full role x tenant x
// grant-scope policy matrix lives in services_logs_policy_test.go
// (BE-0231).
//
// logs.read is a CapRead action: every built-in role holds CapRead,
// so the happy-path tests authenticate as RoleOwner and the deny
// paths matrix-cover the other failure modes (unauthenticated,
// invalid limit, store outage, missing wiring). The role matrix is
// exhaustively covered in the policy test file.

// fakeServiceLogReader is a canned ServiceLogReader for httpapi-layer
// tests. The zero value returns an empty ServiceLogs and no error,
// which is all the test helpers that never reach the handler need;
// the logs tests set logs/err and read got back to prove the handler
// forwards the principal's home organization, the path service id,
// and the resolved limit to the store layer unchanged.
type fakeServiceLogReader struct {
	logs store.ServiceLogs
	err  error
	got  *store.ListServiceLogsInput
}

func (f fakeServiceLogReader) ListLogs(_ context.Context, in store.ListServiceLogsInput) (store.ServiceLogs, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.logs, f.err
}

// listServiceLogsSuccessEnvelope is the decoded shape of the GET
// /v1/services/{service_id}/logs success envelope. The lines slice
// marshals as [] when empty (never null), so the wire-shape decoder
// here matches the contract every other list endpoint pins.
type listServiceLogsSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		ServiceID string           `json:"service_id"`
		Lines     []serviceLogLine `json:"lines"`
	} `json:"data"`
}

// listServiceLogsHandlerFor builds the full NewHandler surface with
// an Authenticator that resolves every credential to id and the
// given ServiceLogReader. It is the production request path: the
// GET /v1/services/{service_id}/logs route is wrapped in RequireAuth
// for action logs.read.
func listServiceLogsHandlerFor(id auth.Identity, authErr error, reader ServiceLogReader) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, reader, nil, nil, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// listServiceLogs issues GET /v1/services/{service_id}/logs against
// handler. An empty token omits the Authorization header so the
// unauthenticated path is exercised; a non-empty rawQuery is
// appended verbatim so the invalid-limit deny paths can submit a
// concrete query string without re-encoding here.
func listServiceLogs(handler http.Handler, serviceID, token, rawQuery string) *httptest.ResponseRecorder {
	target := "/v1/services/" + serviceID + "/logs"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListServiceLogs(t *testing.T, rec *httptest.ResponseRecorder) listServiceLogsSuccessEnvelope {
	t.Helper()
	var env listServiceLogsSuccessEnvelope
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

// canonicalServiceLogs is the canned ServiceLogs the happy-path
// tests render. The placeholder reader returns an empty Lines slice;
// these tests use a non-empty slice with recognisable contents to
// pin the wire projection of stream, occurred_at, and message.
func canonicalServiceLogs() store.ServiceLogs {
	t1 := time.Date(2026, 5, 16, 12, 0, 0, 100_000_000, time.UTC)
	t2 := t1.Add(50 * time.Millisecond)
	return store.ServiceLogs{
		ServiceID: "svc_canonical_logs",
		Lines: []store.ServiceLogLine{
			{OccurredAt: t1, Stream: "stdout", Message: "listening on :8080"},
			{OccurredAt: t2, Stream: "stderr", Message: "warning: deprecated flag"},
		},
	}
}

// TestListServiceLogsSuccess proves the happy path renders 200 OK,
// uses the yalla.output.v1 envelope, projects the canned log lines
// in occurrence order, forwards the principal's home organization
// id, the path service_id, and the default limit (100) to the
// ServiceLogReader port, and echoes the service id in the response.
func TestListServiceLogsSuccess(t *testing.T) {
	t.Parallel()

	logs := canonicalServiceLogs()
	var captured store.ListServiceLogsInput
	reader := fakeServiceLogReader{logs: logs, got: &captured}
	handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceLogs(handler, logs.ServiceID, "valid-key", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeListServiceLogs(t, rec)
	if env.Data.ServiceID != logs.ServiceID {
		t.Errorf("data.service_id = %q, want %q", env.Data.ServiceID, logs.ServiceID)
	}
	if len(env.Data.Lines) != len(logs.Lines) {
		t.Fatalf("lines len = %d, want %d", len(env.Data.Lines), len(logs.Lines))
	}
	if env.Data.Lines[0].Stream != "stdout" || env.Data.Lines[0].Message != "listening on :8080" {
		t.Errorf("lines[0] = %+v, want stream=stdout / message=listening on :8080", env.Data.Lines[0])
	}
	if env.Data.Lines[1].Stream != "stderr" || env.Data.Lines[1].Message != "warning: deprecated flag" {
		t.Errorf("lines[1] = %+v, want stream=stderr / message=warning: deprecated flag", env.Data.Lines[1])
	}
	if !strings.HasPrefix(env.Data.Lines[0].OccurredAt, "2026-05-16T12:00:00") {
		t.Errorf("lines[0].occurred_at = %q, want RFC3339-style UTC prefix", env.Data.Lines[0].OccurredAt)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want %q (principal home)", captured.OrganizationID, "org_acme")
	}
	if captured.ServiceID != logs.ServiceID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, logs.ServiceID)
	}
	if captured.Limit != serviceLogsDefaultLimit {
		t.Errorf("forwarded limit = %d, want default %d", captured.Limit, serviceLogsDefaultLimit)
	}
}

// TestListServiceLogsEmptyLinesAreSliceNotNull proves the wire shape
// renders an empty Lines slice as "lines": [] rather than
// "lines": null, so an agent does not need to special-case the
// absent-vs-empty distinction. The placeholder reader returns no
// lines for every service, so this is the dominant happy-path shape
// today.
func TestListServiceLogsEmptyLinesAreSliceNotNull(t *testing.T) {
	t.Parallel()

	reader := fakeServiceLogReader{logs: store.ServiceLogs{ServiceID: "svc_empty_logs", Lines: nil}}
	handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceLogs(handler, "svc_empty_logs", "valid-key", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"lines":[]`) {
		t.Errorf("response body %s does not contain \"lines\":[]; an empty list must marshal as [] not null", rec.Body.String())
	}
}

// TestListServiceLogsCustomLimitForwarded proves a valid ?limit=
// query parameter is forwarded to the reader as the resolved page
// size. The handler clamps the range at the boundary, so a value of
// 1 (low end) and serviceLogsMaxLimit (high end) both round-trip to
// the reader unchanged.
func TestListServiceLogsCustomLimitForwarded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"min", "1", 1},
		{"max", "1000", serviceLogsMaxLimit},
		{"middle", "250", 250},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.ListServiceLogsInput
			reader := fakeServiceLogReader{logs: store.ServiceLogs{ServiceID: "svc_x"}, got: &captured}
			handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)
			rec := listServiceLogs(handler, "svc_x", "valid-key", "limit="+tc.raw)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if captured.Limit != tc.want {
				t.Errorf("forwarded limit = %d, want %d", captured.Limit, tc.want)
			}
		})
	}
}

// TestListServiceLogsInvalidLimit proves a malformed, non-positive,
// or larger-than-ceiling limit is rejected as a typed 400
// E_INVALID_INPUT before any reader call runs. The reader must
// never see a request that did not pass limit validation.
func TestListServiceLogsInvalidLimit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{"zero", "0"},
		{"negative", "-3"},
		{"non-numeric", "abc"},
		{"over ceiling", "1001"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.ListServiceLogsInput
			reader := fakeServiceLogReader{
				err: stderrors.New("reader must not be called for an invalid limit"),
				got: &captured,
			}
			handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)
			rec := listServiceLogs(handler, "svc_x", "valid-key", "limit="+tc.raw)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for invalid limit; body %s", rec.Code, rec.Body.String())
			}
			decodeError(t, rec, string(yerr.CodeInvalidInput))
			if captured.OrganizationID != "" || captured.ServiceID != "" {
				t.Errorf("reader was called for an invalid limit; got %+v — it must never run", captured)
			}
			if tc.name == "non-numeric" && strings.Contains(rec.Body.String(), tc.raw) {
				// A typo must never become a reflection-style content channel —
				// the message names the accepted range, never the submitted
				// value. Numeric out-of-range / off-by-one inputs may legitimately
				// share digits with the accepted-range string ("0" is a substring
				// of "1000"), so the reflection assertion only fires on
				// non-numeric input, which is where caller-controlled byte
				// content could realistically reach the response body.
				t.Errorf("error body %s echoed the submitted limit %q; the message must not reflect caller input", rec.Body.String(), tc.raw)
			}
		})
	}
}

// TestListServiceLogsUnauthenticated proves a missing bearer token
// is rejected by RequireAuth before the reader runs.
func TestListServiceLogsUnauthenticated(t *testing.T) {
	t.Parallel()

	reader := fakeServiceLogReader{
		logs: canonicalServiceLogs(),
		err:  stderrors.New("reader must not be called"),
	}
	handler := listServiceLogsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)

	rec := listServiceLogs(handler, "svc_acme_api", "", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestListServiceLogsNotFound proves the typed store-layer NotFound
// — the disposition for a cross-tenant or unknown service_id — is
// rendered as a 404, never as a silent empty success that would
// mask a tenant-isolation failure.
func TestListServiceLogsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeServiceLogReader{err: apierr.NotFound("service", "svc_missing")}
	handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceLogs(handler, "svc_missing", "valid-key", "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestListServiceLogsStoreUnavailable proves a typed store-unavailable
// error is rendered as a 503 — the datastore outage surfaces as the
// typed 503, never disguised as a 500 leaking the pgx cause.
func TestListServiceLogsStoreUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceLogReader{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceLogs(handler, "svc_acme_api", "valid-key", "")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListServiceLogsCrossTenantNoForeignEcho proves the handler
// never trusts the path service_id to override the principal's home
// organization id: a cross-tenant service_id is reported as 404 (the
// store's tenant-scoped existence check) — never disguised as a 200
// with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's
// home org, not the foreign tenant.
func TestListServiceLogsCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns_logs"
		victimOrg   = "org_victim"
	)
	var captured store.ListServiceLogsInput
	reader := fakeServiceLogReader{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}
	handler := listServiceLogsHandlerFor(ownerIdentity(attackerOrg, "usr_attacker"), nil, reader)

	rec := listServiceLogs(handler, victimSvc, "valid-key", "")
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

// TestListServiceLogsMissingReader proves a wiring error (nil
// reader reaching the handler) is reported as a typed internal
// error rather than a misleading empty success. The wiring goes
// through NewHandler so the request reaches the typed-internal
// guard inside listServiceLogsHandler.
func TestListServiceLogsMissingReader(t *testing.T) {
	t.Parallel()

	// Use an explicit typed-nil ServiceLogReader so the production
	// nil-guard branch is exercised; a bare `nil` literal would not
	// satisfy the interface positional argument.
	var nilReader ServiceLogReader
	_ = (*fakeServiceLogReader)(nil) // keep the type imported referenced even when unused at the typed nil
	handler := listServiceLogsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nilReader)

	rec := listServiceLogs(handler, "svc_acme_api", "valid-key", "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestListServiceLogsOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/services/{service_id}/logs operation
// with the stable operationId, the logs.read required action, the
// services tag, and 200 OK success status — every detail an agent
// reads to discover the endpoint.
func TestListServiceLogsOpenAPIRouteIsRegistered(t *testing.T) {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/logs" {
			found = true
			if rt.endpoint.OperationID != "listServiceLogs" {
				t.Errorf("operation_id = %q, want listServiceLogs", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionLogsRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionLogsRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			// SuccessStatus zero defaults to 200 in the OpenAPI builder —
			// the endpoint deliberately omits an explicit status, mirroring
			// every other GET in the surface, so the documented status is
			// 200 OK by convention.
			if rt.endpoint.SuccessStatus != 0 && rt.endpoint.SuccessStatus != http.StatusOK {
				t.Errorf("success_status = %d, want %d (or unset for 200 default)", rt.endpoint.SuccessStatus, http.StatusOK)
			}
			var hasServices bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagServices {
					hasServices = true
				}
			}
			if !hasServices {
				t.Errorf("tags = %v, want %q", rt.endpoint.Tags, tagServices)
			}
		}
	}
	if !found {
		t.Errorf("GET /v1/services/{service_id}/logs not in route table")
	}
}

// Keep the domain import live for the package-doc reference to the
// closed-set service kind even when no test currently uses it.
var _ = domain.KindService
