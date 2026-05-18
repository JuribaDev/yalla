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
// /v1/services/{service_id}/metrics (BE-0232 + BE-0233). The endpoint
// returns the most recent metric samples for the service named by the
// {service_id} path parameter through the ServiceMetricsReader port.
// The tests drive it through NewHandler with a fake Authenticator,
// the real policy engine, and a fake reader — the same wiring a
// request hits in production, minus the database. The full
// role x tenant x grant-scope policy matrix lives in
// services_metrics_policy_test.go (BE-0234).
//
// metrics.read is a CapRead action: every built-in role holds
// CapRead, so the happy-path tests authenticate as RoleOwner and the
// deny paths matrix-cover the other failure modes (unauthenticated,
// invalid limit, store outage, missing wiring). The role matrix is
// exhaustively covered in the policy test file.

// fakeServiceMetricsReader is a canned ServiceMetricsReader for
// httpapi-layer tests. The zero value returns an empty ServiceMetrics
// and no error, which is all the test helpers that never reach the
// handler need; the metrics tests set metrics/err and read got back
// to prove the handler forwards the principal's home organization,
// the path service id, and the resolved limit to the store layer
// unchanged.
type fakeServiceMetricsReader struct {
	metrics store.ServiceMetrics
	err     error
	got     *store.ListServiceMetricsInput
}

func (f fakeServiceMetricsReader) ListMetrics(_ context.Context, in store.ListServiceMetricsInput) (store.ServiceMetrics, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.metrics, f.err
}

// listServiceMetricsSuccessEnvelope is the decoded shape of the GET
// /v1/services/{service_id}/metrics success envelope. The samples
// slice marshals as [] when empty (never null), so the wire-shape
// decoder here matches the contract every other list endpoint pins.
type listServiceMetricsSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		ServiceID string                `json:"service_id"`
		Samples   []serviceMetricSample `json:"samples"`
	} `json:"data"`
}

// listServiceMetricsHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceMetricsReader. It is the production request path: the
// GET /v1/services/{service_id}/metrics route is wrapped in
// RequireAuth for action metrics.read.
func listServiceMetricsHandlerFor(id auth.Identity, authErr error, reader ServiceMetricsReader) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, reader, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// listServiceMetrics issues GET /v1/services/{service_id}/metrics
// against handler. An empty token omits the Authorization header so
// the unauthenticated path is exercised; a non-empty rawQuery is
// appended verbatim so the invalid-limit deny paths can submit a
// concrete query string without re-encoding here.
func listServiceMetrics(handler http.Handler, serviceID, token, rawQuery string) *httptest.ResponseRecorder {
	target := "/v1/services/" + serviceID + "/metrics"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Request-Id", "req-service-metrics-test")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListServiceMetrics(t *testing.T, rec *httptest.ResponseRecorder) listServiceMetricsSuccessEnvelope {
	t.Helper()
	var env listServiceMetricsSuccessEnvelope
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

// canonicalServiceMetrics is the canned ServiceMetrics the happy-path
// tests render. The placeholder reader returns an empty Samples slice;
// these tests use a non-empty slice with recognisable contents to
// pin the wire projection of name, occurred_at, value, and unit.
func canonicalServiceMetrics() store.ServiceMetrics {
	t1 := time.Date(2026, 5, 16, 12, 0, 0, 250_000_000, time.UTC)
	t2 := t1.Add(30 * time.Second)
	return store.ServiceMetrics{
		ServiceID: "svc_canonical_metrics",
		Samples: []store.ServiceMetricSample{
			{Name: "http_requests", OccurredAt: t1, Value: 4321, Unit: "count"},
			{Name: "latency_p95_ms", OccurredAt: t2, Value: 87.5, Unit: "ms"},
		},
	}
}

// TestListServiceMetricsSuccess proves the happy path renders 200
// OK, uses the yalla.output.v1 envelope, projects the canned metric
// samples in occurrence order, forwards the principal's home
// organization id, the path service_id, and the default limit (100)
// to the ServiceMetricsReader port, and echoes the service id in
// the response.
func TestListServiceMetricsSuccess(t *testing.T) {
	t.Parallel()

	metrics := canonicalServiceMetrics()
	var captured store.ListServiceMetricsInput
	reader := fakeServiceMetricsReader{metrics: metrics, got: &captured}
	handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceMetrics(handler, metrics.ServiceID, "valid-key", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeListServiceMetrics(t, rec)
	if env.Data.ServiceID != metrics.ServiceID {
		t.Errorf("data.service_id = %q, want %q", env.Data.ServiceID, metrics.ServiceID)
	}
	if len(env.Data.Samples) != len(metrics.Samples) {
		t.Fatalf("samples len = %d, want %d", len(env.Data.Samples), len(metrics.Samples))
	}
	if env.Data.Samples[0].Name != "http_requests" || env.Data.Samples[0].Unit != "count" || env.Data.Samples[0].Value != 4321 {
		t.Errorf("samples[0] = %+v, want name=http_requests / unit=count / value=4321", env.Data.Samples[0])
	}
	if env.Data.Samples[1].Name != "latency_p95_ms" || env.Data.Samples[1].Unit != "ms" || env.Data.Samples[1].Value != 87.5 {
		t.Errorf("samples[1] = %+v, want name=latency_p95_ms / unit=ms / value=87.5", env.Data.Samples[1])
	}
	if !strings.HasPrefix(env.Data.Samples[0].OccurredAt, "2026-05-16T12:00:00") {
		t.Errorf("samples[0].occurred_at = %q, want RFC3339-style UTC prefix", env.Data.Samples[0].OccurredAt)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want %q (principal home)", captured.OrganizationID, "org_acme")
	}
	if captured.ServiceID != metrics.ServiceID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, metrics.ServiceID)
	}
	if captured.Limit != serviceMetricsDefaultLimit {
		t.Errorf("forwarded limit = %d, want default %d", captured.Limit, serviceMetricsDefaultLimit)
	}
}

// TestListServiceMetricsEmptySamplesAreSliceNotNull proves the wire
// shape renders an empty Samples slice as "samples": [] rather than
// "samples": null, so an agent does not need to special-case the
// absent-vs-empty distinction. The placeholder reader returns no
// samples for every service, so this is the dominant happy-path
// shape today.
func TestListServiceMetricsEmptySamplesAreSliceNotNull(t *testing.T) {
	t.Parallel()

	reader := fakeServiceMetricsReader{metrics: store.ServiceMetrics{ServiceID: "svc_empty_metrics", Samples: nil}}
	handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceMetrics(handler, "svc_empty_metrics", "valid-key", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"samples":[]`) {
		t.Errorf("response body %s does not contain \"samples\":[]; an empty list must marshal as [] not null", rec.Body.String())
	}
}

// TestListServiceMetricsCustomLimitForwarded proves a valid ?limit=
// query parameter is forwarded to the reader as the resolved page
// size. The handler clamps the range at the boundary, so a value of
// 1 (low end) and serviceMetricsMaxLimit (high end) both round-trip
// to the reader unchanged.
func TestListServiceMetricsCustomLimitForwarded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"min", "1", 1},
		{"max", "1000", serviceMetricsMaxLimit},
		{"middle", "250", 250},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var captured store.ListServiceMetricsInput
			reader := fakeServiceMetricsReader{metrics: store.ServiceMetrics{ServiceID: "svc_x"}, got: &captured}
			handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)
			rec := listServiceMetrics(handler, "svc_x", "valid-key", "limit="+tc.raw)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if captured.Limit != tc.want {
				t.Errorf("forwarded limit = %d, want %d", captured.Limit, tc.want)
			}
		})
	}
}

// TestListServiceMetricsInvalidLimit proves a malformed,
// non-positive, or larger-than-ceiling limit is rejected as a typed
// 400 E_VALIDATION before any reader call runs. The reader must
// never see a request that did not pass limit validation.
func TestListServiceMetricsInvalidLimit(t *testing.T) {
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
			var captured store.ListServiceMetricsInput
			reader := fakeServiceMetricsReader{
				err: stderrors.New("reader must not be called for an invalid limit"),
				got: &captured,
			}
			handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)
			rec := listServiceMetrics(handler, "svc_x", "valid-key", "limit="+tc.raw)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for invalid limit; body %s", rec.Code, rec.Body.String())
			}
			decodeError(t, rec, string(yerr.CodeValidation))
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

// TestListServiceMetricsUnauthenticated proves a missing bearer
// token is rejected by RequireAuth before the reader runs.
func TestListServiceMetricsUnauthenticated(t *testing.T) {
	t.Parallel()

	reader := fakeServiceMetricsReader{
		metrics: canonicalServiceMetrics(),
		err:     stderrors.New("reader must not be called"),
	}
	handler := listServiceMetricsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)

	rec := listServiceMetrics(handler, "svc_acme_api", "", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestListServiceMetricsNotFound proves the typed store-layer
// NotFound — the disposition for a cross-tenant or unknown
// service_id — is rendered as a 404, never as a silent empty success
// that would mask a tenant-isolation failure.
func TestListServiceMetricsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeServiceMetricsReader{err: apierr.NotFound("service", "svc_missing")}
	handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceMetrics(handler, "svc_missing", "valid-key", "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestListServiceMetricsStoreUnavailable proves a typed
// store-unavailable error is rendered as a 503 — the datastore
// outage surfaces as the typed 503, never disguised as a 500
// leaking the pgx cause.
func TestListServiceMetricsStoreUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceMetricsReader{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceMetrics(handler, "svc_acme_api", "valid-key", "")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListServiceMetricsCrossTenantNoForeignEcho proves the handler
// never trusts the path service_id to override the principal's home
// organization id: a cross-tenant service_id is reported as 404 (the
// store's tenant-scoped existence check) — never disguised as a 200
// with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's
// home org, not the foreign tenant.
func TestListServiceMetricsCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns_metrics"
		victimOrg   = "org_victim"
	)
	var captured store.ListServiceMetricsInput
	reader := fakeServiceMetricsReader{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}
	handler := listServiceMetricsHandlerFor(ownerIdentity(attackerOrg, "usr_attacker"), nil, reader)

	rec := listServiceMetrics(handler, victimSvc, "valid-key", "")
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

// TestListServiceMetricsMissingReader proves a wiring error (nil
// reader reaching the handler) is reported as a typed internal
// error rather than a misleading empty success. The wiring goes
// through NewHandler so the request reaches the typed-internal
// guard inside listServiceMetricsHandler.
func TestListServiceMetricsMissingReader(t *testing.T) {
	t.Parallel()

	var nilReader ServiceMetricsReader
	_ = (*fakeServiceMetricsReader)(nil)
	handler := listServiceMetricsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nilReader)

	rec := listServiceMetrics(handler, "svc_acme_api", "valid-key", "")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestListServiceMetricsOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/services/{service_id}/metrics
// operation with the stable operationId, the metrics.read required
// action, the services tag, and 200 OK success status — every
// detail an agent reads to discover the endpoint.
func TestListServiceMetricsOpenAPIRouteIsRegistered(t *testing.T) {
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
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/metrics" {
			found = true
			if rt.endpoint.OperationID != "listServiceMetrics" {
				t.Errorf("operation_id = %q, want listServiceMetrics", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionMetricsRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionMetricsRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
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
		t.Errorf("GET /v1/services/{service_id}/metrics not in route table")
	}
}

// Keep the domain import live for the package-doc reference to the
// closed-set service kind even when no test currently uses it.
var _ = domain.KindService
