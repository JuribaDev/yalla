package httpapi

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract tests for GET /v1/services/{service_id}/rendered (BE-0196,
// BE-0197).
// The rendered endpoint is the deterministic identity projection of a
// service: the canonical Docker-safe Dokploy resource name domain
// .DokployName builds from the row's display_name and id, the Dokploy
// service taxonomy mapped from the row's kind, and the structural
// attribution labels (yalla.organization_id, yalla.project_id,
// yalla.environment_id, yalla.service_id) the worker stamps onto every
// provisioned Dokploy object. The endpoint reads one services row
// through the SHARED ServiceReader port — the same port GET
// /v1/services/{service_id} (BE-0184) depends on — so the wire shape,
// the tenant boundary, the failure-mode taxonomy, and the wiring-error
// contract are uniform across both routes. The fixtures and helpers
// (fakeServiceReader, getServiceHandlerFor, authForSvcGet,
// canonicalServiceForGet, principalForSvcGet) are shared with
// services_test.go.

// renderedServiceWire is the JSON shape decoded from a rendered-
// endpoint response body. Keeping it separate from renderedService
// keeps the wire contract explicit — a future renderedService Go
// rename cannot silently change the JSON keys without failing here.
type renderedServiceWire struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Labels []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"labels"`
}

// renderedServiceEnvelopeWire is the success envelope shape this
// route returns. SchemaVersion and RequestID are asserted on every
// success path; Data carries both the service row and the rendered
// preview so the response can be correlated with the underlying row
// by id and version.
type renderedServiceEnvelopeWire struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Service  environmentService  `json:"service"`
		Rendered renderedServiceWire `json:"rendered"`
	} `json:"data"`
}

// getServiceRendered fires GET /v1/services/{service_id}/rendered
// with the supplied bearer token and returns the response recorder.
func getServiceRendered(handler http.Handler, svcID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/services/"+svcID+"/rendered", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// getServiceRenderedWithRequestID is the request-id propagation variant
// of getServiceRendered. The public contract is that a safe inbound
// X-Request-Id reaches both the response header and the envelope body.
func getServiceRenderedWithRequestID(handler http.Handler, svcID, token, requestID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/services/"+svcID+"/rendered", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

const getServiceRenderedContractSecret = "yk_live_supersecret_services_rendered_DEADBEEF0123456789"

// getServiceRenderedHandlerForWithLogger builds the production rendered
// endpoint path with a caller-supplied logger. It mirrors the GET
// /v1/services/{service_id} contract helper, but drives the rendered
// route so the bearer-token redaction and stdout/stderr assertions are
// pinned on this endpoint itself.
func getServiceRenderedHandlerForWithLogger(id auth.Identity, authErr error, reader ServiceReader, logger *slog.Logger) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil)
}

// decodeRenderedServiceBody decodes the success envelope into the
// rendered-service wire shape so assertions read the JSON contract,
// not the in-process Go type.
func decodeRenderedServiceBody(t *testing.T, rec *httptest.ResponseRecorder) renderedServiceEnvelopeWire {
	t.Helper()
	var env renderedServiceEnvelopeWire
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty")
	}
	return env
}

// canonicalServiceForRendered is the canned services row the
// rendered happy-path tests render. Unlike canonicalServiceForGet
// (services_test.go), the IDs are canonical domain-issued resource
// IDs — domain.DokployName runs domain.ParseID on the service id and
// rejects any non-canonical form, so the rendered handler can only
// produce a name for a row that carries a real id. Production rows
// always carry canonical IDs (the store-layer validators reject
// anything else before insert), so this fixture mirrors production
// data; the parent test (services_test.go) doesn't call DokployName
// and continues to use the simpler canonicalServiceForGet fixture.
// The principal's home organization id (principalForSvcGet) is kept
// distinct from this row's organization id so the wire test proves
// the reader is called with the PRINCIPAL's home org, never with
// caller-controlled state.
var canonicalServiceForRendered = func() store.Service {
	return store.Service{
		ID:             domain.MustNewID(domain.KindService).String(),
		OrganizationID: principalForSvcGet.OrganizationID,
		ProjectID:      domain.MustNewID(domain.KindProject).String(),
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "api",
		DisplayName:    "Rendered API",
		Kind:           "application",
		Version:        7,
		CreatedAt:      time.Date(2025, 4, 11, 9, 30, 0, 0, time.UTC),
		UpdatedAt:      time.Date(2025, 4, 12, 10, 0, 0, 0, time.UTC),
	}
}()

// TestGetServiceRenderedHappyPath proves a request with a valid
// bearer token reaches the reader with the principal's home
// organization id (never a caller-supplied id) and the path
// service_id, and renders the canonical row through environmentServiceOf
// alongside the deterministic Dokploy resource name (computed from
// display_name and id), the Dokploy type mapped from the row's kind,
// and the structural identity labels — all in a stable yalla.output.v1
// envelope.
func TestGetServiceRenderedHappyPath(t *testing.T) {
	t.Parallel()

	svc := canonicalServiceForRendered
	var gotOrg, gotSvc string
	callCount := 0
	reader := fakeServiceReader{
		svc:       svc,
		gotOrgID:  &gotOrg,
		gotSvcID:  &gotSvc,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)

	rec := getServiceRendered(handler, svc.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != principalForSvcGet.OrganizationID {
		t.Errorf("reader called with org_id = %q; want %q (principal home org, never caller-supplied)", gotOrg, principalForSvcGet.OrganizationID)
	}
	if gotSvc != svc.ID {
		t.Errorf("reader called with service_id = %q; want %q (path parameter, verbatim)", gotSvc, svc.ID)
	}

	env := decodeRenderedServiceBody(t, rec)

	// The service block carries the same wire shape as every other
	// services endpoint, so the rendered response can be correlated
	// with the underlying row by id and version.
	if env.Data.Service.ID != svc.ID ||
		env.Data.Service.OrganizationID != svc.OrganizationID ||
		env.Data.Service.ProjectID != svc.ProjectID ||
		env.Data.Service.EnvironmentID != svc.EnvironmentID ||
		env.Data.Service.Slug != svc.Slug ||
		env.Data.Service.DisplayName != svc.DisplayName ||
		env.Data.Service.Kind != svc.Kind ||
		env.Data.Service.Version != svc.Version {
		t.Errorf("service projection = %+v, want canonical row (%s, %s, %s, %s, kind=%s, v=%d)",
			env.Data.Service,
			svc.ID, svc.OrganizationID,
			svc.ProjectID, svc.EnvironmentID,
			svc.Kind, svc.Version)
	}

	// The rendered name is the deterministic domain.DokployName of
	// (display_name, id). Pinning the value here locks the rendered
	// projection against the underlying domain helper: a regression in
	// either side fails here.
	wantName, err := domain.DokployName(svc.DisplayName, domain.ID(svc.ID))
	if err != nil {
		t.Fatalf("domain.DokployName: %v", err)
	}
	if env.Data.Rendered.Name != wantName {
		t.Errorf("rendered.name = %q, want %q (deterministic DokployName(display_name, id))", env.Data.Rendered.Name, wantName)
	}
	if env.Data.Rendered.Type != string(dokploy.ServiceApplication) {
		t.Errorf("rendered.type = %q, want %q (mapped from kind %q)", env.Data.Rendered.Type, dokploy.ServiceApplication, svc.Kind)
	}

	// The structural labels carry only canonical hierarchy ids — no
	// slug, no display name, no credential material — in a
	// deterministic order (organization → project → environment →
	// service) so the wire shape is stable across calls.
	wantLabels := []renderedLabel{
		{Key: "yalla.organization_id", Value: svc.OrganizationID},
		{Key: "yalla.project_id", Value: svc.ProjectID},
		{Key: "yalla.environment_id", Value: svc.EnvironmentID},
		{Key: "yalla.service_id", Value: svc.ID},
	}
	if len(env.Data.Rendered.Labels) != len(wantLabels) {
		t.Fatalf("rendered.labels length = %d, want %d", len(env.Data.Rendered.Labels), len(wantLabels))
	}
	for i, want := range wantLabels {
		got := env.Data.Rendered.Labels[i]
		if got.Key != want.Key || got.Value != want.Value {
			t.Errorf("rendered.labels[%d] = (%q, %q), want (%q, %q)", i, got.Key, got.Value, want.Key, want.Value)
		}
	}
	for _, l := range env.Data.Rendered.Labels {
		if l.Value == svc.Slug || l.Value == svc.DisplayName {
			t.Errorf("rendered.labels echoed human content (%q): labels must carry only canonical ids", l.Value)
		}
	}
}

// TestGetServiceRenderedPropagatesRequestID proves the rendered
// endpoint uses the canonical request-correlation middleware: a safe
// inbound request id is copied to the response header and into the
// yalla.output.v1 envelope body. Agents rely on this to correlate a
// preview response with request logs and audit trails.
func TestGetServiceRenderedPropagatesRequestID(t *testing.T) {
	t.Parallel()

	const requestID = "req_rendered_contract_123"
	reader := fakeServiceReader{svc: canonicalServiceForRendered}
	handler := getServiceHandlerFor(t, reader)

	rec := getServiceRenderedWithRequestID(handler, canonicalServiceForRendered.ID, "a-valid-token", requestID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRenderedServiceBody(t, rec)
	if env.RequestID != requestID {
		t.Errorf("envelope request_id = %q, want inbound %q", env.RequestID, requestID)
	}
	if got := rec.Header().Get("X-Request-Id"); got != requestID {
		t.Errorf("response X-Request-Id = %q, want inbound %q", got, requestID)
	}
}

// TestGetServiceRenderedInvalidServiceIDIsValidationError proves the
// path parameter is validated before any source-of-truth read. A
// malformed id is a deterministic 400 E_VALIDATION and the reader
// is never reached, so invalid input cannot become a cross-tenant
// existence probe or a misleading rendered preview.
func TestGetServiceRenderedInvalidServiceIDIsValidationError(t *testing.T) {
	t.Parallel()

	callCount := 0
	reader := fakeServiceReader{
		svc:       canonicalServiceForRendered,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)

	rec := getServiceRendered(handler, "not-a-service-id!", "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader was reached (calls=%d), want validation to short-circuit before persistence", callCount)
	}
	decodeError(t, rec, string(yerr.CodeValidation))
}

// TestGetServiceRenderedKindMapping proves the rendered.type field
// mirrors the row's kind taxonomy verbatim through renderedServiceType.
// The closed taxonomy ("application", "database", "compose") MUST stay
// in lockstep with dokploy.ServiceType — a future addition there
// requires an entry in renderedServiceType. The test asserts the
// mapping for every documented kind and the default-passthrough for
// any other value (a defensive contract assertion, not a customer
// path).
func TestGetServiceRenderedKindMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		kind string
		want dokploy.ServiceType
	}{
		{"application", dokploy.ServiceApplication},
		{"database", dokploy.ServiceDatabase},
		{"compose", dokploy.ServiceCompose},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.kind, func(t *testing.T) {
			t.Parallel()
			svc := canonicalServiceForRendered
			svc.ID = domain.MustNewID(domain.KindService).String()
			svc.Slug = tc.kind + "-svc"
			svc.DisplayName = "Rendered " + tc.kind
			svc.Kind = tc.kind

			reader := fakeServiceReader{svc: svc}
			handler := getServiceHandlerFor(t, reader)
			rec := getServiceRendered(handler, svc.ID, "a-valid-token")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			env := decodeRenderedServiceBody(t, rec)
			if env.Data.Rendered.Type != string(tc.want) {
				t.Errorf("rendered.type = %q, want %q for kind %q", env.Data.Rendered.Type, tc.want, tc.kind)
			}
			wantName, err := domain.DokployName(svc.DisplayName, domain.ID(svc.ID))
			if err != nil {
				t.Fatalf("domain.DokployName: %v", err)
			}
			if env.Data.Rendered.Name != wantName {
				t.Errorf("rendered.name = %q, want %q", env.Data.Rendered.Name, wantName)
			}
		})
	}
}

// TestGetServiceRenderedNotFound proves a service_id the store
// rejects as apierr.NotFound surfaces as a deterministic 404
// E_NOT_FOUND envelope. The reader is reached once with the
// principal's home org and the path service_id (so a production
// tenant-scoped GetByID cannot match a foreign row regardless of
// database state); the denied body never echoes another tenant's
// identity.
func TestGetServiceRenderedNotFound(t *testing.T) {
	t.Parallel()

	missingID := domain.MustNewID(domain.KindService).String()
	var gotOrg, gotSvc string
	callCount := 0
	reader := fakeServiceReader{
		err:       apierr.NotFound("service", missingID),
		gotOrgID:  &gotOrg,
		gotSvcID:  &gotSvc,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)

	rec := getServiceRendered(handler, missingID, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != principalForSvcGet.OrganizationID {
		t.Errorf("reader called with org_id = %q; want %q (principal home org, never caller-supplied)", gotOrg, principalForSvcGet.OrganizationID)
	}
	if gotSvc != missingID {
		t.Errorf("reader called with service_id = %q; want %q", gotSvc, missingID)
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestGetServiceRenderedStoreUnavailable proves a transient store
// outage surfaces as a typed 5xx through toAPIError; the contract of
// THIS endpoint is the same uniform failure-mode taxonomy GET
// /v1/services/{service_id} carries.
func TestGetServiceRenderedStoreUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceReader{
		err: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}
	handler := getServiceHandlerFor(t, reader)
	rec := getServiceRendered(handler, canonicalServiceForRendered.ID, "a-valid-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx for StoreUnavailable; body %s", rec.Code, rec.Body.String())
	}
}

// TestGetServiceRenderedErrorEnvelopeDoesNotLeakDependencyCause proves
// a wrapped reader outage surfaces as a stable 503 envelope without
// copying internal datastore details or the bearer credential onto the
// public wire surface.
func TestGetServiceRenderedErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.44.0.19:5432"
	reader := fakeServiceReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := getServiceRenderedHandlerForWithLogger(
		auth.Identity{Principal: principalForSvcGet, Method: auth.MethodAPIKey},
		nil, reader, nil,
	)

	rec := getServiceRendered(handler, canonicalServiceForRendered.ID, getServiceRenderedContractSecret)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, string(yerr.CodeDBUnavailable))
	if env.Error.Message == "" {
		t.Error("error.message is empty, want a stable generic message")
	}
	body := rec.Body.String()
	if strings.Contains(body, cause) || strings.Contains(body, "10.44.0.19") {
		t.Errorf("error envelope leaked the wrapped dependency cause: %s", body)
	}
	if strings.Contains(body, getServiceRenderedContractSecret) {
		t.Errorf("error envelope leaked the bearer credential: %s", body)
	}
}

// TestGetServiceRenderedUnauthenticated proves a request with no
// bearer token is rejected with a deterministic 401 — the
// authentication middleware short-circuits before the handler runs,
// so the reader is never reached. This is the structural property
// every authenticated endpoint shares.
func TestGetServiceRenderedUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	reader := fakeServiceReader{
		svc:       canonicalServiceForRendered,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)
	rec := getServiceRendered(handler, canonicalServiceForRendered.ID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader was reached (calls=%d) on an unauthenticated request; the auth middleware must short-circuit", callCount)
	}
}

// TestGetServiceRenderedServerWritesResponseDataOnlyToResponseWriter
// proves the rendered endpoint carries response data exclusively
// through the http.ResponseWriter: serving the request writes nothing
// to process stdout/stderr. Structured request logs are allowed only
// through the caller-supplied logger sink.
func TestGetServiceRenderedServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps process-global stdout/stderr.

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeServiceReader{svc: canonicalServiceForRendered}
	handler := getServiceRenderedHandlerForWithLogger(
		auth.Identity{Principal: principalForSvcGet, Method: auth.MethodAPIKey},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getServiceRendered(handler, canonicalServiceForRendered.ID, getServiceRenderedContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing", stderr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRenderedServiceBody(t, rec)
	if env.Data.Service.ID != canonicalServiceForRendered.ID {
		t.Errorf("service.id = %q, want %q in response body", env.Data.Service.ID, canonicalServiceForRendered.ID)
	}
	if env.Data.Rendered.Name == "" {
		t.Error("rendered.name is empty, want rendered data carried by response body")
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestGetServiceRenderedRequestLogRedactsBearerToken proves the
// per-request structured log never carries the bearer credential on
// either the allow path or the authorization-denied path. Headers are
// not logged at all; this contract prevents a future logging change
// from leaking API keys while debugging rendered desired state.
func TestGetServiceRenderedRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	allowed := principalForSvcGet
	disabled := principalForSvcGet
	disabled.ID = "usr_rendered_revoked"
	disabled.Disabled = true

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     ServiceReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: allowed, Method: auth.MethodAPIKey},
			reader:     fakeServiceReader{svc: canonicalServiceForRendered},
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodAPIKey},
			reader:     fakeServiceReader{err: stderrors.New("reader must not be called")},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := getServiceRenderedHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getServiceRendered(handler, canonicalServiceForRendered.ID, getServiceRenderedContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getServiceRenderedContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getServiceRenderedContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestGetServiceRenderedNoReaderConfigured proves a request that
// reaches the handler without a ServiceReader wired into NewHandler
// is reported as a typed internal error (errNoServiceReader) rather
// than disguised as an empty or misleading success. This is a wiring
// error — a programming mistake, not a client-recoverable failure —
// and the contract is the same as GET /v1/services/{service_id}.
func TestGetServiceRenderedNoReaderConfigured(t *testing.T) {
	t.Parallel()

	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authForSvcGet{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, nil, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := getServiceRendered(handler, canonicalServiceForRendered.ID, "a-valid-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx (typed internal error for a wiring fault); body %s", rec.Code, rec.Body.String())
	}
}

// TestGetServiceRenderedOpenAPIRouteIsRegistered proves the OpenAPI
// route table carries the rendered operation with its stable
// operationId, service.read action, services tag, and documented
// service_id path parameter.
func TestGetServiceRenderedOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/rendered" {
			found = true
			if rt.endpoint.OperationID != "getServiceRendered" {
				t.Errorf("operation_id = %q, want getServiceRendered", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionServiceRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionServiceRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			var hasServicesTag bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagServices {
					hasServicesTag = true
				}
			}
			if !hasServicesTag {
				t.Errorf("tags = %v, want to contain %q", rt.endpoint.Tags, tagServices)
			}
			if len(rt.endpoint.PathParams) != 1 || rt.endpoint.PathParams[0].Name != "service_id" {
				t.Errorf("path_params = %+v, want a single service_id path param", rt.endpoint.PathParams)
			}
			if rt.resolver == nil {
				t.Error("resolver is nil; rendered route must use serviceIDResolver")
			}
		}
	}
	if !found {
		t.Error("OpenAPI route GET /v1/services/{service_id}/rendered is not registered")
	}
}

// TestGetServiceRenderedLabelsCarryNoSecrets proves the rendered
// labels NEVER echo human content from the row — only canonical
// hierarchy ids. The slug and display name carry human-authored
// content; the labels are the structural attribution channel and must
// be deterministic from ids alone. A future regression that copies
// the slug or display name into a label would fail this test before
// it could leak human content into Dokploy.
func TestGetServiceRenderedLabelsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	const human = "Customer Internal Stamp"
	svc := store.Service{
		ID:             domain.MustNewID(domain.KindService).String(),
		OrganizationID: domain.MustNewID(domain.KindOrganization).String(),
		ProjectID:      domain.MustNewID(domain.KindProject).String(),
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "label-guard",
		DisplayName:    human,
		Kind:           "application",
		Version:        1,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	reader := fakeServiceReader{svc: svc}
	authIdentity := auth.Identity{
		Method: auth.MethodAPIKey,
		Principal: policy.Principal{
			ID:             "usr_label_guard",
			OrganizationID: svc.OrganizationID,
			Role:           policy.RoleAdmin,
		},
	}
	// Direct identity injection because principalForSvcGet's home org
	// is fixed to canonicalServiceForGet's tenant, and this test wants
	// a tenant that matches the seeded service's own org.
	a := fakeAuthenticator{identity: authIdentity}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := getServiceRendered(handler, svc.ID, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeRenderedServiceBody(t, rec)
	for _, l := range env.Data.Rendered.Labels {
		if strings.Contains(l.Value, human) {
			t.Errorf("rendered.labels[%q] = %q leaked human content %q; labels must carry only canonical ids", l.Key, l.Value, human)
		}
	}
}
