package httpapi

import (
	"encoding/json"
	stderrors "errors"
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
)

// Contract tests for GET /v1/services/{service_id}/rendered (BE-0196).
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

	var gotOrg, gotSvc string
	callCount := 0
	reader := fakeServiceReader{
		err:       apierr.NotFound("service", "svc_missing"),
		gotOrgID:  &gotOrg,
		gotSvcID:  &gotSvc,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)

	rec := getServiceRendered(handler, "svc_missing", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != principalForSvcGet.OrganizationID {
		t.Errorf("reader called with org_id = %q; want %q (principal home org, never caller-supplied)", gotOrg, principalForSvcGet.OrganizationID)
	}
	if gotSvc != "svc_missing" {
		t.Errorf("reader called with service_id = %q; want %q", gotSvc, "svc_missing")
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
	rec := getServiceRendered(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx for StoreUnavailable; body %s", rec.Code, rec.Body.String())
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
		svc:       canonicalServiceForGet,
		callCount: &callCount,
	}
	handler := getServiceHandlerFor(t, reader)
	rec := getServiceRendered(handler, canonicalServiceForGet.ID, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader was reached (calls=%d) on an unauthenticated request; the auth middleware must short-circuit", callCount)
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, nil, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

	rec := getServiceRendered(handler, canonicalServiceForGet.ID, "a-valid-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx (typed internal error for a wiring fault); body %s", rec.Code, rec.Body.String())
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
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, reader, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)

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
