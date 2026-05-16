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
// /v1/services/{service_id}/domains (BE-0238 + BE-0239). The endpoint
// creates a public-facing domain row bound to the service named by the
// {service_id} path parameter through the ServiceDomainCreator port.
// The tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake creator — the same wiring a request
// hits in production, minus the database. The store-backed creator
// (ServiceDomainService.Create) has its own isolated-Postgres
// integration coverage in store/service_domain_test.go; this file
// exercises the HTTP surface in isolation. The full role x tenant x
// grant-scope matrix lives in service_domains_create_policy_test.go
// (BE-0240).
//
// domain.create is a CapWrite action: viewer and support principals
// in the tenant cannot create domains (the CI key DOES write — the
// load-bearing distinction from service.read). The happy-path tests
// authenticate as RoleDeveloper to keep the role matrix focused on
// the policy suite.
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON
// contract). Field-level validation of the domain id, hostname, path,
// port, and certificate_type taxonomy is the store-layer's job and is
// asserted through the creator error path here, not by re-validating
// in the handler.

// fakeServiceDomainCreator is the test double for the
// ServiceDomainCreator port: it captures the
// CreateServiceDomainInput a test passed in, the call count, and
// returns a canned ServiceDomain / error. The captured input is the
// single load-bearing proof that the handler never trusts caller-
// controlled organization ids and plumbs the authenticated
// principal's identity to the audit record.
type fakeServiceDomainCreator struct {
	domain    store.ServiceDomain
	err       error
	gotInput  *store.CreateServiceDomainInput
	callCount *int
}

func (f fakeServiceDomainCreator) Create(_ context.Context, in store.CreateServiceDomainInput) (store.ServiceDomain, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.domain, f.err
}

// createServiceDomainSuccessEnvelope is the decoded shape of the POST
// /v1/services/{service_id}/domains success envelope.
type createServiceDomainSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          createServiceDomainPayload `json:"data"`
}

// seedServiceDomainWire is the helper every contract / policy test
// uses to seed a canonical ServiceDomain for the fake creator to
// return. The timestamps and structural ids are deterministic so leak
// guards can needle for them and assertions can compare verbatim.
func seedServiceDomainWire(id, orgID, serviceID, hostname, path string, port int, https bool, certificateType string, version int64, created, updated time.Time) store.ServiceDomain {
	return store.ServiceDomain{
		ID:              id,
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		Hostname:        hostname,
		Path:            path,
		Port:            port,
		HTTPS:           https,
		CertificateType: certificateType,
		Version:         version,
		CreatedAt:       created,
		UpdatedAt:       updated,
	}
}

// createServiceDomainHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceDomainCreator. It is the production request path: the
// POST /v1/services/{service_id}/domains route is wrapped in
// RequireAuth for action domain.create.
func createServiceDomainHandlerFor(id auth.Identity, authErr error, creator ServiceDomainCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, creator, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postServiceDomain issues POST /v1/services/{service_id}/domains
// against handler with the given body and optional bearer token.
func postServiceDomain(handler http.Handler, serviceID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/services/"+serviceID+"/domains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateServiceDomain(t *testing.T, rec *httptest.ResponseRecorder) createServiceDomainSuccessEnvelope {
	t.Helper()
	var env createServiceDomainSuccessEnvelope
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

// principalForCreateDomain returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// domain.create is a CapWrite action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence
// behavior, not on the role matrix (which is BE-0240's job).
func principalForCreateDomain(principalID, organizationID string) auth.Identity {
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

// TestCreateServiceDomainHappyPath drives the production request
// path: an organization-wide Developer principal creates a domain
// against a service owned by its home organization. The handler must
// forward the principal's home org id and the {service_id} path
// parameter to the creator (never a caller-supplied org id from the
// body), and must echo the persisted row through the canonical wire
// projection in a 201 envelope.
func TestCreateServiceDomainHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		domID = "sdom_abc123"
	)
	created := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	updated := created

	var gotIn store.CreateServiceDomainInput
	callCount := 0
	creator := fakeServiceDomainCreator{
		domain: seedServiceDomainWire(
			domID, org, svcID, "api.example.com", "/", 443, true,
			store.ServiceDomainCertificateLetsEncrypt, 1, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}

	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_abc123","hostname":"api.example.com","path":"/","port":443,"https":true,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")

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
	if gotIn.DomainID != domID || gotIn.Hostname != "api.example.com" || gotIn.Path != "/" || gotIn.Port != 443 || !gotIn.HTTPS || gotIn.CertificateType != store.ServiceDomainCertificateLetsEncrypt {
		t.Errorf("creator received intent = (id=%q, host=%q, path=%q, port=%d, https=%v, cert=%q), want (sdom_abc123, api.example.com, /, 443, true, lets-encrypt)",
			gotIn.DomainID, gotIn.Hostname, gotIn.Path, gotIn.Port, gotIn.HTTPS, gotIn.CertificateType)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org {
		t.Errorf("creator received actor = (%q, org=%q), want (usr_dev, org=%s) — actor identity must be plumbed for the audit record",
			gotIn.ActorID, gotIn.ActorOrgID, org)
	}

	envelope := decodeCreateServiceDomain(t, rec)
	d := envelope.Data.Domain
	if d.ID != domID {
		t.Errorf("domain.id = %q, want %q", d.ID, domID)
	}
	if d.ServiceID != svcID {
		t.Errorf("domain.service_id = %q, want %q", d.ServiceID, svcID)
	}
	if d.Hostname != "api.example.com" || d.Path != "/" || d.Port != 443 || !d.HTTPS || d.CertificateType != "lets-encrypt" {
		t.Errorf("domain wire = (host=%q, path=%q, port=%d, https=%v, cert=%q), want (api.example.com, /, 443, true, lets-encrypt)",
			d.Hostname, d.Path, d.Port, d.HTTPS, d.CertificateType)
	}
	if d.Version != 1 {
		t.Errorf("domain.Version = %d, want 1", d.Version)
	}
}

// TestCreateServiceDomainRequestIDPropagates proves the request
// correlation id reaches the wire envelope's request_id field. The
// telemetry.Correlate middleware generates a fresh request id when
// the request carries none, so the envelope's request_id must be
// non-empty regardless of whether the caller supplied an
// X-Request-Id header.
func TestCreateServiceDomainRequestIDPropagates(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)
	creator := fakeServiceDomainCreator{
		domain: seedServiceDomainWire("sdom_xyz", org, svcID, "api.example.com", "/", 443, true,
			store.ServiceDomainCertificateLetsEncrypt, 1, time.Now().UTC(), time.Now().UTC()),
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateServiceDomain(t, rec)
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want it propagated through the success envelope")
	}
}

// TestCreateServiceDomainValidationFailure proves a malformed
// hostname value surfaces as a typed 400 with code E_INVALID_INPUT
// and a stable yalla.error.v1 envelope. The fake creator returns the
// store-layer's validation error so the test verifies the handler
// propagates it as the correct envelope without touching the orchestrator
// semantics.
func TestCreateServiceDomainValidationFailure(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceDomainCreator{
		err:       apierr.InvalidInput(apierr.FieldViolation{Field: "hostname", Reason: "must be a fully-qualified domain name with at least two labels"}),
		callCount: &callCount,
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_xyz","hostname":"localhost","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 (the handler delegates validation to the orchestrator)",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestCreateServiceDomainMalformedJSON proves an oversized,
// malformed, or unknown-field body is rejected by the strict decoder
// before the creator is touched. The endpoint never echoes the
// caller's input back in the error envelope.
func TestCreateServiceDomainMalformedJSON(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceDomainCreator{callCount: &callCount}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"hostname":"api.example.com","unknown_field":"x"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (strict JSON decoder); body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 — strict-decode failures must precede the creator",
			callCount)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

// TestCreateServiceDomainUnauthenticated proves a request with no
// bearer token is rejected at the auth boundary with a typed 401
// envelope, before the handler is reached. The creator is set up
// with a callCount; it must remain untouched.
func TestCreateServiceDomainUnauthenticated(t *testing.T) {
	t.Parallel()

	callCount := 0
	creator := fakeServiceDomainCreator{callCount: &callCount}

	handler := createServiceDomainHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, "svc_api", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (auth rejected before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

// TestCreateServiceDomainAuthorizationDenied proves a principal
// whose role does not admit action domain.create (a viewer carrying
// no scoped grant) is rejected at the policy gate with a typed 403
// BEFORE the creator is touched. The viewer's CapRead capability
// does not authorize a CapWrite action.
func TestCreateServiceDomainAuthorizationDenied(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	callCount := 0
	creator := fakeServiceDomainCreator{callCount: &callCount}
	viewer := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: org,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := createServiceDomainHandlerFor(viewer, nil, creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator call count = %d, want 0 (policy denied before handler)", callCount)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

// TestCreateServiceDomainNotFoundCrossTenant proves a cross-tenant
// or unknown service_id reaches the persistence layer with the
// principal's home organization id and surfaces as a deterministic
// 404 — never disguised as a 200 or a 403 that would confirm the
// foreign service's existence. The creator receives the principal's
// home org id (never a caller-controlled value).
func TestCreateServiceDomainNotFoundCrossTenant(t *testing.T) {
	t.Parallel()

	const (
		ownOrg       = "org_attacker"
		foreignSvcID = "svc_victim"
	)

	var gotIn store.CreateServiceDomainInput
	callCount := 0
	creator := fakeServiceDomainCreator{
		err:       apierr.NotFound("service", foreignSvcID),
		gotInput:  &gotIn,
		callCount: &callCount,
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_mallory", ownOrg), nil, creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, foreignSvcID, body, "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("creator call count = %d, want 1 — engine admits the same-tenant resource, persistence rejects the foreign id",
			callCount)
	}
	if gotIn.OrganizationID != ownOrg {
		t.Errorf("creator received org id %q, want the attacker's home org %q — handler must NEVER trust a caller-controlled organization id",
			gotIn.OrganizationID, ownOrg)
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestCreateServiceDomainConflict proves a duplicate (hostname,
// path) insertion failure that produced an apierr.Conflict surfaces
// as a stable 409 with a yalla.error.v1 envelope. The redaction
// chokepoint is non-negotiable: the message never echoes the caller-
// supplied hostname or path.
func TestCreateServiceDomainConflict(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeServiceDomainCreator{
		err: apierr.Conflict("a service domain with this hostname and path already exists"),
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","path":"/v1","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	denyEnv := decodeError(t, rec, string(yerr.CodeConflict))
	if strings.Contains(denyEnv.Error.Message, "api.example.com") || strings.Contains(denyEnv.Error.Message, "/v1") {
		t.Errorf("error.message = %q, must not echo the caller-supplied hostname or path", denyEnv.Error.Message)
	}
}

// TestCreateServiceDomainUnwiredCreator proves the route reports a
// typed internal error rather than serving a misleading 2xx when the
// ServiceDomainCreator port is unwired. This is the wiring guard
// the route entry inherits from NewHandler: a nil creator at
// NewHandler time still registers the route, but a request that
// actually reaches the handler is reported as 500 E_SERVER.
func TestCreateServiceDomainUnwiredCreator(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, nil)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestCreateServiceDomainOpenAPIRegistration proves the generated
// OpenAPI document carries an operation registered at POST
// /v1/services/{service_id}/domains with the canonical operationId,
// the domain.create required action, and the services tag. The
// discovery surface must match the served surface verbatim.
func TestCreateServiceDomainOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	creator := fakeServiceDomainCreator{}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", "org_acme"), nil, creator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Look for the operation id, the path, and the canonical required
	// action — three structural facts that pin the wire contract.
	for _, needle := range []string{
		`"operationId": "createServiceDomain"`,
		`"/v1/services/{service_id}/domains"`,
		`"domain.create"`,
		`"services"`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("openapi.json is missing %q", needle)
		}
	}
}

// TestCreateServiceDomainStoreOutage proves a typed StoreUnavailable
// from the creator surfaces as a 503 with a E_STORE_UNAVAILABLE
// envelope — the persistence outage must never be disguised as a
// 5xx without a stable error code.
func TestCreateServiceDomainStoreOutage(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const svcID = "svc_api"

	creator := fakeServiceDomainCreator{
		err: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_xyz","hostname":"api.example.com","port":443,"certificate_type":"lets-encrypt"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
}

// TestCreateServiceDomainDefaultsApplied proves the handler forwards
// the schema-side defaults to the orchestrator when the caller omits
// optional fields: an omitted "path" lets the store layer apply "/",
// an omitted "https" defaults to true, and an omitted
// "certificate_type" defaults to "lets-encrypt". The handler
// resolves "https" from the request-body pointer so an explicit
// false is preserved verbatim.
func TestCreateServiceDomainDefaultsApplied(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)

	var gotIn store.CreateServiceDomainInput
	creator := fakeServiceDomainCreator{
		domain: seedServiceDomainWire("sdom_default", org, svcID, "api.example.com", "/", 80, true,
			store.ServiceDomainCertificateLetsEncrypt, 1, time.Now().UTC(), time.Now().UTC()),
		gotInput: &gotIn,
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	// path, https, and certificate_type are all omitted in this body.
	body := `{"id":"sdom_default","hostname":"api.example.com","port":80}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if !gotIn.HTTPS {
		t.Errorf("creator received https=%v, want true — the handler must default an omitted https to true",
			gotIn.HTTPS)
	}
	if gotIn.CertificateType != "" {
		// An omitted certificate_type rides through as the empty
		// string and the store layer applies the lets-encrypt
		// default — the handler must NOT silently substitute, so
		// behavior remains observable at the orchestrator seam.
		t.Errorf("creator received certificate_type=%q, want \"\" — the handler must forward the omitted field verbatim",
			gotIn.CertificateType)
	}
	if gotIn.Path != "" {
		t.Errorf("creator received path=%q, want \"\" — the handler must forward the omitted field verbatim",
			gotIn.Path)
	}
}

// TestCreateServiceDomainExplicitHTTPSFalse proves the handler
// preserves an explicit https=false against the schema default of
// true. The pointer indirection at the request boundary is the only
// thing that distinguishes absent-vs-explicit-false; this test
// proves the wire boundary respects it.
func TestCreateServiceDomainExplicitHTTPSFalse(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
	)

	var gotIn store.CreateServiceDomainInput
	creator := fakeServiceDomainCreator{
		domain: seedServiceDomainWire("sdom_plain", org, svcID, "api.example.com", "/", 80, false,
			store.ServiceDomainCertificateNone, 1, time.Now().UTC(), time.Now().UTC()),
		gotInput: &gotIn,
	}
	handler := createServiceDomainHandlerFor(
		principalForCreateDomain("usr_dev", org), nil, creator)

	body := `{"id":"sdom_plain","hostname":"api.example.com","port":80,"https":false,"certificate_type":"none"}`
	rec := postServiceDomain(handler, svcID, body, "a-valid-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if gotIn.HTTPS {
		t.Errorf("creator received https=%v, want false — an explicit https=false in the body must NOT silently flip to the schema default",
			gotIn.HTTPS)
	}
}
