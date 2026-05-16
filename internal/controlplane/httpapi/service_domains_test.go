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
// /v1/services/{service_id}/domains (BE-0235 + BE-0236). The endpoint
// returns the public-facing domain rows bound to the service named by
// the {service_id} path parameter through the ServiceDomainReader
// port. The tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The full
// role x tenant x grant-scope policy matrix lives in
// service_domains_policy_test.go (BE-0237).
//
// domain.read is a CapRead action: every built-in role holds CapRead,
// so the happy-path tests authenticate as RoleOwner and the deny
// paths matrix-cover the other failure modes (unauthenticated, store
// outage, missing wiring). The role matrix is exhaustively covered in
// the policy test file.

// fakeServiceDomainReader is a canned ServiceDomainReader for
// httpapi-layer tests. The zero value returns an empty ServiceDomains
// and no error, which is all the test helpers that never reach the
// handler need; the domain tests set domains/err and read got back to
// prove the handler forwards the principal's home organization and
// the path service id to the store layer unchanged.
type fakeServiceDomainReader struct {
	domains store.ServiceDomains
	err     error
	got     *store.ListServiceDomainsInput
}

func (f fakeServiceDomainReader) ListDomains(_ context.Context, in store.ListServiceDomainsInput) (store.ServiceDomains, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.domains, f.err
}

// listServiceDomainsSuccessEnvelope is the decoded shape of the GET
// /v1/services/{service_id}/domains success envelope. The domains
// slice marshals as [] when empty (never null), so the wire-shape
// decoder here matches the contract every other list endpoint pins.
type listServiceDomainsSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		ServiceID string          `json:"service_id"`
		Domains   []serviceDomain `json:"domains"`
	} `json:"data"`
}

// listServiceDomainsHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ServiceDomainReader. It is the production request path: the
// GET /v1/services/{service_id}/domains route is wrapped in
// RequireAuth for action domain.read.
func listServiceDomainsHandlerFor(id auth.Identity, authErr error, reader ServiceDomainReader) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, reader, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// listServiceDomains issues GET /v1/services/{service_id}/domains
// against handler. An empty token omits the Authorization header so
// the unauthenticated path is exercised.
func listServiceDomains(handler http.Handler, serviceID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/services/"+serviceID+"/domains", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListServiceDomains(t *testing.T, rec *httptest.ResponseRecorder) listServiceDomainsSuccessEnvelope {
	t.Helper()
	var env listServiceDomainsSuccessEnvelope
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

// canonicalServiceDomains is the canned ServiceDomains the
// happy-path tests render. The hostname strings and port numbers are
// deliberately distinctive so deny-path leak guards can needle for
// them.
func canonicalServiceDomains() store.ServiceDomains {
	t1 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	return store.ServiceDomains{
		ServiceID: "svc_canonical_domains",
		Domains: []store.ServiceDomain{
			{
				ID:              "sdom_alpha",
				OrganizationID:  "org_acme",
				ServiceID:       "svc_canonical_domains",
				Hostname:        "api.acme.example",
				Path:            "/",
				Port:            8080,
				HTTPS:           true,
				CertificateType: "lets-encrypt",
				Version:         1,
				CreatedAt:       t1,
				UpdatedAt:       t1,
			},
			{
				ID:              "sdom_bravo",
				OrganizationID:  "org_acme",
				ServiceID:       "svc_canonical_domains",
				Hostname:        "edge.acme.example",
				Path:            "/v2",
				Port:            8443,
				HTTPS:           true,
				CertificateType: "custom",
				Version:         3,
				CreatedAt:       t1,
				UpdatedAt:       t1,
			},
		},
	}
}

// TestListServiceDomainsSuccess proves the happy path renders 200
// OK, uses the yalla.output.v1 envelope, projects the canned domain
// rows in deterministic order, forwards the principal's home
// organization id and the path service_id to the ServiceDomainReader
// port, and echoes the service id in the response.
func TestListServiceDomainsSuccess(t *testing.T) {
	t.Parallel()

	domains := canonicalServiceDomains()
	var captured store.ListServiceDomainsInput
	reader := fakeServiceDomainReader{domains: domains, got: &captured}
	handler := listServiceDomainsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceDomains(handler, domains.ServiceID, "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeListServiceDomains(t, rec)
	if env.Data.ServiceID != domains.ServiceID {
		t.Errorf("data.service_id = %q, want %q", env.Data.ServiceID, domains.ServiceID)
	}
	if len(env.Data.Domains) != len(domains.Domains) {
		t.Fatalf("domains len = %d, want %d", len(env.Data.Domains), len(domains.Domains))
	}
	if env.Data.Domains[0].ID != "sdom_alpha" || env.Data.Domains[0].Hostname != "api.acme.example" ||
		env.Data.Domains[0].Port != 8080 || env.Data.Domains[0].CertificateType != "lets-encrypt" {
		t.Errorf("domains[0] = %+v, mismatched projection", env.Data.Domains[0])
	}
	if env.Data.Domains[1].Path != "/v2" || env.Data.Domains[1].Port != 8443 ||
		env.Data.Domains[1].CertificateType != "custom" {
		t.Errorf("domains[1] = %+v, mismatched projection", env.Data.Domains[1])
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want %q (principal home)", captured.OrganizationID, "org_acme")
	}
	if captured.ServiceID != domains.ServiceID {
		t.Errorf("forwarded service_id = %q, want %q", captured.ServiceID, domains.ServiceID)
	}
}

// TestListServiceDomainsEmptyDomainsAreSliceNotNull proves the wire
// shape renders an empty Domains slice as "domains": [] rather than
// "domains": null, so an agent does not need to special-case the
// absent-vs-empty distinction.
func TestListServiceDomainsEmptyDomainsAreSliceNotNull(t *testing.T) {
	t.Parallel()

	reader := fakeServiceDomainReader{domains: store.ServiceDomains{ServiceID: "svc_empty_domains", Domains: nil}}
	handler := listServiceDomainsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceDomains(handler, "svc_empty_domains", "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"domains":[]`) {
		t.Errorf("response body %s does not contain \"domains\":[]; an empty list must marshal as [] not null", rec.Body.String())
	}
}

// TestListServiceDomainsUnauthenticated proves a missing bearer
// token is rejected by RequireAuth before the reader runs.
func TestListServiceDomainsUnauthenticated(t *testing.T) {
	t.Parallel()

	reader := fakeServiceDomainReader{
		domains: canonicalServiceDomains(),
		err:     stderrors.New("reader must not be called"),
	}
	handler := listServiceDomainsHandlerFor(auth.Identity{}, auth.ErrNoCredentials, reader)

	rec := listServiceDomains(handler, "svc_acme_api", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestListServiceDomainsNotFound proves the typed store-layer
// NotFound — the disposition for a cross-tenant or unknown
// service_id — is rendered as a 404, never as a silent empty success
// that would mask a tenant-isolation failure.
func TestListServiceDomainsNotFound(t *testing.T) {
	t.Parallel()

	reader := fakeServiceDomainReader{err: apierr.NotFound("service", "svc_missing")}
	handler := listServiceDomainsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceDomains(handler, "svc_missing", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestListServiceDomainsStoreUnavailable proves a typed
// store-unavailable error is rendered as a 503 — the datastore
// outage surfaces as the typed 503, never disguised as a 500 leaking
// the pgx cause.
func TestListServiceDomainsStoreUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeServiceDomainReader{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := listServiceDomainsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, reader)

	rec := listServiceDomains(handler, "svc_acme_api", "valid-key")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListServiceDomainsCrossTenantNoForeignEcho proves the handler
// never trusts the path service_id to override the principal's home
// organization id: a cross-tenant service_id is reported as 404 (the
// store's tenant-scoped existence check) — never disguised as a 200
// with another tenant's data and never as a 403 that would confirm
// existence. The captured OrganizationID input is the principal's
// home org, not the foreign tenant.
func TestListServiceDomainsCrossTenantNoForeignEcho(t *testing.T) {
	t.Parallel()

	const (
		attackerOrg = "org_attacker"
		victimSvc   = "svc_victim_owns_domains"
		victimOrg   = "org_victim"
	)
	var captured store.ListServiceDomainsInput
	reader := fakeServiceDomainReader{
		err: apierr.NotFound("service", victimSvc),
		got: &captured,
	}
	handler := listServiceDomainsHandlerFor(ownerIdentity(attackerOrg, "usr_attacker"), nil, reader)

	rec := listServiceDomains(handler, victimSvc, "valid-key")
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

// TestListServiceDomainsMissingReader proves a wiring error (nil
// reader reaching the handler) is reported as a typed internal error
// rather than a misleading empty success. The wiring goes through
// NewHandler so the request reaches the typed-internal guard inside
// listServiceDomainsHandler.
func TestListServiceDomainsMissingReader(t *testing.T) {
	t.Parallel()

	var nilReader ServiceDomainReader
	handler := listServiceDomainsHandlerFor(ownerIdentity("org_acme", "usr_owner"), nil, nilReader)

	rec := listServiceDomains(handler, "svc_acme_api", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestListServiceDomainsOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/services/{service_id}/domains
// operation with the stable operationId, the domain.read required
// action, the services tag, and 200 OK success status — every detail
// an agent reads to discover the endpoint.
func TestListServiceDomainsOpenAPIRouteIsRegistered(t *testing.T) {
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
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/services/{service_id}/domains" {
			found = true
			if rt.endpoint.OperationID != "listServiceDomains" {
				t.Errorf("operation_id = %q, want listServiceDomains", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionDomainRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionDomainRead)
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
		t.Errorf("GET /v1/services/{service_id}/domains not in route table")
	}
}
