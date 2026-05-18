package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

type fakeDokployRefReader struct {
	refs []store.DokployRef
	err  error

	gotOrgID string
	calls    int
}

func (f *fakeDokployRefReader) ListDokployRefs(ctx context.Context, organizationID string) ([]store.DokployRef, error) {
	f.calls++
	f.gotOrgID = organizationID
	if f.err != nil {
		return nil, f.err
	}
	return f.refs, nil
}

func adminDokployRefsHandlerFor(authn Authenticator, reader *fakeDokployRefReader) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, reader)
}

func TestListAdminDokployRefsReturnsOrganizationRefs(t *testing.T) {
	t.Parallel()

	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	created := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	reader := &fakeDokployRefReader{refs: []store.DokployRef{{
		ID:              42,
		OrganizationID:  targetOrg,
		YallaKind:       store.YallaKindProject,
		YallaID:         "proj_alpha",
		DokployResource: store.DokployResourceProject,
		DokployID:       "dkp-project-42",
		CreatedAt:       created,
		UpdatedAt:       created,
	}}}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+targetOrg+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	req.Header.Set("X-Request-Id", "req_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if reader.calls != 1 || reader.gotOrgID != targetOrg {
		t.Fatalf("reader calls/org = %d/%q, want 1/%q", reader.calls, reader.gotOrgID, targetOrg)
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			OrganizationID string `json:"organization_id"`
			Refs           []struct {
				ID              int64  `json:"id"`
				OrganizationID  string `json:"organization_id"`
				YallaKind       string `json:"yalla_kind"`
				YallaID         string `json:"yalla_id"`
				DokployResource string `json:"dokploy_resource"`
				DokployID       string `json:"dokploy_id"`
			} `json:"refs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_refs" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.OrganizationID != targetOrg {
		t.Fatalf("organization_id = %q, want %q", env.Data.OrganizationID, targetOrg)
	}
	if len(env.Data.Refs) != 1 || env.Data.Refs[0].ID != 42 || env.Data.Refs[0].DokployID != "dkp-project-42" {
		t.Fatalf("refs = %+v, want seeded ref", env.Data.Refs)
	}
}

func TestListAdminDokployRefsRejectsInvalidOrganizationID(t *testing.T) {
	t.Parallel()

	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/not-an-org/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 on validation failure", reader.calls)
	}
}

func TestListAdminDokployRefsAuthFailures(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+orgID+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_owner_not_support")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")

	h = adminDokployRefsHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, reader)
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+orgID+"/dokploy-refs", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 when auth fails", reader.calls)
	}
}

func TestListAdminDokployRefsPropagatesNotFound(t *testing.T) {
	t.Parallel()

	missingOrg := string(domain.MustNewID(domain.KindOrganization))
	reader := &fakeDokployRefReader{err: apierr.NotFound("organization", missingOrg)}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+missingOrg+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

func TestListAdminDokployRefsOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	h := adminDokployRefsHandlerFor(fakeAuthenticator{}, &fakeDokployRefReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string           `json:"operationId"`
			RequiredAction string           `json:"x-required-action"`
			Security       []map[string]any `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/admin/organizations/{org_id}/dokploy-refs"]["get"]
	if !ok {
		t.Fatalf("GET /v1/admin/organizations/{org_id}/dokploy-refs is missing from OpenAPI")
	}
	if op.OperationID != "listAdminOrganizationDokployRefs" {
		t.Errorf("operationId = %q, want listAdminOrganizationDokployRefs", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAdminRead) {
		t.Errorf("required action = %q, want %q", op.RequiredAction, policy.ActionAdminRead)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement")
	}
}
