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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

type listProjectPreviewsSuccessEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	RequestID     string                     `json:"request_id"`
	Data          listProjectPreviewsPayload `json:"data"`
}

func listProjectPreviewsHandlerFor(id auth.Identity, authErr error, previews PreviewCreator) http.Handler {
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
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{},
		fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{},
		fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{},
		fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{},
		fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{},
		fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{},
		fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, previews)
}

func getProjectPreviews(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID+"/previews", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListProjectPreviews(t *testing.T, rec *httptest.ResponseRecorder) listProjectPreviewsSuccessEnvelope {
	t.Helper()
	var env listProjectPreviewsSuccessEnvelope
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
		t.Errorf("request_id is empty, want generated request id")
	}
	return env
}

func previewPrincipal(principalID, organizationID string, role policy.Role) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           "usr",
			OrganizationID: organizationID,
			Role:           role,
		},
		Method: "api_key",
	}
}

func seedPreviewWire(id, orgID, projectID, envID, sourceID, displayName, changeRef, status string, version int64, created, updated time.Time) store.PreviewEnvironment {
	return store.PreviewEnvironment{
		ID:                  id,
		OrganizationID:      orgID,
		ProjectID:           projectID,
		EnvironmentID:       envID,
		SourceEnvironmentID: sourceID,
		DisplayName:         displayName,
		ChangeRef:           changeRef,
		Status:              status,
		Version:             version,
		CreatedAt:           created,
		UpdatedAt:           updated,
	}
}

func TestListProjectPreviewsHappyPath(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_web"
	created := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	updated := created.Add(2 * time.Hour)
	expires := created.Add(72 * time.Hour)
	deletingAt := created.Add(24 * time.Hour)

	var gotOrg, gotProj string
	calls := 0
	previews := fakePreviewCreator{
		previews: []store.PreviewEnvironment{
			func() store.PreviewEnvironment {
				p := seedPreviewWire("penv_pr_42", org, proj, "env_pr_42", "env_prod", "PR 42", "refs/pull/42/head", store.PreviewEnvironmentStatusReady, 4, created, updated)
				p.ExpiresAt = &expires
				return p
			}(),
			func() store.PreviewEnvironment {
				p := seedPreviewWire("penv_pr_43", org, proj, "env_pr_43", "env_prod", "PR 43", "refs/pull/43/head", store.PreviewEnvironmentStatusDeleting, 5, created.Add(time.Minute), updated.Add(time.Minute))
				p.DeletionScheduledAt = &deletingAt
				return p
			}(),
		},
		gotListOrgID:     &gotOrg,
		gotListProjectID: &gotProj,
		listCallCount:    &calls,
	}

	handler := listProjectPreviewsHandlerFor(previewPrincipal("usr_dev", org, policy.RoleDeveloper), nil, previews)
	rec := getProjectPreviews(handler, proj, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Errorf("list call count = %d, want 1", calls)
	}
	if gotOrg != org {
		t.Errorf("reader org = %q, want principal org %q", gotOrg, org)
	}
	if gotProj != proj {
		t.Errorf("reader project = %q, want path project %q", gotProj, proj)
	}

	env := decodeListProjectPreviews(t, rec)
	if len(env.Data.Previews) != 2 {
		t.Fatalf("previews len = %d, want 2; body %s", len(env.Data.Previews), rec.Body.String())
	}
	first := env.Data.Previews[0]
	if first.ID != "penv_pr_42" || first.EnvironmentID != "env_pr_42" || first.SourceEnvironmentID != "env_prod" {
		t.Errorf("first preview ids = %+v, want penv/env/source ids", first)
	}
	if first.OrganizationID != org || first.ProjectID != proj {
		t.Errorf("first preview scope = (%q, %q), want (%q, %q)", first.OrganizationID, first.ProjectID, org, proj)
	}
	if first.DisplayName != "PR 42" || first.ChangeRef != "refs/pull/42/head" || first.Status != store.PreviewEnvironmentStatusReady {
		t.Errorf("first preview metadata = %+v", first)
	}
	if first.ExpiresAt == nil || *first.ExpiresAt != expires.Format(time.RFC3339Nano) {
		t.Errorf("first expires_at = %v, want %s", first.ExpiresAt, expires.Format(time.RFC3339Nano))
	}
	if first.DeletionScheduledAt != nil {
		t.Errorf("first deletion_scheduled_at = %v, want omitted", *first.DeletionScheduledAt)
	}
	second := env.Data.Previews[1]
	if second.DeletionScheduledAt == nil || *second.DeletionScheduledAt != deletingAt.Format(time.RFC3339Nano) {
		t.Errorf("second deletion_scheduled_at = %v, want %s", second.DeletionScheduledAt, deletingAt.Format(time.RFC3339Nano))
	}
}

func TestListProjectPreviewsEmptyListIsNonNil(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(previewPrincipal("usr_view", "org_acme", policy.RoleViewer), nil, fakePreviewCreator{})
	rec := getProjectPreviews(handler, "proj_empty", "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectPreviews(t, rec)
	if env.Data.Previews == nil {
		t.Fatalf("previews = nil, want non-nil empty list")
	}
	if len(env.Data.Previews) != 0 {
		t.Fatalf("previews len = %d, want 0", len(env.Data.Previews))
	}
}

func TestListProjectPreviewsUnauthenticated(t *testing.T) {
	t.Parallel()

	calls := 0
	handler := listProjectPreviewsHandlerFor(auth.Identity{}, nil, fakePreviewCreator{listCallCount: &calls})
	rec := getProjectPreviews(handler, "proj_web", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("reader called %d times, want 0", calls)
	}
}

func TestListProjectPreviewsAuthorizationFailure(t *testing.T) {
	t.Parallel()

	calls := 0
	handler := listProjectPreviewsHandlerFor(previewPrincipal("usr_limited", "org_acme", policy.Role("limited")), nil, fakePreviewCreator{listCallCount: &calls})
	rec := getProjectPreviews(handler, "proj_web", "a-valid-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("reader called %d times, want 0", calls)
	}
}

func TestListProjectPreviewsNotFound(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(
		previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper),
		nil,
		fakePreviewCreator{listErr: apierr.NotFound("project", "proj_ghost")},
	)
	rec := getProjectPreviews(handler, "proj_ghost", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

func TestListProjectPreviewsStoreUnavailable(t *testing.T) {
	t.Parallel()

	const cause = "database unavailable while listing previews"
	handler := listProjectPreviewsHandlerFor(
		previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper),
		nil,
		fakePreviewCreator{listErr: apierr.StoreUnavailable(stderrors.New(cause))},
	)
	rec := getProjectPreviews(handler, "proj_web", "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, cause) {
		t.Fatalf("response leaked store cause %q: %s", cause, body)
	}
}

func TestListProjectPreviewsNilReader(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper), nil, nil)
	rec := getProjectPreviews(handler, "proj_web", "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
}

func TestListProjectPreviewsOpenAPI(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper), nil, fakePreviewCreator{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string   `json:"operationId"`
			Summary        string   `json:"summary"`
			RequiredAction string   `json:"x-required-action"`
			Security       []any    `json:"security"`
			Tags           []string `json:"tags"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	op, ok := doc.Paths["/v1/projects/{project_id}/previews"]["get"]
	if !ok {
		t.Fatalf("GET /v1/projects/{project_id}/previews missing from openapi.json: %s", rec.Body.String())
	}
	if op.OperationID != "listProjectPreviews" {
		t.Errorf("operationId = %q, want listProjectPreviews", op.OperationID)
	}
	if op.Summary != "List project preview environments" {
		t.Errorf("summary = %q, want List project preview environments", op.Summary)
	}
	if op.RequiredAction != string(policy.ActionPreviewRead) {
		t.Errorf("x-required-action = %q, want %s", op.RequiredAction, policy.ActionPreviewRead)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement for authenticated route")
	}
}
