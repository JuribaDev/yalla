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
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeJobReader struct {
	jobs      []store.ProvisioningJob
	err       error
	callCount *int
	got       *store.ListProvisioningJobsInput
}

func (f fakeJobReader) ListJobs(_ context.Context, in store.ListProvisioningJobsInput) ([]store.ProvisioningJob, error) {
	if f.callCount != nil {
		*f.callCount = *f.callCount + 1
	}
	if f.got != nil {
		*f.got = in
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.jobs, nil
}

func newJobsTestHandler(a Authenticator, reader JobReader) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{},
		fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{},
		fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{},
		fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{},
		fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{},
		fakeBreakGlassController{}, nil, nil, reader)
}

func TestListJobsSuccessFiltersByPrincipalOrganizationAndQueryScope(t *testing.T) {
	t.Parallel()
	var got store.ListProvisioningJobsInput
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	reader := fakeJobReader{
		got: &got,
		jobs: []store.ProvisioningJob{{
			ID:             "job_alpha",
			OrganizationID: "org_jobs",
			JobType:        "ensure_project",
			ProjectID:      "proj_jobs",
			Status:         store.JobStatusQueued,
			MaxAttempts:    20,
			NextRunAt:      now,
			Payload:        map[string]string{"project_id": "proj_jobs"},
			RequestID:      "req_job",
			CorrelationID:  "corr_job",
			CreatedAt:      now,
			UpdatedAt:      now,
		}},
	}
	h := newJobsTestHandler(fakeAuthenticator{identity: auth.Identity{Principal: policy.Principal{
		ID: "usr_jobs", Kind: domain.KindUser, OrganizationID: "org_jobs", Role: policy.RoleViewer,
	}}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs?project_id=proj_jobs&status=queued&limit=25", nil)
	req.Header.Set("Authorization", "Bearer test")
	req.Header.Set("X-Request-Id", "req_jobs_list")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "org_jobs" || got.ProjectID != "proj_jobs" || got.Status != store.JobStatusQueued || got.Limit != 25 {
		t.Fatalf("reader input = %+v, want org/project/status/limit from principal and query", got)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			Jobs []struct {
				ID             string            `json:"id"`
				OrganizationID string            `json:"organization_id"`
				JobType        string            `json:"job_type"`
				ProjectID      string            `json:"project_id,omitempty"`
				Status         string            `json:"status"`
				Payload        map[string]string `json:"payload"`
				RequestID      string            `json:"request_id"`
			} `json:"jobs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_jobs_list" {
		t.Fatalf("envelope = %+v", env)
	}
	if len(env.Data.Jobs) != 1 || env.Data.Jobs[0].ID != "job_alpha" || env.Data.Jobs[0].Payload["project_id"] != "proj_jobs" {
		t.Fatalf("jobs payload = %+v", env.Data.Jobs)
	}
}

func TestListJobsRejectsInvalidQueryBeforeReader(t *testing.T) {
	t.Parallel()
	calls := 0
	h := newJobsTestHandler(fakeAuthenticator{identity: auth.Identity{Principal: policy.Principal{
		ID: "usr_jobs", Kind: domain.KindUser, OrganizationID: "org_jobs", Role: policy.RoleViewer,
	}}}, fakeJobReader{callCount: &calls})

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs?limit=not-a-number", nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("reader call count = %d, want 0", calls)
	}
	decodeError(t, rec, string(yerr.CodeInvalidInput))
}

func TestListJobsUnauthenticated(t *testing.T) {
	t.Parallel()
	calls := 0
	h := newJobsTestHandler(fakeAuthenticator{err: auth.ErrNoCredentials}, fakeJobReader{callCount: &calls})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/jobs", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("reader call count = %d, want 0", calls)
	}
	decodeError(t, rec, string(yerr.CodeAuth))
}

func TestListJobsProjectScopedGrantCannotReadOrgLevelList(t *testing.T) {
	t.Parallel()
	calls := 0
	principal := policy.Principal{
		ID: "sa_jobs", Kind: domain.KindServiceAccount, OrganizationID: "org_jobs",
		Grants: []policy.Grant{{Scope: policy.Scope{OrganizationID: "org_jobs", ProjectID: "proj_jobs"}, Role: policy.RoleViewer}},
	}
	h := newJobsTestHandler(fakeAuthenticator{identity: auth.Identity{Principal: principal}}, fakeJobReader{callCount: &calls})

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("reader call count = %d, want 0", calls)
	}
	decodeError(t, rec, string(yerr.CodeForbidden))
}

func TestListJobsReaderNotFoundPropagatesEnvelope(t *testing.T) {
	t.Parallel()
	h := newJobsTestHandler(fakeAuthenticator{identity: auth.Identity{Principal: policy.Principal{
		ID: "usr_jobs", Kind: domain.KindUser, OrganizationID: "org_jobs", Role: policy.RoleViewer,
	}}}, fakeJobReader{err: apierr.NotFound("project", "proj_missing")})

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs?project_id=proj_missing", nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}
