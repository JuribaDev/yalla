package httpapi

import (
	"bytes"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

// Public-API contract coverage for GET /v1/services/{service_id}/backups
// (BE-0248).
//
// service_backups_test.go already proves the 200 success envelope, the
// stable yalla.output.v1 / yalla.error.v1 schema versions, request_id
// propagation, OpenAPI operation registration, empty-list shape,
// unauthenticated / not-found / dependency-failure rejection paths,
// tenant-scoped reader inputs, and the missing-reader wiring guard.
// service_backups_policy_test.go pins the full role x tenant x grant-scope
// authorization matrix for backup.read. This file closes the remaining
// public contract criteria:
//
//   - response data is written through http.ResponseWriter, never process
//     stdout/stderr;
//   - structured request logs redact bearer credentials on both success and
//     authorization-failure paths;
//   - dependency causes stay server-side and never leak through the error
//     envelope.
//
// The endpoint accepts one opaque {service_id} path parameter and no request
// body or query parameters. Invalid or cross-tenant service identifiers
// surface through the store-backed reader as deterministic 404s, which the
// base test file pins.

const listServiceBackupsContractSecret = "yk_live_supersecret_service_backups_get_DEADBEEF0123456789"

func listServiceBackupsHandlerForWithLogger(
	id auth.Identity, authErr error, reader ServiceBackupReader, logger *slog.Logger,
) http.Handler {
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
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{},
		fakeServiceLogReader{}, fakeServiceMetricsReader{},
		fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{},
		reader, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{},
		fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{},
		fakeBreakGlassController{}, logger, nil)
}

func TestListServiceBackupsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps process-global stdout/stderr.

	backups := canonicalServiceBackups()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	handler := listServiceBackupsHandlerForWithLogger(
		ownerIdentity("org_acme", "usr_owner"), nil,
		fakeServiceBackupReader{backups: backups}, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = listServiceBackups(handler, backups.ServiceID, listServiceBackupsContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing; response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing; response data must go through the ResponseWriter", stderr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListServiceBackups(t, rec)
	if len(env.Data.Backups) != len(backups.Backups) {
		t.Fatalf("backups = %+v, want exactly the seeded rows", env.Data.Backups)
	}
	if env.Data.Backups[0].ID != "sbkp_alpha" {
		t.Errorf("backups[0].id = %q, want sbkp_alpha; payload must be carried by the response body", env.Data.Backups[0].ID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestListServiceBackupsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	allowed := ownerIdentity("org_acme", "usr_owner")
	denied := ownerIdentity("org_acme", "usr_revoked")
	denied.Principal.Disabled = true

	successReader := fakeServiceBackupReader{backups: canonicalServiceBackups()}
	denyReader := fakeServiceBackupReader{err: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     ServiceBackupReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
			reader:     denyReader,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := listServiceBackupsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := listServiceBackups(handler, "svc_canonical_backups", listServiceBackupsContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listServiceBackupsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listServiceBackupsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

func TestListServiceBackupsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeServiceBackupReader{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listServiceBackupsHandlerFor(
		ownerIdentity("org_acme", "usr_owner"), nil, reader,
	)

	rec := listServiceBackups(handler, "svc_canonical_backups", listServiceBackupsContractSecret)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_DB_UNAVAILABLE")
	if env.Error.Message == "" {
		t.Error("error.message is empty, want a stable generic message")
	}
	if strings.Contains(rec.Body.String(), cause) {
		t.Errorf("error envelope leaked the wrapped dependency cause %q: %s", cause, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("error envelope leaked the datastore address: %s", rec.Body.String())
	}
}
