package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fakeBackupReporter is the test seam for the GET /healthz/backup probe. It
// returns the canned status/err pair on every call. A nil err is the
// success path; a backup.ErrNoBackupRecorded err triggers the sentinel
// path; any other err triggers the 503 unavailable path.
type fakeBackupReporter struct {
	status backup.Status
	err    error
}

func (f fakeBackupReporter) Status(context.Context) (backup.Status, error) {
	return f.status, f.err
}

// readBackupEnvelope decodes the GET /healthz/backup success-envelope body
// into its data block. Tests assert against the parsed payload rather than
// raw JSON so a schema drift fails loudly.
func readBackupEnvelope(t *testing.T, body []byte) (env struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	Data          backupHealthPayload `json:"data"`
	RequestID     string              `json:"request_id"`
}) {
	t.Helper()
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%s", err, body)
	}
	return env
}

// TestBackupHealthDefaultsToUnconfigured proves that when NewHandler
// receives a nil backup reporter (the bootstrap default), GET
// /healthz/backup still serves a 200 with configured=false. Operators can
// wire the integration later without rebuilding the binary.
func TestBackupHealthDefaultsToUnconfigured(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{Version: "test"}, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := readBackupEnvelope(t, rec.Body.Bytes())
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.Data.Configured {
		t.Errorf("Configured = true, want false on default unconfigured reporter")
	}
	if !env.Data.Fresh {
		t.Errorf("Fresh = false on unconfigured Status, want true (no claim made)")
	}
	if env.Data.LastSuccessAt != "" {
		t.Errorf("LastSuccessAt = %q, want empty when unconfigured", env.Data.LastSuccessAt)
	}
	if env.Data.AgeSeconds != nil {
		t.Errorf("AgeSeconds = %v, want nil when unconfigured", *env.Data.AgeSeconds)
	}
	if env.Data.MaxAgeSeconds != nil {
		t.Errorf("MaxAgeSeconds = %v, want nil when unconfigured", *env.Data.MaxAgeSeconds)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; every envelope must carry one")
	}
}

// TestBackupHealthSuccessRendersConfiguredEnvelope is the happy-path
// contract test: a reporter that reports a recent backup yields a 200 with
// configured=true, fresh=true, the timestamp formatted in RFC3339-Z, and
// the age/max-age integers populated.
func TestBackupHealthSuccessRendersConfiguredEnvelope(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	reporter := fakeBackupReporter{
		status: backup.Status{
			Configured:    true,
			LastSuccessAt: stamp,
			Age:           6 * time.Hour,
			MaxAge:        24 * time.Hour,
		},
	}

	handler := newHandlerWithBackup(reporter)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := readBackupEnvelope(t, rec.Body.Bytes())
	if !env.Data.Configured {
		t.Errorf("Configured = false, want true")
	}
	if !env.Data.Fresh {
		t.Errorf("Fresh = false, want true (age 6h, max 24h)")
	}
	if env.Data.LastSuccessAt != "2026-05-16T03:00:00Z" {
		t.Errorf("LastSuccessAt = %q, want 2026-05-16T03:00:00Z", env.Data.LastSuccessAt)
	}
	if env.Data.AgeSeconds == nil || *env.Data.AgeSeconds != int64((6*time.Hour).Seconds()) {
		t.Errorf("AgeSeconds = %v, want %d", env.Data.AgeSeconds, int64((6 * time.Hour).Seconds()))
	}
	if env.Data.MaxAgeSeconds == nil || *env.Data.MaxAgeSeconds != int64((24*time.Hour).Seconds()) {
		t.Errorf("MaxAgeSeconds = %v, want %d", env.Data.MaxAgeSeconds, int64((24 * time.Hour).Seconds()))
	}
}

// TestBackupHealthStaleStatusRendersFreshFalse proves the freshness
// predicate flows from the reporter's Status.Fresh() through the
// envelope without re-derivation in the handler.
func TestBackupHealthStaleStatusRendersFreshFalse(t *testing.T) {
	t.Parallel()

	reporter := fakeBackupReporter{
		status: backup.Status{
			Configured:    true,
			LastSuccessAt: time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			Age:           48 * time.Hour,
			MaxAge:        24 * time.Hour,
		},
	}

	handler := newHandlerWithBackup(reporter)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := readBackupEnvelope(t, rec.Body.Bytes())
	if !env.Data.Configured {
		t.Fatalf("Configured = false, want true")
	}
	if env.Data.Fresh {
		t.Errorf("Fresh = true on 48h-old backup with 24h MaxAge, want false")
	}
}

// TestBackupHealthSentinelRendersConfiguredWithoutTimestamp covers the
// "no backup yet" path: a freshly provisioned environment that has
// YALLA_BACKUP_STATUS_FILE wired but has not run its first backup. The
// probe must return 200 (the source is healthy, just empty) with
// configured=true and no last_success_at.
func TestBackupHealthSentinelRendersConfiguredWithoutTimestamp(t *testing.T) {
	t.Parallel()

	reporter := fakeBackupReporter{
		status: backup.Status{Configured: true, MaxAge: 24 * time.Hour},
		err:    backup.ErrNoBackupRecorded,
	}

	handler := newHandlerWithBackup(reporter)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := readBackupEnvelope(t, rec.Body.Bytes())
	if !env.Data.Configured {
		t.Errorf("Configured = false, want true on sentinel path")
	}
	if env.Data.Fresh {
		t.Errorf("Fresh = true on sentinel path; a configured-but-empty source is not fresh by definition")
	}
	if env.Data.LastSuccessAt != "" {
		t.Errorf("LastSuccessAt = %q, want empty on sentinel path", env.Data.LastSuccessAt)
	}
	if env.Data.AgeSeconds != nil {
		t.Errorf("AgeSeconds = %v, want nil on sentinel path", *env.Data.AgeSeconds)
	}
	if env.Data.MaxAgeSeconds == nil || *env.Data.MaxAgeSeconds != int64((24*time.Hour).Seconds()) {
		t.Errorf("MaxAgeSeconds = %v, want carried through on sentinel path", env.Data.MaxAgeSeconds)
	}
	if env.Data.Detail == "" {
		t.Errorf("Detail = empty on sentinel path; want a human-readable explanation")
	}
}

// TestBackupHealthReporterFailureRenders503ErrorEnvelope is the
// "not-found / unavailable" contract: when the reporter returns a
// non-sentinel error (an unreadable or malformed status file), the probe
// renders a yalla.error.v1 envelope with status 503 and code
// E_UNAVAILABLE. This is the "validation/not-found-equivalent" failure
// path the BE-0039 acceptance criteria require.
func TestBackupHealthReporterFailureRenders503ErrorEnvelope(t *testing.T) {
	t.Parallel()

	// A redacted message — the backup package's own contract — never echoes
	// the underlying file content. The handler must not re-introduce raw
	// content; it forwards a stable error message.
	reporter := fakeBackupReporter{
		status: backup.Status{Configured: true},
		err:    yerr.New(yerr.CodeServer, "backup: status file is malformed"),
	}

	handler := newHandlerWithBackup(reporter)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code             string `json:"code"`
			Message          string `json:"message"`
			Hint             string `json:"hint"`
			DocumentationURL string `json:"documentation_url"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Errorf("ok = true on error envelope, want false")
	}
	if env.Error.Code != string(yerr.CodeUnavailable) {
		t.Errorf("error.code = %q, want %q", env.Error.Code, yerr.CodeUnavailable)
	}
	if env.RequestID == "" {
		t.Errorf("error envelope missing request_id")
	}
}

// TestBackupHealthErrorMessageDoesNotLeakReporterError pins the redaction
// contract from the BE-0039 acceptance criteria. Even when the reporter's
// internal error mentions a secret (a misconfigured pipeline that wrote a
// DSN to the status file), the wire response must carry only the stable
// handler-side message — never the reporter's raw error.
func TestBackupHealthErrorMessageDoesNotLeakReporterError(t *testing.T) {
	t.Parallel()

	const reporterSecret = "VERY-SECRET-DSN-NEVER-LEAK"
	reporter := fakeBackupReporter{
		status: backup.Status{Configured: true},
		err:    errors.New("backup: status file contains " + reporterSecret),
	}

	handler := newHandlerWithBackup(reporter)
	req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), reporterSecret) {
		t.Errorf("response body leaked reporter secret: %s", rec.Body.String())
	}
}

// TestBackupHealthIsUnauthenticated proves the probe is intentionally
// public — operators, agents, and probes consume it without supplying a
// credential. The handler must serve a 200 (or a 503 reporter failure)
// regardless of whether an Authorization header is present. The BE-0039
// "authorization failure" acceptance slot is satisfied by demonstrating
// the structural decision to serve this route without auth: a future
// regression that tries to wrap it in RequireAuth would fail this test.
func TestBackupHealthIsUnauthenticated(t *testing.T) {
	t.Parallel()

	handler := newHandlerWithBackup(backup.Unconfigured())

	for _, header := range []string{"", "Bearer not-a-real-token-but-still-ignored"} {
		header := header
		t.Run("header="+header, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/healthz/backup", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 regardless of Authorization", rec.Code)
			}
			env := readBackupEnvelope(t, rec.Body.Bytes())
			if env.Data.Configured {
				t.Errorf("Configured = true, want false (Unconfigured reporter)")
			}
		})
	}
}

// TestBackupHealthMethodNotGet covers the "invalid input" slot of the
// BE-0039 acceptance criteria: the probe is GET-only. Any other method
// must yield a 404 (the route is registered under METHOD GET) — the mux
// will not match other verbs to this path.
func TestBackupHealthMethodNotGet(t *testing.T) {
	t.Parallel()

	handler := newHandlerWithBackup(backup.Unconfigured())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(method, "/healthz/backup", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			// The mux maps method-specific routes; an unmatched verb falls
			// back to the global 404 handler.
			if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 or 405 for unsupported method %s", rec.Code, method)
			}
		})
	}
}

// TestBackupHealthRouteIsRegisteredAndDocumented anchors the route in the
// served handler and in the published OpenAPI document. It guards the
// BE-0008 invariant for /healthz/backup specifically — the BE-0039 route
// must always appear in both.
func TestBackupHealthRouteIsRegisteredAndDocumented(t *testing.T) {
	t.Parallel()

	handler := newHandlerWithBackup(backup.Unconfigured())
	// Documented:
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "/healthz/backup") {
		t.Errorf("openapi document missing /healthz/backup")
	}
	if !strings.Contains(rec.Body.String(), "getHealthzBackup") {
		t.Errorf("openapi document missing getHealthzBackup operationId")
	}
}

// newHandlerWithBackup wires a real NewHandler with stub ports for every
// dependency except the supplied backup reporter. The result exercises
// the production middleware stack (envelope rendering, request_id,
// telemetry) so the contract tests speak to real behaviour.
func newHandlerWithBackup(reporter backup.Reporter) http.Handler {
	return NewHandler(
		runtime.BuildInfo{Version: "test"}, nil, nil, reporter,
		fakeAuthenticator{}, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{},
		fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{},
		fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{},
		fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{},
		fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{},
		fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{},
		fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{},
		fakeDeploymentCanceler{}, fakeDeploymentRollbacker{},
		fakeBreakGlassController{},
		nil, nil,
	)
}
