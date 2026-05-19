package telemetry

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// logRecord is the decoded shape of a single per-request structured log line.
type logRecord struct {
	Time          string `json:"time"`
	Level         string `json:"level"`
	Msg           string `json:"msg"`
	Method        string `json:"method"`
	Route         string `json:"route"`
	Target        string `json:"target"`
	Status        int    `json:"status"`
	StatusClass   string `json:"status_class"`
	Outcome       string `json:"outcome"`
	ErrorCode     string `json:"error_code"`
	LatencyMS     int64  `json:"latency_ms"`
	Bytes         int    `json:"bytes"`
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	OrgID         string `json:"org_id"`
	PrincipalID   string `json:"principal_id"`
	ResourceKind  string `json:"resource_kind"`
	ResourceID    string `json:"resource_id"`
	JobID         string `json:"job_id"`
}

// serveLogged runs handler through Correlate -> RequestLogging at the given
// level, against the given request, and returns the response recorder, the
// decoded log record, and the raw log buffer contents.
func serveLogged(t *testing.T, level slog.Level, req *http.Request, handler http.Handler) (*httptest.ResponseRecorder, logRecord, string) {
	t.Helper()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level}))
	wrapped := Correlate(RequestLogging(logger)(handler))

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		return rec, logRecord{}, ""
	}
	var record logRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatalf("decode log record %q: %v", raw, err)
	}
	return rec, record, raw
}

// statusHandler returns a handler that writes the given status code with a
// small body so the recorder captures both status and byte count.
func statusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("body"))
	})
}

func TestRequestLoggingEmitsOneRecordPerOutcome(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		status    int
		wantLevel string
	}{
		{"success", http.StatusOK, "INFO"},
		{"validation failure", http.StatusBadRequest, "WARN"},
		{"authorization failure", http.StatusUnauthorized, "WARN"},
		{"forbidden", http.StatusForbidden, "WARN"},
		{"not found", http.StatusNotFound, "WARN"},
		{"server error", http.StatusInternalServerError, "ERROR"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/widgets", nil)
			rec, record, _ := serveLogged(t, slog.LevelDebug, req, statusHandler(tc.status))

			if rec.Code != tc.status {
				t.Fatalf("response status = %d, want %d", rec.Code, tc.status)
			}
			if record.Level != tc.wantLevel {
				t.Errorf("log level = %q, want %q", record.Level, tc.wantLevel)
			}
			if record.Status != tc.status {
				t.Errorf("log status = %d, want %d", record.Status, tc.status)
			}
			if record.StatusClass != statusClass(tc.status) {
				t.Errorf("log status_class = %q, want %q", record.StatusClass, statusClass(tc.status))
			}
			wantOutcome := "success"
			if tc.status >= http.StatusBadRequest {
				wantOutcome = "failure"
			}
			if record.Outcome != wantOutcome {
				t.Errorf("log outcome = %q, want %q", record.Outcome, wantOutcome)
			}
			if record.Method != http.MethodGet {
				t.Errorf("log method = %q, want GET", record.Method)
			}
			if record.Route != "/widgets" {
				t.Errorf("log route = %q, want /widgets", record.Route)
			}
			if record.Bytes != len("body") {
				t.Errorf("log bytes = %d, want %d", record.Bytes, len("body"))
			}
			if record.Time == "" {
				t.Error("log record is missing a timestamp")
			}
			if record.LatencyMS < 0 {
				t.Errorf("log latency_ms = %d, want >= 0", record.LatencyMS)
			}
			// Correlate runs outermost, so every record carries a request_id.
			if !SafeID(record.RequestID) {
				t.Errorf("log request_id = %q, want a SafeID value", record.RequestID)
			}
			if record.CorrelationID == "" {
				t.Error("log correlation_id is empty")
			}
			if record.RequestID != rec.Header().Get(HeaderRequestID) {
				t.Errorf("log request_id = %q, want it to match the %s response header %q",
					record.RequestID, HeaderRequestID, rec.Header().Get(HeaderRequestID))
			}
		})
	}
}

func TestRequestLoggingIncludesStructuredErrorCodeFromEnvelope(t *testing.T) {
	t.Parallel()

	const secret = "postgres://operator:supersecret@db/yalla"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetOrgID(r.Context(), "org_error_logs")
		SetPrincipalID(r.Context(), "usr_error_logs")
		SetResource(r.Context(), "project", "proj_error_logs")
		SetJobID(r.Context(), "job_error_logs")
		apienvelope.WriteError(w, RequestID(r.Context()), apierr.StoreUnavailable(stderrors.New(secret)))
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/projects/proj_error_logs?token=secret-query-token", nil)
	rec, record, raw := serveLogged(t, slog.LevelDebug, req, handler)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if record.Level != "ERROR" {
		t.Errorf("level = %q, want ERROR for dependency failure", record.Level)
	}
	if record.ErrorCode != string(yerr.CodeDBUnavailable) {
		t.Errorf("error_code = %q, want %s", record.ErrorCode, yerr.CodeDBUnavailable)
	}
	if record.Outcome != "failure" || record.StatusClass != "5xx" {
		t.Errorf("outcome/status_class = %q/%q, want failure/5xx", record.Outcome, record.StatusClass)
	}
	if record.OrgID != "org_error_logs" || record.PrincipalID != "usr_error_logs" {
		t.Errorf("identity fields = org:%q principal:%q", record.OrgID, record.PrincipalID)
	}
	if record.ResourceKind != "project" || record.ResourceID != "proj_error_logs" {
		t.Errorf("resource fields = kind:%q id:%q", record.ResourceKind, record.ResourceID)
	}
	if record.JobID != "job_error_logs" {
		t.Errorf("job_id = %q, want job_error_logs", record.JobID)
	}
	if strings.Contains(raw, "supersecret") || strings.Contains(raw, "secret-query-token") {
		t.Fatalf("structured error log leaked a secret: %s", raw)
	}
}

func TestRequestLoggingRedactsSecrets(t *testing.T) {
	t.Parallel()

	const headerSecret = "Bearer sk-live-supersecrettoken"
	const querySecret = "topsecretquerytoken"
	const bodySecret = "topsecretbodytoken"

	req := httptest.NewRequest(http.MethodPost, "/login?token="+querySecret,
		strings.NewReader(`{"password":"`+bodySecret+`"}`))
	req.Header.Set("Authorization", headerSecret)
	req.Header.Set("Cookie", "session=topsecretcookievalue")

	_, record, raw := serveLogged(t, slog.LevelInfo, req, statusHandler(http.StatusOK))

	// Headers and bodies are never logged, so their secrets cannot appear.
	for _, secret := range []string{
		headerSecret, "sk-live-supersecrettoken", "topsecretcookievalue", bodySecret,
	} {
		if strings.Contains(raw, secret) {
			t.Errorf("log leaked a secret %q: %s", secret, raw)
		}
	}
	// The request target is logged, but a token-bearing query param is
	// scrubbed by the redactor before it reaches the record.
	if strings.Contains(raw, querySecret) {
		t.Errorf("log leaked a query-string secret %q: %s", querySecret, raw)
	}
	if !strings.Contains(record.Target, "[REDACTED]") {
		t.Errorf("log target = %q, want the token query param redacted", record.Target)
	}
}

func TestRequestLoggingIncludesOrgAndPrincipalWhenKnown(t *testing.T) {
	t.Parallel()

	enriched := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate the auth/policy layers resolving the principal and org
		// partway through request handling.
		SetPrincipalID(r.Context(), "principal_123")
		SetOrgID(r.Context(), "org_456")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	_, record, _ := serveLogged(t, slog.LevelInfo, req, enriched)

	if record.OrgID != "org_456" {
		t.Errorf("log org_id = %q, want org_456", record.OrgID)
	}
	if record.PrincipalID != "principal_123" {
		t.Errorf("log principal_id = %q, want principal_123", record.PrincipalID)
	}
}

func TestRequestLoggingOmitsUnknownOrgAndPrincipal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/anon", nil)
	_, _, raw := serveLogged(t, slog.LevelInfo, req, statusHandler(http.StatusOK))

	// An unauthenticated request must not emit empty-valued org/principal
	// fields — the keys are absent entirely when the values are unknown.
	if strings.Contains(raw, "org_id") {
		t.Errorf("log includes org_id for an unauthenticated request: %s", raw)
	}
	if strings.Contains(raw, "principal_id") {
		t.Errorf("log includes principal_id for an unauthenticated request: %s", raw)
	}
}

func TestRequestLoggingRespectsConfiguredLevel(t *testing.T) {
	t.Parallel()

	// At ERROR threshold an INFO success record is suppressed entirely,
	// proving the log level is controlled by configuration (YALLA_LOG_LEVEL
	// flows into the handler level) with no code change.
	req := httptest.NewRequest(http.MethodGet, "/quiet", nil)
	_, _, raw := serveLogged(t, slog.LevelError, req, statusHandler(http.StatusOK))
	if raw != "" {
		t.Errorf("INFO record emitted under an ERROR threshold: %s", raw)
	}

	// A 5xx outcome still logs at ERROR, so it survives the same threshold.
	req = httptest.NewRequest(http.MethodGet, "/loud", nil)
	_, record, raw := serveLogged(t, slog.LevelError, req, statusHandler(http.StatusBadGateway))
	if raw == "" {
		t.Fatal("ERROR record suppressed under an ERROR threshold")
	}
	if record.Level != "ERROR" || record.Status != http.StatusBadGateway {
		t.Errorf("record = %+v, want level ERROR status 502", record)
	}
}

func TestRequestLoggingNilLoggerIsSafe(t *testing.T) {
	t.Parallel()

	// A nil logger must not panic: request logging is simply disabled.
	handler := RequestLogging(nil)(statusHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequestLoggingDefaultsStatusWhenHandlerNeverSetsIt(t *testing.T) {
	t.Parallel()

	// A handler that writes a body without an explicit WriteHeader still
	// produces a 200 in the log, matching net/http's own default.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	req := httptest.NewRequest(http.MethodGet, "/implicit", nil)
	_, record, _ := serveLogged(t, slog.LevelInfo, req, handler)

	if record.Status != http.StatusOK {
		t.Errorf("log status = %d, want 200 for an implicit write", record.Status)
	}
}
