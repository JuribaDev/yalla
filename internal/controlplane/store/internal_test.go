package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are white-box unit tests for the pure decision logic in the store
// package — input validation, error mapping, constraint classification, and
// constructor guards. They need no database, so they run on every
// `go test ./...` regardless of whether Postgres is available.

func validInput() CreateProjectInput {
	return CreateProjectInput{
		OrganizationID: domain.MustNewID(domain.KindOrganization).String(),
		ProjectID:      domain.MustNewID(domain.KindProject).String(),
		Slug:           "web-api",
		DisplayName:    "Web API",
	}
}

func TestValidateCreateProjectInputAccepted(t *testing.T) {
	t.Parallel()

	in := validInput()
	got, err := validateCreateProjectInput(in)
	if err != nil {
		t.Fatalf("validateCreateProjectInput(valid) error = %v", err)
	}
	if got.ID != in.ProjectID || got.OrganizationID != in.OrganizationID {
		t.Errorf("validateCreateProjectInput ids = %q/%q, want %q/%q",
			got.ID, got.OrganizationID, in.ProjectID, in.OrganizationID)
	}
	if got.Slug != "web-api" || got.DisplayName != "Web API" {
		t.Errorf("validateCreateProjectInput = %+v, want slug/name web-api/Web API", got)
	}
}

func TestStoreObserveSlowQueryEmitsLogAndMetricWithSafeCorrelation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	metrics := telemetry.NewSlowQueryMetrics()
	s := &Store{
		logger:             logger,
		slowQueryThreshold: 100 * time.Millisecond,
		slowQueryMetrics:   metrics,
	}
	ctx := telemetry.WithCorrelation(context.Background(), telemetry.Correlation{
		RequestID:     "req_store_slow_query",
		CorrelationID: "corr_store_slow_query",
	})
	ctx = telemetry.WithLogFields(ctx)
	telemetry.SetOrgID(ctx, "org_store_slow")
	telemetry.SetPrincipalID(ctx, "usr_store_slow")
	telemetry.SetResource(ctx, "project", "proj_store_slow")
	telemetry.SetJobID(ctx, "job_store_slow")

	s.observeQuery(ctx, "read", "SELECT * FROM api_keys WHERE secret_hash = 'super-secret-token'", 150*time.Millisecond, nil)

	raw := buf.String()
	if raw == "" {
		t.Fatal("slow query log was not emitted")
	}
	if strings.Contains(raw, "super-secret-token") || strings.Contains(raw, "api_keys") || strings.Contains(raw, "secret_hash") {
		t.Fatalf("slow query log leaked SQL text or secret material: %s", raw)
	}
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode slow query log: %v", err)
	}
	if record["msg"] != "store slow query observed" || record["operation"] != "read" || record["query_kind"] != "select" || record["outcome"] != "success" {
		t.Fatalf("slow query log record = %+v, want low-cardinality operation/query_kind/outcome", record)
	}
	if record["request_id"] != "req_store_slow_query" || record["correlation_id"] != "corr_store_slow_query" ||
		record["org_id"] != "org_store_slow" || record["principal_id"] != "usr_store_slow" ||
		record["resource_kind"] != "project" || record["resource_id"] != "proj_store_slow" ||
		record["job_id"] != "job_store_slow" {
		t.Fatalf("slow query log correlation fields = %+v", record)
	}

	snapshot := metrics.Snapshot()
	got := findStoreSlowQueryMetric(snapshot.Series, "read", "select", "success")
	if got == nil {
		t.Fatalf("missing slow query metric: %+v", snapshot.Series)
	}
	if got.RequestID != "req_store_slow_query" || got.OrganizationID != "org_store_slow" || got.ResourceID != "proj_store_slow" {
		t.Fatalf("slow query metric hints = %+v, want request/org/resource hints", *got)
	}
}

func TestStoreObserveQuerySkipsFastQueriesAndRecordsFailures(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	metrics := telemetry.NewSlowQueryMetrics()
	s := &Store{
		logger:             slog.New(slog.NewJSONHandler(&buf, nil)),
		slowQueryThreshold: 100 * time.Millisecond,
		slowQueryMetrics:   metrics,
	}

	s.observeQuery(context.Background(), "write", "UPDATE projects SET display_name = $1", 99*time.Millisecond, nil)
	if buf.Len() != 0 {
		t.Fatalf("fast query produced log: %s", buf.String())
	}
	if got := metrics.Snapshot().TotalQueries; got != 0 {
		t.Fatalf("fast query metric count = %d, want 0", got)
	}

	s.observeQuery(context.Background(), "write", "UPDATE projects SET display_name = $1", 101*time.Millisecond, errors.New("postgres://user:secret@db/yalla"))
	raw := buf.String()
	if strings.Contains(raw, "postgres://user:secret@db/yalla") {
		t.Fatalf("slow query failure log leaked error detail: %s", raw)
	}
	got := findStoreSlowQueryMetric(metrics.Snapshot().Series, "write", "update", "error")
	if got == nil {
		t.Fatalf("missing slow query failure metric: %+v", metrics.Snapshot().Series)
	}
}

func findStoreSlowQueryMetric(metrics []telemetry.SlowQueryMetric, operation, queryKind, outcome string) *telemetry.SlowQueryMetric {
	for i := range metrics {
		if metrics[i].Operation == operation && metrics[i].QueryKind == queryKind && metrics[i].Outcome == outcome {
			return &metrics[i]
		}
	}
	return nil
}

func TestValidateCreateProjectInputTrimsWhitespace(t *testing.T) {
	t.Parallel()

	in := validInput()
	in.OrganizationID = "  " + in.OrganizationID + "  "
	in.DisplayName = "  Web API  "
	got, err := validateCreateProjectInput(in)
	if err != nil {
		t.Fatalf("validateCreateProjectInput(padded) error = %v", err)
	}
	if strings.TrimSpace(got.OrganizationID) != got.OrganizationID {
		t.Errorf("organization_id not trimmed: %q", got.OrganizationID)
	}
	if got.DisplayName != "Web API" {
		t.Errorf("display_name not trimmed: %q", got.DisplayName)
	}
}

func TestValidateCreateProjectInputRejectsEachField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(*CreateProjectInput)
		wantField string
	}{
		{"bad organization id", func(in *CreateProjectInput) { in.OrganizationID = "not-an-id" }, "organization_id"},
		{"organization id of wrong kind", func(in *CreateProjectInput) {
			in.OrganizationID = domain.MustNewID(domain.KindProject).String()
		}, "organization_id"},
		{"bad project id", func(in *CreateProjectInput) { in.ProjectID = "nope" }, "project_id"},
		{"project id of wrong kind", func(in *CreateProjectInput) {
			in.ProjectID = domain.MustNewID(domain.KindService).String()
		}, "project_id"},
		{"empty slug", func(in *CreateProjectInput) { in.Slug = "" }, "slug"},
		{"non-canonical slug", func(in *CreateProjectInput) { in.Slug = "Not A Slug!" }, "slug"},
		{"empty display name", func(in *CreateProjectInput) { in.DisplayName = "   " }, "display_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := validInput()
			tc.mutate(&in)
			_, err := validateCreateProjectInput(in)
			if err == nil {
				t.Fatalf("validateCreateProjectInput(%s) error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %s, want %s", ye.Code, yerr.CodeValidation)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok {
				t.Fatalf("apierr.ViolationsOf returned ok=false for %v", err)
			}
			found := false
			for _, v := range violations {
				if v.Field == tc.wantField {
					found = true
				}
			}
			if !found {
				t.Errorf("violations %+v do not name field %q", violations, tc.wantField)
			}
		})
	}
}

func TestValidateCreateProjectInputReportsAllViolations(t *testing.T) {
	t.Parallel()

	_, err := validateCreateProjectInput(CreateProjectInput{})
	if err == nil {
		t.Fatal("validateCreateProjectInput(zero) error = nil, want InvalidInput")
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("apierr.ViolationsOf returned ok=false for %v", err)
	}
	if len(violations) != 4 {
		t.Errorf("got %d violations, want 4 (one per field): %+v", len(violations), violations)
	}
}

func TestIsConstraintViolation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unique violation", &pgconn.PgError{Code: "23505"}, true},
		{"foreign key violation", &pgconn.PgError{Code: "23503"}, true},
		{"check violation", &pgconn.PgError{Code: "23514"}, true},
		{"not-null violation", &pgconn.PgError{Code: "23502"}, true},
		{"connection failure", &pgconn.PgError{Code: "08006"}, false},
		{"plain error", errors.New("boom"), false},
		{"nil error", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isConstraintViolation(tc.err); got != tc.want {
				t.Errorf("isConstraintViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestMapWriteError(t *testing.T) {
	t.Parallel()

	if got := mapWriteError(nil, "conflict"); got != nil {
		t.Errorf("mapWriteError(nil) = %v, want nil", got)
	}

	conflict := mapWriteError(&pgconn.PgError{Code: "23505"}, "slug already taken")
	if ye := yerr.From(conflict); ye.Code != yerr.CodeConflict {
		t.Errorf("constraint violation mapped to %s, want %s", ye.Code, yerr.CodeConflict)
	}

	unavailable := mapWriteError(errors.New("dial tcp: connection refused"), "slug already taken")
	if ye := yerr.From(unavailable); ye.Code != yerr.CodeDBUnavailable {
		t.Errorf("driver failure mapped to %s, want %s", ye.Code, yerr.CodeDBUnavailable)
	}
}

// TestMapWriteErrorDoesNotLeakCause proves the error taxonomy keeps a raw
// driver cause — which may carry a connection string, host, or credential —
// out of the user-facing message. The cause stays reachable via Unwrap for
// server-side logging only.
func TestMapWriteErrorDoesNotLeakCause(t *testing.T) {
	t.Parallel()

	const secret = "postgres://yalla:sup3r-s3cret@db.internal:5432/yalla"
	cause := errors.New("dial " + secret + ": connection refused")

	mapped := mapWriteError(cause, "a project with this slug already exists in the organization")
	if strings.Contains(mapped.Error(), secret) {
		t.Fatalf("mapped error message leaked the driver cause: %q", mapped.Error())
	}
	if strings.Contains(mapped.Error(), "connection refused") {
		t.Errorf("mapped error message echoed the raw driver text: %q", mapped.Error())
	}
	if !errors.Is(mapped, cause) {
		t.Error("mapped error no longer unwraps to its cause; server-side logging would lose it")
	}
}

func TestNewStoreRejectsNilPool(t *testing.T) {
	t.Parallel()

	if _, err := New(nil, nil); err == nil {
		t.Fatal("New(nil pool) error = nil, want an error")
	}
}

func TestNewProjectServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	s := &Store{}
	repo := NewProjectRepository()
	authz := nopAuthorizer{}
	quota := nopQuotaReserver{}
	jobs := nopJobEnqueuer{}
	audit := nopAuditAppender{}

	cases := []struct {
		name string
		call func() (*ProjectService, error)
	}{
		{"nil store", func() (*ProjectService, error) {
			return NewProjectService(nil, repo, authz, quota, jobs, audit)
		}},
		{"nil repo", func() (*ProjectService, error) {
			return NewProjectService(s, nil, authz, quota, jobs, audit)
		}},
		{"nil authorizer", func() (*ProjectService, error) {
			return NewProjectService(s, repo, nil, quota, jobs, audit)
		}},
		{"nil quota", func() (*ProjectService, error) {
			return NewProjectService(s, repo, authz, nil, jobs, audit)
		}},
		{"nil jobs", func() (*ProjectService, error) {
			return NewProjectService(s, repo, authz, quota, nil, audit)
		}},
		{"nil audit", func() (*ProjectService, error) {
			return NewProjectService(s, repo, authz, quota, jobs, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.call(); err == nil {
				t.Errorf("NewProjectService(%s) error = nil, want an error", tc.name)
			}
		})
	}

	if _, err := NewProjectService(s, repo, authz, quota, jobs, audit); err != nil {
		t.Errorf("NewProjectService(all set) error = %v, want nil", err)
	}
}

// nop port implementations let the constructor guard test exercise
// NewProjectService without a database or behaviour fakes.
type nopAuthorizer struct{}

func (nopAuthorizer) Authorize(context.Context, Querier, string, string) error { return nil }

type nopQuotaReserver struct{}

func (nopQuotaReserver) Reserve(context.Context, *Tx, string, string) error { return nil }

func (nopQuotaReserver) ReserveAmount(context.Context, *Tx, string, string, int64) error {
	return nil
}

type nopJobEnqueuer struct{}

func (nopJobEnqueuer) Enqueue(context.Context, *Tx, string, string, string) error { return nil }

type nopAuditAppender struct{}

func (nopAuditAppender) Append(context.Context, *Tx, AuditEvent) (AuditEvent, error) {
	return AuditEvent{}, nil
}
