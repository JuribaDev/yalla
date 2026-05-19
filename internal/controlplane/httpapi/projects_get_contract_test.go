package httpapi

import (
	"bytes"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// Public-API contract coverage for GET /v1/projects/{project_id} (BE-0125).
//
// projects_get_test.go already proves the 200 success envelope, the stable
// yalla.output.v1 / yalla.error.v1 schema versions, the request_id
// propagation, the OpenAPI operation registration, the unauthenticated /
// invalid-credentials / disabled-principal / cross-tenant / not-found /
// dependency-failure rejection space, the CapRead role admission matrix,
// the grant-only acceptance/rejection pair, and the "reader receives
// exactly the authenticated principal's home organization id together
// with the {project_id} path parameter" wiring invariant. This file
// closes the remaining contract-test criteria those tests do not assert
// directly:
//
//   - the HTTP server writes response data only through the http.ResponseWriter
//     — never to the process stdout/stderr;
//   - the per-request structured log stays redacted, on the success path AND
//     the authorization-failure path, so a bearer credential is never logged
//     and never echoed back to the client;
//   - an error envelope built from a wrapped dependency cause never leaks
//     that cause onto the wire, including bare datastore addresses the
//     cause string carries.
//
// GET /v1/projects/{project_id} has no request body and no query parameters:
// its only input is the {project_id} path parameter, an opaque identifier.
// There is therefore no syntactic request to reject as "invalid input"
// beyond the rejection paths already covered in projects_get_test.go (a
// malformed or unknown id surfaces as the typed NotFound the reader
// produces; a cross-tenant id reaches the persistence layer with the
// principal's home organization id and is rejected as a deterministic 404
// by the tenant-scoped repository query). Structural twin of
// organizations_get_contract_test.go (BE-0053) and
// projects_list_contract_test.go (BE-0119), adapted to the GET single-
// project request shape ({project_id} path parameter, ProjectReader port).

// getProjectContractSecret is a recognisable bearer credential used by the
// redaction tests: if any byte of it reaches a log record or a response body,
// the test fails.
const getProjectContractSecret = "yk_live_supersecret_projects_get_DEADBEEF0123456789"

// TestGetProjectServerWritesResponseDataOnlyToResponseWriter proves the
// HTTP server renders the response through the http.ResponseWriter alone:
// a served GET /v1/projects/{project_id} writes nothing to the process
// stdout/stderr, and the project payload is carried by the response body.
// The structured logger is the only sanctioned out-of-band writer and it
// goes to its own buffer, never to the process streams.
func TestGetProjectServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeProjectReader{
		project: seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, created, updated),
	}
	handler := listProjectsHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getProjectByID(handler, "prj_acme_alpha", getProjectContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing — response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing — response data must go through the ResponseWriter", stderr)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProject(t, rec)
	if env.Data.Project.ProjectID != "prj_acme_alpha" {
		t.Errorf("project_id = %q, want prj_acme_alpha — the data must be carried by the response body",
			env.Data.Project.ProjectID)
	}
	// The structured logger is the only sanctioned writer, and it goes to its
	// own sink — never to the response and never to the process streams.
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

// TestGetProjectRequestLogRedactsBearerToken proves the per-request
// structured log never carries the bearer credential — on the happy path and
// on the authorization-failure path alike. Headers are not logged at all;
// this test pins that contract so a future logging change cannot quietly
// start leaking credentials. The response body is also asserted credential-
// free, closing the symmetric leak axis (an error envelope must never echo
// the bearer back to the client either).
func TestGetProjectRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	owner := orgPrincipal("usr_ada", "org_acme", policy.RoleViewer)
	disabled := orgPrincipal("usr_revoked", "org_acme", policy.RoleOwner)
	disabled.Disabled = true

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	successReader := fakeProjectReader{
		project: seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, created, updated),
	}
	// The disabled-principal request must never reach the reader. A reader
	// that would error if invoked proves the deny path short-circuits at
	// policy, so any logged "reader error" can't be the leak source.
	denyReader := fakeProjectReader{getErr: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     ProjectReader
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: owner, Method: auth.MethodSession},
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: disabled, Method: auth.MethodSession},
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
			handler := listProjectsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getProjectByID(handler, "prj_acme_alpha", getProjectContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getProjectContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getProjectContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

// TestGetProjectErrorEnvelopeDoesNotLeakDependencyCause proves a reader-
// store outage surfaces as a typed 5xx whose error envelope carries a
// stable generic message — the wrapped driver cause (host, port,
// "connection refused") is kept for server-side logs only and never
// reaches the client. projects_get_test.go pins the typed-status part of
// this contract (TestGetProjectPropagatesDependencyFailure); this test
// pins the "the wrapped cause stays server-side" half that lives on the
// wire, including the bare datastore address that the cause string
// carries.
func TestGetProjectErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	reader := fakeProjectReader{getErr: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader,
	)

	rec := getProjectByID(handler, "prj_acme_alpha", getProjectContractSecret)
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
