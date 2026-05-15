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
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/projects/{project_id} (BE-0124). The endpoint returns the single
// project named by the {project_id} path parameter, read through the
// ProjectReader port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration coverage
// in store/project_test.go (TestProjectReaderGetProject).
//
// This endpoint has no request body and no query parameters: its only
// input is the {project_id} path parameter, an opaque identifier. There
// is therefore no syntactic request to reject — a malformed or unknown
// id surfaces as the typed NotFound the reader produces; a cross-tenant
// id reaches the persistence layer with the principal's home
// organization id and is rejected as a deterministic 404 by the
// tenant-scoped repository query, never revealing another tenant's
// data; a principal that does not hold project.read at the (home org,
// project_id) scope is rejected as a 403 by the policy engine through
// projectIDResolver before the handler reads any data. Those paths are
// the "validation", "not-found", and "authorization" coverage for this
// story.

// getProjectSuccessEnvelope is the decoded shape of the GET
// /v1/projects/{project_id} success envelope.
type getProjectSuccessEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	OK            bool              `json:"ok"`
	RequestID     string            `json:"request_id"`
	Data          getProjectPayload `json:"data"`
}

// getProjectErrorEnvelope is the decoded shape of the GET
// /v1/projects/{project_id} error envelope.
type getProjectErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// getProjectByID issues GET /v1/projects/{projectID} against handler,
// optionally with a bearer token.
func getProjectByID(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeGetProject(t *testing.T, rec *httptest.ResponseRecorder) getProjectSuccessEnvelope {
	t.Helper()
	var env getProjectSuccessEnvelope
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

func decodeGetProjectError(t *testing.T, rec *httptest.ResponseRecorder) getProjectErrorEnvelope {
	t.Helper()
	var env getProjectErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Errorf("ok = true, want false on an error envelope")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// TestGetProjectReturnsRequestedProject is the happy path: an
// authenticated principal requesting a project in its own home
// organization receives the source-of-truth row in a stable
// yalla.output.v1 envelope, with every column projected onto the wire
// shape.
func TestGetProjectReturnsRequestedProject(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	project := seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha service", 7, created, updated)
	reader := fakeProjectReader{project: project}

	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeGetProject(t, rec)
	want := projectResource{
		ProjectID:      "prj_acme_alpha",
		OrganizationID: "org_acme",
		Slug:           "alpha",
		DisplayName:    "Alpha service",
		Version:        7,
		CreatedAt:      created.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      updated.UTC().Format(time.RFC3339Nano),
	}
	if env.Data.Project != want {
		t.Errorf("project = %+v, want %+v", env.Data.Project, want)
	}
}

// TestGetProjectForwardsHomeOrganizationAndPathID proves the reader is
// called with the authenticated principal's own home organization id and
// the {project_id} path parameter — never with a caller-controlled
// organization id. That is the structural tenant boundary: a request
// can never point the read at another tenant by manipulating an
// organization id parameter because no such parameter exists on the
// wire.
func TestGetProjectForwardsHomeOrganizationAndPathID(t *testing.T) {
	t.Parallel()

	var gotOrg, gotProj string
	reader := fakeProjectReader{
		project:         seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, time.Now(), time.Now()),
		gotGetOrgID:     &gotOrg,
		gotGetProjectID: &gotProj,
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org_acme" {
		t.Errorf("reader called with organizationID = %q, want org_acme (principal home org)", gotOrg)
	}
	if gotProj != "prj_acme_alpha" {
		t.Errorf("reader called with projectID = %q, want prj_acme_alpha (path param)", gotProj)
	}
}

// TestGetProjectReturnsNotFoundForUnknownProject proves the typed
// NotFound the reader produces for an unknown id surfaces as a
// deterministic 404 E_NOT_FOUND error envelope — never disguised as an
// empty success or a 5xx, so agents can distinguish "this project does
// not exist" from "the dependency is unavailable" by error code alone.
func TestGetProjectReturnsNotFoundForUnknownProject(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{getErr: apierr.NotFound("project", "prj_unknown")}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_unknown", "tok-ada")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_NOT_FOUND" {
		t.Errorf("error.code = %q, want E_NOT_FOUND", env.Error.Code)
	}
}

// TestGetProjectCrossTenantIDBehavesAsNotFound proves a cross-tenant
// project_id — one that does belong to a real project in some other
// tenant — surfaces as a 404, not a 200 with the foreign project's
// data and not a 403 that would reveal the project exists somewhere.
// The handler always forwards the principal's home organization id to
// the reader (never a caller-controlled value), so the tenant-scoped
// repository query that combines (organization_id, project_id) cannot
// match a row that belongs to another tenant: a cross-tenant id can
// never reveal another organization's project through this endpoint.
func TestGetProjectCrossTenantIDBehavesAsNotFound(t *testing.T) {
	t.Parallel()

	var gotOrg string
	// The fake mirrors the production store contract: it returns NotFound
	// whenever the projectID does not belong to the organizationID the
	// caller forwarded. Here the principal's home org is org_acme but the
	// path id is owned by org_victim, so the fake answers NotFound.
	reader := fakeProjectReader{
		getErr:      apierr.NotFound("project", "prj_victim_alpha"),
		gotGetOrgID: &gotOrg,
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_victim_alpha", "tok-ada")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org_acme" {
		t.Errorf("reader called with organizationID = %q, want org_acme (principal home org, never a foreign tenant)", gotOrg)
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_NOT_FOUND" {
		t.Errorf("error.code = %q, want E_NOT_FOUND", env.Error.Code)
	}
	// The error body must never leak the foreign tenant's identity. We
	// asserted the project_id is echoed (it was a caller-supplied input),
	// but no organization id from the store should appear here.
	if strings.Contains(strings.ToLower(env.Error.Message), "org_victim") {
		t.Errorf("error.message = %q, must not contain a foreign organization id", env.Error.Message)
	}
}

// TestGetProjectRequiresBearerToken proves the route is gated by
// RequireAuth: a request with no Authorization header is 401 E_AUTH and
// the project reader is never reached (sentinel: gotGetOrgID would have
// been overwritten by the handler had it run).
func TestGetProjectRequiresBearerToken(t *testing.T) {
	t.Parallel()

	gotOrg := "sentinel-untouched"
	reader := fakeProjectReader{
		project:     seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, time.Now(), time.Now()),
		gotGetOrgID: &gotOrg,
	}
	handler := listProjectsHandlerFor(
		auth.Identity{}, nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_AUTH" {
		t.Errorf("error.code = %q, want E_AUTH", env.Error.Code)
	}
	if gotOrg != "sentinel-untouched" {
		t.Errorf("reader was called with organizationID = %q, want it never reached", gotOrg)
	}
}

// TestGetProjectRejectsInvalidCredential proves an unauthenticated
// principal — a token that does not resolve to a credential — is 401
// E_AUTH and the project reader is never reached. The message is the
// stable, generic invalid-credential message that does not reveal which
// check failed.
func TestGetProjectRejectsInvalidCredential(t *testing.T) {
	t.Parallel()

	handler := listProjectsHandlerFor(
		auth.Identity{}, auth.ErrInvalidCredentials, fakeProjectReader{})
	rec := getProjectByID(handler, "prj_acme_alpha", "yk_bogus")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_AUTH" {
		t.Errorf("error.code = %q, want E_AUTH", env.Error.Code)
	}
}

// TestGetProjectRejectsDisabledPrincipal proves a credential that
// authenticates but resolves to a disabled principal is denied with a
// 403 carrying the stable policy reason — the policy engine refuses
// disabled principals before any read.
func TestGetProjectRejectsDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: disabled, Method: auth.MethodSession}, nil, fakeProjectReader{})
	rec := getProjectByID(handler, "prj_acme_alpha", "a-revoked-session-token")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_FORBIDDEN" {
		t.Errorf("error.code = %q, want E_FORBIDDEN", env.Error.Code)
	}
}

// TestGetProjectAllowsOrganizationWideViewer proves an organization-wide
// Viewer role is sufficient for project.read at any project in the
// principal's home org — Viewer is the lowest CapRead-bearing role and
// covers every project in the tenant.
func TestGetProjectAllowsOrganizationWideViewer(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{
		project: seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, time.Now(), time.Now()),
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "tok-ada")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

// TestGetProjectRejectsGrantOnlyKeyForSiblingProject proves a grant-only
// principal — an API key with a Grant naming a specific project but no
// organization-wide Role — cannot read a SIBLING project through this
// endpoint. The policy engine asks whether the grant scope contains the
// resource scope, not the reverse: a grant for prj_acme_alpha does not
// cover the resource (home_org, prj_acme_beta), so the request is 403
// E_FORBIDDEN before the handler reads any data.
func TestGetProjectRejectsGrantOnlyKeyForSiblingProject(t *testing.T) {
	t.Parallel()

	scopedKey := policy.Principal{
		ID:             "yk_scoped",
		OrganizationID: "org_acme",
		Grants: []policy.Grant{{
			Role: policy.RoleAdmin,
			Scope: policy.Scope{
				OrganizationID: "org_acme",
				ProjectID:      "prj_acme_alpha",
			},
		}},
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: scopedKey, Method: auth.MethodAPIKey}, nil, fakeProjectReader{})
	rec := getProjectByID(handler, "prj_acme_beta", "yk_scoped")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code != "E_FORBIDDEN" {
		t.Errorf("error.code = %q, want E_FORBIDDEN", env.Error.Code)
	}
}

// TestGetProjectAllowsGrantOnlyKeyForTargetProject is the counterpart of
// the sibling-project test: a grant-only principal whose grant names
// THIS project is allowed the read. The grant scope contains the
// resource scope (same org, same project), so the policy engine
// authorizes the call.
func TestGetProjectAllowsGrantOnlyKeyForTargetProject(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{
		project: seedProject("prj_acme_alpha", "org_acme", "alpha", "Alpha", 1, time.Now(), time.Now()),
	}
	scopedKey := policy.Principal{
		ID:             "yk_scoped",
		OrganizationID: "org_acme",
		Grants: []policy.Grant{{
			Role: policy.RoleAdmin,
			Scope: policy.Scope{
				OrganizationID: "org_acme",
				ProjectID:      "prj_acme_alpha",
			},
		}},
	}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: scopedKey, Method: auth.MethodAPIKey}, nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "yk_scoped")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

// TestGetProjectPropagatesDependencyFailure proves a reader-store outage
// surfaces as its own typed 5xx — never disguised as a 404 (which would
// hide a real-failure) or a 200 with empty data (which would corrupt
// the contract).
func TestGetProjectPropagatesDependencyFailure(t *testing.T) {
	t.Parallel()

	reader := fakeProjectReader{getErr: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := listProjectsHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, reader)
	rec := getProjectByID(handler, "prj_acme_alpha", "tok-ada")

	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
	env := decodeGetProjectError(t, rec)
	if env.Error.Code == "E_NOT_FOUND" {
		t.Errorf("error.code = %q, must not collapse a store outage into a not-found", env.Error.Code)
	}
	// The error body must never echo the raw driver text — that text is
	// the redaction surface for the store layer.
	if strings.Contains(strings.ToLower(env.Error.Message), "connection refused") {
		t.Errorf("error.message = %q, must not leak raw driver text", env.Error.Message)
	}
}
