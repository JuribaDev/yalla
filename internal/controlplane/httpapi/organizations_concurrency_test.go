package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// HTTP-layer optimistic-concurrency coverage for PATCH and DELETE
// /v1/organizations/{org_id} (BE-0027). The endpoints accept the caller's
// expected resource version through the If-Match request header, plumb it to
// the store layer as the precondition the source-of-truth UPDATE is gated
// on, mirror the row's authoritative version into the ETag response header
// on success, and surface a stale precondition as a typed E_CONFLICT
// carrying current_version under the envelope's structured details map.
//
// These tests drive the production wiring: NewHandler with the real auth
// middleware, the real policy engine, and a fake updater/deleter. The
// store-layer concurrency contract (the WHERE-on-version UPDATE, the
// stale-write apierr.ConflictStale) is exercised end-to-end against an
// isolated Postgres database in store/organization_concurrency_test.go.

// decodedOrganizationErrorEnvelope mirrors yalla.error.v1, including the
// optional details map carrying current_version on a stale-write conflict.
type decodedOrganizationErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Error         struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Hint    string            `json:"hint"`
		Details map[string]string `json:"details"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

// decodeOrganizationError decodes a yalla.error.v1 envelope and asserts the
// stable shape, returning the decoded envelope for further field assertions.
func decodeOrganizationError(t *testing.T, rec *httptest.ResponseRecorder) decodedOrganizationErrorEnvelope {
	t.Helper()
	var env decodedOrganizationErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Errorf("ok = true, want false")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// patchOrganizationWithIfMatch issues PATCH /v1/organizations/{orgID} with an
// optional If-Match header so the test can drive the precondition without
// rebuilding the request from scratch.
func patchOrganizationWithIfMatch(handler http.Handler, orgID, token, ifMatch, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch, "/v1/organizations/"+orgID, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// deleteOrganizationWithIfMatch issues DELETE /v1/organizations/{orgID} with
// an optional If-Match header.
func deleteOrganizationWithIfMatch(handler http.Handler, orgID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/organizations/"+orgID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// staleUpdater returns a fakeOrganizationUpdater that always replies with a
// typed apierr.ConflictStale carrying currentVersion, simulating the store
// layer rejecting a write whose If-Match precondition does not match the
// row's authoritative version.
func staleUpdater(currentVersion int64, captured *store.UpdateOrganizationInput) fakeOrganizationUpdater {
	return fakeOrganizationUpdater{err: apierr.ConflictStale(currentVersion), got: captured}
}

// staleDeleter returns a fakeOrganizationDeleter that always replies with a
// typed apierr.ConflictStale carrying currentVersion.
func staleDeleter(currentVersion int64, captured *store.DeleteOrganizationInput) fakeOrganizationDeleter {
	return fakeOrganizationDeleter{err: apierr.ConflictStale(currentVersion), got: captured}
}

// TestUpdateOrganizationParsesIfMatchHeader proves the handler parses the
// If-Match header in canonical strong-ETag form (`"<n>"`) and forwards the
// version to the store layer. A request with no header still succeeds: the
// header is optional, and an absent precondition disables the check.
func TestUpdateOrganizationParsesIfMatchHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ifMatch string
		want    *int64
	}{
		{"absent", "", nil},
		{"strong etag", `"5"`, ptrInt64(5)},
		{"unquoted integer (lenient)", "5", ptrInt64(5)},
		{"whitespace stripped", `   "12"   `, ptrInt64(12)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var captured store.UpdateOrganizationInput
			updater := fakeOrganizationUpdater{
				org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme", Version: 99},
				got: &captured,
			}
			handler := updateOrganizationHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
				nil, updater)

			rec := patchOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", tc.ifMatch, `{"display_name":"Acme Worldwide"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if !int64PtrEqual(captured.IfMatchVersion, tc.want) {
				t.Errorf("captured.IfMatchVersion = %v, want %v", deref(captured.IfMatchVersion), deref(tc.want))
			}
		})
	}
}

// TestUpdateOrganizationRejectsMalformedIfMatch proves a malformed If-Match
// is rejected with a typed 400 E_INVALID_INPUT before the request reaches
// the store layer, so an unparseable precondition can never silently
// degrade to "no precondition".
func TestUpdateOrganizationRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ifMatch string
	}{
		{"weak etag", `W/"5"`},
		{"wildcard", "*"},
		{"non-integer", `"five"`},
		{"negative", `"-1"`},
		{"zero", `"0"`},
		{"multi-value", `"5", "6"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var captured store.UpdateOrganizationInput
			updater := fakeOrganizationUpdater{
				org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme", Version: 1},
				got: &captured,
			}
			handler := updateOrganizationHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
				nil, updater)

			rec := patchOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", tc.ifMatch, `{"display_name":"Acme"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			env := decodeOrganizationError(t, rec)
			if env.Error.Code != string(yerr.CodeInvalidInput) {
				t.Errorf("error.code = %q, want %s", env.Error.Code, yerr.CodeInvalidInput)
			}
			if captured.OrganizationID != "" {
				t.Errorf("updater was reached with captured = %+v, want a 400 raised before the store layer", captured)
			}
		})
	}
}

// TestUpdateOrganizationStaleIfMatchReturnsConflictWithCurrentVersion proves
// the handler renders a store.ConflictStale error as a 409 carrying the
// row's authoritative current_version under structured details, so a caller
// can rebuild its If-Match header without an extra GET.
func TestUpdateOrganizationStaleIfMatchReturnsConflictWithCurrentVersion(t *testing.T) {
	t.Parallel()

	var captured store.UpdateOrganizationInput
	handler := updateOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, staleUpdater(7, &captured))

	rec := patchOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", `"5"`, `{"display_name":"Acme"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	env := decodeOrganizationError(t, rec)
	if env.Error.Code != string(yerr.CodeConflict) {
		t.Errorf("error.code = %q, want %s", env.Error.Code, yerr.CodeConflict)
	}
	if got := env.Error.Details["current_version"]; got != "7" {
		t.Errorf("details.current_version = %q, want 7", got)
	}
	if env.Error.Hint == "" {
		t.Error("error.hint is empty, want the stable retry-with-current-version remediation")
	}
	if captured.IfMatchVersion == nil || *captured.IfMatchVersion != 5 {
		t.Errorf("captured.IfMatchVersion = %v, want 5 — the handler must forward the parsed version even on conflict",
			deref(captured.IfMatchVersion))
	}
	// The error envelope must not echo an ETag pinned to the rejected
	// caller version; the response carries no successful body.
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("ETag = %q, want empty for an error response", got)
	}
}

// TestUpdateOrganizationSuccessSetsETag proves a successful PATCH mirrors
// the row's authoritative version into the ETag response header, so the
// caller can echo it on a follow-up If-Match without inspecting the body.
func TestUpdateOrganizationSuccessSetsETag(t *testing.T) {
	t.Parallel()

	updater := fakeOrganizationUpdater{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme", Version: 42,
	}}
	handler := updateOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", `"41"`, `{"display_name":"Acme"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("ETag"); got != `"42"` {
		t.Errorf("ETag = %q, want \"42\"", got)
	}

	// The body's version field always agrees with the ETag header.
	var env updateOrganizationSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.Organization.Version != 42 {
		t.Errorf("data.organization.version = %d, want 42 (must agree with ETag)", env.Data.Organization.Version)
	}
}

// TestDeleteOrganizationStaleIfMatchReturnsConflictWithCurrentVersion proves
// the same precondition contract is enforced on DELETE.
func TestDeleteOrganizationStaleIfMatchReturnsConflictWithCurrentVersion(t *testing.T) {
	t.Parallel()

	var captured store.DeleteOrganizationInput
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, staleDeleter(11, &captured))

	rec := deleteOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", `"3"`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	env := decodeOrganizationError(t, rec)
	if env.Error.Code != string(yerr.CodeConflict) {
		t.Errorf("error.code = %q, want %s", env.Error.Code, yerr.CodeConflict)
	}
	if got := env.Error.Details["current_version"]; got != "11" {
		t.Errorf("details.current_version = %q, want 11", got)
	}
	if captured.IfMatchVersion == nil || *captured.IfMatchVersion != 3 {
		t.Errorf("captured.IfMatchVersion = %v, want 3", deref(captured.IfMatchVersion))
	}
}

// TestDeleteOrganizationRejectsMalformedIfMatch proves DELETE applies the
// same input validation as PATCH so the contract is uniform across writes.
func TestDeleteOrganizationRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	var captured store.DeleteOrganizationInput
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, fakeOrganizationDeleter{
			org: store.Organization{ID: "org_acme", Slug: "acme", DisplayName: "Acme"},
			got: &captured,
		})

	rec := deleteOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", `W/"3"`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeOrganizationError(t, rec)
	if env.Error.Code != string(yerr.CodeInvalidInput) {
		t.Errorf("error.code = %q, want %s", env.Error.Code, yerr.CodeInvalidInput)
	}
	if captured.OrganizationID != "" {
		t.Errorf("deleter reached with captured = %+v, want a 400 raised before the store layer", captured)
	}
}

// TestDeleteOrganizationSuccessSetsETag proves a successful DELETE also
// mirrors the row's authoritative version into the ETag header, even though
// the resource is now scheduled for teardown — a follow-up read still
// observes the row, and the ETag agrees with that view.
func TestDeleteOrganizationSuccessSetsETag(t *testing.T) {
	t.Parallel()

	deleter := fakeOrganizationDeleter{org: store.Organization{
		ID: "org_acme", Slug: "acme", DisplayName: "Acme", Version: 9,
	}}
	handler := deleteOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, deleter)

	rec := deleteOrganizationWithIfMatch(handler, "org_acme", "a-valid-session-token", `"8"`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("ETag"); got != `"9"` {
		t.Errorf("ETag = %q, want \"9\"", got)
	}
}

// TestParseIfMatchVersionContractDirect exercises the parser as a focused
// unit test, separately from the routing wiring, so the malformed/empty
// cases are documented at the function level too.
func TestParseIfMatchVersionContractDirect(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		header  string
		want    *int64
		wantErr bool
	}{
		{"absent", "", nil, false},
		{"blank", "   ", nil, false},
		{"strong etag", `"5"`, ptrInt64(5), false},
		{"unquoted integer", "5", ptrInt64(5), false},
		{"weak etag rejected", `W/"5"`, nil, true},
		{"wildcard rejected", "*", nil, true},
		{"negative rejected", `"-1"`, nil, true},
		{"zero rejected", `"0"`, nil, true},
		{"non-integer rejected", `"five"`, nil, true},
		{"multi-value rejected", `"5","6"`, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPatch, "/v1/organizations/org_x", nil)
			if tc.header != "" {
				req.Header.Set("If-Match", tc.header)
			}
			got, err := parseIfMatchVersion(req)
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("parseIfMatchVersion(%q) returned nil error, want a typed validation error", tc.header)
			case !tc.wantErr && err != nil:
				t.Fatalf("parseIfMatchVersion(%q) returned %v, want nil", tc.header, err)
			case !int64PtrEqual(got, tc.want):
				t.Errorf("parseIfMatchVersion(%q) = %v, want %v", tc.header, deref(got), deref(tc.want))
			}
		})
	}
}

// TestFormatETagShape proves the ETag wire shape is the strong validator
// (`"<n>"`) for a positive version, and empty for a non-positive one so the
// caller omits the header rather than emitting a malformed value.
func TestFormatETagShape(t *testing.T) {
	t.Parallel()

	if got := formatETag(1); got != `"1"` {
		t.Errorf("formatETag(1) = %q, want \"1\"", got)
	}
	if got := formatETag(123); got != `"123"` {
		t.Errorf("formatETag(123) = %q, want \"123\"", got)
	}
	if got := formatETag(0); got != "" {
		t.Errorf("formatETag(0) = %q, want empty", got)
	}
	if got := formatETag(-7); got != "" {
		t.Errorf("formatETag(-7) = %q, want empty", got)
	}
}

func ptrInt64(v int64) *int64 { return &v }

func int64PtrEqual(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
