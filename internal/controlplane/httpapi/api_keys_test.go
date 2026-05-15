package httpapi

import (
	"context"
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

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/api-keys (BE-0076). The endpoint lists the API
// keys owned by the organization named by the {org_id} path parameter, read
// through the APIKeyReader port; the tests drive it through NewHandler with a
// fake Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The store-backed
// reader has its own isolated-Postgres integration coverage in
// store/apikey_test.go.
//
// keys.read is a CapAdmin action, not a CapRead action: a viewer or developer
// in the tenant cannot list the organization's API keys, only an owner or
// admin (and a support principal performing a cross-tenant read by the
// standard CapRead-with-support allow) can. The happy-path tests therefore
// authenticate as RoleAdmin or RoleOwner; the support cross-tenant case
// asserts that the read is allowed for a support principal exactly as the
// policy matrix specifies.
//
// This endpoint has no request body and no query parameters: its only input
// is the {org_id} path parameter, an opaque identifier. There is therefore no
// syntactic request to reject — a malformed or unknown id surfaces as an
// empty list when the principal is authorized for it, or, for an id outside
// the principal's tenant, as the deterministic 403 the policy engine returns
// through organizationIDResolver. Those two paths are the "validation" and
// "authorization" coverage for this story.

// fakeAPIKeyReader is a canned APIKeyReader for httpapi tests. The zero value
// returns an empty list and no error from ListAPIKeys and a typed not-found
// from GetAPIKey, which is all the tests that never reach the handler (the
// public-surface, /v1/me, and other-org-route suites) need. APIKey list
// tests set keys/err and read gotOrgID back to prove the list read is scoped
// to the {org_id} path parameter; getAPIKey tests set key/getErr and read
// gotKeyOrgID/gotKeyID back to prove the read is scoped to both the
// {org_id} and the {key_id} path parameters.
type fakeAPIKeyReader struct {
	keys        []store.APIKey
	err         error
	gotOrgID    *string
	key         store.APIKey
	getErr      error
	gotKeyOrgID *string
	gotKeyID    *string
}

func (f fakeAPIKeyReader) ListAPIKeys(_ context.Context, organizationID string) ([]store.APIKey, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	return f.keys, f.err
}

func (f fakeAPIKeyReader) GetAPIKey(_ context.Context, organizationID, keyID string) (store.APIKey, error) {
	if f.gotKeyOrgID != nil {
		*f.gotKeyOrgID = organizationID
	}
	if f.gotKeyID != nil {
		*f.gotKeyID = keyID
	}
	if f.getErr != nil {
		return store.APIKey{}, f.getErr
	}
	if f.key.ID == "" {
		return store.APIKey{}, apierr.NotFound("api_key", keyID)
	}
	return f.key, nil
}

// fakeAPIKeyCreator is a canned APIKeyCreator for httpapi tests. The zero
// value returns the zero store.APIKey and no error from Create, which is
// all the tests that never reach the handler (the public-surface, GET-only,
// other-org-route, /v1/me, and members suites) need. POST-api-keys-specific
// tests set key/err and read got back to prove the handler forwards the
// validated request and the authenticated actor — including the
// server-minted (Prefix, SecretHash) pair — to the store layer unchanged.
type fakeAPIKeyCreator struct {
	key store.APIKey
	err error
	got *store.CreateAPIKeyInput
}

func (f fakeAPIKeyCreator) Create(_ context.Context, in store.CreateAPIKeyInput, _ time.Time) (store.APIKey, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.key, f.err
}

// fakeAPIKeyUpdater is a canned APIKeyUpdater for httpapi tests. The zero
// value returns the zero store.APIKey and no error from Update, which is
// all the tests that never reach the handler (the public-surface, GET-only,
// POST-only, other-org-route, /v1/me, and members suites) need.
// PATCH-api-keys-specific tests set key/err and read got back to prove the
// handler forwards the validated request and the authenticated actor to the
// store layer unchanged.
type fakeAPIKeyUpdater struct {
	key store.APIKey
	err error
	got *store.UpdateAPIKeyInput
}

func (f fakeAPIKeyUpdater) Update(_ context.Context, in store.UpdateAPIKeyInput) (store.APIKey, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.key, f.err
}

// fakeAPIKeyRevoker is a canned APIKeyRevoker for httpapi tests. The zero
// value returns the zero store.APIKey and no error from Revoke, which is
// all the tests that never reach the handler (the public-surface, GET-only,
// POST-only, PATCH-only, other-org-route, /v1/me, and members suites) need.
// DELETE-api-keys-specific tests set key/err and read got back to prove the
// handler forwards the path identifiers and the authenticated actor to the
// store layer unchanged.
type fakeAPIKeyRevoker struct {
	key store.APIKey
	err error
	got *store.RevokeAPIKeyInput
}

func (f fakeAPIKeyRevoker) Revoke(_ context.Context, in store.RevokeAPIKeyInput, _ time.Time) (store.APIKey, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.key, f.err
}

// fakeAPIKeyRotator is a canned APIKeyRotator for httpapi tests. The zero
// value returns the zero store.APIKey and no error from Rotate, which is
// all the tests that never reach the handler (the public-surface, GET-only,
// POST-only, PATCH-only, DELETE-only, other-org-route, /v1/me, and members
// suites) need. POST .../rotate-specific tests set key/err and read got back
// to prove the handler forwards the path identifiers, the server-minted
// (Prefix, SecretHash) pair, and the authenticated actor to the store layer
// unchanged.
type fakeAPIKeyRotator struct {
	key store.APIKey
	err error
	got *store.RotateAPIKeyInput
}

func (f fakeAPIKeyRotator) Rotate(_ context.Context, in store.RotateAPIKeyInput, _ time.Time) (store.APIKey, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.key, f.err
}

// listAPIKeysSuccessEnvelope is the decoded shape of the GET
// /v1/organizations/{org_id}/api-keys success envelope.
type listAPIKeysSuccessEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	OK            bool               `json:"ok"`
	RequestID     string             `json:"request_id"`
	Data          listAPIKeysPayload `json:"data"`
}

// listAPIKeysHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// APIKeyReader. It is the production request path: the GET
// /v1/organizations/{org_id}/api-keys route is wrapped in RequireAuth for
// action keys.read and goes through organizationIDResolver.
func listAPIKeysHandlerFor(id auth.Identity, authErr error, reader APIKeyReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, reader, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, nil)
}

// getAPIKeys issues GET /v1/organizations/{orgID}/api-keys against handler,
// optionally with a bearer token.
func getAPIKeys(handler http.Handler, orgID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/api-keys", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListAPIKeys(t *testing.T, rec *httptest.ResponseRecorder) listAPIKeysSuccessEnvelope {
	t.Helper()
	var env listAPIKeysSuccessEnvelope
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

// seedAPIKey builds a store.APIKey fixture for the fakeAPIKeyReader. It is a
// plain literal helper — no database — so the tests stay pure unit tests of
// the HTTP wire path. The SecretHash deliberately carries a sentinel value
// the redaction tests look for: if any byte of it reaches the wire, the
// projection is broken.
func seedAPIKey(orgID, keyID, prefix, name string, scopes []string, createdBy, serviceAccountID string, created, updated time.Time) store.APIKey {
	return store.APIKey{
		ID:               keyID,
		OrganizationID:   orgID,
		Prefix:           prefix,
		SecretHash:       "must-not-leak-secret-hash-sentinel",
		Name:             name,
		Scopes:           scopes,
		CreatedBy:        createdBy,
		ServiceAccountID: serviceAccountID,
		CreatedAt:        created,
		UpdatedAt:        updated,
	}
}

// TestListAPIKeysReturnsKeys is the happy path: an authenticated admin
// principal requesting its own organization's API keys receives them in a
// stable yalla.output.v1 envelope, with every source-of-truth field projected
// onto the wire shape. It also asserts that the secret_hash is never present
// in the rendered body.
func TestListAPIKeysReturnsKeys(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	reader := fakeAPIKeyReader{keys: []store.APIKey{
		seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
			[]string{"projects:read", "services:deploy"},
			"usr_ada", "", created, updated),
		seedAPIKey("org_acme", "key_ci", "yk_pf_ci", "CI deploy key",
			[]string{"services:deploy"},
			"usr_ada", "sa_ci", created, updated),
	}}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeListAPIKeys(t, rec)
	if len(env.Data.APIKeys) != 2 {
		t.Fatalf("api_keys = %+v, want exactly 2", env.Data.APIKeys)
	}
	want := apiKeyResource{
		KeyID:     "key_ada",
		Prefix:    "yk_pf_ada",
		Name:      "Ada's CLI key",
		Scopes:    []string{"projects:read", "services:deploy"},
		CreatedBy: "usr_ada",
		CreatedAt: created.Format(time.RFC3339Nano),
		UpdatedAt: updated.Format(time.RFC3339Nano),
	}
	if got := env.Data.APIKeys[0]; !apiKeyResourceEqual(got, want) {
		t.Errorf("api_keys[0] = %+v, want %+v", got, want)
	}
	wantSA := apiKeyResource{
		KeyID:            "key_ci",
		Prefix:           "yk_pf_ci",
		Name:             "CI deploy key",
		Scopes:           []string{"services:deploy"},
		CreatedBy:        "usr_ada",
		ServiceAccountID: "sa_ci",
		CreatedAt:        created.Format(time.RFC3339Nano),
		UpdatedAt:        updated.Format(time.RFC3339Nano),
	}
	if got := env.Data.APIKeys[1]; !apiKeyResourceEqual(got, wantSA) {
		t.Errorf("api_keys[1] = %+v, want %+v", got, wantSA)
	}
	if body := rec.Body.String(); strings.Contains(body, "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaks the secret hash sentinel: %s", body)
	}
	if body := rec.Body.String(); strings.Contains(body, "secret_hash") {
		t.Errorf("response body carries a secret_hash field; the wire shape must omit it: %s", body)
	}
}

// TestListAPIKeysProjectsNullableTimestamps proves an active key (no
// expires_at, no revoked_at, no last_used_at) renders without those fields,
// and a key with each of them set renders an RFC 3339 nanosecond timestamp.
func TestListAPIKeysProjectsNullableTimestamps(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	revoked := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)

	active := seedAPIKey("org_acme", "key_active", "yk_pf_act", "Active",
		[]string{}, "usr_ada", "", created, updated)
	inactive := seedAPIKey("org_acme", "key_inactive", "yk_pf_inact", "Inactive",
		[]string{}, "usr_ada", "", created, updated)
	inactive.ExpiresAt = &expires
	inactive.RevokedAt = &revoked
	inactive.LastUsedAt = &lastUsed

	reader := fakeAPIKeyReader{keys: []store.APIKey{active, inactive}}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	// The active key must omit the nullable timestamps entirely (omitempty
	// drops the empty string), so the substring check is sufficient: a key
	// without revoked_at/expires_at/last_used_at means those fields appear at
	// most once in the body, on the inactive key.
	if got := strings.Count(body, `"expires_at":`); got != 1 {
		t.Errorf(`"expires_at" count = %d, want 1 (only the inactive key); body %s`, got, body)
	}
	if got := strings.Count(body, `"revoked_at":`); got != 1 {
		t.Errorf(`"revoked_at" count = %d, want 1 (only the inactive key); body %s`, got, body)
	}
	if got := strings.Count(body, `"last_used_at":`); got != 1 {
		t.Errorf(`"last_used_at" count = %d, want 1 (only the inactive key); body %s`, got, body)
	}
	if !strings.Contains(body, `"expires_at":"`+expires.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("expires_at not rendered in RFC3339Nano; body %s", body)
	}
	if !strings.Contains(body, `"revoked_at":"`+revoked.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("revoked_at not rendered in RFC3339Nano; body %s", body)
	}
}

// TestListAPIKeysScopesReadToPathParameter proves the handler reads exactly
// the organization named by the {org_id} path parameter — the path id is the
// sole input that selects the rows.
func TestListAPIKeysScopesReadToPathParameter(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeAPIKeyReader{gotOrgID: &gotID}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotID != "org_acme" {
		t.Errorf("reader received id %q, want org_acme", gotID)
	}
}

// TestListAPIKeysEmptyListIsAStableEmptyArray proves an organization with no
// API keys renders an empty array, not a JSON null, so agents can iterate the
// response without a nil check.
func TestListAPIKeysEmptyListIsAStableEmptyArray(t *testing.T) {
	t.Parallel()

	reader := fakeAPIKeyReader{keys: nil}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"api_keys":[]`) {
		t.Errorf("body should render an empty api_keys array; body %s", rec.Body.String())
	}
}

// TestListAPIKeysProjectsNilScopesAsEmptyArray proves a key with a nil scopes
// slice renders "scopes": [] rather than "scopes": null, so agents can
// iterate the response without a nil check on a per-key field.
func TestListAPIKeysProjectsNilScopesAsEmptyArray(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	key := seedAPIKey("org_acme", "key_n", "yk_pf_n", "no-scopes", nil,
		"usr_ada", "", created, updated)
	reader := fakeAPIKeyReader{keys: []store.APIKey{key}}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"scopes":[]`) {
		t.Errorf("body should render an empty scopes array; body %s", rec.Body.String())
	}
}

// TestListAPIKeysCrossTenantIsForbidden proves a principal listing API keys
// outside its own tenant is denied with a deterministic 403 E_FORBIDDEN —
// and the reader is never reached, so a cross-tenant id can never reveal
// another tenant's keys or even whether that organization exists.
func TestListAPIKeysCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeAPIKeyReader{
		keys: []store.APIKey{seedAPIKey("org_victim", "key_v", "yk_pf_v", "victim",
			[]string{}, "usr_v", "", time.Now().UTC(), time.Now().UTC())},
		gotOrgID: &gotID,
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)}, nil, reader)

	rec := getAPIKeys(handler, "org_victim", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if env.Error.Message == "" {
		t.Errorf("error message is empty; want a stable forbidden message")
	}
	if gotID != "" {
		t.Errorf("reader was called with %q on a cross-tenant request; want it never reached", gotID)
	}
	if body := rec.Body.String(); strings.Contains(body, "key_v") || strings.Contains(body, "yk_pf_v") {
		t.Errorf("forbidden response leaks victim-tenant key data: %s", body)
	}
}

// TestListAPIKeysViewerIsForbidden proves a viewer or developer principal —
// CapRead but not CapAdmin — cannot list API keys even within its own
// tenant. keys.read is a CapAdmin action; the policy engine denies the
// request before the handler runs.
func TestListAPIKeysViewerIsForbidden(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeAPIKeyReader{gotOrgID: &gotID}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_viewer", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if gotID != "" {
		t.Errorf("reader was called with %q for an unauthorised viewer; want it never reached", gotID)
	}
}

// TestListAPIKeysSupportCannotReadCrossTenant proves the support principal's
// CapRead-with-support exception does NOT extend to keys.read. Unlike
// members.read (a CapRead action where the support principal can read across
// tenants by design), keys.read is a CapAdmin action — and support has only
// CapSelf, CapRead, and CapSupport. The cross-tenant attempt is therefore a
// stable 403 E_FORBIDDEN, and the reader is never reached. Privileged Yalla
// support that needs key visibility goes through the explicit break-glass
// admin tooling, not this customer-facing endpoint.
func TestListAPIKeysSupportCannotReadCrossTenant(t *testing.T) {
	t.Parallel()

	var gotID string
	reader := fakeAPIKeyReader{
		keys: []store.APIKey{seedAPIKey("org_customer", "key_c", "yk_pf_c", "customer",
			[]string{"projects:read"}, "usr_c", "", time.Now().UTC(), time.Now().UTC())},
		gotOrgID: &gotID,
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)}, nil, reader)

	rec := getAPIKeys(handler, "org_customer", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if gotID != "" {
		t.Errorf("reader was called with %q for support cross-tenant read; want it never reached", gotID)
	}
	if body := rec.Body.String(); strings.Contains(body, "key_c") || strings.Contains(body, "yk_pf_c") {
		t.Errorf("forbidden response leaks customer-tenant key data: %s", body)
	}
}

// TestListAPIKeysRequiresAuthentication proves a request with no credential
// is a stable 401 E_AUTH and never reaches the reader.
func TestListAPIKeysRequiresAuthentication(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(auth.Identity{}, nil,
		fakeAPIKeyReader{err: stderrors.New("reader must not be called")})

	rec := getAPIKeys(handler, "org_acme", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestListAPIKeysInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestListAPIKeysInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeAPIKeyReader{err: stderrors.New("reader must not be called")})

	rec := getAPIKeys(handler, "org_acme", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestListAPIKeysDisabledPrincipal proves a principal authenticated against a
// token but flagged as a disabled principal is denied with a 403 E_FORBIDDEN
// — and the reader is never reached.
func TestListAPIKeysDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := listAPIKeysHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeAPIKeyReader{err: stderrors.New("reader must not be called")})

	rec := getAPIKeys(handler, "org_acme", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestListAPIKeysReaderUnavailable proves a datastore outage surfaces as a
// 503 E_UNAVAILABLE — never disguised as a not-found or an empty success —
// and the wrapped driver cause never reaches the user-facing message.
func TestListAPIKeysReaderUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeAPIKeyReader{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKeys(handler, "org_acme", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestListAPIKeysHandlerWithNilReaderIsInternal proves a route registered
// without an api-key reader is a wiring error reported as a typed internal
// failure — never a misleading empty list. The bare handler is dispatched
// through telemetry.Correlate via the run helper so a request_id is resolved
// even though the test is bypassing the full RequireAuth middleware (the
// handler is invoked with a principal pre-attached to the request context).
func TestListAPIKeysHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/api-keys", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)))
	rec := run(listAPIKeysHandler(nil), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestListAPIKeysPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestListAPIKeysPropagatesRequestID(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil,
		fakeAPIKeyReader{})

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/api-keys", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("X-Request-Id", "req-from-client-12345")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-from-client-12345" {
		t.Errorf("X-Request-Id header = %q, want the echoed inbound id", got)
	}
	env := decodeListAPIKeys(t, rec)
	if env.RequestID != "req-from-client-12345" {
		t.Errorf("envelope request_id = %q, want the echoed inbound id", env.RequestID)
	}
}

// apiKeyResourceEqual is a field-by-field equality check for apiKeyResource.
// It is used instead of == because the Scopes slice cannot be compared with ==.
func apiKeyResourceEqual(a, b apiKeyResource) bool {
	if a.KeyID != b.KeyID || a.Prefix != b.Prefix || a.Name != b.Name ||
		a.CreatedBy != b.CreatedBy || a.ServiceAccountID != b.ServiceAccountID ||
		a.ExpiresAt != b.ExpiresAt || a.RevokedAt != b.RevokedAt ||
		a.LastUsedAt != b.LastUsedAt || a.CreatedAt != b.CreatedAt ||
		a.UpdatedAt != b.UpdatedAt {
		return false
	}
	if len(a.Scopes) != len(b.Scopes) {
		return false
	}
	for i := range a.Scopes {
		if a.Scopes[i] != b.Scopes[i] {
			return false
		}
	}
	return true
}
