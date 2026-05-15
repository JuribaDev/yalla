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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/audit-events (BE-0103). The endpoint reads
// the most-recent audit events of the organization through the
// AuditEventReader port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration coverage
// in store/audit_test.go (the AuditRepository tests) — this file exercises
// the HTTP surface in isolation.
//
// Inputs: the {org_id} path parameter (opaque) and an optional ?limit=
// query parameter in [1, 200]. An unknown id within the principal's tenant
// is a deterministic empty list; an id outside the principal's tenant
// surfaces as the deterministic 403 the policy engine returns through
// organizationIDResolver — both validate-and-authorize paths the suite
// pins. The dedicated policy-matrix coverage for every role and grant
// containment property is BE-0105, scheduled to land next.

// fakeAuditEventReader is a canned AuditEventReader for httpapi tests.
// The zero value returns a nil slice and no error, which is all the test
// helpers that never reach the handler (the public-surface and unrelated-
// endpoint suites) need; the audit-event tests set events/err and read
// gotOrgID/gotLimit back to prove the handler forwards the path parameter
// and the resolved ?limit= value to the store layer unchanged.
type fakeAuditEventReader struct {
	events   []store.AuditEvent
	err      error
	gotOrgID *string
	gotLimit *int
}

func (f fakeAuditEventReader) ListByOrganization(_ context.Context, organizationID string, limit int) ([]store.AuditEvent, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotLimit != nil {
		*f.gotLimit = limit
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.events, nil
}

// listAuditEventsHandlerFor builds an http.Handler that points at the
// GET /v1/organizations/{org_id}/audit-events route, wired through the
// same NewHandler the production binary uses. id and authErr drive the
// fake authenticator; reader is the AuditEventReader the handler reads
// from.
func listAuditEventsHandlerFor(id auth.Identity, authErr error, reader AuditEventReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, reader, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, nil)
}

// auditEventActorIdentity builds a session-method identity for an
// organization owner acting on its own tenant — the default principal
// shape the contract tests use when proving the wire surface independent
// of policy matrix combinatorics. audit.read is a CapAdmin action, so an
// owner is the lowest-privilege role authorized inside the tenant
// (admin would also work); a viewer or developer is denied by the policy
// engine and is covered by the dedicated BE-0105 matrix.
func auditEventActorIdentity(orgID, userID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             userID,
			Kind:           domain.KindUser,
			OrganizationID: orgID,
			Role:           policy.RoleOwner,
		},
		Method: auth.MethodSession,
	}
}

// getAuditEvents issues a GET against
// /v1/organizations/{orgID}/audit-events and returns the recorded
// response. It mirrors getUsage in the usage surface — a single,
// deterministic call shape so the assertion blocks can focus on the
// response. limit is the literal ?limit= query value to forward; pass
// "" to omit the parameter entirely.
func getAuditEvents(handler http.Handler, orgID, limit, token string) *httptest.ResponseRecorder {
	url := "/v1/organizations/" + orgID + "/audit-events"
	if limit != "" {
		url += "?limit=" + limit
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeAuditEventList decodes a yalla.output.v1 success envelope's data
// block into the wire shape an agent observes — including actor and
// resource being optional (null for an unauthenticated denied request and
// for an organization-root action respectively).
func decodeAuditEventList(t *testing.T, body []byte) auditEventEnvelope {
	t.Helper()
	var env auditEventEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, body)
	}
	return env
}

type auditEventEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Events []struct {
			ID         string    `json:"id"`
			OccurredAt time.Time `json:"occurred_at"`
			Action     string    `json:"action"`
			Decision   string    `json:"decision"`
			Reason     string    `json:"reason"`
			Actor      *struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"actor"`
			Resource *struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"resource"`
			RequestID     string            `json:"request_id"`
			CorrelationID string            `json:"correlation_id"`
			IPAddress     string            `json:"ip_address"`
			UserAgent     string            `json:"user_agent"`
			Metadata      map[string]string `json:"metadata"`
		} `json:"events"`
	} `json:"data"`
}

// TestListAuditEventsReturnsRecentEvents proves the happy path: the
// handler forwards the {org_id} path parameter to the reader unchanged,
// resolves the default page size when no ?limit= is supplied, and
// projects the rows the reader returns into the stable wire shape. The
// nullable actor/resource objects render as null for the unauthenticated/
// organization-root denied event, and as nested objects for the allowed
// event with both a resolved principal and a target resource. It also
// pins the envelope fields agents read first.
func TestListAuditEventsReturnsRecentEvents(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	var gotLimit int
	occurred := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	reader := fakeAuditEventReader{
		gotOrgID: &gotOrg,
		gotLimit: &gotLimit,
		events: []store.AuditEvent{
			{
				ID:             "aud_001",
				OrganizationID: orgID,
				ActorID:        "usr_admin",
				ActorKind:      domain.KindUser.String(),
				Action:         "limits.write",
				ResourceKind:   "organization",
				ResourceID:     orgID,
				Decision:       store.AuditDecisionAllowed,
				Reason:         "role_capability",
				RequestID:      "req_abc",
				CorrelationID:  "cor_xyz",
				IPAddress:      "203.0.113.7",
				UserAgent:      "yalla-cli/1.0",
				Metadata:       map[string]string{"updated_resources": "projects"},
				OccurredAt:     occurred,
			},
			{
				// Denied: unauthenticated request — no resolved principal,
				// no specific resource. Both actor and resource project
				// as null on the wire.
				ID:             "aud_002",
				OrganizationID: orgID,
				Action:         "organization.read",
				Decision:       store.AuditDecisionDenied,
				Reason:         "no_principal",
				RequestID:      "req_def",
				OccurredAt:     occurred.Add(-time.Minute),
			},
		},
	}

	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != orgID {
		t.Errorf("reader received org_id %q, want %q", gotOrg, orgID)
	}
	if gotLimit != auditEventListDefaultLimit {
		t.Errorf("reader received limit %d, want default %d", gotLimit, auditEventListDefaultLimit)
	}

	env := decodeAuditEventList(t, rec.Body.Bytes())
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; the envelope must propagate the request id")
	}
	if len(env.Data.Events) != 2 {
		t.Fatalf("events len = %d, want 2 (got %+v)", len(env.Data.Events), env.Data.Events)
	}

	first := env.Data.Events[0]
	if first.ID != "aud_001" || first.Action != "limits.write" || first.Decision != "allowed" || first.Reason != "role_capability" {
		t.Errorf("[0] = %+v; want (aud_001 limits.write allowed role_capability)", first)
	}
	if first.Actor == nil || first.Actor.ID != "usr_admin" || first.Actor.Kind != domain.KindUser.String() {
		t.Errorf("[0].actor = %+v; want non-nil {usr_admin, user}", first.Actor)
	}
	if first.Resource == nil || first.Resource.ID != orgID || first.Resource.Kind != "organization" {
		t.Errorf("[0].resource = %+v; want non-nil {%s, organization}", first.Resource, orgID)
	}
	if first.RequestID != "req_abc" || first.CorrelationID != "cor_xyz" {
		t.Errorf("[0] request_id/correlation_id mismatch: %+v", first)
	}
	if first.Metadata["updated_resources"] != "projects" {
		t.Errorf("[0].metadata = %v; want updated_resources=projects", first.Metadata)
	}

	second := env.Data.Events[1]
	if second.Actor != nil {
		t.Errorf("[1].actor = %+v; want nil for an unauthenticated denied event", second.Actor)
	}
	if second.Resource != nil {
		t.Errorf("[1].resource = %+v; want nil for an organization-root action", second.Resource)
	}
	if second.Decision != "denied" || second.Reason != "no_principal" {
		t.Errorf("[1] = %+v; want denied/no_principal", second)
	}
}

// TestListAuditEventsReturnsEmptyListForOrgWithNoHistory proves an
// organization with no audit history yields a deterministic empty list
// rather than a 404 — the same forward-compatible shape every list
// endpoint serves so an agent can iterate without a nil check.
func TestListAuditEventsReturnsEmptyListForOrgWithNoHistory(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeAuditEventReader{events: nil}

	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeAuditEventList(t, rec.Body.Bytes())
	if env.Data.Events == nil {
		t.Errorf("events is nil, want a non-nil empty slice (so agents can iterate without a nil check)")
	}
	if len(env.Data.Events) != 0 {
		t.Errorf("events len = %d, want 0", len(env.Data.Events))
	}
}

// TestListAuditEventsForwardsLimitToReader proves the handler parses
// ?limit= and forwards the resolved value to the store layer
// unchanged, so an operator can shrink or grow the page size within the
// stable [1, 200] bounds.
func TestListAuditEventsForwardsLimitToReader(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotLimit int
	reader := fakeAuditEventReader{gotLimit: &gotLimit}

	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "25", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotLimit != 25 {
		t.Errorf("reader received limit %d, want 25", gotLimit)
	}
}

// TestListAuditEventsRejectsMalformedLimit proves a non-integer ?limit=
// is rejected as a stable 400 E_INVALID_INPUT before any database work
// runs, and the rejection echoes the field path the agent can read to
// pinpoint which parameter was wrong without leaking the submitted
// value.
func TestListAuditEventsRejectsMalformedLimit(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	reader := fakeAuditEventReader{gotOrgID: &gotOrg}

	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "not-a-number", "a-valid-session-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for an invalid request (received org_id %q)", gotOrg)
	}
	if strings.Contains(rec.Body.String(), "not-a-number") {
		t.Errorf("body leaked the submitted value: %s", rec.Body.String())
	}
}

// TestListAuditEventsRejectsOutOfRangeLimit proves a ?limit= outside the
// stable [1, 200] range is rejected as a stable 400 E_INVALID_INPUT,
// matching the repository's hard ceiling so an agent can never request
// more than the documented cap.
func TestListAuditEventsRejectsOutOfRangeLimit(t *testing.T) {
	t.Parallel()
	cases := []string{"0", "-1", "201", "9999"}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			const orgID = "org_acme"
			reader := fakeAuditEventReader{}
			handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
			rec := getAuditEvents(handler, orgID, raw, "a-valid-session-token")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestListAuditEventsForwardsStoreUnavailableAsTypedFiveHundred proves a
// store outage becomes a stable 5xx envelope, not a leaked driver error.
func TestListAuditEventsForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeAuditEventReader{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}

	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("body leaked the raw driver error: %s", rec.Body.String())
	}
}

// TestListAuditEventsRequiresAuthentication proves a missing/invalid
// credential is the typed 401 the authenticator path emits, not a
// leaked panic, and the reader never runs.
func TestListAuditEventsRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	reader := fakeAuditEventReader{gotOrgID: &gotOrg}

	handler := listAuditEventsHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), reader)
	rec := getAuditEvents(handler, orgID, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for an unauthenticated request (received org_id %q)", gotOrg)
	}
}

// TestListAuditEventsDeniesCrossTenantPrincipal proves the policy engine
// — wired through organizationIDResolver — rejects a principal whose
// home organization is not the {org_id} the path names (and who is not a
// support principal allowed cross-tenant for read actions), without the
// reader ever running. audit.read is a CapAdmin action whose cross-tenant
// support exception is pinned exhaustively in the BE-0105 policy matrix,
// not duplicated here.
func TestListAuditEventsDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var gotOrg string
	reader := fakeAuditEventReader{gotOrgID: &gotOrg}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_mallory",
			Kind:           domain.KindUser,
			OrganizationID: homeOrg,
			Role:           policy.RoleOwner,
		},
		Method: auth.MethodSession,
	}
	handler := listAuditEventsHandlerFor(id, nil, reader)
	rec := getAuditEvents(handler, victimOrg, "", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for a cross-tenant principal (received org_id %q)", gotOrg)
	}
	if strings.Contains(rec.Body.String(), `"events"`) {
		t.Errorf("body leaked audit data on a denied request: %s", rec.Body.String())
	}
}

// TestListAuditEventsDeniesViewerWithoutCapAdmin proves that a viewer in
// the tenant — who has CapRead but not CapAdmin — is denied audit.read
// with a deterministic 403. This is the load-bearing distinction from
// CapRead actions: a viewer can list members or read the organization,
// but cannot read the audit log. Exhaustive role/capability coverage is
// the dedicated BE-0105 matrix; this test pins the single in-tenant
// "viewer denied" property at the HTTP boundary so a future regression
// (e.g. dropping audit.read to CapRead) fails the contract test, not
// only the matrix.
func TestListAuditEventsDeniesViewerWithoutCapAdmin(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var gotOrg string
	reader := fakeAuditEventReader{gotOrgID: &gotOrg}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           domain.KindUser,
			OrganizationID: orgID,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := listAuditEventsHandlerFor(id, nil, reader)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if gotOrg != "" {
		t.Errorf("reader ran for a viewer-without-CapAdmin (received org_id %q)", gotOrg)
	}
}

// TestListAuditEventsMissingReaderIsTypedInternalError proves a wiring
// error (a nil AuditEventReader threaded into NewHandler) surfaces as the
// typed internal-error envelope rather than a misleading empty list or a
// panic, the same posture every other list endpoint takes.
func TestListAuditEventsMissingReaderIsTypedInternalError(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	a := fakeAuthenticator{identity: auditEventActorIdentity(orgID, "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, nil, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, nil)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestListAuditEventsRouteIsRegistered proves the OpenAPI document carries
// the GET /v1/organizations/{org_id}/audit-events operation with the
// stable operationId, the audit.read required action, and the
// audit-events tag — every detail an agent reads to discover the
// endpoint.
func TestListAuditEventsRouteIsRegistered(t *testing.T) {
	t.Parallel()
	a := fakeAuthenticator{identity: auditEventActorIdentity("org_acme", "usr_owner")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string   `json:"operationId"`
			Tags           []string `json:"tags"`
			RequiredAction string   `json:"x-required-action"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/audit-events"]["get"]
	if !ok {
		t.Fatalf("GET /v1/organizations/{org_id}/audit-events missing from OpenAPI document")
	}
	if op.OperationID != "listOrganizationAuditEvents" {
		t.Errorf("operationId = %q, want listOrganizationAuditEvents", op.OperationID)
	}
	foundTag := false
	for _, tag := range op.Tags {
		if tag == "audit-events" {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Errorf("tags = %v, want it to include \"audit-events\"", op.Tags)
	}
}

// TestAuditEventProjectionDoesNotReintroduceRedaction proves the wire
// projection trusts the persistence-layer contract: every value reaches
// the handler already redacted by the audit.Auditor, so projecting them
// onto the wire cannot leak a secret. Even if a fake reader returns a
// row whose IP / user agent / metadata still bear the redaction
// sentinel, those sentinels reach the wire verbatim — the handler does
// NOT silently strip them and let an unredacted value slip through. This
// is the structural redaction proof for BE-0103: redaction happens at
// persistence, the wire mirrors persistence.
func TestAuditEventProjectionDoesNotReintroduceRedaction(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	reader := fakeAuditEventReader{
		events: []store.AuditEvent{
			{
				ID:             "aud_redacted",
				OrganizationID: orgID,
				Action:         "limits.write",
				Decision:       store.AuditDecisionAllowed,
				Reason:         "role_capability",
				IPAddress:      output.Sentinel,
				UserAgent:      output.Sentinel,
				Metadata: map[string]string{
					"token":             output.Sentinel,
					"updated_resources": "projects",
				},
				OccurredAt: time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	handler := listAuditEventsHandlerFor(auditEventActorIdentity(orgID, "usr_owner"), nil, reader)
	rec := getAuditEvents(handler, orgID, "", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeAuditEventList(t, rec.Body.Bytes())
	if len(env.Data.Events) != 1 {
		t.Fatalf("events len = %d, want 1", len(env.Data.Events))
	}
	e := env.Data.Events[0]
	if e.IPAddress != output.Sentinel {
		t.Errorf("ip_address = %q, want sentinel (handler must NOT undo persistence-layer redaction)", e.IPAddress)
	}
	if e.UserAgent != output.Sentinel {
		t.Errorf("user_agent = %q, want sentinel", e.UserAgent)
	}
	if e.Metadata["token"] != output.Sentinel {
		t.Errorf("metadata[token] = %q, want sentinel", e.Metadata["token"])
	}
	if e.Metadata["updated_resources"] != "projects" {
		t.Errorf("metadata[updated_resources] = %q, want projects (non-secret values pass through verbatim)", e.Metadata["updated_resources"])
	}
}
