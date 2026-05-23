package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/audit"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Unit tests for the Auditor — the service that maps a policy decision plus
// request context into a redacted, immutable audit record. They use a fake
// Recorder, so they need no database: the persistence half of the audit log is
// integration-tested in package store_test.

// fakeRecorder is a stand-in for *store.AuditRepository that captures the
// event it was asked to append. It ignores the transaction — the Auditor only
// passes it through — so the unit tests can call Record with a nil *store.Tx.
type fakeRecorder struct {
	got   store.AuditEvent
	calls int
	err   error
}

func (r *fakeRecorder) Append(_ context.Context, _ *store.Tx, e store.AuditEvent) (store.AuditEvent, error) {
	r.calls++
	r.got = e
	if r.err != nil {
		return store.AuditEvent{}, r.err
	}
	return e, nil
}

// orgID is a stable organization id reused across the table tests.
const orgID = "org_audit_test_0001"

// ctxWith builds a request context carrying principal and correlation, the way
// the auth and telemetry middleware would have populated it.
func ctxWith(principal policy.Principal, c telemetry.Correlation) context.Context {
	ctx := telemetry.WithCorrelation(context.Background(), c)
	return policy.WithPrincipal(ctx, principal)
}

func newAuditor(t *testing.T, rec audit.Recorder) *audit.Auditor {
	t.Helper()
	a, err := audit.NewAuditor(rec)
	if err != nil {
		t.Fatalf("NewAuditor: %v", err)
	}
	return a
}

func TestNewAuditorNilRecorder(t *testing.T) {
	t.Parallel()

	if _, err := audit.NewAuditor(nil); err == nil {
		t.Fatal("NewAuditor(nil) returned no error")
	}
}

func TestAuditorRecordAllowedDecision(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	a := newAuditor(t, rec)
	principal := policy.Principal{
		ID:             "usr_actor_0001",
		Kind:           domain.KindUser,
		OrganizationID: orgID,
		Role:           policy.RoleAdmin,
	}
	ctx := ctxWith(principal, telemetry.Correlation{RequestID: "req-1", CorrelationID: "corr-1"})

	got, err := a.Record(ctx, nil, audit.Entry{
		Action:   "project.create",
		Resource: policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: orgID, ProjectID: "proj_1"}},
		Decision: policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("recorder calls = %d, want 1", rec.calls)
	}
	if got.Decision != store.AuditDecisionAllowed {
		t.Errorf("Decision = %q, want allowed", got.Decision)
	}
	if got.Reason != string(policy.ReasonAllowedByRole) {
		t.Errorf("Reason = %q, want %q", got.Reason, policy.ReasonAllowedByRole)
	}
	if got.OrganizationID != orgID || got.ActorID != principal.ID || got.ActorKind != string(domain.KindUser) {
		t.Errorf("actor/org = %q/%q/%q, want %q/%q/%q",
			got.OrganizationID, got.ActorID, got.ActorKind, orgID, principal.ID, domain.KindUser)
	}
	if got.Action != "project.create" || got.ResourceKind != string(domain.KindProject) || got.ResourceID != "proj_1" {
		t.Errorf("action/kind/id = %q/%q/%q, want project.create/proj/proj_1", got.Action, got.ResourceKind, got.ResourceID)
	}
	if got.RequestID != "req-1" || got.CorrelationID != "corr-1" {
		t.Errorf("correlation = %q/%q, want req-1/corr-1", got.RequestID, got.CorrelationID)
	}
}

// TestAuditorRecordDeniedDecision proves a denied decision — including one with
// no authenticated principal — is recorded just like an allowed one. The audit
// log must answer "who was refused what".
func TestAuditorRecordDeniedDecision(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	a := newAuditor(t, rec)
	// No principal on the context: an unauthenticated request that was denied.
	ctx := telemetry.WithCorrelation(context.Background(), telemetry.Correlation{RequestID: "req-2"})

	got, err := a.Record(ctx, nil, audit.Entry{
		Action:   "project.delete",
		Resource: policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: orgID, ProjectID: "proj_9"}},
		Decision: policy.Decision{Allow: false, Reason: policy.ReasonDeniedNoPrincipal},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got.Decision != store.AuditDecisionDenied {
		t.Errorf("Decision = %q, want denied", got.Decision)
	}
	if got.Reason != string(policy.ReasonDeniedNoPrincipal) {
		t.Errorf("Reason = %q, want %q", got.Reason, policy.ReasonDeniedNoPrincipal)
	}
	// No principal: the actor fields are empty, and the event is filed under
	// the targeted resource's organization.
	if got.ActorID != "" || got.ActorKind != "" {
		t.Errorf("denied unauthenticated event carried an actor: id=%q kind=%q", got.ActorID, got.ActorKind)
	}
	if got.OrganizationID != orgID {
		t.Errorf("OrganizationID = %q, want %q (from the resource scope)", got.OrganizationID, orgID)
	}
}

// TestAuditorRecordRedactsMetadata proves the Auditor never lets a secret reach
// the audit log: a value under a secret-shaped key is replaced wholesale, and a
// value carrying a known secret transport pattern is scrubbed.
func TestAuditorRecordRedactsMetadata(t *testing.T) {
	t.Parallel()

	const (
		keyedSecret    = "yk_live_super_secret_key_value"
		transportToken = "Bearer abcdef0123456789secret"
	)
	rec := &fakeRecorder{}
	a := newAuditor(t, rec)
	principal := policy.Principal{ID: "usr_1", Kind: domain.KindUser, OrganizationID: orgID, Role: policy.RoleAdmin}
	ctx := ctxWith(principal, telemetry.Correlation{RequestID: "req-3"})

	got, err := a.Record(ctx, nil, audit.Entry{
		Action:    "apikey.create",
		Resource:  policy.Resource{Kind: domain.KindAPIKey, Scope: policy.Scope{OrganizationID: orgID}},
		Decision:  policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
		UserAgent: "Authorization: " + transportToken,
		Metadata: map[string]string{
			"api_token":   keyedSecret,
			"changed":     "name",
			"raw_header":  "Authorization: " + transportToken,
			"description": "rotated the key",
		},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// The value under the secret-shaped key is replaced wholesale.
	if got.Metadata["api_token"] != output.Sentinel {
		t.Errorf("metadata[api_token] = %q, want %q", got.Metadata["api_token"], output.Sentinel)
	}
	// A non-secret key is preserved verbatim.
	if got.Metadata["changed"] != "name" {
		t.Errorf("metadata[changed] = %q, want it preserved", got.Metadata["changed"])
	}
	// A transport pattern in an ordinary value is still scrubbed.
	if strings.Contains(got.Metadata["raw_header"], transportToken) {
		t.Errorf("metadata[raw_header] still contains the token: %q", got.Metadata["raw_header"])
	}
	if !strings.Contains(got.Metadata["raw_header"], output.Sentinel) {
		t.Errorf("metadata[raw_header] = %q, want it redacted", got.Metadata["raw_header"])
	}
	// The user agent is scrubbed of the same pattern.
	if strings.Contains(got.UserAgent, transportToken) {
		t.Errorf("UserAgent still contains the token: %q", got.UserAgent)
	}

	// Defence in depth: no rendering of the stored event leaks either secret.
	testutil.AssertRedactedValue(t, got, keyedSecret, transportToken)
}

func TestAuditorRecordValidationFailures(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{}
	a := newAuditor(t, rec)
	principal := policy.Principal{ID: "usr_1", Kind: domain.KindUser, OrganizationID: orgID, Role: policy.RoleAdmin}
	validResource := policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: orgID}}
	validDecision := policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole}

	tests := []struct {
		name  string
		ctx   context.Context
		entry audit.Entry
	}{
		{
			name:  "blank action",
			ctx:   ctxWith(principal, telemetry.Correlation{}),
			entry: audit.Entry{Action: "  ", Resource: validResource, Decision: validDecision},
		},
		{
			name:  "missing resource kind",
			ctx:   ctxWith(principal, telemetry.Correlation{}),
			entry: audit.Entry{Action: "project.create", Resource: policy.Resource{Scope: policy.Scope{OrganizationID: orgID}}, Decision: validDecision},
		},
		{
			name:  "missing decision reason",
			ctx:   ctxWith(principal, telemetry.Correlation{}),
			entry: audit.Entry{Action: "project.create", Resource: validResource, Decision: policy.Decision{Allow: true}},
		},
		{
			name: "unresolvable organization",
			ctx:  context.Background(), // no principal, and the resource scope names no org
			entry: audit.Entry{
				Action:   "project.create",
				Resource: policy.Resource{Kind: domain.KindProject},
				Decision: validDecision,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := a.Record(tc.ctx, nil, tc.entry)
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("Record(%s) error code = %v, want %s", tc.name, err, yerr.CodeValidation)
			}
		})
	}
}

func TestAuditorRecordPropagatesRecorderError(t *testing.T) {
	t.Parallel()

	rec := &fakeRecorder{err: errors.New("datastore down")}
	a := newAuditor(t, rec)
	principal := policy.Principal{ID: "usr_1", Kind: domain.KindUser, OrganizationID: orgID, Role: policy.RoleAdmin}
	ctx := ctxWith(principal, telemetry.Correlation{})

	_, err := a.Record(ctx, nil, audit.Entry{
		Action:   "project.create",
		Resource: policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: orgID}},
		Decision: policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
	})
	if err == nil {
		t.Fatal("Record returned nil, want the recorder's error")
	}
}
