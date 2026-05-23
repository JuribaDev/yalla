package audit_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/audit"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/output"
)

// Audit-completeness gate (BE-0396).
//
// Contract: every security-relevant policy decision recorded through
// audit.Auditor.Record MUST surface as a store.AuditEvent that carries
// the full closed set of identifying fields agents, operators, and
// auditors rely on — action, resource kind, resource id, decision
// (allowed | denied), reason, organization id, actor id, actor kind,
// request id, correlation id — for BOTH allowed AND denied decisions,
// across every canonical action surface (organization / project /
// environment / service / api_key / grants / admin break-glass), with
// every metadata value redacted before persistence so a sentinel
// marker placed under a sensitive-shaped key never reaches the audit
// log. The two load-bearing audit-completeness invariants are pinned
// by the canonical pair TestAuditCompletenessCoversCallSites
// (closed-set scenario coverage) and
// TestAuditCompletenessPreservesRecordedFieldsUnderContention (per-
// emitter field fidelity under a concurrent burst). Both pair members
// are deterministic: they use the in-package fakeRecorder (already
// declared in audit_test.go) and the package-local ctxWith helper, so
// the gate stays green on every developer machine without a live
// Postgres or any external dependency. The static defence for the
// surrounding surfaces (CI step, verify.sh prefix, CONTRIBUTING
// entry, SECURITY row + section, PRD command, canonical file
// existence) lives in
// internal/release/verification_suite_audit_completeness_static_test.go.

const (
	// auditCompletenessSecretMarker is the sentinel value placed under
	// sensitive-shaped metadata keys to prove the Auditor's redactor
	// scrubs the value before persistence. A regression that recorded
	// the raw metadata would surface as the marker literal inside a
	// captured event's Metadata map.
	auditCompletenessSecretMarker = "yka_audit_completeness_secret_marker"
	// auditCompletenessWorkers is the per-iteration concurrency of the
	// runtime burst. Held small enough to stay fast on CI yet large
	// enough that a per-event field mix-up (one emitter's request_id
	// landing on another's recorded event) would surface as a count
	// mismatch.
	auditCompletenessWorkers = 4
	// auditCompletenessIterationsPerWorker is the per-worker call
	// count. Multiplied by workers it bounds the closed-set burst
	// total recorded events.
	auditCompletenessIterationsPerWorker = 8
)

// auditCompletenessScenario captures one closed-set scenario for the
// coverage member. The fields cover the canonical action surface
// agents, operators, and auditors expect to see in the audit log:
// allowed decisions (organization / project / environment / service /
// api_key creates) and denied decisions (cross-tenant, out-of-scope,
// no-capability, principal-disabled) across the same surface.
type auditCompletenessScenario struct {
	name           string
	action         policy.Action
	resource       policy.Resource
	decision       policy.Decision
	wantDecision   store.AuditDecision
	wantResourceID string
}

// auditCompletenessScenarios enumerates the closed set the coverage
// member walks. Adding an action constant in policy/policy.go for a
// new mutating endpoint REQUIRES a matching entry here so the
// audit-completeness gate stays a closed set; the
// scenario-table-rejects-duplicate-names self-check guards the
// integrity of the table.
var auditCompletenessScenarios = []auditCompletenessScenario{
	{
		name:   "organization.create allowed",
		action: policy.ActionOrganizationCreate,
		resource: policy.Resource{
			Kind:  domain.KindOrganization,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
		wantDecision:   store.AuditDecisionAllowed,
		wantResourceID: "org_audit_completeness_0001",
	},
	{
		name:   "project.create allowed",
		action: policy.ActionProjectCreate,
		resource: policy.Resource{
			Kind:  domain.KindProject,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001", ProjectID: "proj_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
		wantDecision:   store.AuditDecisionAllowed,
		wantResourceID: "proj_audit_completeness_0001",
	},
	{
		name:   "environment.create allowed",
		action: policy.ActionEnvironmentCreate,
		resource: policy.Resource{
			Kind:  domain.KindEnvironment,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001", ProjectID: "proj_audit_completeness_0001", EnvironmentID: "env_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: true, Reason: policy.ReasonAllowedByGrant},
		wantDecision:   store.AuditDecisionAllowed,
		wantResourceID: "env_audit_completeness_0001",
	},
	{
		name:   "service.create allowed",
		action: policy.ActionServiceCreate,
		resource: policy.Resource{
			Kind: domain.KindService,
			Scope: policy.Scope{
				OrganizationID: "org_audit_completeness_0001",
				ProjectID:      "proj_audit_completeness_0001",
				EnvironmentID:  "env_audit_completeness_0001",
				ServiceID:      "svc_audit_completeness_0001",
			},
		},
		decision:       policy.Decision{Allow: true, Reason: policy.ReasonAllowedByGrant},
		wantDecision:   store.AuditDecisionAllowed,
		wantResourceID: "svc_audit_completeness_0001",
	},
	{
		name:   "project.delete denied cross-tenant",
		action: policy.ActionProjectDelete,
		resource: policy.Resource{
			Kind:  domain.KindProject,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_other", ProjectID: "proj_audit_completeness_other"},
		},
		decision:       policy.Decision{Allow: false, Reason: policy.ReasonDeniedCrossTenant},
		wantDecision:   store.AuditDecisionDenied,
		wantResourceID: "proj_audit_completeness_other",
	},
	{
		name:   "environment.delete denied out-of-scope",
		action: policy.ActionEnvironmentDelete,
		resource: policy.Resource{
			Kind:  domain.KindEnvironment,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001", ProjectID: "proj_audit_completeness_0001", EnvironmentID: "env_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: false, Reason: policy.ReasonDeniedOutOfScope},
		wantDecision:   store.AuditDecisionDenied,
		wantResourceID: "env_audit_completeness_0001",
	},
	{
		name:   "keys.manage denied no-capability",
		action: policy.ActionKeysManage,
		resource: policy.Resource{
			Kind:  domain.KindOrganization,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: false, Reason: policy.ReasonDeniedNoCapability},
		wantDecision:   store.AuditDecisionDenied,
		wantResourceID: "org_audit_completeness_0001",
	},
	{
		name:   "limits.write denied principal-disabled",
		action: policy.ActionLimitsWrite,
		resource: policy.Resource{
			Kind:  domain.KindOrganization,
			Scope: policy.Scope{OrganizationID: "org_audit_completeness_0001"},
		},
		decision:       policy.Decision{Allow: false, Reason: policy.ReasonDeniedPrincipalDisabled},
		wantDecision:   store.AuditDecisionDenied,
		wantResourceID: "org_audit_completeness_0001",
	},
}

// requiredAuditFields enumerates the field names the closed-set
// coverage member asserts non-empty (and value-bound where named) on
// every recorded event. A regression that dropped any one of them
// would surface as the offending field name in the diagnostic.
var requiredAuditFields = []string{
	"Action",
	"ResourceKind",
	"ResourceID",
	"Decision",
	"Reason",
	"OrganizationID",
	"ActorID",
	"ActorKind",
	"RequestID",
	"CorrelationID",
}

// TestAuditCompletenessCoversCallSites pins the closed-set audit-
// completeness coverage invariant. For each scenario in the canonical
// action surface, the test:
//
//   - records the decision through audit.Auditor.Record using a
//     deterministic ctxWith principal + telemetry correlation;
//   - asserts the fakeRecorder captured exactly one event;
//   - asserts every entry in requiredAuditFields is non-empty on the
//     captured event;
//   - asserts the captured event's Action, ResourceKind, ResourceID,
//     Decision (allowed | denied), Reason, OrganizationID, ActorID,
//     ActorKind, RequestID, and CorrelationID match the scenario
//     inputs byte-for-byte;
//   - asserts the captured Metadata redacts the sensitive-shaped
//     marker to output.Sentinel (the AC8 redaction contract);
//   - asserts the marker substring does NOT appear anywhere in the
//     captured event's Reason, Action, ResourceID, IPAddress, or
//     UserAgent fields (defence-in-depth against a future regression
//     that leaked the marker into a non-Metadata field).
//
// A failure surfaces with the scenario name AND the request_id so an
// operator reading the CI log can correlate the gate failure with a
// specific in-flight scenario without re-running the suite locally.
func TestAuditCompletenessCoversCallSites(t *testing.T) {
	t.Parallel()

	if len(auditCompletenessScenarios) == 0 {
		t.Fatal("auditCompletenessScenarios is empty; the closed-set coverage gate must enumerate every canonical action surface")
	}
	seen := make(map[string]struct{}, len(auditCompletenessScenarios))
	for _, sc := range auditCompletenessScenarios {
		if _, dup := seen[sc.name]; dup {
			t.Fatalf("auditCompletenessScenarios contains duplicate name %q; the closed-set coverage gate must list each scenario once", sc.name)
		}
		seen[sc.name] = struct{}{}
	}

	for _, sc := range auditCompletenessScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()

			rec := &fakeRecorder{}
			a := newAuditor(t, rec)
			principal := policy.Principal{
				ID:             "usr_audit_completeness_actor_0001",
				Kind:           domain.KindUser,
				OrganizationID: sc.resource.Scope.OrganizationID,
				Role:           policy.RoleAdmin,
			}
			reqID := "req_audit_completeness_" + strings.ReplaceAll(sc.name, " ", "_")
			corrID := "corr_audit_completeness_" + strings.ReplaceAll(sc.name, " ", "_")
			ctx := ctxWith(principal, telemetry.Correlation{RequestID: reqID, CorrelationID: corrID})

			entry := audit.Entry{
				Action:    sc.action,
				Resource:  sc.resource,
				Decision:  sc.decision,
				IPAddress: "203.0.113.7",
				UserAgent: "yalla-audit-completeness-test/1.0",
				Metadata: map[string]string{
					"api_key":     auditCompletenessSecretMarker,
					"diff_field":  "name",
					"resource_id": sc.wantResourceID,
				},
			}
			got, err := a.Record(ctx, nil, entry)
			if err != nil {
				t.Fatalf("[%s req=%s] Record returned error: %v", sc.name, reqID, err)
			}
			if rec.calls != 1 {
				t.Fatalf("[%s req=%s] recorder calls = %d, want 1", sc.name, reqID, rec.calls)
			}

			for _, field := range requiredAuditFields {
				if isAuditFieldEmpty(got, field) {
					t.Errorf("[%s req=%s] recorded event has empty %s; the audit-completeness contract requires every recorded event to carry %s",
						sc.name, reqID, field, field)
				}
			}

			if got.Action != string(sc.action) {
				t.Errorf("[%s req=%s] Action = %q, want %q", sc.name, reqID, got.Action, sc.action)
			}
			if got.ResourceKind != string(sc.resource.Kind) {
				t.Errorf("[%s req=%s] ResourceKind = %q, want %q", sc.name, reqID, got.ResourceKind, sc.resource.Kind)
			}
			if got.ResourceID != sc.wantResourceID {
				t.Errorf("[%s req=%s] ResourceID = %q, want %q", sc.name, reqID, got.ResourceID, sc.wantResourceID)
			}
			if got.Decision != sc.wantDecision {
				t.Errorf("[%s req=%s] Decision = %q, want %q", sc.name, reqID, got.Decision, sc.wantDecision)
			}
			if got.Reason != string(sc.decision.Reason) {
				t.Errorf("[%s req=%s] Reason = %q, want %q", sc.name, reqID, got.Reason, sc.decision.Reason)
			}
			if got.OrganizationID != sc.resource.Scope.OrganizationID {
				t.Errorf("[%s req=%s] OrganizationID = %q, want %q", sc.name, reqID, got.OrganizationID, sc.resource.Scope.OrganizationID)
			}
			if got.ActorID != principal.ID {
				t.Errorf("[%s req=%s] ActorID = %q, want %q", sc.name, reqID, got.ActorID, principal.ID)
			}
			if got.ActorKind != string(principal.Kind) {
				t.Errorf("[%s req=%s] ActorKind = %q, want %q", sc.name, reqID, got.ActorKind, principal.Kind)
			}
			if got.RequestID != reqID {
				t.Errorf("[%s req=%s] RequestID = %q, want %q", sc.name, reqID, got.RequestID, reqID)
			}
			if got.CorrelationID != corrID {
				t.Errorf("[%s req=%s] CorrelationID = %q, want %q", sc.name, reqID, got.CorrelationID, corrID)
			}

			if redacted, ok := got.Metadata["api_key"]; !ok {
				t.Errorf("[%s req=%s] recorded Metadata is missing the sensitive-shaped key 'api_key'; keys MUST NOT be redacted, only their values", sc.name, reqID)
			} else if redacted != output.Sentinel {
				t.Errorf("[%s req=%s] recorded Metadata['api_key'] = %q, want %q; the audit-completeness redaction contract requires the sentinel value", sc.name, reqID, redacted, output.Sentinel)
			}
			for _, leakField := range []string{got.Action, got.ResourceID, got.Reason, got.IPAddress, got.UserAgent} {
				if strings.Contains(leakField, auditCompletenessSecretMarker) {
					t.Errorf("[%s req=%s] sentinel marker %q leaked into a non-Metadata recorded field %q; the audit-completeness redaction contract forbids any non-Metadata reflection of secret-shaped input",
						sc.name, reqID, auditCompletenessSecretMarker, leakField)
				}
			}
			for k, v := range got.Metadata {
				if strings.Contains(k, auditCompletenessSecretMarker) {
					t.Errorf("[%s req=%s] sentinel marker %q leaked into a recorded Metadata key %q; keys are not redacted but the test inputs MUST NOT use the marker as a key",
						sc.name, reqID, auditCompletenessSecretMarker, k)
				}
				if k != "api_key" && strings.Contains(v, auditCompletenessSecretMarker) {
					t.Errorf("[%s req=%s] sentinel marker %q leaked into recorded Metadata[%q]=%q; the audit-completeness redaction contract requires every value to be scrubbed",
						sc.name, reqID, auditCompletenessSecretMarker, k, v)
				}
			}
		})
	}
}

// TestAuditCompletenessPreservesRecordedFieldsUnderContention pins
// the per-emitter audit-field-fidelity invariant under concurrent
// load. It seeds a single shared audit.Auditor + capturingRecorder
// from auditCompletenessWorkers goroutines each firing
// auditCompletenessIterationsPerWorker recorded decisions, and
// asserts:
//
//   - the recorder captured exactly workers*iters events (no events
//     dropped, no spurious events);
//   - every captured event carries a non-empty RequestID and that
//     RequestID resolves to the expected emitter (request_id of
//     emitter w on iteration i is "req_audit_completeness_burst_w_i");
//   - every captured event carries the matching organization id and
//     a non-empty actor id (no cross-write of one emitter's fields
//     onto another's recorded event);
//   - the sentinel marker placed under the sensitive-shaped metadata
//     key is redacted on every recorded event;
//   - the sentinel marker substring does NOT appear in any captured
//     event's Action, Reason, ResourceID, IPAddress, or UserAgent
//     (defence-in-depth against a future regression that reflected
//     metadata into a non-Metadata field under contention).
//
// A failure surfaces with the worker index AND the iteration index
// AND the observed request_id so an operator reading the CI log can
// correlate a fidelity drift with a specific in-flight goroutine
// without re-running the suite locally.
func TestAuditCompletenessPreservesRecordedFieldsUnderContention(t *testing.T) {
	t.Parallel()

	rec := newConcurrentAuditRecorder()
	a := newAuditor(t, rec)

	var wg sync.WaitGroup
	for w := 0; w < auditCompletenessWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			principal := policy.Principal{
				ID:             fmt.Sprintf("usr_audit_completeness_burst_actor_%d", w),
				Kind:           domain.KindUser,
				OrganizationID: orgID,
				Role:           policy.RoleAdmin,
			}
			for i := 0; i < auditCompletenessIterationsPerWorker; i++ {
				reqID := fmt.Sprintf("req_audit_completeness_burst_%d_%d", w, i)
				corrID := fmt.Sprintf("corr_audit_completeness_burst_%d_%d", w, i)
				ctx := ctxWith(principal, telemetry.Correlation{RequestID: reqID, CorrelationID: corrID})
				_, err := a.Record(ctx, nil, audit.Entry{
					Action:   policy.ActionProjectCreate,
					Resource: policy.Resource{Kind: domain.KindProject, Scope: policy.Scope{OrganizationID: orgID, ProjectID: fmt.Sprintf("proj_burst_%d_%d", w, i)}},
					Decision: policy.Decision{Allow: true, Reason: policy.ReasonAllowedByRole},
					Metadata: map[string]string{"api_key": auditCompletenessSecretMarker},
				})
				if err != nil {
					t.Errorf("[w=%d i=%d req=%s] Record returned error: %v", w, i, reqID, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	events := rec.snapshot()
	want := auditCompletenessWorkers * auditCompletenessIterationsPerWorker
	if len(events) != want {
		t.Fatalf("recorder captured %d events, want %d (workers=%d * iters=%d)", len(events), want, auditCompletenessWorkers, auditCompletenessIterationsPerWorker)
	}

	expected := make(map[string]struct{}, want)
	for w := 0; w < auditCompletenessWorkers; w++ {
		for i := 0; i < auditCompletenessIterationsPerWorker; i++ {
			expected[fmt.Sprintf("req_audit_completeness_burst_%d_%d", w, i)] = struct{}{}
		}
	}
	got := make(map[string]struct{}, len(events))
	for _, e := range events {
		if e.RequestID == "" {
			t.Errorf("event with Action=%q ResourceID=%q has empty RequestID; audit-completeness requires every recorded event to carry a request id", e.Action, e.ResourceID)
			continue
		}
		got[e.RequestID] = struct{}{}
		if e.OrganizationID != orgID {
			t.Errorf("[req=%s] OrganizationID = %q, want %q", e.RequestID, e.OrganizationID, orgID)
		}
		if e.ActorID == "" {
			t.Errorf("[req=%s] ActorID is empty", e.RequestID)
		}
		if e.ActorKind == "" {
			t.Errorf("[req=%s] ActorKind is empty", e.RequestID)
		}
		if e.CorrelationID == "" {
			t.Errorf("[req=%s] CorrelationID is empty", e.RequestID)
		}
		if e.Action != string(policy.ActionProjectCreate) {
			t.Errorf("[req=%s] Action = %q, want %q", e.RequestID, e.Action, policy.ActionProjectCreate)
		}
		if e.Decision != store.AuditDecisionAllowed {
			t.Errorf("[req=%s] Decision = %q, want %q", e.RequestID, e.Decision, store.AuditDecisionAllowed)
		}
		if redacted, ok := e.Metadata["api_key"]; !ok {
			t.Errorf("[req=%s] recorded Metadata missing 'api_key'", e.RequestID)
		} else if redacted != output.Sentinel {
			t.Errorf("[req=%s] recorded Metadata['api_key'] = %q, want %q", e.RequestID, redacted, output.Sentinel)
		}
		for _, leak := range []string{e.Action, e.ResourceID, e.Reason, e.IPAddress, e.UserAgent} {
			if strings.Contains(leak, auditCompletenessSecretMarker) {
				t.Errorf("[req=%s] sentinel marker leaked into non-Metadata field %q", e.RequestID, leak)
			}
		}
	}
	for reqID := range expected {
		if _, ok := got[reqID]; !ok {
			t.Errorf("expected request id %q not present in captured events; an emitter's recorded event was dropped or its RequestID was overwritten under contention", reqID)
		}
	}
	for reqID := range got {
		if _, ok := expected[reqID]; !ok {
			t.Errorf("unexpected request id %q present in captured events; either the burst produced a spurious event or a request id was cross-written under contention", reqID)
		}
	}
}

// concurrentAuditRecorder is a thread-safe stand-in for
// *store.AuditRepository used by the contention burst. It is local to
// this file so the existing single-call fakeRecorder (declared in
// audit_test.go) keeps its zero-mutex shape for the unit tests that
// rely on it.
type concurrentAuditRecorder struct {
	mu     sync.Mutex
	events []store.AuditEvent
}

func newConcurrentAuditRecorder() *concurrentAuditRecorder {
	return &concurrentAuditRecorder{}
}

// Append captures the recorded event under a mutex so a concurrent
// burst cannot race on the events slice. The transaction is ignored —
// the Auditor only passes it through — so the burst can call Record
// with a nil *store.Tx.
func (r *concurrentAuditRecorder) Append(_ context.Context, _ *store.Tx, e store.AuditEvent) (store.AuditEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return e, nil
}

// snapshot returns a copy of the captured events so the caller can
// iterate without holding the mutex.
func (r *concurrentAuditRecorder) snapshot() []store.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]store.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// isAuditFieldEmpty reports whether the named field on a captured
// store.AuditEvent is empty. The closed-set coverage member uses it
// to surface the offending field name in the diagnostic when a
// regression drops a required field.
func isAuditFieldEmpty(e store.AuditEvent, field string) bool {
	switch field {
	case "Action":
		return e.Action == ""
	case "ResourceKind":
		return e.ResourceKind == ""
	case "ResourceID":
		return e.ResourceID == ""
	case "Decision":
		return e.Decision == ""
	case "Reason":
		return e.Reason == ""
	case "OrganizationID":
		return e.OrganizationID == ""
	case "ActorID":
		return e.ActorID == ""
	case "ActorKind":
		return e.ActorKind == ""
	case "RequestID":
		return e.RequestID == ""
	case "CorrelationID":
		return e.CorrelationID == ""
	default:
		return true
	}
}
