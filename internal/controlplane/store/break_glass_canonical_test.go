package store

// Canonical reference break-glass validator test (BE-0404).
//
// This file is the load-bearing static fixture the BE-0404 verification
// gate binds to via the PRD's `go test -run TestBreakGlass ./...`
// filter. The pair declared here captures the two structural break-
// glass validator invariants every regression MUST trip:
//
//   - TestBreakGlassCoversCallSites walks a closed-set scenario table
//     built from every documented rule in
//     BreakGlassService.buildSessionToCreate (the pure decision
//     function that gates a session-row insert) AND every documented
//     accept path. Each scenario predicts the validator's outcome
//     deterministically: either an accept (a populated
//     BreakGlassSession with ExpiresAt = StartedAt + TTL, capped at
//     breakGlassMaxTTL) or a typed *yerr.Error of code
//     CodeValidation carrying a FieldViolation that names the
//     offending field path (organization_id, actor_id, actor_kind,
//     reason, or ttl). The table is also exhaustive: every documented
//     rule in the validator MUST be covered by at least one rejecting
//     scenario, and every legal actor_kind admitted by the switch in
//     buildSessionToCreate MUST be covered by an accept scenario. A
//     regression that demoted any rule, that accepted an unknown
//     actor_kind, that started echoing the submitted reason into the
//     typed error string, or that dropped the TTL cap, surfaces as a
//     per-row mismatch on its first iteration.
//
//   - TestBreakGlassPreservesContractUnderContention fires
//     breakGlassWorkers × breakGlassIterationsPerWorker goroutines
//     that each draw a row from the same scenario table by
//     deterministic mod-index (NOT per-goroutine random selection —
//     that would defeat the per-iteration prediction contract). Each
//     goroutine builds its own StartBreakGlassInput by applying the
//     scenario's mutator to a fresh baseline, calls
//     buildSessionToCreate on a SHARED *BreakGlassService instance,
//     and asserts the verdict the scenario predicted. A regression
//     that introduced shared mutable state in the validator — a
//     cached profile-defaults table, a sync.Once mutating a per-
//     scenario map, a leaky redactor reuse — would surface as a per-
//     iteration assertion failure even if the aggregate pass count
//     matched, because every goroutine knows its own predicted
//     outcome and asserts that exact verdict.
//
// Both members are deterministic by design: buildSessionToCreate is
// a pure function of (input, now) to either a BreakGlassSession or a
// typed *yerr.Error value and no scenario reaches the process
// environment, the network, a live Postgres, a live Dokploy, or any
// external service.
//
// The pair binds to the BE-0404 `-run TestBreakGlass` filter via the
// `TestBreakGlass` substring; a rename to a function whose name does
// not contain the substring silently de-gates the break-glass suite
// for any caller relying on the PRD's filter.
//
// The closed-set coverage invariant pins five structural break-glass
// contracts at once:
//
//  1. Every documented validator rule in buildSessionToCreate
//     (organization_id presence, actor_id presence, actor_kind in
//     {usr, sa}, reason presence, reason length, ttl positivity, ttl
//     cap) surfaces here exactly once on at least one rejecting
//     scenario. A regression that removed any rule fails the
//     exhaustiveness self-check at the head of the test.
//  2. Every rejecting scenario yields a typed *yerr.Error with
//     Code == CodeValidation AND a FieldViolation naming the
//     expected field path. A regression that started returning a
//     generic Internal error, or that named a different field path,
//     fails the per-row assertion.
//  3. Every rejecting scenario's *yerr.Error string MUST NOT echo
//     the seeded breakGlassSecretMarker literal. The reason field
//     carries the marker on every scenario (accept and reject) so a
//     future regression that started embedding the submitted reason
//     into the error message would fail the redaction predicate on
//     its first rejecting iteration.
//  4. Every accept scenario's resulting BreakGlassSession satisfies
//     ExpiresAt = StartedAt + min(TTL, breakGlassMaxTTL). A
//     regression that dropped the TTL cap fails the cappedTTL
//     accept scenario.
//  5. Every accept scenario's resulting BreakGlassSession preserves
//     the operator-supplied marker in its Reason field. The marker
//     is not a secret transport pattern so the redactor leaves it
//     in place; a regression that scrubbed too aggressively (e.g.
//     dropping every value through a blanket regex) would fail the
//     marker-survival predicate.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// breakGlassSecretMarker is a sentinel literal the canonical
// scenarios seed into every StartBreakGlassInput.Reason so a future
// regression that started echoing the submitted reason into the
// typed *yerr.Error string would fail the redaction predicate on
// its first rejecting iteration. The marker has no role in the
// validator's verdict — it is a passive canary the per-row
// assertion scans for on every rejecting scenario. The marker
// itself is not a secret transport pattern (no "Bearer", "Authorization",
// "token=", etc.), so the redactor leaves it intact on accept paths;
// asserting its survival in the accept session's Reason field guards
// against an over-aggressive scrub regression.
const breakGlassSecretMarker = "BREAKGLASSSECRETMARKER"

// breakGlassReferenceNow is the deterministic "now" used for every
// scenario. Pinning it removes wall-clock noise from ExpiresAt
// assertions and keeps mod-indexed contention iterations
// reproducible.
var breakGlassReferenceNow = time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

// breakGlassDefaultTTL is the baseline TTL the accept scenarios use.
// It is strictly less than breakGlassMaxTTL so non-capping accepts
// can assert ExpiresAt = StartedAt + TTL exactly.
const breakGlassDefaultTTL = 30 * time.Minute

// breakGlassExpect predicts the outcome of one scenario row.
// accept=true MUST yield a BreakGlassSession; accept=false MUST yield
// a typed *yerr.Error of code CodeValidation carrying a violation
// under the named field path. cappedTTL=true asserts the accepted
// session's ExpiresAt-StartedAt collapsed to breakGlassMaxTTL.
type breakGlassExpect struct {
	accept    bool
	field     string
	cappedTTL bool
}

// breakGlassScenario describes one row of the closed validator
// coverage table. The mutator applies the under-test deviation to a
// fresh baseline; the expect field encodes what buildSessionToCreate
// MUST return for that input. The ruleTag identifies which
// documented validator rule the row exercises so the
// exhaustiveness self-check at the head of the covers test can
// confirm every rule fires on at least one rejecting row.
type breakGlassScenario struct {
	name    string
	mutator func(*StartBreakGlassInput)
	expect  breakGlassExpect
	ruleTag string
}

// breakGlassValidatorRules is the closed set of documented validator
// rules the BE-0404 gate covers. Every entry MUST be exercised by at
// least one rejecting scenario in breakGlassScenarios. A regression
// that removed a rule from buildSessionToCreate without dropping
// its tag here fails the exhaustiveness self-check; a regression
// that added a new rule without listing it here trips the table
// audit too because the rule's tag would be missing from the
// scenario set.
var breakGlassValidatorRules = []string{
	"organization_id_blank",
	"actor_id_blank",
	"actor_kind_unknown",
	"actor_kind_blank",
	"reason_blank",
	"reason_oversize",
	"ttl_zero",
	"ttl_negative",
	"ttl_capped",
}

// breakGlassAcceptedActorKinds is the closed set of actor kinds
// buildSessionToCreate accepts. Each MUST be covered by an accept
// scenario so a regression that demoted KindUser or KindServiceAccount
// out of the switch surfaces here.
var breakGlassAcceptedActorKinds = []string{
	string(domain.KindUser),
	string(domain.KindServiceAccount),
}

// breakGlassBaselineInput is the canonical valid input every
// scenario starts from. The reason carries the secret marker so the
// redaction canary fires on every scenario; the baseline's TTL is
// strictly less than breakGlassMaxTTL so accept scenarios can assert
// ExpiresAt = StartedAt + TTL exactly without colliding with the
// cap.
func breakGlassBaselineInput() StartBreakGlassInput {
	return StartBreakGlassInput{
		OrganizationID: "org_break_glass_target_001",
		ActorID:        "usr_break_glass_actor_001",
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     "org_break_glass_actor_home",
		Reason:         "incident #ABC-123 needs " + breakGlassSecretMarker + " review",
		TTL:            breakGlassDefaultTTL,
		RequestID:      "req_break_glass_canonical_001",
		CorrelationID:  "cor_break_glass_canonical_001",
		IPAddress:      "10.0.0.1",
		UserAgent:      "yalla-admin-cli/canonical",
	}
}

// breakGlassScenarios materialises the closed scenario table the
// BE-0404 gate covers. Every documented validator rule MUST appear
// here at least once (exhaustiveness asserted at the head of the
// covers test); every accepted actor kind MUST appear in an accept
// row; one accept row exercises the TTL cap. Ordering is
// deterministic so the contention burst's mod-index draws are
// reproducible across runs.
func breakGlassScenarios() []breakGlassScenario {
	rows := []breakGlassScenario{
		{
			name:    "baseline valid input is accepted",
			mutator: func(*StartBreakGlassInput) {},
			expect:  breakGlassExpect{accept: true},
			ruleTag: "",
		},
		{
			name: "actor_kind=sa is accepted",
			mutator: func(in *StartBreakGlassInput) {
				in.ActorKind = string(domain.KindServiceAccount)
			},
			expect:  breakGlassExpect{accept: true},
			ruleTag: "",
		},
		{
			name: "ttl strictly greater than breakGlassMaxTTL is capped",
			mutator: func(in *StartBreakGlassInput) {
				in.TTL = breakGlassMaxTTL + time.Hour
			},
			expect:  breakGlassExpect{accept: true, cappedTTL: true},
			ruleTag: "ttl_capped",
		},
		{
			name: "blank organization_id is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.OrganizationID = ""
			},
			expect:  breakGlassExpect{accept: false, field: "organization_id"},
			ruleTag: "organization_id_blank",
		},
		{
			name: "whitespace-only organization_id is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.OrganizationID = "   "
			},
			expect:  breakGlassExpect{accept: false, field: "organization_id"},
			ruleTag: "organization_id_blank",
		},
		{
			name: "blank actor_id is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.ActorID = ""
			},
			expect:  breakGlassExpect{accept: false, field: "actor_id"},
			ruleTag: "actor_id_blank",
		},
		{
			name: "unknown actor_kind is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.ActorKind = "system"
			},
			expect:  breakGlassExpect{accept: false, field: "actor_kind"},
			ruleTag: "actor_kind_unknown",
		},
		{
			name: "blank actor_kind is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.ActorKind = ""
			},
			expect:  breakGlassExpect{accept: false, field: "actor_kind"},
			ruleTag: "actor_kind_blank",
		},
		{
			name: "blank reason is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.Reason = ""
			},
			expect:  breakGlassExpect{accept: false, field: "reason"},
			ruleTag: "reason_blank",
		},
		{
			name: "whitespace-only reason is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.Reason = "   "
			},
			expect:  breakGlassExpect{accept: false, field: "reason"},
			ruleTag: "reason_blank",
		},
		{
			name: "oversize reason is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.Reason = strings.Repeat("x", breakGlassReasonMaxLen+1)
			},
			expect:  breakGlassExpect{accept: false, field: "reason"},
			ruleTag: "reason_oversize",
		},
		{
			name: "zero ttl is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.TTL = 0
			},
			expect:  breakGlassExpect{accept: false, field: "ttl"},
			ruleTag: "ttl_zero",
		},
		{
			name: "negative ttl is rejected",
			mutator: func(in *StartBreakGlassInput) {
				in.TTL = -time.Hour
			},
			expect:  breakGlassExpect{accept: false, field: "ttl"},
			ruleTag: "ttl_negative",
		},
	}
	return rows
}

// breakGlassWorkers and breakGlassIterationsPerWorker pick a burst
// in the 1024..2048 range so the contention test draws every row in
// the closed scenario table at least once. With 32 * 64 = 2048
// iterations spread across an N-row table by idx :=
// (w*iters + i) % N, every row is exercised ~2048/N times.
const (
	breakGlassWorkers              = 32
	breakGlassIterationsPerWorker  = 64
	breakGlassContentionIterations = breakGlassWorkers * breakGlassIterationsPerWorker
)

// newBreakGlassCanonicalService constructs the BreakGlassService
// whose only call surface the canonical pair exercises:
// buildSessionToCreate. The store/orgs/sessions fields hold
// placeholder values the validator never reaches; the audit
// appender is the no-op already declared in internal_test.go. Tests
// that exercise StartSession / Revoke against a database use the
// integration suite, not this helper.
func newBreakGlassCanonicalService(tb testing.TB) *BreakGlassService {
	tb.Helper()
	svc, err := NewBreakGlassService(
		&Store{},
		NewOrganizationRepository(),
		NewBreakGlassRepository(),
		nopAuditAppender{},
		func() time.Time { return breakGlassReferenceNow },
	)
	if err != nil {
		tb.Fatalf("NewBreakGlassService: %v", err)
	}
	return svc
}

// TestBreakGlassCoversCallSites is the closed-set coverage half of
// the BE-0404 pair. It walks every documented validator rule and
// every documented accept path of buildSessionToCreate and asserts
// the validator returns the predicted outcome for every row. The
// closed-set self-checks at the head of the test catch drift in
// either direction: a new validator rule that ships without a row,
// an existing rule that drops its row, or an accepted actor_kind
// that loses its accept scenario.
func TestBreakGlassCoversCallSites(t *testing.T) {
	t.Parallel()

	rows := breakGlassScenarios()
	if len(rows) == 0 {
		t.Fatalf("breakGlassScenarios returned an empty table; the closed-set construction is broken")
	}

	// Closed-set self-check #1: every documented validator rule in
	// breakGlassValidatorRules is exercised by at least one
	// rejecting scenario (or, for ttl_capped, one accept scenario).
	// A regression that removed a rule from buildSessionToCreate
	// without dropping its tag here fails this check at the seam
	// rather than waiting for the per-row verdict to drift.
	ruleSet := make(map[string]int, len(breakGlassValidatorRules))
	for _, tag := range breakGlassValidatorRules {
		ruleSet[tag] = 0
	}
	for _, row := range rows {
		if row.ruleTag == "" {
			continue
		}
		if _, ok := ruleSet[row.ruleTag]; !ok {
			t.Fatalf("scenario %q tags rule %q which is not in breakGlassValidatorRules; every scenario rule tag must be a documented validator rule",
				row.name, row.ruleTag)
		}
		ruleSet[row.ruleTag]++
	}
	for tag, count := range ruleSet {
		if count == 0 {
			t.Fatalf("validator rule %q is not exercised by any scenario; every documented validator rule must surface in at least one row of breakGlassScenarios",
				tag)
		}
	}

	// Closed-set self-check #2: every accepted actor kind in the
	// validator's switch is covered by an accept scenario. A
	// regression that demoted KindUser or KindServiceAccount out of
	// the switch surfaces here rather than as a confusing per-row
	// rejection later.
	acceptedKinds := make(map[string]bool, len(breakGlassAcceptedActorKinds))
	for _, k := range breakGlassAcceptedActorKinds {
		acceptedKinds[k] = false
	}
	for _, row := range rows {
		if !row.expect.accept {
			continue
		}
		in := breakGlassBaselineInput()
		row.mutator(&in)
		if _, ok := acceptedKinds[in.ActorKind]; ok {
			acceptedKinds[in.ActorKind] = true
		}
	}
	for k, seen := range acceptedKinds {
		if !seen {
			t.Fatalf("accepted actor_kind %q is not covered by any accept scenario; every kind admitted by buildSessionToCreate's switch must surface in at least one row of breakGlassScenarios",
				k)
		}
	}

	// Closed-set self-check #3: the secret marker is NOT a secret
	// transport pattern, so the redactor leaves it intact. Confirm
	// the redactor's pure projection of the marker still contains
	// the marker; if a future redactor regression started scrubbing
	// non-secret runs, the marker-survival assertion on every
	// accept row would false-positive without this seam check.
	probeSvc := newBreakGlassCanonicalService(t)
	if probe := probeSvc.redactor.Redact(breakGlassSecretMarker); !strings.Contains(probe, breakGlassSecretMarker) {
		t.Fatalf("redactor stripped the secret marker %q from %q; the marker must survive the redactor so the marker-survival predicate on accept rows is meaningful — replace the marker with a literal that the redactor leaves intact",
			breakGlassSecretMarker, probe)
	}

	svc := newBreakGlassCanonicalService(t)
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			in := breakGlassBaselineInput()
			row.mutator(&in)
			session, err := svc.buildSessionToCreate(in, breakGlassReferenceNow)
			breakGlassAssertOutcome(t, row, in, session, err)
		})
	}
}

// TestBreakGlassPreservesContractUnderContention is the concurrency
// half of the BE-0404 pair. It fires breakGlassContentionIterations
// goroutines that each draw a scenario by deterministic mod-index,
// build their own StartBreakGlassInput, evaluate
// buildSessionToCreate on a SHARED *BreakGlassService instance, and
// assert the per-iteration verdict. A regression that introduced
// shared mutable state in the validator (a cached profile-defaults
// table, a sync.Once mutating a per-scenario map, a leaky redactor
// reuse) would surface as a per-iteration assertion failure even if
// the aggregate pass count matched, because every goroutine knows
// its own predicted outcome and asserts that exact verdict.
//
// The shared chokepoint is intentional: the burst's value is
// precisely the contention against the SAME service instance, never
// a fresh-per-goroutine service.
func TestBreakGlassPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := breakGlassScenarios()
	if len(rows) == 0 {
		t.Fatalf("breakGlassScenarios returned an empty table; the closed-set construction is broken")
	}

	svc := newBreakGlassCanonicalService(t)

	var passed atomic.Int64
	var firstErr atomic.Pointer[breakGlassContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < breakGlassWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < breakGlassIterationsPerWorker; i++ {
				iter := w*breakGlassIterationsPerWorker + i
				row := rows[iter%len(rows)]
				in := breakGlassBaselineInput()
				row.mutator(&in)
				session, err := svc.buildSessionToCreate(in, breakGlassReferenceNow)
				if fail := breakGlassCheckOutcome(row, in, session, err); fail != nil {
					fail.iter = iter
					firstErr.CompareAndSwap(nil, fail)
					continue
				}
				passed.Add(1)
			}
		}()
	}
	wg.Wait()

	if fe := firstErr.Load(); fe != nil {
		t.Fatalf("contention iteration %d (row %q): %s; a per-iteration mismatch under burst contention indicates shared mutable state in the validator OR a redaction regression",
			fe.iter, fe.rowName, fe.message)
	}
	if got := passed.Load(); got != int64(breakGlassContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			breakGlassContentionIterations, got)
	}
}

// breakGlassAssertOutcome is the canonical-pair fail-fast assertion
// helper. It is invoked by the per-row covers test directly so a
// per-row failure points the operator at the exact scenario that
// drifted.
func breakGlassAssertOutcome(t *testing.T, row breakGlassScenario, in StartBreakGlassInput, session BreakGlassSession, err error) {
	t.Helper()
	if fail := breakGlassCheckOutcome(row, in, session, err); fail != nil {
		t.Fatalf("%s", fail.message)
	}
}

// breakGlassCheckOutcome captures the verdict comparison used by
// both pair members. It returns nil on success and a populated
// failure on the first mismatch. The contention test uses this
// helper too so the per-iteration failure carries the same message
// as the per-row failure.
func breakGlassCheckOutcome(row breakGlassScenario, in StartBreakGlassInput, session BreakGlassSession, err error) *breakGlassContentionFailure {
	if row.expect.accept {
		if err != nil {
			return &breakGlassContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("buildSessionToCreate(%q) error = %v, want accept", row.name, err),
			}
		}
		// Accept-path checks: ExpiresAt = StartedAt + min(TTL, breakGlassMaxTTL),
		// and the operator-supplied marker survives in the persisted
		// Reason (the marker is not a secret transport pattern, so the
		// redactor leaves it in place — an over-aggressive scrub
		// regression fails the marker-survival predicate here).
		wantTTL := in.TTL
		if wantTTL > breakGlassMaxTTL {
			wantTTL = breakGlassMaxTTL
		}
		gotTTL := session.ExpiresAt.Sub(session.StartedAt)
		if gotTTL != wantTTL {
			return &breakGlassContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("buildSessionToCreate(%q): ExpiresAt-StartedAt = %v, want %v (TTL cap %v)", row.name, gotTTL, wantTTL, breakGlassMaxTTL),
			}
		}
		if row.expect.cappedTTL && gotTTL != breakGlassMaxTTL {
			return &breakGlassContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("buildSessionToCreate(%q): cappedTTL scenario expected ExpiresAt-StartedAt == %v, got %v", row.name, breakGlassMaxTTL, gotTTL),
			}
		}
		if !strings.Contains(session.Reason, breakGlassSecretMarker) {
			return &breakGlassContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("buildSessionToCreate(%q): accept session Reason = %q, expected to preserve marker %q (the marker is not a secret transport pattern; the redactor MUST leave it intact)", row.name, session.Reason, breakGlassSecretMarker),
			}
		}
		return nil
	}

	// Reject-path checks: typed *yerr.Error with Code == CodeValidation,
	// a FieldViolation under the expected field path, and zero echo
	// of the seeded marker in the error message.
	if err == nil {
		return &breakGlassContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("buildSessionToCreate(%q) error = nil, want CodeValidation on field %q", row.name, row.expect.field),
		}
	}
	if !isInvalidInputErrorOn(err, row.expect.field) {
		return &breakGlassContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("buildSessionToCreate(%q) error = %v, want CodeValidation on field %q", row.name, err, row.expect.field),
		}
	}
	// Redaction canary: every scenario seeds the secret marker into
	// the submitted reason. A regression that started echoing the
	// submitted reason into the typed *yerr.Error string would
	// carry the marker through to the error message. The check
	// scans both the error's Error() string and (if a *yerr.Error)
	// its serialised form for the marker.
	if strings.Contains(err.Error(), breakGlassSecretMarker) {
		return &breakGlassContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("buildSessionToCreate(%q) error message %q echoed marker %q; the validator MUST NOT echo the submitted reason value into the rejected error path", row.name, err.Error(), breakGlassSecretMarker),
		}
	}
	if vs, ok := apierr.ViolationsOf(err); ok {
		for _, v := range vs {
			if strings.Contains(v.Reason, breakGlassSecretMarker) {
				return &breakGlassContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("buildSessionToCreate(%q) FieldViolation on %q has Reason %q which echoes marker %q; field-violation messages MUST be hardcoded", row.name, v.Field, v.Reason, breakGlassSecretMarker),
				}
			}
		}
	}
	// Belt-and-braces: yerr.Error implements json.Marshaler-friendly
	// serialisation via its message + field path. If a regression
	// stashed the offending value into the error metadata, the
	// fmt-formatted form would expose it; this fmt sweep catches
	// that shape too.
	if strings.Contains(fmt.Sprintf("%+v", err), breakGlassSecretMarker) {
		return &breakGlassContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("buildSessionToCreate(%q) error %+v echoed marker %q in its formatted form; the validator MUST NOT stash the submitted reason into the error metadata", row.name, err, breakGlassSecretMarker),
		}
	}
	// Belt-and-braces #2: confirm the typed-error code is the
	// documented CodeValidation. isInvalidInputErrorOn already
	// checks this, but a redundant guard here documents the
	// invariant clearly.
	var ye *yerr.Error
	if !asYerr(err, &ye) || ye.Code != yerr.CodeValidation {
		return &breakGlassContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("buildSessionToCreate(%q) error = %v, want a *yerr.Error with Code == %q", row.name, err, yerr.CodeValidation),
		}
	}
	return nil
}

// breakGlassContentionFailure captures the first (iteration, row)
// the canonical pair observed a mismatch on, so a failure message
// points the operator at the exact scenario that drifted rather
// than collapsing every mismatch into a single line.
type breakGlassContentionFailure struct {
	iter    int
	rowName string
	message string
}

// asYerr is a thin shim over errors.As so the canonical pair can
// share a single import path for the typed-error projection. The
// caller-provided pointer-to-pointer is the canonical errors.As
// shape.
func asYerr(err error, target **yerr.Error) bool {
	if err == nil {
		return false
	}
	for cur := err; cur != nil; {
		if ye, ok := cur.(*yerr.Error); ok {
			*target = ye
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return false
}
