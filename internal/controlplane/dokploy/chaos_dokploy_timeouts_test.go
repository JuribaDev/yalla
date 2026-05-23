package dokploy_test

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Verification suite — chaos tests for Dokploy timeouts (BE-0393).
//
// The canonical pair below is the load-bearing test pair that the PRD's
// `go test -run TestChaosDokployTimeouts ./...` filter binds to. Together
// they pin two complementary chaos-timeout invariants:
//
//   - TestChaosDokployTimeoutsCoversCallSites pins the closed-set
//     chaos-scenario coverage invariant. The scenario table the burst
//     harness iterates MUST stay non-empty, free of duplicates, scoped to
//     the typed Dokploy client surface (GET, POST, DELETE call sites the
//     real provisioning intents use), and every scenario MUST declare a
//     valid HTTP method, a positive injected delay, a closed-set
//     expected error code (yerr.CodeTimeout), a closed-set expected
//     dependency (apierr.DependencyDokploy), and an attempt-count
//     consistent with the client's idempotency rule (POST attempted
//     exactly once; GET/DELETE attempted 1 + MaxRetries). This member is
//     deterministic — it walks an in-memory fixture table and trips on
//     every developer machine without spinning up the fake server.
//
//   - TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope pins the runtime
//     chaos invariant. Spinning the typed Dokploy client up against a
//     per-worker fake-Dokploy server (so the FIFO fault queue stays
//     isolated under concurrent goroutines) and firing chaosWorkers *
//     chaosIterationsPerWorker concurrent scenario invocations MUST yield
//     only failures that (a) are typed *yerr.Error values with
//     Code=yerr.CodeTimeout, (b) report apierr.DependencyDokploy via
//     apierr.DependencyOf, (c) carry no Dokploy bearer token literal at
//     any level of the wrapped cause chain, (d) record exactly
//     scenario.expectedAttempts requests against the fake (so a regression
//     that quietly retries a POST or stops retrying a GET trips here),
//     (e) propagate the caller's telemetry.HeaderRequestID into every
//     recorded request so an operator can correlate the gate failure
//     with the offending request_id, and (f) leave the Authorization
//     header redacted to output.Sentinel in every recorded request.
//     Failures surface with the offending scenario name AND the observed
//     request_id so an operator can correlate.
//
// Both members are deterministic by design: the fake-Dokploy server is
// the one dependency the chaos harness needs, and it is constructed
// in-process per worker so no Postgres and no live Dokploy server are
// required. The TimeoutFault honours r.Context().Done() so each
// per-attempt timeout cancels the in-flight request and the harness
// finishes well under one second. The static verification suite under
// `internal/release/verification_suite_chaos_dokploy_timeouts_static_test.go`
// pins every collateral surface (CI step, verify.sh entry, CONTRIBUTING
// entry, SECURITY row+section, PRD command, and this canonical pair's
// existence) so that a rename or deletion trips ONE test, not six.

// chaosTimeoutScenario is one entry in the closed set of Dokploy
// timeout chaos scenarios the burst harness MUST exercise. Each entry
// is intentionally scoped to a real client call site the worker uses
// (GET deployment, POST organization, DELETE service) so a regression
// in either the per-attempt timeout, the idempotency-aware retry
// budget, or the typed-error mapping trips on the call site that
// actually ships.
type chaosTimeoutScenario struct {
	// name is the human-readable scenario label that surfaces in every
	// diagnostic; it MUST be unique across the table so an operator
	// reading a failure can map back to exactly one row.
	name string
	// method is the HTTP method the client.attempt round trip will use.
	// The closed-set member validates it against the typed-client
	// idempotency rule (POST is never retried; GET and DELETE are
	// retried up to MaxRetries times).
	method string
	// expectedAttempts is the number of HTTP attempts the client MUST
	// make under sustained timeout chaos. POST = 1 (no retry); GET and
	// DELETE = 1 + MaxRetries (initial attempt + bounded retry budget).
	expectedAttempts int
	// expectedCode is the yerr.Code the typed *yerr.Error MUST surface
	// to the caller. Timeout chaos MUST always map to yerr.CodeTimeout
	// — a regression that surfaces E_INTERNAL, E_UNAVAILABLE, or
	// E_DOKPLOY_UNAVAILABLE on the timeout path would mis-classify the
	// failure and defeat the dependency-aware retry surface upstream.
	expectedCode yerr.Code
	// expectedDependency is the apierr.Dependency the typed error MUST
	// carry. Every chaos-timeout failure MUST attribute to
	// DependencyDokploy so an operator reading the failure knows which
	// upstream is in trouble without grepping the log path.
	expectedDependency apierr.Dependency
	// call invokes the scenario's client method against c. The callback
	// MUST return the error directly (without any nil-shadowing) so the
	// runtime member can assert against the catalogued typed error.
	call func(ctx context.Context, c *dokploy.Client) error
}

// chaosTimeoutMaxRetries bounds the retry budget every retryable
// scenario receives in the runtime burst. Keeping it small keeps the
// gate fast on every developer machine: per-attempt timeout × (1 +
// MaxRetries) is the worst-case wall-clock the runtime member spends
// per goroutine, plus the (1ms + 2ms) backoff cap from
// chaosTimeoutRetryBaseDelay/chaosTimeoutRetryMaxDelay.
const chaosTimeoutMaxRetries = 2

// chaosTimeoutPerAttemptTimeout is the per-attempt timeout the typed
// client uses inside the runtime member. It MUST be small enough that
// 1 + MaxRetries attempts complete well under one second per
// goroutine, and large enough that the fake's TimeoutFault scheduler
// reliably observes the context cancellation before it fires. Keep this
// comfortably above scheduler stalls seen under `go test -race`: if the
// deadline expires before the httptest handler records the request, the
// idempotency assertion observes a false missing attempt instead of a
// client retry-policy regression.
const chaosTimeoutPerAttemptTimeout = 250 * time.Millisecond

// chaosTimeoutFaultDelay is the sleep every queued TimeoutFault uses
// inside the runtime member. It MUST be substantially larger than
// chaosTimeoutPerAttemptTimeout so the per-attempt deadline always
// fires first; the fake's applyFault returns early when the request
// context is cancelled, so the fault wall-clock cost is bounded by
// the per-attempt timeout, not this constant.
const chaosTimeoutFaultDelay = 2 * time.Second

// chaosTimeoutRetryBaseDelay and chaosTimeoutRetryMaxDelay keep the
// inter-attempt backoff sub-millisecond so the runtime member stays
// fast. The real client's default backoff (200ms/5s) is exercised by
// TestClientRetriesIdempotentRequests; the chaos member is about the
// classification invariant, not the production backoff schedule.
const (
	chaosTimeoutRetryBaseDelay = time.Millisecond
	chaosTimeoutRetryMaxDelay  = 2 * time.Millisecond
)

// chaosWorkers and chaosIterationsPerWorker bound the burst the
// runtime member fires per scenario. The product (workers *
// iterations * scenarios) MUST stay small enough that the test
// completes in well under five seconds on a developer laptop and on
// every CI runner, otherwise the gate becomes flaky. Each iteration
// runs in its own goroutine with its own fake-Dokploy server (so the
// FIFO fault queue stays isolated) and observes via a buffered
// channel sized to the total observation count.
const (
	chaosWorkers             = 4
	chaosIterationsPerWorker = 3
)

// chaosTimeoutSecretMarkers is the closed set of substrings the
// runtime member MUST never observe in any error chain emitted by the
// client. Each marker represents one redaction contract the typed
// client MUST keep even when classifying chaos-timeout failures:
// Dokploy bearer prefix, the canonical Yalla API key prefix, the
// bearer scheme header value, and the literal Dokploy token env var
// name. The list is intentionally short so a new redaction contract
// can be added in one edit.
var chaosTimeoutSecretMarkers = []string{
	dokployfake.DefaultToken,
	"yka_",
	"Bearer ",
	"DOKPLOY_TOKEN",
}

// chaosTimeoutScenarios is the closed set. Keep it small,
// deterministic, and scoped to real client call sites the worker
// exercises. The TestChaosDokployTimeouts* pair MUST stay green on
// every developer machine without any infrastructure dependency other
// than the in-process fake.
var chaosTimeoutScenarios = []chaosTimeoutScenario{
	{
		name:               "GET deployment under sustained timeout retries within bound",
		method:             http.MethodGet,
		expectedAttempts:   1 + chaosTimeoutMaxRetries,
		expectedCode:       yerr.CodeTimeout,
		expectedDependency: apierr.DependencyDokploy,
		call: func(ctx context.Context, c *dokploy.Client) error {
			_, err := c.GetDeployment(ctx, "dep_chaos")
			return err
		},
	},
	{
		name:               "POST organization under timeout never retries",
		method:             http.MethodPost,
		expectedAttempts:   1,
		expectedCode:       yerr.CodeTimeout,
		expectedDependency: apierr.DependencyDokploy,
		call: func(ctx context.Context, c *dokploy.Client) error {
			_, err := c.EnsureOrganization(ctx, dokploy.EnsureOrganizationInput{Name: "chaos-acme"})
			return err
		},
	},
	{
		name:               "DELETE service under sustained timeout retries within bound",
		method:             http.MethodDelete,
		expectedAttempts:   1 + chaosTimeoutMaxRetries,
		expectedCode:       yerr.CodeTimeout,
		expectedDependency: apierr.DependencyDokploy,
		call: func(ctx context.Context, c *dokploy.Client) error {
			return c.RemoveService(ctx, dokploy.RemoveServiceInput{ServiceID: "svc_chaos"})
		},
	},
}

// validChaosMethods is the closed set of HTTP methods the typed
// Dokploy client uses. The closed-set member rejects a scenario whose
// method is not in this set so a typo (e.g. `Method: "Get"`) trips
// before the runtime member runs.
var validChaosMethods = map[string]struct{}{
	http.MethodGet:    {},
	http.MethodPost:   {},
	http.MethodDelete: {},
}

// idempotentChaosMethods is the closed set of HTTP methods the typed
// client retries. POST is intentionally absent: a retry on POST would
// duplicate a provisioning side effect, so the chaos contract requires
// expectedAttempts == 1 for POST and expectedAttempts == 1 +
// MaxRetries for every method in this set.
var idempotentChaosMethods = map[string]struct{}{
	http.MethodGet:    {},
	http.MethodDelete: {},
}

// TestChaosDokployTimeoutsCoversCallSites pins the closed-set
// chaos-scenario coverage invariant for the chaos-timeout gate. The
// scenario table the burst harness iterates MUST stay non-empty, free
// of duplicate scenario names, scoped to the typed Dokploy client
// surface (GET, POST, DELETE), and every entry MUST carry a valid HTTP
// method, an attempt count consistent with the idempotency rule, a
// closed-set expected error code (yerr.CodeTimeout), and a closed-set
// expected dependency (apierr.DependencyDokploy). Runs without any
// infrastructure dependency so the gate trips on every developer
// machine.
func TestChaosDokployTimeoutsCoversCallSites(t *testing.T) {
	t.Parallel()

	if len(chaosTimeoutScenarios) == 0 {
		t.Fatal("chaosTimeoutScenarios is empty; the burst harness MUST exercise at least one Dokploy chaos scenario or the chaos-timeout gate is a no-op")
	}

	seen := map[string]struct{}{}
	methodsSeen := map[string]struct{}{}
	for _, sc := range chaosTimeoutScenarios {
		if strings.TrimSpace(sc.name) == "" {
			t.Errorf("chaosTimeoutScenarios: a scenario carries an empty name; the runtime member surfaces the scenario name in every diagnostic and an empty name silently de-correlates failures")
			continue
		}
		if _, dup := seen[sc.name]; dup {
			t.Errorf("chaosTimeoutScenarios: duplicate scenario name %q; the runtime member MUST be able to map a failure back to exactly one row",
				sc.name)
		}
		seen[sc.name] = struct{}{}

		if _, ok := validChaosMethods[sc.method]; !ok {
			t.Errorf("chaosTimeoutScenarios[%q]: method %q is not a recognised typed Dokploy client method; the closed-set member MUST trip on a typo before the runtime member runs",
				sc.name, sc.method)
		}
		methodsSeen[sc.method] = struct{}{}

		if sc.call == nil {
			t.Errorf("chaosTimeoutScenarios[%q]: call closure is nil; the runtime member cannot exercise a scenario without an invocable closure",
				sc.name)
		}

		if sc.expectedCode != yerr.CodeTimeout {
			t.Errorf("chaosTimeoutScenarios[%q]: expectedCode = %q, want %q; chaos-timeout failures MUST always map to yerr.CodeTimeout — a regression that surfaces E_INTERNAL, E_UNAVAILABLE, or E_DOKPLOY_UNAVAILABLE on the timeout path would mis-classify the failure and defeat the dependency-aware retry surface upstream",
				sc.name, sc.expectedCode, yerr.CodeTimeout)
		}

		if sc.expectedDependency != apierr.DependencyDokploy {
			t.Errorf("chaosTimeoutScenarios[%q]: expectedDependency = %q, want %q; every chaos-timeout failure MUST attribute to the Dokploy dependency so an operator reading the failure knows which upstream is in trouble without grepping the log path",
				sc.name, sc.expectedDependency, apierr.DependencyDokploy)
		}

		if _, retryable := idempotentChaosMethods[sc.method]; retryable {
			want := 1 + chaosTimeoutMaxRetries
			if sc.expectedAttempts != want {
				t.Errorf("chaosTimeoutScenarios[%q]: method %s is idempotent but expectedAttempts = %d, want %d (1 initial + %d retries); the chaos contract MUST mirror the typed client's bounded retry budget on idempotent failures",
					sc.name, sc.method, sc.expectedAttempts, want, chaosTimeoutMaxRetries)
			}
		} else {
			if sc.expectedAttempts != 1 {
				t.Errorf("chaosTimeoutScenarios[%q]: method %s is non-idempotent but expectedAttempts = %d, want 1; a regression that retried POST under chaos timeouts would duplicate a provisioning side effect — the closed-set member MUST trip before the duplication ships",
					sc.name, sc.method, sc.expectedAttempts)
			}
		}
	}

	for _, want := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if _, ok := methodsSeen[want]; !ok {
			t.Errorf("chaosTimeoutScenarios: no scenario covers HTTP method %s; the runtime member MUST exercise every typed-client method shape (retried idempotent GET, retried idempotent DELETE, never-retried POST) so an idempotency-rule regression cannot slip through one untested method",
				want)
		}
	}

	if len(chaosTimeoutSecretMarkers) == 0 {
		t.Fatal("chaosTimeoutSecretMarkers is empty; the runtime member would have no redaction contract to assert against and a leaked bearer token in the error chain would silently slip through")
	}
	for _, marker := range chaosTimeoutSecretMarkers {
		if strings.TrimSpace(marker) == "" {
			t.Errorf("chaosTimeoutSecretMarkers contains an empty entry; an empty substring would match every error and silently de-gate the redaction contract")
		}
	}

	if chaosTimeoutPerAttemptTimeout >= chaosTimeoutFaultDelay {
		t.Errorf("chaosTimeoutPerAttemptTimeout (%s) MUST be strictly less than chaosTimeoutFaultDelay (%s); if the fault delay completes before the per-attempt timeout the fake returns 504 instead of letting the deadline fire and the runtime member would assert against StatusFault classification, not Timeout classification",
			chaosTimeoutPerAttemptTimeout, chaosTimeoutFaultDelay)
	}
}

// chaosObservation is one runtime data point captured by the burst
// harness. Pushing observations onto a buffered channel and aggregating
// in the main goroutine keeps the test assertion surface free of
// goroutine-unsafe testing.T calls (race-detector hostile and
// stdlib-discouraged) and lets the diagnostic carry the offending
// scenario name AND the observed request_id so an operator can
// correlate.
type chaosObservation struct {
	scenario  string
	requestID string
	err       error
	attemptN  int
	idLeak    string // non-empty when a recorded request lost the request_id propagation
	tokenLeak string // non-empty when a recorded Authorization header was not redacted
	chainLeak string // non-empty when a secret marker appears anywhere in the error chain
}

// TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope pins the runtime
// chaos invariant. Each worker spins its own fake-Dokploy server up,
// queues `scenario.expectedAttempts` TimeoutFaults whose delay outlasts
// the client's per-attempt timeout, fires the scenario's typed-client
// call under a context carrying a SafeID request_id, and asserts the
// returned error is a typed *yerr.Error with Code=yerr.CodeTimeout
// attributed to apierr.DependencyDokploy, with the bearer token
// redacted from every level of the wrapped cause chain, with every
// recorded request carrying the caller's request_id, and with every
// recorded Authorization header redacted to output.Sentinel.
//
// Failures surface with the offending scenario name AND the observed
// request_id so an operator can correlate the gate failure with a
// specific in-flight chaos run without re-running the suite locally.
func TestChaosDokployTimeoutsMapsToTypedTimeoutEnvelope(t *testing.T) {
	t.Parallel()

	totalPerScenario := chaosWorkers * chaosIterationsPerWorker
	results := make(chan chaosObservation, len(chaosTimeoutScenarios)*totalPerScenario)

	var wg sync.WaitGroup
	for _, sc := range chaosTimeoutScenarios {
		sc := sc
		for w := 0; w < chaosWorkers; w++ {
			w := w
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < chaosIterationsPerWorker; i++ {
					obs := runChaosIteration(sc, w, i)
					results <- obs
				}
			}()
		}
	}
	wg.Wait()
	close(results)

	// Aggregate.
	perScenarioCount := map[string]int{}
	requestIDs := map[string]int{}
	var observations []chaosObservation
	for obs := range results {
		observations = append(observations, obs)
		perScenarioCount[obs.scenario]++
		if obs.requestID != "" {
			requestIDs[obs.requestID]++
		}
	}

	for _, sc := range chaosTimeoutScenarios {
		if got, want := perScenarioCount[sc.name], totalPerScenario; got != want {
			t.Errorf("chaos burst fired %d iterations against scenario %q, want %d; a missing observation hides a panic or a silently dropped iteration",
				got, sc.name, want)
		}
	}

	for _, obs := range observations {
		if obs.err == nil {
			t.Errorf("scenario %q (request_id=%q) returned nil error under sustained chaos timeouts; the typed client MUST surface yerr.CodeTimeout instead of swallowing the failure",
				obs.scenario, obs.requestID)
			continue
		}

		var ye *yerr.Error
		if !stderrors.As(obs.err, &ye) {
			t.Errorf("scenario %q (request_id=%q) returned untyped error %v; every Dokploy chaos failure MUST be a *yerr.Error so the dependency-aware retry surface upstream can classify it",
				obs.scenario, obs.requestID, obs.err)
			continue
		}

		// Find the matching scenario fixture for the expected fields.
		var sc chaosTimeoutScenario
		for _, candidate := range chaosTimeoutScenarios {
			if candidate.name == obs.scenario {
				sc = candidate
				break
			}
		}

		if ye.Code != sc.expectedCode {
			t.Errorf("scenario %q (request_id=%q) returned code=%q, want %q; chaos-timeout failures MUST map to yerr.CodeTimeout",
				obs.scenario, obs.requestID, ye.Code, sc.expectedCode)
		}

		dep, ok := apierr.DependencyOf(obs.err)
		if !ok {
			t.Errorf("scenario %q (request_id=%q) carried no dependency tag; apierr.DependencyOf MUST surface apierr.DependencyDokploy so an operator knows which upstream is in trouble",
				obs.scenario, obs.requestID)
		} else if dep != sc.expectedDependency {
			t.Errorf("scenario %q (request_id=%q) carried dependency=%q, want %q",
				obs.scenario, obs.requestID, dep, sc.expectedDependency)
		}

		if obs.attemptN != sc.expectedAttempts {
			t.Errorf("scenario %q (request_id=%q) recorded %d attempts against the fake, want %d; idempotency rule mismatch — POST MUST attempt exactly once, GET and DELETE MUST attempt 1 + MaxRetries",
				obs.scenario, obs.requestID, obs.attemptN, sc.expectedAttempts)
		}

		if obs.idLeak != "" {
			t.Errorf("scenario %q (request_id=%q) failed request_id propagation: %s; every Dokploy attempt MUST carry telemetry.HeaderRequestID so an operator can correlate the chaos failure with the caller's request",
				obs.scenario, obs.requestID, obs.idLeak)
		}

		if obs.tokenLeak != "" {
			t.Errorf("scenario %q (request_id=%q) leaked Authorization header to the recorded request: %s; the fake's record() MUST stamp output.Sentinel on every Authorization-carrying request",
				obs.scenario, obs.requestID, obs.tokenLeak)
		}

		if obs.chainLeak != "" {
			t.Errorf("scenario %q (request_id=%q) leaked a secret marker in the error chain: %s; the client's redact() chokepoint MUST scrub every level of the wrapped cause",
				obs.scenario, obs.requestID, obs.chainLeak)
		}
	}

	// Burst-level uniqueness sanity: every iteration used its own
	// fresh request_id seed, so every request_id should appear in
	// exactly one observation. A duplicate is either a SafeID
	// collision or a request_id propagation regression that fanned a
	// single id across iterations.
	for id, n := range requestIDs {
		if n != 1 {
			t.Errorf("request_id %q surfaced in %d observations; SafeID collision or context-propagation regression",
				id, n)
		}
	}
}

// runChaosIteration runs one chaos-timeout iteration in isolation. It
// constructs a fresh fake-Dokploy server (so the FIFO fault queue
// stays per-iteration), constructs a fresh client wired to that fake
// with deterministic short timings, queues expectedAttempts
// TimeoutFaults, fires the scenario's call under a context carrying a
// SafeID request_id, and packages the outcome as a chaosObservation.
// All testing.T-free so it can be invoked from worker goroutines
// without race-hostile assertions.
func runChaosIteration(sc chaosTimeoutScenario, worker, iter int) chaosObservation {
	obs := chaosObservation{scenario: sc.name}

	fake := dokployfake.New()
	defer fake.Close()

	cfg := dokploy.Config{
		BaseURL:        fake.URL(),
		Token:          fake.Token(),
		MaxRetries:     chaosTimeoutMaxRetries,
		Timeout:        chaosTimeoutPerAttemptTimeout,
		RetryBaseDelay: chaosTimeoutRetryBaseDelay,
		RetryMaxDelay:  chaosTimeoutRetryMaxDelay,
	}
	c, err := dokploy.New(cfg)
	if err != nil {
		obs.err = err
		obs.requestID = "<dokploy-new-failed>"
		return obs
	}

	for i := 0; i < sc.expectedAttempts; i++ {
		fake.QueueFault(dokployfake.TimeoutFault(chaosTimeoutFaultDelay))
	}

	requestID := telemetry.NewRequestID()
	if !telemetry.SafeID(requestID) {
		obs.requestID = "<unsafe-id:" + requestID + ">"
		return obs
	}
	obs.requestID = requestID

	ctx := telemetry.WithCorrelation(context.Background(), telemetry.Correlation{
		RequestID:     requestID,
		CorrelationID: requestID,
	})

	obs.err = sc.call(ctx, c)

	// Capture the per-fake attempt count for assertion.
	obs.attemptN = fake.RequestCount()

	// Inspect every recorded request for the propagation invariants.
	for _, rec := range fake.Requests() {
		if got := rec.Headers.Get(telemetry.HeaderRequestID); got != requestID {
			obs.idLeak = "recorded request " + rec.Method + " " + rec.Path +
				" carried request_id=" + quote(got) + ", want " + quote(requestID)
			break
		}
		if rec.AuthHeader != output.Sentinel {
			obs.tokenLeak = "recorded request " + rec.Method + " " + rec.Path +
				" Authorization header was not redacted; got " + quote(rec.AuthHeader)
			break
		}
	}

	// Walk the whole error chain for secret-marker leaks.
	if obs.err != nil {
		for e := obs.err; e != nil; e = stderrors.Unwrap(e) {
			msg := e.Error()
			for _, marker := range chaosTimeoutSecretMarkers {
				if strings.Contains(msg, marker) {
					obs.chainLeak = "marker " + quote(marker) + " surfaced in error chain at level " + quote(msg)
					break
				}
			}
			if obs.chainLeak != "" {
				break
			}
		}
	}

	_ = worker
	_ = iter
	return obs
}

// quote is a thin wrapper around strconv-style %q formatting that
// keeps the chaos diagnostics readable without pulling fmt into the
// worker hot loop. It also keeps the diagnostic free of any embedded
// double-quote that might otherwise terminate a string literal in the
// failure output.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
