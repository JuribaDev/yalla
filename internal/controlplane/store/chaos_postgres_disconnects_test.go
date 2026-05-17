package store_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store/fakepg"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Verification suite — chaos tests for Postgres disconnects (BE-0394).
//
// The canonical pair below is the load-bearing test pair that the PRD's
// `go test -run TestChaosPostgresDisconnects ./...` filter binds to. Together
// they pin two complementary chaos-disconnect invariants:
//
//   - TestChaosPostgresDisconnectsCoversCallSites pins the closed-set
//     chaos-scenario coverage invariant. The scenario table the burst
//     harness iterates MUST stay non-empty, free of duplicates, scoped to
//     the pgxpool surface every store method exercises (Ping, Acquire,
//     Begin, Exec, Query), and every scenario MUST declare an invocable
//     pool closure, a closed-set expected error code
//     (yerr.CodeUnavailable), and a closed-set expected dependency
//     (apierr.DependencyStore). This member is deterministic — it walks
//     an in-memory fixture table and trips on every developer machine
//     without spinning up the fake server.
//
//   - TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope pins the
//     runtime chaos invariant. Spinning a per-iteration fakepg.Server up
//     in-process (so the FIFO fault queue stays isolated under concurrent
//     goroutines), wiring a fresh pgxpool against it via a DSN whose
//     password is a sentinel literal, queuing one DisconnectFault per
//     pool op, and firing chaosWorkers * chaosIterationsPerWorker
//     concurrent scenario invocations MUST yield only failures that
//     (a) are non-nil errors from the pgxpool op, (b) wrap into typed
//     *yerr.Error values with Code=yerr.CodeUnavailable via
//     apierr.StoreUnavailable, (c) report apierr.DependencyStore via
//     apierr.DependencyOf, (d) carry no DSN password literal at any level
//     of the wrapped cause chain (the redaction contract every secret
//     marker in chaosPostgresSecretMarkers pins), and (e) the fake records
//     at least one accepted TCP connection per attempt so a regression
//     that short-circuited pgx without ever attempting a network connect
//     trips here. Failures surface with the offending scenario name AND
//     the observed request_id from telemetry.NewRequestID so an operator
//     can correlate.
//
// Both members are deterministic by design: the fakepg.Server is the one
// dependency the chaos harness needs, and it is constructed in-process per
// iteration so no live Postgres and no live Dokploy server are required.
// The fake closes accepted connections gracefully (FIN, not RST) so pgx's
// dial completes and the chaos error surfaces on the startup-handshake
// read, which is the production failure mode an actual Postgres restart
// or network partition produces. The static verification suite under
// `internal/release/verification_suite_chaos_postgres_disconnects_static_test.go`
// pins every collateral surface (CI step, verify.sh entry, CONTRIBUTING
// entry, SECURITY row+section, PRD command, and this canonical pair's
// existence) so that a rename or deletion trips ONE test, not six.

// chaosPostgresScenario describes one entry in the closed-set chaos
// fixture table. Adding a scenario means adding a new row whose call
// closure invokes the pgxpool op under test; the closure MUST return
// the error directly (without any nil-shadowing) so the runtime member
// can assert against the catalogued typed error.
type chaosPostgresScenario struct {
	// name is the human-readable scenario label that surfaces in every
	// diagnostic; it MUST be unique across the table so an operator
	// reading a failure can map back to exactly one row.
	name string
	// op is the pgxpool surface the scenario exercises. The closed-set
	// member validates it against the recognised-surface set so a typo
	// trips before the runtime member runs.
	op string
	// expectedCode is the yerr.Code the wrapped *yerr.Error MUST surface
	// to the caller. Chaos disconnects MUST always map to
	// yerr.CodeUnavailable — a regression that surfaces E_INTERNAL,
	// E_TIMEOUT, or any other code on the disconnect path would
	// mis-classify the failure and defeat the dependency-aware retry
	// surface upstream.
	expectedCode yerr.Code
	// expectedDependency is the apierr.Dependency the typed error MUST
	// carry. Every chaos-disconnect failure MUST attribute to
	// DependencyStore so an operator reading the failure knows the
	// Postgres datastore is the upstream in trouble without grepping
	// the log path.
	expectedDependency apierr.Dependency
	// call invokes the scenario's pgxpool op against pool. The callback
	// MUST return the error directly so the runtime member can wrap it
	// via apierr.StoreUnavailable and assert against the classification
	// contract.
	call func(ctx context.Context, pool *pgxpool.Pool) error
}

// chaosPostgresConnectTimeout bounds the ConnectTimeout the chaos pool
// uses per attempt. It MUST be small enough that 1 attempt completes
// well under one second per goroutine, and large enough that the
// fake's FIN-close reliably surfaces as a typed transport error on
// every developer machine.
const chaosPostgresConnectTimeout = 750 * time.Millisecond

// chaosPostgresOpTimeout bounds the per-op deadline. It is the
// dominant cost when pgx attempts a connection — the fake closes
// immediately after accept so the deadline rarely fires; the constant
// is the worst-case wall-clock the runtime member spends per op
// before declaring the iteration stuck.
const chaosPostgresOpTimeout = 2 * time.Second

// chaosPostgresPoolMaxConns pins the pool size. The chaos harness
// creates a fresh pool per iteration so a single MaxConn is plenty
// and a small pool keeps the per-iteration cost predictable.
const chaosPostgresPoolMaxConns = 1

// chaosPostgresWorkers and chaosPostgresIterationsPerWorker bound the
// per-scenario concurrent burst. The product (12 iterations per
// scenario × len(scenarios) = 60) is small enough to finish well
// under one second per scenario while still producing repeatable
// concurrent pressure on the fake.
const (
	chaosPostgresWorkers             = 4
	chaosPostgresIterationsPerWorker = 3
)

// chaosPostgresSentinelPassword is the literal password embedded in
// every chaos DSN. It is deliberately distinct from any real
// credential the codebase ships so the runtime member can assert it
// never leaks into the wrapped error chain. Asserting on this sentinel
// rather than the empty string makes the redaction contract loud: if
// pgx (or any wrapper) ever started embedding the DSN in error
// messages, the sentinel would surface and the gate would trip.
const chaosPostgresSentinelPassword = "yallachaossecret_DO_NOT_LEAK_42"

// chaosPostgresSentinelUser is the literal username embedded in every
// chaos DSN. The chaos test does NOT assert the username never leaks
// into the cause chain: pgx's connect error formatter intentionally
// includes the username for operator debuggability, and that
// debuggability is a deliberate trade-off the upstream driver owns.
// The username sentinel exists so the top-level envelope assertion
// can prove apierr.StoreUnavailable's rendered message never echoes
// DSN fields — that is the wrapper's contract, not pgx's.
const chaosPostgresSentinelUser = "yallachaosuser_DO_NOT_LEAK_42"

// chaosPostgresSecretMarkers is the closed set of substrings the
// runtime member walks the error chain looking for. The password is
// the sole DSN field that MUST NEVER appear at any level of the
// wrapped cause chain — pgx redacts it by design, and a regression
// that surfaced the password would defeat the secret-redaction
// contract every operator and audit reviewer relies on. The
// top-level wrapper envelope additionally asserts neither the
// password nor the username leaks (the wrapper's Error() message is
// static and MUST NOT echo any cause-chain content); see
// chaosPostgresEnvelopeMarkers.
var chaosPostgresSecretMarkers = []string{
	chaosPostgresSentinelPassword,
}

// chaosPostgresEnvelopeMarkers is the closed set of substrings the
// runtime member asserts NEVER appear in apierr.StoreUnavailable's
// rendered Error() string. The wrapper's message is static ("the
// Yalla datastore is temporarily unavailable") and MUST NOT echo any
// pgx cause-chain content; both the password and the username sentinel
// are tracked so a regression that started embedding the cause's
// message in the envelope would trip on the first observation.
var chaosPostgresEnvelopeMarkers = []string{
	chaosPostgresSentinelPassword,
	chaosPostgresSentinelUser,
}

// chaosPostgresScenarios is the closed-set chaos fixture table. Each
// row exercises one pgxpool surface; together they cover the four
// production pools' public ops (Ping for health checks, Acquire for
// per-request connection use, Begin for transactional writes, Exec
// for one-shot mutating statements, Query for one-shot reads).
var chaosPostgresScenarios = []chaosPostgresScenario{
	{
		name:               "Pool.Ping under disconnect chaos surfaces typed unavailable",
		op:                 "Ping",
		expectedCode:       yerr.CodeUnavailable,
		expectedDependency: apierr.DependencyStore,
		call: func(ctx context.Context, pool *pgxpool.Pool) error {
			return pool.Ping(ctx)
		},
	},
	{
		name:               "Pool.Acquire under disconnect chaos surfaces typed unavailable",
		op:                 "Acquire",
		expectedCode:       yerr.CodeUnavailable,
		expectedDependency: apierr.DependencyStore,
		call: func(ctx context.Context, pool *pgxpool.Pool) error {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			conn.Release()
			return nil
		},
	},
	{
		name:               "Pool.Begin under disconnect chaos surfaces typed unavailable",
		op:                 "Begin",
		expectedCode:       yerr.CodeUnavailable,
		expectedDependency: apierr.DependencyStore,
		call: func(ctx context.Context, pool *pgxpool.Pool) error {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			_ = tx.Rollback(ctx)
			return nil
		},
	},
	{
		name:               "Pool.Exec under disconnect chaos surfaces typed unavailable",
		op:                 "Exec",
		expectedCode:       yerr.CodeUnavailable,
		expectedDependency: apierr.DependencyStore,
		call: func(ctx context.Context, pool *pgxpool.Pool) error {
			_, err := pool.Exec(ctx, "SELECT 1")
			return err
		},
	},
	{
		name:               "Pool.Query under disconnect chaos surfaces typed unavailable",
		op:                 "Query",
		expectedCode:       yerr.CodeUnavailable,
		expectedDependency: apierr.DependencyStore,
		call: func(ctx context.Context, pool *pgxpool.Pool) error {
			rows, err := pool.Query(ctx, "SELECT 1")
			if err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		},
	},
}

// validChaosPostgresOps is the closed set of recognised pgxpool surface
// names a scenario may exercise. The closed-set member validates each
// scenario's op against this set so a typo (e.g. a missing letter in
// "Acquire" or "Begin") trips before the runtime member runs.
var validChaosPostgresOps = map[string]struct{}{
	"Ping":    {},
	"Acquire": {},
	"Begin":   {},
	"Exec":    {},
	"Query":   {},
}

// TestChaosPostgresDisconnectsCoversCallSites pins the closed-set
// chaos-scenario coverage invariant. The scenario table MUST stay
// non-empty, free of duplicates, scoped to the recognised pgxpool
// surface set, and every entry MUST carry a recognised op, a non-nil
// call closure, the canonical expected error code
// (yerr.CodeUnavailable), and the canonical expected dependency
// (apierr.DependencyStore). The harness also asserts that every
// recognised pgxpool surface (Ping, Acquire, Begin, Exec, Query) is
// covered by at least one scenario, that the secret-marker set is
// non-empty (so the redaction contract has something to assert
// against), and that chaosPostgresConnectTimeout is strictly less than
// chaosPostgresOpTimeout so the per-attempt deadline fires inside the
// per-op deadline budget.
func TestChaosPostgresDisconnectsCoversCallSites(t *testing.T) {
	t.Parallel()

	if len(chaosPostgresScenarios) == 0 {
		t.Fatal("chaosPostgresScenarios is empty; the burst harness MUST exercise at least one Postgres chaos scenario or the chaos-disconnect gate is a no-op")
	}

	seen := map[string]struct{}{}
	opsSeen := map[string]struct{}{}
	for _, sc := range chaosPostgresScenarios {
		if strings.TrimSpace(sc.name) == "" {
			t.Errorf("chaosPostgresScenarios: a scenario carries an empty name; the runtime member surfaces the scenario name in every diagnostic and an empty name silently de-correlates failures")
			continue
		}
		if _, dup := seen[sc.name]; dup {
			t.Errorf("chaosPostgresScenarios: duplicate scenario name %q; the runtime member MUST be able to map a failure back to exactly one row",
				sc.name)
		}
		seen[sc.name] = struct{}{}

		if _, ok := validChaosPostgresOps[sc.op]; !ok {
			t.Errorf("chaosPostgresScenarios[%q]: op %q is not a recognised pgxpool surface; the closed-set member MUST trip on a typo before the runtime member runs",
				sc.name, sc.op)
		}
		opsSeen[sc.op] = struct{}{}

		if sc.call == nil {
			t.Errorf("chaosPostgresScenarios[%q]: call closure is nil; the runtime member cannot exercise a scenario without an invocable closure",
				sc.name)
		}

		if sc.expectedCode != yerr.CodeUnavailable {
			t.Errorf("chaosPostgresScenarios[%q]: expectedCode = %q, want %q; chaos-disconnect failures MUST always map to yerr.CodeUnavailable — a regression that surfaces E_INTERNAL, E_TIMEOUT, or any other code on the disconnect path would mis-classify the failure and defeat the dependency-aware retry surface upstream",
				sc.name, sc.expectedCode, yerr.CodeUnavailable)
		}

		if sc.expectedDependency != apierr.DependencyStore {
			t.Errorf("chaosPostgresScenarios[%q]: expectedDependency = %q, want %q; every chaos-disconnect failure MUST attribute to the Postgres dependency so an operator reading the failure knows which upstream is in trouble without grepping the log path",
				sc.name, sc.expectedDependency, apierr.DependencyStore)
		}
	}

	for _, want := range []string{"Ping", "Acquire", "Begin", "Exec", "Query"} {
		if _, ok := opsSeen[want]; !ok {
			t.Errorf("chaosPostgresScenarios: no scenario covers pgxpool surface %s; the runtime member MUST exercise every public pgxpool op shape so a classification regression cannot slip through one untested method",
				want)
		}
	}

	if len(chaosPostgresSecretMarkers) == 0 {
		t.Fatal("chaosPostgresSecretMarkers is empty; the runtime member would have no redaction contract to assert against and a leaked DSN field in the error chain would silently slip through")
	}
	for _, marker := range chaosPostgresSecretMarkers {
		if strings.TrimSpace(marker) == "" {
			t.Errorf("chaosPostgresSecretMarkers contains an empty entry; an empty substring would match every error and silently de-gate the redaction contract")
		}
	}

	if chaosPostgresConnectTimeout >= chaosPostgresOpTimeout {
		t.Errorf("chaosPostgresConnectTimeout (%s) MUST be strictly less than chaosPostgresOpTimeout (%s); if the per-attempt deadline cannot fire inside the per-op deadline the runtime member would surface deadline-exceeded as a context error instead of letting pgx classify the transport failure",
			chaosPostgresConnectTimeout, chaosPostgresOpTimeout)
	}

	if chaosPostgresWorkers <= 0 || chaosPostgresIterationsPerWorker <= 0 {
		t.Errorf("chaosPostgresWorkers (%d) and chaosPostgresIterationsPerWorker (%d) MUST both be positive; a zero on either side silently makes the runtime burst a no-op",
			chaosPostgresWorkers, chaosPostgresIterationsPerWorker)
	}
}

// chaosPostgresObservation is one runtime data point captured by the
// burst harness. Pushing observations onto a buffered channel and
// aggregating in the main goroutine keeps the test assertion surface
// free of goroutine-unsafe testing.T calls (race-detector hostile and
// stdlib-discouraged) and lets the diagnostic carry the offending
// scenario name AND the observed request_id so an operator can
// correlate.
type chaosPostgresObservation struct {
	scenario  string
	requestID string
	err       error
	accepted  int
	chainLeak string // non-empty when a secret marker appears anywhere in the error chain
}

// TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope pins the
// runtime chaos invariant. Each worker spins its own fakepg.Server up,
// queues one DisconnectFault per pool op, fires the scenario's
// pgxpool call under a per-op context carrying a SafeID request_id,
// wraps the returned error via apierr.StoreUnavailable, and asserts
// the wrapped error is a typed *yerr.Error with Code=yerr.CodeUnavailable
// attributed to apierr.DependencyStore, with no DSN password literal
// in the wrapped cause chain, and with the fake recording at least
// one accepted TCP connection so a regression that short-circuited
// pgx without ever attempting a network connect trips here.
//
// Failures surface with the offending scenario name AND the observed
// request_id so an operator can correlate the gate failure with a
// specific in-flight chaos run without re-running the suite locally.
func TestChaosPostgresDisconnectsMapsToTypedUnavailableEnvelope(t *testing.T) {
	t.Parallel()

	totalPerScenario := chaosPostgresWorkers * chaosPostgresIterationsPerWorker
	results := make(chan chaosPostgresObservation, len(chaosPostgresScenarios)*totalPerScenario)

	var wg sync.WaitGroup
	for _, sc := range chaosPostgresScenarios {
		sc := sc
		for w := 0; w < chaosPostgresWorkers; w++ {
			w := w
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < chaosPostgresIterationsPerWorker; i++ {
					results <- runChaosPostgresIteration(sc, w, i)
				}
			}()
		}
	}
	wg.Wait()
	close(results)

	// Aggregate.
	perScenarioCount := map[string]int{}
	requestIDs := map[string]int{}
	var observations []chaosPostgresObservation
	for obs := range results {
		observations = append(observations, obs)
		perScenarioCount[obs.scenario]++
		if obs.requestID != "" {
			requestIDs[obs.requestID]++
		}
	}

	for _, sc := range chaosPostgresScenarios {
		if got, want := perScenarioCount[sc.name], totalPerScenario; got != want {
			t.Errorf("chaos burst fired %d iterations against scenario %q, want %d; a missing observation hides a panic or a silently dropped iteration",
				got, sc.name, want)
		}
	}

	for _, obs := range observations {
		if obs.err == nil {
			t.Errorf("scenario %q (request_id=%q) returned nil error under sustained chaos disconnects; the pgxpool op MUST surface a transport error so the store-layer classifier can map it to yerr.CodeUnavailable",
				obs.scenario, obs.requestID)
			continue
		}

		// Wrap the raw pgx error through the production classifier
		// chokepoint. apierr.StoreUnavailable is the single public
		// API every store call site uses to surface a transient
		// datastore failure; the chaos contract pins its post-wrap
		// classification under sustained disconnect chaos.
		wrapped := apierr.StoreUnavailable(obs.err)

		var ye *yerr.Error
		if !stderrors.As(error(wrapped), &ye) {
			t.Errorf("scenario %q (request_id=%q) wrapped error %v is not a *yerr.Error; every Postgres chaos failure MUST be a typed envelope so the dependency-aware retry surface upstream can classify it",
				obs.scenario, obs.requestID, wrapped)
			continue
		}

		// Find the matching scenario fixture for the expected fields.
		var sc chaosPostgresScenario
		for _, candidate := range chaosPostgresScenarios {
			if candidate.name == obs.scenario {
				sc = candidate
				break
			}
		}

		if ye.Code != sc.expectedCode {
			t.Errorf("scenario %q (request_id=%q) wrapped code=%q, want %q; chaos-disconnect failures MUST map to yerr.CodeUnavailable",
				obs.scenario, obs.requestID, ye.Code, sc.expectedCode)
		}

		dep, ok := apierr.DependencyOf(wrapped)
		if !ok {
			t.Errorf("scenario %q (request_id=%q) carried no dependency tag; apierr.DependencyOf MUST surface apierr.DependencyStore so an operator knows which upstream is in trouble",
				obs.scenario, obs.requestID)
		} else if dep != sc.expectedDependency {
			t.Errorf("scenario %q (request_id=%q) carried dependency=%q, want %q",
				obs.scenario, obs.requestID, dep, sc.expectedDependency)
		}

		if obs.accepted < 1 {
			t.Errorf("scenario %q (request_id=%q) recorded %d accepted TCP connections, want >= 1; pgxpool MUST attempt at least one network connect per op or the chaos harness is asserting against a path that bypassed the production transport",
				obs.scenario, obs.requestID, obs.accepted)
		}

		if obs.chainLeak != "" {
			t.Errorf("scenario %q (request_id=%q) leaked a secret marker in the error chain: %s; the redaction contract MUST scrub every level of the wrapped cause so DSN credentials never reach a test log or an audit blob",
				obs.scenario, obs.requestID, obs.chainLeak)
		}

		// Re-assert on the wrapped envelope to catch a regression that
		// would let the wrapper itself embed the cause's message.
		// The envelope marker set is wider than the cause-chain set
		// (the wrapper's message is static and MUST NOT echo ANY
		// DSN field — pgx's choice to leak the username in its own
		// connect error is upstream's; the wrapper has no such excuse).
		envelopeRendered := wrapped.Error()
		for _, marker := range chaosPostgresEnvelopeMarkers {
			if strings.Contains(envelopeRendered, marker) {
				t.Errorf("scenario %q (request_id=%q) wrapped envelope Error() leaked %q; apierr.StoreUnavailable's rendered message MUST be static and MUST NOT echo any pgx cause-chain field",
					obs.scenario, obs.requestID, marker)
			}
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

// runChaosPostgresIteration runs one chaos-disconnect iteration in
// isolation. It constructs a fresh fakepg.Server (so the FIFO fault
// queue stays per-iteration), wires a fresh pgxpool with a sentinel
// DSN, queues one DisconnectFault, fires the scenario's call under a
// context carrying a SafeID request_id, walks the resulting error
// chain for secret markers, and packages the outcome as a
// chaosPostgresObservation. All testing.T-free so it can be invoked
// from worker goroutines without race-hostile assertions.
func runChaosPostgresIteration(sc chaosPostgresScenario, worker, iter int) chaosPostgresObservation {
	requestID := telemetry.NewRequestID()

	srv, err := fakepg.NewServer()
	if err != nil {
		return chaosPostgresObservation{
			scenario:  sc.name,
			requestID: requestID,
			err:       fmt.Errorf("worker=%d iter=%d construct fake: %w", worker, iter, err),
		}
	}
	defer func() { _ = srv.Close() }()

	// Queue one disconnect per pool op. The default behaviour is also
	// a disconnect (see fakepg.Server.handle) so even a queue-arming
	// regression still produces deterministic chaos.
	srv.QueueFault(fakepg.DisconnectFault())

	pool, err := newChaosPostgresPool(srv.Addr())
	if err != nil {
		return chaosPostgresObservation{
			scenario:  sc.name,
			requestID: requestID,
			err:       fmt.Errorf("worker=%d iter=%d construct pool: %w", worker, iter, err),
		}
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(
		telemetry.WithCorrelation(context.Background(), telemetry.Correlation{RequestID: requestID}),
		chaosPostgresOpTimeout,
	)
	defer cancel()

	callErr := sc.call(ctx, pool)

	leak := findSecretMarkerInChain(callErr)
	if callErr == nil {
		// Some platforms accept the connect before the kernel notices
		// the close; pgx may report success or hit a different op
		// boundary. Force a Ping to keep the contract deterministic
		// across kernels — if even the Ping succeeds, the iteration
		// reports nil (the runtime member will flag it as a missing
		// chaos failure).
		callErr = pool.Ping(ctx)
		leak = findSecretMarkerInChain(callErr)
	}

	return chaosPostgresObservation{
		scenario:  sc.name,
		requestID: requestID,
		err:       callErr,
		accepted:  srv.AcceptedConnections(),
		chainLeak: leak,
	}
}

// newChaosPostgresPool builds a pgxpool against the fake's address
// with a sentinel DSN and bounded timing knobs.
func newChaosPostgresPool(addr string) (*pgxpool.Pool, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", addr, err)
	}
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/yallachaosdb?sslmode=disable&connect_timeout=1",
		url.QueryEscape(chaosPostgresSentinelUser),
		url.QueryEscape(chaosPostgresSentinelPassword),
		host,
		port,
	)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.ConnConfig.ConnectTimeout = chaosPostgresConnectTimeout
	cfg.MaxConns = chaosPostgresPoolMaxConns
	cfg.MinConns = 0
	// MaxConnLifetime/IdleTime defaults are fine — the iteration's
	// pool is closed immediately after the scenario call, so the
	// per-iteration cost is bounded by the connect timeout.
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	return pool, nil
}

// splitHostPort is a tiny helper that splits "host:port" while keeping
// the dependency surface free of net dependencies in the call site.
func splitHostPort(addr string) (host, port string, err error) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("address %q missing port", addr)
	}
	return addr[:idx], addr[idx+1:], nil
}

// findSecretMarker scans s for any literal in chaosPostgresSecretMarkers
// and returns the first hit. An empty return means the redaction
// contract held for s.
func findSecretMarker(s string) string {
	for _, marker := range chaosPostgresSecretMarkers {
		if strings.Contains(s, marker) {
			return marker
		}
	}
	return ""
}

// findSecretMarkerInChain walks the errors.Unwrap chain of err and
// returns the first secret marker that appears in any level's
// .Error() string. The redaction contract requires every level of the
// chain to stay clean — a leak at the cause level would surface in a
// reviewer's audit log even if the top-level envelope is redacted.
func findSecretMarkerInChain(err error) string {
	for err != nil {
		if hit := findSecretMarker(err.Error()); hit != "" {
			return hit
		}
		err = stderrors.Unwrap(err)
	}
	return ""
}
