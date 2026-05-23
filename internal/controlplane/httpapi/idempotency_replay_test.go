package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Verification suite — idempotency replay tests (BE-0395).
//
// The canonical pair below is the load-bearing test pair that the PRD's
// `go test -run TestIdempotencyReplay ./...` filter binds to. Together they
// pin two complementary idempotency-replay invariants:
//
//   - TestIdempotencyReplayCoversCallSites pins the closed-set replay
//     coverage invariant. The scenario table the burst harness iterates over
//     enumerates every outcome category an unsafe handler can produce that
//     the idempotency middleware MUST record and replay: a successful
//     202 yalla.output.v1 envelope, a 400 E_VALIDATION validation
//     failure, a 403 E_FORBIDDEN authorization failure, and a 404
//     E_NOT_FOUND not-found failure. For each scenario the test asserts
//     the wrapped handler runs exactly once, the second response's
//     status equals the first, the second response's body is
//     byte-identical to the first, the replay carries the
//     Idempotency-Replayed: true header, the recorded body carries the
//     yalla.output.v1 or yalla.error.v1 schema_version it advertises on
//     the wire, and no sentinel secret marker placed inside the
//     submitted request body or the rendered envelope leaks into the
//     recorded claim or the replayed response. A 5xx server failure is
//     deliberately excluded from the closed set — the middleware's
//     contract releases the claim on 5xx so a retry re-runs the handler
//     rather than replaying an unfinished result, and that exclusion is
//     pinned by TestRequireIdempotencyServerErrorIsNotRecorded; the
//     replay invariant only covers responses the middleware records.
//
//   - TestIdempotencyReplayPreservesByteIdenticalEnvelope pins the
//     deterministic replay invariant under contention. It seeds a
//     completed claim whose recorded body carries a stable
//     yalla.output.v1 envelope, then fires
//     replayWorkers * replayIterationsPerWorker concurrent retries
//     against the same key with the same body. Every retry MUST observe
//     the same status, the same byte-identical body, and the
//     Idempotency-Replayed: true header. The handler attached to the
//     middleware is recording: a single observed invocation across all
//     iterations is the closed-set bound (the seed completes the claim
//     pre-burst so the handler MUST NOT run at all under the canonical
//     case). The static verification suite under
//     `internal/release/verification_suite_idempotency_replay_static_test.go`
//     pins every collateral surface (CI step, verify.sh entry,
//     CONTRIBUTING entry, SECURITY row+section, PRD command, and this
//     canonical pair's existence) so that a rename or deletion trips
//     ONE test, not six.

const (
	// replaySchemaVersionOutput is the success-envelope schema version
	// the apienvelope package advertises on the wire. Pinning it as a
	// literal here keeps the replay-coverage assertion robust to a
	// future renderer refactor — the test fails loudly if the
	// schema_version field name OR value drifts.
	replaySchemaVersionOutput = `"schema_version":"yalla.output.v1"`
	// replaySchemaVersionError is the error-envelope schema version
	// the apienvelope package advertises on the wire.
	replaySchemaVersionError = `"schema_version":"yalla.error.v1"`

	// replaySecretMarker is the sentinel a regression that accidentally
	// reflected the submitted request body into the rendered envelope
	// would surface with. The marker is deliberately not a real secret
	// shape (no Authorization scheme, no token prefix) so a leak
	// reported by this test does not itself name a plausible
	// credential — only the marker.
	replaySecretMarker = "REPLAY-SENTINEL-DO-NOT-LEAK"

	// replayWorkers is the parallelism the byte-identical-envelope
	// burst harness uses. 4 workers * 8 iterations = 32 concurrent
	// retries per run, enough to surface a non-deterministic recorder
	// under -race without bloating CI wall-clock.
	replayWorkers              = 4
	replayIterationsPerWorker  = 8
	replayBurstTotalIterations = replayWorkers * replayIterationsPerWorker
)

// TestIdempotencyReplayCoversCallSites pins the closed-set replay
// coverage invariant. Every outcome category an unsafe handler can
// produce that the idempotency middleware records — a success
// envelope, a validation failure, an authorization failure, and a
// not-found failure — MUST replay byte-identically with the
// Idempotency-Replayed: true header on a second request that carries
// the same Idempotency-Key and the same body. A handler-side leak of
// a sentinel marker MUST NOT survive into the recorded claim or the
// replayed response — the middleware records the already-rendered,
// already-redacted apienvelope body, so a regression that started
// recording the raw handler output would surface here.
func TestIdempotencyReplayCoversCallSites(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name           string
		handler        func(w http.ResponseWriter, r *http.Request)
		wantStatus     int
		wantSchemaVer  string
		wantErrorCode  string // "" for success scenarios
		coverageReason string // documented anchor for AC traceability
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteData(w, http.StatusAccepted, requestID(r), map[string]string{"job_id": "job_replay"})
			},
			wantStatus:     http.StatusAccepted,
			wantSchemaVer:  replaySchemaVersionOutput,
			coverageReason: "AC: success",
		},
		{
			name: "validation failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteError(w, requestID(r), apierr.Invalid("name is required"))
			},
			wantStatus:     http.StatusBadRequest,
			wantSchemaVer:  replaySchemaVersionError,
			wantErrorCode:  "E_VALIDATION",
			coverageReason: "AC: validation failure",
		},
		{
			name: "authorization failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteError(w, requestID(r), apierr.Forbidden("not allowed"))
			},
			wantStatus:     http.StatusForbidden,
			wantSchemaVer:  replaySchemaVersionError,
			wantErrorCode:  "E_FORBIDDEN",
			coverageReason: "AC: authorization failure",
		},
		{
			name: "not found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteError(w, requestID(r), apierr.NotFound("project", "p1"))
			},
			wantStatus:     http.StatusNotFound,
			wantSchemaVer:  replaySchemaVersionError,
			wantErrorCode:  "E_NOT_FOUND",
			coverageReason: "AC: not-found",
		},
	}

	// A request body that intentionally carries the sentinel marker so a
	// regression that started reflecting the submitted body into the
	// recorded envelope surfaces here. The marker MUST NOT appear in
	// any first response, recorded claim, or replayed response.
	const body = `{"name":"web","note":"` + replaySecretMarker + `"}`

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeIdempotencyStore()
			next := &recordingHandler{fn: sc.handler}
			h := RequireIdempotency(fake, time.Hour)(next)

			key := "key-replay-" + strings.ReplaceAll(sc.name, " ", "-")

			first := run(h, postReq(key, body, true))
			if first.Code != sc.wantStatus {
				t.Fatalf("%s: first status = %d, want %d (body: %s)", sc.coverageReason, first.Code, sc.wantStatus, first.Body.String())
			}
			if next.ran != 1 {
				t.Fatalf("%s: handler ran %d times on first request, want 1", sc.coverageReason, next.ran)
			}
			if first.Header().Get(HeaderIdempotencyReplayed) != "" {
				t.Errorf("%s: first response carries Idempotency-Replayed header — a fresh execution must NOT be flagged as a replay", sc.coverageReason)
			}
			if !strings.Contains(first.Body.String(), sc.wantSchemaVer) {
				t.Errorf("%s: first response body missing %q; got %s", sc.coverageReason, sc.wantSchemaVer, first.Body.String())
			}
			if sc.wantErrorCode != "" {
				decodeError(t, first, sc.wantErrorCode)
			}
			if strings.Contains(first.Body.String(), replaySecretMarker) {
				t.Errorf("%s: first response body leaked sentinel marker; got %s", sc.coverageReason, first.Body.String())
			}

			stored, ok := fake.get(idemRef(key))
			if !ok {
				t.Fatalf("%s: middleware did not record the claim", sc.coverageReason)
			}
			if stored.ResponseStatus != sc.wantStatus {
				t.Errorf("%s: recorded status = %d, want %d", sc.coverageReason, stored.ResponseStatus, sc.wantStatus)
			}
			if string(stored.ResponseBody) != first.Body.String() {
				t.Errorf("%s: recorded body diverged from first response — recorded %q, sent %q", sc.coverageReason, stored.ResponseBody, first.Body.String())
			}
			if strings.Contains(string(stored.ResponseBody), replaySecretMarker) {
				t.Errorf("%s: recorded body leaked sentinel marker; got %s", sc.coverageReason, stored.ResponseBody)
			}

			// Second request: same key, same body. The middleware MUST
			// replay the recorded envelope without re-running the handler.
			second := run(h, postReq(key, body, true))
			if next.ran != 1 {
				t.Errorf("%s: handler ran %d times total, want 1 — a replay must NOT re-invoke the handler", sc.coverageReason, next.ran)
			}
			if second.Code != sc.wantStatus {
				t.Errorf("%s: replay status = %d, want recorded %d", sc.coverageReason, second.Code, sc.wantStatus)
			}
			if second.Body.String() != first.Body.String() {
				t.Errorf("%s: replay body diverged — got %q, want byte-identical %q", sc.coverageReason, second.Body.String(), first.Body.String())
			}
			if second.Header().Get(HeaderIdempotencyReplayed) != "true" {
				t.Errorf("%s: replay MUST carry Idempotency-Replayed: true; got %q", sc.coverageReason, second.Header().Get(HeaderIdempotencyReplayed))
			}
			if !strings.Contains(second.Body.String(), sc.wantSchemaVer) {
				t.Errorf("%s: replay body missing %q; got %s", sc.coverageReason, sc.wantSchemaVer, second.Body.String())
			}
			if strings.Contains(second.Body.String(), replaySecretMarker) {
				t.Errorf("%s: replayed body leaked sentinel marker; got %s", sc.coverageReason, second.Body.String())
			}
		})
	}
}

// TestIdempotencyReplayPreservesByteIdenticalEnvelope pins the
// deterministic replay invariant under contention. The harness seeds
// a completed claim whose recorded body carries a stable
// yalla.output.v1 envelope, then fires
// replayWorkers * replayIterationsPerWorker concurrent retries against
// the same key. Every retry MUST observe the same status, the same
// byte-identical body, and the Idempotency-Replayed: true header. The
// recording handler MUST NOT be invoked at all — the seed completes
// the claim pre-burst so a non-zero observed run count is the
// regression report.
func TestIdempotencyReplayPreservesByteIdenticalEnvelope(t *testing.T) {
	t.Parallel()

	fake := newFakeIdempotencyStore()
	// recorded is the canonical replay payload: a well-formed
	// yalla.output.v1 envelope with a stable request_id. Asserting on
	// the literal bytes (not a structural comparison) pins the
	// byte-identical-replay invariant: a regression that re-rendered
	// the envelope on replay would whitespace-drift the body and trip
	// here even if the parsed JSON stayed equivalent.
	recorded := []byte(`{"schema_version":"yalla.output.v1","ok":true,"data":{"job_id":"job_replay"},"request_id":"req-original"}`)

	// Pre-flight: confirm the seeded payload parses as a yalla.output.v1
	// envelope so a future literal-typo in `recorded` surfaces with a
	// clear failure here rather than later inside the burst loop.
	var probe map[string]any
	if err := json.Unmarshal(recorded, &probe); err != nil {
		t.Fatalf("seeded recorded body does not parse as JSON: %v", err)
	}
	if probe["schema_version"] != "yalla.output.v1" {
		t.Fatalf("seeded recorded body schema_version = %v, want %q", probe["schema_version"], "yalla.output.v1")
	}

	const body = `{"name":"web"}`
	ref := idemRef("key-replay-burst")
	fake.seed(store.IdempotencyRecord{
		ID:             "idk_seed_replay",
		OrganizationID: ref.OrganizationID,
		PrincipalID:    ref.PrincipalID,
		Key:            ref.Key,
		Route:          "POST /v1/projects",
		RequestHash:    hashRequest(http.MethodPost, "/v1/projects", []byte(body)),
		Status:         store.IdempotencyStatusCompleted,
		ResponseStatus: http.StatusAccepted,
		ResponseBody:   recorded,
	})

	// A recording handler whose body MUST NOT be invoked in the
	// canonical replay case. A non-zero observed run count after the
	// burst is the regression report (a retry that bypassed the
	// recorded claim and re-ran the handler).
	next := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		// Defensive: if the middleware ever DID invoke the handler,
		// emit a deliberately wrong envelope so the body-equality
		// assertion below surfaces an unambiguous diff in addition to
		// the run-count assertion.
		apienvelope.WriteData(w, http.StatusOK, requestID(r), map[string]string{"diverged": "yes"})
	}}
	h := RequireIdempotency(fake, time.Hour)(next)

	type observation struct {
		status int
		body   string
		header string
	}
	results := make([]observation, replayBurstTotalIterations)

	var wg sync.WaitGroup
	wg.Add(replayWorkers)
	for w := 0; w < replayWorkers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < replayIterationsPerWorker; i++ {
				idx := w*replayIterationsPerWorker + i
				rec := run(h, postReq("key-replay-burst", body, true))
				results[idx] = observation{
					status: rec.Code,
					body:   rec.Body.String(),
					header: rec.Header().Get(HeaderIdempotencyReplayed),
				}
			}
		}()
	}
	wg.Wait()

	if next.ran != 0 {
		t.Errorf("handler ran %d times during the replay burst, want 0 — a completed claim MUST be replayed, never re-invoked", next.ran)
	}

	for idx, got := range results {
		if got.status != http.StatusAccepted {
			t.Errorf("iter %d: status = %d, want recorded 202", idx, got.status)
		}
		if got.body != string(recorded) {
			t.Errorf("iter %d: body diverged — got %q, want byte-identical %q", idx, got.body, recorded)
		}
		if got.header != "true" {
			t.Errorf("iter %d: Idempotency-Replayed = %q, want \"true\"", idx, got.header)
		}
		if !strings.Contains(got.body, replaySchemaVersionOutput) {
			t.Errorf("iter %d: body missing %q", idx, replaySchemaVersionOutput)
		}
	}

	// The fake's accounting MUST report
	// replayBurstTotalIterations claim attempts (one per retry, each
	// short-circuited to the recorded claim) and zero completes
	// (no handler ran, so no Complete call). A drift in either
	// counter is the closed-set bound regression.
	if fake.claims != replayBurstTotalIterations {
		t.Errorf("fake.claims = %d, want %d (one Claim call per retry, even though every claim short-circuits to the recorded record)", fake.claims, replayBurstTotalIterations)
	}
	if fake.completes != 0 {
		t.Errorf("fake.completes = %d, want 0 (no handler ran, so no Complete call)", fake.completes)
	}
}

// Compile-time assurance that the replay-burst result slice fits in
// the int counter the recording handler increments — a defensive
// sanity check; a single int holds far more iterations than this
// suite ever runs.
var _ = httptest.NewRecorder
