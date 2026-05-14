package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Contract tests for the BE-0026 HTTP idempotency middleware. They cover the
// pass-through cases (safe method, no key), key validation, the missing-
// principal wiring guard, a first request that runs and records, a retry that
// replays a completed response (after job completion), a retry that collides
// with an in-flight request (before job completion), the same-key/different-
// request conflict, server failures that are not recorded, that client-error
// responses (validation, authorization, not found) are recorded and replayed,
// a claim-store dependency failure, and that the request body is preserved for
// the wrapped handler. They use a fake IdempotencyStore; no database required.

// fakeIdempotencyStore is an in-memory IdempotencyStore for middleware tests.
type fakeIdempotencyStore struct {
	mu       sync.Mutex
	records  map[store.IdempotencyKeyRef]store.IdempotencyRecord
	nextID   int
	claimErr error

	claims    int
	completes int
	releases  int
}

func newFakeIdempotencyStore() *fakeIdempotencyStore {
	return &fakeIdempotencyStore{records: map[store.IdempotencyKeyRef]store.IdempotencyRecord{}}
}

// seed installs a pre-existing claim, simulating a request that already ran.
func (f *fakeIdempotencyStore) seed(rec store.IdempotencyRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[rec.Ref()] = rec
}

func (f *fakeIdempotencyStore) get(ref store.IdempotencyKeyRef) (store.IdempotencyRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[ref]
	return rec, ok
}

func (f *fakeIdempotencyStore) Claim(_ context.Context, rec store.IdempotencyRecord) (store.IdempotencyRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims++
	if f.claimErr != nil {
		return store.IdempotencyRecord{}, false, f.claimErr
	}
	ref := rec.Ref()
	if existing, ok := f.records[ref]; ok {
		return existing, false, nil
	}
	f.nextID++
	rec.ID = fmt.Sprintf("idk_fake_%d", f.nextID)
	rec.Status = store.IdempotencyStatusPending
	f.records[ref] = rec
	return rec, true, nil
}

func (f *fakeIdempotencyStore) Complete(_ context.Context, ref store.IdempotencyKeyRef, status int, body []byte) (store.IdempotencyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completes++
	rec, ok := f.records[ref]
	if !ok || rec.Status != store.IdempotencyStatusPending {
		return store.IdempotencyRecord{}, apierr.Conflict("the idempotency key claim is no longer pending")
	}
	rec.Status = store.IdempotencyStatusCompleted
	rec.ResponseStatus = status
	rec.ResponseBody = append([]byte(nil), body...)
	rec.CompletedAt = time.Now()
	f.records[ref] = rec
	return rec, nil
}

func (f *fakeIdempotencyStore) Release(_ context.Context, ref store.IdempotencyKeyRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
	delete(f.records, ref)
	return nil
}

// idemPrincipal is the authenticated principal idempotency tests act as.
func idemPrincipal() policy.Principal {
	return policy.Principal{
		ID:             "usr_idem_test",
		Kind:           domain.KindUser,
		OrganizationID: "org_idem_test",
		Role:           policy.RoleDeveloper,
	}
}

// idemRef is the key ref a request for key resolves to under idemPrincipal.
func idemRef(key string) store.IdempotencyKeyRef {
	p := idemPrincipal()
	return store.IdempotencyKeyRef{OrganizationID: p.OrganizationID, PrincipalID: p.ID, Key: key}
}

// postReq builds a POST /v1/projects request with the given idempotency key
// and body. When withPrincipal is true the request context carries
// idemPrincipal, as RequireAuth would have installed it.
func postReq(key, body string, withPrincipal bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/projects", strings.NewReader(body))
	if key != "" {
		req.Header.Set(HeaderIdempotencyKey, key)
	}
	if withPrincipal {
		req = req.WithContext(policy.WithPrincipal(req.Context(), idemPrincipal()))
	}
	return req
}

// recordingHandler counts its invocations and delegates to fn for the response.
type recordingHandler struct {
	ran int
	fn  func(w http.ResponseWriter, r *http.Request)
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.ran++
	if h.fn != nil {
		h.fn(w, r)
	}
}

// jsonHandler returns a handler that renders a fixed yalla.output.v1 envelope.
func jsonHandler(status int, data any) *recordingHandler {
	return &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		apienvelope.WriteData(w, status, requestID(r), data)
	}}
}

func TestRequireIdempotencySafeMethodPassesThrough(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	next := jsonHandler(http.StatusOK, map[string]string{"ok": "yes"})
	h := RequireIdempotency(fake, time.Hour)(next)

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set(HeaderIdempotencyKey, "key-1")
	rec := run(h, req)

	if next.ran != 1 {
		t.Errorf("handler ran %d times, want 1 (a safe method is served directly)", next.ran)
	}
	if fake.claims != 0 {
		t.Errorf("safe method claimed an idempotency key %d times, want 0", fake.claims)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireIdempotencyNoKeyPassesThrough(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	next := jsonHandler(http.StatusAccepted, map[string]string{"job": "j1"})
	h := RequireIdempotency(fake, time.Hour)(next)

	rec := run(h, postReq("", `{"name":"web"}`, true))

	if next.ran != 1 {
		t.Errorf("handler ran %d times, want 1 (idempotency is opt-in)", next.ran)
	}
	if fake.claims != 0 {
		t.Errorf("a request with no key claimed %d times, want 0", fake.claims)
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
}

func TestRequireIdempotencyInvalidKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  string
	}{
		{"space", "bad key"},
		{"control character", "bad\nkey"},
		{"too long", strings.Repeat("k", maxIdempotencyKeyLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeIdempotencyStore()
			next := jsonHandler(http.StatusAccepted, nil)
			h := RequireIdempotency(fake, time.Hour)(next)

			rec := run(h, postReq(tc.key, `{}`, true))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			decodeError(t, rec, "E_INVALID_INPUT")
			if next.ran != 0 {
				t.Error("handler ran for a request with a malformed idempotency key")
			}
			if fake.claims != 0 {
				t.Error("a malformed key reached the store")
			}
		})
	}
}

func TestRequireIdempotencyMissingPrincipalIsInternal(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	next := jsonHandler(http.StatusAccepted, nil)
	h := RequireIdempotency(fake, time.Hour)(next)

	// No principal on the context: the middleware was installed outside
	// RequireAuth — a wiring bug, surfaced as a 500, never a client error.
	rec := run(h, postReq("key-1", `{}`, false))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
	if next.ran != 0 {
		t.Error("handler ran without an authenticated principal")
	}
}

func TestRequireIdempotencyFirstRequestRunsAndRecords(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	next := jsonHandler(http.StatusAccepted, map[string]string{"job_id": "job_1"})
	h := RequireIdempotency(fake, time.Hour)(next)

	rec := run(h, postReq("key-first", `{"name":"web"}`, true))

	if next.ran != 1 {
		t.Errorf("handler ran %d times, want 1", next.ran)
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if rec.Header().Get(HeaderIdempotencyReplayed) != "" {
		t.Error("a first execution must not be marked as a replay")
	}
	stored, ok := fake.get(idemRef("key-first"))
	if !ok {
		t.Fatal("the claim was not recorded")
	}
	if stored.Status != store.IdempotencyStatusCompleted {
		t.Errorf("recorded status = %q, want completed", stored.Status)
	}
	if stored.ResponseStatus != http.StatusAccepted {
		t.Errorf("recorded response status = %d, want 202", stored.ResponseStatus)
	}
	if string(stored.ResponseBody) != rec.Body.String() {
		t.Errorf("recorded body = %q, want the response body %q", stored.ResponseBody, rec.Body.String())
	}
	if stored.Route != "POST /v1/projects" {
		t.Errorf("recorded route = %q, want %q", stored.Route, "POST /v1/projects")
	}
	if stored.RequestHash == "" {
		t.Error("recorded claim is missing its request hash")
	}
}

func TestRequireIdempotencyReplaysCompletedResponse(t *testing.T) {
	t.Parallel()
	const body = `{"name":"web"}`
	fake := newFakeIdempotencyStore()
	// A claim that already completed — the original request finished, e.g. its
	// provisioning job was enqueued and even completed since.
	recorded := []byte(`{"schema_version":"yalla.output.v1","ok":true,"data":{"job_id":"job_1"},"request_id":"req-original"}`)
	rec := idemRef("key-replay")
	fake.seed(store.IdempotencyRecord{
		ID:             "idk_seed_1",
		OrganizationID: rec.OrganizationID,
		PrincipalID:    rec.PrincipalID,
		Key:            rec.Key,
		Route:          "POST /v1/projects",
		RequestHash:    hashRequest(http.MethodPost, "/v1/projects", []byte(body)),
		Status:         store.IdempotencyStatusCompleted,
		ResponseStatus: http.StatusAccepted,
		ResponseBody:   recorded,
	})

	next := jsonHandler(http.StatusAccepted, map[string]string{"job_id": "job_2"})
	h := RequireIdempotency(fake, time.Hour)(next)

	resp := run(h, postReq("key-replay", body, true))

	if next.ran != 0 {
		t.Error("handler ran for a retry of a completed claim; it must be replayed")
	}
	if resp.Code != http.StatusAccepted {
		t.Errorf("status = %d, want the recorded 202", resp.Code)
	}
	if resp.Body.String() != string(recorded) {
		t.Errorf("body = %q, want the recorded body %q", resp.Body.String(), recorded)
	}
	if resp.Header().Get(HeaderIdempotencyReplayed) != "true" {
		t.Error("a replayed response must carry Idempotency-Replayed: true")
	}
}

func TestRequireIdempotencyInProgressConflict(t *testing.T) {
	t.Parallel()
	const body = `{"name":"web"}`
	fake := newFakeIdempotencyStore()
	rec := idemRef("key-inflight")
	// A claim that is still pending — the original request has not finished.
	fake.seed(store.IdempotencyRecord{
		ID:             "idk_seed_1",
		OrganizationID: rec.OrganizationID,
		PrincipalID:    rec.PrincipalID,
		Key:            rec.Key,
		Route:          "POST /v1/projects",
		RequestHash:    hashRequest(http.MethodPost, "/v1/projects", []byte(body)),
		Status:         store.IdempotencyStatusPending,
	})

	next := jsonHandler(http.StatusAccepted, nil)
	h := RequireIdempotency(fake, time.Hour)(next)

	resp := run(h, postReq("key-inflight", body, true))

	if next.ran != 0 {
		t.Error("handler ran while an identical request was still in flight")
	}
	if resp.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", resp.Code, resp.Body.String())
	}
	decodeError(t, resp, "E_CONFLICT")
}

func TestRequireIdempotencyDifferentRequestConflict(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	rec := idemRef("key-collision")
	// A claim recorded for a request whose hash will not match this retry.
	fake.seed(store.IdempotencyRecord{
		ID:             "idk_seed_1",
		OrganizationID: rec.OrganizationID,
		PrincipalID:    rec.PrincipalID,
		Key:            rec.Key,
		Route:          "POST /v1/projects",
		RequestHash:    "a-hash-from-a-completely-different-request",
		Status:         store.IdempotencyStatusCompleted,
		ResponseStatus: http.StatusAccepted,
		ResponseBody:   []byte(`{"ok":true}`),
	})

	next := jsonHandler(http.StatusAccepted, nil)
	h := RequireIdempotency(fake, time.Hour)(next)

	resp := run(h, postReq("key-collision", `{"name":"different"}`, true))

	if next.ran != 0 {
		t.Error("handler ran for a key reused with a different request")
	}
	if resp.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", resp.Code, resp.Body.String())
	}
	decodeError(t, resp, "E_IDEMPOTENCY_CONFLICT")
}

func TestRequireIdempotencyServerErrorIsNotRecorded(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	next := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		apienvelope.WriteError(w, requestID(r), apierr.Internal(nil))
	}}
	h := RequireIdempotency(fake, time.Hour)(next)

	resp := run(h, postReq("key-5xx", `{}`, true))

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.Code)
	}
	if _, ok := fake.get(idemRef("key-5xx")); ok {
		t.Error("a 5xx response must not leave a recorded claim behind")
	}
	if fake.releases != 1 {
		t.Errorf("releases = %d, want 1 (a server failure releases the claim)", fake.releases)
	}

	// A retry re-runs the handler because the claim was released.
	resp2 := run(h, postReq("key-5xx", `{}`, true))
	if next.ran != 2 {
		t.Errorf("handler ran %d times, want 2 (a released claim is re-executed on retry)", next.ran)
	}
	if resp2.Code != http.StatusInternalServerError {
		t.Errorf("retry status = %d, want 500", resp2.Code)
	}
}

// TestRequireIdempotencyRecordsClientErrors proves a client-error response
// (validation failure, authorization failure, not found) is a final answer:
// it is recorded and replayed verbatim on a retry, just like a success.
func TestRequireIdempotencyRecordsClientErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		status   int
		err      *yerr.Error
		wantCode string
	}{
		{"validation failure", http.StatusBadRequest, apierr.Invalid("name is required"), "E_INVALID_INPUT"},
		{"authorization failure", http.StatusForbidden, apierr.Forbidden("not allowed"), "E_FORBIDDEN"},
		{"not found", http.StatusNotFound, apierr.NotFound("project", "p1"), "E_NOT_FOUND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeIdempotencyStore()
			next := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
				apienvelope.WriteError(w, requestID(r), tc.err)
			}}
			h := RequireIdempotency(fake, time.Hour)(next)

			first := run(h, postReq("key-clienterr", `{}`, true))
			if first.Code != tc.status {
				t.Fatalf("first status = %d, want %d", first.Code, tc.status)
			}
			decodeError(t, first, tc.wantCode)
			if next.ran != 1 {
				t.Fatalf("handler ran %d times on the first request, want 1", next.ran)
			}

			// The retry replays the recorded client-error response without
			// re-running the handler.
			second := run(h, postReq("key-clienterr", `{}`, true))
			if next.ran != 1 {
				t.Errorf("handler ran %d times total, want 1 (the client error is replayed)", next.ran)
			}
			if second.Code != tc.status {
				t.Errorf("replay status = %d, want %d", second.Code, tc.status)
			}
			if second.Body.String() != first.Body.String() {
				t.Errorf("replay body = %q, want the original %q", second.Body.String(), first.Body.String())
			}
			if second.Header().Get(HeaderIdempotencyReplayed) != "true" {
				t.Error("the replayed client error must carry Idempotency-Replayed: true")
			}
		})
	}
}

// TestRequireIdempotencyRetryBeforeAndAfterCompletion exercises the headline
// contract: an identical retry while the original is in flight is told the
// request is in progress, and once the original completes the same retry
// replays the recorded response.
func TestRequireIdempotencyRetryBeforeAndAfterCompletion(t *testing.T) {
	t.Parallel()
	const body = `{"name":"web"}`
	fake := newFakeIdempotencyStore()

	// A handler we can hold open to model "job not finished yet".
	release := make(chan struct{})
	started := make(chan struct{})
	blocking := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), map[string]string{"job_id": "job_1"})
	}}
	h := RequireIdempotency(fake, time.Hour)(blocking)

	// First request runs in the background, holding its claim pending.
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- run(h, postReq("key-e2e", body, true)) }()
	<-started

	// A retry that arrives before completion is told the request is in flight.
	inFlight := run(h, postReq("key-e2e", body, true))
	if inFlight.Code != http.StatusConflict {
		t.Fatalf("in-flight retry status = %d, want 409; body %s", inFlight.Code, inFlight.Body.String())
	}
	decodeError(t, inFlight, "E_CONFLICT")

	// Let the original finish.
	close(release)
	first := <-firstDone
	if first.Code != http.StatusAccepted {
		t.Fatalf("first request status = %d, want 202", first.Code)
	}

	// The same retry, now after completion, replays the recorded response.
	afterDone := run(h, postReq("key-e2e", body, true))
	if afterDone.Code != http.StatusAccepted {
		t.Errorf("post-completion retry status = %d, want the recorded 202", afterDone.Code)
	}
	if afterDone.Body.String() != first.Body.String() {
		t.Errorf("post-completion retry body = %q, want the recorded %q", afterDone.Body.String(), first.Body.String())
	}
	if afterDone.Header().Get(HeaderIdempotencyReplayed) != "true" {
		t.Error("the post-completion retry must be flagged as a replay")
	}
	if blocking.ran != 1 {
		t.Errorf("handler ran %d times, want exactly 1 across all three requests", blocking.ran)
	}
}

func TestRequireIdempotencyClaimStoreFailure(t *testing.T) {
	t.Parallel()
	fake := newFakeIdempotencyStore()
	fake.claimErr = apierr.StoreUnavailable(nil)
	next := jsonHandler(http.StatusAccepted, nil)
	hh := RequireIdempotency(fake, time.Hour)(next)

	resp := run(hh, postReq("key-storefail", `{}`, true))

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", resp.Code, resp.Body.String())
	}
	decodeError(t, resp, "E_UNAVAILABLE")
	if next.ran != 0 {
		t.Error("handler ran despite the claim store failing")
	}
}

func TestRequireIdempotencyPreservesRequestBodyForHandler(t *testing.T) {
	t.Parallel()
	const body = `{"name":"web","replicas":3}`
	fake := newFakeIdempotencyStore()
	var seen string
	next := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("handler could not read the request body: %v", err)
		}
		seen = string(b)
		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), nil)
	}}
	hh := RequireIdempotency(fake, time.Hour)(next)

	run(hh, postReq("key-body", body, true))

	if seen != body {
		t.Errorf("handler saw body %q, want the original %q (the middleware must restore it)", seen, body)
	}
}

// TestRequireIdempotencyReplayedBodyCarriesNoSecret proves the recorded and
// replayed response is the already-redacted apienvelope body: a secret that a
// handler accidentally placed in an error message never survives into the
// stored claim or the replay.
func TestRequireIdempotencyReplayedBodyCarriesNoSecret(t *testing.T) {
	t.Parallel()
	const secret = "leaked-token-abc123"
	fake := newFakeIdempotencyStore()
	next := &recordingHandler{fn: func(w http.ResponseWriter, r *http.Request) {
		apienvelope.WriteError(w, requestID(r),
			apierr.Conflict("rejected request carrying Authorization: Bearer "+secret))
	}}
	hh := RequireIdempotency(fake, time.Hour)(next)

	first := run(hh, postReq("key-secret", `{}`, true))
	if strings.Contains(first.Body.String(), secret) {
		t.Fatalf("the rendered response leaked a secret: %s", first.Body.String())
	}
	stored, ok := fake.get(idemRef("key-secret"))
	if !ok {
		t.Fatal("the client-error claim was not recorded")
	}
	if strings.Contains(string(stored.ResponseBody), secret) {
		t.Errorf("the recorded claim body leaked a secret: %s", stored.ResponseBody)
	}
	second := run(hh, postReq("key-secret", `{}`, true))
	if strings.Contains(second.Body.String(), secret) {
		t.Errorf("the replayed response leaked a secret: %s", second.Body.String())
	}
}
