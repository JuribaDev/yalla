package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// This file is the HTTP idempotency middleware for the Yalla Control Plane
// API. It is the layer that makes a mutating endpoint safe for an agent or CI
// to retry: a client attaches an Idempotency-Key to an unsafe request, and the
// middleware guarantees the handler runs at most once per key while every
// retry receives the same response.
//
// The wire contract is deterministic:
//
//   - A safe method (GET, HEAD, OPTIONS, TRACE) or an unsafe request with no
//     Idempotency-Key passes straight through — idempotency is opt-in.
//   - A malformed Idempotency-Key is 400 E_VALIDATION.
//   - The first request for a key claims it, runs the handler, and records the
//     rendered response envelope. A retry with the same key and the same
//     request replays that recorded envelope verbatim (with an
//     Idempotency-Replayed: true response header) without running the handler
//     again.
//   - A retry with the same key but a different request is 409
//     E_IDEMPOTENCY_CONFLICT.
//   - A retry that arrives while the original request is still in flight is 409
//     E_CONFLICT ("already in progress").
//   - A server failure (5xx) is never recorded: the claim is released so the
//     client may retry and re-run the handler.
//
// Every response is rendered through the apienvelope package (or, on replay,
// is a previously-rendered apienvelope body), so the yalla.output.v1 /
// yalla.error.v1 contract holds on the idempotency path too.

// HeaderIdempotencyKey is the request header a client sets to make a mutating
// request idempotent. It is part of the public API contract.
const HeaderIdempotencyKey = "Idempotency-Key"

// HeaderIdempotencyReplayed is the response header set to "true" when the body
// is a replay of a previously recorded response rather than a fresh execution.
// It is part of the public API contract; agents may read it to distinguish a
// replay from a first execution.
const HeaderIdempotencyReplayed = "Idempotency-Replayed"

// DefaultIdempotencyTTL is the lifetime a claimed idempotency key is honoured
// for when RequireIdempotency is given a non-positive ttl. After it elapses the
// key may be reused for a different request.
const DefaultIdempotencyTTL = 24 * time.Hour

const (
	// maxIdempotencyKeyLen bounds the length of an Idempotency-Key header.
	// Generous enough for UUIDs, ULIDs, and random tokens; small enough that a
	// hostile caller cannot use the header to bloat database rows.
	maxIdempotencyKeyLen = 255
	// maxIdempotentRequestBody bounds how much of an unsafe request body the
	// middleware will read to compute the request hash. A larger body is
	// rejected rather than buffered.
	maxIdempotentRequestBody = 1 << 20 // 1 MiB
	// maxIdempotentResponseBody bounds how large a recorded response may be. A
	// handler that writes more than this has its claim released instead of
	// recorded — the client may retry rather than lose the response silently.
	maxIdempotentResponseBody = 256 * 1024 // 256 KiB
)

// IdempotencyStore is the narrow persistence port the idempotency middleware
// depends on. The store-backed adapter (NewIdempotencyStore) satisfies it in
// production; tests supply a fake. Keeping the dependency an interface keeps
// the middleware unit-testable without a real database, and keeps the *Tx
// boundary — every method here runs its own transaction internally — out of
// the middleware's view.
type IdempotencyStore interface {
	// Claim atomically takes the key named by rec. claimed is true when the
	// caller now owns the key (and must run the handler); false when a live
	// claim already exists, in which case the returned record is that claim.
	Claim(ctx context.Context, rec store.IdempotencyRecord) (record store.IdempotencyRecord, claimed bool, err error)
	// Complete records the rendered response for a pending claim.
	Complete(ctx context.Context, ref store.IdempotencyKeyRef, status int, body []byte) (store.IdempotencyRecord, error)
	// Release drops a pending claim so the key may be retried from scratch.
	Release(ctx context.Context, ref store.IdempotencyKeyRef) error
}

// storeIdempotency is the production IdempotencyStore: it runs every operation
// of the store.IdempotencyRepository inside its own Store.Write transaction, so
// the middleware never has to hold a *Tx.
type storeIdempotency struct {
	store *store.Store
	repo  *store.IdempotencyRepository
}

// NewIdempotencyStore builds the production IdempotencyStore over a Store.
func NewIdempotencyStore(s *store.Store) IdempotencyStore {
	return storeIdempotency{store: s, repo: store.NewIdempotencyRepository()}
}

func (a storeIdempotency) Claim(ctx context.Context, rec store.IdempotencyRecord) (store.IdempotencyRecord, bool, error) {
	var (
		result  store.IdempotencyRecord
		claimed bool
	)
	err := a.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, c, e := a.repo.Claim(ctx, tx, rec)
		if e != nil {
			return e
		}
		result, claimed = r, c
		return nil
	})
	if err != nil {
		return store.IdempotencyRecord{}, false, err
	}
	return result, claimed, nil
}

func (a storeIdempotency) Complete(ctx context.Context, ref store.IdempotencyKeyRef, status int, body []byte) (store.IdempotencyRecord, error) {
	var result store.IdempotencyRecord
	err := a.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		r, e := a.repo.Complete(ctx, tx, ref, status, body, time.Time{})
		if e != nil {
			return e
		}
		result = r
		return nil
	})
	if err != nil {
		return store.IdempotencyRecord{}, err
	}
	return result, nil
}

func (a storeIdempotency) Release(ctx context.Context, ref store.IdempotencyKeyRef) error {
	return a.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return a.repo.Release(ctx, tx, ref)
	})
}

// idempotencyConfig is the resolved configuration of a RequireIdempotency
// middleware instance.
type idempotencyConfig struct {
	store IdempotencyStore
	ttl   time.Duration
	now   func() time.Time
}

// RequireIdempotency builds middleware that makes the wrapped handler safe to
// retry under an Idempotency-Key. It must be installed inside RequireAuth: it
// reads the authenticated principal from the request context to scope the key
// to a principal within a tenant.
//
// ttl bounds how long a claimed key is honoured; a non-positive ttl defaults
// to DefaultIdempotencyTTL.
func RequireIdempotency(s IdempotencyStore, ttl time.Duration) func(http.Handler) http.Handler {
	cfg := idempotencyConfig{store: s, ttl: ttl, now: time.Now}
	if cfg.ttl <= 0 {
		cfg.ttl = DefaultIdempotencyTTL
	}
	return cfg.middleware
}

// middleware is the http.Handler decorator RequireIdempotency returns.
func (c idempotencyConfig) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Idempotency only applies to unsafe (state-changing) methods; a safe
		// method is already retry-safe by definition.
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// Idempotency is opt-in: an unsafe request with no key is served
		// directly, with no bookkeeping.
		key := r.Header.Get(HeaderIdempotencyKey)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if err := validateIdempotencyKey(key); err != nil {
			apienvelope.WriteError(w, requestID(r), err)
			return
		}

		// The middleware is installed inside RequireAuth, so the principal is
		// always present here. Its absence is a wiring bug, not a client error.
		principal, ok := policy.PrincipalFromContext(r.Context())
		if !ok || principal.ID == "" || principal.OrganizationID == "" {
			apienvelope.WriteError(w, requestID(r),
				apierr.Internal(errors.New("httpapi: idempotency middleware ran without an authenticated principal")))
			return
		}

		body, bodyErr := readAndRestoreBody(r)
		if bodyErr != nil {
			apienvelope.WriteError(w, requestID(r), bodyErr)
			return
		}
		route := r.Method + " " + r.URL.Path
		hash := hashRequest(r.Method, r.URL.RequestURI(), body)

		ref := store.IdempotencyKeyRef{
			OrganizationID: principal.OrganizationID,
			PrincipalID:    principal.ID,
			Key:            key,
		}
		claim, claimed, err := c.store.Claim(r.Context(), store.IdempotencyRecord{
			OrganizationID: ref.OrganizationID,
			PrincipalID:    ref.PrincipalID,
			Key:            key,
			Route:          route,
			RequestHash:    hash,
			RequestID:      requestID(r),
			ExpiresAt:      c.now().UTC().Add(c.ttl),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		if !claimed {
			c.serveExistingClaim(w, r, claim, hash)
			return
		}

		// We own the claim: run the handler against a capturing writer so the
		// rendered response can be recorded before it reaches the client.
		capture := &responseCapture{header: make(http.Header)}
		next.ServeHTTP(capture, r)
		status, respBody := capture.result()

		// A server failure is not a final answer, and a response too large to
		// store durably must not silently drop the idempotency guarantee. In
		// both cases the claim is released so the client may retry and re-run
		// the handler.
		if status >= http.StatusInternalServerError || len(respBody) > maxIdempotentResponseBody {
			_ = c.store.Release(r.Context(), ref)
			capture.flushTo(w)
			return
		}

		if _, err := c.store.Complete(r.Context(), ref, status, respBody); err != nil {
			// The response was produced; only recording it for replay failed.
			// Release the claim so a retry re-runs the handler rather than
			// being told the request is "still in progress" forever.
			_ = c.store.Release(r.Context(), ref)
		}
		capture.flushTo(w)
	})
}

// serveExistingClaim renders the response for an unsafe request whose key is
// already held by a live claim: a replay of the recorded response when the
// request matches, an idempotency conflict when it does not, and an
// "in progress" conflict when the original request has not finished yet.
func (c idempotencyConfig) serveExistingClaim(w http.ResponseWriter, r *http.Request, claim store.IdempotencyRecord, hash string) {
	if claim.RequestHash != hash {
		// Same key, different request: the defining idempotency conflict.
		apienvelope.WriteError(w, requestID(r),
			apierr.IdempotencyConflict("the Idempotency-Key was already used for a different request"))
		return
	}
	switch claim.Status {
	case store.IdempotencyStatusCompleted:
		replayResponse(w, claim)
	default:
		// An identical request under the same key is still in flight. This is
		// a transient collision, not an idempotency conflict: the client
		// should back off and retry, at which point it will get the recorded
		// response.
		apienvelope.WriteError(w, requestID(r),
			apierr.Conflict("a request with this Idempotency-Key is already in progress").
				WithHint("the original request has not finished yet; retry after a short backoff"))
	}
}

// isSafeMethod reports whether method is an HTTP method with no state-changing
// semantics, and therefore already retry-safe without idempotency bookkeeping.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// validateIdempotencyKey rejects a malformed Idempotency-Key. A valid key is
// 1..maxIdempotencyKeyLen characters drawn only from [A-Za-z0-9._-] — the same
// conservative character set Yalla accepts for correlation identifiers, which
// keeps the value safe to place verbatim into database rows, logs, and audit
// metadata. The caller-supplied key value is never echoed in the error.
func validateIdempotencyKey(key string) *yerr.Error {
	if len(key) > maxIdempotencyKeyLen {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field:  HeaderIdempotencyKey,
			Reason: "must be at most 255 characters",
		})
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return apierr.InvalidInput(apierr.FieldViolation{
				Field:  HeaderIdempotencyKey,
				Reason: "must contain only letters, digits, '.', '-', and '_'",
			})
		}
	}
	return nil
}

// readAndRestoreBody reads the request body so it can be hashed, then restores
// it as a fresh reader so the wrapped handler still sees the full body. A body
// larger than maxIdempotentRequestBody is rejected rather than buffered. A nil
// body (a request with no payload) yields a nil slice and no error.
func readAndRestoreBody(r *http.Request) ([]byte, *yerr.Error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxIdempotentRequestBody+1)
	buf, err := io.ReadAll(limited)
	_ = r.Body.Close()
	if err != nil {
		return nil, apierr.Invalid("the request body could not be read")
	}
	if len(buf) > maxIdempotentRequestBody {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "body",
			Reason: "exceeds the maximum size for an idempotent request",
		})
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	return buf, nil
}

// hashRequest returns a stable sha256 hex digest of the canonical request:
// method, request URI (path and query), and body. Two requests hash equal
// exactly when an agent's retry is truly the same request — which is what lets
// the middleware tell a safe replay from an E_IDEMPOTENCY_CONFLICT. The body is
// hashed, never stored, so the digest carries no secret.
func hashRequest(method, requestURI string, body []byte) string {
	h := sha256.New()
	// Length-prefix-free but newline-delimited: method and requestURI cannot
	// contain a newline, so the framing is unambiguous.
	h.Write([]byte(method))
	h.Write([]byte{'\n'})
	h.Write([]byte(requestURI))
	h.Write([]byte{'\n'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// replayResponse writes a previously recorded response back to the client. The
// recorded body is an already-rendered, already-redacted apienvelope body, so
// it is written verbatim; Content-Type is application/json because every Yalla
// envelope is JSON, and Idempotency-Replayed flags the response as a replay.
func replayResponse(w http.ResponseWriter, claim store.IdempotencyRecord) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderIdempotencyReplayed, "true")
	w.WriteHeader(claim.ResponseStatus)
	_, _ = w.Write(claim.ResponseBody)
}

// responseCapture is an http.ResponseWriter that buffers a handler's response
// in memory instead of sending it, so the idempotency middleware can record
// the rendered envelope before deciding whether to flush it to the client.
type responseCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

// Header returns the captured header map.
func (c *responseCapture) Header() http.Header { return c.header }

// WriteHeader records the response status. Like the real net/http writer, only
// the first call takes effect.
func (c *responseCapture) WriteHeader(status int) {
	if c.wrote {
		return
	}
	c.status = status
	c.wrote = true
}

// Write buffers response bytes, defaulting the status to 200 on the first
// write — matching net/http's implicit-header behaviour.
func (c *responseCapture) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(b)
}

// result returns the captured status and body. A handler that never wrote a
// header or body is treated as a 200 with an empty body, matching net/http.
func (c *responseCapture) result() (int, []byte) {
	status := c.status
	if !c.wrote {
		status = http.StatusOK
	}
	return status, c.body.Bytes()
}

// flushTo copies the captured headers, status, and body onto the real
// response writer.
func (c *responseCapture) flushTo(w http.ResponseWriter) {
	dst := w.Header()
	for k, vv := range c.header {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	status, body := c.result()
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
