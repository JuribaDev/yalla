package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// IdempotencyStatus is the lifecycle state of an idempotency-key claim. It
// mirrors the idempotency_keys.status CHECK constraint exactly: the set is
// closed, so a value outside it is rejected both by this type's Valid check and
// by the database.
type IdempotencyStatus string

const (
	// IdempotencyStatusPending marks a claimed key whose request is still
	// in flight: the handler has not finished, so no response is recorded yet.
	IdempotencyStatusPending IdempotencyStatus = "pending"
	// IdempotencyStatusCompleted marks a claim whose handler finished and whose
	// rendered response envelope is recorded for replay.
	IdempotencyStatusCompleted IdempotencyStatus = "completed"
)

// Valid reports whether s is one of the two recognised states.
func (s IdempotencyStatus) Valid() bool {
	return s == IdempotencyStatusPending || s == IdempotencyStatusCompleted
}

// String returns the status's stable string value.
func (s IdempotencyStatus) String() string { return string(s) }

// IdempotencyKeyRef identifies a single idempotency-key claim. A key is scoped
// to a principal within a tenant: the same key string used by two different
// principals — or in two different organizations — names two independent
// claims, so every lookup and mutation is keyed by all three fields.
type IdempotencyKeyRef struct {
	OrganizationID string
	PrincipalID    string
	Key            string
}

// IdempotencyRecord is the source-of-truth representation of a row in the
// idempotency_keys table — one durable record that lets a mutating endpoint be
// retried safely by an agent or CI.
//
// It is the persistence-layer shape; deriving it from an HTTP request and
// rendering its stored response back onto the wire is the job of the httpapi
// layer. ResponseBody holds the already-rendered yalla.output.v1 /
// yalla.error.v1 envelope — the apienvelope renderer has already run it through
// the output redactor — and RequestHash is a sha256 digest, never the raw
// request body, so no field ever carries a secret.
//
// ResponseStatus, ResponseBody, and CompletedAt are zero while Status is
// pending and populated once Status is completed.
type IdempotencyRecord struct {
	ID             string
	OrganizationID string
	PrincipalID    string
	Key            string
	Route          string
	RequestHash    string
	RequestID      string
	Status         IdempotencyStatus
	ResponseStatus int
	ResponseBody   []byte
	CreatedAt      time.Time
	CompletedAt    time.Time
	ExpiresAt      time.Time
}

// Ref returns the IdempotencyKeyRef that identifies this record.
func (r IdempotencyRecord) Ref() IdempotencyKeyRef {
	return IdempotencyKeyRef{
		OrganizationID: r.OrganizationID,
		PrincipalID:    r.PrincipalID,
		Key:            r.Key,
	}
}

// IdempotencyRepository is the persistence layer for Yalla's idempotency-key
// records. It follows the same transaction pattern as the other repositories:
//
//   - Mutations (Claim, Complete, Release) require a *Tx, so they can only run
//     inside Store.Write and commit or roll back atomically.
//   - Reads (Find) accept a Querier, so they run against a read-only
//     transaction or an open write transaction.
//   - Every query is tenant scoped by organization_id (then principal_id), so a
//     key from another tenant — or another principal — can never match.
//
// On top of that pattern it owns the claim protocol: Claim atomically takes a
// key (inserting a fresh row, or stealing an expired one) or reports the
// existing live claim, so two concurrent requests under the same key are
// serialised by the row lock rather than racing.
//
// The repository is stateless; the constructor exists so call sites depend on
// a value rather than a bare struct literal.
type IdempotencyRepository struct{}

// NewIdempotencyRepository returns an IdempotencyRepository.
func NewIdempotencyRepository() *IdempotencyRepository { return &IdempotencyRepository{} }

// idempotencyKeyColumns is the column list returned by every idempotency query,
// in the order scanIdempotencyRecord expects.
const idempotencyKeyColumns = `id, organization_id, principal_id, idempotency_key, route, ` +
	`request_hash, request_id, status, response_status, response_body, ` +
	`created_at, completed_at, expires_at`

// Claim atomically takes the idempotency key named by rec inside tx. It is the
// single entry point of the claim protocol and has exactly two outcomes:
//
//   - claimed == true: the caller now owns the key. Either no row existed and a
//     fresh pending row was inserted, or the existing row had expired and was
//     taken over (reset to pending with rec's request identity). The caller
//     must run the handler and then call Complete — or Release on a server
//     failure.
//   - claimed == false: a live (unexpired) claim already exists for the key.
//     The returned record is that existing claim; the caller must not run the
//     handler. It either replays the recorded response (when the request
//     matches) or rejects the request as an idempotency conflict (when it does
//     not).
//
// The upsert's ON CONFLICT ... DO UPDATE locks the conflicting row even when
// its WHERE excludes it from the update, so the follow-up read of a live claim
// sees a stable, locked row and concurrent claimers serialise here rather than
// racing.
//
// It requires a *Tx so a claim can never escape its transaction. The request
// identity fields (OrganizationID, PrincipalID, Key, Route, RequestHash) and a
// non-zero ExpiresAt are required; a blank ID is minted here.
func (r *IdempotencyRepository) Claim(ctx context.Context, tx *Tx, rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	if tx == nil {
		return IdempotencyRecord{}, false, apierr.Internal(errors.New("store: IdempotencyRepository.Claim called with a nil transaction"))
	}
	var violations []apierr.FieldViolation
	if rec.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if rec.PrincipalID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "principal_id", Reason: "is required"})
	}
	if rec.Key == "" {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "is required"})
	}
	if rec.Route == "" {
		violations = append(violations, apierr.FieldViolation{Field: "route", Reason: "is required"})
	}
	if rec.RequestHash == "" {
		violations = append(violations, apierr.FieldViolation{Field: "request_hash", Reason: "is required"})
	}
	if rec.ExpiresAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "expires_at", Reason: "is required"})
	}
	if len(violations) > 0 {
		return IdempotencyRecord{}, false, apierr.InvalidInput(violations...)
	}

	if rec.ID == "" {
		id, err := newIdempotencyID()
		if err != nil {
			return IdempotencyRecord{}, false, apierr.Internal(err)
		}
		rec.ID = id
	}

	// The WHERE on DO UPDATE only steals an expired row; against a live row the
	// conflict action touches nothing and RETURNING yields no row. Either way
	// the conflicting row is locked for the rest of tx.
	row := tx.QueryRow(ctx,
		`INSERT INTO idempotency_keys
		   (id, organization_id, principal_id, idempotency_key, route,
		    request_hash, request_id, status, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
		 ON CONFLICT (organization_id, principal_id, idempotency_key) DO UPDATE
		   SET id = EXCLUDED.id,
		       route = EXCLUDED.route,
		       request_hash = EXCLUDED.request_hash,
		       request_id = EXCLUDED.request_id,
		       status = 'pending',
		       response_status = NULL,
		       response_body = NULL,
		       created_at = now(),
		       completed_at = NULL,
		       expires_at = EXCLUDED.expires_at
		   WHERE idempotency_keys.expires_at <= now()
		 RETURNING `+idempotencyKeyColumns,
		rec.ID, rec.OrganizationID, rec.PrincipalID, rec.Key, rec.Route,
		rec.RequestHash, rec.RequestID, rec.ExpiresAt)
	claimed, err := scanIdempotencyRecord(row)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// A live claim already holds the key. It is locked by the DO UPDATE
		// attempt above, so this read inside the same tx sees a stable row.
		existing, ok, ferr := r.Find(ctx, tx, rec.Ref())
		if ferr != nil {
			return IdempotencyRecord{}, false, ferr
		}
		if !ok {
			// Vanishingly rare: the row was released between the upsert and
			// this read. Surface a typed, retryable-shaped conflict rather
			// than an opaque failure.
			return IdempotencyRecord{}, false, apierr.Conflict("the idempotency key claim could not be resolved; retry the request")
		}
		return existing, false, nil
	case err != nil:
		return IdempotencyRecord{}, false, mapWriteError(err, "the idempotency key could not be claimed")
	default:
		return claimed, true, nil
	}
}

// Complete records the rendered response for a pending claim inside tx and
// returns the completed row. status is the HTTP status of the response and
// body is the rendered yalla.output.v1 / yalla.error.v1 envelope; both are
// stored verbatim so a later retry replays the exact original response.
//
// It requires a *Tx and is tenant scoped: the UPDATE matches only a pending
// row for the given organization, principal, and key. A claim that is no
// longer pending — released, or stolen after expiry — matches nothing and is
// reported as a Conflict rather than silently doing nothing. A zero now
// defaults to the current UTC time.
func (r *IdempotencyRepository) Complete(ctx context.Context, tx *Tx, ref IdempotencyKeyRef, status int, body []byte, now time.Time) (IdempotencyRecord, error) {
	if tx == nil {
		return IdempotencyRecord{}, apierr.Internal(errors.New("store: IdempotencyRepository.Complete called with a nil transaction"))
	}
	if status < 100 || status > 599 {
		return IdempotencyRecord{}, apierr.Internal(fmt.Errorf("store: IdempotencyRepository.Complete called with an out-of-range status %d", status))
	}
	if body == nil {
		// The completion CHECK rejects a NULL response_body; an empty (but
		// non-nil) envelope is still a valid recorded response.
		body = []byte{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	row := tx.QueryRow(ctx,
		`UPDATE idempotency_keys
		    SET status = 'completed',
		        response_status = $4,
		        response_body = $5,
		        completed_at = $6
		  WHERE organization_id = $1 AND principal_id = $2 AND idempotency_key = $3
		    AND status = 'pending'
		  RETURNING `+idempotencyKeyColumns,
		ref.OrganizationID, ref.PrincipalID, ref.Key, status, body, now)
	completed, err := scanIdempotencyRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdempotencyRecord{}, apierr.Conflict("the idempotency key claim is no longer pending and cannot be completed")
	}
	if err != nil {
		return IdempotencyRecord{}, mapWriteError(err, "the idempotency key claim could not be completed")
	}
	return completed, nil
}

// Release deletes a pending claim inside tx. The middleware calls it when the
// handler produced a server failure (a 5xx) that the client should be allowed
// to retry: dropping the claim frees the key so a retry re-runs the handler
// rather than replaying the failure forever.
//
// It requires a *Tx and is tenant scoped: the DELETE matches only a pending
// row for the given organization, principal, and key. Releasing a claim that
// is already completed or already gone is a no-op, not an error — Release is
// safe to call defensively.
func (r *IdempotencyRepository) Release(ctx context.Context, tx *Tx, ref IdempotencyKeyRef) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: IdempotencyRepository.Release called with a nil transaction"))
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM idempotency_keys
		  WHERE organization_id = $1 AND principal_id = $2 AND idempotency_key = $3
		    AND status = 'pending'`,
		ref.OrganizationID, ref.PrincipalID, ref.Key); err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

// Find returns the idempotency-key claim identified by ref. The boolean is
// false when no row exists for the key. The query is tenant scoped by
// organization_id (then principal_id), so a key from another tenant — or
// another principal — never matches. It accepts a Querier so it works against a
// read-only transaction or an open write transaction.
//
// Find returns the row as stored, including an expired one: deciding whether an
// expired claim is still honoured is the caller's policy, and Claim already
// takes over an expired row transparently.
func (r *IdempotencyRepository) Find(ctx context.Context, q Querier, ref IdempotencyKeyRef) (IdempotencyRecord, bool, error) {
	row := q.QueryRow(ctx,
		`SELECT `+idempotencyKeyColumns+`
		   FROM idempotency_keys
		  WHERE organization_id = $1 AND principal_id = $2 AND idempotency_key = $3`,
		ref.OrganizationID, ref.PrincipalID, ref.Key)
	rec, err := scanIdempotencyRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdempotencyRecord{}, false, nil
	}
	if err != nil {
		return IdempotencyRecord{}, false, apierr.StoreUnavailable(err)
	}
	return rec, true, nil
}

// scanIdempotencyRecord scans one idempotency_keys row in idempotencyKeyColumns
// order, mapping the nullable response and completion columns to their zero
// values when absent. pgx.Rows satisfies pgx.Row, so the same scanner serves
// both single-row RETURNING queries and any future list query.
func scanIdempotencyRecord(row pgx.Row) (IdempotencyRecord, error) {
	var (
		rec            IdempotencyRecord
		status         string
		responseStatus *int
		responseBody   []byte
		completedAt    *time.Time
	)
	if err := row.Scan(
		&rec.ID, &rec.OrganizationID, &rec.PrincipalID, &rec.Key, &rec.Route,
		&rec.RequestHash, &rec.RequestID, &status, &responseStatus, &responseBody,
		&rec.CreatedAt, &completedAt, &rec.ExpiresAt,
	); err != nil {
		return IdempotencyRecord{}, err
	}
	rec.Status = IdempotencyStatus(status)
	if responseStatus != nil {
		rec.ResponseStatus = *responseStatus
	}
	rec.ResponseBody = responseBody
	if completedAt != nil {
		rec.CompletedAt = *completedAt
	}
	return rec, nil
}

// newIdempotencyID mints an opaque, non-guessable id for an idempotency_keys
// row. Idempotency records are an internal accounting trail rather than
// customer-facing domain resources, so — like audit and quota accounting rows —
// they carry their own prefixed id rather than a domain.Kind id.
func newIdempotencyID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating idempotency id entropy: %w", err)
	}
	return "idk_" + hex.EncodeToString(buf[:]), nil
}
