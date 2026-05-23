package store

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultSlowQueryThreshold = 250 * time.Millisecond

// Querier is the read/write surface shared by a connection pool and a
// transaction. Both pgx.Tx and *Tx satisfy it, so read-oriented repository
// methods can run against either a standalone read-only transaction or an open
// write transaction without changing their signature.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Tx is an open database transaction handle and the write surface of the
// store. Repository mutation methods require a *Tx, and a *Tx can only be
// obtained from inside Store.Write — so a mutation can never run outside a
// transaction. That is the mechanism that makes the authorization and quota
// checks which share that transaction impossible to bypass: every step of a
// unit of work commits or rolls back atomically with the write.
//
// The embedded pgx.Tx is unexported so callers cannot commit or roll back the
// transaction out from under Store.Write, which owns its lifecycle.
type Tx struct {
	tx        pgx.Tx
	store     *Store
	operation string
}

// Exec runs a statement inside the transaction.
func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	start := time.Now()
	tag, err := t.tx.Exec(ctx, sql, args...)
	t.observe(ctx, sql, time.Since(start), err)
	return tag, err
}

// Query runs a query inside the transaction.
func (t *Tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	start := time.Now()
	rows, err := t.tx.Query(ctx, sql, args...)
	t.observe(ctx, sql, time.Since(start), err)
	return rows, err
}

// QueryRow runs a single-row query inside the transaction.
func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	start := time.Now()
	return slowQueryRow{
		row:       t.tx.QueryRow(ctx, sql, args...),
		ctx:       ctx,
		store:     t.store,
		operation: t.operation,
		sql:       sql,
		start:     start,
	}
}

func (t *Tx) observe(ctx context.Context, sql string, elapsed time.Duration, err error) {
	if t == nil || t.store == nil {
		return
	}
	t.store.observeQuery(ctx, t.operation, sql, elapsed, err)
}

// Store owns Postgres access for control-plane source-of-truth state. It is
// the only place repository code reaches the database: every query is either
// an explicit read (Read) or part of a transaction (Write), so a mutation can
// never escape the transaction that also carries its authorization and quota
// checks.
type Store struct {
	pool               *pgxpool.Pool
	logger             *slog.Logger
	slowQueryThreshold time.Duration
	slowQueryMetrics   *telemetry.SlowQueryMetrics
}

// Option customizes Store observability and persistence behavior.
type Option func(*Store)

// WithSlowQueryThreshold configures the minimum query duration that emits the
// datastore slow-query log and metric. A non-positive duration disables slow
// query observations.
func WithSlowQueryThreshold(threshold time.Duration) Option {
	return func(s *Store) {
		s.slowQueryThreshold = threshold
	}
}

// WithSlowQueryMetrics configures the slow-query metrics collector. A nil
// collector disables slow-query metric aggregation while leaving logs intact.
func WithSlowQueryMetrics(metrics *telemetry.SlowQueryMetrics) Option {
	return func(s *Store) {
		s.slowQueryMetrics = metrics
	}
}

// New builds a Store over an established connection pool. A nil logger is
// replaced with a discard logger so callers may omit one. It returns an error
// for a nil pool so a misconfigured store fails at construction.
func New(pool *pgxpool.Pool, logger *slog.Logger, opts ...Option) (*Store, error) {
	if pool == nil {
		return nil, errors.New("store: nil pool")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Store{
		pool:               pool,
		logger:             logger,
		slowQueryThreshold: defaultSlowQueryThreshold,
		slowQueryMetrics:   telemetry.DefaultSlowQueryMetrics,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

// Pool exposes the underlying connection pool for callers that own process
// lifecycle — health checks, readiness probes, the migration runner. Repository
// code never uses it directly; it goes through Read and Write.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Write runs fn inside a single database transaction and hands it the *Tx that
// every mutation and check in the unit of work must share. The transaction is
// committed only when fn returns nil; any error — a validation failure, a
// denied authorization decision, an exhausted quota, or a failed
// provisioning-job enqueue — rolls the whole transaction back, so
// partially-applied state can never be observed. A panic inside fn also rolls
// the transaction back before the panic resumes unwinding.
//
// fn's error is returned unchanged so the typed apierr classification it
// carries reaches the caller intact; only failures owned by Store itself
// (opening or committing the transaction) are mapped to the error taxonomy.
func (s *Store) Write(ctx context.Context, fn func(context.Context, *Tx) error) error {
	pgtx, err := s.pool.Begin(ctx)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	tx := &Tx{tx: pgtx, store: s, operation: "write"}

	committed := false
	defer func() {
		if committed {
			return
		}
		// context.WithoutCancel: the caller's context may already be cancelled
		// — that is often *why* the unit of work is being rolled back — but the
		// rollback must still reach the database. ErrTxClosed is expected when a
		// commit failed after partially closing the transaction.
		if rbErr := pgtx.Rollback(context.WithoutCancel(ctx)); rbErr != nil &&
			!errors.Is(rbErr, pgx.ErrTxClosed) {
			s.logger.ErrorContext(ctx, "store: transaction rollback failed",
				slog.String("error", rbErr.Error()))
		}
	}()

	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := pgtx.Commit(ctx); err != nil {
		return apierr.StoreUnavailable(err)
	}
	committed = true
	return nil
}

// Read runs fn inside a read-only transaction and hands it a Querier. A
// read-only transaction gives fn a consistent snapshot across multiple
// statements while the database rejects any write attempt, so Read can never
// be used to smuggle a mutation past Write. Use Write for anything that
// mutates state.
func (s *Store) Read(ctx context.Context, fn func(context.Context, Querier) error) error {
	pgtx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	defer func() {
		// A read-only transaction is always rolled back: there is nothing to
		// commit. context.WithoutCancel ensures the connection is released back
		// to the pool even when the caller's context is already cancelled.
		_ = pgtx.Rollback(context.WithoutCancel(ctx))
	}()
	return fn(ctx, readQuerier{q: pgtx, store: s})
}

type readQuerier struct {
	q     pgx.Tx
	store *Store
}

func (q readQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	start := time.Now()
	tag, err := q.q.Exec(ctx, sql, args...)
	q.store.observeQuery(ctx, "read", sql, time.Since(start), err)
	return tag, err
}

func (q readQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	start := time.Now()
	rows, err := q.q.Query(ctx, sql, args...)
	q.store.observeQuery(ctx, "read", sql, time.Since(start), err)
	return rows, err
}

func (q readQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	start := time.Now()
	return slowQueryRow{
		row:       q.q.QueryRow(ctx, sql, args...),
		ctx:       ctx,
		store:     q.store,
		operation: "read",
		sql:       sql,
		start:     start,
	}
}

type slowQueryRow struct {
	row       pgx.Row
	ctx       context.Context
	store     *Store
	operation string
	sql       string
	start     time.Time
}

func (r slowQueryRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	r.store.observeQuery(r.ctx, r.operation, r.sql, time.Since(r.start), err)
	return err
}

func (s *Store) observeQuery(ctx context.Context, operation, sql string, elapsed time.Duration, err error) {
	if s == nil || s.slowQueryThreshold <= 0 || elapsed < s.slowQueryThreshold {
		return
	}
	queryKind := queryKind(sql)
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	if s.slowQueryMetrics != nil {
		s.slowQueryMetrics.RecordSlowQuery(ctx, telemetry.SlowQueryObservation{
			Operation: operation,
			QueryKind: queryKind,
			Outcome:   outcome,
			Duration:  elapsed,
			Threshold: s.slowQueryThreshold,
		})
	}

	attrs := []any{
		slog.String("operation", operation),
		slog.String("query_kind", queryKind),
		slog.String("outcome", outcome),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
		slog.Int64("threshold_ms", s.slowQueryThreshold.Milliseconds()),
	}
	attrs = append(attrs, telemetry.LogHintAttrs(ctx)...)
	s.logger.WarnContext(ctx, "store slow query observed", attrs...)
}

func queryKind(sql string) string {
	sql = strings.TrimSpace(sql)
	for strings.HasPrefix(sql, "--") {
		if i := strings.IndexByte(sql, '\n'); i >= 0 {
			sql = strings.TrimSpace(sql[i+1:])
			continue
		}
		return "other"
	}
	if strings.HasPrefix(sql, "/*") {
		if i := strings.Index(sql, "*/"); i >= 0 {
			sql = strings.TrimSpace(sql[i+2:])
		}
	}
	fields := strings.Fields(sql)
	if len(fields) == 0 {
		return "unknown"
	}
	switch strings.ToLower(fields[0]) {
	case "select", "insert", "update", "delete", "with", "begin", "commit", "rollback":
		return strings.ToLower(fields[0])
	default:
		return "other"
	}
}

// isConstraintViolation reports whether err is a Postgres integrity-constraint
// violation — SQLSTATE class 23, which covers foreign-key, unique, check, and
// not-null failures uniformly.
func isConstraintViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && len(pgErr.Code) >= 2 && pgErr.Code[:2] == "23"
}

// mapWriteError converts a raw driver error from a mutation into the backend
// error taxonomy. A constraint violation is a Conflict — the request collides
// with existing state — carrying the caller-supplied, non-sensitive
// conflictMessage. Anything else is treated as a transient datastore failure.
// In both cases the raw driver error, which may name columns, constraints,
// connection strings, or host details, is preserved only as the wrapped cause
// for server-side logging and never reaches the user-facing Message.
func mapWriteError(err error, conflictMessage string) error {
	if err == nil {
		return nil
	}
	if isConstraintViolation(err) {
		return apierr.Conflict(conflictMessage).Wrap(err)
	}
	return apierr.StoreUnavailable(err)
}
