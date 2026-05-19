package worker

// queue.go is the Postgres-backed implementation of the worker's Claimer and
// Lease interfaces. loop.go stays pure — it depends only on those interfaces —
// so the run-loop lifecycle remains testable with fakes; this file is where
// the durable job store, the SKIP LOCKED claim, retry classification, and
// bounded exponential backoff actually live.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Defaults for a StoreClaimer left partially configured. They are deliberately
// conservative; a caller can override every one.
const (
	defaultLeaseDuration   = 30 * time.Second
	defaultCompleteTimeout = 10 * time.Second
	defaultBackoffBase     = time.Second
	defaultBackoffMax      = 5 * time.Minute
)

// JobRunner executes the actual provisioning work for one claimed job. The
// Postgres-backed queue owns everything around the work — claiming, leasing,
// retry, backoff, dead-lettering — and the runner owns only "carry out this
// job". Real Dokploy provisioning lands in a later story; until then a runner
// is injected, and tests supply a fake one.
//
// A nil return means the job succeeded. A non-nil return is a failure: a plain
// error is treated as transient and retried with backoff until the retry
// budget is spent, while an error marked with Terminal is permanent and fails
// the job immediately.
type JobRunner interface {
	Run(ctx context.Context, job store.ProvisioningJob) error
}

// RunnerFunc adapts an ordinary function to the JobRunner interface.
type RunnerFunc func(ctx context.Context, job store.ProvisioningJob) error

// Run calls f.
func (f RunnerFunc) Run(ctx context.Context, job store.ProvisioningJob) error {
	return f(ctx, job)
}

// terminalError marks a job failure as permanent so the queue records it as
// failed and never retries it.
type terminalError struct{ err error }

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// Terminal marks err as a permanent job failure. A job that fails with a
// Terminal error is recorded as failed straight away and never retried — use
// it for failures that retrying cannot fix: an invalid desired state, a
// rejected request, a permanent dependency error. A plain (non-Terminal) error
// is treated as transient and retried with bounded exponential backoff until
// the retry budget is spent. Terminal(nil) returns nil.
func Terminal(err error) error {
	if err == nil {
		return nil
	}
	return &terminalError{err: err}
}

// IsTerminal reports whether err — or any error it wraps — was marked Terminal.
func IsTerminal(err error) bool {
	var t *terminalError
	return errors.As(err, &t)
}

// Backoff computes a bounded exponential retry delay. Delay(attempt) grows as
// Base * 2^(attempt-1), capped at Max. With Jitter set, the delay is spread
// uniformly across [Base, computed] so a fleet of workers that failed together
// does not retry in lockstep.
type Backoff struct {
	// Base is the delay before the first retry. A non-positive value defaults
	// to defaultBackoffBase.
	Base time.Duration
	// Max is the ceiling for any retry delay. A non-positive value defaults to
	// defaultBackoffMax; a value below Base is raised to Base.
	Max time.Duration
	// Jitter randomises the delay within [Base, computed] when true.
	Jitter bool
}

// Delay returns the retry delay for the given attempt number (1 = the first
// retry). attempt values below 1 are treated as 1.
func (b Backoff) Delay(attempt int) time.Duration {
	baseDelay := b.Base
	if baseDelay <= 0 {
		baseDelay = defaultBackoffBase
	}
	maxDelay := b.Max
	if maxDelay <= 0 {
		maxDelay = defaultBackoffMax
	}
	if maxDelay < baseDelay {
		maxDelay = baseDelay
	}
	if attempt < 1 {
		attempt = 1
	}

	// base * 2^(attempt-1), computed by doubling so a large attempt count can
	// never overflow into a negative duration: the cap is applied the instant
	// the delay reaches or would exceed it.
	delay := baseDelay
	for i := 1; i < attempt; i++ {
		if delay >= maxDelay {
			delay = maxDelay
			break
		}
		delay *= 2
		if delay <= 0 { // overflow guard
			delay = maxDelay
			break
		}
	}
	if delay > maxDelay {
		delay = maxDelay
	}

	if b.Jitter {
		// Full jitter: a uniform point in [Base, delay]. A retry is therefore
		// never effectively immediate, and the upper bound is still the
		// computed exponential delay.
		jittered := baseDelay + time.Duration(randFloat()*float64(delay-baseDelay))
		if jittered < baseDelay {
			jittered = baseDelay
		}
		if jittered > delay {
			jittered = delay
		}
		delay = jittered
	}
	return delay
}

// randFloat returns a uniform random float64 in [0, 1). It draws from
// crypto/rand so retry jitter needs no seeded PRNG; on the (practically
// impossible) read failure it falls back to the midpoint.
func randFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// StoreClaimerConfig configures a StoreClaimer. Store, Runner, and Owner are
// required; everything else has a safe default.
type StoreClaimerConfig struct {
	// Store is the Postgres-backed control-plane store. Required.
	Store *store.Store
	// Jobs is the provisioning-job repository. A nil value defaults to a fresh
	// store.NewJobRepository().
	Jobs *store.JobRepository
	// Runner carries out the work for each claimed job. Required.
	Runner JobRunner
	// Owner identifies this worker as the lease holder. It must be unique per
	// worker process so a lease is always attributable to exactly one worker;
	// NewOwnerID mints a suitable value. Required.
	Owner string
	// LeaseDuration is how long a claim holds the lease before it becomes
	// reclaimable. A non-positive value defaults to defaultLeaseDuration.
	LeaseDuration time.Duration
	// CompleteTimeout bounds the write that records a job's outcome. A
	// non-positive value defaults to defaultCompleteTimeout.
	CompleteTimeout time.Duration
	// Backoff governs transient-failure retry delays. The zero value is valid
	// and uses the package defaults.
	Backoff Backoff
	// Logger receives structured diagnostics. A nil value defaults to
	// slog.Default().
	Logger *slog.Logger
	// Now is an injectable clock; tests set it for determinism. A nil value
	// defaults to time.Now().UTC.
	Now func() time.Time
}

// StoreClaimer is a Postgres-backed worker.Claimer. Each Claim leases the next
// eligible provisioning job with SELECT ... FOR UPDATE SKIP LOCKED, so any
// number of StoreClaimers — in one process or many — can poll the same queue
// and a job is still run by exactly one worker at a time.
type StoreClaimer struct {
	store           *store.Store
	jobs            *store.JobRepository
	runner          JobRunner
	owner           string
	leaseDuration   time.Duration
	completeTimeout time.Duration
	backoff         Backoff
	logger          *slog.Logger
	now             func() time.Time
}

// NewStoreClaimer validates cfg, applies defaults, and returns a ready
// StoreClaimer. A missing Store, Runner, or Owner is reported as an
// InvalidInput error carrying the offending field.
func NewStoreClaimer(cfg StoreClaimerConfig) (*StoreClaimer, error) {
	var violations []apierr.FieldViolation
	if cfg.Store == nil {
		violations = append(violations, apierr.FieldViolation{Field: "store", Reason: "is required"})
	}
	if cfg.Runner == nil {
		violations = append(violations, apierr.FieldViolation{Field: "runner", Reason: "is required"})
	}
	if cfg.Owner == "" {
		violations = append(violations, apierr.FieldViolation{Field: "owner", Reason: "is required"})
	}
	if len(violations) > 0 {
		return nil, apierr.InvalidInput(violations...)
	}

	jobs := cfg.Jobs
	if jobs == nil {
		jobs = store.NewJobRepository()
	}
	leaseDuration := cfg.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultLeaseDuration
	}
	completeTimeout := cfg.CompleteTimeout
	if completeTimeout <= 0 {
		completeTimeout = defaultCompleteTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Now
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}

	return &StoreClaimer{
		store:           cfg.Store,
		jobs:            jobs,
		runner:          cfg.Runner,
		owner:           cfg.Owner,
		leaseDuration:   leaseDuration,
		completeTimeout: completeTimeout,
		backoff:         cfg.Backoff,
		logger:          logger,
		now:             clock,
	}, nil
}

// Claim leases the next eligible provisioning job and returns it as a Lease.
// It returns (nil, nil) when the queue holds nothing eligible — the empty-queue
// signal the run loop backs off on.
func (c *StoreClaimer) Claim(ctx context.Context) (Lease, error) {
	var (
		job   store.ProvisioningJob
		found bool
	)
	if err := c.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		claimed, ok, err := c.jobs.ClaimNext(ctx, tx, c.owner, c.leaseDuration, c.now())
		if err != nil {
			return err
		}
		job, found = claimed, ok
		return nil
	}); err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	c.logger.InfoContext(ctx, "claimed provisioning job",
		"job_id", job.ID, "job_type", job.JobType, "organization_id", job.OrganizationID,
		"attempt", job.Attempts, "max_attempts", job.MaxAttempts,
		"request_id", job.RequestID, "correlation_id", job.CorrelationID)
	return &storeLease{claimer: c, job: job}, nil
}

// storeLease is a single claimed provisioning job. Run executes it through the
// runner and records the outcome; Release returns an unfinished job to the
// queue when shutdown interrupts it.
type storeLease struct {
	claimer *StoreClaimer
	job     store.ProvisioningJob
}

// Run executes the leased job and records its outcome. It returns nil once an
// outcome — success, scheduled retry, permanent failure, or dead-letter — has
// been committed; the worker must not release the lease afterwards. It returns
// a non-nil error only when shutdown interrupted the job before it finished, so
// the run loop releases the lease and another worker reclaims it.
func (l *storeLease) Run(ctx context.Context) error {
	c := l.claimer
	runErr := c.runner.Run(ctx, l.job)
	if runErr == nil {
		if err := c.complete(ctx, l.job, store.JobStatusSucceeded, store.JobTransition{}); err != nil {
			c.logger.ErrorContext(ctx, "recording provisioning job success failed; the lease will expire and the job will be reclaimed",
				"job_id", l.job.ID, "error", err.Error())
			return err
		}
		c.logger.InfoContext(ctx, "provisioning job succeeded",
			"job_id", l.job.ID, "request_id", l.job.RequestID, "correlation_id", l.job.CorrelationID)
		return nil
	}

	// Shutdown interrupted the job before it finished. Leave the row untouched
	// and signal the loop to release the lease so the job is retried, not lost.
	if interrupted(ctx, runErr) {
		return runErr
	}

	return l.recordFailure(ctx, runErr)
}

// recordFailure classifies a genuine (non-interrupted) job failure and commits
// the matching transition: a Terminal failure fails the job immediately, a
// transient failure that has spent the retry budget is dead-lettered, and a
// transient failure with budget left is scheduled for a backed-off retry. The
// raw error string is handed to the store, which is the redaction chokepoint
// for job error summaries.
func (l *storeLease) recordFailure(ctx context.Context, runErr error) error {
	c := l.claimer

	if IsTerminal(runErr) {
		if err := c.complete(ctx, l.job, store.JobStatusFailed, store.JobTransition{
			ErrorSummary: runErr.Error(),
		}); err != nil {
			return err
		}
		c.logger.ErrorContext(ctx, "provisioning job failed permanently",
			"job_id", l.job.ID, "attempt", l.job.Attempts,
			"request_id", l.job.RequestID, "correlation_id", l.job.CorrelationID)
		return nil
	}

	if l.job.Attempts >= l.job.MaxAttempts {
		if err := c.complete(ctx, l.job, store.JobStatusDeadLetter, store.JobTransition{
			ErrorSummary: runErr.Error(),
		}); err != nil {
			return err
		}
		c.logger.ErrorContext(ctx, "provisioning job dead-lettered after exhausting its retry budget",
			"job_id", l.job.ID, "attempts", l.job.Attempts, "max_attempts", l.job.MaxAttempts,
			"request_id", l.job.RequestID, "correlation_id", l.job.CorrelationID)
		return nil
	}

	delay := c.backoff.Delay(l.job.Attempts)
	if err := c.complete(ctx, l.job, store.JobStatusRetrying, store.JobTransition{
		NextRunAt:    c.now().Add(delay),
		ErrorSummary: runErr.Error(),
	}); err != nil {
		return err
	}
	c.logger.WarnContext(ctx, "provisioning job failed; scheduled for retry",
		"job_id", l.job.ID, "attempt", l.job.Attempts, "retry_in", delay.String(),
		"request_id", l.job.RequestID, "correlation_id", l.job.CorrelationID)
	return nil
}

// Release returns an unfinished job to the queue, claimable immediately, after
// shutdown interrupted it. It is given a context independent of shutdown
// cancellation by the run loop, so the requeue always gets a chance to commit.
func (l *storeLease) Release(ctx context.Context) error {
	c := l.claimer
	if err := c.complete(ctx, l.job, store.JobStatusRetrying, store.JobTransition{
		NextRunAt:    c.now(),
		ErrorSummary: "worker shut down before the job finished; released for retry",
	}); err != nil {
		c.logger.ErrorContext(ctx, "releasing in-flight lease failed; the lease will expire and the job will be reclaimed",
			"job_id", l.job.ID, "error", err.Error())
		return err
	}
	c.logger.InfoContext(ctx, "released in-flight provisioning job for retry",
		"job_id", l.job.ID, "request_id", l.job.RequestID, "correlation_id", l.job.CorrelationID)
	return nil
}

// complete records a job's outcome transition. The runner has already done (or
// definitively failed) the work, so the write must reach the database even if
// shutdown has started: it runs on a context detached from cancellation and
// bounded by completeTimeout. The transition clock is pinned to c.now() so the
// store's bookkeeping matches the claimer's clock under test.
func (c *StoreClaimer) complete(ctx context.Context, job store.ProvisioningJob, to store.JobStatus, mut store.JobTransition) error {
	mut.Now = c.now()
	mut.ExpectedLeaseOwner = c.owner
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.completeTimeout)
	defer cancel()
	return c.store.Write(writeCtx, func(ctx context.Context, tx *store.Tx) error {
		_, err := c.jobs.Transition(ctx, tx, job.OrganizationID, job.ID, to, mut)
		return err
	})
}

// interrupted reports whether ctx was cancelled or err is a context
// cancellation/deadline error — i.e. the work stopped because the process is
// shutting down rather than because the job itself failed.
func interrupted(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// NewOwnerID returns a process-unique lease owner identifier. Every worker
// process must claim with a distinct owner so a lease is always attributable
// to exactly one worker.
func NewOwnerID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "worker-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("worker-%s-%s", host, hex.EncodeToString(b[:]))
}
