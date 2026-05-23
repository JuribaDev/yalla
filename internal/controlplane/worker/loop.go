// Package worker executes background provisioning and metering jobs.
//
// The worker's run loop is intentionally separated from the durable job
// store: Loop depends only on the Claimer and Lease interfaces, so the
// Postgres-backed implementation can land with the persistence stories
// while the lifecycle behaviour — claim, process, and a clean shutdown that
// stops claiming new work and releases in-flight leases — is testable now
// with fakes.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Lease represents a single unit of work claimed by exactly one worker. The
// durable job store hands out leases; the worker is responsible for either
// running them to completion or releasing them back so they are not lost.
type Lease interface {
	// Run executes the leased job to completion. A nil return means the job
	// finished and the Lease implementation has committed that outcome; the
	// worker must not release it afterwards. A non-nil return means the job
	// did not complete.
	Run(ctx context.Context) error
	// Release returns an unfinished job to the queue so another worker — or
	// a later run of this one — can pick it up. It is given a context that
	// is independent of shutdown cancellation so the release can always
	// complete even though the process is stopping.
	Release(ctx context.Context) error
}

// Claimer leases jobs from the durable queue.
type Claimer interface {
	// Claim leases the next available job. It returns (nil, nil) when the
	// queue is empty. It must return promptly when ctx is cancelled.
	Claim(ctx context.Context) (Lease, error)
}

// NoopClaimer is a Claimer that never returns work. It is the placeholder the
// worker binary uses until the Postgres-backed job store is implemented:
// with it, the worker starts, idles, and shuts down cleanly without any
// durable queue wired up.
type NoopClaimer struct{}

// Claim always reports an empty queue.
func (NoopClaimer) Claim(context.Context) (Lease, error) { return nil, nil }

// Default loop timings. They are deliberately conservative; callers can
// override them per Loop.
const (
	defaultIdleDelay      = time.Second
	defaultReleaseTimeout = 10 * time.Second
)

// Loop is the worker's run loop. It repeatedly claims and processes jobs
// until its context is cancelled, at which point it stops claiming new work
// and ensures any in-flight lease is released rather than lost.
type Loop struct {
	// Claimer leases jobs. Required.
	Claimer Claimer
	// Logger receives structured diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
	// IdleDelay is how long the loop waits before polling again when the
	// queue is empty or a claim failed. Defaults to defaultIdleDelay.
	IdleDelay time.Duration
	// ReleaseTimeout bounds how long releasing an interrupted in-flight
	// lease may take during shutdown. Defaults to defaultReleaseTimeout.
	ReleaseTimeout time.Duration
}

// Run drives the loop until ctx is cancelled. It always returns nil today —
// shutdown is a normal, expected outcome — but keeps an error return so
// future fatal conditions (e.g. an unrecoverable store failure) have a
// channel without a breaking signature change.
func (l *Loop) Run(ctx context.Context) error {
	logger := l.logger()
	idleDelay := l.IdleDelay
	if idleDelay <= 0 {
		idleDelay = defaultIdleDelay
	}

	logger.Info("worker loop started")
	for {
		// Stop claiming new work as soon as shutdown begins. Checking here,
		// before every Claim, is what guarantees the worker never picks up
		// a job it cannot finish during the shutdown window.
		if ctx.Err() != nil {
			logger.Info("worker loop stopped claiming jobs", "reason", ctx.Err().Error())
			return nil
		}

		lease, err := l.Claimer.Claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				logger.Info("worker loop stopped claiming jobs", "reason", ctx.Err().Error())
				return nil
			}
			logger.Error("claim job failed", "error", err)
			if !wait(ctx, idleDelay) {
				return nil
			}
			continue
		}

		if lease == nil {
			// Queue is empty; back off briefly so we do not busy-poll.
			if !wait(ctx, idleDelay) {
				return nil
			}
			continue
		}

		l.handle(ctx, lease)
	}
}

// handle runs a single leased job. If the job does not complete and shutdown
// is in progress, the lease is released so the job is retried by another
// worker instead of being silently dropped.
func (l *Loop) handle(ctx context.Context, lease Lease) {
	logger := l.logger()

	runErr := lease.Run(ctx)
	if runErr == nil {
		// The job completed; the Lease implementation has committed it.
		return
	}

	interrupted := ctx.Err() != nil ||
		errors.Is(runErr, context.Canceled) ||
		errors.Is(runErr, context.DeadlineExceeded)
	if !interrupted {
		// A genuine job failure (not a shutdown). Retry/dead-letter handling
		// lands with the durable job store; for now, surface it.
		logger.Error("job failed", "error", runErr)
		return
	}

	// Shutdown interrupted an in-flight job. Release the lease on a context
	// that is independent of the cancelled shutdown context so the release
	// itself always gets a chance to complete.
	releaseTimeout := l.ReleaseTimeout
	if releaseTimeout <= 0 {
		releaseTimeout = defaultReleaseTimeout
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()

	if err := lease.Release(releaseCtx); err != nil {
		logger.Error("release in-flight lease during shutdown failed", "error", err)
		return
	}
	logger.Info("released in-flight lease for shutdown; job will be retried")
}

func (l *Loop) logger() *slog.Logger {
	if l.Logger != nil {
		return l.Logger
	}
	return slog.Default()
}

// wait sleeps for d or until ctx is cancelled. It returns false when ctx was
// cancelled (the caller should stop) and true when the full delay elapsed.
func wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
