package worker_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/worker"
)

// claimerFunc adapts a function to the Claimer interface.
type claimerFunc func(ctx context.Context) (worker.Lease, error)

func (f claimerFunc) Claim(ctx context.Context) (worker.Lease, error) { return f(ctx) }

// fakeLease is a controllable Lease for loop tests.
type fakeLease struct {
	run        func(ctx context.Context) error
	releaseErr error
	released   atomic.Bool
}

func (l *fakeLease) Run(ctx context.Context) error {
	if l.run != nil {
		return l.run(ctx)
	}
	return nil
}

func (l *fakeLease) Release(context.Context) error {
	l.released.Store(true)
	return l.releaseErr
}

func TestLoopProcessesJobsThenStopsClaimingOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var claims, processed atomic.Int64
	claimer := claimerFunc(func(context.Context) (worker.Lease, error) {
		claims.Add(1)
		return &fakeLease{run: func(context.Context) error {
			if processed.Add(1) == 3 {
				// Begin shutdown after the third job completes.
				cancel()
			}
			return nil
		}}, nil
	})

	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	if got := processed.Load(); got != 3 {
		t.Errorf("processed = %d, want 3", got)
	}
	// The loop checks ctx before each Claim, so it must not claim a fourth
	// job after the third one triggered shutdown.
	if got := claims.Load(); got != 3 {
		t.Errorf("claims = %d, want 3 (no claim after shutdown began)", got)
	}
}

func TestLoopReleasesInFlightLeaseOnShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lease := &fakeLease{run: func(runCtx context.Context) error {
		// Simulate an in-flight job interrupted by shutdown.
		<-runCtx.Done()
		return runCtx.Err()
	}}

	var claims atomic.Int64
	claimer := claimerFunc(func(context.Context) (worker.Lease, error) {
		if claims.Add(1) == 1 {
			return lease, nil
		}
		return nil, nil
	})

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	if !lease.released.Load() {
		t.Error("in-flight lease was not released on shutdown; the job would be lost")
	}
}

func TestLoopDoesNotReleaseCompletedJobOnShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The job completes successfully at the same moment shutdown begins.
	lease := &fakeLease{run: func(context.Context) error {
		cancel()
		return nil
	}}

	var claims atomic.Int64
	claimer := claimerFunc(func(context.Context) (worker.Lease, error) {
		if claims.Add(1) == 1 {
			return lease, nil
		}
		return nil, nil
	})

	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	if lease.released.Load() {
		t.Error("a completed job was released; it could be run twice")
	}
}

func TestLoopRetriesAfterClaimError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var claims atomic.Int64
	claimer := claimerFunc(func(context.Context) (worker.Lease, error) {
		switch claims.Add(1) {
		case 1:
			return nil, errors.New("transient store error")
		default:
			cancel() // recover, then stop the test
			return nil, nil
		}
	})

	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if got := claims.Load(); got < 2 {
		t.Errorf("claims = %d, want the loop to retry after a claim error", got)
	}
}

func TestLoopWithNoopClaimerShutsDownCleanly(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	loop := &worker.Loop{Claimer: worker.NoopClaimer{}, IdleDelay: time.Millisecond}

	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
