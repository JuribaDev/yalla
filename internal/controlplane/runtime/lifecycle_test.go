package runtime

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestReadinessStartsUnreadyAndTransitions(t *testing.T) {
	t.Parallel()

	r := NewReadiness("migrations", "database")
	if r.Ready() {
		t.Fatal("readiness with pending gates must start unready")
	}
	if got := r.PendingGates(); len(got) != 2 {
		t.Fatalf("pending gates = %v, want 2", got)
	}

	r.MarkReady("migrations")
	if r.Ready() {
		t.Fatal("readiness must stay unready while a gate is pending")
	}
	if got := r.PendingGates(); len(got) != 1 || got[0] != "database" {
		t.Fatalf("pending gates = %v, want [database]", got)
	}

	r.MarkReady("database")
	if !r.Ready() {
		t.Fatal("readiness must report ready once every gate passes")
	}
	if got := r.PendingGates(); len(got) != 0 {
		t.Fatalf("pending gates = %v, want empty", got)
	}

	// A gate can fail again (e.g. a dependency health check flips).
	r.Set("database", false)
	if r.Ready() {
		t.Fatal("readiness must report unready when a gate regresses")
	}
}

func TestReadinessWithNoGatesIsImmediatelyReady(t *testing.T) {
	t.Parallel()

	r := NewReadiness()
	if !r.Ready() {
		t.Fatal("readiness with no gates must be immediately ready")
	}
}

func TestReadinessSnapshotIsACopy(t *testing.T) {
	t.Parallel()

	r := NewReadiness("migrations")
	snap := r.Snapshot()
	snap["migrations"] = true
	if r.Ready() {
		t.Fatal("mutating a snapshot must not affect the Readiness state")
	}
}

// fakeServer is a controllable httpServer for lifecycle tests. It never binds
// a real socket.
type fakeServer struct {
	listenErr    error         // immediate ListenAndServe failure when set
	serveBlock   chan struct{} // ListenAndServe blocks here until closed
	shutdownHook func(context.Context) error
	once         sync.Once
}

func newFakeServer() *fakeServer {
	return &fakeServer{serveBlock: make(chan struct{})}
}

func (f *fakeServer) ListenAndServe() error {
	if f.listenErr != nil {
		return f.listenErr
	}
	<-f.serveBlock
	// A real *http.Server returns http.ErrServerClosed once Shutdown drains
	// it; RunHTTPServer must treat that sentinel as a clean stop.
	return http.ErrServerClosed
}

func (f *fakeServer) Shutdown(ctx context.Context) error {
	var err error
	if f.shutdownHook != nil {
		err = f.shutdownHook(ctx)
	}
	f.once.Do(func() { close(f.serveBlock) })
	return err
}

func TestRunHTTPServerGracefulShutdownOnCancel(t *testing.T) {
	t.Parallel()

	srv := newFakeServer()
	srv.shutdownHook = func(ctx context.Context) error {
		// Drains quickly, well within the bound.
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunHTTPServer(ctx, srv, time.Second, nil) }()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunHTTPServer returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunHTTPServer did not return after cancellation")
	}
}

func TestRunHTTPServerHonoursShutdownTimeout(t *testing.T) {
	t.Parallel()

	srv := newFakeServer()
	// Shutdown drains forever; only the bounded context can stop it.
	srv.shutdownHook = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- RunHTTPServer(ctx, srv, 50*time.Millisecond, nil) }()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RunHTTPServer returned %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("shutdown took %s, want bounded near 50ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunHTTPServer ignored the shutdown timeout bound")
	}
}

func TestRunHTTPServerReturnsServeError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("listen tcp :8080: bind: address already in use")
	srv := newFakeServer()
	srv.listenErr = wantErr

	err := RunHTTPServer(context.Background(), srv, time.Second, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunHTTPServer returned %v, want %v", err, wantErr)
	}
}
