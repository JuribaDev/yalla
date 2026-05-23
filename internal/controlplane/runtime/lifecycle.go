package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ReadinessReporter exposes whether a backend process is ready to serve
// traffic. The HTTP API's /readyz handler depends on this interface so the
// load balancer only routes requests once startup dependencies (migrations,
// database connectivity, and similar checks) have passed.
type ReadinessReporter interface {
	// Ready reports whether every registered gate has passed.
	Ready() bool
	// Snapshot returns a copy of each gate's current state, keyed by gate
	// name, so operators and the /readyz payload can see which dependency
	// is still failing.
	Snapshot() map[string]bool
}

// Readiness tracks a fixed set of named startup gates. A process is ready
// only once every gate it registered has been marked passing. It starts
// unready: a freshly constructed Readiness with one or more gates reports
// Ready() == false until each gate is explicitly set.
//
// Readiness is safe for concurrent use: the HTTP /readyz handler reads it
// while startup goroutines flip gates.
type Readiness struct {
	mu    sync.RWMutex
	gates map[string]bool
}

// NewReadiness registers the supplied gate names, all starting unready.
// Passing no gates yields a Readiness that is immediately ready, which is
// the correct behaviour for a process with no startup dependencies.
func NewReadiness(gates ...string) *Readiness {
	r := &Readiness{gates: make(map[string]bool, len(gates))}
	for _, g := range gates {
		r.gates[g] = false
	}
	return r
}

// Set records whether the named gate is passing. Setting a gate that was not
// registered at construction adds it, so a process can register dependencies
// it discovers at runtime.
func (r *Readiness) Set(gate string, passing bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gates[gate] = passing
}

// MarkReady is shorthand for Set(gate, true).
func (r *Readiness) MarkReady(gate string) { r.Set(gate, true) }

// Ready reports whether every registered gate is passing.
func (r *Readiness) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, passing := range r.gates {
		if !passing {
			return false
		}
	}
	return true
}

// Snapshot returns a copy of the current gate states. The returned map is
// owned by the caller and never mutated by Readiness.
func (r *Readiness) Snapshot() map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]bool, len(r.gates))
	for gate, passing := range r.gates {
		out[gate] = passing
	}
	return out
}

// PendingGates returns the sorted names of every gate that is not yet
// passing. It is useful for logging which dependency is blocking readiness.
func (r *Readiness) PendingGates() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pending := make([]string, 0, len(r.gates))
	for gate, passing := range r.gates {
		if !passing {
			pending = append(pending, gate)
		}
	}
	sort.Strings(pending)
	return pending
}

// httpServer is the subset of *http.Server that RunHTTPServer needs. Keeping
// it an interface lets tests drive the lifecycle with a fake server without
// binding a real socket.
type httpServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
}

// RunHTTPServer runs srv until ctx is cancelled, then performs a graceful
// shutdown bounded by shutdownTimeout. It returns nil on a clean shutdown.
//
// Lifecycle:
//   - ListenAndServe runs in a goroutine. If it fails before ctx is
//     cancelled (for example, the listen address is already in use), that
//     error is returned immediately.
//   - When ctx is cancelled, Shutdown is called with a fresh context bounded
//     by shutdownTimeout so a wedged in-flight request cannot block process
//     exit forever. If draining exceeds the bound, Shutdown's
//     context.DeadlineExceeded is returned so the caller can exit non-zero.
//   - http.ErrServerClosed is treated as success: it is the expected result
//     of a graceful Shutdown.
func RunHTTPServer(ctx context.Context, srv httpServer, shutdownTimeout time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	serveErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		// The server stopped on its own before a shutdown signal arrived.
		return err
	case <-ctx.Done():
		logger.Info("http server shutdown signal received, draining in-flight requests",
			"shutdown_timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http server graceful shutdown failed", "error", err)
		return err
	}

	// Drain the serve goroutine so it cannot leak; ListenAndServe has
	// already returned (or is about to) once Shutdown completes.
	if err := <-serveErr; err != nil {
		return err
	}
	logger.Info("http server stopped cleanly")
	return nil
}
