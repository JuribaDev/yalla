// Package fakepg provides a deterministic, in-memory TCP test double for
// Postgres-disconnect chaos testing.
//
// Postgres is the only source of truth for tenants, ownership, quota, audit,
// and provisioning state. Every store call (Pool.Ping, Pool.Acquire,
// Pool.Begin, Pool.Exec, Pool.Query) speaks the Postgres wire protocol over a
// TCP socket. Exercising the store layer's classification contract under
// sustained connection-drop chaos against a live Postgres would be slow,
// flaky, and require a real Postgres instance in CI. The chaos suite under
// internal/controlplane/store/chaos_postgres_disconnects_test.go runs against
// this fake instead so the gate stays green and fast on every developer
// machine.
//
// # Disconnect chaos
//
// QueueFault arms a FIFO queue of DisconnectFault entries. Each incoming TCP
// connection consumes the next queued fault; a DisconnectFault closes the
// accepted socket immediately so pgx sees EOF during its startup handshake
// and surfaces a typed transport error. The fake never speaks the Postgres
// wire protocol — it only proves the network endpoint is reachable, accept
// the connection, and drop it. That is the load-bearing behaviour the
// store-layer classification chokepoint MUST handle.
//
// # Redaction
//
// The fake never stores, logs, or echoes anything from the connecting
// client; it only counts accepted connections via AcceptedConnections so
// the chaos harness can assert pgx made exactly N attempts. Credentials in
// the caller's DSN never reach the fake's address space — pgx fails before
// authentication. The chaos harness asserts no DSN password literal leaks
// at any level of the wrapped cause chain returned from pgx.
package fakepg

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// FaultKind selects which kind of network failure an injected Fault produces.
type FaultKind int

const (
	// FaultDisconnect closes the accepted TCP connection immediately so
	// pgx observes EOF during its startup handshake. This is the
	// canonical Postgres-disconnect chaos primitive: it forces pgx to
	// fail its connect attempt without speaking the wire protocol.
	FaultDisconnect FaultKind = iota
)

// Fault describes a single injected failure. Construct one with
// DisconnectFault rather than building it directly.
type Fault struct {
	Kind FaultKind
}

// DisconnectFault builds a Fault that closes the next accepted TCP
// connection immediately. pgx will return a typed transport error when
// the startup handshake reads EOF.
func DisconnectFault() Fault {
	return Fault{Kind: FaultDisconnect}
}

// Server is a deterministic, in-memory TCP test double for a Postgres
// endpoint under chaos. The zero value is not usable; construct one with New.
// A Server is safe for concurrent use: every field is guarded by mu.
type Server struct {
	listener net.Listener
	wg       sync.WaitGroup

	mu       sync.Mutex
	faults   []Fault
	accepted int
	closed   bool
}

// New starts a Server listening on a free 127.0.0.1 port and registers a
// t.Cleanup that closes the listener. The Server's serve loop accepts
// connections, pops the next queued fault, and applies it. If no fault is
// queued, the connection is closed immediately (the default behaviour is a
// disconnect — the fake never speaks Postgres protocol).
func New(t testing.TB) *Server {
	t.Helper()
	s, err := NewServer()
	if err != nil {
		t.Fatalf("fakepg: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

// NewServer starts a Server listening on a free 127.0.0.1 port without
// requiring a testing.TB. The caller is responsible for Close. Use this
// from worker goroutines inside chaos harnesses where the testing.TB
// is owned by the parent goroutine.
func NewServer() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on 127.0.0.1:0: %w", err)
	}
	s := &Server{listener: ln}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr returns the host:port the server is listening on. The value is
// suitable for embedding in a pgx DSN.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Host returns the dotted-decimal host the server is listening on.
func (s *Server) Host() string {
	if tcp, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return "127.0.0.1"
}

// Port returns the TCP port the server is listening on.
func (s *Server) Port() int {
	if tcp, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

// QueueFault appends a fault to the FIFO queue. The next accepted
// connection will consume and apply it.
func (s *Server) QueueFault(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, f)
}

// AcceptedConnections returns the number of TCP connections the fake has
// accepted since construction. The chaos harness uses this to assert pgx
// made exactly N connect attempts per scenario.
func (s *Server) AcceptedConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Close stops the listener and waits for the serve loop to exit. Safe to
// call more than once. New registers Close via t.Cleanup so tests do not
// need to call it directly.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed; exit loop.
			return
		}
		s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	s.mu.Lock()
	s.accepted++
	var fault Fault
	if len(s.faults) > 0 {
		fault = s.faults[0]
		s.faults = s.faults[1:]
	} else {
		// Default behaviour is a disconnect — the fake never speaks
		// the Postgres wire protocol. A caller that forgets to queue a
		// fault still observes deterministic chaos.
		fault = DisconnectFault()
	}
	s.mu.Unlock()

	switch fault.Kind {
	case FaultDisconnect:
		// Close gracefully (FIN, not RST). The dial completes
		// successfully — the kernel reports the TCP handshake done —
		// and pgx then observes EOF when it tries to read the
		// expected Postgres startup-response bytes. A RST close
		// (SetLinger(0)) races the dial on some kernels and surfaces
		// as `connection reset by peer` on connect, which would still
		// satisfy the chaos contract but breaks the "dial succeeds,
		// handshake fails" property the chaos suite asserts on.
		_ = conn.Close()
	default:
		_ = conn.Close()
	}
}
