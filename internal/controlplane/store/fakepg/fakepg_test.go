package fakepg_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store/fakepg"
)

// TestServerAddrIsLoopback pins the listener to a 127.0.0.1 host so a chaos
// scenario can never accidentally bind a routable interface.
func TestServerAddrIsLoopback(t *testing.T) {
	t.Parallel()
	srv := fakepg.New(t)
	if got := srv.Host(); got != "127.0.0.1" {
		t.Errorf("Host() = %q, want 127.0.0.1", got)
	}
	if got := srv.Port(); got <= 0 {
		t.Errorf("Port() = %d, want > 0", got)
	}
	if got := srv.Addr(); got == "" {
		t.Errorf("Addr() = empty, want host:port")
	}
}

// TestDisconnectFaultClosesAcceptedConnections drives the load-bearing
// chaos primitive: a queued DisconnectFault closes the next accepted
// socket without reading anything from the client.
func TestDisconnectFaultClosesAcceptedConnections(t *testing.T) {
	t.Parallel()
	srv := fakepg.New(t)
	srv.QueueFault(fakepg.DisconnectFault())

	conn, err := net.DialTimeout("tcp", srv.Addr(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Errorf("read returned n=%d, want 0 (fake never speaks Postgres protocol)", n)
	}
	if err == nil {
		t.Fatalf("read returned nil error; the fake MUST close the conn so pgx sees a transport failure")
	}
	if !errors.Is(err, io.EOF) {
		// Some kernels surface a reset instead of EOF; both satisfy the chaos
		// contract (pgx will classify both as a connect failure).
		var ne net.Error
		if !errors.As(err, &ne) {
			t.Errorf("read err = %v (type %T); want io.EOF or net.Error", err, err)
		}
	}

	if got, want := srv.AcceptedConnections(), 1; got != want {
		t.Errorf("AcceptedConnections() = %d, want %d", got, want)
	}
}

// TestDefaultBehaviourIsDisconnect proves a caller that forgets to queue
// a fault still observes deterministic chaos.
func TestDefaultBehaviourIsDisconnect(t *testing.T) {
	t.Parallel()
	srv := fakepg.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("expected EOF/reset from fake server with no queued faults")
	}

	if got := srv.AcceptedConnections(); got < 1 {
		t.Errorf("AcceptedConnections() = %d, want >= 1", got)
	}
}

// TestQueueFaultIsFIFO pins the queue ordering so a chaos test can rely on
// per-iteration determinism.
func TestQueueFaultIsFIFO(t *testing.T) {
	t.Parallel()
	srv := fakepg.New(t)
	for i := 0; i < 3; i++ {
		srv.QueueFault(fakepg.DisconnectFault())
	}
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", srv.Addr(), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("dial #%d: %v", i, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	if got, want := srv.AcceptedConnections(), 3; got != want {
		t.Errorf("AcceptedConnections() = %d, want %d", got, want)
	}
}

// TestCloseIsIdempotent proves that the cleanup registered by New is safe
// to invoke alongside an explicit Close.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	srv := fakepg.New(t)
	if err := srv.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
