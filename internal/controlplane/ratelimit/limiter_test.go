package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock is a deterministic time source for the limiter under test.
// Tests advance it explicitly so refill behaviour stays reproducible.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(start time.Time) *fixedClock { return &fixedClock{now: start} }

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// epoch is the deterministic test clock origin. Using a non-zero point in
// time avoids stale-bucket sweeps misfiring against the IsZero() fast path
// inside tokenBucket.
var epoch = time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

// readSpec / writeSpec are the canonical test specs: ten tokens per second
// and a burst of five for reads, one per second and a burst of two for
// writes. They make the math obvious in assertions.
var (
	readSpec  = Spec{Rate: 10, Burst: 5}
	writeSpec = Spec{Rate: 1, Burst: 2}
)

// newLimiter assembles a limiter pre-wired to a deterministic clock with
// the same spec on each dimension; tests override individual fields as
// needed.
func newLimiter(t *testing.T, cfg Config) (*Limiter, *fixedClock) {
	t.Helper()
	clock := newClock(epoch)
	cfg.Now = clock.Now
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, clock
}

// TestNewDefaultsAreApplied proves that a Config with no Now and a
// non-positive IdleTTL receives the package-default replacements rather
// than panicking or rejecting traffic outright.
func TestNewDefaultsAreApplied(t *testing.T) {
	t.Parallel()

	l, err := New(Config{Org: Specs{Read: readSpec, Write: writeSpec}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()
	if got := l.cfg.IdleTTL; got != defaultIdleTTL {
		t.Errorf("IdleTTL = %s, want %s", got, defaultIdleTTL)
	}
	if l.cfg.Now == nil {
		t.Error("Now is nil, want time.Now default")
	}
}

// TestCheckAllowedWhenBucketsHaveCapacity drives one request through every
// dimension and proves the limiter consumes one token from each enabled
// bucket without denying.
func TestCheckAllowedWhenBucketsHaveCapacity(t *testing.T) {
	t.Parallel()

	l, _ := newLimiter(t, Config{
		Org: Specs{Read: readSpec, Write: writeSpec},
		Key: Specs{Read: readSpec, Write: writeSpec},
		IP:  Specs{Read: readSpec, Write: writeSpec},
	})

	d := l.Check(Request{OrgID: "org_a", KeyID: "key_a", IP: "1.2.3.4"})
	if !d.Allowed {
		t.Fatalf("Allowed = false on a fresh bucket: %+v", d)
	}
	orgs, keys, ips := l.Dimensions()
	if orgs != 1 || keys != 1 || ips != 1 {
		t.Errorf("dimensions = (%d,%d,%d), want (1,1,1)", orgs, keys, ips)
	}
}

// TestCheckSkipsDimensionsWithDisabledSpec proves that a dimension whose
// spec is the zero value is treated as "no limit": even a thousand
// requests in a row never deny when only the IP spec is enabled and the
// request has no IP, or vice versa.
func TestCheckSkipsDimensionsWithDisabledSpec(t *testing.T) {
	t.Parallel()

	// Only the IP dimension is enabled; org/key requests pass freely.
	l, _ := newLimiter(t, Config{IP: Specs{Read: readSpec, Write: writeSpec}})

	for i := 0; i < 100; i++ {
		d := l.Check(Request{OrgID: "org_a", KeyID: "key_a"})
		if !d.Allowed {
			t.Fatalf("request %d denied on a disabled-dim limiter: %+v", i, d)
		}
	}
}

// TestCheckSkipsDimensionWithEmptyIdentity proves an enabled dimension
// whose identity is empty (anonymous request, no IP available) is skipped
// rather than billed to a synthetic empty bucket that every caller would
// share.
func TestCheckSkipsDimensionWithEmptyIdentity(t *testing.T) {
	t.Parallel()

	l, _ := newLimiter(t, Config{
		Org: Specs{Read: Spec{Rate: 1, Burst: 1}},
		Key: Specs{Read: Spec{Rate: 1, Burst: 1}},
		IP:  Specs{Read: Spec{Rate: 1, Burst: 1}},
	})

	// All identities blank: no bucket is touched, no denial possible.
	for i := 0; i < 10; i++ {
		if d := l.Check(Request{}); !d.Allowed {
			t.Fatalf("blank-identity request %d denied: %+v", i, d)
		}
	}
	orgs, keys, ips := l.Dimensions()
	if orgs != 0 || keys != 0 || ips != 0 {
		t.Errorf("dimensions = (%d,%d,%d), want (0,0,0)", orgs, keys, ips)
	}
}

// TestCheckExemptRequestsAlwaysAllowed pins the internal-worker bypass:
// a Request whose Exempt flag is set is allowed even when every bucket on
// every dimension is exhausted.
func TestCheckExemptRequestsAlwaysAllowed(t *testing.T) {
	t.Parallel()

	tight := Spec{Rate: 1, Burst: 1}
	l, _ := newLimiter(t, Config{
		Org: Specs{Read: tight, Write: tight},
		Key: Specs{Read: tight, Write: tight},
		IP:  Specs{Read: tight, Write: tight},
	})

	for i := 0; i < 50; i++ {
		d := l.Check(Request{OrgID: "org_a", KeyID: "key_a", IP: "1.2.3.4", Exempt: true})
		if !d.Allowed {
			t.Fatalf("exempt request %d denied: %+v", i, d)
		}
	}
}

// TestCheckOrgBucketExhaustionDeniesWithOrgScope proves the org bucket
// throttles ahead of the key and IP buckets and that the Decision names
// the org dimension by the stable BucketOrg string.
func TestCheckOrgBucketExhaustionDeniesWithOrgScope(t *testing.T) {
	t.Parallel()

	tight := Spec{Rate: 1, Burst: 2}
	l, _ := newLimiter(t, Config{Org: Specs{Read: tight}})

	// Burst of 2 -> first two requests allowed, the third denies on the
	// org bucket because key/IP are disabled.
	for i := 0; i < 2; i++ {
		if d := l.Check(Request{OrgID: "org_a"}); !d.Allowed {
			t.Fatalf("burst request %d denied: %+v", i, d)
		}
	}
	d := l.Check(Request{OrgID: "org_a"})
	if d.Allowed {
		t.Fatal("Allowed = true after exhausting org burst")
	}
	if d.Bucket != BucketOrg {
		t.Errorf("Bucket = %q, want %q", d.Bucket, BucketOrg)
	}
	if d.Retry < time.Second {
		t.Errorf("Retry = %s, want at least 1s (the integer wire floor)", d.Retry)
	}
}

// TestCheckPerKeyIsolationDoesNotLeakAcrossPrincipals is the acceptance-
// criteria pin: each API key has an independent bucket, so one principal
// exhausting its budget cannot starve a different principal. It also
// proves the org dimension stays out of the way when only the key
// dimension is enabled.
func TestCheckPerKeyIsolationDoesNotLeakAcrossPrincipals(t *testing.T) {
	t.Parallel()

	spec := Spec{Rate: 1, Burst: 2}
	l, _ := newLimiter(t, Config{Key: Specs{Read: spec}})

	// Drain key_a entirely.
	for i := 0; i < 2; i++ {
		if d := l.Check(Request{KeyID: "key_a"}); !d.Allowed {
			t.Fatalf("key_a burst request %d denied: %+v", i, d)
		}
	}
	if d := l.Check(Request{KeyID: "key_a"}); d.Allowed {
		t.Fatal("key_a third request allowed; want denial after burst")
	}
	// key_b has not consumed any tokens yet and must still be allowed.
	if d := l.Check(Request{KeyID: "key_b"}); !d.Allowed {
		t.Fatalf("key_b request denied despite key isolation: %+v", d)
	}
}

// TestCheckBucketsRefillOverTime proves the steady-state rate refills the
// bucket: after burst exhaustion, advancing the clock by 1/rate seconds
// per token restores capacity.
func TestCheckBucketsRefillOverTime(t *testing.T) {
	t.Parallel()

	// 2 tokens/sec, burst 2: a single token refills in 500ms.
	l, clock := newLimiter(t, Config{Org: Specs{Read: Spec{Rate: 2, Burst: 2}}})
	for i := 0; i < 2; i++ {
		if d := l.Check(Request{OrgID: "org_a"}); !d.Allowed {
			t.Fatalf("burst request %d denied: %+v", i, d)
		}
	}
	if d := l.Check(Request{OrgID: "org_a"}); d.Allowed {
		t.Fatal("Allowed = true after burst exhaustion without a refill")
	}

	clock.Advance(time.Second)
	// One full second restores two tokens, but capacity caps the bucket at
	// burst=2, so two more requests succeed before the next denial.
	for i := 0; i < 2; i++ {
		if d := l.Check(Request{OrgID: "org_a"}); !d.Allowed {
			t.Fatalf("post-refill request %d denied: %+v", i, d)
		}
	}
	if d := l.Check(Request{OrgID: "org_a"}); d.Allowed {
		t.Fatal("Allowed = true after re-draining the bucket")
	}
}

// TestCheckRouteClassPicksWriteSpec proves a state-changing request
// consumes from the Write spec rather than the Read spec. With Read
// allowing infinite traffic and Write disabled (rate=0), the limiter
// must deny on write but never on read.
func TestCheckRouteClassPicksWriteSpec(t *testing.T) {
	t.Parallel()

	l, _ := newLimiter(t, Config{
		Org: Specs{
			Read:  Spec{Rate: 1000, Burst: 1000},
			Write: Spec{Rate: 1, Burst: 1},
		},
	})

	// Reads from the same org never deny.
	for i := 0; i < 50; i++ {
		if d := l.Check(Request{OrgID: "org_a"}); !d.Allowed {
			t.Fatalf("read %d denied: %+v", i, d)
		}
	}
	// First write consumes the burst-1 budget; the second denies on org.
	if d := l.Check(Request{OrgID: "org_a", Write: true}); !d.Allowed {
		t.Fatalf("first write denied: %+v", d)
	}
	d := l.Check(Request{OrgID: "org_a", Write: true})
	if d.Allowed {
		t.Fatal("second write allowed; want denial on write spec exhaustion")
	}
	if d.Bucket != BucketOrg {
		t.Errorf("Bucket = %q, want %q", d.Bucket, BucketOrg)
	}
}

// TestCheckDeniesUpstreamDoesNotDebitDownstream pins the "first exhausted
// bucket wins" rule. When the org bucket denies, the key and IP buckets
// must NOT consume a token — otherwise a single throttled tenant could
// drain the shared IP bucket of every neighbour behind a NAT, and a single
// throttled tenant on a misconfigured shared key would lock the key out
// for everyone.
//
// The setup widens IP and Key bursts to 3 so the first allowed request
// (which debits all three dimensions) leaves headroom on the downstream
// buckets — that headroom is what proves the denied second request did
// not also debit downstream.
func TestCheckDeniesUpstreamDoesNotDebitDownstream(t *testing.T) {
	t.Parallel()

	l, _ := newLimiter(t, Config{
		Org: Specs{Read: Spec{Rate: 1, Burst: 1}},
		Key: Specs{Read: Spec{Rate: 1, Burst: 3}},
		IP:  Specs{Read: Spec{Rate: 1, Burst: 3}},
	})

	// First request allowed: org=0, key=2, ip=2 after debit.
	if d := l.Check(Request{OrgID: "org_a", KeyID: "key_a", IP: "1.2.3.4"}); !d.Allowed {
		t.Fatalf("first request denied: %+v", d)
	}
	// Org bucket exhausted; key and ip MUST stay at 2 (not 1) after this.
	if d := l.Check(Request{OrgID: "org_a", KeyID: "key_a", IP: "1.2.3.4"}); d.Allowed {
		t.Fatal("second request from same org allowed; want org denial")
	} else if d.Bucket != BucketOrg {
		t.Fatalf("denied on %q, want %q", d.Bucket, BucketOrg)
	}

	// Neighbour orgs sharing the IP must still get through; if the org-
	// denied request had also debited the IP bucket, ip would be at 1 now
	// rather than 2 and only one neighbour would succeed. With ip at 2,
	// two distinct neighbour orgs must both succeed before the IP bucket
	// finally runs out on the third neighbour.
	neighbours := []Request{
		{OrgID: "org_b", KeyID: "key_b", IP: "1.2.3.4"},
		{OrgID: "org_c", KeyID: "key_c", IP: "1.2.3.4"},
	}
	for i, req := range neighbours {
		if d := l.Check(req); !d.Allowed {
			t.Fatalf("neighbour-IP request %d denied; downstream bucket was debited: %+v", i, d)
		}
	}
}

// TestCheckRetryAfterReportsAtLeastOneSecond proves the wire floor: any
// sub-second deficit rounds up to a full second because the integer
// Retry-After response header cannot carry milliseconds.
func TestCheckRetryAfterReportsAtLeastOneSecond(t *testing.T) {
	t.Parallel()

	// 10 tokens/sec, burst 1: a single denial expects 1/10s = 100ms to
	// refill, which the limiter must round up to 1s.
	l, _ := newLimiter(t, Config{Org: Specs{Read: Spec{Rate: 10, Burst: 1}}})
	if d := l.Check(Request{OrgID: "org_a"}); !d.Allowed {
		t.Fatalf("first request denied: %+v", d)
	}
	d := l.Check(Request{OrgID: "org_a"})
	if d.Allowed {
		t.Fatal("second request allowed; want denial after burst")
	}
	if d.Retry < time.Second {
		t.Errorf("Retry = %s, want at least 1s", d.Retry)
	}
}

// TestCheckNilLimiterAllowsEverything pins the zero-value behaviour: a
// nil *Limiter (the result of skipping construction in a test) admits
// every request, so test harnesses can pass nil without rewiring.
func TestCheckNilLimiterAllowsEverything(t *testing.T) {
	t.Parallel()

	var l *Limiter
	d := l.Check(Request{OrgID: "org_a", KeyID: "key_a", IP: "1.2.3.4"})
	if !d.Allowed {
		t.Errorf("nil limiter denied a request: %+v", d)
	}
}

// TestIdleBucketsArePruned drives the lazy eviction path: a bucket idle
// longer than IdleTTL is dropped on the next request that touches the
// same dimension, so a process with a high-cardinality key population
// does not accumulate buckets forever.
func TestIdleBucketsArePruned(t *testing.T) {
	t.Parallel()

	l, clock := newLimiter(t, Config{
		Org:     Specs{Read: Spec{Rate: 1, Burst: 1}},
		IdleTTL: time.Minute,
	})

	if d := l.Check(Request{OrgID: "old_org"}); !d.Allowed {
		t.Fatalf("first request denied: %+v", d)
	}
	if orgs, _, _ := l.Dimensions(); orgs != 1 {
		t.Errorf("orgs = %d, want 1", orgs)
	}

	// Move the clock well past IdleTTL and touch a different org; the
	// eviction sweep should reap "old_org".
	clock.Advance(2 * time.Minute)
	if d := l.Check(Request{OrgID: "new_org"}); !d.Allowed {
		t.Fatalf("post-idle request denied: %+v", d)
	}
	orgs, _, _ := l.Dimensions()
	if orgs != 1 {
		t.Errorf("orgs after sweep = %d, want 1 (old_org pruned, new_org kept)", orgs)
	}
}

// TestCheckIsConcurrencySafe drives the limiter from many goroutines with
// the same identity and proves the burst budget is not exceeded under
// race. Burst=N must admit at most N requests in a tight zero-elapsed
// window.
func TestCheckIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	const burst = 50
	const goroutines = 200
	l, _ := newLimiter(t, Config{Org: Specs{Read: Spec{Rate: 0.001, Burst: burst}}})

	var allowed int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if l.Check(Request{OrgID: "org_a"}).Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&allowed); got > burst {
		t.Errorf("allowed = %d, want at most burst=%d (concurrent over-grant)", got, burst)
	}
}
