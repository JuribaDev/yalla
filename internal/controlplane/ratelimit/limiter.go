// Package ratelimit provides the in-process token-bucket rate limiter that
// throttles inbound requests to the Yalla Control Plane HTTP API.
//
// The limiter is multi-dimensional: every authenticated request consumes
// from three independent token buckets — one keyed by the principal's home
// organization, one keyed by the API key id (or session principal id), and
// one keyed by the client IP — and an anonymous request from a public
// endpoint consumes from the IP bucket only. The most restrictive denial
// wins: if any bucket is empty the request is rejected and the limiter
// reports which bucket dimension throttled it so the response and the log
// record name it without echoing the bucket identity (an org id, key id,
// or IP).
//
// Two cross-cutting guarantees are part of the package contract:
//
//   - Internal-worker exemption. A Request whose Exempt flag is set always
//     resolves to an Allowed Decision, regardless of bucket state. The
//     httpapi middleware sets Exempt for principals authenticated through
//     auth.MethodInternalWorker so internal callbacks are never throttled
//     by the customer-facing rate limit.
//   - No-secret leakage. The bucket identity (org id, key id, IP) never
//     appears in the Decision; only the bucket dimension does. A caller
//     that logs Decision.Bucket records "organization" or "api_key" or
//     "ip", never the throttled tenant's id.
//
// The limiter draws no global goroutine: idle buckets are pruned lazily on
// the request path so the limiter cleans up after itself even when the
// process never calls Close.
package ratelimit

import (
	"errors"
	"math"
	"sync"
	"time"
)

// Spec is the throughput parameter for one token bucket. A Spec with a
// non-positive Rate or Burst is treated as "no limit on this dimension";
// the limiter skips the bucket check entirely instead of denying every
// request. Rate is steady-state tokens (requests) per second; Burst is the
// bucket capacity, which is also the initial token count when a bucket is
// first observed.
type Spec struct {
	Rate  float64
	Burst int
}

// Enabled reports whether the spec admits any traffic. A disabled spec is
// the "no limit on this dimension" sentinel.
func (s Spec) Enabled() bool { return s.Rate > 0 && s.Burst > 0 }

// Specs holds the read- and write-side throughput specifications for a
// single bucket dimension. Read covers HTTP GET / HEAD / OPTIONS; Write
// covers every other method. A zero Specs means the dimension is disabled
// for both read and write.
type Specs struct {
	Read  Spec
	Write Spec
}

// For returns the spec that applies to the request: Write when the request
// is a state-changing method, Read otherwise.
func (s Specs) For(write bool) Spec {
	if write {
		return s.Write
	}
	return s.Read
}

// AnyEnabled reports whether either side of the dimension is rate-limited.
func (s Specs) AnyEnabled() bool { return s.Read.Enabled() || s.Write.Enabled() }

// Config is the resolved limiter configuration. Org, Key, and IP each
// independently rate-limit the matching dimension; a zero Specs disables
// that dimension entirely.
//
// IdleTTL is how long an unused bucket is retained before lazy eviction
// reclaims it; a non-positive value defaults to five minutes. The eviction
// runs piggybacked on Check, so the limiter holds no background goroutine
// and Close is a no-op (kept for forward compatibility).
//
// Now lets tests inject a deterministic clock. A nil Now defaults to
// time.Now, which is the production source.
type Config struct {
	Org     Specs
	Key     Specs
	IP      Specs
	IdleTTL time.Duration
	Now     func() time.Time
}

// Bucket names are the stable strings reported in Decision.Bucket. They
// are the only identity-related strings the limiter ever publishes — the
// concrete org/key/IP identity stays inside the limiter.
const (
	BucketOrg = "organization"
	BucketKey = "api_key"
	BucketIP  = "ip"
)

// Request describes one inbound HTTP request the limiter must decide on.
// OrgID, KeyID, and IP are the bucket identities for the org/key/IP
// dimensions; an empty value skips that dimension's check (the limiter
// cannot bill a missing identity). Write reports whether the route is a
// state-changing method so the limiter can pick the Write Spec.
type Request struct {
	// OrgID is the principal's home organization id. Empty for anonymous
	// requests on public endpoints.
	OrgID string
	// KeyID is the API key or session principal id. Empty for anonymous
	// requests.
	KeyID string
	// IP is the client IP address resolved from the request. Empty falls
	// through; the limiter treats it as "unknown" and skips the IP bucket.
	IP string
	// Write reports whether the HTTP method is state-changing (POST, PUT,
	// PATCH, DELETE, and friends). Read methods (GET, HEAD, OPTIONS) set
	// this to false so the read spec applies.
	Write bool
	// Exempt is the internal-worker bypass: a request whose principal
	// authenticated through auth.MethodInternalWorker carries Exempt=true
	// and is unconditionally Allowed.
	Exempt bool
}

// Decision is the limiter's verdict on one Request. Allowed is true on the
// happy path; Bucket and Retry are populated on a denial so the caller can
// shape the response (a stable Retry-After header, a structured envelope
// detail) and the log record.
//
// Retry is the integer-second wait the caller should advertise to the
// client. A zero value never reaches the wire because the apierr.RateLimited
// constructor clamps it to one second.
type Decision struct {
	Allowed bool
	Bucket  string
	Retry   time.Duration
}

// Limiter is a token-bucket rate limiter with three independent bucket
// dimensions. It is safe for concurrent use.
type Limiter struct {
	cfg Config
	org *bucketMap
	key *bucketMap
	ip  *bucketMap
}

// Default constants for the bucket idle TTL. A bucket idle longer than the
// TTL is pruned on the next request path that touches the same map. Five
// minutes is generous enough that bursty workloads do not pay reinitialization
// cost every minute, and short enough that the working set stays bounded
// even with a large key population.
const defaultIdleTTL = 5 * time.Minute

// errNilNow is returned by New only when the caller explicitly supplied a
// nil time function via a non-nil Config that overrode the default. It is
// kept package-internal because New auto-fills time.Now.
var errNilNow = errors.New("ratelimit: Config.Now must return a non-zero time")

// New constructs a Limiter from cfg. A nil Now is replaced with time.Now;
// a non-positive IdleTTL is replaced with the package default. The limiter
// rejects no request when every dimension is disabled — useful in tests
// that exercise the wiring without enforcing any cap.
func New(cfg Config) (*Limiter, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Now().IsZero() {
		return nil, errNilNow
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	return &Limiter{
		cfg: cfg,
		org: newBucketMap(cfg.IdleTTL),
		key: newBucketMap(cfg.IdleTTL),
		ip:  newBucketMap(cfg.IdleTTL),
	}, nil
}

// Check returns the limiter's decision for req. The decision is computed
// in fixed order — organization, API key, IP — and the first exhausted
// bucket wins; downstream dimensions are NOT debited when an upstream
// dimension already denied the request, so a single throttled client
// cannot drain the IP bucket of every neighbour behind a shared NAT.
//
// Exempt requests, requests on a Spec-less dimension, and requests whose
// identity is empty for a given dimension all skip that dimension's check.
func (l *Limiter) Check(req Request) Decision {
	if l == nil {
		return Decision{Allowed: true}
	}
	if req.Exempt {
		return Decision{Allowed: true}
	}
	now := l.cfg.Now()

	if spec := l.cfg.Org.For(req.Write); spec.Enabled() && req.OrgID != "" {
		if d, ok := l.org.take(req.OrgID, spec, now); !ok {
			return Decision{Bucket: BucketOrg, Retry: d}
		}
	}
	if spec := l.cfg.Key.For(req.Write); spec.Enabled() && req.KeyID != "" {
		if d, ok := l.key.take(req.KeyID, spec, now); !ok {
			return Decision{Bucket: BucketKey, Retry: d}
		}
	}
	if spec := l.cfg.IP.For(req.Write); spec.Enabled() && req.IP != "" {
		if d, ok := l.ip.take(req.IP, spec, now); !ok {
			return Decision{Bucket: BucketIP, Retry: d}
		}
	}
	return Decision{Allowed: true}
}

// Close releases the limiter's resources. It is currently a no-op because
// the eviction goroutine is lazy, but callers should still invoke it on
// shutdown so the contract stays forward-compatible.
func (l *Limiter) Close() error { return nil }

// tokenBucket is a single keyed token bucket. tokens is fractional so a
// rate less than one token per second still refills correctly; capacity
// is the burst allowance and the initial fill.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
	lastUsed time.Time
}

// take attempts to consume one token at time now. It returns the wait
// duration until the next token would be available on a denial; on an
// allow it returns 0. The returned duration is always at least one second
// because the wire contract is integer-second Retry-After; a sub-second
// wait would round to zero and the client would retry immediately.
func (b *tokenBucket) take(now time.Time, spec Spec) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.capacity = float64(spec.Burst)
		b.rate = spec.Rate
		b.tokens = b.capacity
		b.last = now
	} else if spec.Rate != b.rate || float64(spec.Burst) != b.capacity {
		// Config can be reloaded in tests; adopt the new spec but never
		// hand out more tokens than the new capacity allows.
		b.capacity = float64(spec.Burst)
		b.rate = spec.Rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	b.lastUsed = now

	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}
	if b.rate <= 0 {
		// A disabled rate cannot refill; one whole second is the smallest
		// instruction the integer Retry-After wire shape can carry.
		return time.Second, false
	}
	missing := 1 - b.tokens
	wait := time.Duration(math.Ceil(missing/b.rate*float64(time.Second.Nanoseconds()))) * time.Nanosecond
	if wait < time.Second {
		wait = time.Second
	}
	return wait, false
}

// bucketMap is a concurrent map of bucket key -> tokenBucket with lazy
// eviction. It is sharded by mu rather than sync.Map so the eviction sweep
// can iterate the map safely.
type bucketMap struct {
	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	idleTTL   time.Duration
	lastSweep time.Time
}

func newBucketMap(idleTTL time.Duration) *bucketMap {
	return &bucketMap{
		buckets: make(map[string]*tokenBucket),
		idleTTL: idleTTL,
	}
}

// take resolves the bucket for key and consumes one token from it. A
// freshly-created bucket has its lastUsed timestamp set to now BEFORE
// the eviction sweep runs, so the sweep cannot reap the bucket we just
// inserted (its zero-value lastUsed would otherwise be older than any
// cutoff and the bucket would be deleted out from under the caller).
func (m *bucketMap) take(key string, spec Spec, now time.Time) (time.Duration, bool) {
	m.mu.Lock()
	b, ok := m.buckets[key]
	if !ok {
		b = &tokenBucket{lastUsed: now}
		m.buckets[key] = b
	}
	m.maybeSweepLocked(now)
	m.mu.Unlock()
	return b.take(now, spec)
}

// maybeSweepLocked prunes buckets that have been idle longer than idleTTL.
// It runs at most once per idleTTL so the request path stays O(1)
// amortised; sweeping the whole map every request would defeat the point
// of the lazy strategy.
func (m *bucketMap) maybeSweepLocked(now time.Time) {
	if m.idleTTL <= 0 {
		return
	}
	if !m.lastSweep.IsZero() && now.Sub(m.lastSweep) < m.idleTTL {
		return
	}
	m.lastSweep = now
	cutoff := now.Add(-m.idleTTL)
	for k, b := range m.buckets {
		b.mu.Lock()
		expired := b.lastUsed.Before(cutoff)
		b.mu.Unlock()
		if expired {
			delete(m.buckets, k)
		}
	}
}

// Len reports the current number of live buckets across one dimension.
// It is exported only for tests; production code never inspects it.
func (m *bucketMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

// Dimensions returns the live bucket counts for each dimension. It is a
// test-and-diagnostics helper; production code never inspects it.
func (l *Limiter) Dimensions() (orgs, keys, ips int) {
	return l.org.Len(), l.key.Len(), l.ip.Len()
}
