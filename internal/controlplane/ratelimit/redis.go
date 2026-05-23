package ratelimit

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

// RedisClient is the narrow go-redis surface the distributed limiter needs.
// It keeps RedisLimiter testable while still accepting *redis.Client in
// production.
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
	Close() error
}

// RedisLimiter stores token buckets in Redis and updates all enabled
// dimensions with one Lua script. It satisfies the same no-secret Decision
// contract as the in-process Limiter: Redis keys contain identities, but the
// returned Bucket is only organization, api_key, or ip.
type RedisLimiter struct {
	client RedisClient
	cfg    Config
	prefix string
	now    func() time.Time
}

const defaultRedisPrefix = "yalla:ratelimit"

// NewRedisLimiter constructs a Redis-backed limiter. A nil Now is replaced
// with time.Now; a non-positive IdleTTL is replaced with the package default.
func NewRedisLimiter(client RedisClient, cfg Config, prefix string) (*RedisLimiter, error) {
	if client == nil {
		return nil, errors.New("ratelimit: redis client is nil")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Now().IsZero() {
		return nil, errNilNow
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = defaultRedisPrefix
	}
	return &RedisLimiter{
		client: client,
		cfg:    cfg,
		prefix: strings.TrimRight(prefix, ":"),
		now:    cfg.Now,
	}, nil
}

// Check returns the limiter's decision for req. Redis errors fail closed on
// the first enabled bucket so a degraded cache cannot silently remove
// protection from the public API.
func (l *RedisLimiter) Check(req Request) Decision {
	if l == nil {
		return Decision{Allowed: true}
	}
	if req.Exempt {
		return Decision{Allowed: true}
	}
	checks := l.bucketChecks(req)
	if len(checks) == 0 {
		return Decision{Allowed: true}
	}

	now := l.now()
	keys := make([]string, 0, len(checks))
	args := make([]any, 0, 2+len(checks)*3)
	args = append(args, now.UnixMilli(), int64(l.cfg.IdleTTL/time.Millisecond))
	for _, check := range checks {
		keys = append(keys, l.redisKey(check.bucket, check.identity))
		args = append(args, check.bucket, check.spec.Rate, check.spec.Burst)
	}

	raw, err := l.client.Eval(context.Background(), redisLimiterScript, keys, args...).Result()
	if err != nil {
		return failClosed(checks[0].bucket)
	}
	return parseRedisDecision(raw, checks[0].bucket)
}

// Close releases the Redis client owned by the limiter.
func (l *RedisLimiter) Close() error {
	if l == nil || l.client == nil {
		return nil
	}
	return l.client.Close()
}

type redisBucketCheck struct {
	bucket   string
	identity string
	spec     Spec
}

func (l *RedisLimiter) bucketChecks(req Request) []redisBucketCheck {
	out := make([]redisBucketCheck, 0, 3)
	if spec := l.cfg.Org.For(req.Write); spec.Enabled() && req.OrgID != "" {
		out = append(out, redisBucketCheck{bucket: BucketOrg, identity: req.OrgID, spec: spec})
	}
	if spec := l.cfg.Key.For(req.Write); spec.Enabled() && req.KeyID != "" {
		out = append(out, redisBucketCheck{bucket: BucketKey, identity: req.KeyID, spec: spec})
	}
	if spec := l.cfg.IP.For(req.Write); spec.Enabled() && req.IP != "" {
		out = append(out, redisBucketCheck{bucket: BucketIP, identity: req.IP, spec: spec})
	}
	return out
}

func (l *RedisLimiter) redisKey(bucket, identity string) string {
	return l.prefix + ":" + bucket + ":" + identity
}

func failClosed(bucket string) Decision {
	return Decision{Bucket: bucket, Retry: time.Second}
}

func parseRedisDecision(raw any, fallbackBucket string) Decision {
	items, ok := raw.([]any)
	if !ok || len(items) < 3 {
		return failClosed(fallbackBucket)
	}
	allowed, ok := asInt64(items[0])
	if !ok {
		return failClosed(fallbackBucket)
	}
	if allowed == 1 {
		return Decision{Allowed: true}
	}
	bucket, ok := items[1].(string)
	if !ok || bucket == "" {
		bucket = fallbackBucket
	}
	retryMS, ok := asInt64(items[2])
	if !ok || retryMS <= 0 {
		retryMS = int64(time.Second / time.Millisecond)
	}
	retry := time.Duration(retryMS) * time.Millisecond
	if retry < time.Second {
		retry = time.Second
	}
	return Decision{Bucket: bucket, Retry: retry}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		if math.Trunc(n) != n {
			return 0, false
		}
		return int64(n), true
	case string:
		parsed, err := strconv.ParseInt(n, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

const redisLimiterScript = `
local now_ms = tonumber(ARGV[1])
local ttl_ms = tonumber(ARGV[2])
local buckets = {}

for i = 1, #KEYS do
  local arg = 3 + ((i - 1) * 3)
  local name = ARGV[arg]
  local rate = tonumber(ARGV[arg + 1])
  local burst = tonumber(ARGV[arg + 2])
  local values = redis.call("HMGET", KEYS[i], "tokens", "last_ms")
  local tokens = tonumber(values[1])
  local last_ms = tonumber(values[2])

  if tokens == nil or last_ms == nil then
    tokens = burst
    last_ms = now_ms
  else
    local elapsed_ms = now_ms - last_ms
    if elapsed_ms > 0 then
      tokens = math.min(burst, tokens + ((elapsed_ms / 1000) * rate))
      last_ms = now_ms
    end
  end

  if tokens < 1 then
    local retry_ms = 1000
    if rate > 0 then
      retry_ms = math.ceil(((1 - tokens) / rate) * 1000)
      if retry_ms < 1000 then
        retry_ms = 1000
      end
    end
    return {0, name, retry_ms}
  end

  buckets[i] = {tokens - 1, last_ms}
end

for i = 1, #KEYS do
  redis.call("HSET", KEYS[i], "tokens", tostring(buckets[i][1]), "last_ms", tostring(buckets[i][2]))
  redis.call("PEXPIRE", KEYS[i], ttl_ms)
end

return {1, "", 0}
`

var _ RedisClient = (*redis.Client)(nil)
