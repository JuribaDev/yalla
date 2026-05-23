package ratelimit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redis "github.com/redis/go-redis/v9"
)

func testRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	if raw := strings.TrimSpace(os.Getenv("YALLA_TEST_REDIS_URL")); raw != "" {
		opt, err := redis.ParseURL(raw)
		if err != nil {
			t.Fatalf("parse YALLA_TEST_REDIS_URL: %v", err)
		}
		client := redis.NewClient(opt)
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Ping(context.Background()).Err(); err != nil {
			t.Fatalf("ping test redis: %v", err)
		}
		return client
	}

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func redisTestPrefix(t *testing.T, suffix string) string {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	return fmt.Sprintf("test:%s:%d:%s", name, time.Now().UnixNano(), suffix)
}

func newRedisLimiter(t *testing.T, client *redis.Client, cfg Config, prefix string) *RedisLimiter {
	t.Helper()

	if cfg.Now == nil {
		cfg.Now = newClock(epoch).Now
	}
	l, err := NewRedisLimiter(client, cfg, prefix)
	if err != nil {
		t.Fatalf("NewRedisLimiter: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestRedisLimiterDeniesAcrossInstances(t *testing.T) {
	t.Parallel()

	client := testRedisClient(t)
	cfg := Config{IP: Specs{Read: Spec{Rate: 0.01, Burst: 2}}, IdleTTL: time.Minute}
	prefix := redisTestPrefix(t, "shared")
	first := newRedisLimiter(t, client, cfg, prefix)
	second := newRedisLimiter(t, client, cfg, prefix)

	req := Request{IP: "203.0.113.10"}
	if d := first.Check(req); !d.Allowed {
		t.Fatalf("first instance first request denied: %+v", d)
	}
	if d := second.Check(req); !d.Allowed {
		t.Fatalf("second instance shared burst request denied: %+v", d)
	}
	d := first.Check(req)
	if d.Allowed {
		t.Fatal("third request allowed; want denial after shared Redis burst")
	}
	if d.Bucket != BucketIP {
		t.Fatalf("Bucket = %q, want %q", d.Bucket, BucketIP)
	}
	if d.Retry < time.Second {
		t.Fatalf("Retry = %s, want at least 1s", d.Retry)
	}
}

func TestRedisLimiterDoesNotDebitIPWhenOrgDenied(t *testing.T) {
	t.Parallel()

	client := testRedisClient(t)
	cfg := Config{
		Org:     Specs{Read: Spec{Rate: 0.01, Burst: 1}},
		IP:      Specs{Read: Spec{Rate: 0.01, Burst: 1}},
		IdleTTL: time.Minute,
	}
	l := newRedisLimiter(t, client, cfg, redisTestPrefix(t, "atomic"))

	if d := l.Check(Request{OrgID: "org_a", IP: "198.51.100.10"}); !d.Allowed {
		t.Fatalf("initial request denied: %+v", d)
	}
	if d := l.Check(Request{OrgID: "org_a", IP: "198.51.100.11"}); d.Allowed || d.Bucket != BucketOrg {
		t.Fatalf("second org request = %+v, want org denial", d)
	}
	if d := l.Check(Request{OrgID: "org_b", IP: "198.51.100.11"}); !d.Allowed {
		t.Fatalf("ip bucket was debited during org denial: %+v", d)
	}
}

func TestRedisLimiterExemptsInternalWorker(t *testing.T) {
	t.Parallel()

	client := testRedisClient(t)
	tight := Spec{Rate: 0.01, Burst: 1}
	l := newRedisLimiter(t, client, Config{
		Org: Specs{Read: tight, Write: tight},
		Key: Specs{Read: tight, Write: tight},
		IP:  Specs{Read: tight, Write: tight},
	}, redisTestPrefix(t, "exempt"))

	for i := 0; i < 20; i++ {
		d := l.Check(Request{OrgID: "org_a", KeyID: "secret-key-id", IP: "203.0.113.20", Exempt: true})
		if !d.Allowed {
			t.Fatalf("exempt request %d denied: %+v", i, d)
		}
	}
}

func TestRedisLimiterDoesNotReturnBucketIdentity(t *testing.T) {
	t.Parallel()

	client := testRedisClient(t)
	l := newRedisLimiter(t, client, Config{
		Key: Specs{Read: Spec{Rate: 0.01, Burst: 1}},
	}, redisTestPrefix(t, "redaction"))

	const secretKeyID = "secret-key-id"
	if d := l.Check(Request{KeyID: secretKeyID}); !d.Allowed {
		t.Fatalf("initial key request denied: %+v", d)
	}
	d := l.Check(Request{KeyID: secretKeyID})
	if d.Allowed {
		t.Fatal("second key request allowed; want denial")
	}
	if d.Bucket != BucketKey {
		t.Fatalf("Bucket = %q, want %q", d.Bucket, BucketKey)
	}
	if strings.Contains(d.Bucket, secretKeyID) {
		t.Fatalf("Decision bucket leaked key identity: %q", d.Bucket)
	}
}
