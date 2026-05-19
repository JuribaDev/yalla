package metering_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/controlplane/metering"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestDokployMetricsAdapterNormalizesConfiguredMonitoringSources(t *testing.T) {
	fake := dokployfake.New()
	defer fake.Close()
	fake.SetApplicationMonitoring("app_web", map[string]any{
		"requests": 42,
		"cpu": map[string]any{
			"millicores": 250,
		},
	})
	fake.SetContainerMetrics("app_web", map[string]any{
		"container_id": "container_123",
		"cpu_millicore_seconds": []any{
			map[string]any{"timestamp": "2026-05-19T10:00:00Z", "value": 12.5},
		},
		"memory_mb_hours": 3.25,
	})
	fake.SetServerMetrics("node-a", map[string]any{
		"cpu_percent": 51,
	})
	fake.SetUserServerMetrics(map[string]any{
		"disk_used_bytes": 4096,
	})

	client := newDokployMetricsTestClient(t, fake, nil)
	adapter, err := metering.NewDokployMetricsAdapter(metering.DokployMetricsAdapterConfig{
		Client:      client,
		ServerURL:   "https://node-a.internal.example",
		ServerToken: "node-token-super-secret",
	})
	if err != nil {
		t.Fatalf("NewDokployMetricsAdapter: %v", err)
	}

	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	got, err := adapter.Collect(context.Background(), metering.DokployMetricsCollectInput{
		ApplicationName: "app_web",
		ServerName:      "node-a",
		Start:           start,
		End:             start.Add(5 * time.Minute),
		DataPoints:      5,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertDokploySample(t, got.Samples, "application.requests", 42, "count", false)
	assertDokploySample(t, got.Samples, "application.cpu.millicores", 250, "millicore", false)
	assertDokploySample(t, got.Samples, "container_cpu_millicore_seconds", 12.5, "millicore_second", true)
	assertDokploySample(t, got.Samples, "container_memory_mb_hours", 3.25, "mb_hour", true)
	assertDokploySample(t, got.Samples, "server.cpu_percent", 51, "percent", false)
	assertDokploySample(t, got.Samples, "user_server.disk_used_bytes", 4096, "byte", false)
	if got.Source != "dokploy" || got.QueryVersion == "" || got.RawSampleChecksum == "" {
		t.Fatalf("collection metadata = %+v, want source/query version/checksum", got)
	}
	for _, sample := range got.Samples {
		if sample.Source != "dokploy" {
			t.Fatalf("sample source = %q, want dokploy", sample.Source)
		}
		if sample.WindowStart != start || sample.WindowEnd != start.Add(5*time.Minute) {
			t.Fatalf("sample window = %s..%s", sample.WindowStart, sample.WindowEnd)
		}
	}
	if len(got.UnavailableSources) != 0 {
		t.Fatalf("unavailable sources = %v, want none", got.UnavailableSources)
	}
	for _, req := range fake.Requests() {
		if strings.Contains(req.RawQuery, "node-token-super-secret") || strings.Contains(req.Body, "node-token-super-secret") {
			t.Fatalf("fake recorded unredacted secret in request: %+v", req)
		}
	}
}

func TestDokployMetricsAdapterDegradesUnavailableMonitoring(t *testing.T) {
	metrics := telemetry.NewDokployDependencyMetrics()
	fake := dokployfake.New()
	defer fake.Close()
	fake.SetApplicationMonitoring("app_web", map[string]any{"requests": 7})
	fake.QueueMonitoringFault("container", dokployfake.StatusFault(http.StatusForbidden))
	fake.QueueMonitoringFault("server", dokployfake.MalformedJSONFault())
	fake.QueueMonitoringFault("user_server", dokployfake.TimeoutFault(250*time.Millisecond))

	client := newDokployMetricsTestClient(t, fake, func(cfg *dokploy.Config) {
		cfg.Timeout = 50 * time.Millisecond
		cfg.MaxRetries = -1
		cfg.Metrics = metrics
	})
	adapter, err := metering.NewDokployMetricsAdapter(metering.DokployMetricsAdapterConfig{
		Client:      client,
		ServerURL:   "https://node-a.internal.example",
		ServerToken: "node-token-super-secret",
	})
	if err != nil {
		t.Fatalf("NewDokployMetricsAdapter: %v", err)
	}

	start := time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC)
	got, err := adapter.Collect(context.Background(), metering.DokployMetricsCollectInput{
		ApplicationName: "app_web",
		ServerName:      "node-a",
		Start:           start,
		End:             start.Add(time.Minute),
		DataPoints:      3,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertDokploySample(t, got.Samples, "application.requests", 7, "count", false)
	if len(got.UnavailableSources) != 3 {
		t.Fatalf("unavailable sources = %v, want three degraded sources", got.UnavailableSources)
	}
	wantCodes := map[yerr.Code]bool{
		yerr.CodeDokployForbidden:   false,
		yerr.CodeDokployBadResponse: false,
		yerr.CodeTimeout:            false,
	}
	for _, src := range got.UnavailableSources {
		code := yerr.Code(src.ErrorCode)
		if _, ok := wantCodes[code]; ok {
			wantCodes[code] = true
		}
	}
	for code, seen := range wantCodes {
		if !seen {
			t.Fatalf("missing degraded error code %s in %+v", code, got.UnavailableSources)
		}
	}
	if metrics.Snapshot().TotalCalls < 4 {
		t.Fatalf("dokploy dependency metrics total calls = %d, want at least 4", metrics.Snapshot().TotalCalls)
	}
}

func TestDokployMetricsAdapterValidatesInputBeforeCallingDokploy(t *testing.T) {
	fake := dokployfake.New()
	defer fake.Close()
	adapter, err := metering.NewDokployMetricsAdapter(metering.DokployMetricsAdapterConfig{
		Client: newDokployMetricsTestClient(t, fake, nil),
	})
	if err != nil {
		t.Fatalf("NewDokployMetricsAdapter: %v", err)
	}

	_, err = adapter.Collect(context.Background(), metering.DokployMetricsCollectInput{
		ApplicationName: " ",
		Start:           time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC),
		End:             time.Date(2026, 5, 19, 10, 1, 0, 0, time.UTC),
		DataPoints:      1,
	})
	if err == nil {
		t.Fatal("Collect returned nil error, want validation failure")
	}
	if fake.RequestCount() != 0 {
		t.Fatalf("validation failure reached Dokploy: %d requests", fake.RequestCount())
	}
}

func newDokployMetricsTestClient(t *testing.T, fake *dokployfake.Server, mutate func(*dokploy.Config)) *dokploy.Client {
	t.Helper()
	cfg := dokploy.Config{
		BaseURL: fake.URL(),
		Token:   fake.Token(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := dokploy.New(cfg)
	if err != nil {
		t.Fatalf("dokploy.New: %v", err)
	}
	return client
}

func assertDokploySample(t *testing.T, samples []metering.DokployMetricSample, name string, value float64, unit string, billing bool) {
	t.Helper()
	for _, sample := range samples {
		if sample.Name == name {
			if sample.Value != value || sample.Unit != unit || sample.BillingGrade != billing {
				t.Fatalf("%s sample = %+v, want value=%v unit=%s billing=%v", name, sample, value, unit, billing)
			}
			return
		}
	}
	t.Fatalf("missing sample %s in %+v", name, samples)
}
