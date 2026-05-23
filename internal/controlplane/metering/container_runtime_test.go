package metering

import (
	"context"
	"testing"
	"time"
)

type fakeContainerStatsClient struct {
	stats []ContainerRuntimeStat
}

func (f fakeContainerStatsClient) ListContainerStats(context.Context) ([]ContainerRuntimeStat, error) {
	return f.stats, nil
}

func TestContainerRuntimeStatsCollectorNormalizesCPUResetAndMemoryMBHours(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	collector, err := NewContainerRuntimeStatsCollector(ContainerRuntimeStatsCollectorConfig{
		Client: fakeContainerStatsClient{stats: []ContainerRuntimeStat{
			{
				ContainerID:                   "ctr-web",
				CumulativeCPUMillicoreSeconds: 25,
				MemoryMB:                      512,
				Labels:                        map[string]string{"yalla_service_id": "svc_web"},
			},
			{
				ContainerID:                   "ctr-worker",
				CumulativeCPUMillicoreSeconds: 150,
				MemoryMB:                      256,
				Labels:                        map[string]string{"yalla_service_id": "svc_worker"},
			},
		}},
		Source: "cadvisor",
	})
	if err != nil {
		t.Fatalf("NewContainerRuntimeStatsCollector: %v", err)
	}

	got, err := collector.Collect(context.Background(), ContainerRuntimeStatsCollectInput{
		Start: start,
		End:   start.Add(30 * time.Minute),
		Previous: []ContainerRuntimeStat{
			{ContainerID: "ctr-web", CumulativeCPUMillicoreSeconds: 100},
			{ContainerID: "ctr-worker", CumulativeCPUMillicoreSeconds: 125},
			{ContainerID: "ctr-gone", CumulativeCPUMillicoreSeconds: 10, MemoryMB: 64},
		},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byContainerMetric := map[string]ContainerMetricSample{}
	for _, sample := range got.Samples {
		byContainerMetric[sample.ContainerID+"/"+sample.Name] = sample
	}
	assertContainerRuntimeSample(t, byContainerMetric["ctr-web/container_cpu_millicore_seconds"], 25, "millicore_second")
	assertContainerRuntimeSample(t, byContainerMetric["ctr-web/container_memory_mb_hours"], 256, "mb_hour")
	assertContainerRuntimeSample(t, byContainerMetric["ctr-worker/container_cpu_millicore_seconds"], 25, "millicore_second")
	assertContainerRuntimeSample(t, byContainerMetric["ctr-worker/container_memory_mb_hours"], 128, "mb_hour")
	if _, ok := byContainerMetric["ctr-gone/container_memory_mb_hours"]; ok {
		t.Fatalf("missing container emitted a sample: %+v", byContainerMetric["ctr-gone/container_memory_mb_hours"])
	}
	if got.Source != "cadvisor" || got.QueryVersion != "container-runtime-stats-v1" {
		t.Fatalf("source/version = %q/%q, want cadvisor/container-runtime-stats-v1", got.Source, got.QueryVersion)
	}
	if got.RawSampleChecksum == "" {
		t.Fatal("RawSampleChecksum is empty")
	}
}

func assertContainerRuntimeSample(t *testing.T, got ContainerMetricSample, wantValue float64, wantUnit string) {
	t.Helper()
	if got.Value != wantValue || got.Unit != wantUnit {
		t.Fatalf("sample = %+v, want value=%g unit=%s", got, wantValue, wantUnit)
	}
	if got.Source != "cadvisor" || got.QueryVersion != "container-runtime-stats-v1" || got.RawSampleChecksum == "" {
		t.Fatalf("sample metadata = %+v, want source/version/checksum", got)
	}
}
