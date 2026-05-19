package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

const defaultContainerRuntimeStatsQueryVersion = "container-runtime-stats-v1"

// ContainerRuntimeStatsClient is the narrow cAdvisor/Docker-stats style input
// port for container resource metering.
type ContainerRuntimeStatsClient interface {
	ListContainerStats(context.Context) ([]ContainerRuntimeStat, error)
}

// ContainerRuntimeStat is one current or previous container runtime sample.
// CumulativeCPUMillicoreSeconds is a monotonically increasing counter until
// the container restarts; MemoryMB is a point-in-time resident memory gauge.
type ContainerRuntimeStat struct {
	ContainerID                   string
	CumulativeCPUMillicoreSeconds float64
	MemoryMB                      float64
	Labels                        map[string]string
}

// ContainerRuntimeStatsCollectorConfig configures the cAdvisor/Docker stats
// collector.
type ContainerRuntimeStatsCollectorConfig struct {
	Client       ContainerRuntimeStatsClient
	Source       string
	QueryVersion string
}

// ContainerRuntimeStatsCollectInput selects one bounded runtime stats window.
type ContainerRuntimeStatsCollectInput struct {
	Start    time.Time
	End      time.Time
	Previous []ContainerRuntimeStat
}

// ContainerRuntimeStatsCollection is one normalized runtime stats collection.
type ContainerRuntimeStatsCollection struct {
	Source            string
	WindowStart       time.Time
	WindowEnd         time.Time
	QueryVersion      string
	RawSampleChecksum string
	Samples           []ContainerMetricSample
}

// ContainerRuntimeStatsCollector normalizes cAdvisor/Docker stats into the
// same container metric samples consumed by attribution and usage emission.
type ContainerRuntimeStatsCollector struct {
	client       ContainerRuntimeStatsClient
	source       string
	queryVersion string
}

// NewContainerRuntimeStatsCollector validates config and returns a source
// adapter for cAdvisor/Docker-style stats.
func NewContainerRuntimeStatsCollector(cfg ContainerRuntimeStatsCollectorConfig) (*ContainerRuntimeStatsCollector, error) {
	if cfg.Client == nil {
		return nil, errors.New("metering: container runtime stats client must not be nil")
	}
	source := strings.TrimSpace(cfg.Source)
	if source == "" {
		source = "container_runtime"
	}
	version := strings.TrimSpace(cfg.QueryVersion)
	if version == "" {
		version = defaultContainerRuntimeStatsQueryVersion
	}
	return &ContainerRuntimeStatsCollector{client: cfg.Client, source: source, queryVersion: version}, nil
}

// Collect reads current container stats, normalizes CPU counter deltas to
// millicore-seconds and memory gauges to MB-hours, and skips containers absent
// from the current sample set.
func (c *ContainerRuntimeStatsCollector) Collect(ctx context.Context, in ContainerRuntimeStatsCollectInput) (ContainerRuntimeStatsCollection, error) {
	if c == nil || c.client == nil {
		return ContainerRuntimeStatsCollection{}, errors.New("metering: nil ContainerRuntimeStatsCollector")
	}
	start := in.Start.UTC()
	end := in.End.UTC()
	if err := validateContainerRuntimeStatsCollectInput(start, end); err != nil {
		return ContainerRuntimeStatsCollection{}, err
	}
	current, err := c.client.ListContainerStats(ctx)
	if err != nil {
		return ContainerRuntimeStatsCollection{}, err
	}
	checksum := checksumContainerRuntimeStats(current)
	out := ContainerRuntimeStatsCollection{
		Source:            c.source,
		WindowStart:       start,
		WindowEnd:         end,
		QueryVersion:      c.queryVersion,
		RawSampleChecksum: checksum,
		Samples:           []ContainerMetricSample{},
	}
	previous := map[string]ContainerRuntimeStat{}
	for _, stat := range in.Previous {
		id := strings.TrimSpace(stat.ContainerID)
		if id != "" {
			previous[id] = stat
		}
	}
	windowHours := end.Sub(start).Hours()
	for _, stat := range current {
		containerID := strings.TrimSpace(stat.ContainerID)
		if containerID == "" {
			continue
		}
		labels := copyStringMap(stat.Labels)
		if prev, ok := previous[containerID]; ok {
			delta := stat.CumulativeCPUMillicoreSeconds - prev.CumulativeCPUMillicoreSeconds
			if delta < 0 {
				delta = stat.CumulativeCPUMillicoreSeconds
			}
			if delta >= 0 {
				out.Samples = append(out.Samples, containerRuntimeSample("container_cpu_millicore_seconds", containerID, delta, "millicore_second", start, end, c.source, c.queryVersion, checksum, labels))
			}
		}
		if stat.MemoryMB >= 0 {
			out.Samples = append(out.Samples, containerRuntimeSample("container_memory_mb_hours", containerID, stat.MemoryMB*windowHours, "mb_hour", start, end, c.source, c.queryVersion, checksum, labels))
		}
	}
	sort.Slice(out.Samples, func(i, j int) bool {
		if out.Samples[i].ContainerID == out.Samples[j].ContainerID {
			return out.Samples[i].Name < out.Samples[j].Name
		}
		return out.Samples[i].ContainerID < out.Samples[j].ContainerID
	})
	return out, nil
}

func validateContainerRuntimeStatsCollectInput(start, end time.Time) error {
	var violations []apierr.FieldViolation
	if start.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "start", Reason: "is required"})
	}
	if end.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "end", Reason: "is required"})
	} else if !end.After(start) {
		violations = append(violations, apierr.FieldViolation{Field: "end", Reason: "must be after start"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func containerRuntimeSample(name, containerID string, value float64, unit string, start, end time.Time, source, version, checksum string, labels map[string]string) ContainerMetricSample {
	return ContainerMetricSample{
		Name:              name,
		ContainerID:       containerID,
		Value:             value,
		Unit:              unit,
		WindowStart:       start,
		WindowEnd:         end,
		Source:            source,
		QueryVersion:      version,
		RawSampleChecksum: checksum,
		Labels:            labels,
	}
}

func checksumContainerRuntimeStats(stats []ContainerRuntimeStat) string {
	normalized := append([]ContainerRuntimeStat(nil), stats...)
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].ContainerID < normalized[j].ContainerID
	})
	raw, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
