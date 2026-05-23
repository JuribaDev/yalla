package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

const defaultDokployMetricsQueryVersion = "dokploy-monitoring-v1"

// DokployMonitoringClient is the typed private Dokploy monitoring surface the
// metering adapter consumes.
type DokployMonitoringClient interface {
	ReadAppMonitoring(context.Context, dokploy.ReadAppMonitoringInput) (dokploy.MonitoringPayload, error)
	GetContainerMetrics(context.Context, dokploy.GetContainerMetricsInput) (dokploy.MonitoringPayload, error)
	GetServerMetrics(context.Context, dokploy.GetServerMetricsInput) (dokploy.MonitoringPayload, error)
	GetUserServerMetrics(context.Context) (dokploy.MonitoringPayload, error)
}

// DokployMetricsAdapterConfig configures the Dokploy monitoring source adapter.
type DokployMetricsAdapterConfig struct {
	Client       DokployMonitoringClient
	ServerURL    string
	ServerToken  string
	QueryVersion string
}

// DokployMetricsAdapter normalizes private Dokploy monitoring payloads into
// Yalla metric samples. It is an operational input, not a billing oracle.
type DokployMetricsAdapter struct {
	client       DokployMonitoringClient
	serverURL    string
	serverToken  string
	queryVersion string
}

// DokployMetricsCollectInput selects one bounded Dokploy monitoring window.
type DokployMetricsCollectInput struct {
	ApplicationName string
	ServerName      string
	Start           time.Time
	End             time.Time
	DataPoints      int
}

// DokployMetricsCollection is one normalized Dokploy monitoring collection.
type DokployMetricsCollection struct {
	Source             string
	WindowStart        time.Time
	WindowEnd          time.Time
	QueryVersion       string
	RawSampleChecksum  string
	Samples            []DokployMetricSample
	UnavailableSources []DokployMetricsUnavailableSource
}

// DokployMetricSample is one normalized numeric leaf from Dokploy monitoring.
type DokployMetricSample struct {
	Name              string
	Value             float64
	Unit              string
	Source            string
	BillingGrade      bool
	WindowStart       time.Time
	WindowEnd         time.Time
	QueryVersion      string
	RawSampleChecksum string
	Labels            map[string]string
}

// DokployMetricsUnavailableSource records a configured monitoring source that
// could not be read without failing the whole collection window.
type DokployMetricsUnavailableSource struct {
	Source    string
	ErrorCode string
}

// NewDokployMetricsAdapter validates config and returns a source adapter.
func NewDokployMetricsAdapter(cfg DokployMetricsAdapterConfig) (*DokployMetricsAdapter, error) {
	if cfg.Client == nil {
		return nil, errors.New("metering: dokploy metrics client must not be nil")
	}
	version := strings.TrimSpace(cfg.QueryVersion)
	if version == "" {
		version = defaultDokployMetricsQueryVersion
	}
	return &DokployMetricsAdapter{
		client:       cfg.Client,
		serverURL:    strings.TrimSpace(cfg.ServerURL),
		serverToken:  strings.TrimSpace(cfg.ServerToken),
		queryVersion: version,
	}, nil
}

// Collect reads configured Dokploy monitoring sources and normalizes numeric
// leaves into deterministic samples. Unavailable optional sources are reported
// in the result instead of aborting the window.
func (a *DokployMetricsAdapter) Collect(ctx context.Context, in DokployMetricsCollectInput) (DokployMetricsCollection, error) {
	if a == nil {
		return DokployMetricsCollection{}, errors.New("metering: nil DokployMetricsAdapter")
	}
	start := in.Start.UTC()
	end := in.End.UTC()
	if err := validateDokployMetricsCollectInput(in, start, end); err != nil {
		return DokployMetricsCollection{}, err
	}
	result := DokployMetricsCollection{
		Source:       "dokploy",
		WindowStart:  start,
		WindowEnd:    end,
		QueryVersion: a.queryVersion,
		Samples:      []DokployMetricSample{},
	}

	raw := map[string]dokploy.MonitoringPayload{}
	collect := func(source string, payload dokploy.MonitoringPayload, err error) {
		if err != nil {
			result.UnavailableSources = append(result.UnavailableSources, DokployMetricsUnavailableSource{
				Source:    source,
				ErrorCode: stableErrorCode(err),
			})
			return
		}
		raw[source] = payload
		prefix := source
		if source == "user_server" {
			prefix = "user_server"
		}
		result.Samples = append(result.Samples, normalizeDokployPayload(prefix, payload, start, end, a.queryVersion)...)
	}

	payload, err := a.client.ReadAppMonitoring(ctx, dokploy.ReadAppMonitoringInput{AppName: in.ApplicationName})
	collect("application", payload, err)
	if a.serverURL != "" || a.serverToken != "" {
		node := dokploy.GetServerMetricsInput{URL: a.serverURL, Token: a.serverToken, DataPoints: in.DataPoints}
		payload, err = a.client.GetContainerMetrics(ctx, dokploy.GetContainerMetricsInput{
			URL:        node.URL,
			Token:      node.Token,
			AppName:    in.ApplicationName,
			DataPoints: node.DataPoints,
		})
		collect("container", payload, err)
		payload, err = a.client.GetServerMetrics(ctx, node)
		collect("server", payload, err)
	}
	payload, err = a.client.GetUserServerMetrics(ctx)
	collect("user_server", payload, err)

	checksum := checksumDokployMonitoring(raw)
	result.RawSampleChecksum = checksum
	sort.Slice(result.Samples, func(i, j int) bool {
		return result.Samples[i].Name < result.Samples[j].Name
	})
	for i := range result.Samples {
		result.Samples[i].RawSampleChecksum = checksum
	}
	return result, nil
}

func validateDokployMetricsCollectInput(in DokployMetricsCollectInput, start, end time.Time) error {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(in.ApplicationName) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "application_name", Reason: "is required"})
	}
	if start.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "start", Reason: "is required"})
	}
	if end.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "end", Reason: "is required"})
	} else if !end.After(start) {
		violations = append(violations, apierr.FieldViolation{Field: "end", Reason: "must be after start"})
	}
	if in.DataPoints < 1 {
		violations = append(violations, apierr.FieldViolation{Field: "data_points", Reason: "must be positive"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func normalizeDokployPayload(prefix string, payload map[string]any, start, end time.Time, version string) []DokployMetricSample {
	var out []DokployMetricSample
	walkDokployPayload(prefix, payload, func(name string, value float64, labels map[string]string) {
		name, unit := normalizeDokployMetricName(name)
		def, billing := LookupMetricDefinition(name)
		if billing {
			unit = def.Unit
		}
		out = append(out, DokployMetricSample{
			Name:         name,
			Value:        value,
			Unit:         unit,
			Source:       "dokploy",
			BillingGrade: billing && def.BillingGrade,
			WindowStart:  start,
			WindowEnd:    end,
			QueryVersion: version,
			Labels:       labels,
		})
	})
	return out
}

func walkDokployPayload(prefix string, value any, emit func(string, float64, map[string]string)) {
	switch v := value.(type) {
	case map[string]any:
		if raw, ok := numericValue(v["value"]); ok {
			labels := map[string]string{}
			for _, key := range []string{"container_id", "container", "app", "name"} {
				if s, ok := v[key].(string); ok && strings.TrimSpace(s) != "" {
					labels[key] = strings.TrimSpace(s)
				}
			}
			emit(prefix, raw, labels)
			return
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "timestamp" || key == "time" {
				continue
			}
			next := key
			if prefix != "" {
				next = prefix + "." + key
			}
			walkDokployPayload(next, v[key], emit)
		}
	case []any:
		for _, item := range v {
			walkDokployPayload(prefix, item, emit)
		}
	default:
		if raw, ok := numericValue(v); ok {
			emit(prefix, raw, nil)
		}
	}
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func normalizeDokployMetricName(name string) (string, string) {
	name = strings.Trim(strings.ReplaceAll(name, "..", "."), ".")
	switch {
	case strings.HasPrefix(name, "container.cpu_millicore_seconds"):
		return "container_cpu_millicore_seconds", "millicore_second"
	case strings.HasPrefix(name, "container.memory_mb_hours"):
		return "container_memory_mb_hours", "mb_hour"
	case strings.Contains(name, "bytes"):
		return name, "byte"
	case strings.Contains(name, "percent"):
		return name, "percent"
	case strings.Contains(name, "millicore"):
		return name, "millicore"
	case strings.Contains(name, "requests") || strings.HasSuffix(name, ".count"):
		return name, "count"
	default:
		return name, "count"
	}
}

func checksumDokployMonitoring(raw map[string]dokploy.MonitoringPayload) string {
	b, err := json.Marshal(raw)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stableErrorCode(err error) string {
	var ye *yerr.Error
	if errors.As(err, &ye) {
		return string(ye.Code)
	}
	return string(yerr.CodeInternal)
}

func (s DokployMetricSample) String() string {
	return fmt.Sprintf("%s=%g %s", s.Name, s.Value, s.Unit)
}
