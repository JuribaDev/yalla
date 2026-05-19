// Package metering contains source adapters that turn operational metrics into
// deterministic, auditable samples for later attribution and usage aggregation.
package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTraefikQueryVersion = "traefik-prom-v1"
	defaultTraefikMaxWindow    = 24 * time.Hour
)

// TraefikAdapterConfig configures a Prometheus-compatible Traefik metrics source.
type TraefikAdapterConfig struct {
	BaseURL      string
	BearerToken  string
	QueryVersion string
	MaxWindow    time.Duration
	HTTPClient   *http.Client
}

// TraefikAdapter queries a Prometheus-compatible API for Traefik service metrics.
type TraefikAdapter struct {
	baseURL      *url.URL
	bearerToken  string
	queryVersion string
	maxWindow    time.Duration
	client       *http.Client
}

// TraefikCollectInput selects one bounded metrics window.
type TraefikCollectInput struct {
	Start time.Time
	End   time.Time
	Step  time.Duration
}

// TraefikCollection is one audited collection result. Attribution to Yalla
// tenant resources is intentionally left to the attribution layer.
type TraefikCollection struct {
	WindowStart       time.Time
	WindowEnd         time.Time
	QueryVersion      string
	RawSampleChecksum string
	DroppedSeries     int
	Samples           []TraefikMetricSample
}

// TraefikMetricSample is one normalized Traefik metric over a collection window.
type TraefikMetricSample struct {
	Name              string
	Service           string
	Status            string
	Bucket            string
	Value             float64
	Unit              string
	WindowStart       time.Time
	WindowEnd         time.Time
	QueryVersion      string
	RawSampleChecksum string
	Labels            map[string]string
}

type traefikMetricQuery struct {
	promMetric string
	name       string
	unit       string
}

var traefikQueries = []traefikMetricQuery{
	{promMetric: "traefik_service_requests_total", name: "http_requests", unit: "request"},
	{promMetric: "traefik_service_requests_bytes_total", name: "http_request_bytes", unit: "byte"},
	{promMetric: "traefik_service_responses_bytes_total", name: "http_response_bytes", unit: "byte"},
	{promMetric: "traefik_service_request_duration_seconds_bucket", name: "http_request_duration_seconds_bucket", unit: "observation"},
}

// NewTraefikAdapter validates config and returns a source adapter.
func NewTraefikAdapter(cfg TraefikAdapterConfig) (*TraefikAdapter, error) {
	rawURL := strings.TrimSpace(cfg.BaseURL)
	if rawURL == "" {
		return nil, errors.New("metering: traefik base URL must not be blank")
	}
	base, err := url.Parse(rawURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("metering: traefik base URL must be an absolute http(s) URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, errors.New("metering: traefik base URL must use http or https")
	}
	version := strings.TrimSpace(cfg.QueryVersion)
	if version == "" {
		version = defaultTraefikQueryVersion
	}
	maxWindow := cfg.MaxWindow
	if maxWindow == 0 {
		maxWindow = defaultTraefikMaxWindow
	}
	if maxWindow < 0 {
		return nil, errors.New("metering: max window must be positive")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &TraefikAdapter{
		baseURL:      base,
		bearerToken:  strings.TrimSpace(cfg.BearerToken),
		queryVersion: version,
		maxWindow:    maxWindow,
		client:       client,
	}, nil
}

// Collect queries Traefik metrics for one bounded window and normalizes
// Prometheus counter matrices into deterministic window samples.
func (a *TraefikAdapter) Collect(ctx context.Context, in TraefikCollectInput) (TraefikCollection, error) {
	if a == nil {
		return TraefikCollection{}, errors.New("metering: nil TraefikAdapter")
	}
	start := in.Start.UTC()
	end := in.End.UTC()
	if start.IsZero() {
		return TraefikCollection{}, errors.New("metering: start must not be zero")
	}
	if end.IsZero() {
		return TraefikCollection{}, errors.New("metering: end must not be zero")
	}
	if !end.After(start) {
		return TraefikCollection{}, errors.New("metering: end must be after start")
	}
	if in.Step <= 0 {
		return TraefikCollection{}, errors.New("metering: step must be positive")
	}
	if a.maxWindow > 0 && end.Sub(start) > a.maxWindow {
		return TraefikCollection{}, fmt.Errorf("metering: window must be at most %s", a.maxWindow)
	}

	result := TraefikCollection{
		WindowStart:  start,
		WindowEnd:    end,
		QueryVersion: a.queryVersion,
		Samples:      []TraefikMetricSample{},
	}
	raw := make([]queryRawResult, 0, len(traefikQueries))
	samples := map[string]TraefikMetricSample{}
	var requestSeries []prometheusSeries
	for _, q := range traefikQueries {
		matrix, body, err := a.queryRange(ctx, q.promMetric, start, end, in.Step)
		if err != nil {
			return TraefikCollection{}, err
		}
		raw = append(raw, queryRawResult{metric: q.promMetric, body: body})
		if q.name == "http_requests" {
			requestSeries = append(requestSeries, matrix.Data.Result...)
		}
		for _, series := range matrix.Data.Result {
			sample, ok := normalizeTraefikSeries(q, series, start, end, a.queryVersion)
			if !ok {
				result.DroppedSeries++
				continue
			}
			key := sample.aggregateKey()
			if existing, ok := samples[key]; ok {
				existing.Value += sample.Value
				samples[key] = existing
				continue
			}
			samples[key] = sample
		}
	}
	addBandwidthSamples(samples, start, end, a.queryVersion)
	addRPSPeakSamples(samples, requestSeries, start, end, a.queryVersion)
	addHTTP5xxCountSamples(samples, start, end, a.queryVersion)

	checksum := checksumPrometheusResults(raw)
	result.RawSampleChecksum = checksum
	keys := make([]string, 0, len(samples))
	for key := range samples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sample := samples[key]
		sample.RawSampleChecksum = checksum
		result.Samples = append(result.Samples, sample)
	}
	return result, nil
}

func (a *TraefikAdapter) queryRange(ctx context.Context, query string, start, end time.Time, step time.Duration) (prometheusMatrixResponse, []byte, error) {
	endpoint := *a.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/query_range"
	q := endpoint.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.Unix(), 10))
	q.Set("end", strconv.FormatInt(end.Unix(), 10))
	q.Set("step", strconv.FormatInt(int64(step/time.Second), 10))
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return prometheusMatrixResponse{}, nil, fmt.Errorf("metering: build prometheus request: %w", err)
	}
	if a.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.bearerToken)
	}
	res, err := a.client.Do(req)
	if err != nil {
		return prometheusMatrixResponse{}, nil, fmt.Errorf("metering: query prometheus: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return prometheusMatrixResponse{}, nil, fmt.Errorf("metering: read prometheus response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return prometheusMatrixResponse{}, nil, fmt.Errorf("metering: prometheus returned HTTP %d", res.StatusCode)
	}
	var matrix prometheusMatrixResponse
	if err := json.Unmarshal(body, &matrix); err != nil {
		return prometheusMatrixResponse{}, nil, fmt.Errorf("metering: decode prometheus response: %w", err)
	}
	if matrix.Status != "success" {
		return prometheusMatrixResponse{}, nil, errors.New("metering: prometheus response status was not success")
	}
	if matrix.Data.ResultType != "matrix" {
		return prometheusMatrixResponse{}, nil, errors.New("metering: prometheus response resultType must be matrix")
	}
	return matrix, body, nil
}

func normalizeTraefikSeries(query traefikMetricQuery, series prometheusSeries, start, end time.Time, version string) (TraefikMetricSample, bool) {
	service := strings.TrimSpace(firstLabel(series.Metric, "service", "service_name", "traefik_service"))
	if service == "" {
		return TraefikMetricSample{}, false
	}
	status := strings.TrimSpace(firstLabel(series.Metric, "code", "status", "status_code"))
	bucket := ""
	if query.name == "http_request_duration_seconds_bucket" {
		bucket = strings.TrimSpace(series.Metric["le"])
		if bucket == "" {
			return TraefikMetricSample{}, false
		}
	}
	delta, ok := counterDelta(series.Values)
	if !ok {
		return TraefikMetricSample{}, false
	}
	labels := copyStringMap(series.Metric)
	return TraefikMetricSample{
		Name:         query.name,
		Service:      service,
		Status:       status,
		Bucket:       bucket,
		Value:        delta,
		Unit:         query.unit,
		WindowStart:  start,
		WindowEnd:    end,
		QueryVersion: version,
		Labels:       labels,
	}, true
}

func firstLabel(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}

func counterDelta(values []prometheusValue) (float64, bool) {
	var prev float64
	havePrev := false
	var total float64
	for _, point := range values {
		current, ok := point.Float()
		if !ok {
			continue
		}
		if !havePrev {
			prev = current
			havePrev = true
			continue
		}
		if current >= prev {
			total += current - prev
		} else {
			total += current
		}
		prev = current
	}
	return total, havePrev
}

func addBandwidthSamples(samples map[string]TraefikMetricSample, start, end time.Time, version string) {
	requestBytes := map[string]float64{}
	responseBytes := map[string]float64{}
	for _, sample := range samples {
		if sample.Status != "" || sample.Bucket != "" {
			continue
		}
		switch sample.Name {
		case "http_request_bytes":
			requestBytes[sample.Service] += sample.Value
		case "http_response_bytes":
			responseBytes[sample.Service] += sample.Value
		}
	}
	services := make(map[string]struct{}, len(requestBytes)+len(responseBytes))
	for service := range requestBytes {
		services[service] = struct{}{}
	}
	for service := range responseBytes {
		services[service] = struct{}{}
	}
	for service := range services {
		sample := TraefikMetricSample{
			Name:         "http_bandwidth_total",
			Service:      service,
			Value:        requestBytes[service] + responseBytes[service],
			Unit:         "byte",
			WindowStart:  start,
			WindowEnd:    end,
			QueryVersion: version,
			Labels:       map[string]string{"service": service},
		}
		samples[sample.aggregateKey()] = sample
	}
}

func addRPSPeakSamples(samples map[string]TraefikMetricSample, requestSeries []prometheusSeries, start, end time.Time, version string) {
	intervalRates := map[string]map[float64]float64{}
	for _, series := range requestSeries {
		service := strings.TrimSpace(firstLabel(series.Metric, "service", "service_name", "traefik_service"))
		if service == "" {
			continue
		}
		for _, interval := range counterRates(series.Values) {
			if intervalRates[service] == nil {
				intervalRates[service] = map[float64]float64{}
			}
			intervalRates[service][interval.timestamp] += interval.rate
		}
	}
	for service, byInterval := range intervalRates {
		var peak float64
		for _, rate := range byInterval {
			if rate > peak {
				peak = rate
			}
		}
		if peak <= 0 {
			continue
		}
		sample := TraefikMetricSample{
			Name:         "http_rps_peak_1m",
			Service:      service,
			Value:        peak,
			Unit:         "requests_per_second",
			WindowStart:  start,
			WindowEnd:    end,
			QueryVersion: version,
			Labels:       map[string]string{"service": service},
		}
		samples[sample.aggregateKey()] = sample
	}
}

func addHTTP5xxCountSamples(samples map[string]TraefikMetricSample, start, end time.Time, version string) {
	counts := map[string]float64{}
	for _, sample := range samples {
		if sample.Name != "http_requests" || sample.Status == "" || sample.Bucket != "" {
			continue
		}
		if !isHTTP5xxStatus(sample.Status) {
			continue
		}
		counts[sample.Service] += sample.Value
	}
	for service, value := range counts {
		if value <= 0 {
			continue
		}
		sample := TraefikMetricSample{
			Name:         "http_5xx_count",
			Service:      service,
			Value:        value,
			Unit:         "response",
			WindowStart:  start,
			WindowEnd:    end,
			QueryVersion: version,
			Labels:       map[string]string{"service": service},
		}
		samples[sample.aggregateKey()] = sample
	}
}

func isHTTP5xxStatus(status string) bool {
	if len(status) != 3 || status[0] != '5' {
		return false
	}
	return status[1] >= '0' && status[1] <= '9' && status[2] >= '0' && status[2] <= '9'
}

type counterRate struct {
	timestamp float64
	rate      float64
}

func counterRates(values []prometheusValue) []counterRate {
	var prev prometheusValue
	prevValue := 0.0
	havePrev := false
	rates := []counterRate{}
	for _, point := range values {
		current, ok := point.Float()
		if !ok {
			continue
		}
		if !havePrev {
			prev = point
			prevValue = current
			havePrev = true
			continue
		}
		elapsed := point.Timestamp - prev.Timestamp
		if elapsed <= 0 {
			prev = point
			prevValue = current
			continue
		}
		delta := current - prevValue
		if delta < 0 {
			delta = current
		}
		rates = append(rates, counterRate{timestamp: point.Timestamp, rate: delta / elapsed})
		prev = point
		prevValue = current
	}
	return rates
}

func (s TraefikMetricSample) aggregateKey() string {
	return s.Name + "\x00" + s.Service + "\x00" + s.Status + "\x00" + s.Bucket
}

type queryRawResult struct {
	metric string
	body   []byte
}

func checksumPrometheusResults(results []queryRawResult) string {
	h := sha256.New()
	sort.Slice(results, func(i, j int) bool { return results[i].metric < results[j].metric })
	for _, result := range results {
		_, _ = h.Write([]byte(result.metric))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(result.body)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type prometheusMatrixResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string             `json:"resultType"`
		Result     []prometheusSeries `json:"result"`
	} `json:"data"`
}

type prometheusSeries struct {
	Metric map[string]string `json:"metric"`
	Values []prometheusValue `json:"values"`
}

type prometheusValue struct {
	Timestamp float64
	Value     string
}

func (v *prometheusValue) UnmarshalJSON(raw []byte) error {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return errors.New("prometheus sample must be [timestamp, value]")
	}
	if err := json.Unmarshal(tuple[0], &v.Timestamp); err != nil {
		return err
	}
	if err := json.Unmarshal(tuple[1], &v.Value); err != nil {
		var f float64
		if numErr := json.Unmarshal(tuple[1], &f); numErr != nil {
			return err
		}
		v.Value = strconv.FormatFloat(f, 'g', -1, 64)
	}
	return nil
}

func (v prometheusValue) Float() (float64, bool) {
	f, err := strconv.ParseFloat(v.Value, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
