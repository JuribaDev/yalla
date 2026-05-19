package metering

import "strings"

// MetricEnforcement is the stable runtime category for a usage metric.
type MetricEnforcement string

const (
	// MetricEnforcementHard rejects usage above the configured limit.
	MetricEnforcementHard MetricEnforcement = "hard"
	// MetricEnforcementSoft records warning-grade usage without rejection.
	MetricEnforcementSoft MetricEnforcement = "soft"
	// MetricEnforcementMetered records billing-grade usage without a hard ceiling.
	MetricEnforcementMetered MetricEnforcement = "metered"
	// MetricEnforcementObservability records non-billing operational signals.
	MetricEnforcementObservability MetricEnforcement = "observability"
)

// MetricDefinition is the accepted runtime contract for one tracked metric.
type MetricDefinition struct {
	Key          string
	Unit         string
	Source       string
	Enforcement  MetricEnforcement
	BillingGrade bool
}

var metricDefinitions = map[string]MetricDefinition{
	"http_requests": {
		Key:          "http_requests",
		Unit:         "request",
		Source:       "traefik",
		Enforcement:  MetricEnforcementMetered,
		BillingGrade: true,
	},
}

// LookupMetricDefinition returns the accepted metric contract for key.
func LookupMetricDefinition(key string) (MetricDefinition, bool) {
	key = strings.TrimSpace(key)
	def, ok := metricDefinitions[key]
	return def, ok
}
