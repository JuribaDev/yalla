package metering

import "testing"

func TestHTTPRequestsMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_requests")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_requests) missing")
	}
	if def.Key != "http_requests" || def.Unit != "request" || def.Source != "traefik" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("http_requests definition = %+v, want request/traefik/metered/billing-grade", def)
	}
}
