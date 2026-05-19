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

func TestHTTPRPSPeak1mMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_rps_peak_1m")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_rps_peak_1m) missing")
	}
	if def.Key != "http_rps_peak_1m" || def.Unit != "requests_per_second" || def.Source != "traefik" || def.Enforcement != MetricEnforcementSoft || def.BillingGrade {
		t.Fatalf("http_rps_peak_1m definition = %+v, want requests_per_second/traefik/soft/non-billing-grade", def)
	}
}

func TestHTTP5xxCountMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_5xx_count")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_5xx_count) missing")
	}
	if def.Key != "http_5xx_count" || def.Unit != "response" || def.Source != "traefik" || def.Enforcement != MetricEnforcementObservability || def.BillingGrade {
		t.Fatalf("http_5xx_count definition = %+v, want response/traefik/observability/non-billing-grade", def)
	}
}

func TestLatencyP95MSMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("latency_p95_ms")
	if !ok {
		t.Fatal("LookupMetricDefinition(latency_p95_ms) missing")
	}
	if def.Key != "latency_p95_ms" || def.Unit != "millisecond" || def.Source != "traefik" || def.Enforcement != MetricEnforcementObservability || def.BillingGrade {
		t.Fatalf("latency_p95_ms definition = %+v, want millisecond/traefik/observability/non-billing-grade", def)
	}
}

func TestHTTPResponseBytesMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_response_bytes")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_response_bytes) missing")
	}
	if def.Key != "http_response_bytes" || def.Unit != "byte" || def.Source != "traefik" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("http_response_bytes definition = %+v, want byte/traefik/metered/billing-grade", def)
	}
}

func TestHTTPRequestBytesMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_request_bytes")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_request_bytes) missing")
	}
	if def.Key != "http_request_bytes" || def.Unit != "byte" || def.Source != "traefik" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("http_request_bytes definition = %+v, want byte/traefik/metered/billing-grade", def)
	}
}

func TestHTTPBandwidthTotalMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("http_bandwidth_total")
	if !ok {
		t.Fatal("LookupMetricDefinition(http_bandwidth_total) missing")
	}
	if def.Key != "http_bandwidth_total" || def.Unit != "byte" || def.Source != "traefik" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("http_bandwidth_total definition = %+v, want byte/traefik/metered/billing-grade", def)
	}
}

func TestContainerCPUMillicoreSecondsMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("container_cpu_millicore_seconds")
	if !ok {
		t.Fatal("LookupMetricDefinition(container_cpu_millicore_seconds) missing")
	}
	if def.Key != "container_cpu_millicore_seconds" || def.Unit != "millicore_second" || def.Source != "dokploy_or_cadvisor" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("container_cpu_millicore_seconds definition = %+v, want millicore_second/dokploy_or_cadvisor/metered/billing-grade", def)
	}
}

func TestContainerMemoryMBHoursMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("container_memory_mb_hours")
	if !ok {
		t.Fatal("LookupMetricDefinition(container_memory_mb_hours) missing")
	}
	if def.Key != "container_memory_mb_hours" || def.Unit != "mb_hour" || def.Source != "dokploy_or_cadvisor" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("container_memory_mb_hours definition = %+v, want mb_hour/dokploy_or_cadvisor/metered/billing-grade", def)
	}
}

func TestStorageGBMonthMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("storage_gb_month")
	if !ok {
		t.Fatal("LookupMetricDefinition(storage_gb_month) missing")
	}
	if def.Key != "storage_gb_month" || def.Unit != "gb_month" || def.Source != "volume_scanner" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("storage_gb_month definition = %+v, want gb_month/volume_scanner/metered/billing-grade", def)
	}
}

func TestBackupStorageGBMonthMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("backup_storage_gb_month")
	if !ok {
		t.Fatal("LookupMetricDefinition(backup_storage_gb_month) missing")
	}
	if def.Key != "backup_storage_gb_month" || def.Unit != "gb_month" || def.Source != "backup_metadata" || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("backup_storage_gb_month definition = %+v, want gb_month/backup_metadata/metered/billing-grade", def)
	}
}

func TestBuildMinutesMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("build_minutes")
	if !ok {
		t.Fatal("LookupMetricDefinition(build_minutes) missing")
	}
	if def.Key != "build_minutes" || def.Unit != "minute" || def.Source != BuildMinutesUsageSource || def.Enforcement != MetricEnforcementMetered || !def.BillingGrade {
		t.Fatalf("build_minutes definition = %+v, want minute/yalla_jobs/metered/billing-grade", def)
	}
}

func TestDeploymentsMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("deployments")
	if !ok {
		t.Fatal("LookupMetricDefinition(deployments) missing")
	}
	if def.Key != "deployments" || def.Unit != "deployment" || def.Source != DeploymentUsageSource || def.Enforcement != MetricEnforcementHardOrMetered || !def.BillingGrade {
		t.Fatalf("deployments definition = %+v, want deployment/yalla_events/hard_or_metered/billing-grade", def)
	}
}

func TestActiveServicesMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("active_services")
	if !ok {
		t.Fatal("LookupMetricDefinition(active_services) missing")
	}
	if def.Key != "active_services" || def.Unit != "service" || def.Source != CurrentStateUsageSource || def.Enforcement != MetricEnforcementHard || def.BillingGrade {
		t.Fatalf("active_services definition = %+v, want service/yalla_current_state/hard/non-billing-grade", def)
	}
}

func TestActiveDatabasesMetricDefinition(t *testing.T) {
	t.Parallel()

	def, ok := LookupMetricDefinition("active_databases")
	if !ok {
		t.Fatal("LookupMetricDefinition(active_databases) missing")
	}
	if def.Key != "active_databases" || def.Unit != "database" || def.Source != CurrentStateUsageSource || def.Enforcement != MetricEnforcementHard || def.BillingGrade {
		t.Fatalf("active_databases definition = %+v, want database/yalla_current_state/hard/non-billing-grade", def)
	}
}
