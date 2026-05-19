package store

import (
	"strings"
	"testing"
)

// Unit tests for the quota repository's pure decision logic — the closed
// resource set and id minting — that need no database.

func TestQuotaResourceValid(t *testing.T) {
	t.Parallel()

	valid := []QuotaResource{
		QuotaResourceProjects, QuotaResourceEnvironments, QuotaResourceServices,
		QuotaResourceApplications, QuotaResourceComposeStacks, QuotaResourceDatabases,
		QuotaResourceDomains, QuotaResourcePreviewEnvironments, QuotaResourceCPUMillicores,
		QuotaResourceMemoryMB, QuotaResourceStorageGB, QuotaResourceBackups,
		QuotaResourceBackupSchedules, QuotaResourceAPIKeys, QuotaResourceMembers,
		QuotaResourceConcurrentDeployments, QuotaResourceMonthlyDeployments,
		QuotaResourceDeployments, QuotaResourceFailedDeployments, QuotaResourceBuildMinutes,
		QuotaResourceHTTPRequests, QuotaResourceHTTPResponseBytes, QuotaResourceHTTPRequestBytes,
		QuotaResourceHTTPBandwidthTotal, QuotaResourceHTTPRPSPeak1m, QuotaResourceHTTP5xxCount,
		QuotaResourceLatencyP95MS,
		QuotaResourceContainerCPUMillicoreSeconds, QuotaResourceContainerMemoryMBHours, QuotaResourceStorageGBMonth,
		QuotaResourceBackupStorageGBMonth, QuotaResourceActiveServices, QuotaResourceActiveDatabases,
	}
	if len(valid) != len(quotaResources) {
		t.Fatalf("constant count = %d, membership set size = %d; keep them in lockstep", len(valid), len(quotaResources))
	}
	for _, r := range valid {
		if !r.Valid() {
			t.Errorf("QuotaResource(%q).Valid() = false, want true", r)
		}
		if r.String() != string(r) {
			t.Errorf("QuotaResource(%q).String() = %q, want %q", r, r.String(), string(r))
		}
	}
	for _, r := range []QuotaResource{"", "project", "Projects", "unknown", "cpu", "vms"} {
		if r.Valid() {
			t.Errorf("QuotaResource(%q).Valid() = true, want false", r)
		}
	}
}

func TestNewQuotaIDUniqueAndPrefixed(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		id, err := newQuotaID("qres")
		if err != nil {
			t.Fatalf("newQuotaID: %v", err)
		}
		if !strings.HasPrefix(id, "qres_") {
			t.Fatalf("newQuotaID returned %q, want a qres_ prefix", id)
		}
		if len(id) <= len("qres_") {
			t.Fatalf("newQuotaID returned %q, want entropy after the prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("newQuotaID produced a duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
}
