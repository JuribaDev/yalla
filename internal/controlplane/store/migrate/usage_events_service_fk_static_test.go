package migrate

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

const (
	usageEventsMeteringContractUpPath   = "migrations/0051_usage_events_metering_contract.up.sql"
	usageEventsMeteringContractDownPath = "migrations/0051_usage_events_metering_contract.down.sql"
	servicesHierarchyIdentityConstraint = "services_hierarchy_identity_key"
)

// TestUsageEventsServiceFKMigrationDeclaresTargetKey pins the PostgreSQL
// requirement behind the usage_events service foreign key: the referenced
// services column set must be unique before the FK is added.
func TestUsageEventsServiceFKMigrationDeclaresTargetKey(t *testing.T) {
	t.Parallel()

	sql := mustReadMigration(t, usageEventsMeteringContractUpPath)
	if !hasServicesHierarchyIdentityKey(sql) {
		t.Fatalf("%s: missing `%s` on services (organization_id, project_id, environment_id, id). "+
			"PostgreSQL requires the exact referenced column set to be unique before `usage_events_service_fk` can reference it.",
			usageEventsMeteringContractUpPath, servicesHierarchyIdentityConstraint)
	}
	if servicesKey := strings.Index(sql, servicesHierarchyIdentityConstraint); servicesKey >= 0 {
		serviceFK := strings.Index(sql, "usage_events_service_fk")
		if serviceFK < 0 {
			t.Fatalf("%s: usage_events_service_fk not found", usageEventsMeteringContractUpPath)
		}
		if servicesKey > serviceFK {
			t.Fatalf("%s: `%s` must be declared before `usage_events_service_fk`; otherwise an empty-DB migration ladder fails on PostgreSQL.",
				usageEventsMeteringContractUpPath, servicesHierarchyIdentityConstraint)
		}
	}
}

// TestUsageEventsServiceFKDownMigrationDropsTargetKey pins the reverse path so
// a 0051 down migration removes the auxiliary unique key after dropping the FK.
func TestUsageEventsServiceFKDownMigrationDropsTargetKey(t *testing.T) {
	t.Parallel()

	sql := mustReadMigration(t, usageEventsMeteringContractDownPath)
	if !hasDropServicesHierarchyIdentityKey(sql) {
		t.Fatalf("%s: missing `ALTER TABLE services DROP CONSTRAINT IF EXISTS %s`; the 0051 down migration must reverse the key it added.",
			usageEventsMeteringContractDownPath, servicesHierarchyIdentityConstraint)
	}
}

func mustReadMigration(t *testing.T, path string) string {
	t.Helper()

	content, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func hasServicesHierarchyIdentityKey(sql string) bool {
	return regexp.MustCompile(`(?is)ALTER\s+TABLE\s+services\s+ADD\s+CONSTRAINT\s+` +
		regexp.QuoteMeta(servicesHierarchyIdentityConstraint) +
		`\s+UNIQUE\s*\(\s*organization_id\s*,\s*project_id\s*,\s*environment_id\s*,\s*id\s*\)`).MatchString(sql)
}

func hasDropServicesHierarchyIdentityKey(sql string) bool {
	return regexp.MustCompile(`(?is)ALTER\s+TABLE\s+services\s+DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+` +
		regexp.QuoteMeta(servicesHierarchyIdentityConstraint)).MatchString(sql)
}
