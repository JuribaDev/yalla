package backoffice

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestStoreImpactReaderReadsCurrentUsageAndValidatesOrganizations(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	reader, err := NewStoreImpactReader(s)
	if err != nil {
		t.Fatalf("NewStoreImpactReader: %v", err)
	}
	f := testutil.NewFactory(t)
	org := f.Organization("impact")
	now := time.Date(2026, 5, 19, 8, 0, 0, 0, time.UTC)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		org.ID, org.Slug, org.Name); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if _, err := db.Exec(context.Background(),
		`INSERT INTO usage_counters
		    (id, organization_id, key, unit, period_start, period_end, quantity, source, aggregation_version, last_aggregated_at)
		 VALUES ($1, $2, 'services', 'service', $3, $4, 7, 'dry_run_test', 1, $5),
		        ($6, $2, 'services', 'service', $7, $3, 99, 'dry_run_test', 1, $5)`,
		"usage_current", org.ID, now.Add(-time.Hour), now.Add(time.Hour), now, "usage_old", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("insert usage counters: %v", err)
	}

	usage, err := reader.UsageByOrganization(context.Background(), []string{org.ID}, now)
	if err != nil {
		t.Fatalf("UsageByOrganization: %v", err)
	}
	if got := usage[org.ID]["services"]; got != 7 {
		t.Fatalf("usage services = %v, want current-period sum 7", got)
	}

	missing := f.Organization("missing")
	_, err = reader.UsageByOrganization(context.Background(), []string{missing.ID}, now)
	if code := yerr.From(err).Code; code != yerr.CodeNotFound {
		t.Fatalf("missing org code = %s, want %s; err %v", code, yerr.CodeNotFound, err)
	}
}
