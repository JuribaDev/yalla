package backoffice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

func TestRuntimeConfigCacheReloadsPublishedConfigWithVersionIdentifiers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	loader := &fakeRuntimeConfigLoader{
		snapshots: [][]RuntimeConfigItem{{
			runtimeConfigItem("cfg_pricing", store.AdminConfigDomainPricing, "cfgver_pricing_v1", 1, 7, []byte(`{"plans":[{"slug":"starter"}]}`)),
			runtimeConfigItem("cfg_features", store.AdminConfigDomainFeatures, "cfgver_features_v3", 3, 11, []byte(`{"flags":[]}`)),
		}},
	}
	cache := NewRuntimeConfigCache(loader, RuntimeConfigCacheOptions{Now: func() time.Time { return now }})

	snapshot, err := cache.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if snapshot.LoadedAt != now {
		t.Fatalf("LoadedAt = %s, want %s", snapshot.LoadedAt, now)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("Generation = %d, want 1", snapshot.Generation)
	}
	if got, want := len(snapshot.Items), 2; got != want {
		t.Fatalf("len(Items) = %d, want %d", got, want)
	}
	pricing, ok := snapshot.ByConfigSetID("cfg_pricing")
	if !ok {
		t.Fatalf("ByConfigSetID(cfg_pricing) missing")
	}
	if pricing.VersionID != "cfgver_pricing_v1" || pricing.Version != 1 || pricing.Revision != 7 || string(pricing.Payload) != `{"plans":[{"slug":"starter"}]}` {
		t.Fatalf("pricing item = %+v", pricing)
	}
	byDomain := snapshot.ByDomain(store.AdminConfigDomainPricing)
	if len(byDomain) != 1 || byDomain[0].ConfigSetID != "cfg_pricing" {
		t.Fatalf("ByDomain(pricing) = %+v", byDomain)
	}
}

func TestRuntimeConfigCacheKeepsLastKnownGoodAndAlertsOnReloadFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	loadErr := errors.New("postgres unavailable")
	var alerts []RuntimeConfigAlert
	loader := &fakeRuntimeConfigLoader{
		snapshots: [][]RuntimeConfigItem{{
			runtimeConfigItem("cfg_metering", store.AdminConfigDomainMetering, "cfgver_metering_v1", 1, 2, []byte(`{"metric_definitions":[]}`)),
		}},
		errs: []error{nil, loadErr},
	}
	cache := NewRuntimeConfigCache(loader, RuntimeConfigCacheOptions{
		Now:     func() time.Time { return now },
		AlertFn: func(_ context.Context, alert RuntimeConfigAlert) { alerts = append(alerts, alert) },
	})
	first, err := cache.Reload(ctx)
	if err != nil {
		t.Fatalf("initial Reload: %v", err)
	}

	now = now.Add(time.Minute)
	got, err := cache.Reload(ctx)
	if !errors.Is(err, loadErr) {
		t.Fatalf("second Reload error = %v, want %v", err, loadErr)
	}
	if got.Generation != first.Generation || got.LoadedAt != first.LoadedAt {
		t.Fatalf("failed reload snapshot = %+v, want last known good %+v", got, first)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want one reload failure alert", alerts)
	}
	if alerts[0].Kind != RuntimeConfigAlertReloadFailed || alerts[0].Err == nil || alerts[0].Snapshot.Generation != first.Generation {
		t.Fatalf("alert = %+v", alerts[0])
	}
}

func TestRuntimeConfigCacheMarksSnapshotStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	var alerts []RuntimeConfigAlert
	cache := NewRuntimeConfigCache(&fakeRuntimeConfigLoader{
		snapshots: [][]RuntimeConfigItem{{
			runtimeConfigItem("cfg_billing", store.AdminConfigDomainBilling, "cfgver_billing_v1", 1, 4, []byte(`{"providers":[]}`)),
		}},
	}, RuntimeConfigCacheOptions{
		Now:         func() time.Time { return now },
		StaleAfter:  5 * time.Minute,
		StaleWarnIn: time.Minute,
		AlertFn:     func(_ context.Context, alert RuntimeConfigAlert) { alerts = append(alerts, alert) },
	})
	if _, err := cache.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	now = now.Add(6 * time.Minute)
	snapshot := cache.Snapshot()
	if !snapshot.Stale {
		t.Fatalf("Snapshot stale = false, want true")
	}
	if snapshot.Age != 6*time.Minute {
		t.Fatalf("Snapshot age = %s, want 6m", snapshot.Age)
	}
	if len(alerts) != 1 || alerts[0].Kind != RuntimeConfigAlertStale {
		t.Fatalf("alerts = %+v, want one stale alert", alerts)
	}

	_ = cache.Snapshot()
	if len(alerts) != 1 {
		t.Fatalf("stale alert repeated: %+v", alerts)
	}
}

func TestRuntimeConfigCacheConcurrentReadersSeeImmutableSnapshots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	loader := &fakeRuntimeConfigLoader{
		snapshots: [][]RuntimeConfigItem{{
			runtimeConfigItem("cfg_features", store.AdminConfigDomainFeatures, "cfgver_features_v1", 1, 1, []byte(`{"flags":["a"]}`)),
		}, {
			runtimeConfigItem("cfg_features", store.AdminConfigDomainFeatures, "cfgver_features_v2", 2, 2, []byte(`{"flags":["b"]}`)),
		}},
	}
	cache := NewRuntimeConfigCache(loader, RuntimeConfigCacheOptions{})
	if _, err := cache.Reload(ctx); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				snapshot := cache.Snapshot()
				item, ok := snapshot.ByConfigSetID("cfg_features")
				if !ok {
					errs <- errors.New("cfg_features missing")
					return
				}
				item.Payload[0] = '!'
			}
		}()
	}
	if _, err := cache.Reload(ctx); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	snapshot := cache.Snapshot()
	item, ok := snapshot.ByConfigSetID("cfg_features")
	if !ok {
		t.Fatalf("cfg_features missing after concurrent reads")
	}
	if item.VersionID != "cfgver_features_v2" || string(item.Payload) != `{"flags":["b"]}` {
		t.Fatalf("post-concurrency item = %+v", item)
	}
}

type fakeRuntimeConfigLoader struct {
	mu        sync.Mutex
	snapshots [][]RuntimeConfigItem
	errs      []error
	calls     int
}

func (f *fakeRuntimeConfigLoader) LoadRuntimeConfig(context.Context, time.Time) ([]RuntimeConfigItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.calls
	f.calls++
	if call < len(f.errs) && f.errs[call] != nil {
		return nil, f.errs[call]
	}
	if call >= len(f.snapshots) {
		call = len(f.snapshots) - 1
	}
	out := make([]RuntimeConfigItem, len(f.snapshots[call]))
	copy(out, f.snapshots[call])
	return out, nil
}

func runtimeConfigItem(configSetID string, domain store.AdminConfigDomain, versionID string, version int, revision int64, payload []byte) RuntimeConfigItem {
	return RuntimeConfigItem{
		ConfigSetID: configSetID,
		Domain:      domain,
		VersionID:   versionID,
		Version:     version,
		Revision:    revision,
		Payload:     payload,
	}
}
