package backoffice

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// RuntimeConfigLoader loads the effective published backoffice configuration
// for one process. Implementations must return only runtime-active versions.
type RuntimeConfigLoader interface {
	LoadRuntimeConfig(ctx context.Context, at time.Time) ([]RuntimeConfigItem, error)
}

// RuntimeConfigItem is one effective published config version with the set
// revision token that invalidates local caches.
type RuntimeConfigItem struct {
	ConfigSetID string
	Domain      store.AdminConfigDomain
	VersionID   string
	Version     int
	Revision    int64
	Payload     []byte
}

// RuntimeConfigSnapshot is the immutable config view used by API, worker, and
// aggregator processes.
type RuntimeConfigSnapshot struct {
	Items      []RuntimeConfigItem
	LoadedAt   time.Time
	CheckedAt  time.Time
	Generation int64
	Age        time.Duration
	Stale      bool
}

// ByConfigSetID returns the item for a config set, if it is present.
func (s RuntimeConfigSnapshot) ByConfigSetID(id string) (RuntimeConfigItem, bool) {
	for _, item := range s.Items {
		if item.ConfigSetID == id {
			return cloneRuntimeConfigItem(item), true
		}
	}
	return RuntimeConfigItem{}, false
}

// ByDomain returns every active config item in the requested domain.
func (s RuntimeConfigSnapshot) ByDomain(domain store.AdminConfigDomain) []RuntimeConfigItem {
	out := make([]RuntimeConfigItem, 0)
	for _, item := range s.Items {
		if item.Domain == domain {
			out = append(out, cloneRuntimeConfigItem(item))
		}
	}
	return out
}

// RuntimeConfigAlertKind identifies a cache operational alert.
type RuntimeConfigAlertKind string

const (
	// RuntimeConfigAlertReloadFailed means a reload failed and the cache kept
	// serving the last known good snapshot.
	RuntimeConfigAlertReloadFailed RuntimeConfigAlertKind = "runtime_config_reload_failed"
	// RuntimeConfigAlertStale means the last known good snapshot exceeded its
	// configured staleness threshold.
	RuntimeConfigAlertStale RuntimeConfigAlertKind = "runtime_config_stale"
)

// RuntimeConfigAlert describes a cache operational condition. It carries the
// last known good snapshot but never raw database or credential values.
type RuntimeConfigAlert struct {
	Kind     RuntimeConfigAlertKind
	At       time.Time
	Err      error
	Snapshot RuntimeConfigSnapshot
}

// RuntimeConfigCacheOptions customizes RuntimeConfigCache.
type RuntimeConfigCacheOptions struct {
	Now         func() time.Time
	StaleAfter  time.Duration
	StaleWarnIn time.Duration
	AlertFn     func(context.Context, RuntimeConfigAlert)
}

// RuntimeConfigCache keeps the latest effective admin configuration in memory
// and falls back to the last known good snapshot when reloads fail.
type RuntimeConfigCache struct {
	loader RuntimeConfigLoader
	now    func() time.Time

	staleAfter  time.Duration
	staleWarnIn time.Duration
	alertFn     func(context.Context, RuntimeConfigAlert)

	mu                   sync.RWMutex
	snapshot             RuntimeConfigSnapshot
	generation           int64
	staleAlertGeneration int64
}

// NewRuntimeConfigCache creates a cache over the supplied loader.
func NewRuntimeConfigCache(loader RuntimeConfigLoader, opts RuntimeConfigCacheOptions) *RuntimeConfigCache {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &RuntimeConfigCache{
		loader:      loader,
		now:         now,
		staleAfter:  opts.StaleAfter,
		staleWarnIn: opts.StaleWarnIn,
		alertFn:     opts.AlertFn,
	}
}

// Reload fetches effective published config. On success it publishes a new
// immutable snapshot; on failure it keeps and returns the last known good one.
func (c *RuntimeConfigCache) Reload(ctx context.Context) (RuntimeConfigSnapshot, error) {
	if c == nil || c.loader == nil {
		return RuntimeConfigSnapshot{}, apierr.Internal(errors.New("backoffice: runtime config cache has no loader"))
	}
	checkedAt := c.now().UTC()
	items, err := c.loader.LoadRuntimeConfig(ctx, checkedAt)
	if err != nil {
		snapshot := c.Snapshot()
		c.alert(ctx, RuntimeConfigAlert{
			Kind:     RuntimeConfigAlertReloadFailed,
			At:       checkedAt,
			Err:      err,
			Snapshot: snapshot,
		})
		return snapshot, err
	}
	snapshot := RuntimeConfigSnapshot{
		Items:     cloneRuntimeConfigItems(items),
		LoadedAt:  checkedAt,
		CheckedAt: checkedAt,
	}
	sortRuntimeConfigItems(snapshot.Items)

	c.mu.Lock()
	c.generation++
	snapshot.Generation = c.generation
	c.snapshot = snapshot
	c.staleAlertGeneration = 0
	c.mu.Unlock()
	return snapshot.cloneAt(checkedAt, c.staleAfter), nil
}

// Snapshot returns the current immutable snapshot. If it has exceeded the
// configured staleness threshold, Stale is set and one alert is emitted per
// loaded generation.
func (c *RuntimeConfigCache) Snapshot() RuntimeConfigSnapshot {
	if c == nil {
		return RuntimeConfigSnapshot{}
	}
	checkedAt := c.now().UTC()
	c.mu.RLock()
	snapshot := c.snapshot.cloneAt(checkedAt, c.staleAfter)
	c.mu.RUnlock()
	if snapshot.Stale && snapshot.Generation != 0 {
		c.maybeAlertStale(context.Background(), checkedAt, snapshot)
	}
	return snapshot
}

func (c *RuntimeConfigCache) maybeAlertStale(ctx context.Context, at time.Time, snapshot RuntimeConfigSnapshot) {
	if c.alertFn == nil {
		return
	}
	c.mu.Lock()
	if c.staleAlertGeneration == snapshot.Generation {
		c.mu.Unlock()
		return
	}
	c.staleAlertGeneration = snapshot.Generation
	c.mu.Unlock()

	c.alert(ctx, RuntimeConfigAlert{
		Kind:     RuntimeConfigAlertStale,
		At:       at,
		Snapshot: snapshot,
	})
}

func (c *RuntimeConfigCache) alert(ctx context.Context, alert RuntimeConfigAlert) {
	if c.alertFn == nil {
		return
	}
	c.alertFn(ctx, alert)
}

func (s RuntimeConfigSnapshot) cloneAt(checkedAt time.Time, staleAfter time.Duration) RuntimeConfigSnapshot {
	out := RuntimeConfigSnapshot{
		Items:      cloneRuntimeConfigItems(s.Items),
		LoadedAt:   s.LoadedAt,
		CheckedAt:  checkedAt,
		Generation: s.Generation,
	}
	if !out.LoadedAt.IsZero() {
		out.Age = checkedAt.Sub(out.LoadedAt)
		if out.Age < 0 {
			out.Age = 0
		}
		out.Stale = staleAfter > 0 && out.Age > staleAfter
	}
	return out
}

func cloneRuntimeConfigItems(items []RuntimeConfigItem) []RuntimeConfigItem {
	out := make([]RuntimeConfigItem, len(items))
	for i, item := range items {
		out[i] = cloneRuntimeConfigItem(item)
	}
	return out
}

func cloneRuntimeConfigItem(item RuntimeConfigItem) RuntimeConfigItem {
	item.Payload = append([]byte(nil), item.Payload...)
	return item
}

func sortRuntimeConfigItems(items []RuntimeConfigItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Domain != items[j].Domain {
			return items[i].Domain < items[j].Domain
		}
		if items[i].ConfigSetID != items[j].ConfigSetID {
			return items[i].ConfigSetID < items[j].ConfigSetID
		}
		return items[i].VersionID < items[j].VersionID
	})
}

// StoreRuntimeConfigLoader adapts the admin config repository to the cache.
type StoreRuntimeConfigLoader struct {
	store *store.Store
	repo  *store.AdminConfigRepository
}

// NewStoreRuntimeConfigLoader returns a repository-backed runtime config loader.
func NewStoreRuntimeConfigLoader(s *store.Store, repo *store.AdminConfigRepository) (*StoreRuntimeConfigLoader, error) {
	if s == nil {
		return nil, apierr.Internal(errors.New("backoffice: nil store for runtime config loader"))
	}
	if repo == nil {
		repo = store.NewAdminConfigRepository()
	}
	return &StoreRuntimeConfigLoader{store: s, repo: repo}, nil
}

// LoadRuntimeConfig reads active published config and attaches each set's
// current revision token for cache invalidation.
func (l *StoreRuntimeConfigLoader) LoadRuntimeConfig(ctx context.Context, at time.Time) ([]RuntimeConfigItem, error) {
	if l == nil || l.store == nil || l.repo == nil {
		return nil, apierr.Internal(errors.New("backoffice: runtime config loader is not configured"))
	}
	var items []RuntimeConfigItem
	err := l.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		versions, err := l.repo.ListActivePublishedRuntime(ctx, q, at)
		if err != nil {
			return err
		}
		items = make([]RuntimeConfigItem, 0, len(versions))
		for _, runtimeVersion := range versions {
			version := runtimeVersion.Version
			items = append(items, RuntimeConfigItem{
				ConfigSetID: version.ConfigSetID,
				Domain:      runtimeVersion.Domain,
				VersionID:   version.ID,
				Version:     version.Version,
				Revision:    runtimeVersion.Revision,
				Payload:     version.Payload,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}
