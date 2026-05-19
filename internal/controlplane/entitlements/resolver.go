// Package entitlements resolves the effective runtime entitlement set for an
// organization from the pricing catalog, accepted subscription, and overrides.
package entitlements

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Source identifies the layer that produced an effective entitlement.
type Source string

const (
	// SourcePlan marks an entitlement inherited from the accepted plan version.
	SourcePlan Source = "plan"
	// SourceSubscriptionOverride marks a subscription-scoped override.
	SourceSubscriptionOverride Source = "subscription_override"
	// SourceEmergencyAdmin marks an organization-root emergency admin override.
	SourceEmergencyAdmin Source = "emergency_admin"
)

// Entitlement is one resolved runtime permission or limit.
type Entitlement struct {
	Key             string
	Value           *int64
	EnforcementMode store.EnforcementMode
	Source          Source
	Explanation     string
	PlanID          string
	SubscriptionID  string
	OverrideID      string
}

// Snapshot is the deterministic runtime view for one organization at one
// instant. Entitlements is keyed by Entitlement.Key.
type Snapshot struct {
	OrganizationID string
	ResolvedAt     time.Time
	Revision       string
	Entitlements   map[string]Entitlement
}

// Get returns the entitlement for key.
func (s Snapshot) Get(key string) (Entitlement, bool) {
	ent, ok := s.Entitlements[strings.TrimSpace(key)]
	return ent, ok
}

// ReadStore is the narrow store port Resolver needs.
type ReadStore interface {
	Read(context.Context, func(context.Context, store.Querier) error) error
}

// SourceRepository is the narrow repository port Resolver needs.
type SourceRepository interface {
	EntitlementRevision(context.Context, store.Querier, string, time.Time) (string, error)
	ResolveEntitlements(context.Context, store.Querier, string, time.Time) ([]store.EffectiveEntitlement, error)
}

// Resolver resolves and safely caches effective entitlement snapshots.
type Resolver struct {
	store  ReadStore
	source SourceRepository

	mu    sync.RWMutex
	cache map[cacheKey]Snapshot
}

type cacheKey struct {
	organizationID string
	at             int64
}

// NewResolver wires an entitlement resolver from narrow ports.
func NewResolver(readStore ReadStore, source SourceRepository) (*Resolver, error) {
	if readStore == nil {
		return nil, errors.New("entitlements: nil read store")
	}
	if source == nil {
		return nil, errors.New("entitlements: nil source repository")
	}
	return &Resolver{
		store:  readStore,
		source: source,
		cache:  make(map[cacheKey]Snapshot),
	}, nil
}

// Resolve returns the effective entitlement map for organizationID at at. The
// cache is keyed by organization+instant and validated against a datastore
// revision before reuse, so plan, subscription, or override changes invalidate
// stale entries without a process restart.
func (r *Resolver) Resolve(ctx context.Context, organizationID string, at time.Time) (Snapshot, error) {
	orgID, at, _, err := resolveInputs(organizationID, at)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	err = r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		snapshot, err = r.ResolveWithQuerier(ctx, q, orgID, at)
		return err
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// ResolveWithQuerier returns the effective entitlement map using an existing
// transaction or read snapshot. Callers already inside a Store.Write unit of
// work should use this method so the entitlement read observes the same
// snapshot as the quota reservation and desired-state write.
func (r *Resolver) ResolveWithQuerier(ctx context.Context, q store.Querier, organizationID string, at time.Time) (Snapshot, error) {
	if q == nil {
		return Snapshot{}, apierr.Internal(errors.New("entitlements: nil querier"))
	}
	orgID, at, key, err := resolveInputs(organizationID, at)
	if err != nil {
		return Snapshot{}, err
	}
	revision, err := r.source.EntitlementRevision(ctx, q, orgID, at)
	if err != nil {
		return Snapshot{}, err
	}
	if cached, ok := r.cached(key, revision); ok {
		return cached, nil
	}
	rows, err := r.source.ResolveEntitlements(ctx, q, orgID, at)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := buildSnapshot(orgID, at, revision, rows)
	r.storeCache(key, snapshot)
	return snapshot, nil
}

func resolveInputs(organizationID string, at time.Time) (string, time.Time, cacheKey, error) {
	orgID := strings.TrimSpace(organizationID)
	if orgID == "" {
		return "", time.Time{}, cacheKey{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be empty",
		})
	}
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	key := cacheKey{organizationID: orgID, at: at.UnixNano()}
	return orgID, at, key, nil
}

func (r *Resolver) cached(key cacheKey, revision string) (Snapshot, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot, ok := r.cache[key]
	if !ok || snapshot.Revision != revision {
		return Snapshot{}, false
	}
	return cloneSnapshot(snapshot), true
}

func (r *Resolver) storeCache(key cacheKey, snapshot Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = cloneSnapshot(snapshot)
}

func buildSnapshot(orgID string, at time.Time, revision string, rows []store.EffectiveEntitlement) Snapshot {
	ents := make(map[string]Entitlement, len(rows))
	for _, row := range rows {
		ent := Entitlement{
			Key:             row.EntitlementKey,
			Value:           cloneInt64(row.LimitValue),
			EnforcementMode: row.EnforcementMode,
			Source:          mapSource(row.Source),
			PlanID:          row.PlanID,
			SubscriptionID:  row.SubscriptionID,
			OverrideID:      row.OverrideID,
		}
		ent.Explanation = explanation(ent)
		ents[ent.Key] = ent
	}
	return Snapshot{
		OrganizationID: orgID,
		ResolvedAt:     at,
		Revision:       revision,
		Entitlements:   ents,
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	clone := snapshot
	clone.Entitlements = make(map[string]Entitlement, len(snapshot.Entitlements))
	for key, ent := range snapshot.Entitlements {
		ent.Value = cloneInt64(ent.Value)
		clone.Entitlements[key] = ent
	}
	return clone
}

func cloneInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func mapSource(source store.EntitlementOverrideSource) Source {
	switch source {
	case store.EntitlementSourceSubscriptionOverride:
		return SourceSubscriptionOverride
	case store.EntitlementSourceEmergencyAdmin:
		return SourceEmergencyAdmin
	default:
		return SourcePlan
	}
}

func explanation(ent Entitlement) string {
	switch ent.Source {
	case SourceEmergencyAdmin:
		return fmt.Sprintf("emergency_admin override %s applies to accepted plan %s", ent.OverrideID, ent.PlanID)
	case SourceSubscriptionOverride:
		return fmt.Sprintf("subscription override %s applies to subscription %s", ent.OverrideID, ent.SubscriptionID)
	default:
		return fmt.Sprintf("accepted plan %s default applies", ent.PlanID)
	}
}
