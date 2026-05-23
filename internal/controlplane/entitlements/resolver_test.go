package entitlements_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/entitlements"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

type fakeStore struct {
	q     store.Querier
	reads int
}

func (s *fakeStore) Read(ctx context.Context, fn func(context.Context, store.Querier) error) error {
	s.reads++
	if s.q == nil {
		s.q = &store.Tx{}
	}
	return fn(ctx, s.q)
}

type fakeSource struct {
	revision string
	rows     []store.EffectiveEntitlement
	revs     int
	resolves int
}

func (s *fakeSource) EntitlementRevision(context.Context, store.Querier, string, time.Time) (string, error) {
	s.revs++
	return s.revision, nil
}

func (s *fakeSource) ResolveEntitlements(context.Context, store.Querier, string, time.Time) ([]store.EffectiveEntitlement, error) {
	s.resolves++
	out := make([]store.EffectiveEntitlement, len(s.rows))
	copy(out, s.rows)
	return out, nil
}

func TestResolverReturnsEffectiveMapWithExplanation(t *testing.T) {
	t.Parallel()
	limit := int64(25)
	source := &fakeSource{
		revision: "rev-1",
		rows: []store.EffectiveEntitlement{{
			EntitlementKey:  "projects",
			LimitValue:      &limit,
			EnforcementMode: store.EnforcementModeHard,
			Source:          store.EntitlementSourceEmergencyAdmin,
			PlanID:          "plan_business_monthly_v1",
			SubscriptionID:  "sub_current",
			OverrideID:      "sent_override",
		}},
	}
	resolver, err := entitlements.NewResolver(&fakeStore{}, source)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	snapshot, err := resolver.Resolve(context.Background(), "org_123", time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, ok := snapshot.Get("projects")
	if !ok {
		t.Fatalf("snapshot missing projects entitlement: %+v", snapshot)
	}
	if got.Value == nil || *got.Value != 25 || got.EnforcementMode != store.EnforcementModeHard || got.Source != entitlements.SourceEmergencyAdmin {
		t.Fatalf("projects entitlement = %+v, want emergency hard limit 25", got)
	}
	if got.Explanation == "" || got.PlanID != "plan_business_monthly_v1" || got.SubscriptionID != "sub_current" || got.OverrideID != "sent_override" {
		t.Fatalf("projects entitlement missing stable explanation/ids: %+v", got)
	}
}

func TestResolverCachesByRevisionAndInvalidatesOnChange(t *testing.T) {
	t.Parallel()
	limit := int64(5)
	source := &fakeSource{
		revision: "rev-1",
		rows: []store.EffectiveEntitlement{{
			EntitlementKey:  "projects",
			LimitValue:      &limit,
			EnforcementMode: store.EnforcementModeHard,
			Source:          store.EntitlementSourcePlan,
			PlanID:          "plan_pro_monthly_v1",
			SubscriptionID:  "sub_current",
		}},
	}
	resolver, err := entitlements.NewResolver(&fakeStore{}, source)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	at := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)

	first, err := resolver.Resolve(context.Background(), "org_123", at)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	second, err := resolver.Resolve(context.Background(), "org_123", at)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if source.resolves != 1 {
		t.Fatalf("source resolves = %d, want 1 cached read", source.resolves)
	}
	if first.Revision != second.Revision || first.Entitlements["projects"].Explanation != second.Entitlements["projects"].Explanation {
		t.Fatalf("cached snapshot changed: first=%+v second=%+v", first, second)
	}

	next := int64(9)
	source.revision = "rev-2"
	source.rows[0].LimitValue = &next
	third, err := resolver.Resolve(context.Background(), "org_123", at)
	if err != nil {
		t.Fatalf("third Resolve: %v", err)
	}
	if source.resolves != 2 {
		t.Fatalf("source resolves after revision change = %d, want 2", source.resolves)
	}
	if got := third.Entitlements["projects"].Value; got == nil || *got != 9 {
		t.Fatalf("third projects value = %v, want 9 after invalidation", got)
	}
}

func TestResolverMissingSubscriptionFallbackIsEmpty(t *testing.T) {
	t.Parallel()
	source := &fakeSource{revision: "empty"}
	resolver, err := entitlements.NewResolver(&fakeStore{}, source)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	snapshot, err := resolver.Resolve(context.Background(), "org_without_subscription", time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(snapshot.Entitlements) != 0 {
		t.Fatalf("missing subscription snapshot = %+v, want empty entitlements", snapshot)
	}
}

func TestNewResolverRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	source := &fakeSource{}
	if _, err := entitlements.NewResolver(nil, source); err == nil {
		t.Fatal("NewResolver(nil store) error = nil, want error")
	}
	if _, err := entitlements.NewResolver(&fakeStore{}, nil); err == nil {
		t.Fatal("NewResolver(nil source) error = nil, want error")
	}
}

func TestResolverReturnsValidationForBlankOrganization(t *testing.T) {
	t.Parallel()
	resolver, err := entitlements.NewResolver(&fakeStore{}, &fakeSource{})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = resolver.Resolve(context.Background(), " ", time.Now())
	if err == nil {
		t.Fatal("Resolve(blank org) error = nil, want validation")
	}
}

func TestResolverPropagatesSourceErrors(t *testing.T) {
	t.Parallel()
	want := errors.New("boom")
	source := entitlementSourceFunc{
		revision: func(context.Context, store.Querier, string, time.Time) (string, error) { return "", want },
	}
	resolver, err := entitlements.NewResolver(&fakeStore{}, source)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = resolver.Resolve(context.Background(), "org_123", time.Now())
	if !errors.Is(err, want) {
		t.Fatalf("Resolve err = %v, want %v", err, want)
	}
}

type entitlementSourceFunc struct {
	revision func(context.Context, store.Querier, string, time.Time) (string, error)
	resolve  func(context.Context, store.Querier, string, time.Time) ([]store.EffectiveEntitlement, error)
}

func (f entitlementSourceFunc) EntitlementRevision(ctx context.Context, q store.Querier, org string, at time.Time) (string, error) {
	return f.revision(ctx, q, org, at)
}

func (f entitlementSourceFunc) ResolveEntitlements(ctx context.Context, q store.Querier, org string, at time.Time) ([]store.EffectiveEntitlement, error) {
	if f.resolve == nil {
		return nil, nil
	}
	return f.resolve(ctx, q, org, at)
}
