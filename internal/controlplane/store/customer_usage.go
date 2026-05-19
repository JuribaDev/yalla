package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

var defaultWarningThresholds = []int{80, 90, 100}

type currentSubscriptionView struct {
	PlanID             string
	Status             SubscriptionStatus
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
}

func readCurrentSubscriptionView(ctx context.Context, q Querier, organizationID string, at time.Time) (currentSubscriptionView, bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var current currentSubscriptionView
	err := q.QueryRow(ctx,
		`SELECT plan_id, status, current_period_start, current_period_end
		   FROM subscriptions
		  WHERE organization_id = $1
		    AND status IN ('trialing', 'active', 'past_due')
		    AND current_period_start <= $2
		    AND current_period_end > $2
		  ORDER BY current_period_start DESC, created_at DESC, id DESC
		  LIMIT 1`,
		organizationID, at,
	).Scan(&current.PlanID, &current.Status, &current.CurrentPeriodStart, &current.CurrentPeriodEnd)
	if errors.Is(err, pgx.ErrNoRows) {
		return currentSubscriptionView{}, false, nil
	}
	if err != nil {
		return currentSubscriptionView{}, false, apierr.StoreUnavailable(err)
	}
	return current, true, nil
}

func quotaUsageCounterMap(ctx context.Context, q Querier, organizationID string) (map[QuotaResource]int64, error) {
	rows, err := q.Query(ctx,
		`SELECT resource, used_value
		   FROM quota_usage
		  WHERE organization_id = $1`,
		organizationID)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	usage := make(map[QuotaResource]int64)
	for rows.Next() {
		var resource string
		var used int64
		if err := rows.Scan(&resource, &used); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		usage[QuotaResource(resource)] = used
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return usage, nil
}

func entitlementScope(source EntitlementOverrideSource) QuotaScope {
	switch source {
	case EntitlementSourceSubscriptionOverride:
		return QuotaScopeSubscriptionOverride
	case EntitlementSourceEmergencyAdmin:
		return QuotaScopeEmergencyAdmin
	default:
		return QuotaScopePlan
	}
}

func warningThresholdCopy() []int {
	return append([]int(nil), defaultWarningThresholds...)
}
