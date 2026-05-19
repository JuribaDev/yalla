package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoAdminUsageAggregationScheduleManager = errors.New("httpapi: no admin usage aggregation schedule manager configured")

// AdminUsageAggregationScheduleUpsertInput is the validated write payload
// passed to the backoffice usage aggregation schedule manager.
type AdminUsageAggregationScheduleUpsertInput = store.UpsertUsageAggregationScheduleInput

// AdminUsageAggregationScheduleManager owns backoffice aggregation schedules.
type AdminUsageAggregationScheduleManager interface {
	UpsertUsageAggregationSchedule(ctx context.Context, key string, in AdminUsageAggregationScheduleUpsertInput, auditCtx store.AdminUsageAggregationScheduleAuditContext) (store.UsageAggregationSchedule, error)
	GetUsageAggregationSchedule(ctx context.Context, key string) (store.UsageAggregationSchedule, error)
	DisableUsageAggregationSchedule(ctx context.Context, key string, auditCtx store.AdminUsageAggregationScheduleAuditContext) (store.UsageAggregationSchedule, error)
}

type adminUsageAggregationScheduleUpsertRequestBody struct {
	Source                     string              `json:"source"`
	MetricKey                  string              `json:"metric_key"`
	AggregationIntervalSeconds int                 `json:"aggregation_interval_seconds,omitempty"`
	ReplayLookbackSeconds      int                 `json:"replay_lookback_seconds,omitempty"`
	CloseDelaySeconds          int                 `json:"close_delay_seconds,omitempty"`
	LateEventMode              store.LateEventMode `json:"late_event_mode"`
	Enabled                    bool                `json:"enabled"`
}

type adminUsageAggregationSchedulePayload struct {
	ID                         string `json:"id"`
	ScheduleKey                string `json:"schedule_key"`
	Version                    int    `json:"version"`
	Source                     string `json:"source"`
	MetricKey                  string `json:"metric_key"`
	AggregationIntervalSeconds int    `json:"aggregation_interval_seconds"`
	ReplayLookbackSeconds      int    `json:"replay_lookback_seconds"`
	CloseDelaySeconds          int    `json:"close_delay_seconds"`
	LateEventMode              string `json:"late_event_mode"`
	Enabled                    bool   `json:"enabled"`
	Revision                   int64  `json:"revision"`
	PublishedAt                string `json:"published_at,omitempty"`
	CreatedAt                  string `json:"created_at,omitempty"`
	UpdatedAt                  string `json:"updated_at,omitempty"`
}

func upsertAdminUsageAggregationScheduleHandler(manager AdminUsageAggregationScheduleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminUsageAggregationScheduleManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("schedule_key"))
		var body adminUsageAggregationScheduleUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminUsageAggregationScheduleAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		schedule, err := manager.UpsertUsageAggregationSchedule(r.Context(), key, AdminUsageAggregationScheduleUpsertInput{
			Source:                     body.Source,
			MetricKey:                  body.MetricKey,
			AggregationIntervalSeconds: body.AggregationIntervalSeconds,
			ReplayLookbackSeconds:      body.ReplayLookbackSeconds,
			CloseDelaySeconds:          body.CloseDelaySeconds,
			LateEventMode:              body.LateEventMode,
			Enabled:                    body.Enabled,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminUsageAggregationScheduleResponse(schedule))
	}
}

func getAdminUsageAggregationScheduleHandler(manager AdminUsageAggregationScheduleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminUsageAggregationScheduleManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("schedule_key"))
		schedule, err := manager.GetUsageAggregationSchedule(r.Context(), key)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminUsageAggregationScheduleResponse(schedule))
	}
}

func disableAdminUsageAggregationScheduleHandler(manager AdminUsageAggregationScheduleManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminUsageAggregationScheduleManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("schedule_key"))
		auditCtx, err := adminUsageAggregationScheduleAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		schedule, err := manager.DisableUsageAggregationSchedule(r.Context(), key, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminUsageAggregationScheduleResponse(schedule))
	}
}

func adminUsageAggregationScheduleAuditContext(r *http.Request) (store.AdminUsageAggregationScheduleAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok {
		return store.AdminUsageAggregationScheduleAuditContext{}, apierr.Unauthenticated("admin usage aggregation schedule operation requires an authenticated principal")
	}
	return store.AdminUsageAggregationScheduleAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     string(principal.Kind),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        strings.TrimSpace(r.Header.Get("X-Yalla-Reason")),
	}, nil
}

func adminUsageAggregationScheduleResponse(schedule store.UsageAggregationSchedule) adminUsageAggregationSchedulePayload {
	return adminUsageAggregationSchedulePayload{
		ID:                         schedule.ID,
		ScheduleKey:                schedule.ScheduleKey,
		Version:                    schedule.Version,
		Source:                     schedule.Source,
		MetricKey:                  schedule.MetricKey,
		AggregationIntervalSeconds: schedule.AggregationIntervalSeconds,
		ReplayLookbackSeconds:      schedule.ReplayLookbackSeconds,
		CloseDelaySeconds:          schedule.CloseDelaySeconds,
		LateEventMode:              string(schedule.LateEventMode),
		Enabled:                    schedule.Enabled,
		Revision:                   schedule.Revision,
		PublishedAt:                formatAdminUsageAggregationScheduleTime(schedule.PublishedAt),
		CreatedAt:                  formatAdminUsageAggregationScheduleTime(schedule.CreatedAt),
		UpdatedAt:                  formatAdminUsageAggregationScheduleTime(schedule.UpdatedAt),
	}
}

func formatAdminUsageAggregationScheduleTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
