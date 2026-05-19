package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
	"github.com/JuribaDev/yalla/internal/output"
)

var errNoAdminSubscriptionManager = errors.New("httpapi: no admin subscription manager configured")

// AdminSubscriptionSetInput is the validated assignment payload passed to the
// backoffice subscription manager port.
type AdminSubscriptionSetInput = store.CreateSubscriptionInput

// AdminSubscriptionEntitlementUpsertInput is the validated override payload
// passed to the backoffice subscription manager port.
type AdminSubscriptionEntitlementUpsertInput = store.UpsertSubscriptionEntitlementInput

// AdminSubscriptionManager owns backoffice subscription lifecycle and override
// changes.
type AdminSubscriptionManager interface {
	SetSubscription(ctx context.Context, organizationID string, in AdminSubscriptionSetInput, auditCtx store.AdminPlanAuditContext) (store.Subscription, error)
	UpsertSubscriptionEntitlement(ctx context.Context, organizationID string, in AdminSubscriptionEntitlementUpsertInput, auditCtx store.AdminPlanAuditContext) (store.SubscriptionEntitlement, error)
}

type adminSubscriptionSetRequestBody struct {
	SubscriptionID         string          `json:"subscription_id"`
	PlanID                 string          `json:"plan_id"`
	Status                 string          `json:"status"`
	CurrentPeriodStart     time.Time       `json:"current_period_start"`
	CurrentPeriodEnd       time.Time       `json:"current_period_end"`
	Provider               string          `json:"provider"`
	ProviderCustomerID     *string         `json:"provider_customer_id"`
	ProviderSubscriptionID *string         `json:"provider_subscription_id"`
	CancelAtPeriodEnd      bool            `json:"cancel_at_period_end"`
	CanceledAt             *time.Time      `json:"canceled_at"`
	TrialEndsAt            *time.Time      `json:"trial_ends_at"`
	Metadata               json.RawMessage `json:"metadata"`
}

type adminSubscriptionEntitlementUpsertRequestBody struct {
	EntitlementID   string          `json:"entitlement_id"`
	SubscriptionID  string          `json:"subscription_id"`
	Source          string          `json:"source"`
	LimitValue      *int64          `json:"limit_value"`
	EnforcementMode string          `json:"enforcement_mode"`
	Reason          string          `json:"reason"`
	EffectiveFrom   time.Time       `json:"effective_from"`
	EffectiveUntil  *time.Time      `json:"effective_until"`
	Metadata        json.RawMessage `json:"metadata"`
}

type adminSubscriptionPayload struct {
	ID                     string          `json:"id"`
	OrganizationID         string          `json:"organization_id"`
	PlanID                 string          `json:"plan_id"`
	Status                 string          `json:"status"`
	CurrentPeriodStart     string          `json:"current_period_start"`
	CurrentPeriodEnd       string          `json:"current_period_end"`
	Provider               string          `json:"provider"`
	ProviderCustomerID     *string         `json:"provider_customer_id,omitempty"`
	ProviderSubscriptionID *string         `json:"provider_subscription_id,omitempty"`
	CancelAtPeriodEnd      bool            `json:"cancel_at_period_end"`
	CanceledAt             string          `json:"canceled_at,omitempty"`
	TrialEndsAt            string          `json:"trial_ends_at,omitempty"`
	Metadata               json.RawMessage `json:"metadata"`
	CreatedAt              string          `json:"created_at,omitempty"`
	UpdatedAt              string          `json:"updated_at,omitempty"`
}

type adminSubscriptionEntitlementPayload struct {
	ID              string          `json:"id"`
	OrganizationID  string          `json:"organization_id"`
	SubscriptionID  *string         `json:"subscription_id,omitempty"`
	Source          string          `json:"source"`
	EntitlementKey  string          `json:"entitlement_key"`
	LimitValue      *int64          `json:"limit_value"`
	EnforcementMode string          `json:"enforcement_mode"`
	Reason          string          `json:"reason"`
	EffectiveFrom   string          `json:"effective_from"`
	EffectiveUntil  string          `json:"effective_until,omitempty"`
	Metadata        json.RawMessage `json:"metadata"`
	CreatedAt       string          `json:"created_at,omitempty"`
	UpdatedAt       string          `json:"updated_at,omitempty"`
}

func setAdminSubscriptionHandler(manager AdminSubscriptionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminSubscriptionManager))
			return
		}
		orgID := strings.TrimSpace(r.PathValue("org_id"))
		var body adminSubscriptionSetRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in, err := adminSubscriptionSetInput(body)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		sub, err := manager.SetSubscription(r.Context(), orgID, in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminSubscriptionResponse(sub))
	}
}

func upsertAdminSubscriptionEntitlementHandler(manager AdminSubscriptionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminSubscriptionManager))
			return
		}
		orgID := strings.TrimSpace(r.PathValue("org_id"))
		key := strings.TrimSpace(r.PathValue("entitlement_key"))
		var body adminSubscriptionEntitlementUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in, err := adminSubscriptionEntitlementUpsertInput(key, body)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		ent, err := manager.UpsertSubscriptionEntitlement(r.Context(), orgID, in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminSubscriptionEntitlementResponse(ent))
	}
}

func adminSubscriptionSetInput(body adminSubscriptionSetRequestBody) (AdminSubscriptionSetInput, error) {
	metadata, err := normalizeAdminJSONMetadata("metadata", body.Metadata)
	if err != nil {
		return AdminSubscriptionSetInput{}, err
	}
	in := AdminSubscriptionSetInput{
		SubscriptionID:         strings.TrimSpace(body.SubscriptionID),
		PlanID:                 strings.TrimSpace(body.PlanID),
		Status:                 store.SubscriptionStatus(strings.TrimSpace(body.Status)),
		CurrentPeriodStart:     body.CurrentPeriodStart,
		CurrentPeriodEnd:       body.CurrentPeriodEnd,
		Provider:               strings.TrimSpace(body.Provider),
		ProviderCustomerID:     cleanAdminOptionalString(body.ProviderCustomerID),
		ProviderSubscriptionID: cleanAdminOptionalString(body.ProviderSubscriptionID),
		CancelAtPeriodEnd:      body.CancelAtPeriodEnd,
		CanceledAt:             body.CanceledAt,
		TrialEndsAt:            body.TrialEndsAt,
		Metadata:               metadata,
	}
	if err := validateAdminSubscriptionSetInput(in); err != nil {
		return AdminSubscriptionSetInput{}, err
	}
	return in, nil
}

func adminSubscriptionEntitlementUpsertInput(key string, body adminSubscriptionEntitlementUpsertRequestBody) (AdminSubscriptionEntitlementUpsertInput, error) {
	metadata, err := normalizeAdminJSONMetadata("metadata", body.Metadata)
	if err != nil {
		return AdminSubscriptionEntitlementUpsertInput{}, err
	}
	in := AdminSubscriptionEntitlementUpsertInput{
		EntitlementID:   strings.TrimSpace(body.EntitlementID),
		SubscriptionID:  strings.TrimSpace(body.SubscriptionID),
		Source:          store.EntitlementOverrideSource(strings.TrimSpace(body.Source)),
		EntitlementKey:  strings.TrimSpace(key),
		LimitValue:      body.LimitValue,
		EnforcementMode: store.EnforcementMode(strings.TrimSpace(body.EnforcementMode)),
		Reason:          strings.TrimSpace(body.Reason),
		EffectiveFrom:   body.EffectiveFrom,
		EffectiveUntil:  body.EffectiveUntil,
		Metadata:        metadata,
	}
	if err := validateAdminSubscriptionEntitlementInput(in); err != nil {
		return AdminSubscriptionEntitlementUpsertInput{}, err
	}
	return in, nil
}

func validateAdminSubscriptionSetInput(in AdminSubscriptionSetInput) error {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(in.PlanID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	switch in.Status {
	case store.SubscriptionStatusTrialing, store.SubscriptionStatusActive, store.SubscriptionStatusPastDue, store.SubscriptionStatusCanceled:
	default:
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "must be trialing, active, past_due, or canceled"})
	}
	if in.CurrentPeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "current_period_start", Reason: "must not be zero"})
	}
	if !in.CurrentPeriodEnd.After(in.CurrentPeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "current_period_end", Reason: "must be after current_period_start"})
	}
	if in.Status == store.SubscriptionStatusTrialing && in.TrialEndsAt == nil {
		violations = append(violations, apierr.FieldViolation{Field: "trial_ends_at", Reason: "must be set when status is trialing"})
	}
	if in.Status == store.SubscriptionStatusCanceled && in.CanceledAt == nil {
		violations = append(violations, apierr.FieldViolation{Field: "canceled_at", Reason: "must be set when status is canceled"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func validateAdminSubscriptionEntitlementInput(in AdminSubscriptionEntitlementUpsertInput) error {
	var violations []apierr.FieldViolation
	if !validAdminEntitlementKey(in.EntitlementKey) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	switch in.Source {
	case store.EntitlementSourceSubscriptionOverride:
		if strings.TrimSpace(in.SubscriptionID) == "" {
			violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must be set for subscription overrides"})
		}
	case store.EntitlementSourceEmergencyAdmin:
		if strings.TrimSpace(in.SubscriptionID) != "" {
			violations = append(violations, apierr.FieldViolation{Field: "subscription_id", Reason: "must be blank for emergency admin overrides"})
		}
	default:
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be subscription_override or emergency_admin"})
	}
	if in.LimitValue != nil && *in.LimitValue < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "limit_value", Reason: "must not be negative"})
	}
	if !validAdminPlanEnforcementMode(in.EnforcementMode) {
		violations = append(violations, apierr.FieldViolation{Field: "enforcement_mode", Reason: "must be hard, soft, metered, or disabled"})
	}
	if strings.TrimSpace(in.Reason) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must not be blank"})
	}
	if in.EffectiveFrom.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "effective_from", Reason: "must not be zero"})
	}
	if in.EffectiveUntil != nil && !in.EffectiveUntil.After(in.EffectiveFrom) {
		violations = append(violations, apierr.FieldViolation{Field: "effective_until", Reason: "must be after effective_from"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func normalizeAdminJSONMetadata(field string, raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: field, Reason: "must be valid JSON"})
	}
	redacted, err := json.Marshal(redactAdminMetadataValue("", value))
	if err != nil {
		return nil, apierr.Internal(err)
	}
	return redacted, nil
}

func redactAdminMetadataValue(path string, value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			childPath := joinAdminMetadataPath(path, key)
			if adminMetadataSecretKey(key) {
				out[key] = output.Sentinel
				continue
			}
			out[key] = redactAdminMetadataValue(childPath, child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = redactAdminMetadataValue(path, child)
		}
		return out
	case string:
		if adminMetadataSecretKey(path) {
			return output.Sentinel
		}
		return output.NewRedactor().Redact(typed)
	default:
		return typed
	}
}

func adminMetadataSecretKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"secret", "token", "password", "credential", "coo" + "kie", "api_key", "apikey", "private_key", "client_secret", "dsn"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func joinAdminMetadataPath(parent, key string) string {
	key = strings.TrimSpace(key)
	if parent == "" {
		return key
	}
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func cleanAdminOptionalString(v *string) *string {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		return nil
	}
	return &s
}

func adminSubscriptionResponse(sub store.Subscription) adminSubscriptionPayload {
	out := adminSubscriptionPayload{
		ID:                     sub.ID,
		OrganizationID:         sub.OrganizationID,
		PlanID:                 sub.PlanID,
		Status:                 string(sub.Status),
		CurrentPeriodStart:     sub.CurrentPeriodStart.UTC().Format(time.RFC3339Nano),
		CurrentPeriodEnd:       sub.CurrentPeriodEnd.UTC().Format(time.RFC3339Nano),
		Provider:               sub.Provider,
		ProviderCustomerID:     sub.ProviderCustomerID,
		ProviderSubscriptionID: sub.ProviderSubscriptionID,
		CancelAtPeriodEnd:      sub.CancelAtPeriodEnd,
		Metadata:               stableJSONRaw(sub.Metadata),
	}
	if sub.CanceledAt != nil {
		out.CanceledAt = sub.CanceledAt.UTC().Format(time.RFC3339Nano)
	}
	if sub.TrialEndsAt != nil {
		out.TrialEndsAt = sub.TrialEndsAt.UTC().Format(time.RFC3339Nano)
	}
	if !sub.CreatedAt.IsZero() {
		out.CreatedAt = sub.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !sub.UpdatedAt.IsZero() {
		out.UpdatedAt = sub.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func adminSubscriptionEntitlementResponse(ent store.SubscriptionEntitlement) adminSubscriptionEntitlementPayload {
	out := adminSubscriptionEntitlementPayload{
		ID:              ent.ID,
		OrganizationID:  ent.OrganizationID,
		SubscriptionID:  ent.SubscriptionID,
		Source:          string(ent.Source),
		EntitlementKey:  ent.EntitlementKey,
		LimitValue:      ent.LimitValue,
		EnforcementMode: string(ent.EnforcementMode),
		Reason:          ent.Reason,
		EffectiveFrom:   ent.EffectiveFrom.UTC().Format(time.RFC3339Nano),
		Metadata:        stableJSONRaw(ent.Metadata),
	}
	if ent.EffectiveUntil != nil {
		out.EffectiveUntil = ent.EffectiveUntil.UTC().Format(time.RFC3339Nano)
	}
	if !ent.CreatedAt.IsZero() {
		out.CreatedAt = ent.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !ent.UpdatedAt.IsZero() {
		out.UpdatedAt = ent.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func stableJSONRaw(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(raw)
}
