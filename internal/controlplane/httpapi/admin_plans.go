package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoAdminPlanManager = errors.New("httpapi: no admin plan manager configured")

// AdminPlanCreateInput is the validated create payload passed to the
// backoffice plan manager port.
type AdminPlanCreateInput = store.CreatePlanInput

// AdminPlanEditInput is the validated edit payload passed to the backoffice
// plan manager port.
type AdminPlanEditInput = store.UpdatePlanInput

// AdminPlanManager owns backoffice pricing-plan lifecycle changes.
type AdminPlanManager interface {
	CreatePlan(ctx context.Context, in AdminPlanCreateInput, auditCtx store.AdminPlanAuditContext) (store.Plan, error)
	EditPlan(ctx context.Context, id string, in AdminPlanEditInput, auditCtx store.AdminPlanAuditContext) (store.Plan, error)
	PublishPlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error)
	ArchivePlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error)
	RollbackPlan(ctx context.Context, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error)
	UpsertPlanEntitlement(ctx context.Context, planID string, in AdminPlanEntitlementUpsertInput, auditCtx store.AdminPlanAuditContext) (store.PlanEntitlement, error)
	RenamePlanEntitlement(ctx context.Context, planID, fromKey, toKey, impactValidationID string, auditCtx store.AdminPlanAuditContext) (store.PlanEntitlement, error)
	DeletePlanEntitlement(ctx context.Context, planID, key, impactValidationID string, auditCtx store.AdminPlanAuditContext) error
}

type adminPlanCreateRequestBody struct {
	Slug          string              `json:"slug"`
	Name          string              `json:"name"`
	BillingPeriod store.BillingPeriod `json:"billing_period"`
	DisplayOrder  int                 `json:"display_order"`
}

type adminPlanEditRequestBody struct {
	Name         string `json:"name"`
	DisplayOrder int    `json:"display_order"`
}

type adminPlanPayload struct {
	ID            string `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	BillingPeriod string `json:"billing_period"`
	DisplayOrder  int    `json:"display_order"`
	Version       int    `json:"version"`
	ArchivedAt    string `json:"archived_at,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// AdminPlanEntitlementUpsertInput is the validated entitlement payload passed
// to the backoffice plan manager port.
type AdminPlanEntitlementUpsertInput = store.UpsertPlanEntitlementInput

type adminPlanEntitlementUpsertRequestBody struct {
	LimitValue       *int64 `json:"limit_value"`
	EnforcementMode  string `json:"enforcement_mode"`
	Unit             string `json:"unit"`
	WarningThreshold *int   `json:"warning_threshold"`
	UpgradeHint      string `json:"upgrade_hint"`
	OverageBehavior  string `json:"overage_behavior"`
}

type adminPlanEntitlementRenameRequestBody struct {
	NewEntitlementKey  string `json:"new_entitlement_key"`
	ImpactValidationID string `json:"impact_validation_id"`
}

type adminPlanEntitlementDeleteRequestBody struct {
	ImpactValidationID string `json:"impact_validation_id"`
}

type adminPlanEntitlementMetadata struct {
	Unit             string `json:"unit,omitempty"`
	WarningThreshold *int   `json:"warning_threshold,omitempty"`
	UpgradeHint      string `json:"upgrade_hint,omitempty"`
	OverageBehavior  string `json:"overage_behavior,omitempty"`
}

type adminPlanEntitlementPayload struct {
	ID                 string `json:"id,omitempty"`
	PlanID             string `json:"plan_id"`
	EntitlementKey     string `json:"entitlement_key"`
	LimitValue         *int64 `json:"limit_value"`
	EnforcementMode    string `json:"enforcement_mode"`
	Unit               string `json:"unit,omitempty"`
	WarningThreshold   *int   `json:"warning_threshold,omitempty"`
	UpgradeHint        string `json:"upgrade_hint,omitempty"`
	OverageBehavior    string `json:"overage_behavior,omitempty"`
	ImpactValidationID string `json:"impact_validation_id,omitempty"`
}

type adminPlanEntitlementDeletePayload struct {
	Deleted            bool   `json:"deleted"`
	PlanID             string `json:"plan_id"`
	EntitlementKey     string `json:"entitlement_key"`
	ImpactValidationID string `json:"impact_validation_id"`
}

func createAdminPlanHandler(manager AdminPlanManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		var body adminPlanCreateRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in := AdminPlanCreateInput{
			Slug:          body.Slug,
			Name:          body.Name,
			Status:        store.PlanStatusDraft,
			BillingPeriod: body.BillingPeriod,
			DisplayOrder:  body.DisplayOrder,
		}
		if err := validateAdminPlanCreate(in); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		plan, err := manager.CreatePlan(r.Context(), in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusCreated, requestID(r), adminPlanResponse(plan))
	}
}

func editAdminPlanHandler(manager AdminPlanManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		id := strings.TrimSpace(r.PathValue("plan_id"))
		var body adminPlanEditRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in := AdminPlanEditInput{Name: body.Name, Status: store.PlanStatusDraft, DisplayOrder: body.DisplayOrder}
		if err := validateAdminPlanEdit(id, in); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		plan, err := manager.EditPlan(r.Context(), id, in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminPlanResponse(plan))
	}
}

func publishAdminPlanHandler(manager AdminPlanManager) http.HandlerFunc {
	return adminPlanIDActionHandler(manager, http.StatusOK, func(ctx context.Context, manager AdminPlanManager, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
		return manager.PublishPlan(ctx, id, auditCtx)
	})
}

func archiveAdminPlanHandler(manager AdminPlanManager) http.HandlerFunc {
	return adminPlanIDActionHandler(manager, http.StatusOK, func(ctx context.Context, manager AdminPlanManager, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
		return manager.ArchivePlan(ctx, id, auditCtx)
	})
}

func rollbackAdminPlanHandler(manager AdminPlanManager) http.HandlerFunc {
	return adminPlanIDActionHandler(manager, http.StatusCreated, func(ctx context.Context, manager AdminPlanManager, id string, auditCtx store.AdminPlanAuditContext) (store.Plan, error) {
		return manager.RollbackPlan(ctx, id, auditCtx)
	})
}

func upsertAdminPlanEntitlementHandler(manager AdminPlanManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		planID := strings.TrimSpace(r.PathValue("plan_id"))
		key := strings.TrimSpace(r.PathValue("entitlement_key"))
		var body adminPlanEntitlementUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in, err := adminPlanEntitlementUpsertInput(planID, key, body)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		ent, err := manager.UpsertPlanEntitlement(r.Context(), planID, in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminPlanEntitlementResponse(ent, ""))
	}
}

func renameAdminPlanEntitlementHandler(manager AdminPlanManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		planID := strings.TrimSpace(r.PathValue("plan_id"))
		key := strings.TrimSpace(r.PathValue("entitlement_key"))
		var body adminPlanEntitlementRenameRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if err := validateAdminPlanEntitlementRename(planID, key, body); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		ent, err := manager.RenamePlanEntitlement(r.Context(), planID, key, body.NewEntitlementKey, body.ImpactValidationID, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminPlanEntitlementResponse(ent, body.ImpactValidationID))
	}
}

func deleteAdminPlanEntitlementHandler(manager AdminPlanManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		planID := strings.TrimSpace(r.PathValue("plan_id"))
		key := strings.TrimSpace(r.PathValue("entitlement_key"))
		var body adminPlanEntitlementDeleteRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if err := validateAdminPlanEntitlementDelete(planID, key, body); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if err := manager.DeletePlanEntitlement(r.Context(), planID, key, body.ImpactValidationID, auditCtx); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminPlanEntitlementDeletePayload{
			Deleted:            true,
			PlanID:             planID,
			EntitlementKey:     key,
			ImpactValidationID: strings.TrimSpace(body.ImpactValidationID),
		})
	}
}

func adminPlanIDActionHandler(manager AdminPlanManager, successStatus int, run func(context.Context, AdminPlanManager, string, store.AdminPlanAuditContext) (store.Plan, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminPlanManager))
			return
		}
		id := strings.TrimSpace(r.PathValue("plan_id"))
		if id == "" {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"}))
			return
		}
		var body struct{}
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminPlanAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		plan, err := run(r.Context(), manager, id, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, successStatus, requestID(r), adminPlanResponse(plan))
	}
}

func adminPlanAuditContext(r *http.Request) (store.AdminPlanAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminPlanAuditContext{}, apierr.Unauthenticated("admin plan operation requires an authenticated principal")
	}
	return store.AdminPlanAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
	}, nil
}

func adminPlanResponse(plan store.Plan) adminPlanPayload {
	out := adminPlanPayload{
		ID:            plan.ID,
		Slug:          plan.Slug,
		Name:          plan.Name,
		Status:        plan.Status.String(),
		BillingPeriod: plan.BillingPeriod.String(),
		DisplayOrder:  plan.DisplayOrder,
		Version:       plan.Version,
	}
	if plan.ArchivedAt != nil {
		out.ArchivedAt = plan.ArchivedAt.UTC().Format(time.RFC3339Nano)
	}
	if !plan.CreatedAt.IsZero() {
		out.CreatedAt = plan.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !plan.UpdatedAt.IsZero() {
		out.UpdatedAt = plan.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func adminPlanEntitlementResponse(ent store.PlanEntitlement, impactValidationID string) adminPlanEntitlementPayload {
	out := adminPlanEntitlementPayload{
		ID:                 ent.ID,
		PlanID:             ent.PlanID,
		EntitlementKey:     ent.EntitlementKey,
		LimitValue:         ent.LimitValue,
		EnforcementMode:    string(ent.EnforcementMode),
		ImpactValidationID: strings.TrimSpace(impactValidationID),
	}
	var meta adminPlanEntitlementMetadata
	if len(ent.Metadata) > 0 && json.Unmarshal(ent.Metadata, &meta) == nil {
		out.Unit = meta.Unit
		out.WarningThreshold = meta.WarningThreshold
		out.UpgradeHint = meta.UpgradeHint
		out.OverageBehavior = meta.OverageBehavior
	}
	return out
}

func validateAdminPlanCreate(in AdminPlanCreateInput) error {
	var violations []apierr.FieldViolation
	if !validAdminPlanSlug(in.Slug) {
		violations = append(violations, apierr.FieldViolation{Field: "slug", Reason: "must be a canonical plan slug"})
	}
	violations = append(violations, adminPlanNameViolations(in.Name)...)
	if !validAdminBillingPeriod(in.BillingPeriod) {
		violations = append(violations, apierr.FieldViolation{Field: "billing_period", Reason: "must be monthly, annual, or custom"})
	}
	if in.DisplayOrder < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "display_order", Reason: "must not be negative"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func validateAdminPlanEdit(id string, in AdminPlanEditInput) error {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(id) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	violations = append(violations, adminPlanNameViolations(in.Name)...)
	if in.DisplayOrder < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "display_order", Reason: "must not be negative"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func adminPlanEntitlementUpsertInput(planID, key string, body adminPlanEntitlementUpsertRequestBody) (AdminPlanEntitlementUpsertInput, error) {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(planID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !validAdminEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if body.LimitValue != nil && *body.LimitValue < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "limit_value", Reason: "must not be negative"})
	}
	mode := store.EnforcementMode(strings.TrimSpace(body.EnforcementMode))
	if !validAdminPlanEnforcementMode(mode) {
		violations = append(violations, apierr.FieldViolation{Field: "enforcement_mode", Reason: "must be hard, soft, metered, or disabled"})
	}
	meta, metaViolations := adminPlanEntitlementMetadataFromBody(body)
	violations = append(violations, metaViolations...)
	if len(violations) > 0 {
		return AdminPlanEntitlementUpsertInput{}, apierr.InvalidInput(violations...)
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		return AdminPlanEntitlementUpsertInput{}, apierr.Internal(err)
	}
	return AdminPlanEntitlementUpsertInput{
		PlanID:          strings.TrimSpace(planID),
		EntitlementKey:  strings.TrimSpace(key),
		LimitValue:      body.LimitValue,
		EnforcementMode: mode,
		Metadata:        metadata,
	}, nil
}

func adminPlanEntitlementMetadataFromBody(body adminPlanEntitlementUpsertRequestBody) (adminPlanEntitlementMetadata, []apierr.FieldViolation) {
	var violations []apierr.FieldViolation
	meta := adminPlanEntitlementMetadata{
		Unit:             strings.TrimSpace(body.Unit),
		WarningThreshold: body.WarningThreshold,
		UpgradeHint:      strings.TrimSpace(body.UpgradeHint),
		OverageBehavior:  strings.TrimSpace(body.OverageBehavior),
	}
	if meta.Unit != "" && (!validAdminEntitlementUnit(meta.Unit) || len(meta.Unit) > 32) {
		violations = append(violations, apierr.FieldViolation{Field: "unit", Reason: "must be a canonical unit at most 32 bytes"})
	}
	if meta.WarningThreshold != nil && (*meta.WarningThreshold < 0 || *meta.WarningThreshold > 100) {
		violations = append(violations, apierr.FieldViolation{Field: "warning_threshold", Reason: "must be between 0 and 100"})
	}
	if meta.UpgradeHint != "" {
		switch {
		case !utf8.ValidString(meta.UpgradeHint):
			violations = append(violations, apierr.FieldViolation{Field: "upgrade_hint", Reason: "must be valid UTF-8"})
		case len(meta.UpgradeHint) > 240:
			violations = append(violations, apierr.FieldViolation{Field: "upgrade_hint", Reason: "must be at most 240 bytes"})
		}
	}
	if meta.OverageBehavior != "" && !validAdminOverageBehavior(meta.OverageBehavior) {
		violations = append(violations, apierr.FieldViolation{Field: "overage_behavior", Reason: "must be allow, warn, block, or require_admin_review"})
	}
	return meta, violations
}

func validateAdminPlanEntitlementRename(planID, key string, body adminPlanEntitlementRenameRequestBody) error {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(planID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !validAdminEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if !validAdminEntitlementKey(body.NewEntitlementKey) {
		violations = append(violations, apierr.FieldViolation{Field: "new_entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if strings.TrimSpace(key) == strings.TrimSpace(body.NewEntitlementKey) {
		violations = append(violations, apierr.FieldViolation{Field: "new_entitlement_key", Reason: "must differ from entitlement_key"})
	}
	if strings.TrimSpace(body.ImpactValidationID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "impact_validation_id", Reason: "is required for entitlement rename"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func validateAdminPlanEntitlementDelete(planID, key string, body adminPlanEntitlementDeleteRequestBody) error {
	var violations []apierr.FieldViolation
	if strings.TrimSpace(planID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "plan_id", Reason: "must not be blank"})
	}
	if !validAdminEntitlementKey(key) {
		violations = append(violations, apierr.FieldViolation{Field: "entitlement_key", Reason: "must be a canonical entitlement key"})
	}
	if strings.TrimSpace(body.ImpactValidationID) == "" {
		violations = append(violations, apierr.FieldViolation{Field: "impact_validation_id", Reason: "is required for entitlement delete"})
	}
	if len(violations) > 0 {
		return apierr.InvalidInput(violations...)
	}
	return nil
}

func adminPlanNameViolations(name string) []apierr.FieldViolation {
	trimmed := strings.TrimSpace(name)
	switch {
	case trimmed == "":
		return []apierr.FieldViolation{{Field: "name", Reason: "must not be blank"}}
	case !utf8.ValidString(trimmed):
		return []apierr.FieldViolation{{Field: "name", Reason: "must be valid UTF-8"}}
	case len(trimmed) > 120:
		return []apierr.FieldViolation{{Field: "name", Reason: "must be at most 120 bytes"}}
	default:
		return nil
	}
}

func validAdminPlanSlug(raw string) bool {
	slug := strings.TrimSpace(raw)
	if slug == "" || len(slug) > 63 {
		return false
	}
	for i, r := range slug {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if !ok {
			return false
		}
		if (i == 0 || i == len(slug)-1) && r == '-' {
			return false
		}
	}
	return true
}

func validAdminBillingPeriod(period store.BillingPeriod) bool {
	switch period {
	case store.BillingPeriodMonthly, store.BillingPeriodAnnual, store.BillingPeriodCustom:
		return true
	default:
		return false
	}
}

func validAdminPlanEnforcementMode(mode store.EnforcementMode) bool {
	switch mode {
	case store.EnforcementModeHard, store.EnforcementModeSoft, store.EnforcementModeMetered, store.EnforcementModeDisabled:
		return true
	default:
		return false
	}
}

func validAdminEntitlementKey(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 128 {
		return false
	}
	for i, r := range key {
		ok := r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' ||
			r == '_' || r == '.' || r == '-'
		if !ok {
			return false
		}
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validAdminEntitlementUnit(unit string) bool {
	if unit == "" {
		return true
	}
	for i, r := range unit {
		ok := r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '/'
		if !ok {
			return false
		}
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validAdminOverageBehavior(value string) bool {
	switch value {
	case "allow", "warn", "block", "require_admin_review":
		return true
	default:
		return false
	}
}
