package httpapi

import (
	"context"
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
